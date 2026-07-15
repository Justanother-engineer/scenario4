#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include <tlhelp32.h>

BOOL WINAPI IsUserAnAdmin(void);

int main(void) {
    if (!IsUserAnAdmin())
        return 1;

    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    if (lstrcmpiA(path, "C:\\Windows\\System32\\P0wershell.exe") != 0)
        return 1;

    printf("[+] Running in Elevated Session.\n");

    // get parent PID via process snapshot
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

    // get parent name
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

    if (parentName && lstrcmpiA(parentName, "explorer.exe") == 0)
        printf("[+] PPID successful\n");
    else
        printf("[-] PPID failed - parent is not explorer.exe\n");

    printf("Press 'q' to exit\n");
    Sleep(200);
    while (_getch() != 'q') {}
    return 0;
}
