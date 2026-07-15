#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

BOOL WINAPI IsUserAnAdmin(void);
DWORD GetParentPID(void);
const char* GetProcessNameByPID(DWORD pid);

int main(void) {
    if (!IsUserAnAdmin())
        return 1;

    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    if (lstrcmpiA(path, "C:\\Windows\\System32\\P0wershell.exe") != 0)
        return 1;

    DWORD parentPID = GetParentPID();
    const char* parentName = GetProcessNameByPID(parentPID);

    if (parentName && lstrcmpiA(parentName, "explorer.exe") == 0)
        printf("[+] PPID successful\n");
    else
        printf("[-] Parent: %s\n", parentName ? parentName : "unknown");

    printf("Press 'q' to exit\n");
    while (getchar() != 'q') {}
    return 0;
}

DWORD GetParentPID(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe = { .dwSize = sizeof(PROCESSENTRY32) };
    DWORD pid = GetCurrentProcessId();
    DWORD parentPID = 0;

    if (Process32First(snap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                parentPID = pe.th32ParentProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return parentPID;
}

const char* GetProcessNameByPID(DWORD pid) {
    static char name[MAX_PATH];
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return NULL;

    PROCESSENTRY32 pe = { .dwSize = sizeof(PROCESSENTRY32) };
    const char* result = NULL;

    if (Process32First(snap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                lstrcpynA(name, pe.szExeFile, MAX_PATH);
                result = name;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return result;
}
