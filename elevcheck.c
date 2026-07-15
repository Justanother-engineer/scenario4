#include <windows.h>
#include <stdio.h>

BOOL WINAPI IsUserAnAdmin(void);

int main(void) {
    if (!IsUserAnAdmin())
        return 1;

    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    if (lstrcmpiA(path, "C:\\Program Files\\Microsoft\\svchost.exe") != 0)
        return 1;

    printf("elevated\n");
    Sleep(2000);
    return 0;
}
