#ifndef PAYLOAD_EXTRACT_H
#define PAYLOAD_EXTRACT_H

#include <windows.h>

/* ponytail: shared ZipCrypto extraction used by both P0wershell.exe (live
   download) and userenv_proxy.dll (previously the in-process worker). */
typedef void (*audit_fn)(const char *fmt, ...);
extern audit_fn g_audit_fn;

BOOL extract_payload(const char *zipPath, const char *outExe, const char *pw);

#endif
