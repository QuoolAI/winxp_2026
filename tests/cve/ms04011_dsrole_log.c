/* MS04-011 (CVE-2003-0533) regression: the DsRole log line formatter in lsasrv.dll.

   extracted.c (written by tests/test_cve.py) holds, verbatim from Source/XPSP1/NT:
     - wvsprintfW and its helpers from windows/core/ntuser/client/wsprintf.c (XP25's
       source-built user32: output limited to WSPRINTF_LIMIT characters wherever it starts);
     - DsRolepDebugDumpRoutine and DsRolepLogPrintRoutine from ds/security/dsrole/server/log.c,
       original or patched.
   The harness calls DsRolepLogPrintRoutine exactly as DsRolerUpgradeDownlevelServer does with
   a caller-supplied DNS domain name, and checks what reaches the log file.

   usage: ms04011 normal|long|boundary   exit 0 = log line correct and bounded */
#include "nt_shim.h"

#define WSPRINTF_LIMIT 1024
#define LOG_GENERAL 0
#define DUMMYCALLINGTYPE
#define FUNCLOG3(...)
#define CP_ACP 0
#define DEB_ERROR 0x00000001
#define DEB_WARN 0x00000002
#define DEB_TRACE 0x00000004
#define DEB_TRACE_DS 0x00000008
#define FLAG_ON(flag, bits) ((flag) & (bits))
#define DsRoleDebugOut(x)
#define LockLogFile()
#define UnlockLogFile()

typedef struct { WORD wYear, wMonth, wDayOfWeek, wDay, wHour, wMinute, wSecond, wMilliseconds; } SYSTEMTIME;

static HANDLE DsRolepLogFile = (HANDLE)1;
static WCHAR captured[8192];
static size_t captured_len;

static void GetLocalTime(SYSTEMTIME *t)
{
    memset(t, 0, sizeof(*t));
    t->wMonth = 11; t->wDay = 12; t->wHour = 23; t->wMinute = 59; t->wSecond = 58;
}

static BOOL WriteFile(HANDLE h, LPCVOID data, DWORD bytes, LPDWORD written, void *overlapped)
{
    (void)h; (void)overlapped;
    if (captured_len + bytes / 2 > sizeof(captured) / sizeof(captured[0])) abort();
    memcpy(captured + captured_len, data, bytes);
    captured_len += bytes / 2;
    *written = bytes;
    return TRUE;
}

static int MultiByteToWideChar(UINT cp, DWORD flags, LPCSTR in, int cbIn, LPWSTR out, int cchOut)
{
    (void)cp; (void)flags; (void)cbIn;
    xp_to_wide(out, in, (size_t)cchOut);
    return (int)xp_wcslen(out) + 1;
}

/* user32's ANSI-to-Unicode allocation used by wvsprintfW for %S / %hs arguments. */
static int MBToWCS(LPBYTE psz, int cch, LPWSTR *ppwsz, int cchUnicode, BOOL alloc)
{
    int i;
    (void)cchUnicode; (void)alloc;
    if (cch < 0) cch = (int)strlen((const char *)psz);
    *ppwsz = malloc(((size_t)cch + 1) * sizeof(WCHAR));
    if (!*ppwsz) return 0;
    for (i = 0; i < cch; i++) (*ppwsz)[i] = psz[i];
    (*ppwsz)[cch] = 0;
    return cch;
}
#define UserLocalFree(p) free(p)
#define strlen(p) strlen((const char *)(p))

int wvsprintfW(LPWSTR lpOut, LPCWSTR lpFmt, va_list arglist);

/* msvcrt _vsnwprintf semantics: at most count characters; the count when the text fits
   (terminated when there is room), -1 when it does not. The formatting itself is done by
   the source wvsprintfW into a scratch buffer; the formats DsRole uses (%ws %S %lu %x)
   mean the same in both. */
static int _vsnwprintf(WCHAR *buffer, size_t count, const WCHAR *format, va_list args)
{
    WCHAR scratch[WSPRINTF_LIMIT + 1];
    size_t length;
    va_list copy;
    va_copy(copy, args);
    length = (size_t)wvsprintfW(scratch, format, copy);
    va_end(copy);
    if (length > count) {
        memcpy(buffer, scratch, count * sizeof(WCHAR));
        return -1;
    }
    memcpy(buffer, scratch, length * sizeof(WCHAR));
    if (length < count) buffer[length] = 0;
    return (int)length;
}

#include "extracted.c"

static int check_line(const char *expect_inside, size_t min_length)
{
    char text[8192];
    xp_from_wide(text, captured, captured_len + 1 < sizeof(text) ? captured_len + 1 : sizeof(text));
    printf("logged %zu characters\n", captured_len);
    if (captured_len < min_length || captured_len > 1024) {
        printf("FAIL: length outside the log buffer\n");
        return 1;
    }
    if (captured_len < 2 || captured[captured_len - 2] != '\r' || captured[captured_len - 1] != '\n') {
        printf("FAIL: line not terminated by CR LF\n");
        return 1;
    }
    if (!strstr(text, "11/12 23:59:58 [INFO] ") || !strstr(text, expect_inside)) {
        printf("FAIL: unexpected text: %.200s\n", text);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    static WCHAR name[4096];
    size_t i, n;
    const char *mode = argc > 1 ? argv[1] : "normal";
    if (!strcmp(mode, "normal")) {
        static const WCHAR domain[] = L"xp25.example";
        DsRolepLogPrintRoutine(DEB_TRACE, "DsRolerDcAsDc: DnsDomainName  %ws\n", domain);
        if (check_line("DsRolerDcAsDc: DnsDomainName  xp25.example", 20)) return 1;
        DsRolepLogPrintRoutine(DEB_TRACE, "\tOptions  %lu\n", (ULONG)7);
        printf("second line ok\n");
        return 0;
    }
    /* A caller-supplied name longer than the line: 3000 characters (the RPC interface
       accepts any length). "boundary" uses the longest name that still fits exactly. */
    n = !strcmp(mode, "long") ? 3000 : 1024 - 23 - 32 - 3;
    for (i = 0; i < n; i++) name[i] = (WCHAR)('a' + i % 26);
    name[n] = 0;
    DsRolepLogPrintRoutine(DEB_TRACE, "DsRolerDcAsDc: DnsDomainName  %ws\n", name);
    return check_line("DsRolerDcAsDc: DnsDomainName  abcdefghij", 500);
}
