/* MS08-067 (CVE-2008-4250) regression: path canonicalization in netapi32.dll
   (ds/netapi/netlib/canon.c), reached remotely through the Server service's
   NetprPathCanonicalize -> NetpwPathCanonicalize -> CanonicalizePathName.

   extracted.c (written by tests/test_cve.py) holds CanonicalizePathName and its helpers
   verbatim, original or patched. The Rtl path-type helpers are modelled after their
   documented NT behaviour for the inputs used here (drive, UNC, relative, DOS devices).

   usage: ms08067 valid|traversal|prefix   exit 0 = every expectation met */
#include "nt_shim.h"

#define UNICODE 1
#define MAX_PATH 260
#define NERR_Success 0
#define NERR_BufTooSmall 2123
#define ERROR_INVALID_NAME 123
typedef DWORD NET_API_STATUS;
typedef enum { RtlPathTypeUnknown, RtlPathTypeUncAbsolute, RtlPathTypeDriveAbsolute, RtlPathTypeDriveRelative,
               RtlPathTypeRooted, RtlPathTypeRelative, RtlPathTypeLocalDevice, RtlPathTypeRootLocalDevice } RTL_PATH_TYPE;

#define TCHAR_EOS ((TCHAR)'\0')
#define TCHAR_BACKSLASH ((TCHAR)'\\')
#define TCHAR_FWDSLASH ((TCHAR)'/')
#define TCHAR_COLON ((TCHAR)':')
#define TCHAR_DOT ((TCHAR)'.')
#define IS_PATH_SEPARATOR(ch) ((ch == TCHAR_BACKSLASH) || (ch == TCHAR_FWDSLASH))

static WCHAR upper(WCHAR c) { return (c >= 'a' && c <= 'z') ? (WCHAR)(c - 32) : c; }
static int xp_wcsnicmp(const WCHAR *a, const WCHAR *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        WCHAR x = upper(a[i]), y = upper(b[i]);
        if (x != y) return x < y ? -1 : 1;
        if (!x) return 0;
    }
    return 0;
}
static int xp_wcsicmp(const WCHAR *a, const WCHAR *b) { return xp_wcsnicmp(a, b, (size_t)-1); }
static WCHAR *xp_wcsupr(WCHAR *s) { WCHAR *p = s; for (; *p; p++) *p = upper(*p); return s; }

#define STRLEN(s) ((DWORD)xp_wcslen(s))
#define STRCPY(d, s) xp_wcscpy((d), (s))
#define STRCAT(d, s) xp_wcscat((d), (s))
#define STRICMP(a, b) xp_wcsicmp((a), (b))
#define STRNICMP(a, b, n) xp_wcsnicmp((a), (b), (n))
#define STRUPR(s) xp_wcsupr(s)
#define TOUPPER(c) upper(c)
#define STRSIZE(p) ((STRLEN(p) + 1) * sizeof(TCHAR))

/* RtlIsDosDeviceName_U: non-zero for a reserved DOS device name, optionally with a colon. */
static ULONG RtlIsDosDeviceName_U(const WCHAR *path)
{
    static const char *const names[] = {"PRN", "AUX", "NUL", "CON", "COM1", "COM2", "COM3", "COM4", "LPT1", "LPT2", "LPT3", 0};
    const WCHAR *base = path, *p;
    WCHAR name[16];
    size_t n = 0;
    int i;
    for (p = path; *p; p++) if (*p == '\\' || *p == '/' || *p == ':') { if (*p != ':' || p[1]) base = p + 1; }
    while (base[n] && base[n] != ':' && n < 15) { name[n] = upper(base[n]); n++; }
    name[n] = 0;
    for (i = 0; names[i]; i++) {
        WCHAR w[8];
        xp_to_wide(w, names[i], 8);
        if (!xp_wcsicmp(name, w)) return 1;
    }
    return 0;
}

static RTL_PATH_TYPE RtlDetermineDosPathNameType_U(const WCHAR *p)
{
    if (IS_PATH_SEPARATOR(p[0])) return IS_PATH_SEPARATOR(p[1]) ? RtlPathTypeUncAbsolute : RtlPathTypeRooted;
    if (p[0] && p[1] == ':') return IS_PATH_SEPARATOR(p[2]) ? RtlPathTypeDriveAbsolute : RtlPathTypeDriveRelative;
    return RtlPathTypeRelative;
}

const TCHAR text_AUX[] = L"AUX";
const TCHAR text_COM[] = L"COM";
const TCHAR text_DEV[] = L"DEV";
const TCHAR text_LPT[] = L"LPT";
const TCHAR text_PRN[] = L"PRN";

STATIC VOID ConvertPathCharacters(LPTSTR Path);
STATIC BOOL ConvertDeviceName(LPTSTR PathName);
STATIC BOOL ParseLocalDevicePrefix(LPTSTR *DeviceName);
STATIC BOOL ConvertPathMacros(LPTSTR Path);
STATIC LPTSTR BackUpPath(LPTSTR Stopper, LPTSTR Path);
NET_API_STATUS CanonicalizePathName(LPTSTR PathPrefix, LPTSTR PathName, LPTSTR Buffer, DWORD BufferSize, LPDWORD RequiredSize);

#include "extracted.c"

static int failures;

static void expect(const char *prefix, const char *path, DWORD status, const char *result)
{
    WCHAR wprefix[1200], wpath[1200], out[MAX_PATH * 2 + 1];
    char got[1200];
    DWORD rc, required = 0;
    xp_to_wide(wprefix, prefix ? prefix : "", sizeof(wprefix) / sizeof(WCHAR));
    xp_to_wide(wpath, path, sizeof(wpath) / sizeof(WCHAR));
    out[0] = 0;
    rc = CanonicalizePathName(prefix ? wprefix : NULL, wpath, out, sizeof(out), &required);
    xp_from_wide(got, out, sizeof(got));
    if (rc != status || (status == NERR_Success && strcmp(got, result))) {
        printf("FAIL %s + %.60s: status %u (want %u) result '%s' (want '%s')\n", prefix ? prefix : "-", path,
               (unsigned)rc, (unsigned)status, got, result ? result : "");
        failures++;
    } else {
        printf("ok   %s + %.60s -> %u %s\n", prefix ? prefix : "-", path, (unsigned)rc, status == NERR_Success ? got : "");
    }
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "valid";
    if (!strcmp(mode, "valid")) {
        /* Inputs that both the original and the patched function handle identically: a '..' never
           backs up past the first component here, so the original does not read before the buffer. */
        expect(NULL, "d:\\alpha\\beta\\gamma\\..\\delta", NERR_Success, "D:\\alpha\\beta\\delta");
        expect(NULL, "\\\\server\\share\\dir\\..\\file.txt", NERR_Success, "\\\\server\\share\\file.txt");
        expect(NULL, "\\\\server\\share\\.\\a\\.\\b", NERR_Success, "\\\\server\\share\\a\\b");
        expect(NULL, "c:/windows/system32/../explorer.exe", NERR_Success, "C:\\windows\\explorer.exe");
        expect(NULL, "a\\b\\..\\c", NERR_Success, "a\\c");
        expect("c:\\work", "notes\\..\\todo.txt", NERR_Success, "C:\\work\\todo.txt");
        expect(NULL, "prn", NERR_Success, "LPT1");
        expect(NULL, "\\\\server", ERROR_INVALID_NAME, NULL);
        expect(NULL, "c:\\a\\\\b", ERROR_INVALID_NAME, NULL);
        return failures != 0;
    }
    if (!strcmp(mode, "recovered")) {
        /* A '..' that removes the very first component: the correct result is well defined, but
           reaching it makes the original back the search pointer up before the buffer. The patched
           function returns the right path instead of reading out of bounds. Patched build only. */
        expect(NULL, "\\a\\..\\x", NERR_Success, "\\x");
        expect(NULL, "/a/../x", NERR_Success, "\\x");
        expect(NULL, "\\alpha\\..\\beta\\gamma", NERR_Success, "\\beta\\gamma");
        return failures != 0;
    }
    if (!strcmp(mode, "traversal")) {
        /* more ".." than components, after a leading separator: the historical trigger shape.
           The original reads before the buffer; the patched function returns ERROR_INVALID_NAME. */
        expect(NULL, "\\a\\..\\..\\x", ERROR_INVALID_NAME, NULL);
        expect(NULL, "\\c\\..\\..\\xxxxxxxxxxxxxxxx", ERROR_INVALID_NAME, NULL);
        expect(NULL, "/a/../../x", ERROR_INVALID_NAME, NULL);
        return failures != 0;
    }
    if (!strcmp(mode, "prefix")) {
        /* a prefix of exactly MAX_PATH*2 characters without a trailing separator */
        static char prefix[MAX_PATH * 2 + 1];
        memset(prefix, 'p', MAX_PATH * 2);
        prefix[0] = 'c'; prefix[1] = ':'; prefix[2] = '\\';
        expect(prefix, "x", ERROR_INVALID_NAME, NULL);
        prefix[MAX_PATH * 2 - 1] = 0;
        expect(prefix, "", ERROR_INVALID_NAME, NULL);
        return failures != 0;
    }
    return 2;
}
