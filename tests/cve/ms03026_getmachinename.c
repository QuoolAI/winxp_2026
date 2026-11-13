/* MS03-026 (CVE-2003-0352) regression: GetMachineName in rpcss.dll's DCOM activation
   (com/ole32/dcomss/olescm/actmisc.cxx), reached from a remote activation request that
   carries a UNC path. extracted.c holds GetMachineName verbatim, original or patched.

   For a UNC path (two leading backslashes) the function skips the drive / impersonation /
   DFS block entirely and copies the server name straight into the caller's
   wszMachineName[MAX_COMPUTERNAME_LENGTH+1] buffer. The stubs below satisfy the skipped
   block at compile time; they are never called on this path. The buffer is a real stack
   array so AddressSanitizer sees the overflow.

   usage: ms03026 valid|overflow|noseparator   exit 0 = expectations met */
#include "nt_shim.h"

#define MAX_COMPUTERNAME_LENGTH 15      /* NT 5.1 NetBIOS computer-name limit (the historical 16-char buffer) */
#define MAX_PATH 260
#define S_OK ((HRESULT)0)
#define S_FALSE ((HRESULT)1)
#define NO_ERROR 0L
#define DRIVE_REMOTE 4
#define UNIVERSAL_NAME_INFO_LEVEL 1
#define CO_E_SCM_RPC_FAILURE ((HRESULT)0x80080006L)
#define CO_E_BAD_PATH ((HRESULT)0x80080004L)
#define ARGUMENT_PRESENT_LOCAL(p) ((p) != NULL)

typedef struct { LPWSTR lpUniversalName; LPWSTR lpConnectionName; LPWSTR lpRemainingPath; } REMOTE_NAME_INFO;
typedef struct { LPWSTR lpUniversalName; } UNIVERSAL_NAME_INFO;
typedef void *RPC_BINDING_HANDLE;

/* Stubs for the non-UNC branch (never reached with a UNC path). */
static DWORD RpcImpersonateClient(RPC_BINDING_HANDLE h) { (void)h; return 0; }
static DWORD RpcRevertToSelf(void) { return 0; }
static UINT GetDriveType(LPWSTR d) { (void)d; return DRIVE_REMOTE; }
static DWORD ScmWNetGetUniversalName(LPWSTR p, DWORD l, void *b, DWORD *s) { (void)p; (void)l; (void)b; (void)s; return NO_ERROR; }
static LPWSTR lstrcpynW(LPWSTR d, const WCHAR *s, int n) { int i; for (i = 0; i + 1 < n && s[i]; i++) d[i] = s[i]; d[i] = 0; return d; }

HRESULT GetMachineName(WCHAR *pwszPath, WCHAR wszMachineName[MAX_COMPUTERNAME_LENGTH + 1]);

#include "extracted.c"

static int check(const char *label, const char *path, HRESULT want_status, const char *want_name)
{
    WCHAR wpath[4096], buffer[MAX_COMPUTERNAME_LENGTH + 1];
    char got[64];
    HRESULT rc;
    size_t i;
    xp_to_wide(wpath, path, sizeof(wpath) / sizeof(WCHAR));
    for (i = 0; i < MAX_COMPUTERNAME_LENGTH + 1; i++) buffer[i] = 0;
    rc = GetMachineName(wpath, buffer);
    xp_from_wide(got, buffer, sizeof(got));
    if (rc != want_status || (want_status == S_OK && strcmp(got, want_name))) {
        printf("FAIL %s: status 0x%08lx (want 0x%08lx) name '%s' (want '%s')\n", label,
               (unsigned long)rc, (unsigned long)want_status, got, want_name ? want_name : "");
        return 1;
    }
    printf("ok   %s -> 0x%08lx %s\n", label, (unsigned long)rc, want_status == S_OK ? got : "");
    return 0;
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "valid";
    if (!strcmp(mode, "valid"))
        return check("short server name", "\\\\server\\share\\dir", S_OK, "server");
    if (!strcmp(mode, "overflow")) {
        /* A UNC server name far longer than the computer-name buffer. */
        static char path[256];
        int i;
        path[0] = path[1] = '\\';
        for (i = 0; i < 100; i++) path[2 + i] = 'A' + i % 26;
        path[102] = '\\';
        path[103] = 's';
        path[104] = 0;
        /* Original: overflows wszMachineName. Patched: rejected with CO_E_BAD_PATH. */
        return check("100-char server name", path, CO_E_BAD_PATH, NULL);
    }
    if (!strcmp(mode, "noseparator")) {
        /* No backslash after the server name: the patched bound still stops. */
        return check("unterminated UNC", "\\\\AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", CO_E_BAD_PATH, NULL);
    }
    return 2;
}
