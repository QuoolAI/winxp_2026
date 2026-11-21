/* MerlinClient.dll: memory, files, time, randomness, registry and text helpers. */
#include <windows.h>
#include <wincrypt.h>
#include "mc_internal.h"

void *mc_alloc(SIZE_T bytes) { return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytes); }
void mc_free(void *p) { if (p) HeapFree(GetProcessHeap(), 0, p); }
void MERLINAPI MerlinFree(void *p) { mc_free(p); }

char *mc_read_file(const WCHAR *path, DWORD max, DWORD *len, DWORD *error)
{
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD size, got = 0;
    char *data;
    *len = 0;
    *error = 0;
    if (f == INVALID_HANDLE_VALUE) {
        *error = GetLastError();
        return NULL;
    }
    size = GetFileSize(f, NULL);
    if (size == INVALID_FILE_SIZE || size > max) {
        CloseHandle(f);
        *error = ERROR_FILE_TOO_LARGE;
        return NULL;
    }
    data = (char *)mc_alloc(size + 1);
    if (!data) {
        CloseHandle(f);
        *error = ERROR_NOT_ENOUGH_MEMORY;
        return NULL;
    }
    if (size && (!ReadFile(f, data, size, &got, NULL) || got != size)) {
        *error = GetLastError() ? GetLastError() : ERROR_READ_FAULT;
        CloseHandle(f);
        mc_free(data);
        return NULL;
    }
    CloseHandle(f);
    data[size] = 0;
    *len = size;
    return data;
}

DWORD mc_write_file_atomic(const WCHAR *path, const void *data, DWORD len)
{
    WCHAR temp[MAX_PATH + 8];
    HANDLE f;
    DWORD wrote = 0, error = 0;
    if (lstrlenW(path) > MAX_PATH - 1) return ERROR_FILENAME_EXCED_RANGE;
    lstrcpyW(temp, path);
    lstrcatW(temp, L".tmp");
    f = CreateFileW(temp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return GetLastError();
    if (!WriteFile(f, data, len, &wrote, NULL) || wrote != len) error = GetLastError() ? GetLastError() : ERROR_WRITE_FAULT;
    if (!error && !FlushFileBuffers(f)) error = GetLastError();
    CloseHandle(f);
    if (!error && !MoveFileExW(temp, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) error = GetLastError();
    if (error) DeleteFileW(temp);
    return error;
}

BOOL mc_random(unsigned char *out, DWORD len)
{
    HCRYPTPROV prov;
    BOOL ok;
    if (!CryptAcquireContextW(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) return FALSE;
    ok = CryptGenRandom(prov, len, out);
    CryptReleaseContext(prov, 0);
    return ok;
}

void mc_random_hex(char *out, DWORD bytes)
{
    unsigned char raw[64];
    out[0] = 0;
    if (bytes > sizeof(raw)) bytes = sizeof(raw);
    if (!mc_random(raw, bytes)) {
        /* Without CryptoAPI there is no safe nonce; callers check for an empty result. */
        return;
    }
    merlin_append_hex(out, bytes * 2 + 1, raw, bytes);
    SecureZeroMemory(raw, sizeof(raw));
}

unsigned long mc_filetime_seconds(const FILETIME *ft)
{
    ULARGE_INTEGER v;
    v.LowPart = ft->dwLowDateTime;
    v.HighPart = ft->dwHighDateTime;
    if (v.QuadPart < MC_U64(116444736000000000)) return 0;
    return (unsigned long)((v.QuadPart - MC_U64(116444736000000000)) / MC_U64(10000000));
}

unsigned long mc_now(void)
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    return mc_filetime_seconds(&ft);
}

BOOL MERLINAPI MerlinUtf8ToWide(const char *in, WCHAR *out, int chars)
{
    if (chars <= 0) return FALSE;
    out[0] = 0;
    if (!MultiByteToWideChar(CP_UTF8, 0, in, -1, out, chars)) {
        out[chars - 1] = 0;
        return FALSE;
    }
    return TRUE;
}

BOOL MERLINAPI MerlinWideToUtf8(const WCHAR *in, char *out, int size)
{
    if (size <= 0) return FALSE;
    out[0] = 0;
    if (!WideCharToMultiByte(CP_UTF8, 0, in, -1, out, size, NULL, NULL)) {
        out[size - 1] = 0;
        return FALSE;
    }
    return TRUE;
}

BOOL MERLINAPI MerlinIsAdmin(void)
{
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    PSID admins = NULL;
    BOOL member = FALSE;
    if (!AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admins))
        return FALSE;
    if (!CheckTokenMembership(NULL, admins, &member)) member = FALSE;
    FreeSid(admins);
    return member;
}

void mc_identity_names(char *user, int user_size, char *computer, int computer_size)
{
    WCHAR name[260];
    DWORD n = 260;
    user[0] = computer[0] = 0;
    if (GetUserNameW(name, &n)) MerlinWideToUtf8(name, user, user_size);
    n = 260;
    if (GetComputerNameW(name, &n)) MerlinWideToUtf8(name, computer, computer_size);
}

void MERLINAPI MerlinRedact(char *utf8, DWORD size)
{
    char user[128], computer[128];
    MERLIN_REDACT ctx;
    mc_identity_names(user, sizeof(user), computer, sizeof(computer));
    ctx.user = user;
    ctx.computer = computer;
    merlin_redact(utf8, size, &ctx);
}

void MERLINAPI MerlinLogEvent(WORD type, const WCHAR *text)
{
    HANDLE log = RegisterEventSourceW(NULL, MERLIN_EVENT_SOURCE);
    if (!log) return;
    /* Event 1 of MerlinClient.dll's message table is "%1". */
    ReportEventW(log, type, 0, 1, NULL, 1, 0, &text, NULL);
    DeregisterEventSource(log);
}

DWORD mc_reg_read_string(HKEY root, const WCHAR *key, const WCHAR *name, WCHAR *out, DWORD chars)
{
    HKEY k;
    DWORD type, size = (chars - 1) * sizeof(WCHAR), error;
    out[0] = 0;
    error = (DWORD)RegOpenKeyExW(root, key, 0, KEY_QUERY_VALUE, &k);
    if (error) return error;
    error = (DWORD)RegQueryValueExW(k, name, NULL, &type, (BYTE *)out, &size);
    RegCloseKey(k);
    if (error) {
        out[0] = 0;
        return error;
    }
    if (type != REG_SZ && type != REG_EXPAND_SZ) {
        out[0] = 0;
        return ERROR_INVALID_DATA;
    }
    out[size / sizeof(WCHAR)] = 0;
    return 0;
}

DWORD mc_reg_read_dword(HKEY root, const WCHAR *key, const WCHAR *name, DWORD *value)
{
    HKEY k;
    DWORD type, size = sizeof(DWORD), error, v = 0;
    error = (DWORD)RegOpenKeyExW(root, key, 0, KEY_QUERY_VALUE, &k);
    if (error) return error;
    error = (DWORD)RegQueryValueExW(k, name, NULL, &type, (BYTE *)&v, &size);
    RegCloseKey(k);
    if (!error && (type != REG_DWORD || size != sizeof(DWORD))) error = ERROR_INVALID_DATA;
    if (!error) *value = v;
    return error;
}

DWORD mc_reg_write_dword(HKEY root, const WCHAR *key, const WCHAR *name, DWORD value)
{
    HKEY k;
    DWORD error = (DWORD)RegCreateKeyExW(root, key, 0, NULL, 0, KEY_SET_VALUE, NULL, &k, NULL);
    if (error) return error;
    error = (DWORD)RegSetValueExW(k, name, 0, REG_DWORD, (const BYTE *)&value, sizeof(value));
    RegCloseKey(k);
    return error;
}

DWORD mc_reg_write_string(HKEY root, const WCHAR *key, const WCHAR *name, const WCHAR *value)
{
    HKEY k;
    DWORD error = (DWORD)RegCreateKeyExW(root, key, 0, NULL, 0, KEY_SET_VALUE, NULL, &k, NULL);
    if (error) return error;
    error = (DWORD)RegSetValueExW(k, name, 0, REG_SZ, (const BYTE *)value, (DWORD)(lstrlenW(value) + 1) * sizeof(WCHAR));
    RegCloseKey(k);
    return error;
}
