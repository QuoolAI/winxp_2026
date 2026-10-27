/* XP25 AI runtime: native platform adapters (NT 5.1). */
#include <windows.h>
#include <shlobj.h>
#include <wincrypt.h>
#include <wincred.h>
#include <string.h>
#include "xp25_win.h"

#ifndef CSIDL_PROFILE
#define CSIDL_PROFILE 0x0028
#endif
#ifndef CSIDL_LOCAL_APPDATA
#define CSIDL_LOCAL_APPDATA 0x001c
#endif
#ifndef CRYPTPROTECT_UI_FORBIDDEN
#define CRYPTPROTECT_UI_FORBIDDEN 0x1
#endif

static const char entropy_text[] = "XP25-Agent-Protected-v1";
/* 1601-01-01 to 1970-01-01 in 100 ns units (0x019DB1DED53E8000); VC7 has no ULL suffix. */
#define EPOCH_DIFF ((((ULONGLONG)0x019DB1DEUL) << 32) | 0xD53E8000UL)

void xp25w_wipe(void *data, size_t size)
{
    volatile unsigned char *p = (volatile unsigned char *)data;
    while (size--) *p++ = 0;
}

WCHAR *xp25w_wide(const char *utf8)
{
    int n;
    WCHAR *out;
    if (!utf8) return NULL;
    n = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, NULL, 0);
    if (n <= 0) return NULL;
    out = (WCHAR *)xp25_alloc((size_t)n * sizeof(WCHAR));
    if (out && !MultiByteToWideChar(CP_UTF8, 0, utf8, -1, out, n)) { xp25_free(out); return NULL; }
    return out;
}

char *xp25w_utf8(const WCHAR *wide)
{
    int n;
    char *out;
    if (!wide) return NULL;
    n = WideCharToMultiByte(CP_UTF8, 0, wide, -1, NULL, 0, NULL, NULL);
    if (n <= 0) return NULL;
    out = (char *)xp25_alloc((size_t)n);
    if (out && !WideCharToMultiByte(CP_UTF8, 0, wide, -1, out, n, NULL, NULL)) { xp25_free(out); return NULL; }
    return out;
}

int xp25w_buf_wide(XP25_BUF *b, const WCHAR *wide)
{
    char *u = xp25w_utf8(wide);
    int ok = u != NULL && xp25_buf_puts(b, u);
    xp25_free(u);
    return ok;
}

void xp25w_copy_utf8(char *out, size_t size, const WCHAR *wide)
{
    if (!size) return;
    out[0] = 0;
    if (wide && !WideCharToMultiByte(CP_UTF8, 0, wide, -1, out, (int)size, NULL, NULL)) out[0] = 0;
    out[size - 1] = 0;
}

void xp25w_copy_wide(WCHAR *out, size_t count, const char *utf8)
{
    if (!count) return;
    out[0] = 0;
    if (utf8 && !MultiByteToWideChar(CP_UTF8, 0, utf8, -1, out, (int)count)) out[0] = 0;
    out[count - 1] = 0;
}

unsigned long xp25w_unix_time(const FILETIME *utc)
{
    ULARGE_INTEGER v;
    v.LowPart = utc->dwLowDateTime;
    v.HighPart = utc->dwHighDateTime;
    if (v.QuadPart < EPOCH_DIFF) return 0;
    return (unsigned long)((v.QuadPart - EPOCH_DIFF) / 10000000UL);
}

unsigned long xp25w_now(void)
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    return xp25w_unix_time(&ft);
}

long xp25w_bias_minutes(void)
{
    TIME_ZONE_INFORMATION tz;
    DWORD mode = GetTimeZoneInformation(&tz);
    long bias = tz.Bias;
    if (mode == TIME_ZONE_ID_DAYLIGHT) bias += tz.DaylightBias;
    else if (mode == TIME_ZONE_ID_STANDARD) bias += tz.StandardBias;
    return bias;
}

void xp25w_format_filetime(const FILETIME *utc, char out[20])
{
    FILETIME local;
    SYSTEMTIME st;
    out[0] = 0;
    if (!FileTimeToLocalFileTime(utc, &local) || !FileTimeToSystemTime(&local, &st)) return;
    out[0] = (char)('0' + st.wYear / 1000); out[1] = (char)('0' + (st.wYear / 100) % 10);
    out[2] = (char)('0' + (st.wYear / 10) % 10); out[3] = (char)('0' + st.wYear % 10); out[4] = '-';
    out[5] = (char)('0' + st.wMonth / 10); out[6] = (char)('0' + st.wMonth % 10); out[7] = '-';
    out[8] = (char)('0' + st.wDay / 10); out[9] = (char)('0' + st.wDay % 10); out[10] = ' ';
    out[11] = (char)('0' + st.wHour / 10); out[12] = (char)('0' + st.wHour % 10); out[13] = ':';
    out[14] = (char)('0' + st.wMinute / 10); out[15] = (char)('0' + st.wMinute % 10); out[16] = 0;
}

static void trim_slash(WCHAR *path)
{
    size_t n = lstrlenW(path);
    while (n > 3 && path[n - 1] == L'\\') path[--n] = 0;
}

static void long_form(WCHAR *path, size_t count)
{
    WCHAR full[MAX_PATH];
    DWORD n = GetLongPathNameW(path, full, MAX_PATH);
    if (n && n < MAX_PATH && n < count) lstrcpyW(path, full);
    trim_slash(path);
}

static void folder(int csidl, WCHAR *out)
{
    out[0] = 0;
    if (FAILED(SHGetFolderPathW(NULL, csidl, NULL, 0, out))) out[0] = 0;
    long_form(out, MAX_PATH);
}

int xp25w_paths(XP25W_PATHS *p)
{
    WCHAR *slash;
    WCHAR secret[MAX_PATH];
    memset(p, 0, sizeof(*p));
    folder(CSIDL_WINDOWS, p->windows);
    folder(CSIDL_PROFILE, p->profile);
    folder(CSIDL_PROGRAM_FILES, p->program_files);
    folder(CSIDL_PERSONAL, p->documents);
    folder(CSIDL_DESKTOPDIRECTORY, p->desktop);
    folder(CSIDL_APPDATA, p->app_data);
    folder(CSIDL_LOCAL_APPDATA, p->local_data);
    if (p->app_data[0] && lstrlenW(p->app_data) < MAX_PATH - 6) lstrcatW(p->app_data, L"\\XP25");
    if (p->local_data[0] && lstrlenW(p->local_data) < MAX_PATH - 6) lstrcatW(p->local_data, L"\\XP25");
    if (!GetTempPathW(MAX_PATH, p->temp)) p->temp[0] = 0;
    long_form(p->temp, MAX_PATH);
    lstrcpyW(p->profiles_root, p->profile);
    slash = wcsrchr(p->profiles_root, L'\\');
    if (slash && slash > p->profiles_root + 2) *slash = 0;
    lstrcpyW(secret, p->app_data);
    if (lstrlenW(secret) < MAX_PATH - 16) lstrcatW(secret, L"\\secrets.bin");
    xp25w_copy_utf8(p->u_windows, sizeof(p->u_windows), p->windows);
    xp25w_copy_utf8(p->u_profile, sizeof(p->u_profile), p->profile);
    xp25w_copy_utf8(p->u_profiles_root, sizeof(p->u_profiles_root), p->profiles_root);
    xp25w_copy_utf8(p->u_temp, sizeof(p->u_temp), p->temp);
    xp25w_copy_utf8(p->u_program_files, sizeof(p->u_program_files), p->program_files);
    xp25w_copy_utf8(p->u_secret, sizeof(p->u_secret), secret);
    p->policy.windows = p->u_windows;
    p->policy.profile = p->u_profile;
    p->policy.other_profiles_root = p->u_profiles_root;
    p->policy.temp = p->u_temp;
    p->policy.program_files = p->u_program_files;
    p->policy.secret_store = p->u_secret;
    if (p->app_data[0]) CreateDirectoryW(p->app_data, NULL);
    if (p->local_data[0]) CreateDirectoryW(p->local_data, NULL);
    return p->windows[0] && p->profile[0];
}

int xp25w_full_path(const char *utf8, WCHAR *out, size_t count, char *u_out, size_t u_size)
{
    WCHAR *wide = xp25w_wide(utf8);
    WCHAR *part;
    DWORD n;
    if (!wide) return 0;
    if (wcschr(wide, L'*') || wcschr(wide, L'?') || !wide[0]) { xp25_free(wide); return 0; }
    n = GetFullPathNameW(wide, (DWORD)count, out, &part);
    xp25_free(wide);
    if (!n || n >= count) return 0;
    long_form(out, count);
    if (u_out) xp25w_copy_utf8(u_out, u_size, out);
    return 1;
}

const char *xp25w_provider_name(XP25_PROVIDER_KIND kind)
{
    switch (kind) {
    case XP25_PROVIDER_GATEWAY: return "gateway";
    case XP25_PROVIDER_LOCAL: return "local";
    case XP25_PROVIDER_OPENAI: return "openai";
    default: return "offline";
    }
}

void xp25w_config_defaults(XP25_CONFIG *c)
{
    memset(c, 0, sizeof(*c));
    c->provider = XP25_PROVIDER_OFFLINE;
    c->api = 0;
    lstrcpyA(c->model, "gpt-4.1-mini");
    lstrcpyA(c->gateway_client, "xp25");
    c->timeout_seconds = 60;
    c->retries = 2;
    c->max_output_tokens = 1200;
    lstrcpynA(c->service_allowlist, xp25_default_service_allowlist, sizeof(c->service_allowlist));
    lstrcpyA(c->mascot, "builtin");
    c->ai_query_interpretation = 1;
    c->content_index = 1;
}

static void read_string(HKEY key, const WCHAR *name, char *out, size_t size)
{
    WCHAR value[1200];
    DWORD type, bytes = sizeof(value) - sizeof(WCHAR);
    if (RegQueryValueExW(key, name, NULL, &type, (BYTE *)value, &bytes) != ERROR_SUCCESS || type != REG_SZ) return;
    value[bytes / sizeof(WCHAR)] = 0;
    xp25w_copy_utf8(out, size, value);
}

static void read_dword(HKEY key, const WCHAR *name, long *out, long low, long high)
{
    DWORD type, value, bytes = sizeof(value);
    if (RegQueryValueExW(key, name, NULL, &type, (BYTE *)&value, &bytes) == ERROR_SUCCESS && type == REG_DWORD &&
        (long)value >= low && (long)value <= high) *out = (long)value;
}

int xp25w_config_load(XP25_CONFIG *c)
{
    HKEY key;
    char provider[32];
    long value;
    xp25w_config_defaults(c);
    if (RegOpenKeyExW(HKEY_CURRENT_USER, XP25_REG_ROOT, 0, KEY_READ, &key) == ERROR_SUCCESS) {
        provider[0] = 0;
        read_string(key, L"Provider", provider, sizeof(provider));
        if (!lstrcmpiA(provider, "gateway")) c->provider = XP25_PROVIDER_GATEWAY;
        else if (!lstrcmpiA(provider, "local")) c->provider = XP25_PROVIDER_LOCAL;
        else if (!lstrcmpiA(provider, "openai")) c->provider = XP25_PROVIDER_OPENAI;
        value = c->api; read_dword(key, L"Api", &value, 0, 1); c->api = (int)value;
        read_string(key, L"Endpoint", c->endpoint, sizeof(c->endpoint));
        read_string(key, L"Model", c->model, sizeof(c->model));
        read_string(key, L"GatewayClient", c->gateway_client, sizeof(c->gateway_client));
        read_dword(key, L"TimeoutSeconds", &c->timeout_seconds, 5, 600);
        read_dword(key, L"Retries", &c->retries, 0, 5);
        read_dword(key, L"MaxOutputTokens", &c->max_output_tokens, 64, 32000);
        read_string(key, L"Mascot", c->mascot, sizeof(c->mascot));
        value = c->ai_query_interpretation; read_dword(key, L"AiQueryInterpretation", &value, 0, 1);
        c->ai_query_interpretation = (int)value;
        value = c->content_index; read_dword(key, L"ContentIndex", &value, 0, 1); c->content_index = (int)value;
        read_string(key, L"IndexRoots", c->index_roots, sizeof(c->index_roots));
        read_string(key, L"IndexExcludes", c->index_excludes, sizeof(c->index_excludes));
        RegCloseKey(key);
    }
    /* Administrator policy: only HKLM can change which services may be controlled. */
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\XP25\\Agent\\Policy", 0, KEY_READ, &key) == ERROR_SUCCESS) {
        read_string(key, L"ServiceAllowlist", c->service_allowlist, sizeof(c->service_allowlist));
        RegCloseKey(key);
    }
    return 1;
}

static void write_string(HKEY key, const WCHAR *name, const char *value)
{
    WCHAR *wide = xp25w_wide(value ? value : "");
    if (wide) RegSetValueExW(key, name, 0, REG_SZ, (const BYTE *)wide, (DWORD)((lstrlenW(wide) + 1) * sizeof(WCHAR)));
    xp25_free(wide);
}

static void write_dword(HKEY key, const WCHAR *name, long value)
{
    DWORD v = (DWORD)value;
    RegSetValueExW(key, name, 0, REG_DWORD, (const BYTE *)&v, sizeof(v));
}

int xp25w_config_save(const XP25_CONFIG *c)
{
    HKEY key;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, XP25_REG_ROOT, 0, NULL, 0, KEY_WRITE, NULL, &key, NULL) != ERROR_SUCCESS)
        return 0;
    write_string(key, L"Provider", xp25w_provider_name(c->provider));
    write_dword(key, L"Api", c->api);
    write_string(key, L"Endpoint", c->endpoint);
    write_string(key, L"Model", c->model);
    write_string(key, L"GatewayClient", c->gateway_client);
    write_dword(key, L"TimeoutSeconds", c->timeout_seconds);
    write_dword(key, L"Retries", c->retries);
    write_dword(key, L"MaxOutputTokens", c->max_output_tokens);
    write_string(key, L"Mascot", c->mascot);
    write_dword(key, L"AiQueryInterpretation", c->ai_query_interpretation);
    write_dword(key, L"ContentIndex", c->content_index);
    write_string(key, L"IndexRoots", c->index_roots);
    write_string(key, L"IndexExcludes", c->index_excludes);
    RegCloseKey(key);
    return 1;
}

/* Credential Manager target for a protected setting: "XP25 Agent/<name>". */
static void cred_target(const WCHAR *name, WCHAR *out, size_t count)
{
    lstrcpynW(out, L"XP25 Agent/", (int)count);
    if ((size_t)lstrlenW(out) + (size_t)lstrlenW(name) < count) lstrcatW(out, name);
}

/* User-scope DPAPI first. Where it is unavailable (the accepted engineering
   image returns RPC_X_BAD_STUB_DATA for user-scope CryptProtectData), the
   per-user Windows Credential Manager holds the value instead. Machine-scope
   DPAPI is never used: any local process could decrypt it. */
int xp25w_secret_set(const WCHAR *name, const unsigned char *data, DWORD size)
{
    DATA_BLOB in, out, entropy;
    CREDENTIALW cred;
    WCHAR target[128];
    HKEY key;
    LONG status;
    DWORD dpapi_error;
    in.pbData = (BYTE *)data;
    in.cbData = size;
    entropy.pbData = (BYTE *)entropy_text;
    entropy.cbData = sizeof(entropy_text) - 1;
    if (CryptProtectData(&in, L"XP25 Agent protected setting", &entropy, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &out)) {
        status = RegCreateKeyExW(HKEY_CURRENT_USER, XP25_REG_SECRETS, 0, NULL, 0, KEY_WRITE, NULL, &key, NULL);
        if (status == ERROR_SUCCESS) {
            status = RegSetValueExW(key, name, 0, REG_BINARY, out.pbData, out.cbData);
            RegCloseKey(key);
        }
        LocalFree(out.pbData);
        if (status == ERROR_SUCCESS) {
            cred_target(name, target, 128);
            CredDeleteW(target, CRED_TYPE_GENERIC, 0);
        }
        SetLastError((DWORD)status);
        return status == ERROR_SUCCESS;
    }
    dpapi_error = GetLastError();
    memset(&cred, 0, sizeof(cred));
    cred_target(name, target, 128);
    cred.Type = CRED_TYPE_GENERIC;
    cred.TargetName = target;
    cred.Comment = L"XP25 Agent protected setting";
    cred.CredentialBlobSize = size;
    cred.CredentialBlob = (BYTE *)data;
    cred.Persist = CRED_PERSIST_LOCAL_MACHINE;
    cred.UserName = L"XP25 Agent";
    if (!CredWriteW(&cred, 0)) {
        SetLastError(dpapi_error);      /* report the primary mechanism's failure */
        return 0;
    }
    xp25w_secret_delete_dpapi(name);
    return 1;
}

int xp25w_secret_get(const WCHAR *name, unsigned char **data, DWORD *size)
{
    DATA_BLOB in, out, entropy;
    HKEY key;
    DWORD type, bytes = 0;
    BYTE *blob;
    CREDENTIALW *cred = NULL;
    WCHAR target[128];
    int ok = 0;
    *data = NULL;
    *size = 0;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, XP25_REG_SECRETS, 0, KEY_READ, &key) == ERROR_SUCCESS) {
        if (RegQueryValueExW(key, name, NULL, &type, NULL, &bytes) == ERROR_SUCCESS && type == REG_BINARY &&
            bytes && bytes < 65536 && (blob = (BYTE *)xp25_alloc(bytes)) != NULL) {
            if (RegQueryValueExW(key, name, NULL, &type, blob, &bytes) == ERROR_SUCCESS) {
                in.pbData = blob;
                in.cbData = bytes;
                entropy.pbData = (BYTE *)entropy_text;
                entropy.cbData = sizeof(entropy_text) - 1;
                if (CryptUnprotectData(&in, NULL, &entropy, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &out)) {
                    *data = (unsigned char *)xp25_alloc(out.cbData + 1);
                    if (*data) {
                        memcpy(*data, out.pbData, out.cbData);
                        *size = out.cbData;
                        ok = 1;
                    }
                    xp25w_wipe(out.pbData, out.cbData);
                    LocalFree(out.pbData);
                }
            }
            xp25_free(blob);
        }
        RegCloseKey(key);
    }
    if (ok) return 1;
    cred_target(name, target, 128);
    if (CredReadW(target, CRED_TYPE_GENERIC, 0, &cred) && cred) {
        if (cred->CredentialBlobSize && cred->CredentialBlobSize < 65536 &&
            (*data = (unsigned char *)xp25_alloc(cred->CredentialBlobSize + 1)) != NULL) {
            memcpy(*data, cred->CredentialBlob, cred->CredentialBlobSize);
            *size = cred->CredentialBlobSize;
            ok = 1;
        }
        xp25w_wipe(cred->CredentialBlob, cred->CredentialBlobSize);
        CredFree(cred);
    }
    return ok;
}

void xp25w_secret_free(unsigned char *data, DWORD size)
{
    if (data) xp25w_wipe(data, size);
    xp25_free(data);
}

int xp25w_secret_delete_dpapi(const WCHAR *name)
{
    HKEY key;
    LONG status;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, XP25_REG_SECRETS, 0, KEY_WRITE, &key) != ERROR_SUCCESS) return 1;
    status = RegDeleteValueW(key, name);
    RegCloseKey(key);
    return status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND;
}

int xp25w_secret_delete(const WCHAR *name)
{
    WCHAR target[128];
    cred_target(name, target, 128);
    if (!CredDeleteW(target, CRED_TYPE_GENERIC, 0) && GetLastError() != ERROR_NOT_FOUND) return 0;
    return xp25w_secret_delete_dpapi(name);
}

void xp25w_audit(const char *application, const char *json_line)
{
    XP25W_PATHS paths;
    WCHAR file[MAX_PATH], old[MAX_PATH];
    HANDLE h;
    XP25_BUF line;
    XP25_JW w;
    FILETIME now;
    char stamp[20];
    DWORD written, size;
    if (!xp25w_paths(&paths) || lstrlenW(paths.app_data) > MAX_PATH - 20) return;
    lstrcpyW(file, paths.app_data);
    lstrcatW(file, L"\\audit.jsonl");
    h = CreateFileW(file, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    size = GetFileSize(h, NULL);
    if (size != INVALID_FILE_SIZE && size > 4 * 1024 * 1024) {
        CloseHandle(h);
        lstrcpyW(old, paths.app_data);
        lstrcatW(old, L"\\audit.1.jsonl");
        MoveFileExW(file, old, MOVEFILE_REPLACE_EXISTING);
        h = CreateFileW(file, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) return;
    }
    GetSystemTimeAsFileTime(&now);
    xp25w_format_filetime(&now, stamp);
    xp25_buf_init(&line);
    xp25_jw_init(&w, &line);
    xp25_jw_obj(&w);
    xp25_jw_key(&w, "time"); xp25_jw_str(&w, stamp);
    xp25_jw_key(&w, "app"); xp25_jw_str(&w, application);
    xp25_jw_key(&w, "pid"); xp25_jw_u64(&w, (xp25_u64)GetCurrentProcessId());
    xp25_jw_key(&w, "record"); xp25_jw_raw(&w, json_line);
    xp25_jw_end(&w);
    xp25_buf_puts(&line, "\r\n");
    if (xp25_buf_ok(&line)) WriteFile(h, line.data, (DWORD)line.len, &written, NULL);
    xp25_buf_free(&line);
    CloseHandle(h);
}

int xp25w_is_admin(void)
{
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    PSID admins = NULL;
    BOOL member = FALSE;
    if (!AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admins))
        return 0;
    if (!CheckTokenMembership(NULL, admins, &member)) member = FALSE;
    FreeSid(admins);
    return member != FALSE;
}

DWORD xp25w_read_file(const WCHAR *path, char **data, DWORD max_bytes, int *truncated)
{
    HANDLE h;
    DWORD size, got = 0;
    *data = NULL;
    if (truncated) *truncated = 0;
    h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h == INVALID_HANDLE_VALUE) return (DWORD)-1;
    size = GetFileSize(h, NULL);
    if (size == INVALID_FILE_SIZE) { CloseHandle(h); return (DWORD)-1; }
    if (size > max_bytes) { size = max_bytes; if (truncated) *truncated = 1; }
    *data = (char *)xp25_alloc(size + 1);
    if (!*data) { CloseHandle(h); return (DWORD)-1; }
    if (!ReadFile(h, *data, size, &got, NULL)) got = 0;
    (*data)[got] = 0;
    CloseHandle(h);
    return got;
}

int xp25w_write_file_atomic(const WCHAR *path, const void *data, DWORD size)
{
    WCHAR temp[MAX_PATH + 40];
    HANDLE h;
    DWORD written = 0;
    BOOL ok;
    if (lstrlenW(path) >= MAX_PATH) return 0;
    /* A per-writer temporary name: concurrent writers never share it. */
    wsprintfW(temp, L"%s.%lu.%lu.new", path, GetCurrentProcessId(), GetCurrentThreadId());
    h = CreateFileW(temp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    ok = WriteFile(h, data, size, &written, NULL) && written == size && FlushFileBuffers(h);
    CloseHandle(h);
    if (!ok || !MoveFileExW(temp, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(temp);
        return 0;
    }
    return 1;
}
