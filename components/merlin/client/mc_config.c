/* MerlinClient.dll: configuration (HKLM\SOFTWARE\XP25\MerlinAI) and the
   installation identity (HKLM\SOFTWARE\XP25\MerlinAI\Credentials, whose DACL
   admits only SYSTEM and Administrators). Model-provider and source-code
   credentials never exist on the guest: they belong to the builder. */
#include <windows.h>
#include <shlobj.h>
#include <sddl.h>
#include "mc_internal.h"

static void defaults(MERLIN_CONFIG *c)
{
    ZeroMemory(c, sizeof(*c));
    c->auto_collect = 1;
    c->collect_minutes = 30;
    c->retention_days = 90;
    c->notify_jobs = 1;
    c->collect_dumps = 1;
}

/* http://host[:port] with an optional path; no credentials, query or spaces. */
static BOOL endpoint_valid(const WCHAR *url)
{
    const WCHAR *c;
    if (!url[0]) return TRUE;
    if (lstrlenW(url) < 8 || lstrlenW(url) > 200 || (url[0] | 32) != L'h' || (url[1] | 32) != L't' || (url[2] | 32) != L't' ||
        (url[3] | 32) != L'p' || url[4] != L':' || url[5] != L'/' || url[6] != L'/')
        return FALSE;
    for (c = url; *c; ++c)
        if (*c <= L' ' || *c >= 0x7F || *c == L'@' || *c == L'?' || *c == L'#' || *c == L'\\') return FALSE;
    return TRUE;
}

BOOL MERLINAPI MerlinGetConfig(MERLIN_CONFIG *c)
{
    DWORD v;
    defaults(c);
    mc_reg_read_string(HKEY_LOCAL_MACHINE, MERLIN_REG_ROOT, L"Builder", c->builder, 256);
    mc_reg_read_string(HKEY_LOCAL_MACHINE, MERLIN_REG_ROOT, L"Deploy", c->deploy, 256);
    if (!endpoint_valid(c->builder)) c->builder[0] = 0;
    if (!endpoint_valid(c->deploy)) c->deploy[0] = 0;
    if (!mc_reg_read_dword(HKEY_LOCAL_MACHINE, MERLIN_REG_ROOT, L"AutoCollect", &v)) c->auto_collect = v != 0;
    if (!mc_reg_read_dword(HKEY_LOCAL_MACHINE, MERLIN_REG_ROOT, L"CollectMinutes", &v) && v <= 1440) c->collect_minutes = v;
    if (!mc_reg_read_dword(HKEY_LOCAL_MACHINE, MERLIN_REG_ROOT, L"RetentionDays", &v) && v >= 1 && v <= 3650) c->retention_days = v;
    if (!mc_reg_read_dword(HKEY_LOCAL_MACHINE, MERLIN_REG_ROOT, L"NotifyJobs", &v)) c->notify_jobs = v != 0;
    if (!mc_reg_read_dword(HKEY_LOCAL_MACHINE, MERLIN_REG_ROOT, L"CollectDumps", &v)) c->collect_dumps = v != 0;
    return TRUE;
}

DWORD MERLINAPI MerlinSetConfig(const MERLIN_CONFIG *c)
{
    DWORD e;
    if (!MerlinIsAdmin()) return ERROR_ACCESS_DENIED;
    if (!endpoint_valid(c->builder) || !endpoint_valid(c->deploy) || c->collect_minutes > 1440 || c->retention_days < 1 ||
        c->retention_days > 3650)
        return ERROR_INVALID_PARAMETER;
    if ((e = mc_reg_write_string(HKEY_LOCAL_MACHINE, MERLIN_REG_ROOT, L"Builder", c->builder)) != 0) return e;
    if ((e = mc_reg_write_string(HKEY_LOCAL_MACHINE, MERLIN_REG_ROOT, L"Deploy", c->deploy)) != 0) return e;
    if ((e = mc_reg_write_dword(HKEY_LOCAL_MACHINE, MERLIN_REG_ROOT, L"AutoCollect", c->auto_collect != 0)) != 0) return e;
    if ((e = mc_reg_write_dword(HKEY_LOCAL_MACHINE, MERLIN_REG_ROOT, L"CollectMinutes", c->collect_minutes)) != 0) return e;
    if ((e = mc_reg_write_dword(HKEY_LOCAL_MACHINE, MERLIN_REG_ROOT, L"RetentionDays", c->retention_days)) != 0) return e;
    if ((e = mc_reg_write_dword(HKEY_LOCAL_MACHINE, MERLIN_REG_ROOT, L"NotifyJobs", c->notify_jobs != 0)) != 0) return e;
    return mc_reg_write_dword(HKEY_LOCAL_MACHINE, MERLIN_REG_ROOT, L"CollectDumps", c->collect_dumps != 0);
}

DWORD MERLINAPI MerlinGetIdentity(MERLIN_IDENTITY *id)
{
    HKEY k;
    DWORD error, type, size;
    WCHAR name[80];
    ZeroMemory(id, sizeof(*id));
    error = (DWORD)RegOpenKeyExW(HKEY_LOCAL_MACHINE, MERLIN_REG_CREDENTIALS, 0, KEY_QUERY_VALUE, &k);
    if (error) return error;
    size = sizeof(name) - sizeof(WCHAR);
    if (!RegQueryValueExW(k, L"Installation", NULL, &type, (BYTE *)name, &size) && type == REG_SZ) {
        name[size / sizeof(WCHAR)] = 0;
        MerlinWideToUtf8(name, id->installation, sizeof(id->installation));
        if (!merlin_token_valid(id->installation, 64)) id->installation[0] = 0;
    }
    size = MERLIN_KEY_BYTES;
    id->has_builder_key = !RegQueryValueExW(k, L"BuilderKey", NULL, &type, id->builder_key, &size) && type == REG_BINARY &&
                          size == MERLIN_KEY_BYTES;
    size = MERLIN_KEY_BYTES;
    id->has_deploy_key = !RegQueryValueExW(k, L"DeployKey", NULL, &type, id->deploy_key, &size) && type == REG_BINARY &&
                         size == MERLIN_KEY_BYTES;
    RegCloseKey(k);
    if (!id->installation[0]) return ERROR_NOT_FOUND;
    return 0;
}

static int hex_key(const char *hex, unsigned char out[MERLIN_KEY_BYTES])
{
    int i;
    if (!merlin_hex_valid(hex, 64)) return 0;
    for (i = 0; i < MERLIN_KEY_BYTES; ++i) {
        int hi = hex[2 * i] <= '9' ? hex[2 * i] - '0' : hex[2 * i] - 'a' + 10;
        int lo = hex[2 * i + 1] <= '9' ? hex[2 * i + 1] - '0' : hex[2 * i + 1] - 'a' + 10;
        out[i] = (unsigned char)(hi * 16 + lo);
    }
    return 1;
}

DWORD MERLINAPI MerlinSetIdentity(const char *installation, const char *builder_hex, const char *deploy_hex)
{
    SECURITY_ATTRIBUTES sa;
    PSECURITY_DESCRIPTOR sd = NULL;
    HKEY k;
    DWORD error;
    unsigned char key[MERLIN_KEY_BYTES];
    WCHAR name[80];
    if (!MerlinIsAdmin()) return ERROR_ACCESS_DENIED;
    if (!merlin_token_valid(installation, 64)) return ERROR_INVALID_PARAMETER;
    if ((builder_hex && builder_hex[0] && !merlin_hex_valid(builder_hex, 64)) || (deploy_hex && deploy_hex[0] && !merlin_hex_valid(deploy_hex, 64)))
        return ERROR_INVALID_PARAMETER;
    /* Protected DACL: SYSTEM and Administrators only; standard users cannot read the keys. */
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)", SDDL_REVISION_1, &sd, NULL))
        return GetLastError();
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = sd;
    sa.bInheritHandle = FALSE;
    error = (DWORD)RegCreateKeyExW(HKEY_LOCAL_MACHINE, MERLIN_REG_CREDENTIALS, 0, NULL, 0, KEY_SET_VALUE | WRITE_DAC, &sa, &k, NULL);
    if (!error) {
        /* An existing key keeps its own DACL from creation; enforce it anyway. */
        error = (DWORD)RegSetKeySecurity(k, DACL_SECURITY_INFORMATION, sd);
        MerlinUtf8ToWide(installation, name, 80);
        if (!error) error = (DWORD)RegSetValueExW(k, L"Installation", 0, REG_SZ, (const BYTE *)name, (DWORD)(lstrlenW(name) + 1) * sizeof(WCHAR));
        if (!error && builder_hex && builder_hex[0] && hex_key(builder_hex, key))
            error = (DWORD)RegSetValueExW(k, L"BuilderKey", 0, REG_BINARY, key, MERLIN_KEY_BYTES);
        if (!error && deploy_hex && deploy_hex[0] && hex_key(deploy_hex, key))
            error = (DWORD)RegSetValueExW(k, L"DeployKey", 0, REG_BINARY, key, MERLIN_KEY_BYTES);
        RegCloseKey(k);
    }
    SecureZeroMemory(key, sizeof(key));
    LocalFree(sd);
    return error;
}

BOOL MERLINAPI MerlinQueueDirectory(WCHAR *path, DWORD chars)
{
    WCHAR base[MAX_PATH];
    if (chars < MAX_PATH || FAILED(SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, SHGFP_TYPE_CURRENT, base))) return FALSE;
    if (lstrlenW(base) > MAX_PATH - 40) return FALSE;
    lstrcpyW(path, base);
    lstrcatW(path, L"\\XP25\\MerlinAI\\Queue");
    return TRUE;
}

BOOL mc_queue_path(const char *name, WCHAR *path, DWORD chars)
{
    WCHAR wname[80];
    if (!MerlinQueueDirectory(path, chars) || lstrlenA(name) > 70) return FALSE;
    MerlinUtf8ToWide(name, wname, 80);
    if ((DWORD)(lstrlenW(path) + lstrlenW(wname) + 2) > chars) return FALSE;
    lstrcatW(path, L"\\");
    lstrcatW(path, wname);
    return TRUE;
}
