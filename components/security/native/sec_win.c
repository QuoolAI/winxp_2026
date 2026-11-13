/* XP25 security baseline and audit: native NT 5.1 helpers. See sec_win.h. */
#include "sec_win.h"
#include <shellapi.h>
#include <string.h>

static void write_all(HANDLE handle, const char *data, DWORD size)
{
    DWORD done;
    while (size && WriteFile(handle, data, size, &done, NULL) && done) { data += done; size -= done; }
}

void secw_error_text(const char *what, DWORD error)
{
    char line[320];
    HANDLE err = GetStdHandle(STD_ERROR_HANDLE);
    wsprintfA(line, "%.200s (error %lu)\r\n", what, error);
    if (err && err != INVALID_HANDLE_VALUE) write_all(err, line, (DWORD)lstrlenA(line));
}

WCHAR **secw_arguments(int *count)
{
    return CommandLineToArgvW(GetCommandLineW(), count);
}

void secw_utf8(const WCHAR *wide, char *out, int size)
{
    int n;
    if (size <= 0) return;
    out[0] = 0;
    if (!wide) return;
    n = WideCharToMultiByte(CP_UTF8, 0, wide, -1, out, size, NULL, NULL);
    if (!n) {
        /* Too long: convert what fits and end on a character boundary. */
        int chars = lstrlenW(wide);
        while (chars > 0 && !n) {
            n = WideCharToMultiByte(CP_UTF8, 0, wide, chars, out, size - 1, NULL, NULL);
            chars = chars * 3 / 4;
        }
        out[n] = 0;
    }
}

void secw_wide(const char *utf8, WCHAR *out, int count)
{
    if (count <= 0) return;
    out[0] = 0;
    if (utf8 && !MultiByteToWideChar(CP_UTF8, 0, utf8, -1, out, count)) out[0] = 0;
}

BOOL secw_sink_open(SECW_SINK *sink, int argc, WCHAR **argv, int first)
{
    int i;
    BOOL serial = FALSE, quiet = FALSE;
    ZeroMemory(sink, sizeof(*sink));
    sink->file = sink->serial = sink->console = INVALID_HANDLE_VALUE;
    for (i = first; i < argc; ++i) {
        if (!lstrcmpW(argv[i], L"--serial")) serial = TRUE;
        else if (!lstrcmpW(argv[i], L"--quiet")) quiet = TRUE;
        else if (!lstrcmpW(argv[i], L"--out") && i + 1 < argc) {
            sink->file = CreateFileW(argv[++i], GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (sink->file == INVALID_HANDLE_VALUE) { secw_error_text("cannot create the output file", GetLastError()); return FALSE; }
        } else if (argv[i][0] == L'-' && argv[i][1] == L'-' && lstrcmpW(argv[i], L"--privileged") &&
                   lstrcmpW(argv[i], L"--modules") && lstrcmpW(argv[i], L"--events") && lstrcmpW(argv[i], L"--from")) {
            secw_error_text("unknown option", ERROR_INVALID_PARAMETER);
            return FALSE;
        }
    }
    if (serial) sink->serial = CreateFileW(L"COM1", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (!quiet) sink->console = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!sink->console) sink->console = INVALID_HANDLE_VALUE;
    return TRUE;
}

void secw_sink_close(SECW_SINK *sink)
{
    if (sink->file != INVALID_HANDLE_VALUE) CloseHandle(sink->file);
    if (sink->serial != INVALID_HANDLE_VALUE) CloseHandle(sink->serial);
    sink->file = sink->serial = INVALID_HANDLE_VALUE;
}

void secw_emit(SECW_SINK *sink, SEC_JSON *json)
{
    size_t n = sec_json_end(json);
    if (!n) { ++sink->dropped; return; }
    ++sink->lines;
    if (sink->file != INVALID_HANDLE_VALUE) write_all(sink->file, json->data, (DWORD)n);
    if (sink->serial != INVALID_HANDLE_VALUE) write_all(sink->serial, json->data, (DWORD)n);
    if (sink->console != INVALID_HANDLE_VALUE) write_all(sink->console, json->data, (DWORD)n);
}

BOOL secw_is_admin(void)
{
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    PSID admins = NULL;
    BOOL member = FALSE;
    if (!AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admins)) return FALSE;
    /* A deny-only Administrators SID (restricted token) is not membership. */
    if (!CheckTokenMembership(NULL, admins, &member)) member = FALSE;
    FreeSid(admins);
    return member;
}

BOOL secw_enable_privilege(const WCHAR *name)
{
    HANDLE token;
    TOKEN_PRIVILEGES p;
    BOOL ok;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) return FALSE;
    ZeroMemory(&p, sizeof(p));
    p.PrivilegeCount = 1;
    p.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    ok = LookupPrivilegeValueW(NULL, name, &p.Privileges[0].Luid);
    if (ok) {
        SetLastError(0);
        ok = AdjustTokenPrivileges(token, FALSE, &p, 0, NULL, NULL) && GetLastError() == ERROR_SUCCESS;
    }
    CloseHandle(token);
    return ok;
}

void secw_sid_string(PSID sid, char *out, int size)
{
    WCHAR *text = NULL;
    if (size > 0) out[0] = 0;
    if (sid && IsValidSid(sid) && ConvertSidToStringSidW(sid, &text)) {
        secw_utf8(text, out, size);
        LocalFree(text);
    }
}

void secw_account(PSID sid, char *out, int size)
{
    WCHAR name[128], domain[128], both[260];
    DWORD n = 128, d = 128;
    SID_NAME_USE use;
    if (size > 0) out[0] = 0;
    if (!sid || !IsValidSid(sid)) return;
    if (LookupAccountSidW(NULL, sid, name, &n, domain, &d, &use)) {
        wsprintfW(both, domain[0] ? L"%s\\%s" : L"%s%s", domain, name);
        secw_utf8(both, out, size);
    } else secw_sid_string(sid, out, size);
}

static void time_text(const SYSTEMTIME *t, char *out, int size)
{
    char text[32];
    wsprintfA(text, "%04u-%02u-%02uT%02u:%02u:%02uZ", t->wYear, t->wMonth, t->wDay, t->wHour, t->wMinute, t->wSecond);
    lstrcpynA(out, text, size);
}

void secw_utc_now(char *out, int size)
{
    SYSTEMTIME t;
    GetSystemTime(&t);
    time_text(&t, out, size);
}

void secw_filetime_text(const FILETIME *time, char *out, int size)
{
    SYSTEMTIME t;
    if (size > 0) out[0] = 0;
    if (FileTimeToSystemTime(time, &t)) time_text(&t, out, size);
}

BOOL secw_store_path(const WCHAR *name, WCHAR *out, int count)
{
    UINT n = GetWindowsDirectoryW(out, (UINT)count);
    if (!n || n + 16 + (name ? lstrlenW(name) + 1 : 0) >= (UINT)count) return FALSE;
    lstrcatW(out, L"\\XP25\\Security");
    if (name) { lstrcatW(out, L"\\"); lstrcatW(out, name); }
    return TRUE;
}

static DWORD protect(WCHAR *object, SE_OBJECT_TYPE type, const WCHAR *sddl)
{
    PSECURITY_DESCRIPTOR sd = NULL;
    PACL dacl = NULL;
    PSID owner = NULL;
    BOOL present = FALSE, defaulted = FALSE;
    DWORD error;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd, NULL)) return GetLastError();
    if (!GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) || !GetSecurityDescriptorOwner(sd, &owner, &defaulted))
        error = GetLastError();
    else error = SetNamedSecurityInfoW(object, type, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION |
                                       PROTECTED_DACL_SECURITY_INFORMATION, owner, NULL, dacl, NULL);
    LocalFree(sd);
    return error;
}

DWORD secw_store_prepare(void)
{
    WCHAR path[MAX_PATH], parent[MAX_PATH], key[] = L"MACHINE\\" SECW_STORE_KEY;
    HKEY handle;
    DWORD error, attributes;
    if (!secw_store_path(NULL, path, MAX_PATH)) return ERROR_BUFFER_OVERFLOW;
    lstrcpyW(parent, path);
    parent[lstrlenW(parent) - 9] = 0;            /* strip \Security */
    if (!CreateDirectoryW(parent, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) return GetLastError();
    if (!CreateDirectoryW(path, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) return GetLastError();
    /* A junction planted under the Windows directory must not redirect the store. */
    attributes = GetFileAttributesW(path);
    if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) return ERROR_INVALID_DATA;
    attributes = GetFileAttributesW(parent);
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) return ERROR_INVALID_DATA;
    /* Taking ownership back needs the privilege when the object was planted by someone else. */
    secw_enable_privilege(SE_TAKE_OWNERSHIP_NAME);
    secw_enable_privilege(SE_RESTORE_NAME);
    error = protect(parent, SE_FILE_OBJECT, L"O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)");
    if (!error) error = protect(path, SE_FILE_OBJECT, L"O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)");
    if (error) return error;
    error = (DWORD)RegCreateKeyExW(HKEY_LOCAL_MACHINE, SECW_BASELINE_KEY, 0, NULL, 0, KEY_READ, NULL, &handle, NULL);
    if (error) return error;
    RegCloseKey(handle);
    return protect(key, SE_REGISTRY_KEY, L"O:BAD:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;BU)");
}

unsigned secw_dacl_writers(PACL dacl, BOOL present, DWORD write_mask)
{
    static const struct { const WCHAR *sid; unsigned who; } principals[] = {
        {L"S-1-1-0", SECW_WHO_EVERYONE}, {L"S-1-5-32-545", SECW_WHO_USERS}, {L"S-1-5-11", SECW_WHO_AUTHENTICATED},
        {L"S-1-5-4", SECW_WHO_INTERACTIVE}, {L"S-1-5-32-546", SECW_WHO_GUESTS}, {L"S-1-5-7", SECW_WHO_ANONYMOUS},
        {L"S-1-5-32-547", SECW_WHO_POWER_USERS}
    };
    unsigned allowed = 0, denied = 0, p;
    DWORD i;
    if (!present || !dacl) return SECW_WHO_NULL_DACL;
    /* GENERIC_WRITE and GENERIC_ALL in an ACE always include modification rights. */
    for (i = 0; i < dacl->AceCount; ++i) {
        ACE_HEADER *header;
        ACCESS_ALLOWED_ACE *ace;
        DWORD mask;
        if (!GetAce(dacl, i, (void **)&header)) continue;
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE && header->AceType != ACCESS_DENIED_ACE_TYPE) continue;
        if (header->AceFlags & INHERIT_ONLY_ACE) continue;
        ace = (ACCESS_ALLOWED_ACE *)header;
        mask = ace->Mask;
        if (mask & (GENERIC_WRITE | GENERIC_ALL)) mask |= write_mask;
        if (!(mask & write_mask)) continue;
        {
            /* S-1-5-21-<machine or domain>-<rid>: a named user or group account. */
            SID *named = (SID *)&ace->SidStart;
            static const SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
            if (header->AceType == ACCESS_ALLOWED_ACE_TYPE && named->SubAuthorityCount >= 2 && named->SubAuthority[0] == 21 &&
                !memcmp(&named->IdentifierAuthority, &nt, sizeof(nt))) allowed |= SECW_WHO_INDIVIDUAL;
        }
        for (p = 0; p < sizeof(principals) / sizeof(principals[0]); ++p) {
            PSID sid = NULL;
            if (!ConvertStringSidToSidW(principals[p].sid, &sid)) continue;
            if (EqualSid(sid, (PSID)&ace->SidStart)) {
                /* An earlier deny of the whole write set removes a later allow. */
                if (header->AceType == ACCESS_DENIED_ACE_TYPE) {
                    if ((mask & write_mask) == write_mask && !(allowed & principals[p].who)) denied |= principals[p].who;
                } else if (!(denied & principals[p].who)) allowed |= principals[p].who;
            }
            LocalFree(sid);
        }
    }
    return allowed;
}

DWORD secw_object_writers(const WCHAR *name, SE_OBJECT_TYPE type, DWORD write_mask, unsigned *who)
{
    PSECURITY_DESCRIPTOR sd = NULL;
    PACL dacl = NULL;
    WCHAR copy[600];
    DWORD error;
    *who = 0;
    if (lstrlenW(name) >= 600) return ERROR_BUFFER_OVERFLOW;
    lstrcpyW(copy, name);
    error = GetNamedSecurityInfoW(copy, type, DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, &sd);
    if (error) return error;
    *who = secw_dacl_writers(dacl, TRUE, write_mask);
    LocalFree(sd);
    return ERROR_SUCCESS;
}

void secw_who_text(unsigned who, char *out, int size)
{
    static const struct { unsigned who; const char *name; } names[] = {
        {SECW_WHO_NULL_DACL, "everyone (no DACL)"}, {SECW_WHO_EVERYONE, "Everyone"}, {SECW_WHO_USERS, "Users"},
        {SECW_WHO_AUTHENTICATED, "Authenticated Users"}, {SECW_WHO_INTERACTIVE, "INTERACTIVE"}, {SECW_WHO_GUESTS, "Guests"},
        {SECW_WHO_ANONYMOUS, "ANONYMOUS LOGON"}, {SECW_WHO_POWER_USERS, "Power Users"},
        {SECW_WHO_INDIVIDUAL, "an individual account"}, {SECW_OWNER_NOT_SYSTEM, "its owner (not SYSTEM or Administrators)"}
    };
    char text[200];
    unsigned i;
    text[0] = 0;
    for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
        if (who & names[i].who) {
            if (text[0]) lstrcatA(text, ", ");
            lstrcatA(text, names[i].name);
        }
    lstrcpynA(out, text, size);
}

DWORD secw_reg_read(HKEY root, const char *key, const char *value, DWORD *type, BYTE *data, DWORD *size)
{
    WCHAR wkey[512], wvalue[256];
    HKEY handle;
    DWORD error;
    secw_wide(key, wkey, 512);
    secw_wide(value, wvalue, 256);
    error = (DWORD)RegOpenKeyExW(root, wkey, 0, KEY_QUERY_VALUE, &handle);
    if (error) return error;
    error = (DWORD)RegQueryValueExW(handle, wvalue, NULL, type, data, size);
    RegCloseKey(handle);
    return error;
}

BOOL secw_reg_string(HKEY root, const char *key, const char *value, char *out, int size)
{
    WCHAR data[1024];
    DWORD type = 0, bytes = sizeof(data) - sizeof(WCHAR);
    if (size > 0) out[0] = 0;
    if (secw_reg_read(root, key, value, &type, (BYTE *)data, &bytes) || (type != REG_SZ && type != REG_EXPAND_SZ)) return FALSE;
    data[bytes / sizeof(WCHAR)] = 0;
    secw_utf8(data, out, size);
    return TRUE;
}

BOOL secw_reg_dword(HKEY root, const char *key, const char *value, DWORD *out)
{
    DWORD type = 0, bytes = sizeof(*out);
    return !secw_reg_read(root, key, value, &type, (BYTE *)out, &bytes) && type == REG_DWORD && bytes == sizeof(*out);
}

void secw_directories(char *windows, int windows_size, char *programs, int programs_size)
{
    WCHAR path[MAX_PATH];
    path[0] = 0;
    GetWindowsDirectoryW(path, MAX_PATH);
    secw_utf8(path, windows, windows_size);
    if (!secw_reg_string(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", "ProgramFilesDir", programs, programs_size))
        lstrcpynA(programs, "C:\\Program Files", programs_size);
}

DWORD secw_reg_create(const WCHAR *key, HKEY *handle)
{
    PSECURITY_DESCRIPTOR sd = NULL;
    SECURITY_ATTRIBUTES attributes;
    WCHAR partial[520];
    DWORD error = ERROR_SUCCESS;
    int i, length = lstrlenW(key);
    HKEY level;
    *handle = NULL;
    if (length >= 520) return ERROR_BUFFER_OVERFLOW;
    /* Owner only: the DACL still comes from the parent key. */
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:BA", SDDL_REVISION_1, &sd, NULL)) return GetLastError();
    attributes.nLength = sizeof(attributes);
    attributes.lpSecurityDescriptor = sd;
    attributes.bInheritHandle = FALSE;
    for (i = 1; i <= length && !error; ++i) {
        if (key[i] != L'\\' && key[i] != 0) continue;
        lstrcpynW(partial, key, i + 1);
        error = (DWORD)RegCreateKeyExW(HKEY_LOCAL_MACHINE, partial, 0, NULL, 0, i == length ? KEY_SET_VALUE : KEY_READ, &attributes, &level, NULL);
        /* Existing upper levels that only allow reading are fine. */
        if (error == ERROR_ACCESS_DENIED && i != length) error = ERROR_SUCCESS;
        else if (!error) { if (i == length) *handle = level; else RegCloseKey(level); }
    }
    LocalFree(sd);
    return error;
}

BOOL secw_registry_matches(const SEC_REGISTRY_RULE *rule, unsigned present, DWORD type, const BYTE *data, DWORD size)
{
    if (rule->kind == SEC_REG_DWORD || rule->kind == SEC_REG_DWORD_MIN)
        return present && type == REG_DWORD && size == 4 && sec_registry_dword_ok(rule, 1, *(const DWORD *)data);
    if (rule->kind == SEC_REG_SZ) {
        char text[512];
        WCHAR wide[256];
        if (!present || (type != REG_SZ && type != REG_EXPAND_SZ) || size >= sizeof(wide)) return FALSE;
        CopyMemory(wide, data, size);
        wide[size / sizeof(WCHAR)] = 0;
        secw_utf8(wide, text, sizeof(text));
        return sec_equal_nocase(text, rule->text);
    }
    if (rule->kind == SEC_REG_MULTI_EMPTY)
        return !present || (type == REG_MULTI_SZ && (size < sizeof(WCHAR) || *(const WCHAR *)data == 0));
    return FALSE;
}

void secw_registry_describe(char *text, int text_size, unsigned present, DWORD type, const BYTE *data, DWORD size)
{
    char local[400];
    if (!present) lstrcpyA(local, "(absent)");
    else if (type == REG_DWORD && size == 4) wsprintfA(local, "%lu", *(const DWORD *)data);
    else if ((type == REG_SZ || type == REG_EXPAND_SZ) && size < 380) {
        WCHAR wide[200];
        CopyMemory(wide, data, size);
        wide[size / sizeof(WCHAR)] = 0;
        secw_utf8(wide, local, sizeof(local));
    } else wsprintfA(local, "(type %lu, %lu bytes)", type, size);
    lstrcpynA(text, local, text_size);
}

BOOL secw_registry_rule_state(const SEC_REGISTRY_RULE *rule, char *current, int current_size, DWORD *error)
{
    BYTE data[SEC_BACKUP_DATA_MAX];
    DWORD type = 0, size = sizeof(data);
    unsigned present = 1;
    *error = secw_reg_read(HKEY_LOCAL_MACHINE, rule->key, rule->value, &type, data, &size);
    if (*error == ERROR_FILE_NOT_FOUND || *error == ERROR_PATH_NOT_FOUND) { *error = ERROR_SUCCESS; present = 0; size = 0; }
    if (*error) { lstrcpynA(current, "(unreadable)", current_size); return FALSE; }
    secw_registry_describe(current, current_size, present, type, data, size);
    return secw_registry_matches(rule, present, type, data, size);
}

DWORD secw_object_exposure(const WCHAR *name, SE_OBJECT_TYPE type, DWORD write_mask, unsigned *exposure)
{
    PSECURITY_DESCRIPTOR sd = NULL;
    PACL dacl = NULL;
    PSID owner = NULL;
    WCHAR copy[600];
    DWORD error;
    *exposure = 0;
    if (lstrlenW(name) >= 600) return ERROR_BUFFER_OVERFLOW;
    lstrcpyW(copy, name);
    error = GetNamedSecurityInfoW(copy, type, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, NULL, &dacl, NULL, &sd);
    if (error) return error;
    *exposure = secw_dacl_writers(dacl, TRUE, write_mask);
    if (owner && !IsWellKnownSid(owner, WinLocalSystemSid) && !IsWellKnownSid(owner, WinBuiltinAdministratorsSid))
        *exposure |= SECW_OWNER_NOT_SYSTEM;
    LocalFree(sd);
    return ERROR_SUCCESS;
}

DWORD secw_sddl_get(const WCHAR *name, SE_OBJECT_TYPE type, char *sddl, int size)
{
    PSECURITY_DESCRIPTOR sd = NULL;
    WCHAR copy[600], *text = NULL;
    DWORD error;
    if (size > 0) sddl[0] = 0;
    if (lstrlenW(name) >= 600) return ERROR_BUFFER_OVERFLOW;
    lstrcpyW(copy, name);
    error = GetNamedSecurityInfoW(copy, type, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &sd);
    if (error) return error;
    if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, SDDL_REVISION_1, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &text, NULL))
        error = GetLastError();
    else {
        if (lstrlenW(text) >= size) error = ERROR_BUFFER_OVERFLOW;
        else secw_utf8(text, sddl, size);
        LocalFree(text);
    }
    LocalFree(sd);
    return error;
}

DWORD secw_sddl_set(const WCHAR *name, SE_OBJECT_TYPE type, const char *sddl)
{
    PSECURITY_DESCRIPTOR sd = NULL;
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    PACL dacl = NULL;
    PSID owner = NULL;
    WCHAR copy[600], *wide;
    BOOL present = FALSE, defaulted = FALSE;
    DWORD error, revision = 0, length = (DWORD)lstrlenA(sddl) + 1;
    if (lstrlenW(name) >= 600) return ERROR_BUFFER_OVERFLOW;
    lstrcpyW(copy, name);
    wide = (WCHAR *)HeapAlloc(GetProcessHeap(), 0, length * sizeof(WCHAR));
    if (!wide) return ERROR_NOT_ENOUGH_MEMORY;
    secw_wide(sddl, wide, (int)length);
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(wide, SDDL_REVISION_1, &sd, NULL)) error = GetLastError();
    else {
        if (!GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) || !GetSecurityDescriptorOwner(sd, &owner, &defaulted) ||
            !GetSecurityDescriptorControl(sd, &control, &revision) || !present || !owner) error = ERROR_INVALID_SECURITY_DESCR;
        else {
            secw_enable_privilege(SE_TAKE_OWNERSHIP_NAME);
            secw_enable_privilege(SE_RESTORE_NAME);
            error = SetNamedSecurityInfoW(copy, type, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION |
                                          ((control & SE_DACL_PROTECTED) ? PROTECTED_DACL_SECURITY_INFORMATION : UNPROTECTED_DACL_SECURITY_INFORMATION),
                                          owner, NULL, dacl, NULL);
        }
        LocalFree(sd);
    }
    HeapFree(GetProcessHeap(), 0, wide);
    return error;
}

DWORD secw_service_dacl(const WCHAR *service, char *sddl, int size, BOOL *others_control)
{
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT), handle;
    BYTE buffer[4096];
    PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR)buffer;
    PACL dacl = NULL;
    BOOL present = FALSE, defaulted = FALSE;
    WCHAR *text = NULL;
    DWORD error = ERROR_SUCCESS, needed = 0, i;
    if (size > 0) sddl[0] = 0;
    *others_control = FALSE;
    if (!scm) return GetLastError();
    handle = OpenServiceW(scm, service, READ_CONTROL);
    if (!handle) { error = GetLastError(); CloseServiceHandle(scm); return error; }
    if (!QueryServiceObjectSecurity(handle, DACL_SECURITY_INFORMATION, sd, sizeof(buffer), &needed) ||
        !GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted)) error = GetLastError();
    else if (!present || !dacl) *others_control = TRUE;            /* no DACL: everyone has every right */
    else for (i = 0; i < dacl->AceCount; ++i) {
        ACCESS_ALLOWED_ACE *ace;
        DWORD mask;
        if (!GetAce(dacl, i, (void **)&ace) || ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE) continue;
        mask = ace->Mask;
        if (mask & (GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL)) mask |= SECW_SERVICE_CONTROL;
        if ((mask & SECW_SERVICE_CONTROL) && !IsWellKnownSid((PSID)&ace->SidStart, WinLocalSystemSid) &&
            !IsWellKnownSid((PSID)&ace->SidStart, WinBuiltinAdministratorsSid)) *others_control = TRUE;
    }
    if (!error) {
        if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &text, NULL)) error = GetLastError();
        else {
            if (lstrlenW(text) >= size) error = ERROR_BUFFER_OVERFLOW;
            else secw_utf8(text, sddl, size);
            LocalFree(text);
        }
    }
    CloseServiceHandle(handle);
    CloseServiceHandle(scm);
    return error;
}

DWORD secw_service_dacl_set(const WCHAR *service, const char *sddl)
{
    SC_HANDLE scm, handle;
    PSECURITY_DESCRIPTOR sd = NULL;
    PACL dacl = NULL;
    BOOL present = FALSE, defaulted = FALSE;
    WCHAR wide[SEC_BACKUP_DATA_MAX];
    DWORD error = ERROR_SUCCESS;
    if ((unsigned)lstrlenA(sddl) >= SEC_BACKUP_DATA_MAX || sddl[0] != 'D' || sddl[1] != ':') return ERROR_INVALID_SECURITY_DESCR;
    secw_wide(sddl, wide, SEC_BACKUP_DATA_MAX);
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(wide, SDDL_REVISION_1, &sd, NULL)) return GetLastError();
    if (!GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) || !present || !dacl) { LocalFree(sd); return ERROR_INVALID_SECURITY_DESCR; }
    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    handle = scm ? OpenServiceW(scm, service, WRITE_DAC) : NULL;
    if (!handle || !SetServiceObjectSecurity(handle, DACL_SECURITY_INFORMATION, sd)) error = GetLastError();
    if (handle) CloseServiceHandle(handle);
    if (scm) CloseServiceHandle(scm);
    LocalFree(sd);
    return error;
}

DWORD secw_inherit_only(const WCHAR *name, SE_OBJECT_TYPE type)
{
    /* An empty unprotected DACL: the object keeps only what its parent passes down. */
    return secw_sddl_set(name, type, "O:BAD:");
}

DWORD secw_walk_files(const WCHAR *directory, BOOL recursive, SECW_VISIT visit, void *context)
{
    WCHAR *path = (WCHAR *)HeapAlloc(GetProcessHeap(), 0, 600 * sizeof(WCHAR));
    WIN32_FIND_DATAW found;
    HANDLE h;
    DWORD error = ERROR_SUCCESS;
    int base = lstrlenW(directory);
    if (!path) return ERROR_NOT_ENOUGH_MEMORY;
    if (base + 4 >= 600) { HeapFree(GetProcessHeap(), 0, path); return ERROR_BUFFER_OVERFLOW; }
    wsprintfW(path, L"%s\\*", directory);
    h = FindFirstFileW(path, &found);
    if (h == INVALID_HANDLE_VALUE) {
        error = GetLastError();
        HeapFree(GetProcessHeap(), 0, path);
        return error == ERROR_FILE_NOT_FOUND ? ERROR_SUCCESS : error;
    }
    do {
        BOOL is_directory = (found.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        if (!lstrcmpW(found.cFileName, L".") || !lstrcmpW(found.cFileName, L"..")) continue;
        if (base + 1 + lstrlenW(found.cFileName) >= 600) { error = ERROR_BUFFER_OVERFLOW; break; }
        wsprintfW(path, L"%s\\%s", directory, found.cFileName);
        if (!is_directory || recursive) error = visit(path, is_directory, context);
        if (!error && is_directory && recursive && !(found.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
            error = secw_walk_files(path, TRUE, visit, context);
    } while (!error && FindNextFileW(h, &found));
    FindClose(h);
    HeapFree(GetProcessHeap(), 0, path);
    return error;
}

static DWORD walk_keys(HKEY parent, WCHAR *path, int depth, SECW_VISIT visit, void *context)
{
    WCHAR name[256];
    DWORD index, count, error = ERROR_SUCCESS;
    int base = lstrlenW(path);
    for (index = 0; !error && depth < 16; ++index) {
        HKEY child;
        count = 256;
        if (RegEnumKeyExW(parent, index, name, &count, NULL, NULL, NULL, NULL)) break;
        if (base + 1 + (int)count >= 590) return ERROR_BUFFER_OVERFLOW;
        wsprintfW(path + base, L"\\%s", name);
        error = visit(path, TRUE, context);
        if (!error && !RegOpenKeyExW(parent, name, 0, KEY_ENUMERATE_SUB_KEYS, &child)) {
            error = walk_keys(child, path, depth + 1, visit, context);
            RegCloseKey(child);
        }
        path[base] = 0;
    }
    return error;
}

DWORD secw_walk_keys(const WCHAR *key, SECW_VISIT visit, void *context)
{
    WCHAR *path = (WCHAR *)HeapAlloc(GetProcessHeap(), 0, 600 * sizeof(WCHAR));
    HKEY handle;
    DWORD error;
    if (!path) return ERROR_NOT_ENOUGH_MEMORY;
    if (lstrlenW(key) + 10 >= 590) { HeapFree(GetProcessHeap(), 0, path); return ERROR_BUFFER_OVERFLOW; }
    wsprintfW(path, L"MACHINE\\%s", key);
    error = (DWORD)RegOpenKeyExW(HKEY_LOCAL_MACHINE, key, 0, KEY_ENUMERATE_SUB_KEYS, &handle);
    if (!error) {
        error = walk_keys(handle, path, 0, visit, context);
        RegCloseKey(handle);
    }
    HeapFree(GetProcessHeap(), 0, path);
    return error;
}
