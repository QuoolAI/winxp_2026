/* XP25Sec.exe: XP25 security-baseline configuration utility for NT 5.1.

   enumerate  list every Win32 service with its configuration and baseline decision
   plan       show what apply would change (no changes)
   apply      record the original configuration, then apply the hardened defaults
   verify     check that the baseline is in force; exit code = number of deviations
   rollback   restore the recorded original configuration
   status     whether a baseline and its backup are present

   Options: --out <file>  --serial (also write records to COM1)  --quiet
            rollback --from <file> (use an exported backup file)

   Only the reviewed tables in sec_core.c are applied; no service name, key or
   value is taken from the command line. Original values are written to the
   protected store before the first change, and rollback restores only items
   those tables name. apply and rollback need an administrator. */
#include "sec_win.h"

#define MAX_RECORDS 640
#define MAX_REPAIRS 400            /* more exposed system files than this is not a state to change blindly */
#define BACKUP_TEXT_MAX (768 * 1024)

static SECW_SINK sink;
static char line[SECW_LINE];
static SEC_BACKUP_RECORD *records;
static unsigned record_count;
static unsigned long changed, already, failed, absent, restart_needed;

static void *allocate(SIZE_T bytes) { return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytes); }
static void release(void *p) { if (p) HeapFree(GetProcessHeap(), 0, p); }

/* ---- backup store --------------------------------------------------------- */
static SEC_BACKUP_RECORD *backup_find(unsigned item, const char *id)
{
    unsigned i;
    for (i = 0; i < record_count; ++i)
        if (records[i].item == item && sec_equal_nocase(records[i].id, id)) return &records[i];
    return NULL;
}

static SEC_BACKUP_RECORD *backup_add(unsigned item, const char *id)
{
    SEC_BACKUP_RECORD *r;
    if (record_count >= MAX_RECORDS) return NULL;
    r = &records[record_count++];
    ZeroMemory(r, sizeof(*r));
    r->item = item;
    lstrcpynA(r->id, id, sizeof(r->id));
    return r;
}

/* Parses backup text; any malformed line rejects the whole backup. */
static BOOL backup_parse(char *text)
{
    char *p = text, *end;
    BOOL header = FALSE;
    record_count = 0;
    while (*p) {
        for (end = p; *end && *end != '\n'; ++end) { }
        if (*end) *end++ = 0;
        if (end > p + 1 && end[-2] == '\r') end[-2] = 0;
        if (!header) {
            if (lstrcmpA(p, SEC_BACKUP_MAGIC)) return FALSE;
            header = TRUE;
        } else if (*p) {
            if (record_count >= MAX_RECORDS || !sec_backup_parse(p, &records[record_count])) return FALSE;
            ++record_count;
        }
        p = end;
    }
    return header;
}

/* Returns ERROR_FILE_NOT_FOUND when no backup exists, ERROR_INVALID_DATA for a damaged one. */
static DWORD backup_load(const WCHAR *file)
{
    char *text = allocate(BACKUP_TEXT_MAX + 2);
    DWORD error = ERROR_SUCCESS, size = BACKUP_TEXT_MAX, type = 0;
    if (!text) return ERROR_NOT_ENOUGH_MEMORY;
    if (file) {
        HANDLE h = CreateFileW(file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (h == INVALID_HANDLE_VALUE) error = GetLastError();
        else {
            if (!ReadFile(h, text, BACKUP_TEXT_MAX, &size, NULL)) error = GetLastError();
            else if (size == BACKUP_TEXT_MAX) error = ERROR_INVALID_DATA;
            CloseHandle(h);
        }
    } else {
        HKEY key = NULL;
        error = (DWORD)RegOpenKeyExW(HKEY_LOCAL_MACHINE, SECW_BASELINE_KEY, 0, KEY_QUERY_VALUE, &key);
        if (!error) {
            error = (DWORD)RegQueryValueExW(key, L"Backup", NULL, &type, (BYTE *)text, &size);
            if (!error && type != REG_BINARY) error = ERROR_INVALID_DATA;
            RegCloseKey(key);
        }
    }
    if (!error) {
        text[size] = 0;
        if (!backup_parse(text)) { record_count = 0; error = ERROR_INVALID_DATA; }
    }
    release(text);
    return error;
}

static DWORD backup_save(void)
{
    char *text = allocate(BACKUP_TEXT_MAX + 2);
    WCHAR path[MAX_PATH], temporary[MAX_PATH];
    DWORD error = ERROR_SUCCESS, length, done;
    unsigned i;
    HKEY key = NULL;
    HANDLE h;
    if (!text) return ERROR_NOT_ENOUGH_MEMORY;
    lstrcpyA(text, SEC_BACKUP_MAGIC "\n");
    length = (DWORD)lstrlenA(text);
    for (i = 0; i < record_count && !error; ++i) {
        size_t n = sec_backup_format(&records[i], text + length, BACKUP_TEXT_MAX - length);
        if (!n) error = ERROR_INVALID_DATA;
        length += (DWORD)n;
    }
    if (!error) error = (DWORD)RegCreateKeyExW(HKEY_LOCAL_MACHINE, SECW_BASELINE_KEY, 0, NULL, 0, KEY_SET_VALUE, NULL, &key, NULL);
    if (!error) {
        error = (DWORD)RegSetValueExW(key, L"Backup", 0, REG_BINARY, (BYTE *)text, length);
        if (!error) error = (DWORD)RegFlushKey(key);
        RegCloseKey(key);
    }
    /* The file copy lets an administrator recover from another installation
       or from the host; it is replaced atomically. */
    if (!error && secw_store_path(L"baseline-backup.txt", path, MAX_PATH) && secw_store_path(L"baseline-backup.tmp", temporary, MAX_PATH)) {
        h = CreateFileW(temporary, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) error = GetLastError();
        else {
            if (!WriteFile(h, text, length, &done, NULL) || done != length || !FlushFileBuffers(h)) error = GetLastError();
            CloseHandle(h);
            if (!error && !MoveFileExW(temporary, path, MOVEFILE_REPLACE_EXISTING)) error = GetLastError();
        }
    }
    release(text);
    return error;
}

/* ---- services ------------------------------------------------------------- */
static DWORD service_query(SC_HANDLE scm, const char *name, DWORD *start, DWORD *state)
{
    WCHAR wide[128];
    BYTE buffer[8192];
    QUERY_SERVICE_CONFIGW *config = (QUERY_SERVICE_CONFIGW *)buffer;
    SERVICE_STATUS status;
    SC_HANDLE service;
    DWORD needed, error = ERROR_SUCCESS;
    secw_wide(name, wide, 128);
    service = OpenServiceW(scm, wide, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
    if (!service) return GetLastError();
    if (!QueryServiceConfigW(service, config, sizeof(buffer), &needed) || !QueryServiceStatus(service, &status)) error = GetLastError();
    else { *start = config->dwStartType; *state = status.dwCurrentState; }
    CloseServiceHandle(service);
    return error;
}

static DWORD wait_stopped(SC_HANDLE service)
{
    SERVICE_STATUS status;
    DWORD started = GetTickCount();
    for (;;) {
        if (!QueryServiceStatus(service, &status)) return GetLastError();
        if (status.dwCurrentState == SERVICE_STOPPED) return ERROR_SUCCESS;
        if (GetTickCount() - started > 45000) return ERROR_SERVICE_REQUEST_TIMEOUT;
        Sleep(250);
    }
}

/* Stops a running service after its running dependents. */
static DWORD service_stop(SC_HANDLE scm, SC_HANDLE service, int depth)
{
    BYTE buffer[4096];
    ENUM_SERVICE_STATUSW *dependents = (ENUM_SERVICE_STATUSW *)buffer;
    SERVICE_STATUS status;
    DWORD needed = 0, count = 0, i, error;
    if (!QueryServiceStatus(service, &status)) return GetLastError();
    if (status.dwCurrentState == SERVICE_STOPPED) return ERROR_SUCCESS;
    if (depth < 4 && EnumDependentServicesW(service, SERVICE_ACTIVE, dependents, sizeof(buffer), &needed, &count))
        for (i = 0; i < count; ++i) {
            SC_HANDLE child = OpenServiceW(scm, dependents[i].lpServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS);
            if (!child) return GetLastError();
            error = service_stop(scm, child, depth + 1);
            CloseServiceHandle(child);
            if (error) return error;
        }
    if (status.dwCurrentState != SERVICE_STOP_PENDING && !ControlService(service, SERVICE_CONTROL_STOP, &status)) {
        error = GetLastError();
        if (error != ERROR_SERVICE_NOT_ACTIVE) return error;
    }
    return wait_stopped(service);
}

/* Sets the start type; stops the service when it is being disabled. A
   failed stop is reported in *stop_error and leaves the start type set. */
static DWORD service_configure(SC_HANDLE scm, const char *name, DWORD start, DWORD *stop_error)
{
    WCHAR wide[128];
    SC_HANDLE service;
    DWORD error = ERROR_SUCCESS;
    *stop_error = ERROR_SUCCESS;
    secw_wide(name, wide, 128);
    service = OpenServiceW(scm, wide, SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS | SERVICE_STOP | SERVICE_ENUMERATE_DEPENDENTS);
    if (!service) return GetLastError();
    if (!ChangeServiceConfigW(service, SERVICE_NO_CHANGE, start, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL))
        error = GetLastError();
    else if (start == SERVICE_DISABLED) *stop_error = service_stop(scm, service, 0);
    CloseServiceHandle(service);
    return error;
}

static const char *start_name(DWORD start)
{
    static const char *const names[] = {"boot", "system", "auto", "manual", "disabled"};
    return start <= SERVICE_DISABLED ? names[start] : "unknown";
}

static const char *state_name(DWORD state)
{
    static const char *const names[] = {"unknown", "stopped", "start_pending", "stop_pending", "running",
                                        "continue_pending", "pause_pending", "paused"};
    return state <= SERVICE_PAUSED ? names[state] : "unknown";
}

/* ---- registry --------------------------------------------------------------- */
static DWORD registry_get(const SEC_REGISTRY_RULE *rule, unsigned *present, DWORD *type, BYTE *data, DWORD *size)
{
    DWORD error, capacity = *size;
    *present = 0; *type = 0; *size = capacity;
    error = secw_reg_read(HKEY_LOCAL_MACHINE, rule->key, rule->value, type, data, size);
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) { *size = 0; *type = 0; return ERROR_SUCCESS; }
    if (!error) *present = 1;
    return error;
}

static DWORD registry_write(const SEC_REGISTRY_RULE *rule, unsigned present, DWORD type, const BYTE *data, DWORD size)
{
    WCHAR key[512], value[256];
    HKEY handle;
    DWORD error;
    secw_wide(rule->key, key, 512);
    secw_wide(rule->value, value, 256);
    if (!present) {
        error = (DWORD)RegOpenKeyExW(HKEY_LOCAL_MACHINE, key, 0, KEY_SET_VALUE, &handle);
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) return ERROR_SUCCESS;
        if (error) return error;
        error = (DWORD)RegDeleteValueW(handle, value);
        if (error == ERROR_FILE_NOT_FOUND) error = ERROR_SUCCESS;
    } else {
        error = secw_reg_create(key, &handle);
        if (error) return error;
        error = (DWORD)RegSetValueExW(handle, value, 0, type, data, size);
    }
    RegCloseKey(handle);
    return error;
}

static DWORD registry_apply(const SEC_REGISTRY_RULE *rule)
{
    WCHAR wide[256];
    DWORD number = (DWORD)rule->number;
    static const WCHAR empty[1] = {0};
    if (rule->kind == SEC_REG_DWORD || rule->kind == SEC_REG_DWORD_MIN)
        return registry_write(rule, 1, REG_DWORD, (const BYTE *)&number, sizeof(number));
    if (rule->kind == SEC_REG_SZ) {
        secw_wide(rule->text, wide, 256);
        return registry_write(rule, 1, REG_SZ, (const BYTE *)wide, (DWORD)((lstrlenW(wide) + 1) * sizeof(WCHAR)));
    }
    if (rule->kind == SEC_REG_MULTI_EMPTY) return registry_write(rule, 1, REG_MULTI_SZ, (const BYTE *)empty, sizeof(empty));
    return ERROR_INVALID_PARAMETER;
}

static void registry_describe(SEC_JSON *json, const char *key, unsigned present, DWORD type, const BYTE *data, DWORD size)
{
    char text[400];
    secw_registry_describe(text, sizeof(text), present, type, data, size);
    sec_json_string(json, key, text);
}

static void registry_target(SEC_JSON *json, const SEC_REGISTRY_RULE *rule)
{
    char text[64];
    if (rule->kind == SEC_REG_SZ) sec_json_string(json, "target", rule->text);
    else if (rule->kind == SEC_REG_MULTI_EMPTY) sec_json_string(json, "target", "(empty list)");
    else {
        wsprintfA(text, rule->kind == SEC_REG_DWORD_MIN ? ">=%lu" : "%lu", rule->number);
        sec_json_string(json, "target", text);
    }
}

/* ---- audit policy ------------------------------------------------------------ */
static DWORD audit_get(ULONG *options, unsigned *mode)
{
    LSA_OBJECT_ATTRIBUTES attributes;
    LSA_HANDLE policy;
    POLICY_AUDIT_EVENTS_INFO *info = NULL;
    NTSTATUS status;
    ULONG i;
    ZeroMemory(&attributes, sizeof(attributes));
    status = LsaOpenPolicy(NULL, &attributes, POLICY_VIEW_AUDIT_INFORMATION, &policy);
    if (status) return LsaNtStatusToWinError(status);
    status = LsaQueryInformationPolicy(policy, PolicyAuditEventsInformation, (PVOID *)&info);
    if (!status) {
        *mode = info->AuditingMode ? 1u : 0u;
        for (i = 0; i < SEC_AUDIT_CATEGORIES; ++i)
            options[i] = i < info->MaximumAuditEventCount ? (info->EventAuditingOptions[i] & 3) : 0;
        LsaFreeMemory(info);
    }
    LsaClose(policy);
    return status ? LsaNtStatusToWinError(status) : ERROR_SUCCESS;
}

static DWORD audit_set(const ULONG *options, unsigned mode)
{
    LSA_OBJECT_ATTRIBUTES attributes;
    LSA_HANDLE policy;
    POLICY_AUDIT_EVENTS_INFO info;
    ULONG values[SEC_AUDIT_CATEGORIES], i;
    NTSTATUS status;
    ZeroMemory(&attributes, sizeof(attributes));
    status = LsaOpenPolicy(NULL, &attributes, POLICY_VIEW_AUDIT_INFORMATION | POLICY_SET_AUDIT_REQUIREMENTS, &policy);
    if (status) return LsaNtStatusToWinError(status);
    /* Zero means "unchanged" to LSA; an explicit NONE clears a category. */
    for (i = 0; i < SEC_AUDIT_CATEGORIES; ++i) values[i] = options[i] ? options[i] : POLICY_AUDIT_EVENT_NONE;
    info.AuditingMode = (BOOLEAN)(mode != 0);
    info.EventAuditingOptions = values;
    info.MaximumAuditEventCount = SEC_AUDIT_CATEGORIES;
    status = LsaSetInformationPolicy(policy, PolicyAuditEventsInformation, &info);
    LsaClose(policy);
    return status ? LsaNtStatusToWinError(status) : ERROR_SUCCESS;
}

/* ---- access control -------------------------------------------------------------- */
static char windows_dir[600], programs_dir[600];

typedef struct {
    const SEC_ACL_RULE *rule;
    SE_OBJECT_TYPE type;
    DWORD mask;
    int action;                 /* 0 count exposed, 1 record originals, 2 reset to inheritance */
    unsigned long exposed, changed, errors, recorded;
    DWORD first_error;
    char first[300];
} ACL_PASS;

static SEC_BACKUP_RECORD *acl_record_find(const char *rule, const char *path)
{
    unsigned i;
    for (i = 0; i < record_count; ++i)
        if (records[i].item == SEC_ITEM_ACL && !lstrcmpA(records[i].id, rule) && sec_equal_nocase((const char *)records[i].data, path))
            return &records[i];
    return NULL;
}

/* Records an object's original owner and DACL unless it already has a record. */
static DWORD acl_record(const SEC_ACL_RULE *rule, const WCHAR *object, const char *path, SE_OBJECT_TYPE type)
{
    SEC_BACKUP_RECORD *r;
    char sddl[SEC_BACKUP_DATA_MAX];
    DWORD error, used = (DWORD)lstrlenA(path) + 1;
    if (acl_record_find(rule->id, path)) return ERROR_SUCCESS;
    error = secw_sddl_get(object, type, sddl, (int)(sizeof(sddl) - used));
    if (error) return error;
    r = backup_add(SEC_ITEM_ACL, rule->id);
    if (!r) return ERROR_BUFFER_OVERFLOW;
    CopyMemory(r->data, path, used);
    CopyMemory(r->data + used, sddl, (SIZE_T)lstrlenA(sddl));
    r->size = used + (DWORD)lstrlenA(sddl);
    r->present = 1;
    return ERROR_SUCCESS;
}

static DWORD acl_visit(const WCHAR *path, BOOL directory, void *context)
{
    ACL_PASS *pass = (ACL_PASS *)context;
    unsigned exposure = 0;
    char utf8[800];
    DWORD error;
    if (directory && pass->rule->kind == SEC_ACL_REPAIR_FILES) return ERROR_SUCCESS;
    error = secw_object_exposure(path, pass->type, pass->mask, &exposure);
    /* Registry objects are named "MACHINE\\<key>"; records hold the key below HKEY_LOCAL_MACHINE. */
    secw_utf8(pass->type == SE_REGISTRY_KEY ? path + 8 : path, utf8, sizeof(utf8));
    if (error) {
        /* A file that vanished or is exclusively locked is reported, not fatal. */
        if (!pass->errors++) pass->first_error = error;
        return ERROR_SUCCESS;
    }
    if (!(exposure & SECW_EXPOSED)) return ERROR_SUCCESS;
    if (!pass->exposed++) lstrcpynA(pass->first, utf8, sizeof(pass->first));
    if (pass->action == 1 && (pass->rule->kind == SEC_ACL_REPAIR_FILES || pass->rule->kind == SEC_ACL_REPAIR_KEYS)) {
        if (pass->recorded >= MAX_REPAIRS) return ERROR_TOO_MANY_NAMES;
        error = acl_record(pass->rule, path, utf8, pass->type);
        if (error) return error;
        ++pass->recorded;
    } else if (pass->action == 2) {
        error = secw_inherit_only(path, pass->type);
        if (error) { if (!pass->errors++) pass->first_error = error; }
        else ++pass->changed;
    }
    return ERROR_SUCCESS;
}

/* Runs one pass over a rule. *root_exists is FALSE when the rule's root is absent. */
static DWORD acl_pass(const SEC_ACL_RULE *rule, int action, ACL_PASS *pass, BOOL *root_exists)
{
    char root8[600];
    WCHAR root[600], object[620];
    unsigned exposure = 0;
    DWORD error;
    ZeroMemory(pass, sizeof(*pass));
    pass->rule = rule; pass->action = action;
    *root_exists = FALSE;
    if (rule->kind == SEC_ACL_TREE_REGISTRY || rule->kind == SEC_ACL_REPAIR_KEYS) {
        HKEY key;
        secw_wide(rule->root, root, 600);
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, root, 0, KEY_READ, &key)) return ERROR_SUCCESS;
        RegCloseKey(key);
        wsprintfW(object, L"MACHINE\\%s", root);
        lstrcpynA(root8, rule->root, sizeof(root8));
        pass->type = SE_REGISTRY_KEY; pass->mask = SECW_KEY_WRITE;
    } else {
        if (!sec_acl_root(rule, windows_dir, programs_dir, root8, sizeof(root8))) return ERROR_BUFFER_OVERFLOW;
        secw_wide(root8, root, 600);
        if (GetFileAttributesW(root) == INVALID_FILE_ATTRIBUTES) return ERROR_SUCCESS;
        if (GetFileAttributesW(root) & FILE_ATTRIBUTE_REPARSE_POINT) return ERROR_INVALID_DATA;
        lstrcpyW(object, root);
        pass->type = SE_FILE_OBJECT; pass->mask = SECW_FILE_WRITE;
    }
    *root_exists = TRUE;
    if (rule->kind == SEC_ACL_TREE_FILES || rule->kind == SEC_ACL_TREE_REGISTRY) {
        /* The root itself: recorded once, then given the rule's protected descriptor. */
        error = secw_object_exposure(object, pass->type, pass->mask, &exposure);
        if (error) return error;
        if (exposure & SECW_EXPOSED) { ++pass->exposed; lstrcpynA(pass->first, root8, sizeof(pass->first)); }
        if (action == 1) {
            error = acl_record(rule, object, root8, pass->type);
            if (error) return error;
        } else if (action == 2) {
            error = secw_sddl_set(object, pass->type, rule->sddl);
            if (error) return error;
            ++pass->changed;
        }
    }
    if (pass->type == SE_REGISTRY_KEY) return secw_walk_keys(root, acl_visit, pass);
    return secw_walk_files(root, rule->kind == SEC_ACL_TREE_FILES, acl_visit, pass);
}

static void acl_result(const char *command, const SEC_ACL_RULE *rule, const ACL_PASS *pass, BOOL exists, DWORD error, BOOL ok, BOOL detail)
{
    SEC_JSON json;
    char root[600];
    sec_json_begin(&json, line, sizeof(line));
    sec_json_string(&json, "kind", command);
    sec_json_string(&json, "item", "acl");
    sec_json_string(&json, "id", rule->id);
    if (rule->kind == SEC_ACL_TREE_REGISTRY || rule->kind == SEC_ACL_REPAIR_KEYS) wsprintfA(root, "HKLM\\%.500s", rule->root);
    else if (!sec_acl_root(rule, windows_dir, programs_dir, root, sizeof(root))) root[0] = 0;
    sec_json_string(&json, "root", root);
    sec_json_bool(&json, "present", exists);
    sec_json_uint(&json, "modifiable_by_non_administrators", pass->exposed);
    if (pass->exposed) sec_json_string(&json, "first", pass->first);
    if (pass->changed) sec_json_uint(&json, "reset", pass->changed);
    if (pass->errors) { sec_json_uint(&json, "unreadable", pass->errors); sec_json_uint(&json, "first_error", pass->first_error); }
    if (error) sec_json_uint(&json, "error", error);
    sec_json_bool(&json, "ok", ok);
    if (detail) { sec_json_string(&json, "reason", rule->reason); sec_json_string(&json, "compatibility", rule->compatibility); }
    secw_emit(&sink, &json);
}

/* ---- commands ------------------------------------------------------------------ */
static void result(const char *command, const char *item, const char *id, const char *outcome, DWORD error)
{
    SEC_JSON json;
    sec_json_begin(&json, line, sizeof(line));
    sec_json_string(&json, "kind", command);
    sec_json_string(&json, "item", item);
    sec_json_string(&json, "id", id);
    sec_json_string(&json, "result", outcome);
    if (error) sec_json_uint(&json, "error", error);
    secw_emit(&sink, &json);
}

static void summary(const char *command, int code)
{
    SEC_JSON json;
    char now[32];
    secw_utc_now(now, sizeof(now));
    sec_json_begin(&json, line, sizeof(line));
    sec_json_string(&json, "kind", "summary");
    sec_json_string(&json, "command", command);
    sec_json_uint(&json, "baseline_version", SEC_BASELINE_VERSION);
    sec_json_uint(&json, "changed", changed);
    sec_json_uint(&json, "already", already);
    sec_json_uint(&json, "absent", absent);
    sec_json_uint(&json, "failed", failed);
    sec_json_bool(&json, "restart_required", restart_needed != 0);
    sec_json_uint(&json, "exit_code", (unsigned long)code);
    sec_json_string(&json, "utc", now);
    secw_emit(&sink, &json);
}

static int enumerate(void)
{
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    BYTE *buffer = allocate(65536), config_buffer[8192];
    QUERY_SERVICE_CONFIGW *config = (QUERY_SERVICE_CONFIGW *)config_buffer;
    DWORD needed, count, resume = 0, i, error = ERROR_SUCCESS, total = 0;
    BOOL more = TRUE;
    if (!scm || !buffer) { secw_error_text("cannot open the service control manager", GetLastError()); return 1; }
    while (more) {
        ENUM_SERVICE_STATUS_PROCESSW *entries = (ENUM_SERVICE_STATUS_PROCESSW *)buffer;
        more = FALSE;
        if (!EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, buffer, 65536, &needed, &count, &resume, NULL)) {
            error = GetLastError();
            if (error != ERROR_MORE_DATA) break;
            more = TRUE; error = ERROR_SUCCESS;
        }
        for (i = 0; i < count; ++i) {
            char name[160], text[1024];
            const SEC_SERVICE_RULE *rule;
            SEC_JSON json;
            SC_HANDLE service = OpenServiceW(scm, entries[i].lpServiceName, SERVICE_QUERY_CONFIG);
            secw_utf8(entries[i].lpServiceName, name, sizeof(name));
            rule = sec_service_rule(name);
            sec_json_begin(&json, line, sizeof(line));
            sec_json_string(&json, "kind", "service");
            sec_json_string(&json, "name", name);
            secw_utf8(entries[i].lpDisplayName, text, sizeof(text));
            sec_json_string(&json, "display_name", text);
            sec_json_string(&json, "state", state_name(entries[i].ServiceStatusProcess.dwCurrentState));
            sec_json_uint(&json, "pid", entries[i].ServiceStatusProcess.dwProcessId);
            if (service && QueryServiceConfigW(service, config, sizeof(config_buffer), &needed)) {
                sec_json_string(&json, "start", start_name(config->dwStartType));
                secw_utf8(config->lpServiceStartName, text, sizeof(text));
                sec_json_string(&json, "account", text);
                secw_utf8(config->lpBinaryPathName, text, sizeof(text));
                sec_json_string(&json, "image", text);
                sec_json_bool(&json, "own_process", (config->dwServiceType & SERVICE_WIN32_OWN_PROCESS) != 0);
                if (rule) sec_json_bool(&json, "compliant", config->dwStartType == rule->start &&
                                        (rule->start != SERVICE_DISABLED || entries[i].ServiceStatusProcess.dwCurrentState == SERVICE_STOPPED));
            } else sec_json_uint(&json, "config_error", GetLastError());
            if (service) CloseServiceHandle(service);
            sec_json_bool(&json, "critical", sec_service_is_critical(name));
            sec_json_bool(&json, "managed", rule != NULL);
            if (rule) {
                sec_json_string(&json, "target_start", start_name(rule->start));
                sec_json_bool(&json, "network_listener", (rule->flags & SEC_SVC_NETWORK_LISTENER) != 0);
                sec_json_bool(&json, "remote_administration", (rule->flags & SEC_SVC_REMOTE_ADMIN) != 0);
                sec_json_bool(&json, "legacy_discovery", (rule->flags & SEC_SVC_LEGACY_DISCOVERY) != 0);
                sec_json_bool(&json, "legacy_protocol", (rule->flags & SEC_SVC_LEGACY_PROTOCOL) != 0);
                sec_json_bool(&json, "retired_endpoint", (rule->flags & SEC_SVC_RETIRED_ENDPOINT) != 0);
                sec_json_string(&json, "reason", rule->reason);
                sec_json_string(&json, "compatibility", rule->compatibility);
            }
            secw_emit(&sink, &json);
            ++total;
        }
    }
    CloseServiceHandle(scm);
    release(buffer);
    changed = 0; already = total;
    if (error) { secw_error_text("service enumeration failed", error); return 1; }
    return 0;
}

/* plan (write = FALSE) and verify share the comparison; apply uses it after the backup. */
static int compare(const char *command, BOOL verify)
{
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    ULONG options[SEC_AUDIT_CATEGORIES];
    unsigned i, mode = 0, deviations = 0;
    DWORD error;
    if (!scm) { secw_error_text("cannot open the service control manager", GetLastError()); return 100; }
    for (i = 0; i < sec_service_rule_count(); ++i) {
        const SEC_SERVICE_RULE *rule = sec_service_rule_at(i);
        DWORD start = 0, state = 0;
        SEC_JSON json;
        BOOL ok;
        error = service_query(scm, rule->name, &start, &state);
        sec_json_begin(&json, line, sizeof(line));
        sec_json_string(&json, "kind", command);
        sec_json_string(&json, "item", "service");
        sec_json_string(&json, "id", rule->name);
        if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
            sec_json_bool(&json, "installed", 0);
            sec_json_bool(&json, "ok", 1);
            ++absent;
        } else if (error) {
            sec_json_uint(&json, "error", error);
            sec_json_bool(&json, "ok", 0);
            ++deviations;
        } else {
            ok = start == rule->start && (rule->start != SERVICE_DISABLED || state == SERVICE_STOPPED);
            sec_json_string(&json, "start", start_name(start));
            sec_json_string(&json, "state", state_name(state));
            sec_json_string(&json, "target_start", start_name(rule->start));
            sec_json_bool(&json, "ok", ok);
            if (!ok) ++deviations; else ++already;
        }
        if (!verify) sec_json_string(&json, "reason", rule->reason);
        secw_emit(&sink, &json);
    }
    CloseServiceHandle(scm);
    for (i = 0; i < sec_registry_rule_count(); ++i) {
        const SEC_REGISTRY_RULE *rule = sec_registry_rule_at(i);
        BYTE data[SEC_BACKUP_DATA_MAX];
        DWORD type, size = sizeof(data);
        unsigned present;
        SEC_JSON json;
        BOOL ok;
        error = registry_get(rule, &present, &type, data, &size);
        ok = !error && secw_registry_matches(rule, present, type, data, size);
        sec_json_begin(&json, line, sizeof(line));
        sec_json_string(&json, "kind", command);
        sec_json_string(&json, "item", "registry");
        sec_json_string(&json, "id", rule->id);
        sec_json_string(&json, "area", rule->area);
        if (error) sec_json_uint(&json, "error", error);
        else registry_describe(&json, "current", present, type, data, size);
        registry_target(&json, rule);
        sec_json_bool(&json, "ok", ok);
        if (!verify) {
            sec_json_string(&json, "key", rule->key);
            sec_json_string(&json, "value", rule->value);
            sec_json_bool(&json, "restart_to_take_effect", rule->effect == SEC_EFFECT_RESTART);
            sec_json_string(&json, "reason", rule->reason);
            sec_json_string(&json, "compatibility", rule->compatibility);
        }
        secw_emit(&sink, &json);
        if (!ok) ++deviations; else ++already;
    }
    error = audit_get(options, &mode);
    for (i = 0; i < SEC_AUDIT_CATEGORIES; ++i) {
        SEC_JSON json;
        BOOL ok = !error && mode && (options[i] & sec_audit_baseline(i)) == sec_audit_baseline(i);
        sec_json_begin(&json, line, sizeof(line));
        sec_json_string(&json, "kind", command);
        sec_json_string(&json, "item", "audit");
        sec_json_string(&json, "id", sec_audit_category_name(i));
        if (error) sec_json_uint(&json, "error", error);
        else {
            sec_json_bool(&json, "auditing_enabled", (int)mode);
            sec_json_bool(&json, "success", (options[i] & SEC_AUDIT_SUCCESS) != 0);
            sec_json_bool(&json, "failure", (options[i] & SEC_AUDIT_FAILURE) != 0);
        }
        sec_json_bool(&json, "target_success", (sec_audit_baseline(i) & SEC_AUDIT_SUCCESS) != 0);
        sec_json_bool(&json, "target_failure", (sec_audit_baseline(i) & SEC_AUDIT_FAILURE) != 0);
        sec_json_bool(&json, "ok", ok);
        secw_emit(&sink, &json);
        if (!ok) ++deviations; else ++already;
    }
    for (i = 0; i < sec_acl_rule_count(); ++i) {
        const SEC_ACL_RULE *rule = sec_acl_rule_at(i);
        ACL_PASS pass;
        BOOL exists = FALSE, ok;
        error = acl_pass(rule, 0, &pass, &exists);
        ok = !error && !pass.exposed;
        acl_result(command, rule, &pass, exists, error, ok, !verify);
        if (!exists && !error) ++absent; else if (!ok) ++deviations; else ++already;
    }
    if (verify) {
        /* The store that rollback trusts must not be writable by unprivileged accounts. */
        WCHAR path[MAX_PATH], key[] = L"MACHINE\\" SECW_STORE_KEY;
        unsigned who_file = 0, who_key = 0;
        DWORD file_error = secw_store_path(NULL, path, MAX_PATH) ? secw_object_writers(path, SE_FILE_OBJECT, SECW_FILE_WRITE, &who_file) : ERROR_BUFFER_OVERFLOW;
        DWORD key_error = secw_object_writers(key, SE_REGISTRY_KEY, SECW_KEY_WRITE, &who_key);
        BOOL ok = !file_error && !key_error && !who_file && !who_key && backup_load(NULL) == ERROR_SUCCESS;
        SEC_JSON json;
        sec_json_begin(&json, line, sizeof(line));
        sec_json_string(&json, "kind", command);
        sec_json_string(&json, "item", "store");
        sec_json_string(&json, "id", "protected_store_and_backup");
        sec_json_uint(&json, "backup_records", record_count);
        sec_json_uint(&json, "directory_error", file_error);
        sec_json_uint(&json, "key_error", key_error);
        sec_json_uint(&json, "unprivileged_writers", who_file | who_key);
        sec_json_bool(&json, "ok", ok);
        secw_emit(&sink, &json);
        if (!ok) ++deviations; else ++already;
    }
    failed = deviations;
    return deviations > 100 ? 100 : (int)deviations;
}

static int apply(void)
{
    SC_HANDLE scm;
    ULONG options[SEC_AUDIT_CATEGORIES], wanted[SEC_AUDIT_CATEGORIES];
    unsigned i, mode = 0;
    DWORD error;
    HKEY key;
    char now[32];
    BOOL audit_change = FALSE;
    if (!secw_is_admin()) { secw_error_text("apply needs an administrator", ERROR_ACCESS_DENIED); return 5; }
    error = secw_store_prepare();
    if (error) { secw_error_text("cannot prepare the protected store", error); return 1; }
    error = backup_load(NULL);
    if (error && error != ERROR_FILE_NOT_FOUND) { secw_error_text("the existing backup is damaged; nothing was changed", error); return 1; }
    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) { secw_error_text("cannot open the service control manager", GetLastError()); return 1; }
    /* Phase 1: record every original that has no record yet, and persist it. */
    for (i = 0; i < sec_service_rule_count(); ++i) {
        const SEC_SERVICE_RULE *rule = sec_service_rule_at(i);
        DWORD start = 0, state = 0;
        SEC_BACKUP_RECORD *r;
        if (sec_service_is_critical(rule->name)) { secw_error_text("baseline table names a critical service", ERROR_INVALID_DATA); return 1; }
        if (backup_find(SEC_ITEM_SERVICE, rule->name) || service_query(scm, rule->name, &start, &state)) continue;
        r = backup_add(SEC_ITEM_SERVICE, rule->name);
        if (!r) { secw_error_text("backup table full", ERROR_BUFFER_OVERFLOW); return 1; }
        r->start = start;
        r->running = state != SERVICE_STOPPED;
    }
    for (i = 0; i < sec_registry_rule_count(); ++i) {
        const SEC_REGISTRY_RULE *rule = sec_registry_rule_at(i);
        SEC_BACKUP_RECORD *r;
        DWORD type, size = SEC_BACKUP_DATA_MAX;
        if (backup_find(SEC_ITEM_REGISTRY, rule->id)) continue;
        r = backup_add(SEC_ITEM_REGISTRY, rule->id);
        if (!r) { secw_error_text("backup table full", ERROR_BUFFER_OVERFLOW); return 1; }
        error = registry_get(rule, &r->present, &type, r->data, &size);
        if (error) { secw_error_text(rule->id, error); secw_error_text("cannot record an original value; nothing was changed", error); return 1; }
        r->type = type; r->size = size;
    }
    error = audit_get(options, &mode);
    if (error) { secw_error_text("cannot read the audit policy; nothing was changed", error); return 1; }
    if (!backup_find(SEC_ITEM_AUDIT, "mode")) {
        SEC_BACKUP_RECORD *r = backup_add(SEC_ITEM_AUDIT, "mode");
        if (r) r->options = mode;
        for (i = 0; i < SEC_AUDIT_CATEGORIES; ++i) {
            r = backup_add(SEC_ITEM_AUDIT, sec_audit_category_name(i));
            if (!r) { secw_error_text("backup table full", ERROR_BUFFER_OVERFLOW); return 1; }
            r->options = options[i];
        }
    }
    for (i = 0; i < sec_acl_rule_count(); ++i) {
        ACL_PASS pass;
        BOOL exists = FALSE;
        error = acl_pass(sec_acl_rule_at(i), 1, &pass, &exists);
        if (error) { secw_error_text(sec_acl_rule_at(i)->id, error); secw_error_text("cannot record original access control; nothing was changed", error); return 1; }
    }
    error = backup_save();
    if (error) { secw_error_text("cannot write the backup; nothing was changed", error); return 1; }
    /* Phase 2: apply. */
    for (i = 0; i < sec_service_rule_count(); ++i) {
        const SEC_SERVICE_RULE *rule = sec_service_rule_at(i);
        DWORD start = 0, state = 0, stop_error = 0;
        error = service_query(scm, rule->name, &start, &state);
        if (error == ERROR_SERVICE_DOES_NOT_EXIST) { result("apply", "service", rule->name, "not_installed", 0); ++absent; continue; }
        if (!error && start == rule->start && (rule->start != SERVICE_DISABLED || state == SERVICE_STOPPED)) {
            result("apply", "service", rule->name, "already", 0); ++already; continue;
        }
        /* Never change an item whose original was not recorded. */
        if (!error && !backup_find(SEC_ITEM_SERVICE, rule->name)) error = ERROR_NOT_FOUND;
        if (!error) error = service_configure(scm, rule->name, rule->start, &stop_error);
        if (error) { result("apply", "service", rule->name, "failed", error); ++failed; }
        else if (stop_error) { result("apply", "service", rule->name, "changed_stops_at_restart", stop_error); ++changed; ++restart_needed; }
        else { result("apply", "service", rule->name, "changed", 0); ++changed; }
    }
    CloseServiceHandle(scm);
    for (i = 0; i < sec_registry_rule_count(); ++i) {
        const SEC_REGISTRY_RULE *rule = sec_registry_rule_at(i);
        BYTE data[SEC_BACKUP_DATA_MAX];
        DWORD type, size = sizeof(data);
        unsigned present;
        error = registry_get(rule, &present, &type, data, &size);
        if (!error && secw_registry_matches(rule, present, type, data, size) && !(rule->kind == SEC_REG_MULTI_EMPTY && !present)) {
            result("apply", "registry", rule->id, "already", 0); ++already; continue;
        }
        if (!error) error = registry_apply(rule);
        if (error) { result("apply", "registry", rule->id, "failed", error); ++failed; }
        else {
            result("apply", "registry", rule->id, rule->effect == SEC_EFFECT_RESTART ? "changed_effective_at_restart" : "changed", 0);
            ++changed;
            if (rule->effect == SEC_EFFECT_RESTART) ++restart_needed;
        }
    }
    for (i = 0; i < SEC_AUDIT_CATEGORIES; ++i) {
        wanted[i] = options[i] | sec_audit_baseline(i);
        if (wanted[i] != options[i]) audit_change = TRUE;
    }
    if (!audit_change && mode) { result("apply", "audit", "policy", "already", 0); ++already; }
    else {
        error = audit_set(wanted, 1);
        if (error) { result("apply", "audit", "policy", "failed", error); ++failed; }
        else { result("apply", "audit", "policy", "changed", 0); ++changed; }
    }
    for (i = 0; i < sec_acl_rule_count(); ++i) {
        const SEC_ACL_RULE *rule = sec_acl_rule_at(i);
        ACL_PASS pass, after;
        BOOL exists = FALSE;
        ZeroMemory(&after, sizeof(after));
        error = acl_pass(rule, 0, &pass, &exists);
        if (!error && !exists) { result("apply", "acl", rule->id, "not_present", 0); ++absent; continue; }
        if (!error && !pass.exposed) { result("apply", "acl", rule->id, "already", 0); ++already; continue; }
        if (!error) error = acl_pass(rule, 2, &pass, &exists);
        if (!error) error = acl_pass(rule, 0, &after, &exists);
        if (error || after.exposed) { acl_result("apply", rule, &after, exists, error ? error : pass.first_error, FALSE, FALSE); ++failed; }
        else { acl_result("apply", rule, &pass, exists, 0, TRUE, FALSE); ++changed; }
    }
    if (!RegCreateKeyExW(HKEY_LOCAL_MACHINE, SECW_BASELINE_KEY, 0, NULL, 0, KEY_SET_VALUE, NULL, &key, NULL)) {
        DWORD version = SEC_BASELINE_VERSION;
        WCHAR wide[32];
        secw_utc_now(now, sizeof(now));
        secw_wide(now, wide, 32);
        RegSetValueExW(key, L"Version", 0, REG_DWORD, (BYTE *)&version, sizeof(version));
        RegSetValueExW(key, L"AppliedUtc", 0, REG_SZ, (BYTE *)wide, (DWORD)((lstrlenW(wide) + 1) * sizeof(WCHAR)));
        RegCloseKey(key);
    }
    return failed ? 1 : 0;
}

static int rollback(const WCHAR *file)
{
    SC_HANDLE scm;
    ULONG options[SEC_AUDIT_CATEGORIES];
    unsigned i, mode = 0, c;
    BOOL audit_seen = FALSE;
    DWORD error;
    if (!secw_is_admin()) { secw_error_text("rollback needs an administrator", ERROR_ACCESS_DENIED); return 5; }
    error = backup_load(file);
    if (error) { secw_error_text(error == ERROR_FILE_NOT_FOUND ? "no baseline backup exists" : "the backup cannot be used", error); return 3; }
    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) { secw_error_text("cannot open the service control manager", GetLastError()); return 1; }
    error = audit_get(options, &mode);
    if (error) { secw_error_text("cannot read the audit policy", error); return 1; }
    for (i = 0; i < record_count; ++i) {
        SEC_BACKUP_RECORD *r = &records[i];
        if (r->item == SEC_ITEM_SERVICE) {
            WCHAR wide[128];
            SC_HANDLE service;
            secw_wide(r->id, wide, 128);
            service = OpenServiceW(scm, wide, SERVICE_CHANGE_CONFIG | SERVICE_START | SERVICE_QUERY_STATUS);
            if (!service) { error = GetLastError(); result("rollback", "service", r->id, "failed", error); ++failed; continue; }
            if (!ChangeServiceConfigW(service, SERVICE_NO_CHANGE, r->start, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL)) {
                result("rollback", "service", r->id, "failed", GetLastError()); ++failed;
            } else if (r->running && r->start != SERVICE_DISABLED && !StartServiceW(service, 0, NULL) &&
                       GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
                /* The configuration is restored; the service starts again at the next boot. */
                result("rollback", "service", r->id, "restored_starts_at_restart", GetLastError()); ++changed; ++restart_needed;
            } else { result("rollback", "service", r->id, "restored", 0); ++changed; }
            CloseServiceHandle(service);
        } else if (r->item == SEC_ITEM_REGISTRY) {
            const SEC_REGISTRY_RULE *rule = sec_registry_rule(r->id);
            error = rule ? registry_write(rule, r->present, r->type, r->data, r->size) : ERROR_INVALID_DATA;
            if (error) { result("rollback", "registry", r->id, "failed", error); ++failed; }
            else {
                result("rollback", "registry", r->id, "restored", 0); ++changed;
                if (rule->effect == SEC_EFFECT_RESTART) ++restart_needed;
            }
        } else if (r->item == SEC_ITEM_ACL) {
            const SEC_ACL_RULE *rule = sec_acl_rule(r->id);
            const char *path = (const char *)r->data, *sddl = path + lstrlenA(path) + 1;
            WCHAR object[620], wide[600];
            /* The record names the object; it is honoured only inside its rule's own root. */
            if (!rule || r->size >= SEC_BACKUP_DATA_MAX) { result("rollback", "acl", r->id, "failed", ERROR_INVALID_DATA); ++failed; continue; }
            r->data[r->size] = 0;
            if (!rule) error = ERROR_INVALID_DATA;
            else if (rule->kind == SEC_ACL_TREE_REGISTRY || rule->kind == SEC_ACL_REPAIR_KEYS) {
                HKEY key = NULL;
                error = sec_acl_in_scope(rule, path, "", "") && lstrlenA(path) < 580 ? ERROR_SUCCESS : ERROR_INVALID_DATA;
                secw_wide(path, wide, 600);
                wsprintfW(object, L"MACHINE\\%s", wide);
                if (!error && RegOpenKeyExW(HKEY_LOCAL_MACHINE, wide, 0, KEY_READ, &key) == ERROR_FILE_NOT_FOUND) { result("rollback", "acl", path, "object_gone", 0); ++absent; continue; }
                else if (!error) RegCloseKey(key);
            } else {
                error = sec_acl_in_scope(rule, path, windows_dir, programs_dir) ? ERROR_SUCCESS : ERROR_INVALID_DATA;
                secw_wide(path, object, 600);
                if (!error && GetFileAttributesW(object) == INVALID_FILE_ATTRIBUTES) { result("rollback", "acl", path, "object_gone", 0); ++absent; continue; }
            }
            if (!error) error = secw_sddl_set(object, rule->kind == SEC_ACL_TREE_REGISTRY || rule->kind == SEC_ACL_REPAIR_KEYS ? SE_REGISTRY_KEY : SE_FILE_OBJECT, sddl);
            if (error) { result("rollback", "acl", path, "failed", error); ++failed; }
            else { result("rollback", "acl", path, "restored", 0); ++changed; }
        } else if (r->item == SEC_ITEM_AUDIT) {
            audit_seen = TRUE;
            if (!lstrcmpA(r->id, "mode")) mode = r->options ? 1u : 0u;
            else for (c = 0; c < SEC_AUDIT_CATEGORIES; ++c)
                if (!lstrcmpA(r->id, sec_audit_category_name(c))) options[c] = r->options;
        }
    }
    CloseServiceHandle(scm);
    if (audit_seen) {
        error = audit_set(options, mode);
        if (error) { result("rollback", "audit", "policy", "failed", error); ++failed; }
        else { result("rollback", "audit", "policy", "restored", 0); ++changed; }
    }
    if (!failed) {
        WCHAR path[MAX_PATH], kept[MAX_PATH];
        HKEY key;
        if (!RegOpenKeyExW(HKEY_LOCAL_MACHINE, SECW_BASELINE_KEY, 0, KEY_SET_VALUE, &key)) {
            RegDeleteValueW(key, L"Backup");
            RegDeleteValueW(key, L"AppliedUtc");
            RegDeleteValueW(key, L"Version");
            RegCloseKey(key);
        }
        if (secw_store_path(L"baseline-backup.txt", path, MAX_PATH) && secw_store_path(L"baseline-backup-restored.txt", kept, MAX_PATH))
            MoveFileExW(path, kept, MOVEFILE_REPLACE_EXISTING);
    }
    return failed ? 1 : 0;
}

static int status(void)
{
    SEC_JSON json;
    char applied[64];
    DWORD version = 0, error = backup_load(NULL);
    applied[0] = 0;
    secw_reg_string(HKEY_LOCAL_MACHINE, "SOFTWARE\\XP25\\Security\\Baseline", "AppliedUtc", applied, sizeof(applied));
    secw_reg_dword(HKEY_LOCAL_MACHINE, "SOFTWARE\\XP25\\Security\\Baseline", "Version", &version);
    sec_json_begin(&json, line, sizeof(line));
    sec_json_string(&json, "kind", "status");
    sec_json_bool(&json, "baseline_applied", version != 0 && !error);
    sec_json_uint(&json, "applied_version", version);
    sec_json_uint(&json, "tool_baseline_version", SEC_BASELINE_VERSION);
    sec_json_string(&json, "applied_utc", applied);
    sec_json_bool(&json, "backup_present", !error);
    sec_json_uint(&json, "backup_records", record_count);
    if (error && error != ERROR_FILE_NOT_FOUND) sec_json_uint(&json, "backup_error", error);
    sec_json_uint(&json, "service_rules", sec_service_rule_count());
    sec_json_uint(&json, "registry_rules", sec_registry_rule_count());
    sec_json_uint(&json, "acl_rules", sec_acl_rule_count());
    sec_json_bool(&json, "administrator", secw_is_admin());
    secw_emit(&sink, &json);
    return 0;
}

void __cdecl XP25SecMain(void)
{
    int argc = 0, code = 2, i;
    WCHAR **argv = secw_arguments(&argc);
    const WCHAR *command, *from = NULL;
    char name[32];
    records = allocate(sizeof(SEC_BACKUP_RECORD) * MAX_RECORDS);
    if (!argv || !records || !secw_sink_open(&sink, argc, argv, 2)) ExitProcess(2);
    command = argc > 1 ? argv[1] : L"";
    for (i = 2; i + 1 < argc; ++i) if (!lstrcmpW(argv[i], L"--from")) from = argv[i + 1];
    secw_utf8(command, name, sizeof(name));
    secw_directories(windows_dir, sizeof(windows_dir), programs_dir, sizeof(programs_dir));
    if (!lstrcmpW(command, L"enumerate")) code = enumerate();
    else if (!lstrcmpW(command, L"plan")) { compare("plan", FALSE); code = 0; }
    else if (!lstrcmpW(command, L"verify")) code = compare("verify", TRUE);
    else if (!lstrcmpW(command, L"apply")) code = apply();
    else if (!lstrcmpW(command, L"rollback")) code = rollback(from);
    else if (!lstrcmpW(command, L"status")) code = status();
    else {
        secw_error_text("usage: XP25Sec enumerate|plan|apply|verify|rollback|status [--out <file>] [--serial] [--quiet]", ERROR_INVALID_PARAMETER);
        ExitProcess(2);
    }
    if (lstrcmpW(command, L"status") && lstrcmpW(command, L"enumerate")) summary(name, code);
    secw_sink_close(&sink);
    ExitProcess((UINT)code);
}
