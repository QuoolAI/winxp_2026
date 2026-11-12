/* XP25Audit.exe: read-only security audit for NT 5.1, the first part of the
   XP25 Security Engine.

   report    collect processes, services, drivers, autostart locations,
             listeners, accounts, access control, baseline settings and
             Event Log records, apply the deterministic rules of sec_core.c
             and write one JSON object per line
   snapshot  record the current autostart, service, driver and account
             configuration in the protected store as the reference that
             later reports compare against (administrators only)

   Options: --out <file>  --serial  --quiet  --modules (list loaded modules)
            --privileged (enable SeDebugPrivilege and SeSecurityPrivilege
            when the caller already holds them)

   The audit observes. It opens everything read-only, never stops a process,
   deletes a file or changes configuration, sends nothing over the network
   and needs no model or service. Without --privileged it runs with exactly
   the caller's enabled rights and reports what it could not read. Event
   strings of failed logons are not copied: a mistyped password can appear
   in them. */
#include "sec_win.h"
#include <psapi.h>
#include <iphlpapi.h>
#include <shlobj.h>
#include <oleauto.h>
#include <string.h>

#define MAX_SNAPSHOT 4096
#define SNAPSHOT_BYTES (1024 * 1024)

typedef struct { char *key, *value; int seen; } ENTRY;

static SECW_SINK sink;
static char line[SECW_LINE], finding_line[SECW_LINE];
static char windows_dir[600], programs_dir[600];
static unsigned long findings[4], unreadable, records_of_kind;
static BOOL admin, privileged, list_modules, snapshot_mode, snapshot_loaded, firewall_on, firewall_known;
static ENTRY *snapshot;
static unsigned snapshot_count;
static HANDLE snapshot_file = INVALID_HANDLE_VALUE;

static void *allocate(SIZE_T bytes) { return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytes); }
static void release(void *p) { if (p) HeapFree(GetProcessHeap(), 0, p); }

static void begin(SEC_JSON *json, const char *kind)
{
    sec_json_begin(json, line, sizeof(line));
    sec_json_string(json, "kind", kind);
}

static void emit(SEC_JSON *json)
{
    if (!snapshot_mode) secw_emit(&sink, json);
}

static void finding(int severity, const char *rule, const char *subject, const char *title, const char *detail, const char *advice)
{
    SEC_JSON json;
    if (snapshot_mode) return;
    ++findings[severity < 0 || severity > 3 ? 0 : severity];
    sec_json_begin(&json, finding_line, sizeof(finding_line));
    sec_json_string(&json, "kind", "finding");
    sec_json_string(&json, "severity", sec_severity_name(severity));
    sec_json_string(&json, "rule", rule);
    sec_json_string(&json, "subject", subject);
    sec_json_string(&json, "title", title);
    sec_json_string(&json, "detail", detail ? detail : "");
    sec_json_string(&json, "recommendation", advice ? advice : "");
    secw_emit(&sink, &json);
}

static void cannot_read(const char *what, DWORD error)
{
    SEC_JSON json;
    ++unreadable;
    begin(&json, "unreadable");
    sec_json_string(&json, "source", what);
    sec_json_uint(&json, "error", error);
    emit(&json);
}

/* ---- configuration snapshot -------------------------------------------------- */
static void snapshot_load(void)
{
    WCHAR path[MAX_PATH];
    HANDLE h;
    char *text, *p, *end, *tab;
    DWORD size = 0;
    if (!secw_store_path(L"audit-snapshot.txt", path, MAX_PATH)) return;
    h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    text = allocate(SNAPSHOT_BYTES + 2);
    snapshot = allocate(sizeof(ENTRY) * MAX_SNAPSHOT);
    if (text && snapshot && ReadFile(h, text, SNAPSHOT_BYTES, &size, NULL) && size < SNAPSHOT_BYTES) {
        text[size] = 0;
        for (p = text; *p && snapshot_count < MAX_SNAPSHOT; p = end) {
            for (end = p; *end && *end != '\n'; ++end) { }
            if (*end) *end++ = 0;
            for (tab = p; *tab && *tab != '\t'; ++tab) { }
            if (!*tab) continue;
            *tab = 0;
            snapshot[snapshot_count].key = p;
            snapshot[snapshot_count].value = tab + 1;
            ++snapshot_count;
        }
        snapshot_loaded = snapshot_count > 0;
    }
    CloseHandle(h);
}

/* One configuration item. In snapshot mode it is recorded; in report mode it
   is compared with the recorded reference. Tabs and line breaks never occur
   in keys or values: they are replaced before use. */
static void config_entry(const char *kind, const char *id, const char *value, int severity)
{
    char key[900], clean[1400], detail[2600];
    unsigned i;
    DWORD done;
    wsprintfA(key, "%.40s:%.800s", kind, id);
    lstrcpynA(clean, value ? value : "", sizeof(clean));
    for (i = 0; key[i]; ++i) if (key[i] == '\t' || key[i] == '\n' || key[i] == '\r') key[i] = ' ';
    for (i = 0; clean[i]; ++i) if (clean[i] == '\t' || clean[i] == '\n' || clean[i] == '\r') clean[i] = ' ';
    if (snapshot_mode) {
        if (snapshot_file != INVALID_HANDLE_VALUE) {
            WriteFile(snapshot_file, key, (DWORD)lstrlenA(key), &done, NULL);
            WriteFile(snapshot_file, "\t", 1, &done, NULL);
            WriteFile(snapshot_file, clean, (DWORD)lstrlenA(clean), &done, NULL);
            WriteFile(snapshot_file, "\n", 1, &done, NULL);
            ++records_of_kind;
        }
        return;
    }
    if (!snapshot_loaded) return;
    for (i = 0; i < snapshot_count; ++i)
        if (!lstrcmpA(snapshot[i].key, key)) {
            snapshot[i].seen = 1;
            if (lstrcmpA(snapshot[i].value, clean)) {
                wsprintfA(detail, "now: %.1200s | reference: %.1200s", clean, snapshot[i].value);
                finding(severity, "config.changed", key, "A monitored configuration item changed since the reference snapshot", detail,
                        "Confirm the change was intended; if so, an administrator can record a new snapshot.");
            }
            return;
        }
    finding(severity, "config.added", key, "A monitored configuration item was added since the reference snapshot", clean,
            "Confirm what installed it. Unexpected autostart entries, services, drivers and accounts are how software persists.");
}

static void snapshot_finish(void)
{
    unsigned i;
    if (snapshot_mode || !snapshot_loaded) return;
    for (i = 0; i < snapshot_count; ++i)
        if (!snapshot[i].seen)
            finding(SEC_SEVERITY_LOW, "config.removed", snapshot[i].key, "A monitored configuration item no longer exists",
                    snapshot[i].value, "Removal is usually an uninstall; it matters when a security component disappears.");
}

/* ---- path helpers ---------------------------------------------------------------- */
/* Extracts and expands the program of a service or Run command line. */
static void program_path(const char *command, WCHAR *out, int count)
{
    WCHAR wide[1024], expanded[1024], *p = wide, *end;
    int i;
    out[0] = 0;
    secw_wide(command, wide, 1024);
    while (*p == L' ') ++p;
    if (*p == L'"') {
        ++p;
        for (end = p; *end && *end != L'"'; ++end) { }
        *end = 0;
    } else {
        static const WCHAR *const extensions[] = {L".exe", L".sys", L".dll", L".com", L".bat", L".cmd"};
        WCHAR *cut = NULL;
        for (end = p; *end && !cut; ++end)
            if (*end == L'.' && end[1] && end[2] && end[3] && (end[4] == L' ' || end[4] == 0))
                for (i = 0; i < 6; ++i)
                    if (CompareStringW(LOCALE_INVARIANT, NORM_IGNORECASE, end, 4, extensions[i], 4) == CSTR_EQUAL) cut = end + 4;
        if (cut) *cut = 0;
        else { for (end = p; *end && *end != L' '; ++end) { } *end = 0; }
    }
    if (CompareStringW(LOCALE_INVARIANT, NORM_IGNORECASE, p, 12, L"\\SystemRoot\\", 12) == CSTR_EQUAL) {
        GetWindowsDirectoryW(expanded, MAX_PATH);
        lstrcatW(expanded, p + 11);
    } else if (CompareStringW(LOCALE_INVARIANT, NORM_IGNORECASE, p, 9, L"System32\\", 9) == CSTR_EQUAL) {
        GetWindowsDirectoryW(expanded, MAX_PATH);
        lstrcatW(expanded, L"\\");
        lstrcatW(expanded, p);
    } else if (p[0] == L'\\' && p[1] == L'?' && p[2] == L'?' && p[3] == L'\\') lstrcpynW(expanded, p + 4, 1024);
    else if (!ExpandEnvironmentStringsW(p, expanded, 1024)) expanded[0] = 0;
    lstrcpynW(out, expanded, count);
}

static void path_rules(const char *kind, const char *name, const char *command, BOOL runs_as_system)
{
    unsigned facts = sec_path_facts(command, windows_dir, programs_dir);
    char subject[400];
    wsprintfA(subject, "%.40s %.300s", kind, name);
    if (facts & SEC_PATH_UNQUOTED_SPACE)
        finding(SEC_SEVERITY_MEDIUM, "path.unquoted_with_spaces", subject, "A program path with spaces is not quoted", command,
                "Quote the path: Windows may run a planted program named after the part before the space.");
    if (facts & SEC_PATH_USER_WRITABLE)
        finding(runs_as_system ? SEC_SEVERITY_HIGH : SEC_SEVERITY_MEDIUM, "path.user_writable_location", subject,
                "Code is started from a profile, temporary or recycler directory", command,
                "Programs that start automatically or run as a service belong in a directory ordinary users cannot change.");
    if (facts & SEC_PATH_NETWORK)
        finding(SEC_SEVERITY_HIGH, "path.network_location", subject, "Code is started from a network path", command,
                "A network path can be answered by any computer that claims the name.");
}

static void binary_acl_rule(const char *kind, const char *name, const char *command)
{
    WCHAR path[1024];
    char subject[400], detail[1200], who_text[200], utf8[800];
    unsigned who = 0;
    program_path(command, path, 1024);
    if (!path[0] || path[1] != L':') return;
    if (secw_object_writers(path, SE_FILE_OBJECT, SECW_FILE_WRITE, &who) || !(who & SECW_WHO_UNPRIVILEGED)) return;
    secw_who_text(who & SECW_WHO_UNPRIVILEGED, who_text, sizeof(who_text));
    secw_utf8(path, utf8, sizeof(utf8));
    wsprintfA(subject, "%.40s %.300s", kind, name);
    wsprintfA(detail, "%.800s is writable by %.190s", utf8, who_text);
    finding(SEC_SEVERITY_HIGH, "acl.program_writable", subject, "A privileged program file can be replaced by unprivileged accounts", detail,
            "Restrict the file to Administrators and SYSTEM for writing.");
}

/* ---- collectors ---------------------------------------------------------------------- */
static void collect_system(void)
{
    OSVERSIONINFOEXW version;
    WCHAR name[MAX_COMPUTERNAME_LENGTH + 2], user[300];
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1, baseline = 0;
    char text[700], applied[64];
    SEC_JSON json;
    ZeroMemory(&version, sizeof(version));
    version.dwOSVersionInfoSize = sizeof(version);
    GetVersionExW((OSVERSIONINFOW *)&version);
    begin(&json, "system");
    sec_json_string(&json, "tool", "XP25Audit");
    sec_json_uint(&json, "schema", 1);
    sec_json_uint(&json, "baseline_version_known", SEC_BASELINE_VERSION);
    secw_utc_now(text, sizeof(text));
    sec_json_string(&json, "utc", text);
    wsprintfA(text, "%lu.%lu.%lu", version.dwMajorVersion, version.dwMinorVersion, version.dwBuildNumber);
    sec_json_string(&json, "os_version", text);
    secw_utf8(version.szCSDVersion, text, sizeof(text));
    sec_json_string(&json, "service_pack", text);
    name[0] = 0;
    GetComputerNameW(name, &size);
    secw_utf8(name, text, sizeof(text));
    sec_json_string(&json, "computer", text);
    size = 300; user[0] = 0;
    GetUserNameW(user, &size);
    secw_utf8(user, text, sizeof(text));
    sec_json_string(&json, "audit_user", text);
    sec_json_bool(&json, "administrator", admin);
    sec_json_bool(&json, "privileged_mode", privileged);
    applied[0] = 0;
    secw_reg_dword(HKEY_LOCAL_MACHINE, "SOFTWARE\\XP25\\Security\\Baseline", "Version", &baseline);
    secw_reg_string(HKEY_LOCAL_MACHINE, "SOFTWARE\\XP25\\Security\\Baseline", "AppliedUtc", applied, sizeof(applied));
    sec_json_bool(&json, "baseline_applied", baseline != 0);
    sec_json_string(&json, "baseline_applied_utc", applied);
    sec_json_bool(&json, "reference_snapshot", snapshot_loaded);
    sec_json_uint(&json, "reference_snapshot_items", snapshot_count);
    emit(&json);
    if (!baseline)
        finding(SEC_SEVERITY_MEDIUM, "baseline.not_applied", "XP25 security baseline", "The XP25 security baseline has not been applied",
                "No baseline state is recorded in HKLM\\SOFTWARE\\XP25\\Security\\Baseline.",
                "An administrator can run XP25Sec plan to review it and XP25Sec apply to apply it.");
    if (!snapshot_loaded)
        finding(SEC_SEVERITY_LOW, "config.no_reference_snapshot", "XP25 audit", "No reference snapshot exists",
                "Configuration changes cannot be detected without a reference.", "An administrator can run XP25Audit snapshot.");
}

static BOOL token_identity(HANDLE process, char *account, int size, BOOL *is_service_account, DWORD *session)
{
    HANDLE token;
    BYTE buffer[256];
    TOKEN_USER *user = (TOKEN_USER *)buffer;
    DWORD bytes;
    BOOL ok;
    *is_service_account = FALSE; *session = 0;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token)) return FALSE;
    ok = GetTokenInformation(token, TokenUser, user, sizeof(buffer), &bytes);
    if (ok) {
        secw_account(user->User.Sid, account, size);
        *is_service_account = IsWellKnownSid(user->User.Sid, WinLocalSystemSid) || IsWellKnownSid(user->User.Sid, WinLocalServiceSid) ||
                              IsWellKnownSid(user->User.Sid, WinNetworkServiceSid);
    }
    GetTokenInformation(token, TokenSessionId, session, sizeof(*session), &bytes);
    CloseHandle(token);
    return ok;
}

static void collect_processes(void)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W entry;
    HMODULE *modules = allocate(sizeof(HMODULE) * 2048);
    unsigned long total = 0, opened = 0;
    SEC_JSON json;
    if (snap == INVALID_HANDLE_VALUE || !modules) { cannot_read("process list", GetLastError()); return; }
    ZeroMemory(&entry, sizeof(entry));
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snap, &entry)) do {
        char name[400], image[800], account[300];
        WCHAR path[MAX_PATH * 2];
        HANDLE process = entry.th32ProcessID ? OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, entry.th32ProcessID) : NULL;
        BOOL service_account = FALSE, identified = FALSE;
        DWORD session = 0, needed = 0, count = 0, i;
        ++total;
        secw_utf8(entry.szExeFile, name, sizeof(name));
        image[0] = 0; account[0] = 0;
        begin(&json, "process");
        sec_json_uint(&json, "pid", entry.th32ProcessID);
        sec_json_uint(&json, "parent_pid", entry.th32ParentProcessID);
        sec_json_string(&json, "name", name);
        sec_json_uint(&json, "threads", entry.cntThreads);
        if (process) {
            ++opened;
            if (GetModuleFileNameExW(process, NULL, path, MAX_PATH * 2)) secw_utf8(path, image, sizeof(image));
            identified = token_identity(process, account, sizeof(account), &service_account, &session);
            if (EnumProcessModules(process, modules, sizeof(HMODULE) * 2048, &needed)) count = needed / sizeof(HMODULE);
            if (count > 2048) count = 2048;
        }
        sec_json_bool(&json, "accessible", process != NULL);
        sec_json_string(&json, "image", image);
        sec_json_string(&json, "account", account);
        sec_json_bool(&json, "service_account", service_account);
        sec_json_uint(&json, "session", session);
        sec_json_uint(&json, "modules", count);
        emit(&json);
        if (image[0] && identified) {
            unsigned facts = sec_path_facts(image, windows_dir, programs_dir);
            if (service_account && (facts & SEC_PATH_USER_WRITABLE))
                finding(SEC_SEVERITY_HIGH, "process.service_account_from_user_writable_path", name,
                        "A process with a service account runs from a user-writable location", image,
                        "Investigate the file's origin before trusting it; nothing was stopped.");
            else if (service_account && (facts & SEC_PATH_OUTSIDE_SYSTEM))
                finding(SEC_SEVERITY_MEDIUM, "process.service_account_outside_system_directories", name,
                        "A process with a service account runs from outside the Windows and Program Files directories", image,
                        "Confirm which product installed it.");
        }
        for (i = 1; i < count; ++i) {
            char module[800];
            if (!GetModuleFileNameExW(process, modules[i], path, MAX_PATH * 2)) continue;
            secw_utf8(path, module, sizeof(module));
            if (list_modules) {
                begin(&json, "module");
                sec_json_uint(&json, "pid", entry.th32ProcessID);
                sec_json_string(&json, "path", module);
                emit(&json);
            }
            if (service_account && (sec_path_facts(module, windows_dir, programs_dir) & SEC_PATH_USER_WRITABLE)) {
                char subject[600];
                wsprintfA(subject, "%.200s (pid %lu)", name, entry.th32ProcessID);
                finding(SEC_SEVERITY_HIGH, "process.module_from_user_writable_path", subject,
                        "A service-account process loaded a module from a user-writable location", module,
                        "Investigate the module; injection into privileged processes is a common escalation step.");
            }
        }
        if (process) CloseHandle(process);
    } while (Process32NextW(snap, &entry));
    CloseHandle(snap);
    release(modules);
    begin(&json, "process_summary");
    sec_json_uint(&json, "processes", total);
    sec_json_uint(&json, "accessible", opened);
    emit(&json);
}

static const char *start_text(DWORD start)
{
    static const char *const names[] = {"boot", "system", "auto", "manual", "disabled"};
    return start <= SERVICE_DISABLED ? names[start] : "unknown";
}

static void collect_services(void)
{
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    BYTE *buffer = allocate(65536), config_buffer[8192], sd_buffer[4096];
    QUERY_SERVICE_CONFIGW *config = (QUERY_SERVICE_CONFIGW *)config_buffer;
    DWORD needed, count, resume = 0, i, error;
    unsigned long services = 0, drivers = 0, running = 0;
    BOOL more = TRUE;
    SEC_JSON json;
    if (!scm || !buffer) { cannot_read("service control manager", GetLastError()); return; }
    while (more) {
        ENUM_SERVICE_STATUS_PROCESSW *entries = (ENUM_SERVICE_STATUS_PROCESSW *)buffer;
        more = FALSE;
        if (!EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32 | SERVICE_DRIVER, SERVICE_STATE_ALL, buffer, 65536,
                                   &needed, &count, &resume, NULL)) {
            error = GetLastError();
            if (error != ERROR_MORE_DATA) { cannot_read("service enumeration", error); break; }
            more = TRUE;
        }
        for (i = 0; i < count; ++i) {
            char name[200], account[300], image[1100], value[1700];
            const SEC_SERVICE_RULE *rule;
            SC_HANDLE service = OpenServiceW(scm, entries[i].lpServiceName, SERVICE_QUERY_CONFIG | READ_CONTROL);
            DWORD state = entries[i].ServiceStatusProcess.dwCurrentState, type = entries[i].ServiceStatusProcess.dwServiceType;
            BOOL driver = (type & SERVICE_DRIVER) != 0, system_account;
            secw_utf8(entries[i].lpServiceName, name, sizeof(name));
            if (!service || !QueryServiceConfigW(service, config, sizeof(config_buffer), &needed)) {
                cannot_read(name, GetLastError());
                if (service) CloseServiceHandle(service);
                continue;
            }
            secw_utf8(config->lpServiceStartName, account, sizeof(account));
            secw_utf8(config->lpBinaryPathName, image, sizeof(image));
            system_account = driver || !account[0] || sec_equal_nocase(account, "LocalSystem");
            begin(&json, driver ? "driver" : "service");
            sec_json_string(&json, "name", name);
            sec_json_string(&json, "start", start_text(config->dwStartType));
            sec_json_bool(&json, "running", state == SERVICE_RUNNING);
            if (!driver) {
                sec_json_string(&json, "account", account);
                sec_json_uint(&json, "pid", entries[i].ServiceStatusProcess.dwProcessId);
            }
            sec_json_string(&json, "image", image);
            if (driver) ++drivers; else ++services;
            if (state == SERVICE_RUNNING) ++running;
            rule = driver ? NULL : sec_service_rule(name);
            if (rule) {
                BOOL ok = config->dwStartType == rule->start && (rule->start != SERVICE_DISABLED || state == SERVICE_STOPPED);
                sec_json_bool(&json, "baseline_managed", 1);
                sec_json_bool(&json, "baseline_compliant", ok);
                emit(&json);
                if (!ok)
                    finding(state != SERVICE_STOPPED ? SEC_SEVERITY_HIGH : SEC_SEVERITY_MEDIUM, "service.baseline_deviation", name,
                            state != SERVICE_STOPPED ? "A service the baseline disables is running" : "A service the baseline disables can be started",
                            rule->reason, "An administrator can run XP25Sec apply; nothing was changed by this audit.");
            } else emit(&json);
            wsprintfA(value, "start=%s;account=%.200s;image=%.1090s", start_text(config->dwStartType), account, image);
            config_entry(driver ? "driver" : "service", name, value, driver ? SEC_SEVERITY_HIGH : SEC_SEVERITY_MEDIUM);
            if (image[0] && config->dwStartType != SERVICE_DISABLED) {
                path_rules(driver ? "driver" : "service", name, image, system_account);
                if (type & (SERVICE_WIN32_OWN_PROCESS | SERVICE_DRIVER)) binary_acl_rule(driver ? "driver" : "service", name, image);
            }
            if (QueryServiceObjectSecurity(service, DACL_SECURITY_INFORMATION, sd_buffer, sizeof(sd_buffer), &needed)) {
                PACL dacl = NULL;
                BOOL present = FALSE, defaulted = FALSE;
                unsigned who;
                if (GetSecurityDescriptorDacl(sd_buffer, &present, &dacl, &defaulted)) {
                    who = secw_dacl_writers(dacl, present, SECW_SERVICE_WRITE) & SECW_WHO_UNPRIVILEGED;
                    if (who) {
                        char who_text[200];
                        secw_who_text(who, who_text, sizeof(who_text));
                        finding(SEC_SEVERITY_HIGH, "acl.service_configurable", name,
                                "Unprivileged accounts can reconfigure a service", who_text,
                                "A service's image path decides what runs as its account; only administrators may change it.");
                    }
                }
            }
            CloseServiceHandle(service);
        }
    }
    CloseServiceHandle(scm);
    release(buffer);
    begin(&json, "service_summary");
    sec_json_uint(&json, "services", services);
    sec_json_uint(&json, "drivers", drivers);
    sec_json_uint(&json, "running", running);
    emit(&json);
}

static void collect_kernel_modules(void)
{
    void **bases = allocate(sizeof(void *) * 1024);
    DWORD needed = 0, count, i;
    unsigned long outside = 0, kernel = 0;
    SEC_JSON json;
    if (!bases || !EnumDeviceDrivers(bases, sizeof(void *) * 1024, &needed)) { cannot_read("loaded kernel modules", GetLastError()); release(bases); return; }
    count = needed / sizeof(void *);
    if (count > 1024) count = 1024;
    for (i = 0; i < count; ++i) {
        WCHAR path[MAX_PATH * 2];
        char text[800];
        /* A checked kernel also lists user-mode images here; kernel modules load at or above 0x80000000. */
        if ((ULONG_PTR)bases[i] < 0x80000000UL) continue;
        ++kernel;
        if (!GetDeviceDriverFileNameW(bases[i], path, MAX_PATH * 2)) continue;
        secw_utf8(path, text, sizeof(text));
        begin(&json, "kernel_module");
        sec_json_string(&json, "path", text);
        emit(&json);
        /* The kernel reports \WINDOWS\system32\..., \SystemRoot\... or \??\C:\... forms. */
        CharLowerA(text);
        /* Modules the loader starts before the file system (kernel, HAL, boot drivers) carry no path. */
        if (strchr(text, '\\') && !strstr(text, "\\system32\\")) {
            ++outside;
            finding(SEC_SEVERITY_MEDIUM, "driver.loaded_outside_system32", text, "A kernel module is loaded from outside system32", text,
                    "Kernel code has full control of the computer; confirm which product installed it.");
        }
    }
    begin(&json, "kernel_module_summary");
    sec_json_uint(&json, "loaded", kernel);
    sec_json_uint(&json, "outside_system32", outside);
    emit(&json);
    release(bases);
}

static void autostart_entry(const SEC_AUTOSTART *location, const char *hive, const char *name, const char *command, BOOL user_hive)
{
    char id[900], subject[900];
    int kind = location->kind & 0xff;
    SEC_JSON json;
    begin(&json, "autostart");
    sec_json_string(&json, "location", location->id);
    sec_json_string(&json, "hive", hive);
    sec_json_string(&json, "name", name);
    sec_json_string(&json, "command", command);
    emit(&json);
    wsprintfA(id, "%s\\%.60s\\%.700s", hive, location->id, name);
    wsprintfA(subject, "%s %.60s: %.700s", hive, location->id, name);
    config_entry("autostart", id, command, location->severity);
    if (!command[0]) return;
    if (location->kind & SEC_AS_ANY_IS_FINDING)
        finding(location->severity, "autostart.rarely_used_location", subject, "An autostart location that is empty on an unmodified system is in use",
                command, "Confirm what created it; debugger and legacy run keys are favoured for hidden persistence.");
    else if (kind == SEC_AS_SINGLE || kind == SEC_AS_MULTI) {
        /* A per-user copy of a machine setting overrides it for that user: any value is a deviation. */
        if (user_hive || (location->expected && !sec_autostart_default(location, command, windows_dir)))
            finding(location->severity, "autostart.nondefault", subject, "A logon or system start setting differs from the installed default",
                    command, "Compare with the installed default before changing anything; these settings decide what runs at logon.");
    } else if (kind == SEC_AS_VALUES)
        path_rules("autostart", subject, command, !user_hive);
}

static void collect_autostart_key(const SEC_AUTOSTART *location, HKEY root, const char *hive, BOOL user_hive)
{
    WCHAR key[512], name[400], data[1024];
    char name8[900], data8[1400];
    HKEY handle, child;
    DWORD i, type, name_count, bytes, error;
    int kind = location->kind & 0xff;
    secw_wide(location->key, key, 512);
    error = (DWORD)RegOpenKeyExW(root, key, 0, KEY_READ, &handle);
    if (error) {
        if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) cannot_read(location->id, error);
        else if (kind == SEC_AS_SINGLE && !user_hive) autostart_entry(location, hive, location->value, "", user_hive);
        return;
    }
    if (kind == SEC_AS_VALUES) {
        for (i = 0; ; ++i) {
            name_count = 400; bytes = sizeof(data) - sizeof(WCHAR);
            error = (DWORD)RegEnumValueW(handle, i, name, &name_count, NULL, &type, (BYTE *)data, &bytes);
            if (error == ERROR_NO_MORE_ITEMS) break;
            if (error && error != ERROR_MORE_DATA) break;
            if (error || (type != REG_SZ && type != REG_EXPAND_SZ)) continue;
            data[bytes / sizeof(WCHAR)] = 0;
            secw_utf8(name, name8, sizeof(name8));
            secw_utf8(data, data8, sizeof(data8));
            if (!name8[0] && !data8[0]) continue;
            autostart_entry(location, hive, name8, data8, user_hive);
        }
    } else if (kind == SEC_AS_SINGLE || kind == SEC_AS_MULTI) {
        WCHAR value[256], *p;
        secw_wide(location->value, value, 256);
        bytes = sizeof(data) - 2 * sizeof(WCHAR); type = 0;
        error = (DWORD)RegQueryValueExW(handle, value, NULL, &type, (BYTE *)data, &bytes);
        if (error) bytes = 0;
        data[bytes / sizeof(WCHAR)] = 0; data[bytes / sizeof(WCHAR) + 1] = 0;
        if (kind == SEC_AS_SINGLE) {
            secw_utf8(data, data8, sizeof(data8));
            if (!user_hive || data8[0]) autostart_entry(location, hive, location->value, data8, user_hive);
        } else for (p = data; *p; p += lstrlenW(p) + 1) {
            secw_utf8(p, data8, sizeof(data8));
            autostart_entry(location, hive, data8, data8, user_hive);
        }
    } else if (kind == SEC_AS_SUBKEYS) {
        WCHAR value[256];
        secw_wide(location->value, value, 256);
        for (i = 0; ; ++i) {
            name_count = 400;
            error = (DWORD)RegEnumKeyExW(handle, i, name, &name_count, NULL, NULL, NULL, NULL);
            if (error) break;
            if (RegOpenKeyExW(handle, name, 0, KEY_QUERY_VALUE, &child)) continue;
            bytes = sizeof(data) - sizeof(WCHAR); type = 0;
            if (!RegQueryValueExW(child, value, NULL, &type, (BYTE *)data, &bytes) && (type == REG_SZ || type == REG_EXPAND_SZ)) {
                data[bytes / sizeof(WCHAR)] = 0;
                secw_utf8(name, name8, sizeof(name8));
                secw_utf8(data, data8, sizeof(data8));
                /* The sample key Windows ships shows the syntax and names no real image. */
                if (lstrcmpiA(name8, "Your Image File Name Here without a path")) autostart_entry(location, hive, name8, data8, user_hive);
            }
            RegCloseKey(child);
        }
    }
    RegCloseKey(handle);
}

static void collect_directory(const WCHAR *directory, const WCHAR *pattern, const char *kind, int severity)
{
    WCHAR search[MAX_PATH * 2];
    WIN32_FIND_DATAW found;
    HANDLE h;
    SEC_JSON json;
    char name[900], dir8[800], value[100], stamp[32];
    if (lstrlenW(directory) + lstrlenW(pattern) + 2 >= MAX_PATH * 2) return;
    wsprintfW(search, L"%s\\%s", directory, pattern);
    secw_utf8(directory, dir8, sizeof(dir8));
    h = FindFirstFileW(search, &found);
    if (h == INVALID_HANDLE_VALUE) {
        if (GetLastError() != ERROR_FILE_NOT_FOUND && GetLastError() != ERROR_PATH_NOT_FOUND) cannot_read(dir8, GetLastError());
        return;
    }
    do {
        char file[600], id[1500];
        if (found.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        secw_utf8(found.cFileName, file, sizeof(file));
        if (!lstrcmpiA(file, "desktop.ini") || !lstrcmpiA(file, "SA.DAT")) continue;
        wsprintfA(name, "%.290s", file);
        wsprintfA(id, "%.790s\\%.590s", dir8, file);
        secw_filetime_text(&found.ftLastWriteTime, stamp, sizeof(stamp));
        wsprintfA(value, "size=%lu;modified=%s", found.nFileSizeLow, stamp);
        begin(&json, kind);
        sec_json_string(&json, "directory", dir8);
        sec_json_string(&json, "name", name);
        sec_json_uint(&json, "size", found.nFileSizeLow);
        sec_json_string(&json, "modified_utc", stamp);
        emit(&json);
        config_entry(kind, id, value, severity);
    } while (FindNextFileW(h, &found));
    FindClose(h);
}

static void collect_autostart(void)
{
    WCHAR path[MAX_PATH * 2];
    unsigned i;
    for (i = 0; i < sec_autostart_count(); ++i) {
        const SEC_AUTOSTART *location = sec_autostart_at(i);
        collect_autostart_key(location, HKEY_LOCAL_MACHINE, "HKLM", FALSE);
        if (location->per_user) collect_autostart_key(location, HKEY_CURRENT_USER, "HKCU", TRUE);
    }
    if (SHGetSpecialFolderPathW(NULL, path, CSIDL_COMMON_STARTUP, FALSE)) collect_directory(path, L"*", "startup_file", SEC_SEVERITY_MEDIUM);
    if (SHGetSpecialFolderPathW(NULL, path, CSIDL_STARTUP, FALSE)) collect_directory(path, L"*", "startup_file", SEC_SEVERITY_MEDIUM);
    if (GetWindowsDirectoryW(path, MAX_PATH)) {
        lstrcatW(path, L"\\Tasks");
        collect_directory(path, L"*.job", "scheduled_task", SEC_SEVERITY_MEDIUM);
    }
}

/* Reads one property of an automation object by name. */
static HRESULT property(IDispatch *object, const WCHAR *name, VARIANT *out)
{
    DISPID id;
    DISPPARAMS none;
    LPOLESTR names[1];
    HRESULT hr;
    names[0] = (LPOLESTR)name;
    ZeroMemory(&none, sizeof(none));
    VariantInit(out);
    hr = object->lpVtbl->GetIDsOfNames(object, &IID_NULL, names, 1, LOCALE_SYSTEM_DEFAULT, &id);
    if (FAILED(hr)) return hr;
    return object->lpVtbl->Invoke(object, id, &IID_NULL, LOCALE_SYSTEM_DEFAULT, DISPATCH_PROPERTYGET, &none, out, NULL, NULL);
}

/* The firewall's own answer (HNetCfg.FwMgr), not an inference from the registry. */
static void collect_firewall(void)
{
    static const CLSID manager_class = {0x304ce942, 0x6e39, 0x40d8, {0x94, 0x3a, 0xb9, 0x13, 0xc4, 0x0c, 0x9c, 0xd4}};
    IDispatch *manager = NULL;
    VARIANT policy, profile, enabled, exceptions, type;
    SEC_JSON json;
    HRESULT hr = CoInitialize(NULL);
    BOOL no_exceptions = FALSE;
    long profile_type = -1;
    VariantInit(&policy); VariantInit(&profile); VariantInit(&enabled); VariantInit(&exceptions); VariantInit(&type);
    if (SUCCEEDED(hr)) hr = CoCreateInstance(&manager_class, NULL, CLSCTX_INPROC_SERVER, &IID_IDispatch, (void **)&manager);
    if (SUCCEEDED(hr)) hr = property(manager, L"LocalPolicy", &policy);
    if (SUCCEEDED(hr) && policy.vt == VT_DISPATCH && policy.pdispVal) hr = property(policy.pdispVal, L"CurrentProfile", &profile);
    else if (SUCCEEDED(hr)) hr = E_NOINTERFACE;
    if (SUCCEEDED(hr) && profile.vt == VT_DISPATCH && profile.pdispVal) {
        hr = property(profile.pdispVal, L"FirewallEnabled", &enabled);
        if (SUCCEEDED(hr) && SUCCEEDED(property(profile.pdispVal, L"ExceptionsNotAllowed", &exceptions))) no_exceptions = exceptions.boolVal != 0;
        if (SUCCEEDED(hr) && SUCCEEDED(property(profile.pdispVal, L"Type", &type))) profile_type = type.lVal;
    } else if (SUCCEEDED(hr)) hr = E_NOINTERFACE;
    if (SUCCEEDED(hr) && enabled.vt == VT_BOOL) { firewall_known = TRUE; firewall_on = enabled.boolVal != 0; }
    begin(&json, "firewall");
    sec_json_bool(&json, "state_known", firewall_known);
    sec_json_bool(&json, "enabled", firewall_on);
    sec_json_bool(&json, "exceptions_not_allowed", no_exceptions);
    sec_json_string(&json, "profile", profile_type == 0 ? "domain" : profile_type == 1 ? "standard" : "unknown");
    if (FAILED(hr)) sec_json_uint(&json, "hresult", (unsigned long)hr);
    emit(&json);
    VariantClear(&policy); VariantClear(&profile); VariantClear(&enabled); VariantClear(&exceptions); VariantClear(&type);
    if (manager) manager->lpVtbl->Release(manager);
    if (!firewall_known) cannot_read("Windows Firewall state", (DWORD)hr);
    else if (!firewall_on)
        finding(SEC_SEVERITY_HIGH, "network.firewall_off", "Windows Firewall", "Windows Firewall is not filtering inbound connections",
                "Every listening port is reachable from the network.", "An administrator can run XP25Sec apply and restart.");
}

static void process_name(DWORD pid, char *out, int size)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W entry;
    out[0] = 0;
    if (snap == INVALID_HANDLE_VALUE) return;
    ZeroMemory(&entry, sizeof(entry));
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snap, &entry)) do {
        if (entry.th32ProcessID == pid) { secw_utf8(entry.szExeFile, out, size); break; }
    } while (Process32NextW(snap, &entry));
    CloseHandle(snap);
}

static void listener(int udp, DWORD address, DWORD port_network, DWORD pid, BOOL pid_known)
{
    unsigned short port = (unsigned short)(((port_network & 0xff) << 8) | ((port_network >> 8) & 0xff));
    const BYTE *a = (const BYTE *)&address;
    const SEC_PORT *known = sec_port_lookup(port, udp);
    BOOL loopback = a[0] == 127;
    char text[32], name[300], subject[80], detail[400];
    SEC_JSON json;
    wsprintfA(text, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
    name[0] = 0;
    if (pid_known) process_name(pid, name, sizeof(name));
    begin(&json, "listener");
    sec_json_string(&json, "protocol", udp ? "udp" : "tcp");
    sec_json_string(&json, "address", text);
    sec_json_uint(&json, "port", port);
    sec_json_bool(&json, "loopback_only", loopback);
    if (pid_known) { sec_json_uint(&json, "pid", pid); sec_json_string(&json, "process", name); }
    if (known) { sec_json_string(&json, "known_as", known->name); sec_json_string(&json, "usual_owner", known->owner); }
    emit(&json);
    if (known && !loopback) {
        BOOL filtered = firewall_known && firewall_on;
        wsprintfA(subject, "%s %u", udp ? "UDP" : "TCP", port);
        wsprintfA(detail, "%.60s is bound on %s (process %.100s, usual owner %.60s). Windows Firewall %s.", known->name, text,
                  name[0] ? name : "unknown", known->owner,
                  filtered ? "is on, so the port is reachable only through an exception" : "is off or unknown, so the port is reachable from the network");
        finding(filtered ? SEC_SEVERITY_LOW : known->severity, "network.legacy_listener", subject,
                "A legacy network service is bound to a network address", detail,
                "Disable the owning service if it is not needed; the baseline lists the ones it disables.");
    }
}

typedef DWORD (WINAPI *EXTENDED_TABLE)(void *, DWORD *, BOOL, ULONG, int, ULONG);
#define IPV4_FAMILY 2           /* AF_INET, without pulling in a sockets header */

static void collect_listeners(void)
{
    HMODULE ip = GetModuleHandleW(L"iphlpapi.dll");
    EXTENDED_TABLE tcp_table = ip ? (EXTENDED_TABLE)GetProcAddress(ip, "GetExtendedTcpTable") : NULL;
    EXTENDED_TABLE udp_table = ip ? (EXTENDED_TABLE)GetProcAddress(ip, "GetExtendedUdpTable") : NULL;
    DWORD *table = allocate(262144), size = 262144, i, error;
    unsigned long tcp = 0, udp = 0;
    BOOL with_pid;
    SEC_JSON json;
    if (!table) return;
    /* Class 3 = TCP_TABLE_OWNER_PID_LISTENER: rows of state, local address, local port, remote address, remote port, pid. */
    with_pid = tcp_table && tcp_table(table, &size, FALSE, IPV4_FAMILY, 3, 0) == NO_ERROR;
    if (with_pid) {
        for (i = 0; i < table[0]; ++i, ++tcp) listener(0, table[1 + i * 6 + 1], table[1 + i * 6 + 2], table[1 + i * 6 + 5], TRUE);
    } else {
        size = 262144;
        error = GetTcpTable((MIB_TCPTABLE *)table, &size, FALSE);
        if (error) cannot_read("TCP listener table", error);
        else for (i = 0; i < table[0]; ++i)
            if (table[1 + i * 5] == MIB_TCP_STATE_LISTEN) { listener(0, table[1 + i * 5 + 1], table[1 + i * 5 + 2], 0, FALSE); ++tcp; }
    }
    /* Class 1 = UDP_TABLE_OWNER_PID: rows of local address, local port, pid. */
    size = 262144;
    if (udp_table && udp_table(table, &size, FALSE, IPV4_FAMILY, 1, 0) == NO_ERROR) {
        for (i = 0; i < table[0]; ++i, ++udp) listener(1, table[1 + i * 3], table[1 + i * 3 + 1], table[1 + i * 3 + 2], TRUE);
    } else {
        size = 262144;
        error = GetUdpTable((MIB_UDPTABLE *)table, &size, FALSE);
        if (error) cannot_read("UDP endpoint table", error);
        else for (i = 0; i < table[0]; ++i, ++udp) listener(1, table[1 + i * 2], table[1 + i * 2 + 1], 0, FALSE);
    }
    begin(&json, "listener_summary");
    sec_json_uint(&json, "tcp_listeners", tcp);
    sec_json_uint(&json, "udp_endpoints", udp);
    sec_json_bool(&json, "owner_process_known", with_pid);
    emit(&json);
    release(table);
}

static void collect_settings(void)
{
    unsigned i, deviations = 0;
    SEC_JSON json;
    for (i = 0; i < sec_registry_rule_count(); ++i) {
        const SEC_REGISTRY_RULE *rule = sec_registry_rule_at(i);
        char current[400], detail[900];
        DWORD error = 0;
        BOOL ok = secw_registry_rule_state(rule, current, sizeof(current), &error);
        begin(&json, "setting");
        sec_json_string(&json, "id", rule->id);
        sec_json_string(&json, "area", rule->area);
        sec_json_string(&json, "current", current);
        sec_json_bool(&json, "compliant", ok);
        if (error) sec_json_uint(&json, "error", error);
        emit(&json);
        if (error) { ++unreadable; continue; }
        if (!ok) {
            ++deviations;
            wsprintfA(detail, "HKLM\\%.300s [%.80s] is %.200s. %.250s", rule->key, rule->value, current, rule->reason);
            finding(SEC_SEVERITY_MEDIUM, "baseline.setting_deviation", rule->id, "A hardened setting is not in force", detail,
                    "An administrator can run XP25Sec apply; nothing was changed by this audit.");
        }
    }
    begin(&json, "setting_summary");
    sec_json_uint(&json, "settings", sec_registry_rule_count());
    sec_json_uint(&json, "deviations", deviations);
    emit(&json);
}

static void collect_accounts(void)
{
    USER_INFO_1 *users = NULL;
    LOCALGROUP_MEMBERS_INFO_2 *members = NULL;
    DWORD read = 0, total = 0, resume = 0, i, status;
    unsigned long administrators = 0;
    static const WCHAR *const groups[] = {L"Administrators", L"Power Users", L"Remote Desktop Users", L"Backup Operators"};
    unsigned g;
    SEC_JSON json;
    status = NetUserEnum(NULL, 1, FILTER_NORMAL_ACCOUNT, (BYTE **)&users, MAX_PREFERRED_LENGTH, &read, &total, &resume);
    if (status && status != ERROR_MORE_DATA) cannot_read("local accounts", status);
    else for (i = 0; i < read; ++i) {
        char name[300], value[120];
        BOOL disabled = (users[i].usri1_flags & UF_ACCOUNTDISABLE) != 0;
        secw_utf8(users[i].usri1_name, name, sizeof(name));
        begin(&json, "account");
        sec_json_string(&json, "name", name);
        sec_json_string(&json, "privilege", users[i].usri1_priv == USER_PRIV_ADMIN ? "administrator" :
                        users[i].usri1_priv == USER_PRIV_USER ? "user" : "guest");
        sec_json_bool(&json, "disabled", disabled);
        sec_json_bool(&json, "password_not_required", (users[i].usri1_flags & UF_PASSWD_NOTREQD) != 0);
        sec_json_bool(&json, "password_never_expires", (users[i].usri1_flags & UF_DONT_EXPIRE_PASSWD) != 0);
        emit(&json);
        wsprintfA(value, "privilege=%lu;disabled=%d", users[i].usri1_priv, disabled);
        config_entry("account", name, value, SEC_SEVERITY_MEDIUM);
        if (!disabled && users[i].usri1_priv == USER_PRIV_ADMIN) ++administrators;
        if (!disabled && users[i].usri1_priv == USER_PRIV_GUEST)
            finding(SEC_SEVERITY_HIGH, "account.guest_enabled", name, "A guest account is enabled", "",
                    "Disable it unless anonymous local use is intended.");
        if (!disabled && (users[i].usri1_flags & UF_PASSWD_NOTREQD))
            finding(SEC_SEVERITY_MEDIUM, "account.password_not_required", name, "An enabled account may have an empty password by policy", "",
                    "Set a password; blank-password accounts are limited to console logon only while LimitBlankPasswordUse is 1.");
    }
    if (users) NetApiBufferFree(users);
    if (administrators > 1) {
        char detail[80];
        wsprintfA(detail, "%lu enabled administrator accounts", administrators);
        finding(SEC_SEVERITY_LOW, "account.several_administrators", "local accounts", "More than one administrator account is enabled", detail,
                "Daily use of an administrator account removes the boundary between programs and the system; keep one for administration.");
    }
    for (g = 0; g < sizeof(groups) / sizeof(groups[0]); ++g) {
        char group[80];
        secw_utf8(groups[g], group, sizeof(group));
        read = 0; resume = 0; members = NULL;
        status = NetLocalGroupGetMembers(NULL, groups[g], 2, (BYTE **)&members, MAX_PREFERRED_LENGTH, &read, &total, &resume);
        if (status) { if (status != NERR_GroupNotFound && status != ERROR_NO_SUCH_ALIAS) cannot_read(group, status); continue; }
        for (i = 0; i < read; ++i) {
            char member[400], id[500];
            secw_utf8(members[i].lgrmi2_domainandname, member, sizeof(member));
            begin(&json, "group_member");
            sec_json_string(&json, "group", group);
            sec_json_string(&json, "member", member);
            emit(&json);
            wsprintfA(id, "%s\\%.390s", group, member);
            config_entry("group_member", id, "", g == 0 ? SEC_SEVERITY_HIGH : SEC_SEVERITY_MEDIUM);
            if (g == 1)
                finding(SEC_SEVERITY_MEDIUM, "account.power_users_member", member, "An account is a member of Power Users",
                        "Power Users can modify Program Files, HKLM\\Software and services' files on NT 5.1, which is enough to become an administrator.",
                        "Use Users for ordinary accounts and Administrators for administration.");
        }
        if (members) NetApiBufferFree(members);
    }
}

static void collect_privileges(void)
{
    static const WCHAR *const rights[] = {L"SeDebugPrivilege", L"SeTcbPrivilege", L"SeLoadDriverPrivilege", L"SeTakeOwnershipPrivilege",
        L"SeRestorePrivilege", L"SeBackupPrivilege", L"SeAssignPrimaryTokenPrivilege", L"SeCreateTokenPrivilege", L"SeImpersonatePrivilege",
        L"SeRemoteShutdownPrivilege", L"SeSecurityPrivilege", L"SeNetworkLogonRight", L"SeRemoteInteractiveLogonRight"};
    HANDLE token;
    BYTE buffer[2048];
    TOKEN_PRIVILEGES *held = (TOKEN_PRIVILEGES *)buffer;
    DWORD bytes, i;
    LSA_OBJECT_ATTRIBUTES attributes;
    LSA_HANDLE policy;
    NTSTATUS status;
    unsigned r;
    SEC_JSON json;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        if (GetTokenInformation(token, TokenPrivileges, held, sizeof(buffer), &bytes))
            for (i = 0; i < held->PrivilegeCount; ++i) {
                WCHAR name[80];
                char text[200];
                DWORD count = 80;
                if (!LookupPrivilegeNameW(NULL, &held->Privileges[i].Luid, name, &count)) continue;
                secw_utf8(name, text, sizeof(text));
                begin(&json, "audit_token_privilege");
                sec_json_string(&json, "name", text);
                sec_json_bool(&json, "enabled", (held->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) != 0);
                emit(&json);
            }
        CloseHandle(token);
    }
    ZeroMemory(&attributes, sizeof(attributes));
    status = LsaOpenPolicy(NULL, &attributes, POLICY_LOOKUP_NAMES | POLICY_VIEW_LOCAL_INFORMATION, &policy);
    if (status) { cannot_read("user rights assignment", LsaNtStatusToWinError(status)); return; }
    for (r = 0; r < sizeof(rights) / sizeof(rights[0]); ++r) {
        LSA_UNICODE_STRING right;
        LSA_ENUMERATION_INFORMATION *holders = NULL;
        ULONG count = 0, h;
        char right8[80];
        right.Buffer = (WCHAR *)rights[r];
        right.Length = (USHORT)(lstrlenW(rights[r]) * sizeof(WCHAR));
        right.MaximumLength = (USHORT)(right.Length + sizeof(WCHAR));
        secw_utf8(rights[r], right8, sizeof(right8));
        status = LsaEnumerateAccountsWithUserRight(policy, &right, (void **)&holders, &count);
        if (status) continue;                      /* STATUS_NO_MORE_ENTRIES: nobody holds it */
        for (h = 0; h < count; ++h) {
            char account[300], id[400];
            BOOL broad = IsWellKnownSid(holders[h].Sid, WinWorldSid) || IsWellKnownSid(holders[h].Sid, WinBuiltinUsersSid) ||
                         IsWellKnownSid(holders[h].Sid, WinAuthenticatedUserSid) || IsWellKnownSid(holders[h].Sid, WinInteractiveSid) ||
                         IsWellKnownSid(holders[h].Sid, WinBuiltinGuestsSid) || IsWellKnownSid(holders[h].Sid, WinBuiltinPowerUsersSid);
            secw_account(holders[h].Sid, account, sizeof(account));
            begin(&json, "user_right");
            sec_json_string(&json, "right", right8);
            sec_json_string(&json, "account", account);
            emit(&json);
            wsprintfA(id, "%s\\%.300s", right8, account);
            config_entry("user_right", id, "", SEC_SEVERITY_HIGH);
            /* The two logon rights are broad by design; the privileges are not. */
            if (broad && r < 11)
                finding(SEC_SEVERITY_HIGH, "privilege.sensitive_right_broadly_held", id,
                        "A privilege that defeats the user/system boundary is held by an unprivileged group", account,
                        "Only Administrators and service accounts should hold it.");
        }
        LsaFreeMemory(holders);
    }
    LsaClose(policy);
}

typedef struct { const SEC_EVENT *event; unsigned long count, newest_record; DWORD newest_time; } EVENT_TOTAL;

static void collect_event_log(const WCHAR *log_name, const char *log8, DWORD limit)
{
    HANDLE log = OpenEventLogW(NULL, log_name);
    BYTE *buffer = allocate(65536);
    EVENT_TOTAL totals[40];
    unsigned total_count = 0, t, emitted = 0;
    DWORD read, needed, scanned = 0, oldest = 0, count = 0;
    SEC_JSON json;
    ZeroMemory(totals, sizeof(totals));
    if (!log || !buffer) { cannot_read(log8, GetLastError()); release(buffer); return; }
    GetNumberOfEventLogRecords(log, &count);
    GetOldestEventLogRecord(log, &oldest);
    while (scanned < limit && ReadEventLogW(log, EVENTLOG_BACKWARDS_READ | EVENTLOG_SEQUENTIAL_READ, 0, buffer, 65536, &read, &needed)) {
        BYTE *p = buffer;
        while (p < buffer + read && scanned < limit) {
            EVENTLOGRECORD *record = (EVENTLOGRECORD *)p;
            const WCHAR *source = (const WCHAR *)(p + sizeof(EVENTLOGRECORD));
            char source8[200];
            const SEC_EVENT *known;
            ++scanned;
            secw_utf8(source, source8, sizeof(source8));
            known = sec_event_lookup(log8, source8, record->EventID & 0xffff);
            if (known) {
                for (t = 0; t < total_count && lstrcmpA(totals[t].event->rule, known->rule); ++t) { }
                if (t == total_count && total_count < 40) { totals[t].event = known; ++total_count; }
                if (t < total_count && !totals[t].count++) { totals[t].newest_record = record->RecordNumber; totals[t].newest_time = record->TimeGenerated; }
                if (emitted < 150) {
                    char stamp[32];
                    LARGE_INTEGER ticks;               /* seconds since 1970 to 100 ns since 1601 */
                    FILETIME time;
                    ticks.QuadPart = UInt32x32To64(record->TimeGenerated, 10000000) + 116444736000000000;
                    time.dwLowDateTime = ticks.LowPart;
                    time.dwHighDateTime = (DWORD)ticks.HighPart;
                    secw_filetime_text(&time, stamp, sizeof(stamp));
                    begin(&json, "event");
                    sec_json_string(&json, "log", log8);
                    sec_json_string(&json, "source", source8);
                    sec_json_uint(&json, "event_id", record->EventID & 0xffff);
                    sec_json_uint(&json, "record", record->RecordNumber);
                    sec_json_string(&json, "utc", stamp);
                    sec_json_string(&json, "rule", known->rule);
                    sec_json_string(&json, "title", known->title);
                    /* Failed-logon strings can contain a password typed into the name field. */
                    if (lstrcmpA(known->rule, "event.logon_failure") && record->NumStrings) {
                        char strings[900], one[160];
                        const WCHAR *s = (const WCHAR *)(p + record->StringOffset);
                        WORD n;
                        strings[0] = 0;
                        for (n = 0; n < record->NumStrings && n < 6 && (const BYTE *)s < p + record->Length; ++n) {
                            secw_utf8(s, one, 120);
                            if (strings[0]) lstrcatA(strings, " | ");
                            lstrcatA(strings, one);
                            s += lstrlenW(s) + 1;
                        }
                        sec_json_string(&json, "strings", strings);
                    }
                    emit(&json);
                    ++emitted;
                }
            }
            if (!record->Length) break;
            p += record->Length;
        }
    }
    begin(&json, "event_summary");
    sec_json_string(&json, "log", log8);
    sec_json_uint(&json, "records_in_log", count);
    sec_json_uint(&json, "records_scanned", scanned);
    sec_json_uint(&json, "relevant_rules", total_count);
    emit(&json);
    for (t = 0; t < total_count; ++t) {
        char detail[200];
        int severity = totals[t].event->severity;
        /* A burst of failed logons is worth more attention than one typo. */
        if (!lstrcmpA(totals[t].event->rule, "event.logon_failure") && totals[t].count >= 10) severity = SEC_SEVERITY_MEDIUM;
        wsprintfA(detail, "%lu record(s) in the %s log; newest record number %lu", totals[t].count, log8, totals[t].newest_record);
        finding(severity, totals[t].event->rule, log8, totals[t].event->title, detail,
                "Review the records in Event Viewer; the audit does not act on them.");
    }
    CloseEventLog(log);
    release(buffer);
}

static void acl_check(const WCHAR *object, SE_OBJECT_TYPE type, DWORD mask, int severity, const char *why)
{
    unsigned who = 0;
    char name[800], who_text[300], detail[800];
    DWORD error = secw_object_exposure(object, type, mask, &who);
    SEC_JSON json;
    secw_utf8(object, name, sizeof(name));
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) return;
    begin(&json, "access_control");
    sec_json_string(&json, "object", name);
    sec_json_string(&json, "type", type == SE_FILE_OBJECT ? "file" : "registry");
    if (error) { sec_json_uint(&json, "error", error); emit(&json); ++unreadable; return; }
    secw_who_text(who, who_text, sizeof(who_text));
    sec_json_string(&json, "modifiable_by", who_text);
    sec_json_bool(&json, "unprivileged_write", (who & SECW_WHO_UNPRIVILEGED) != 0);
    sec_json_bool(&json, "individual_account_write", (who & SECW_WHO_INDIVIDUAL) != 0);
    sec_json_bool(&json, "owner_is_system_or_administrators", !(who & SECW_OWNER_NOT_SYSTEM));
    sec_json_bool(&json, "power_users_write", (who & SECW_WHO_POWER_USERS) != 0);
    emit(&json);
    if (who & SECW_EXPOSED) {
        secw_who_text(who & SECW_EXPOSED, who_text, sizeof(who_text));
        wsprintfA(detail, "Modifiable by %.290s. %.380s", who_text, why);
        /* Access that only the owning administrator account holds matters for restricted processes of that account. */
        finding((who & SECW_WHO_UNPRIVILEGED) || severity < SEC_SEVERITY_MEDIUM ? severity : SEC_SEVERITY_MEDIUM, "acl.protected_object_modifiable", name,
                "A protected system location can be modified without administrator rights", detail,
                "Restrict write access and ownership to Administrators and SYSTEM (XP25Sec apply does this for the locations it manages).");
    }
}

typedef struct { unsigned long checked, exposed, unprivileged, reported; int severity; const char *rule; } FILE_SCAN;

static DWORD scan_visit(const WCHAR *path, BOOL directory, void *context)
{
    FILE_SCAN *scan = (FILE_SCAN *)context;
    unsigned who = 0;
    char name[800], who_text[300], detail[500];
    (void)directory;
    ++scan->checked;
    if (secw_object_exposure(path, wcsncmp(path, L"MACHINE\\", 8) ? SE_FILE_OBJECT : SE_REGISTRY_KEY,
                             wcsncmp(path, L"MACHINE\\", 8) ? SECW_FILE_WRITE : SECW_KEY_WRITE, &who) || !(who & SECW_EXPOSED)) return ERROR_SUCCESS;
    ++scan->exposed;
    if (who & SECW_WHO_UNPRIVILEGED) ++scan->unprivileged;
    if (scan->reported++ < 40) {
        secw_utf8(path, name, sizeof(name));
        secw_who_text(who & SECW_EXPOSED, who_text, sizeof(who_text));
        wsprintfA(detail, "Modifiable by %.290s", who_text);
        finding((who & SECW_WHO_UNPRIVILEGED) ? SEC_SEVERITY_HIGH : scan->severity, scan->rule, name,
                "A system or XP25 object can be modified without administrator rights", detail,
                "XP25Sec apply resets it to the access control of its directory; nothing was changed by this audit.");
    }
    return ERROR_SUCCESS;
}

/* Every file directly in the system directories, and the XP25 trees: the same
   objects the baseline's access-control rules manage. */
static void collect_managed_access_control(void)
{
    unsigned i;
    SEC_JSON json;
    for (i = 0; i < sec_acl_rule_count(); ++i) {
        const SEC_ACL_RULE *rule = sec_acl_rule_at(i);
        FILE_SCAN scan;
        char root8[600];
        WCHAR root[600];
        DWORD error;
        ZeroMemory(&scan, sizeof(scan));
        scan.severity = SEC_SEVERITY_MEDIUM;
        scan.rule = rule->kind == SEC_ACL_REPAIR_FILES ? "acl.system_file_modifiable" :
                    rule->kind == SEC_ACL_REPAIR_KEYS ? "acl.system_key_modifiable" : "acl.xp25_object_modifiable";
        if (rule->kind == SEC_ACL_TREE_REGISTRY || rule->kind == SEC_ACL_REPAIR_KEYS) {
            WCHAR object[620];
            lstrcpynA(root8, rule->root, sizeof(root8));
            secw_wide(root8, root, 600);
            wsprintfW(object, L"MACHINE\\%s", root);
            if (rule->kind == SEC_ACL_TREE_REGISTRY) scan_visit(object, TRUE, &scan);
            error = secw_walk_keys(root, scan_visit, &scan);
        } else {
            if (!sec_acl_root(rule, windows_dir, programs_dir, root8, sizeof(root8))) continue;
            secw_wide(root8, root, 600);
            if (GetFileAttributesW(root) == INVALID_FILE_ATTRIBUTES) continue;
            if (rule->kind == SEC_ACL_TREE_FILES) scan_visit(root, TRUE, &scan);
            error = secw_walk_files(root, rule->kind == SEC_ACL_TREE_FILES, scan_visit, &scan);
        }
        begin(&json, "access_control_scan");
        sec_json_string(&json, "rule", rule->id);
        sec_json_string(&json, "root", root8);
        sec_json_uint(&json, "objects_checked", scan.checked);
        sec_json_uint(&json, "modifiable_without_administrator_rights", scan.exposed);
        sec_json_uint(&json, "modifiable_by_unprivileged_groups", scan.unprivileged);
        if (error) sec_json_uint(&json, "error", error);
        emit(&json);
        if (error) ++unreadable;
    }
}

static void collect_access_control(void)
{
    static const WCHAR *const windows_files[] = {L"", L"\\system32", L"\\system32\\drivers", L"\\system32\\config", L"\\XP25\\Security"};
    static const WCHAR *const program_files[] = {L""};
    static const WCHAR *const keys[] = {L"MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        L"MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
        L"MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"MACHINE\\SOFTWARE\\Classes", L"MACHINE\\SOFTWARE\\Policies",
        L"MACHINE\\SOFTWARE\\XP25", L"MACHINE\\SOFTWARE\\XP25\\Agent\\Policy", L"MACHINE\\SOFTWARE\\XP25\\Security",
        L"MACHINE\\SYSTEM\\CurrentControlSet\\Services", L"MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
        L"MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager",
        L"MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy"};
    WCHAR base[MAX_PATH], path[MAX_PATH * 2], programs[MAX_PATH];
    unsigned i;
    GetWindowsDirectoryW(base, MAX_PATH);
    for (i = 0; i < sizeof(windows_files) / sizeof(windows_files[0]); ++i) {
        wsprintfW(path, L"%s%s", base, windows_files[i]);
        acl_check(path, SE_FILE_OBJECT, SECW_FILE_WRITE, SEC_SEVERITY_HIGH, "System code and configuration are loaded from here by every process.");
    }
    secw_wide(programs_dir, programs, MAX_PATH);
    for (i = 0; i < sizeof(program_files) / sizeof(program_files[0]); ++i) {
        wsprintfW(path, L"%s%s", programs, program_files[i]);
        acl_check(path, SE_FILE_OBJECT, SECW_FILE_WRITE, SEC_SEVERITY_HIGH, "Programs here run with the rights of whoever starts them, including services.");
    }
    /* Ordinary users may add their own scheduled tasks by design; a task runs as its creator. */
    wsprintfW(path, L"%s\\Tasks", base);
    acl_check(path, SE_FILE_OBJECT, SECW_FILE_WRITE, SEC_SEVERITY_LOW,
              "NT 5.1 lets every authenticated user create task files here; tasks run with their creator's own credentials, not the system's.");
    /* NT 5.1 lets Users create files and folders in the system drive root by default. */
    base[3] = 0;
    acl_check(base, SE_FILE_OBJECT, FILE_WRITE_DATA | FILE_APPEND_DATA | WRITE_DAC | WRITE_OWNER | FILE_DELETE_CHILD, SEC_SEVERITY_LOW,
              "Files planted in the drive root (for example C:\\Program.exe) are found by unquoted paths and by programs that search the root.");
    for (i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i)
        acl_check(keys[i], SE_REGISTRY_KEY, SECW_KEY_WRITE, SEC_SEVERITY_HIGH, "Values here decide what code runs for every user or as the system.");
}

static void collect_secure_desktop(void)
{
    HDESK desktop = OpenDesktopW(L"Winlogon", 0, FALSE, DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS | DESKTOP_CREATEWINDOW | DESKTOP_HOOKCONTROL);
    DWORD error = desktop ? 0 : GetLastError();
    SEC_JSON json;
    begin(&json, "secure_desktop");
    sec_json_bool(&json, "winlogon_desktop_opened", desktop != NULL);
    sec_json_uint(&json, "open_error", error);
    emit(&json);
    if (desktop) {
        CloseDesktop(desktop);
        finding(SEC_SEVERITY_HIGH, "winlogon.secure_desktop_open", "Winlogon desktop",
                "The logon desktop can be opened from the user session",
                "A program on the user's desktop could read or drive the password dialogs.",
                "Only SYSTEM may hold window, hook and read access to the Winlogon desktop.");
    }
}

static void collect_audit_policy(void)
{
    LSA_OBJECT_ATTRIBUTES attributes;
    LSA_HANDLE policy;
    POLICY_AUDIT_EVENTS_INFO *info = NULL;
    NTSTATUS status;
    ULONG i, missing = 0;
    SEC_JSON json;
    ZeroMemory(&attributes, sizeof(attributes));
    status = LsaOpenPolicy(NULL, &attributes, POLICY_VIEW_AUDIT_INFORMATION, &policy);
    if (!status) status = LsaQueryInformationPolicy(policy, PolicyAuditEventsInformation, (PVOID *)&info);
    if (status) { cannot_read("audit policy", LsaNtStatusToWinError(status)); return; }
    for (i = 0; i < SEC_AUDIT_CATEGORIES && i < info->MaximumAuditEventCount; ++i) {
        ULONG options = info->AuditingMode ? (info->EventAuditingOptions[i] & 3) : 0;
        begin(&json, "audit_policy");
        sec_json_string(&json, "category", sec_audit_category_name(i));
        sec_json_bool(&json, "success", (options & SEC_AUDIT_SUCCESS) != 0);
        sec_json_bool(&json, "failure", (options & SEC_AUDIT_FAILURE) != 0);
        emit(&json);
        if ((options & sec_audit_baseline(i)) != sec_audit_baseline(i)) ++missing;
    }
    LsaFreeMemory(info);
    LsaClose(policy);
    if (missing)
        finding(SEC_SEVERITY_MEDIUM, "baseline.audit_policy_incomplete", "audit policy", "Security auditing does not record the baseline categories",
                "Logon, account-management, policy-change and system events are not all audited, so the Security log cannot show them.",
                "An administrator can run XP25Sec apply.");
}

static void collect_all(void)
{
    collect_system();
    collect_firewall();
    collect_processes();
    collect_services();
    collect_kernel_modules();
    collect_autostart();
    collect_listeners();
    collect_settings();
    collect_audit_policy();
    collect_accounts();
    collect_privileges();
    collect_access_control();
    collect_managed_access_control();
    collect_secure_desktop();
    if (!snapshot_mode) {
        collect_event_log(L"Security", "Security", 6000);
        collect_event_log(L"System", "System", 3000);
    }
    snapshot_finish();
}

void __cdecl XP25AuditMain(void)
{
    int argc = 0, i;
    WCHAR **argv = secw_arguments(&argc), path[MAX_PATH], temporary[MAX_PATH];
    const WCHAR *command;
    DWORD started = GetTickCount(), error;
    SEC_JSON json;
    if (!argv || !secw_sink_open(&sink, argc, argv, 2)) ExitProcess(2);
    command = argc > 1 ? argv[1] : L"";
    for (i = 2; i < argc; ++i) {
        if (!lstrcmpW(argv[i], L"--modules")) list_modules = TRUE;
        if (!lstrcmpW(argv[i], L"--privileged")) privileged = TRUE;
    }
    admin = secw_is_admin();
    secw_directories(windows_dir, sizeof(windows_dir), programs_dir, sizeof(programs_dir));
    if (privileged) {
        /* Only privileges the caller already holds can be enabled; nothing is acquired. */
        privileged = secw_enable_privilege(SE_DEBUG_NAME);
        secw_enable_privilege(SE_SECURITY_NAME);
    }
    if (!lstrcmpW(command, L"snapshot")) {
        if (!admin) { secw_error_text("snapshot needs an administrator", ERROR_ACCESS_DENIED); ExitProcess(5); }
        error = secw_store_prepare();
        if (error || !secw_store_path(L"audit-snapshot.txt", path, MAX_PATH) || !secw_store_path(L"audit-snapshot.tmp", temporary, MAX_PATH)) {
            secw_error_text("cannot prepare the protected store", error);
            ExitProcess(1);
        }
        snapshot_file = CreateFileW(temporary, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (snapshot_file == INVALID_HANDLE_VALUE) { secw_error_text("cannot write the snapshot", GetLastError()); ExitProcess(1); }
        snapshot_mode = TRUE;
        collect_all();
        FlushFileBuffers(snapshot_file);
        CloseHandle(snapshot_file);
        if (!MoveFileExW(temporary, path, MOVEFILE_REPLACE_EXISTING)) { secw_error_text("cannot replace the snapshot", GetLastError()); ExitProcess(1); }
        snapshot_mode = FALSE;
        begin(&json, "snapshot");
        sec_json_uint(&json, "items", records_of_kind);
        sec_json_uint(&json, "unreadable_sources", unreadable);
        secw_emit(&sink, &json);
        secw_sink_close(&sink);
        ExitProcess(0);
    }
    if (lstrcmpW(command, L"report")) {
        secw_error_text("usage: XP25Audit report|snapshot [--out <file>] [--serial] [--quiet] [--modules] [--privileged]", ERROR_INVALID_PARAMETER);
        ExitProcess(2);
    }
    snapshot_load();
    collect_all();
    begin(&json, "summary");
    sec_json_uint(&json, "findings_high", findings[SEC_SEVERITY_HIGH]);
    sec_json_uint(&json, "findings_medium", findings[SEC_SEVERITY_MEDIUM]);
    sec_json_uint(&json, "findings_low", findings[SEC_SEVERITY_LOW]);
    sec_json_uint(&json, "findings_info", findings[SEC_SEVERITY_INFO]);
    sec_json_uint(&json, "unreadable_sources", unreadable);
    sec_json_uint(&json, "records", sink.lines + 1);
    sec_json_uint(&json, "records_dropped", sink.dropped);
    sec_json_uint(&json, "milliseconds", GetTickCount() - started);
    sec_json_bool(&json, "read_only", 1);
    secw_emit(&sink, &json);
    secw_sink_close(&sink);
    ExitProcess(0);
}
