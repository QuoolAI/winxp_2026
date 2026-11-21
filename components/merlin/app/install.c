/* MerlinAI.exe /install and /uninstall.

   Every value MerlinAI changes is saved first under
   HKLM\SOFTWARE\XP25\MerlinAI\Saved (once: a reinstall keeps the original),
   and /uninstall restores it. Changes:
   - AeDebug: Debugger = "<dir>\MerlinCrash.exe" -p %ld -e %ld, Auto = 1
     (was Dr. Watson behind faultrep.dll's Microsoft dialog);
   - PCHealth\ErrorReporting: DoReport = 0, ShowUI = 0 (nothing is reported to
     Microsoft's retired endpoints; kernel and hang notifications by dwwin stop);
   - Control Panel: MerlinAI.cpl registered in Performance and Maintenance;
     wscui.cpl and wuaucpl.cpl in the "don't load" list and hidden in every
     user hive by the "Hide specified Control Panel items" policy, which also
     removes the Security Center link (MerlinUserPolicyAll, mc_policy.c);
   - Security Center: the antivirus, firewall and update notifications are
     turned off. The Security Center service, the Windows Firewall and its
     settings are not changed;
   - Automatic Updates: policy NoAutoUpdate = 1 and NoWindowsUpdate = 1 (the
     service stays as the security baseline left it);
   - event source "MerlinAI", the queue directory with its DACL, the Run entry
     for collection at logon. */
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <shlobj.h>
#include "app.h"

#define AEDEBUG L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug"
#define ERRREP L"SOFTWARE\\Microsoft\\PCHealth\\ErrorReporting"
#define CPLS L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Control Panel\\Cpls"
#define DONTLOAD L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Control Panel\\don't load"
#define CATEGORY L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Control Panel\\Extended Properties\\{305CA226-D286-468e-B848-2B2E8E697B74} 2"
/* Value name in the form shell32's own entries use; the shell expands it before comparing. */
#define CATEGORY_VALUE L"%SystemRoot%\\system32\\MerlinAI.cpl"
/* Performance and Maintenance. The image's shell32 shows category 10 (Security Center) only as a direct
   link to wscui.cpl, so an applet registered there is never listed. */
#define CATEGORY_PERFORMANCE 5
#define SECCENTER L"SOFTWARE\\Microsoft\\Security Center"
#define AUPOLICY L"SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU"
#define EXPLORERPOLICY L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"
#define RUNKEY L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
#define EVENTSRC L"SYSTEM\\CurrentControlSet\\Services\\Eventlog\\Application\\MerlinAI"
#define QUEUE_SDDL L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a3;;;BU)(A;OICIIO;FA;;;CO)"

typedef struct {
    const WCHAR *key;
    const WCHAR *name;
    DWORD type;                     /* REG_SZ or REG_DWORD */
    const WCHAR *saved;             /* value name under Saved */
} SETTING;

static const SETTING settings[] = {
    { AEDEBUG, L"Debugger", REG_SZ, L"AeDebug.Debugger" },
    { AEDEBUG, L"Auto", REG_SZ, L"AeDebug.Auto" },
    { ERRREP, L"DoReport", REG_DWORD, L"ErrorReporting.DoReport" },
    { ERRREP, L"ShowUI", REG_DWORD, L"ErrorReporting.ShowUI" },
    { DONTLOAD, L"wscui.cpl", REG_SZ, L"DontLoad.wscui" },
    { DONTLOAD, L"wuaucpl.cpl", REG_SZ, L"DontLoad.wuaucpl" },
    { SECCENTER, L"AntiVirusDisableNotify", REG_DWORD, L"SecurityCenter.AntiVirusDisableNotify" },
    { SECCENTER, L"FirewallDisableNotify", REG_DWORD, L"SecurityCenter.FirewallDisableNotify" },
    { SECCENTER, L"UpdatesDisableNotify", REG_DWORD, L"SecurityCenter.UpdatesDisableNotify" },
    { AUPOLICY, L"NoAutoUpdate", REG_DWORD, L"AU.NoAutoUpdate" },
    { EXPLORERPOLICY, L"NoWindowsUpdate", REG_DWORD, L"Explorer.NoWindowsUpdate" },
};
#define SETTING_COUNT (sizeof(settings) / sizeof(settings[0]))

void merlin_serial(const char *line)
{
    HANDLE port = CreateFileW(L"COM1", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    DWORD wrote;
    int tries;
    /* COM1 is exclusive: Winlogon and other writers hold it briefly. */
    for (tries = 0; port == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED && tries < 40; ++tries) {
        Sleep(50);
        port = CreateFileW(L"COM1", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    }
    if (port == INVALID_HANDLE_VALUE) return;
    WriteFile(port, line, (DWORD)lstrlenA(line), &wrote, NULL);
    WriteFile(port, "\r\n", 2, &wrote, NULL);
    CloseHandle(port);
}

static void note(char *log, int size, const char *step, DWORD error)
{
    char line[200];
    merlin_copy(line, sizeof(line), "XP25_MERLIN_INSTALL_STEP ");
    merlin_append(line, sizeof(line), step);
    merlin_append(line, sizeof(line), "=");
    merlin_append_ulong(line, sizeof(line), error);
    merlin_serial(line);
    merlin_append(log, size, line + 25);
    merlin_append(log, size, "\r\n");
}

static void note_policy(char *log, int size, const char *step, DWORD error, const MERLIN_POLICY_STATS *p)
{
    char line[200];
    note(log, size, step, error);
    merlin_copy(line, sizeof(line), "XP25_MERLIN_INSTALL_POLICY loaded=");
    merlin_append_ulong(line, sizeof(line), p->loaded);
    merlin_append(line, sizeof(line), " offline=");
    merlin_append_ulong(line, sizeof(line), p->offline);
    merlin_append(line, sizeof(line), " default_user=");
    merlin_append_ulong(line, sizeof(line), p->default_user);
    merlin_append(line, sizeof(line), " failed=");
    merlin_append_ulong(line, sizeof(line), p->failed);
    merlin_serial(line);
}

static DWORD set_value(const WCHAR *key, const WCHAR *name, DWORD type, const void *data, DWORD size)
{
    HKEY k;
    DWORD e = (DWORD)RegCreateKeyExW(HKEY_LOCAL_MACHINE, key, 0, NULL, 0, KEY_SET_VALUE, NULL, &k, NULL);
    if (e) return e;
    e = (DWORD)RegSetValueExW(k, name, 0, type, (const BYTE *)data, size);
    RegCloseKey(k);
    return e;
}

static DWORD set_string(const WCHAR *key, const WCHAR *name, DWORD type, const WCHAR *value)
{
    return set_value(key, name, type, value, (DWORD)(lstrlenW(value) + 1) * sizeof(WCHAR));
}

static DWORD set_dword(const WCHAR *key, const WCHAR *name, DWORD value) { return set_value(key, name, REG_DWORD, &value, sizeof(value)); }

static DWORD delete_value(const WCHAR *key, const WCHAR *name)
{
    HKEY k;
    DWORD e = (DWORD)RegOpenKeyExW(HKEY_LOCAL_MACHINE, key, 0, KEY_SET_VALUE, &k);
    if (e) return e == ERROR_FILE_NOT_FOUND ? 0 : e;
    e = (DWORD)RegDeleteValueW(k, name);
    RegCloseKey(k);
    return e == ERROR_FILE_NOT_FOUND ? 0 : e;
}

static DWORD read_dword(const WCHAR *key, const WCHAR *name, DWORD *value)
{
    HKEY k;
    DWORD type, size = sizeof(DWORD), e = (DWORD)RegOpenKeyExW(HKEY_LOCAL_MACHINE, key, 0, KEY_QUERY_VALUE, &k);
    if (e) return e;
    e = (DWORD)RegQueryValueExW(k, name, NULL, &type, (BYTE *)value, &size);
    RegCloseKey(k);
    return !e && type != REG_DWORD ? ERROR_INVALID_DATA : e;
}

static DWORD read_string(const WCHAR *key, const WCHAR *name, WCHAR *out, DWORD chars)
{
    HKEY k;
    DWORD type, size = (chars - 1) * sizeof(WCHAR), e = (DWORD)RegOpenKeyExW(HKEY_LOCAL_MACHINE, key, 0, KEY_QUERY_VALUE, &k);
    out[0] = 0;
    if (e) return e;
    e = (DWORD)RegQueryValueExW(k, name, NULL, &type, (BYTE *)out, &size);
    RegCloseKey(k);
    if (e || type != REG_SZ) {
        out[0] = 0;
        return e ? e : ERROR_INVALID_DATA;
    }
    out[size / sizeof(WCHAR)] = 0;
    return 0;
}

/* Copy a value (or its absence) to Saved\<saved> and Saved\<saved>.Present. */
static DWORD save_setting(const SETTING *s)
{
    HKEY k;
    BYTE data[1024];
    DWORD type = REG_NONE, size = sizeof(data) - 2, e;
    WCHAR present[96];
    lstrcpyW(present, s->saved);
    lstrcatW(present, L".Present");
    e = (DWORD)RegOpenKeyExW(HKEY_LOCAL_MACHINE, s->key, 0, KEY_QUERY_VALUE, &k);
    if (!e) {
        e = (DWORD)RegQueryValueExW(k, s->name, NULL, &type, data, &size);
        RegCloseKey(k);
    }
    if (e == ERROR_FILE_NOT_FOUND) return set_dword(MERLIN_REG_SAVED, present, 0);
    if (e) return e;
    e = set_value(MERLIN_REG_SAVED, s->saved, type, data, size);
    return e ? e : set_dword(MERLIN_REG_SAVED, present, 1);
}

static DWORD restore_setting(const SETTING *s)
{
    HKEY k;
    BYTE data[1024];
    DWORD type = REG_NONE, size = sizeof(data), e, present = 0;
    WCHAR name[96];
    lstrcpyW(name, s->saved);
    lstrcatW(name, L".Present");
    if (read_dword(MERLIN_REG_SAVED, name, &present)) return ERROR_NOT_FOUND;
    if (!present) return delete_value(s->key, s->name);
    e = (DWORD)RegOpenKeyExW(HKEY_LOCAL_MACHINE, MERLIN_REG_SAVED, 0, KEY_QUERY_VALUE, &k);
    if (e) return e;
    e = (DWORD)RegQueryValueExW(k, s->saved, NULL, &type, data, &size);
    RegCloseKey(k);
    return e ? e : set_value(s->key, s->name, type, data, size);
}

static DWORD create_queue(void)
{
    WCHAR path[MAX_PATH], *p;
    PSECURITY_DESCRIPTOR sd = NULL;
    SECURITY_ATTRIBUTES sa;
    DWORD e = 0;
    if (!MerlinQueueDirectory(path, MAX_PATH)) return ERROR_PATH_NOT_FOUND;
    /* Parents inherit All Users\Application Data's DACL; only the queue gets its own. */
    for (p = path + 3; *p; ++p)
        if (*p == L'\\') {
            *p = 0;
            CreateDirectoryW(path, NULL);
            *p = L'\\';
        }
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(QUEUE_SDDL, SDDL_REVISION_1, &sd, NULL)) return GetLastError();
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = sd;
    sa.bInheritHandle = FALSE;
    if (!CreateDirectoryW(path, &sa)) {
        e = GetLastError();
        if (e == ERROR_ALREADY_EXISTS) e = SetFileSecurityW(path, DACL_SECURITY_INFORMATION, sd) ? 0 : GetLastError();
    }
    LocalFree(sd);
    return e;
}

/* MerlinSvc (LocalSystem, automatic): health reports to the deployment agent and local collection. */
static DWORD service(const WCHAR *dir, BOOL remove)
{
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS), s;
    WCHAR command[MAX_PATH + 8];
    SERVICE_STATUS st;
    DWORD e = 0;
    if (!scm) return GetLastError();
    if (remove) {
        s = OpenServiceW(scm, L"MerlinSvc", SERVICE_STOP | DELETE);
        if (s) {
            ControlService(s, SERVICE_CONTROL_STOP, &st);
            if (!DeleteService(s)) e = GetLastError();
            CloseServiceHandle(s);
        } else if (GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST) e = GetLastError();
        CloseServiceHandle(scm);
        return e;
    }
    lstrcpyW(command, L"\"");
    lstrcatW(command, dir);
    lstrcatW(command, L"\\MerlinSvc.exe\"");
    s = CreateServiceW(scm, L"MerlinSvc", L"MerlinAI Service", SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
                       SERVICE_ERROR_NORMAL, command, NULL, NULL, L"Eventlog\0Tcpip\0", NULL, NULL);
    if (!s && GetLastError() == ERROR_SERVICE_EXISTS) {
        s = OpenServiceW(scm, L"MerlinSvc", SERVICE_ALL_ACCESS);
        if (s) ChangeServiceConfigW(s, SERVICE_NO_CHANGE, SERVICE_AUTO_START, SERVICE_NO_CHANGE, command, NULL, NULL, NULL, NULL, NULL, NULL);
    }
    if (!s) e = GetLastError();
    else {
        if (!StartServiceW(s, 0, NULL) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) e = GetLastError();
        CloseServiceHandle(s);
    }
    CloseServiceHandle(scm);
    return e;
}

DWORD merlin_install(const WCHAR *dir, char *log, int log_size)
{
    WCHAR value[MAX_PATH * 2], path[MAX_PATH];
    MERLIN_POLICY_STATS policy;
    DWORD e, installed = 0, failures = 0;
    unsigned i;
    log[0] = 0;
    if (!MerlinIsAdmin()) {
        note(log, log_size, "administrator", ERROR_ACCESS_DENIED);
        return ERROR_ACCESS_DENIED;
    }
    if (lstrlenW(dir) > MAX_PATH - 20) return ERROR_FILENAME_EXCED_RANGE;
    e = create_queue();
    note(log, log_size, "queue", e);
    failures += e != 0;
    read_dword(MERLIN_REG_SAVED, L"Installed", &installed);
    if (!installed) {
        for (i = 0; i < SETTING_COUNT; ++i) {
            e = save_setting(&settings[i]);
            failures += e != 0;
        }
        note(log, log_size, "saved_previous_settings", failures ? ERROR_GEN_FAILURE : 0);
    }
    /* AeDebug: the MerlinAI crash handler replaces Dr. Watson behind faultrep/dwwin. */
    lstrcpyW(value, L"\"");
    lstrcatW(value, dir);
    lstrcatW(value, L"\\MerlinCrash.exe\" -p %ld -e %ld");
    e = set_string(AEDEBUG, L"Debugger", REG_SZ, value);
    if (!e) e = set_string(AEDEBUG, L"Auto", REG_SZ, L"1");
    note(log, log_size, "aedebug", e);
    failures += e != 0;
    e = set_dword(ERRREP, L"DoReport", 0);
    if (!e) e = set_dword(ERRREP, L"ShowUI", 0);
    note(log, log_size, "microsoft_error_reporting_off", e);
    failures += e != 0;
    /* The installed shell32 (an older binary) lists only applets in system32 and control.ini's per-user
       [MMCPL]; it ignores the SP2 "Cpls" key. MerlinAI.cpl is therefore copied to system32 (the Cpls value
       stays for newer shells). */
    lstrcpyW(value, dir);
    lstrcatW(value, L"\\MerlinAI.cpl");
    if (!GetSystemDirectoryW(path, MAX_PATH - 16)) e = GetLastError();
    else {
        lstrcatW(path, L"\\MerlinAI.cpl");
        e = CopyFileW(value, path, FALSE) ? 0 : GetLastError();
    }
    if (!e) e = set_string(CPLS, L"MerlinAI", REG_SZ, path);
    if (!e) e = delete_value(CATEGORY, path);                 /* the first release's entry (category 10) */
    if (!e) e = set_dword(CATEGORY, CATEGORY_VALUE, CATEGORY_PERFORMANCE);
    if (!e) e = set_string(DONTLOAD, L"wscui.cpl", REG_SZ, L"no");
    if (!e) e = set_string(DONTLOAD, L"wuaucpl.cpl", REG_SZ, L"no");
    note(log, log_size, "control_panel", e);
    failures += e != 0;
    e = MerlinUserPolicyAll(TRUE, &policy);
    note_policy(log, log_size, "control_panel_user_policy", e, &policy);
    failures += e != 0;
    e = set_dword(SECCENTER, L"AntiVirusDisableNotify", 1);
    if (!e) e = set_dword(SECCENTER, L"FirewallDisableNotify", 1);
    if (!e) e = set_dword(SECCENTER, L"UpdatesDisableNotify", 1);
    note(log, log_size, "security_center_notifications_off", e);
    failures += e != 0;
    e = set_dword(AUPOLICY, L"NoAutoUpdate", 1);
    if (!e) e = set_dword(EXPLORERPOLICY, L"NoWindowsUpdate", 1);
    note(log, log_size, "automatic_updates_policy", e);
    failures += e != 0;
    lstrcpyW(value, dir);
    lstrcatW(value, L"\\MerlinClient.dll");
    e = set_string(EVENTSRC, L"EventMessageFile", REG_EXPAND_SZ, value);
    if (!e) e = set_dword(EVENTSRC, L"TypesSupported", 7);
    note(log, log_size, "event_source", e);
    failures += e != 0;
    lstrcpyW(value, L"\"");
    lstrcatW(value, dir);
    lstrcatW(value, L"\\MerlinAI.exe\" /logon");
    e = set_string(RUNKEY, L"XP25 MerlinAI", REG_SZ, value);
    note(log, log_size, "logon_collection", e);
    failures += e != 0;
    e = service(dir, FALSE);
    note(log, log_size, "service", e);
    failures += e != 0;
    e = set_string(MERLIN_REG_ROOT, L"InstallDirectory", REG_SZ, dir);
    if (!e) e = set_dword(MERLIN_REG_SAVED, L"Installed", 1);
    note(log, log_size, "installed", e);
    failures += e != 0;
    MerlinLogEvent(EVENTLOG_INFORMATION_TYPE, L"MerlinAI was installed. It replaces Microsoft error reporting, Security Center and Automatic Updates pages; previous settings were saved.");
    return failures ? ERROR_GEN_FAILURE : 0;
}

DWORD merlin_uninstall(char *log, int log_size)
{
    DWORD e, failures = 0, installed = 0;
    unsigned i;
    WCHAR dir[MAX_PATH], path[MAX_PATH];
    MERLIN_POLICY_STATS policy;
    log[0] = 0;
    if (!MerlinIsAdmin()) return ERROR_ACCESS_DENIED;
    read_dword(MERLIN_REG_SAVED, L"Installed", &installed);
    if (!installed) {
        note(log, log_size, "not_installed", ERROR_NOT_FOUND);
        return ERROR_NOT_FOUND;
    }
    for (i = 0; i < SETTING_COUNT; ++i) {
        e = restore_setting(&settings[i]);
        failures += e != 0;
    }
    note(log, log_size, "restored_settings", failures ? ERROR_GEN_FAILURE : 0);
    e = MerlinUserPolicyAll(FALSE, &policy);
    note_policy(log, log_size, "control_panel_user_policy_removed", e, &policy);
    failures += e != 0;
    delete_value(CATEGORY, CATEGORY_VALUE);
    if (!read_string(MERLIN_REG_ROOT, L"InstallDirectory", dir, MAX_PATH)) {
        lstrcpyW(path, dir);
        lstrcatW(path, L"\\MerlinAI.cpl");
        delete_value(CATEGORY, path);
    }
    if (GetSystemDirectoryW(path, MAX_PATH - 16)) {
        lstrcatW(path, L"\\MerlinAI.cpl");
        delete_value(CATEGORY, path);
        /* Explorer may hold the applet loaded: then it goes at the next restart. */
        if (!DeleteFileW(path) && GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES)
            MoveFileExW(path, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
    }
    e = service(NULL, TRUE);
    note(log, log_size, "service_removed", e);
    failures += e != 0;
    e = delete_value(CPLS, L"MerlinAI");
    if (!e) e = delete_value(RUNKEY, L"XP25 MerlinAI");
    if (!e) e = delete_value(MERLIN_REG_SAVED, L"Installed");
    note(log, log_size, "unregistered", e);
    failures += e != 0;
    MerlinLogEvent(EVENTLOG_INFORMATION_TYPE, L"MerlinAI was uninstalled and the previous settings were restored. Queued reports were kept.");
    return failures ? ERROR_GEN_FAILURE : 0;
}
