/* XP25 security regression probe for a disposable guest.

   security_probe.exe admin [--hardened] [--xp25-winlogon] [--tools <dir>]
       Run by the logged-on administrator. It creates a temporary ordinary
       account, runs itself as that account (seclogon) and with a restricted
       token of its own, checks that legitimate administrator operations
       still work, and removes the account again.
   security_probe.exe limited|restricted <result file> [...]   (started by the above)

   Every negative case attempts the real operation and passes only on the
   expected denial; a case whose precondition is missing is "not_run", never
   a pass. Without --hardened the baseline-dependent cases are "observed".
   Records go to COM1; the exit code is the number of failed cases. */
#define WINVER 0x0501
#define _WIN32_WINNT 0x0501
#ifndef UNICODE
#define UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <lm.h>
#include <wincrypt.h>
#include <userenv.h>
#include <tlhelp32.h>
#include <string.h>
#include "sec_core.h"

#define ACCOUNT L"xp25sectest"

static HANDLE output = INVALID_HANDLE_VALUE;
static unsigned passes, failures, observed, not_run;
static const char *context = "admin";
static BOOL hardened, xp25_winlogon;
static WCHAR tools[MAX_PATH];

static void emit(const char *text)
{
    DWORD done;
    if (output != INVALID_HANDLE_VALUE) WriteFile(output, text, (DWORD)lstrlenA(text), &done, NULL);
}

/* status: 1 pass, 0 fail, 2 observed (no expectation), 3 not run. */
static void report(const char *name, int status, DWORD error, const char *note)
{
    static const char *const names[] = {"fail", "pass", "observed", "not_run"};
    char row[700];
    if (status == 1) ++passes; else if (status == 0) ++failures; else if (status == 2) ++observed; else ++not_run;
    wsprintfA(row, "{\"security_case\":\"%.80s\",\"context\":\"%s\",\"status\":\"%s\",\"error\":%lu,\"note\":\"%.400s\"}\r\n",
              name, context, names[status], error, note ? note : "");
    emit(row);
}

/* A modification attempt that must be refused with ERROR_ACCESS_DENIED. */
static void denied(const char *name, BOOL succeeded, DWORD error)
{
    report(name, !succeeded && (error == ERROR_ACCESS_DENIED || error == ERROR_PRIVILEGE_NOT_HELD), succeeded ? 0 : error,
           succeeded ? "the operation succeeded" : "");
}

static BOOL is_admin(void)
{
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    PSID admins = NULL;
    BOOL member = FALSE;
    if (!AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admins)) return FALSE;
    if (!CheckTokenMembership(NULL, admins, &member)) member = FALSE;
    FreeSid(admins);
    return member;
}

static BOOL enable_privilege(const WCHAR *name)
{
    HANDLE token;
    TOKEN_PRIVILEGES p;
    BOOL ok;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) return FALSE;
    ZeroMemory(&p, sizeof(p));
    p.PrivilegeCount = 1;
    p.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    ok = LookupPrivilegeValueW(NULL, name, &p.Privileges[0].Luid);
    if (ok) { SetLastError(0); ok = AdjustTokenPrivileges(token, FALSE, &p, 0, NULL, NULL) && GetLastError() == ERROR_SUCCESS; }
    CloseHandle(token);
    return ok;
}

static DWORD find_process(const WCHAR *name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W entry;
    DWORD pid = 0;
    if (snap == INVALID_HANDLE_VALUE) return 0;
    ZeroMemory(&entry, sizeof(entry));
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snap, &entry)) do {
        if (!lstrcmpiW(entry.szExeFile, name)) { pid = entry.th32ProcessID; break; }
    } while (Process32NextW(snap, &entry));
    CloseHandle(snap);
    return pid;
}

static void file_create_denied(const char *name, const WCHAR *path)
{
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    DWORD error = GetLastError();
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    denied(name, h != INVALID_HANDLE_VALUE, error);
}

static void file_write_denied(const char *name, const WCHAR *path)
{
    HANDLE h = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    DWORD error = GetLastError();
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    if (h == INVALID_HANDLE_VALUE && (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)) report(name, 3, error, "the file does not exist");
    else denied(name, h != INVALID_HANDLE_VALUE, error);
}

static void key_write_denied(const char *name, const WCHAR *key)
{
    HKEY handle;
    LONG error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, key, 0, KEY_SET_VALUE | KEY_CREATE_SUB_KEY, &handle);
    if (!error) RegCloseKey(handle);
    if (error == ERROR_FILE_NOT_FOUND) {
        /* A missing key must not be creatable either. */
        error = RegCreateKeyExW(HKEY_LOCAL_MACHINE, key, 0, NULL, REG_OPTION_VOLATILE, KEY_SET_VALUE, NULL, &handle, NULL);
        if (!error) { RegCloseKey(handle); RegDeleteKeyW(HKEY_LOCAL_MACHINE, key); }
    }
    denied(name, error == ERROR_SUCCESS, (DWORD)error);
}

static DWORD run(WCHAR *command, DWORD timeout)
{
    STARTUPINFOW start;
    PROCESS_INFORMATION process;
    DWORD code = 0xffffffff;
    ZeroMemory(&start, sizeof(start));
    start.cb = sizeof(start);
    if (!CreateProcessW(NULL, command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &start, &process)) return 0xfffffffe;
    if (WaitForSingleObject(process.hProcess, timeout) != WAIT_OBJECT_0) TerminateProcess(process.hProcess, 0xfffffffd);
    WaitForSingleObject(process.hProcess, 5000);
    GetExitCodeProcess(process.hProcess, &code);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return code;
}

/* Cases shared by the ordinary account and the restricted token: nothing
   that belongs to the system may be modified. */
static void unprivileged_cases(void)
{
    WCHAR windows[MAX_PATH], path[MAX_PATH * 2], command[MAX_PATH * 2];
    SC_HANDLE scm, service;
    HANDLE process;
    HDESK desktop;
    DWORD error, pid, code;
    GetWindowsDirectoryW(windows, MAX_PATH);
    report("caller_is_not_administrator", !is_admin(), 0, "");
    /* Protected system files. */
    wsprintfW(path, L"%s\\system32\\xp25-probe-%lu.tmp", windows, GetCurrentProcessId());
    file_create_denied("create_file_in_system32", path);
    wsprintfW(path, L"%s\\xp25-probe-%lu.tmp", windows, GetCurrentProcessId());
    file_create_denied("create_file_in_windows", path);
    wsprintfW(path, L"%s\\system32\\drivers\\xp25-probe-%lu.sys", windows, GetCurrentProcessId());
    file_create_denied("create_file_in_drivers", path);
    wsprintfW(path, L"%s\\system32\\ntdll.dll", windows);
    file_write_denied("open_ntdll_for_write", path);
    wsprintfW(path, L"%s\\system32\\winlogon.exe", windows);
    file_write_denied("open_winlogon_for_write", path);
    wsprintfW(path, L"%s\\system32\\xp25krnl.exe", windows);
    file_write_denied("open_kernel_for_write", path);
    wsprintfW(path, L"%s\\system32\\xp25hal.dll", windows);
    file_write_denied("open_hal_for_write", path);
    wsprintfW(path, L"%s\\system32\\ue51sp3.dll", windows);
    file_write_denied("open_userenv_companion_for_write", path);
    wsprintfW(path, L"%s\\system32\\drivers\\xp25ntfs.sys", windows);
    file_write_denied("open_ntfs_driver_for_write", path);
    wsprintfW(path, L"%c:\\xp25\\native-winlogon.log", windows[0]);
    file_write_denied("open_winlogon_log_for_write", path);
    wsprintfW(path, L"%s\\system32\\config\\SAM", windows);
    file_write_denied("open_sam_hive_for_write", path);
    wsprintfW(path, L"%s\\system32\\drivers\\etc\\hosts", windows);
    file_write_denied("open_hosts_for_write", path);
    wsprintfW(path, L"%c:\\Program Files\\XP25\\XP25Broker.exe", windows[0]);
    file_write_denied("open_xp25_broker_for_write", path);
    {
        /* WRITE_DAC is what an owning account always gets. */
        HANDLE h;
        wsprintfW(path, L"%c:\\Program Files\\XP25\\XP25Broker.exe", windows[0]);
        h = CreateFileW(path, WRITE_DAC, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
        error = GetLastError();
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
        if (h == INVALID_HANDLE_VALUE && error == ERROR_FILE_NOT_FOUND) report("change_acl_of_xp25_broker", 3, error, "the file does not exist");
        else denied("change_acl_of_xp25_broker", h != INVALID_HANDLE_VALUE, error);
        wsprintfW(path, L"%s\\system32\\xp25krnl.exe", windows);
        h = CreateFileW(path, WRITE_DAC, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
        error = GetLastError();
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
        if (h == INVALID_HANDLE_VALUE && error == ERROR_FILE_NOT_FOUND) report("change_acl_of_kernel", 3, error, "the file does not exist");
        else denied("change_acl_of_kernel", h != INVALID_HANDLE_VALUE, error);
    }
    wsprintfW(path, L"%c:\\Program Files\\XP25\\xp25-probe-%lu.dll", windows[0], GetCurrentProcessId());
    file_create_denied("create_file_in_xp25_program_directory", path);
    wsprintfW(path, L"%c:\\Program Files\\XP25\\Security\\XP25Sec.exe", windows[0]);
    file_write_denied("open_xp25sec_for_write", path);
    wsprintfW(path, L"%s\\XP25\\Security\\baseline-backup.txt", windows);
    file_write_denied("open_baseline_backup_for_write", path);
    wsprintfW(path, L"%s\\XP25\\Security\\audit-snapshot.txt", windows);
    file_write_denied("open_audit_snapshot_for_write", path);
    wsprintfW(path, L"%s\\XP25\\Security\\xp25-probe-%lu.tmp", windows, GetCurrentProcessId());
    wsprintfW(command, L"%s\\XP25\\Security", windows);
    if (GetFileAttributesW(command) == INVALID_FILE_ATTRIBUTES && !hardened) report("create_file_in_security_store", 3, 0, "the store does not exist");
    else file_create_denied("create_file_in_security_store", path);
    /* Protected registry locations. */
    key_write_denied("write_hklm_run", L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
    key_write_denied("write_winlogon_key", L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon");
    key_write_denied("write_image_file_execution_options", L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options");
    key_write_denied("write_appinit_key", L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows");
    key_write_denied("write_lsa_key", L"SYSTEM\\CurrentControlSet\\Control\\Lsa");
    key_write_denied("write_services_key", L"SYSTEM\\CurrentControlSet\\Services");
    key_write_denied("write_remote_registry_service_key", L"SYSTEM\\CurrentControlSet\\Services\\RemoteRegistry");
    key_write_denied("write_firewall_policy", L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile");
    key_write_denied("write_terminal_server_key", L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server");
    key_write_denied("write_session_manager_key", L"SYSTEM\\CurrentControlSet\\Control\\Session Manager");
    key_write_denied("write_explorer_policies", L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer");
    key_write_denied("write_machine_internet_zone", L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3");
    key_write_denied("write_machine_policies", L"SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings");
    key_write_denied("write_script_file_class", L"SOFTWARE\\Classes\\VBSFile\\Shell");
    key_write_denied("write_xp25_agent_policy", L"SOFTWARE\\XP25\\Agent\\Policy");
    key_write_denied("write_xp25_security_baseline", L"SOFTWARE\\XP25\\Security\\Baseline");
    key_write_denied("write_security_event_log_settings", L"SYSTEM\\CurrentControlSet\\Services\\Eventlog\\Security");
    key_write_denied("write_xp25_broker_service_key", L"SYSTEM\\CurrentControlSet\\Services\\XP25Broker");
    key_write_denied("write_xp25_registry_root", L"SOFTWARE\\XP25");
    {
        /* The owner of a key may rewrite its DACL whatever the DACL says. */
        static const WCHAR *const owned[] = {L"SYSTEM\\CurrentControlSet\\Services\\XP25Broker", L"SOFTWARE\\XP25", L"SOFTWARE\\XP25\\Agent\\Policy"};
        static const char *const cases[] = {"change_acl_of_xp25_broker_service_key", "change_acl_of_xp25_registry_root", "change_acl_of_xp25_agent_policy"};
        unsigned i;
        for (i = 0; i < 3; ++i) {
            HKEY key;
            LONG opened = RegOpenKeyExW(HKEY_LOCAL_MACHINE, owned[i], 0, WRITE_DAC, &key);
            if (!opened) RegCloseKey(key);
            if (opened == ERROR_FILE_NOT_FOUND) report(cases[i], 3, (DWORD)opened, "the key does not exist");
            else denied(cases[i], opened == ERROR_SUCCESS, (DWORD)opened);
        }
    }
    /* Services. */
    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    error = GetLastError();
    if (scm) CloseServiceHandle(scm);
    denied("open_scm_to_create_services", scm != NULL, error);
    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) report("connect_scm", 0, GetLastError(), "");
    else {
        static const WCHAR *const names[] = {L"RemoteRegistry", L"LanmanServer", L"SharedAccess", L"XP25Broker", L"Eventlog"};
        static const char *const cases[] = {"reconfigure_remote_registry", "reconfigure_server", "reconfigure_firewall_service",
                                            "reconfigure_xp25_broker", "reconfigure_event_log"};
        unsigned i;
        for (i = 0; i < 5; ++i) {
            service = OpenServiceW(scm, names[i], SERVICE_CHANGE_CONFIG);
            error = GetLastError();
            if (service) CloseServiceHandle(service);
            if (!service && error == ERROR_SERVICE_DOES_NOT_EXIST) report(cases[i], 3, error, "the service is not installed");
            else denied(cases[i], service != NULL, error);
        }
        service = OpenServiceW(scm, L"RemoteRegistry", SERVICE_START);
        error = GetLastError();
        if (service) CloseServiceHandle(service);
        denied("start_remote_registry", service != NULL, error);
        service = OpenServiceW(scm, L"SharedAccess", SERVICE_STOP);
        error = GetLastError();
        if (service) CloseServiceHandle(service);
        denied("stop_firewall_service", service != NULL, error);
        service = OpenServiceW(scm, L"XP25Broker", WRITE_DAC);
        error = GetLastError();
        if (service) CloseServiceHandle(service);
        if (!service && error == ERROR_SERVICE_DOES_NOT_EXIST) report("change_xp25_broker_acl", 3, error, "the service is not installed");
        else denied("change_xp25_broker_acl", service != NULL, error);
        CloseServiceHandle(scm);
    }
    /* Privileges and other processes. */
    report("cannot_enable_debug_privilege", !enable_privilege(SE_DEBUG_NAME), GetLastError(), "");
    report("cannot_enable_load_driver_privilege", !enable_privilege(SE_LOAD_DRIVER_NAME), GetLastError(), "");
    report("cannot_enable_take_ownership_privilege", !enable_privilege(SE_TAKE_OWNERSHIP_NAME), GetLastError(), "");
    report("cannot_enable_restore_privilege", !enable_privilege(SE_RESTORE_NAME), GetLastError(), "");
    report("cannot_enable_tcb_privilege", !enable_privilege(SE_TCB_NAME), GetLastError(), "");
    {
        static const WCHAR *const names[] = {L"lsass.exe", L"winlogon.exe", L"services.exe", L"csrss.exe", L"XP25Broker.exe"};
        static const char *const cases[] = {"open_lsass_for_injection", "open_winlogon_for_injection", "open_services_for_injection",
                                            "open_csrss_for_injection", "open_xp25_broker_for_injection"};
        unsigned i;
        for (i = 0; i < 5; ++i) {
            pid = find_process(names[i]);
            if (!pid) { report(cases[i], 3, 0, "the process is not running"); continue; }
            process = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, FALSE, pid);
            error = GetLastError();
            if (process) CloseHandle(process);
            denied(cases[i], process != NULL, error);
            process = OpenProcess(PROCESS_VM_READ, FALSE, pid);
            error = GetLastError();
            if (process) CloseHandle(process);
            if (i == 0) denied("read_lsass_memory", process != NULL, error);
        }
    }
    /* The XP25 broker runs as SYSTEM and serves every interactive user. It must refuse to stop the
       firewall, and the firewall must still be running afterwards. */
    {
        static const char request[] = "{\"v\":1,\"op\":\"service_control\",\"name\":\"SharedAccess\",\"action\":\"stop\"}";
        char reply[2048];
        DWORD got = 0;
        SERVICE_STATUS state;
        BOOL answered = WaitNamedPipeW(L"\\\\.\\pipe\\XP25AgentBroker", 5000) &&
                        CallNamedPipeW(L"\\\\.\\pipe\\XP25AgentBroker", (void *)request, sizeof(request) - 1, reply, sizeof(reply) - 1, &got, 30000);
        error = GetLastError();
        reply[answered ? got : 0] = 0;
        ZeroMemory(&state, sizeof(state));
        scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
        service = scm ? OpenServiceW(scm, L"SharedAccess", SERVICE_QUERY_STATUS) : NULL;
        if (service) { QueryServiceStatus(service, &state); CloseServiceHandle(service); }
        if (scm) CloseServiceHandle(scm);
        if (!answered) report("broker_refuses_to_stop_firewall", 3, error, "the XP25 broker did not answer");
        else {
            /* Decided by the firewall's state, not by the wording of the reply. */
            Sleep(3000);
            scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
            service = scm ? OpenServiceW(scm, L"SharedAccess", SERVICE_QUERY_STATUS) : NULL;
            if (service) { QueryServiceStatus(service, &state); CloseServiceHandle(service); }
            if (scm) CloseServiceHandle(scm);
            if (hardened) report("broker_refuses_to_stop_firewall", state.dwCurrentState == SERVICE_RUNNING && strstr(reply, "permission_denied") != NULL,
                                 state.dwCurrentState, state.dwCurrentState == SERVICE_RUNNING ? "firewall still running" : "the firewall was stopped");
            else report("broker_refuses_to_stop_firewall", 2, state.dwCurrentState,
                        state.dwCurrentState == SERVICE_RUNNING ? "firewall still running" : "the firewall was stopped by the broker");
        }
    }
    /* Secure desktop. */
    desktop = OpenDesktopW(L"Winlogon", 0, FALSE, DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS | DESKTOP_CREATEWINDOW | DESKTOP_HOOKCONTROL |
                           DESKTOP_JOURNALRECORD | DESKTOP_JOURNALPLAYBACK);
    error = GetLastError();
    if (desktop) CloseDesktop(desktop);
    denied("open_winlogon_desktop", desktop != NULL, error);
    desktop = OpenDesktopW(L"Winlogon", 0, FALSE, DESKTOP_READOBJECTS);
    error = GetLastError();
    if (desktop) CloseDesktop(desktop);
    denied("read_winlogon_desktop_windows", desktop != NULL, error);
    desktop = OpenDesktopW(L"Winlogon", 0, FALSE, WRITE_DAC);
    error = GetLastError();
    if (desktop) CloseDesktop(desktop);
    denied("change_winlogon_desktop_acl", desktop != NULL, error);
    /* The XP25 tools refuse administrative commands and still report read-only. */
    if (tools[0]) {
        wsprintfW(command, L"\"%s\\XP25Sec.exe\" rollback --quiet", tools);
        code = run(command, 60000);
        report("xp25sec_rollback_refused", code == 5, code, "exit code is in the error field");
        wsprintfW(command, L"\"%s\\XP25Sec.exe\" apply --quiet", tools);
        code = run(command, 60000);
        report("xp25sec_apply_refused", code == 5, code, "exit code is in the error field");
        wsprintfW(command, L"\"%s\\XP25Audit.exe\" snapshot --quiet", tools);
        code = run(command, 60000);
        report("xp25audit_snapshot_refused", code == 5, code, "exit code is in the error field");
        wsprintfW(command, L"\"%s\\XP25Audit.exe\" report --quiet", tools);
        code = run(command, 240000);
        report("xp25audit_report_runs_unprivileged", code == 0, code, "exit code is in the error field");
        wsprintfW(command, L"\"%s\\XP25Sec.exe\" status --quiet", tools);
        code = run(command, 60000);
        report("xp25sec_status_runs_unprivileged", code == 0, code, "exit code is in the error field");
    } else report("xp25_tools_refuse_unprivileged_changes", 3, 0, "no --tools directory was given");
}

static void limited_only_cases(void)
{
    WCHAR path[MAX_PATH];
    HANDLE h;
    HKEY key;
    LONG error;
    /* Observations of NT 5.1 defaults that the baseline does not change. */
    lstrcpyW(path, L"C:\\xp25-probe-root.tmp");
    h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    report("ordinary_user_creates_file_in_drive_root", 2, h == INVALID_HANDLE_VALUE ? GetLastError() : 0,
           h == INVALID_HANDLE_VALUE ? "denied" : "allowed");
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    lstrcpyW(path, L"C:\\xp25-probe-root-dir");
    if (CreateDirectoryW(path, NULL)) {
        RemoveDirectoryW(path);
        report("ordinary_user_creates_directory_in_drive_root", 2, 0, "allowed (NT 5.1 default)");
    } else report("ordinary_user_creates_directory_in_drive_root", 2, GetLastError(), "denied");
    error = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, NULL, 0, KEY_SET_VALUE, NULL, &key, NULL);
    if (!error) {
        error = RegSetValueExW(key, L"XP25SecProbe", 0, REG_SZ, (const BYTE *)L"", sizeof(WCHAR));
        RegDeleteValueW(key, L"XP25SecProbe");
        RegCloseKey(key);
    }
    report("ordinary_user_writes_own_run_key", 2, (DWORD)error, error ? "denied" : "allowed (per-user persistence is by design)");
}

static void restricted_only_cases(void)
{
    STARTUPINFOW start;
    PROCESS_INFORMATION process;
    WCHAR command[] = L"cmd.exe /c exit 0";
    BOOL in_job = FALSE, ok;
    DWORD error;
    IsProcessInJob(GetCurrentProcess(), NULL, &in_job);
    report("restricted_process_is_in_job", in_job, 0, "");
    ZeroMemory(&start, sizeof(start));
    start.cb = sizeof(start);
    ok = CreateProcessW(NULL, command, NULL, NULL, FALSE, CREATE_BREAKAWAY_FROM_JOB | CREATE_NO_WINDOW, NULL, NULL, &start, &process);
    error = GetLastError();
    if (ok) { CloseHandle(process.hThread); CloseHandle(process.hProcess); }
    denied("break_away_from_job", ok, error);
}

/* ---- administrator side ------------------------------------------------------- */
static BOOL random_password(WCHAR *out, int count)
{
    static const WCHAR alphabet[] = L"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    HCRYPTPROV provider;
    BYTE bytes[32];
    int i;
    if (count < 26 || !CryptAcquireContextW(&provider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) return FALSE;
    if (!CryptGenRandom(provider, sizeof(bytes), bytes)) { CryptReleaseContext(provider, 0); return FALSE; }
    CryptReleaseContext(provider, 0);
    for (i = 0; i < 20; ++i) out[i] = alphabet[bytes[i] % (sizeof(alphabet) / sizeof(WCHAR) - 1)];
    /* Satisfy any complexity policy without reducing the random part. */
    out[20] = L'!'; out[21] = L'x'; out[22] = L'P'; out[23] = L'2'; out[24] = 0;
    return TRUE;
}

static void relay(const WCHAR *file)
{
    HANDLE h = CreateFileW(file, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    char buffer[4096];
    DWORD read, done;
    if (h == INVALID_HANDLE_VALUE) return;
    while (ReadFile(h, buffer, sizeof(buffer), &read, NULL) && read)
        if (output != INVALID_HANDLE_VALUE) WriteFile(output, buffer, read, &done, NULL);
    CloseHandle(h);
}

static void child_arguments(WCHAR *command, const WCHAR *mode, const WCHAR *result)
{
    WCHAR self[MAX_PATH];
    GetModuleFileNameW(NULL, self, MAX_PATH);
    wsprintfW(command, L"\"%s\" %s \"%s\"%s%s", self, mode, result, hardened ? L" --hardened" : L"", xp25_winlogon ? L" --xp25-winlogon" : L"");
    if (tools[0]) { lstrcatW(command, L" --tools \""); lstrcatW(command, tools); lstrcatW(command, L"\""); }
}

static void admin_controls(void)
{
    WCHAR windows[MAX_PATH], path[MAX_PATH * 2];
    HANDLE h;
    HKEY key;
    SC_HANDLE scm;
    LONG error;
    GetWindowsDirectoryW(windows, MAX_PATH);
    report("caller_is_administrator", is_admin(), 0, "");
    wsprintfW(path, L"%s\\system32\\xp25-probe-admin-%lu.tmp", windows, GetCurrentProcessId());
    h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    report("administrator_creates_file_in_system32", h != INVALID_HANDLE_VALUE, h == INVALID_HANDLE_VALUE ? GetLastError() : 0, "");
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    error = RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\XP25SecProbeFixture", 0, NULL, REG_OPTION_VOLATILE, KEY_SET_VALUE, NULL, &key, NULL);
    if (!error) { RegCloseKey(key); error = RegDeleteKeyW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\XP25SecProbeFixture"); }
    report("administrator_writes_hklm_software", error == ERROR_SUCCESS, (DWORD)error, "");
    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    report("administrator_opens_scm_fully", scm != NULL, scm ? 0 : GetLastError(), "");
    if (scm) CloseServiceHandle(scm);
    report("administrator_enables_debug_privilege", enable_privilege(SE_DEBUG_NAME), GetLastError(), "");
}

/* The live Winlogon desktop DACL: nobody but SYSTEM may hold more than READ_CONTROL. */
static void winlogon_desktop_acl(void)
{
    HDESK desktop = OpenDesktopW(L"Winlogon", 0, FALSE, READ_CONTROL);
    PSECURITY_DESCRIPTOR sd = NULL;
    PACL dacl = NULL;
    DWORD error, i;
    BOOL clean = TRUE;
    char note[200];
    HDESK full = OpenDesktopW(L"Winlogon", 0, FALSE, DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS | DESKTOP_CREATEWINDOW | DESKTOP_HOOKCONTROL);
    error = GetLastError();
    if (full) CloseDesktop(full);
    if (xp25_winlogon) denied("administrator_cannot_open_winlogon_desktop", full != NULL, error);
    else report("administrator_cannot_open_winlogon_desktop", 2, full ? 0 : error, full ? "opened (original Winlogon ACL)" : "denied");
    if (!desktop) {
        /* USER refuses the logon desktop to every process but the logon process, whatever its DACL grants. */
        error = GetLastError();
        report("winlogon_desktop_acl_system_only", error == ERROR_ACCESS_DENIED ? 1 : 0, error, "not even READ_CONTROL is granted, so the DACL cannot be read");
        return;
    }
    error = GetSecurityInfo(desktop, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, &sd);
    note[0] = 0;
    if (!error && dacl) {
        for (i = 0; i < dacl->AceCount; ++i) {
            ACCESS_ALLOWED_ACE *ace;
            if (!GetAce(dacl, i, (void **)&ace) || ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE) continue;
            if (!IsWellKnownSid((PSID)&ace->SidStart, WinLocalSystemSid) && (ace->Mask & ~(DWORD)READ_CONTROL)) {
                WCHAR *sid = NULL;
                clean = FALSE;
                if (ConvertSidToStringSidW((PSID)&ace->SidStart, &sid)) { wsprintfA(note, "%.80S holds mask 0x%lx", sid, ace->Mask); LocalFree(sid); }
            }
        }
    } else clean = FALSE;
    if (sd) LocalFree(sd);
    CloseDesktop(desktop);
    report("winlogon_desktop_acl_system_only", xp25_winlogon ? clean : 2, error, note);
}

static void baseline_services(void)
{
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT), service;
    BYTE buffer[8192];
    QUERY_SERVICE_CONFIGW *config = (QUERY_SERVICE_CONFIGW *)buffer;
    SERVICE_STATUS status;
    DWORD needed, error;
    unsigned i;
    if (!scm) { report("baseline_services", 0, GetLastError(), "cannot connect to the service control manager"); return; }
    for (i = 0; i < sec_service_rule_count(); ++i) {
        const SEC_SERVICE_RULE *rule = sec_service_rule_at(i);
        WCHAR name[80];
        char label[120];
        BOOL ok;
        MultiByteToWideChar(CP_ACP, 0, rule->name, -1, name, 80);
        wsprintfA(label, "service_disabled_and_stopped_%s", rule->name);
        service = OpenServiceW(scm, name, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
        if (!service) { report(label, GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST ? 3 : 0, GetLastError(), "not installed"); continue; }
        ok = QueryServiceConfigW(service, config, sizeof(buffer), &needed) && QueryServiceStatus(service, &status) &&
             config->dwStartType == SERVICE_DISABLED && status.dwCurrentState == SERVICE_STOPPED;
        report(label, hardened ? ok : 2, 0, ok ? "disabled and stopped" : "enabled or running");
        CloseServiceHandle(service);
    }
    /* Even an administrator cannot start a disabled service without re-enabling it first. */
    service = OpenServiceW(scm, L"RemoteRegistry", SERVICE_START);
    if (service) {
        BOOL started = StartServiceW(service, 0, NULL);
        error = GetLastError();
        if (hardened) report("disabled_service_does_not_start", !started && error == ERROR_SERVICE_DISABLED, started ? 0 : error, "");
        else {
            if (started) { SC_HANDLE stop = OpenServiceW(scm, L"RemoteRegistry", SERVICE_STOP); if (stop) { ControlService(stop, SERVICE_CONTROL_STOP, &status); CloseServiceHandle(stop); } }
            report("disabled_service_does_not_start", 2, started ? 0 : error, started ? "started (not disabled)" : "did not start");
        }
        CloseServiceHandle(service);
    } else report("disabled_service_does_not_start", 3, GetLastError(), "");
    CloseServiceHandle(scm);
}

/* Looks for a recent Security log record with one of the given event ids. */
static BOOL security_event_since(DWORD since, const DWORD *ids, unsigned id_count)
{
    HANDLE log = OpenEventLogW(NULL, L"Security");
    static BYTE buffer[65536];
    DWORD read, needed;
    unsigned scanned = 0, i;
    BOOL found = FALSE;
    if (!log) return FALSE;
    while (!found && scanned < 4000 && ReadEventLogW(log, EVENTLOG_BACKWARDS_READ | EVENTLOG_SEQUENTIAL_READ, 0, buffer, sizeof(buffer), &read, &needed)) {
        BYTE *p = buffer;
        while (p < buffer + read && !found) {
            EVENTLOGRECORD *record = (EVENTLOGRECORD *)p;
            ++scanned;
            if (record->TimeGenerated + 5 < since) { scanned = 4000; break; }
            for (i = 0; i < id_count; ++i) if ((record->EventID & 0xffff) == ids[i]) found = TRUE;
            if (!record->Length) break;
            p += record->Length;
        }
    }
    CloseEventLog(log);
    return found;
}

static DWORD unix_now(void)
{
    FILETIME now;
    ULARGE_INTEGER ticks;
    GetSystemTimeAsFileTime(&now);
    ticks.LowPart = now.dwLowDateTime;
    ticks.HighPart = now.dwHighDateTime;
    return (DWORD)((ticks.QuadPart - 116444736000000000ULL) / 10000000ULL);   /* 100 ns since 1601 -> s since 1970 */
}

static void administrator(void)
{
    USER_INFO_1 user;
    LOCALGROUP_MEMBERS_INFO_3 member;
    WCHAR password[32], wrong[] = L"XP25-Invalid-Probe-Password-2026", command[MAX_PATH * 3], directory[MAX_PATH], result[MAX_PATH], windows[MAX_PATH];
    STARTUPINFOW start;
    PROCESS_INFORMATION process;
    PSECURITY_DESCRIPTOR sd = NULL;
    SECURITY_ATTRIBUTES attributes;
    NET_API_STATUS status;
    DWORD error = 0, code = 0, started = unix_now();
    HANDLE token = NULL, restricted = NULL, job, bad = NULL;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    SID_AND_ATTRIBUTES deny[1];
    JOBOBJECT_BASIC_LIMIT_INFORMATION limits;
    static const DWORD account_events[] = {624, 642, 636, 632};
    static const DWORD logon_failures[] = {529, 680, 681, 675};
    BOOL created, ok;

    admin_controls();
    winlogon_desktop_acl();
    baseline_services();
    GetWindowsDirectoryW(windows, MAX_PATH);

    /* A result directory the test accounts can write to, and nothing else. */
    wsprintfW(directory, L"%c:\\xp25\\secprobe-%lu", windows[0], GetCurrentProcessId());
    ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;AU)", SDDL_REVISION_1, &sd, NULL);
    attributes.nLength = sizeof(attributes); attributes.lpSecurityDescriptor = sd; attributes.bInheritHandle = FALSE;
    if (!CreateDirectoryW(directory, &attributes)) { report("result_directory", 0, GetLastError(), ""); return; }

    /* Ordinary account. The password is random, never written anywhere, and the account is removed below. */
    NetUserDel(NULL, ACCOUNT);
    ZeroMemory(&user, sizeof(user));
    created = random_password(password, 32);
    user.usri1_name = ACCOUNT; user.usri1_password = password; user.usri1_priv = USER_PRIV_USER;
    user.usri1_flags = UF_SCRIPT | UF_NORMAL_ACCOUNT | UF_DONT_EXPIRE_PASSWD;
    user.usri1_comment = L"XP25 security regression (temporary)";
    status = created ? NetUserAdd(NULL, 1, (BYTE *)&user, NULL) : ERROR_INVALID_DATA;
    report("create_ordinary_test_account", status == NERR_Success, status, "");
    if (status == NERR_Success) {
        member.lgrmi3_domainandname = ACCOUNT;
        NetLocalGroupAddMembers(NULL, L"Users", 3, (BYTE *)&member, 1);
        wsprintfW(result, L"%s\\limited.jsonl", directory);
        child_arguments(command, L"limited", result);
        ZeroMemory(&start, sizeof(start));
        start.cb = sizeof(start);
        ok = CreateProcessWithLogonW(ACCOUNT, L".", password, LOGON_WITH_PROFILE, NULL, command, CREATE_NO_WINDOW, NULL, windows, &start, &process);
        error = GetLastError();
        report("run_as_ordinary_account", ok, ok ? 0 : error, "CreateProcessWithLogonW through the Secondary Logon service");
        if (ok) {
            if (WaitForSingleObject(process.hProcess, 600000) != WAIT_OBJECT_0) TerminateProcess(process.hProcess, 250);
            WaitForSingleObject(process.hProcess, 5000);
            GetExitCodeProcess(process.hProcess, &code);
            CloseHandle(process.hThread); CloseHandle(process.hProcess);
            relay(result);
            report("ordinary_account_cases", code == 0, code, "number of failed cases in the ordinary-account process");
        }
        /* A wrong password must be refused and, with the baseline, audited. */
        ok = LogonUserW(ACCOUNT, L".", wrong, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &bad);
        error = GetLastError();
        if (ok) CloseHandle(bad);
        report("wrong_password_rejected", !ok && error == ERROR_LOGON_FAILURE, ok ? 0 : error, "");
    }
    SecureZeroMemory(password, sizeof(password));

    /* Restricted token of this administrator: Administrators deny-only, privileges removed, inside a job. */
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &token) &&
        AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &deny[0].Sid)) {
        deny[0].Attributes = 0;
        ok = CreateRestrictedToken(token, DISABLE_MAX_PRIVILEGE, 1, deny, 0, NULL, 0, NULL, &restricted);
        report("create_restricted_token", ok, ok ? 0 : GetLastError(), "");
        if (ok) {
            wsprintfW(result, L"%s\\restricted.jsonl", directory);
            child_arguments(command, L"restricted", result);
            job = CreateJobObjectW(NULL, NULL);
            ZeroMemory(&limits, sizeof(limits));
            limits.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            limits.ActiveProcessLimit = 8;
            SetInformationJobObject(job, JobObjectBasicLimitInformation, &limits, sizeof(limits));
            ZeroMemory(&start, sizeof(start));
            start.cb = sizeof(start);
            ok = CreateProcessAsUserW(restricted, NULL, command, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, windows, &start, &process);
            error = GetLastError();
            report("run_with_restricted_token", ok, ok ? 0 : error, "");
            if (ok) {
                AssignProcessToJobObject(job, process.hProcess);
                ResumeThread(process.hThread);
                if (WaitForSingleObject(process.hProcess, 600000) != WAIT_OBJECT_0) TerminateProcess(process.hProcess, 250);
                WaitForSingleObject(process.hProcess, 5000);
                GetExitCodeProcess(process.hProcess, &code);
                CloseHandle(process.hThread); CloseHandle(process.hProcess);
                relay(result);
                report("restricted_token_cases", code == 0, code, "number of failed cases in the restricted process");
            }
            CloseHandle(job);
            CloseHandle(restricted);
        }
        FreeSid(deny[0].Sid);
        CloseHandle(token);
    } else report("create_restricted_token", 0, GetLastError(), "");

    /* On an unhardened system the broker case above stops the firewall for real; put it back so
       everything measured after this probe sees the firewall as the system runs it. */
    {
        SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT), service = scm ? OpenServiceW(scm, L"SharedAccess", SERVICE_QUERY_STATUS | SERVICE_START) : NULL;
        SERVICE_STATUS state;
        DWORD waited = 0;
        ZeroMemory(&state, sizeof(state));
        if (service && QueryServiceStatus(service, &state) && state.dwCurrentState == SERVICE_STOPPED) {
            ok = StartServiceW(service, 0, NULL);
            error = ok ? 0 : GetLastError();
            while (ok && waited < 30000 && QueryServiceStatus(service, &state) && state.dwCurrentState != SERVICE_RUNNING) { Sleep(500); waited += 500; }
            report("firewall_restarted_after_broker_case", ok && state.dwCurrentState == SERVICE_RUNNING ? 2 : 0, error, "the firewall had been stopped through the broker");
        }
        if (service) CloseServiceHandle(service);
        if (scm) CloseServiceHandle(scm);
    }

    /* Audit trail of what this probe just did. */
    Sleep(2000);
    if (enable_privilege(SE_SECURITY_NAME)) {
        ok = security_event_since(started, account_events, 4);
        report("audit_records_account_management", hardened ? ok : 2, 0, ok ? "found" : "no record (auditing off)");
        ok = security_event_since(started, logon_failures, 4);
        report("audit_records_failed_logon", hardened ? ok : 2, 0, ok ? "found" : "no record (auditing off)");
    } else report("audit_records_account_management", 3, GetLastError(), "SeSecurityPrivilege unavailable");

    /* Remove the account, its profile and the result directory. */
    {
        BYTE buffer[128];
        DWORD size = sizeof(buffer), domain_size = 128;
        WCHAR domain[128], *sid = NULL;
        SID_NAME_USE use;
        if (LookupAccountNameW(NULL, ACCOUNT, buffer, &size, domain, &domain_size, &use) && ConvertSidToStringSidW((PSID)buffer, &sid)) {
            DeleteProfileW(sid, NULL, NULL);
            LocalFree(sid);
        }
        status = NetUserDel(NULL, ACCOUNT);
        report("remove_ordinary_test_account", status == NERR_Success || status == NERR_UserNotFound, status, "");
        wsprintfW(result, L"%s\\limited.jsonl", directory); DeleteFileW(result);
        wsprintfW(result, L"%s\\restricted.jsonl", directory); DeleteFileW(result);
        RemoveDirectoryW(directory);
    }
    if (sd) LocalFree(sd);
}

void WINAPI ProbeMain(void)
{
    int argc = 0, i;
    WCHAR **argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    const WCHAR *mode = argc > 1 ? argv[1] : L"";
    char done[160];
    for (i = 2; i < argc; ++i) {
        if (!lstrcmpW(argv[i], L"--hardened")) hardened = TRUE;
        else if (!lstrcmpW(argv[i], L"--xp25-winlogon")) xp25_winlogon = TRUE;
        else if (!lstrcmpW(argv[i], L"--tools") && i + 1 < argc) lstrcpynW(tools, argv[++i], MAX_PATH);
    }
    if (!lstrcmpW(mode, L"power") && argc > 2) {
        /* ExitWindowsEx reaches the logon process through USER; shutdown.exe needs the
           InitShutdown RPC interface, which the XP25 Winlogon does not serve. */
        BOOL restart = !lstrcmpW(argv[2], L"restart");
        enable_privilege(SE_SHUTDOWN_NAME);
        ExitProcess(ExitWindowsEx((restart ? EWX_REBOOT : EWX_POWEROFF) | EWX_FORCEIFHUNG, 0) ? 0 : 1);
    }
    if (!lstrcmpW(mode, L"admin")) {
        output = CreateFileW(L"COM1", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (output == INVALID_HANDLE_VALUE) ExitProcess(90);
        emit("SECURITY_PROBE_STARTED\r\n");
        administrator();
    } else if ((!lstrcmpW(mode, L"limited") || !lstrcmpW(mode, L"restricted")) && argc > 2) {
        context = !lstrcmpW(mode, L"limited") ? "ordinary_account" : "restricted_token";
        output = CreateFileW(argv[2], GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (output == INVALID_HANDLE_VALUE) ExitProcess(91);
        unprivileged_cases();
        if (!lstrcmpW(mode, L"limited")) limited_only_cases(); else restricted_only_cases();
    } else ExitProcess(2);
    wsprintfA(done, "SECURITY_PROBE_COMPLETE context=%s passes=%u failures=%u observed=%u not_run=%u\r\n", context, passes, failures, observed, not_run);
    emit(done);
    CloseHandle(output);
    ExitProcess(failures > 200 ? 200 : failures);
}
