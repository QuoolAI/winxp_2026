/* XP25 security regression probe for a disposable guest.

   security_probe.exe admin [--hardened] [--xp25-winlogon] [--tools <dir>]
       Run by the logged-on administrator. It creates a temporary ordinary
       account, runs itself as that account (seclogon) and with a restricted
       token of its own, checks that legitimate administrator operations
       still work, and removes the account again.
   security_probe.exe limited|restricted <result file> [...]   (started by the above)
   security_probe.exe fwcheck <tag>
       Guest-observed state of the Windows Firewall: the service, its kernel
       driver, the policy values and the service's access control list.
   security_probe.exe listen <port> <directory> [broadcast]
       A TCP and UDP test listener that answers with a fixed banner / echo, so
       an outside observer can tell "filtered by the firewall" from "nothing
       is listening". With "broadcast" it also sends a broadcast datagram from
       its UDP port every half second, which opens Windows Firewall's window
       for unicast replies to that port unless the policy disables it. Runs
       until <directory>\listener.stop exists.
   security_probe.exe desktop <result file> [slow]
       Run in a standard user's own interactive session: profile, shell,
       file operations, ClippyAI, RoverAI, the broker, the browser, programs.
   security_probe.exe apps <result file> [slow]
       Starts the legacy programs and games installed with Windows and checks
       each shows a responsive window and closes.
   security_probe.exe hostwait <label> [seconds]
       Wait until the lab's observer has finished the observation the suite
       asked for with XP25_HOST_REQUEST=<kind>:<label> (vm/security_network.py).
   security_probe.exe power shutdown|restart|logoff
   security_probe.exe aireset
       Ends RoverAI and ClippyAI the way a user does (window close, the Exit
       command) between repeated AI suites; exit code 0 when both are gone.

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
#include <winsock2.h>
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <lm.h>
#include <wincrypt.h>
#include <userenv.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <string.h>
#include "sec_core.h"

#define ACCOUNT L"xp25sectest"

static HANDLE output = INVALID_HANDLE_VALUE, serial = INVALID_HANDLE_VALUE;
static DWORD scale = 1;
static unsigned passes, failures, observed, not_run;
static const char *context = "admin";
static BOOL hardened, xp25_winlogon, cve_checks;
static WCHAR tools[MAX_PATH];

static void cve_unprivileged_cases(void);
static void cve_admin_cases(void);

static void emit(const char *text)
{
    DWORD done;
    if (output != INVALID_HANDLE_VALUE) WriteFile(output, text, (DWORD)lstrlenA(text), &done, NULL);
    if (serial != INVALID_HANDLE_VALUE) WriteFile(serial, text, (DWORD)lstrlenA(text), &done, NULL);
}

/* status: 1 pass, 0 fail, 2 observed (no expectation), 3 not run. */
static void report(const char *name, int status, DWORD error, const char *note)
{
    static const char *const names[] = {"fail", "pass", "observed", "not_run"};
    char row[1100], safe[820];
    int i, n = 0;
    if (status == 1) ++passes; else if (status == 0) ++failures; else if (status == 2) ++observed; else ++not_run;
    /* Notes carry paths and window titles: escape them so every record stays valid JSON. */
    for (i = 0; note && note[i] && n < 400; ++i) {
        unsigned char c = (unsigned char)note[i];
        if (c == '\\' || c == '"') { safe[n++] = '\\'; safe[n++] = (char)c; }
        else safe[n++] = (char)(c < 32 ? ' ' : c);
    }
    safe[n] = 0;
    wsprintfA(row, "{\"security_case\":\"%.80s\",\"context\":\"%s\",\"status\":\"%s\",\"error\":%lu,\"note\":\"%s\"}\r\n",
              name, context, names[status], error, safe);
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

static DWORD service_state(const WCHAR *name)
{
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT), service = scm ? OpenServiceW(scm, name, SERVICE_QUERY_STATUS) : NULL;
    SERVICE_STATUS state;
    ZeroMemory(&state, sizeof(state));
    if (service) { QueryServiceStatus(service, &state); CloseServiceHandle(service); }
    if (scm) CloseServiceHandle(scm);
    return state.dwCurrentState;
}

static BOOL machine_dword(const WCHAR *key, const WCHAR *value, DWORD *out)
{
    HKEY handle;
    DWORD type, size = sizeof(*out);
    BOOL ok;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, key, 0, KEY_QUERY_VALUE, &handle)) return FALSE;
    ok = RegQueryValueExW(handle, value, NULL, &type, (BYTE *)out, &size) == ERROR_SUCCESS && type == REG_DWORD;
    RegCloseKey(handle);
    return ok;
}

#define FIREWALL_POLICY L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\"
#define BROKER_PIPE L"\\\\.\\pipe\\XP25AgentBroker"

/* One request to the XP25 broker (LocalSystem), opened the way its real client opens it: without the
   right to add pipe instances and at identification level. The broker serves one client at a time, so a
   busy or momentarily absent pipe is waited for. Returns FALSE when it did not answer. */
static BOOL broker(const char *request, DWORD size, char *reply, DWORD reply_size)
{
    HANDLE pipe = INVALID_HANDLE_VALUE;
    DWORD got = 0, mode = PIPE_READMODE_MESSAGE, start = GetTickCount(), error = 0;
    BOOL ok;
    while (pipe == INVALID_HANDLE_VALUE && GetTickCount() - start < 15000) {
        pipe = CreateFileW(BROKER_PIPE, GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES, 0, NULL, OPEN_EXISTING,
                           SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, NULL);
        if (pipe != INVALID_HANDLE_VALUE) break;
        error = GetLastError();
        if (error == ERROR_PIPE_BUSY) WaitNamedPipeW(BROKER_PIPE, 2000);
        else if (error == ERROR_FILE_NOT_FOUND) Sleep(50);
        else break;
    }
    reply[0] = 0;
    if (pipe == INVALID_HANDLE_VALUE) { SetLastError(error); return FALSE; }
    ok = SetNamedPipeHandleState(pipe, &mode, NULL, NULL) && TransactNamedPipe(pipe, (void *)request, size, reply, reply_size - 1, &got, NULL);
    error = GetLastError();
    CloseHandle(pipe);
    reply[ok ? got : 0] = 0;
    SetLastError(error);
    return ok;
}

/* A request the broker must refuse. Decided by what happened to the service; the reply only
   tells a refusal from "too many requests", which proves nothing and is reported as not run. */
static void broker_must_refuse(const char *name, const char *request, const WCHAR *service, DWORD expected_state)
{
    char reply[2048];
    DWORD before = service ? service_state(service) : 0, after, error;
    BOOL answered = broker(request, (DWORD)lstrlenA(request), reply, sizeof(reply));
    error = GetLastError();
    if (!answered) { report(name, 3, error, "the XP25 broker did not answer"); return; }
    if (strstr(reply, "broker_busy")) { report(name, 3, 0, "the broker's request limit was reached"); return; }
    Sleep(service ? 3000 : 0);
    after = service ? service_state(service) : 0;
    if (!hardened) { report(name, 2, after, strstr(reply, "\"ok\":true") ? "the broker performed the request" : "refused"); return; }
    report(name, !strstr(reply, "\"ok\":true") && (!service || (after == before && (!expected_state || after == expected_state))), after,
           strstr(reply, "\"ok\":true") ? "the broker performed the request" :
           strstr(reply, "permission_denied") ? "permission_denied" : strstr(reply, "broker_refused") ? "broker_refused" :
           strstr(reply, "broker_unsupported") ? "broker_unsupported" : strstr(reply, "broker_malformed") ? "broker_malformed" : "refused");
}

static volatile LONG squat_stop;

static DWORD WINAPI squat_traffic(void *unused)
{
    /* Each request makes the broker finish with one client and wait for the next. */
    static const char request[] = "{}";
    char reply[512];
    unsigned i;
    (void)unused;
    for (i = 0; i < 30 && !squat_stop; ++i) broker(request, sizeof(request) - 1, reply, sizeof(reply));
    return 0;
}

/* The broker's pipe name must never be free for another process to serve: a process that owns
   it would receive the requests of the broker's clients and could impersonate them. */
static void broker_pipe_squat(void)
{
    HANDLE thread, pipe = INVALID_HANDLE_VALUE;
    DWORD start, tries = 0, error = 0, id;
    squat_stop = 0;
    /* With the service stopped the name is free by nature; that case is the client's to detect. */
    if (service_state(L"XP25Broker") != SERVICE_RUNNING) { report("broker_pipe_name_cannot_be_taken", 3, 0, "the XP25 broker service is not running"); return; }
    thread = CreateThread(NULL, 0, squat_traffic, NULL, 0, &id);
    start = GetTickCount();
    while (GetTickCount() - start < 6000 && pipe == INVALID_HANDLE_VALUE) {
        /* Unlimited instances, so that a success does not make the broker's own next instance fail. */
        pipe = CreateNamedPipeW(BROKER_PIPE, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                                PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, NULL);
        error = GetLastError();
        ++tries;
    }
    squat_stop = 1;
    if (pipe != INVALID_HANDLE_VALUE) CloseHandle(pipe);
    if (thread) { WaitForSingleObject(thread, 120000); CloseHandle(thread); }
    report("broker_pipe_name_cannot_be_taken", hardened ? pipe == INVALID_HANDLE_VALUE : 2, pipe == INVALID_HANDLE_VALUE ? error : tries,
           pipe == INVALID_HANDLE_VALUE ? "every attempt to create the pipe was refused (last error is in the error field)" :
           "another process created the broker's pipe (attempt number is in the error field)");
    Sleep(500);
    report("broker_still_running_after_pipe_attempts", service_state(L"XP25Broker") == SERVICE_RUNNING, service_state(L"XP25Broker"), "");
}

static void broker_cases(void)
{
    static char big[9001];
    unsigned i;
    broker_must_refuse("broker_refuses_to_stop_security_center", "{\"v\":1,\"op\":\"service_control\",\"name\":\"wscsvc\",\"action\":\"stop\"}", L"wscsvc", 0);
    broker_must_refuse("broker_refuses_to_stop_event_log", "{\"v\":1,\"op\":\"service_control\",\"name\":\"Eventlog\",\"action\":\"stop\"}", L"Eventlog", SERVICE_RUNNING);
    broker_must_refuse("broker_refuses_to_stop_itself", "{\"v\":1,\"op\":\"service_control\",\"name\":\"XP25Broker\",\"action\":\"stop\"}", L"XP25Broker", SERVICE_RUNNING);
    /* Name resolution for every user: not a desktop repair an unprivileged caller may order. */
    broker_must_refuse("broker_refuses_to_stop_dns_client", "{\"v\":1,\"op\":\"service_control\",\"name\":\"Dnscache\",\"action\":\"stop\"}", L"Dnscache", SERVICE_RUNNING);
    broker_must_refuse("broker_refuses_to_stop_task_scheduler", "{\"v\":1,\"op\":\"service_control\",\"name\":\"Schedule\",\"action\":\"stop\"}", L"Schedule", 0);
    broker_must_refuse("broker_refuses_to_start_disabled_remote_registry", "{\"v\":1,\"op\":\"service_control\",\"name\":\"RemoteRegistry\",\"action\":\"start\"}", L"RemoteRegistry", SERVICE_STOPPED);
    broker_must_refuse("broker_refuses_other_operations", "{\"v\":1,\"op\":\"cmd_execute\",\"command\":\"cmd.exe /c echo x\"}", NULL, 0);
    broker_must_refuse("broker_refuses_path_as_service_name", "{\"v\":1,\"op\":\"service_control\",\"name\":\"..\\\\..\\\\SharedAccess\",\"action\":\"stop\"}", L"SharedAccess", SERVICE_RUNNING);
    broker_must_refuse("broker_refuses_malformed_request", "service_control SharedAccess stop", L"SharedAccess", SERVICE_RUNNING);
    for (i = 0; i < sizeof(big) - 1; ++i) big[i] = ' ';
    {
        static const char head[] = "{\"v\":1,\"op\":\"service_control\",\"name\":\"SharedAccess\",\"action\":\"stop\",\"pad\":\"";
        CopyMemory(big, head, sizeof(head) - 1);
    }
    big[sizeof(big) - 3] = '"'; big[sizeof(big) - 2] = '}'; big[sizeof(big) - 1] = 0;
    {
        char reply[2048];
        BOOL answered = broker(big, sizeof(big) - 1, reply, sizeof(reply));
        DWORD error = GetLastError();
        Sleep(2000);
        if (!answered && error != ERROR_PIPE_NOT_CONNECTED && error != ERROR_BROKEN_PIPE && error != ERROR_MORE_DATA && error != ERROR_NO_DATA)
            report("broker_refuses_oversized_request", 3, error, "the XP25 broker did not answer");
        else report("broker_refuses_oversized_request", !strstr(reply, "\"ok\":true") && service_state(L"SharedAccess") == SERVICE_RUNNING,
                    answered ? 0 : error, answered ? "refused" : "the connection was dropped");
    }
}

static void firewall_cases(void)
{
    static const WCHAR *const names[] = {L"SharedAccess", L"SharedAccess", L"SharedAccess", L"SharedAccess", L"SharedAccess", L"IPNAT", L"IPNAT"};
    static const DWORD rights[] = {SERVICE_PAUSE_CONTINUE, WRITE_DAC, WRITE_OWNER, DELETE, SERVICE_ALL_ACCESS, SERVICE_STOP, SERVICE_CHANGE_CONFIG};
    static const char *const cases[] = {"pause_firewall_service", "change_firewall_service_acl", "take_firewall_service_ownership",
                                        "delete_firewall_service", "open_firewall_service_fully", "stop_firewall_driver", "reconfigure_firewall_driver"};
    static const WCHAR *const keys[] = {L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess", L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters",
                                        FIREWALL_POLICY L"StandardProfile\\GloballyOpenPorts\\List",
                                        FIREWALL_POLICY L"StandardProfile\\AuthorizedApplications\\List", FIREWALL_POLICY L"DomainProfile",
                                        L"SYSTEM\\CurrentControlSet\\Services\\IPNAT", L"SOFTWARE\\Policies\\Microsoft\\WindowsFirewall"};
    static const char *const key_cases[] = {"write_firewall_service_key", "write_firewall_parameters", "write_firewall_open_ports",
                                            "write_firewall_authorized_applications", "write_firewall_domain_profile",
                                            "write_firewall_driver_key", "write_firewall_group_policy"};
    WCHAR command[300];
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT), service;
    HANDLE device;
    HKEY key;
    DWORD error, enabled = 0, code, type, size;
    unsigned i;
    for (i = 0; scm && i < 7; ++i) {
        service = OpenServiceW(scm, names[i], rights[i]);
        error = GetLastError();
        if (service) CloseServiceHandle(service);
        if (!service && error == ERROR_SERVICE_DOES_NOT_EXIST) report(cases[i], 3, error, "the service is not installed");
        else denied(cases[i], service != NULL, error);
    }
    if (scm) CloseServiceHandle(scm);
    for (i = 0; i < 7; ++i) key_write_denied(key_cases[i], keys[i]);
    /* The firewall driver's control device: configuration requests need write access to it. */
    device = CreateFileW(L"\\\\.\\IPNAT", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    error = GetLastError();
    if (device != INVALID_HANDLE_VALUE) CloseHandle(device);
    if (device == INVALID_HANDLE_VALUE && (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)) report("open_firewall_driver_device_for_write", 3, error, "no such device name");
    else denied("open_firewall_driver_device_for_write", device != INVALID_HANDLE_VALUE, error);
    /* The supported management path (netsh, the firewall's own interface). Decided by the policy
       and the service afterwards, not by what netsh prints. */
    lstrcpyW(command, L"netsh.exe firewall set opmode mode=DISABLE");
    code = run(command, 120000);
    Sleep(1500);
    machine_dword(FIREWALL_POLICY L"StandardProfile", L"EnableFirewall", &enabled);
    report("netsh_cannot_disable_firewall", enabled == 1 && service_state(L"SharedAccess") == SERVICE_RUNNING, code, "netsh exit code is in the error field");
    lstrcpyW(command, L"netsh.exe firewall add portopening protocol=TCP port=5025 name=XP25FwUnprivileged");
    code = run(command, 120000);
    Sleep(1500);
    error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, FIREWALL_POLICY L"StandardProfile\\GloballyOpenPorts\\List", 0, KEY_QUERY_VALUE, &key);
    size = 0;
    if (!error) { error = RegQueryValueExW(key, L"5025:TCP", NULL, &type, NULL, &size); RegCloseKey(key); }
    report("netsh_cannot_open_firewall_port", error != ERROR_SUCCESS, code, "netsh exit code is in the error field");
    lstrcpyW(command, L"net.exe stop SharedAccess");
    code = run(command, 120000);
    report("net_stop_cannot_stop_firewall", service_state(L"SharedAccess") == SERVICE_RUNNING, code, "net.exe exit code is in the error field");
}

/* Locations from which code is started for other accounts or for the system. */
static void persistence_cases(void)
{
    static const WCHAR *const keys[] = {
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices", L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify", L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks", L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SharedTaskScheduler",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad", L"SOFTWARE\\Microsoft\\Active Setup\\Installed Components",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug", L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32",
        L"SOFTWARE\\Microsoft\\Command Processor", L"SOFTWARE\\Classes\\exefile\\shell\\open\\command", L"SOFTWARE\\Classes\\CLSID",
        L"SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors", L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders",
        L"SYSTEM\\CurrentControlSet\\Control\\NetworkProvider\\Order", L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs",
        L"SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters", L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"};
    static const char *const key_cases[] = {
        "write_hklm_runonce", "write_hklm_runonceex", "write_hklm_runservices", "write_explorer_policy_run", "write_winlogon_notify",
        "write_browser_helper_objects", "write_shell_execute_hooks", "write_shared_task_scheduler", "write_shell_service_objects",
        "write_active_setup", "write_aedebug", "write_drivers32", "write_command_processor_autorun", "write_exefile_open_command",
        "write_machine_clsid", "write_print_monitors", "write_security_providers", "write_network_provider_order", "write_known_dlls",
        "write_winsock_catalog", "write_tcpip_parameters"};
    static const WCHAR *const system_files[] = {L"win.ini", L"system.ini", L"explorer.exe", L"system32\\userinit.exe", L"system32\\msgina.dll",
                                                L"system32\\autoexec.nt", L"system32\\config.nt", L"system32\\drivers\\ipnat.sys",
                                                L"system32\\ipnathlp.dll", L"system32\\hnetcfg.dll", L"system32\\svchost.exe", L"system32\\config\\system"};
    static const char *const file_cases[] = {"open_win_ini_for_write", "open_system_ini_for_write", "open_explorer_for_write", "open_userinit_for_write",
                                             "open_msgina_for_write", "open_autoexec_nt_for_write", "open_config_nt_for_write",
                                             "open_firewall_driver_for_write", "open_firewall_service_dll_for_write", "open_firewall_config_dll_for_write",
                                             "open_svchost_for_write", "open_system_hive_for_write"};
    static const WCHAR *const system_dirs[] = {L"system32\\wbem\\mof", L"system32\\spool\\drivers", L"inf", L"system32\\GroupPolicy", L"Tasks", L"system32\\config"};
    static const char *const dir_cases[] = {"create_file_in_wmi_mof_directory", "create_file_in_printer_drivers", "create_file_in_inf",
                                            "create_file_in_group_policy", "create_scheduled_task_file", "create_file_in_registry_hive_directory"};
    WCHAR windows[MAX_PATH], path[MAX_PATH * 2], folder[MAX_PATH];
    unsigned i;
    GetWindowsDirectoryW(windows, MAX_PATH);
    for (i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) key_write_denied(key_cases[i], keys[i]);
    for (i = 0; i < sizeof(system_files) / sizeof(system_files[0]); ++i) {
        wsprintfW(path, L"%s\\%s", windows, system_files[i]);
        file_write_denied(file_cases[i], path);
    }
    for (i = 0; i < sizeof(system_dirs) / sizeof(system_dirs[0]); ++i) {
        wsprintfW(path, L"%s\\%s", windows, system_dirs[i]);
        if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) {
            /* A missing directory must not be creatable either. */
            BOOL made = CreateDirectoryW(path, NULL);
            DWORD error = GetLastError();
            if (made) RemoveDirectoryW(path);
            denied(dir_cases[i], made, error);
            continue;
        }
        wsprintfW(path, L"%s\\%s\\xp25-probe-%lu.tmp", windows, system_dirs[i], GetCurrentProcessId());
        file_create_denied(dir_cases[i], path);
    }
    wsprintfW(path, L"%c:\\boot.ini", windows[0]);
    file_write_denied("open_boot_ini_for_write", path);
    wsprintfW(path, L"%c:\\ntldr", windows[0]);
    file_write_denied("open_ntldr_for_write", path);
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_COMMON_STARTUP, NULL, 0, folder))) {
        wsprintfW(path, L"%s\\xp25-probe-%lu.cmd", folder, GetCurrentProcessId());
        file_create_denied("create_file_in_all_users_startup", path);
    } else report("create_file_in_all_users_startup", 3, 0, "no common Startup folder");
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_COMMON_PROGRAMS, NULL, 0, folder))) {
        wsprintfW(path, L"%s\\xp25-probe-%lu.lnk", folder, GetCurrentProcessId());
        file_create_denied("create_file_in_all_users_start_menu", path);
    }
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_COMMON_DESKTOPDIRECTORY, NULL, 0, folder))) {
        wsprintfW(path, L"%s\\xp25-probe-%lu.lnk", folder, GetCurrentProcessId());
        file_create_denied("create_file_on_all_users_desktop", path);
    }
    /* A system program under Program Files (it was iexplore.exe, which XP25 images
       without IE no longer have). */
    wsprintfW(path, L"%c:\\Program Files\\Windows NT\\Accessories\\wordpad.exe", windows[0]);
    file_write_denied("open_program_files_program_for_write", path);
    wsprintfW(path, L"%c:\\Program Files\\Common Files\\xp25-probe-%lu.tmp", windows[0], GetCurrentProcessId());
    file_create_denied("create_file_in_common_files", path);
    /* The broker's audit trail and whatever else XP25 keeps for all users. */
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, 0, folder))) {
        wsprintfW(path, L"%s\\XP25\\broker-audit.jsonl", folder);
        file_write_denied("open_broker_audit_trail_for_write", path);
    }
    wsprintfW(path, L"%s\\XP25\\Broker\\broker-audit.jsonl", windows);
    file_write_denied("open_protected_broker_audit_trail_for_write", path);
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
        SERVICE_STATUS state;
        BOOL answered = broker(request, sizeof(request) - 1, reply, sizeof(reply));
        error = GetLastError();
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
            if (hardened) report("broker_refuses_to_stop_firewall", state.dwCurrentState == SERVICE_RUNNING && !strstr(reply, "\"ok\":true"),
                                 state.dwCurrentState, state.dwCurrentState == SERVICE_RUNNING ? "firewall still running" : "the firewall was stopped");
            else report("broker_refuses_to_stop_firewall", 2, state.dwCurrentState,
                        state.dwCurrentState == SERVICE_RUNNING ? "firewall still running" : "the firewall was stopped by the broker");
        }
    }
    firewall_cases();
    persistence_cases();
    broker_cases();
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
    /* What the broker is for: an ordinary interactive user may have a desktop service restarted. */
    {
        static const char request[] = "{\"v\":1,\"op\":\"service_control\",\"name\":\"Spooler\",\"action\":\"restart\"}";
        char reply[2048];
        BOOL answered = broker(request, sizeof(request) - 1, reply, sizeof(reply));
        DWORD failure = GetLastError();
        if (!answered) report("broker_restarts_print_spooler_for_ordinary_user", 3, failure, "the XP25 broker did not answer");
        else if (strstr(reply, "broker_busy")) report("broker_restarts_print_spooler_for_ordinary_user", 3, 0, "the broker's request limit was reached");
        else report("broker_restarts_print_spooler_for_ordinary_user", strstr(reply, "\"ok\":true") != NULL && service_state(L"Spooler") == SERVICE_RUNNING,
                    service_state(L"Spooler"), strstr(reply, "\"ok\":true") ? "performed" : "refused");
    }
    broker_pipe_squat();
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
    /* A contained process (administrators group deny-only, as the XP25 browser runs) must not be
       able to have the SYSTEM broker act for it at all, not even on a service an ordinary user may restart. */
    broker_must_refuse("broker_refuses_contained_process", "{\"v\":1,\"op\":\"service_control\",\"name\":\"Spooler\",\"action\":\"restart\"}", L"Spooler", 0);
    broker_pipe_squat();
    cve_unprivileged_cases();
}

/* ---- Milestone 8.2: verify the MS04-011 fix in the installed lsasrv.dll ------------
   LSASS serves the DsRole interface to local callers through netapi32's public client.
   The fix adds an administrator access check to the downlevel-upgrade request and bounds
   the DCPROMO.LOG line that records the caller's domain name. These checks confirm the
   request is refused for an unprivileged caller, that LSASS keeps serving the interface
   afterwards (the fix did not break it), and that the logged line stays within its
   buffer. The domain name is a harmless marker string; no promotion is attempted or
   possible on this computer. */
typedef DWORD (WINAPI *DSROLE_UPGRADE_FN)(LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR,
                                          LPCWSTR, LPCWSTR, ULONG, PVOID *);
typedef DWORD (WINAPI *DSROLE_INFO_FN)(LPCWSTR, int, PBYTE *);
typedef VOID (WINAPI *DSROLE_FREE_FN)(PVOID);

/* A downlevel-upgrade request with a `length`-character domain-name marker. */
static DWORD dsrole_upgrade_marker(DWORD length)
{
    static WCHAR name[3100];
    HMODULE netapi = LoadLibraryW(L"netapi32.dll");
    DSROLE_UPGRADE_FN upgrade = netapi ? (DSROLE_UPGRADE_FN)GetProcAddress(netapi, "DsRoleUpgradeDownlevelServer") : NULL;
    PVOID handle = NULL;
    DWORD i;
    if (!upgrade) return ERROR_PROC_NOT_FOUND;
    if (length > 3000) length = 3000;
    for (i = 0; i < length; ++i) name[i] = (WCHAR)(L'a' + i % 26);
    name[i] = 0;
    return upgrade(name, L"xp25-site", L"C:\\xp25-cve-none\\ntds", L"C:\\xp25-cve-none\\ntds", L"C:\\xp25-cve-none\\sysvol",
                   NULL, NULL, NULL, NULL, NULL, 0, &handle);
}

/* A harmless query of the computer's own role: non-zero error only if LSASS stopped answering. */
static BOOL lsa_answers(DWORD *error)
{
    HMODULE netapi = LoadLibraryW(L"netapi32.dll");
    DSROLE_INFO_FN info = netapi ? (DSROLE_INFO_FN)GetProcAddress(netapi, "DsRoleGetPrimaryDomainInformation") : NULL;
    DSROLE_FREE_FN release = netapi ? (DSROLE_FREE_FN)GetProcAddress(netapi, "DsRoleFreeMemory") : NULL;
    PBYTE buffer = NULL;
    *error = ERROR_PROC_NOT_FOUND;
    if (!info || !release) return FALSE;
    *error = info(NULL, 1 /* DsRolePrimaryDomainInfoBasic */, &buffer);
    if (buffer) release(buffer);
    return *error == ERROR_SUCCESS;
}

/* Length (characters) of the DCPROMO.LOG line holding `marker`, and whether CR LF ends it. */
static int dcpromo_line(const WCHAR *log, const WCHAR *marker, DWORD *length, BOOL *crlf)
{
    HANDLE h = CreateFileW(log, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    DWORD size, read = 0, i, start, end, n = (DWORD)lstrlenW(marker);
    WCHAR *text;
    int found = 0;
    if (h == INVALID_HANDLE_VALUE) return -1;
    size = GetFileSize(h, NULL);
    text = (size != INVALID_FILE_SIZE) ? (WCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size + 4) : NULL;
    if (text) ReadFile(h, text, size, &read, NULL);
    CloseHandle(h);
    if (!text) return -1;
    read /= sizeof(WCHAR);
    for (i = 0; i + n <= read && !found; ++i) {
        if (memcmp(text + i, marker, n * sizeof(WCHAR))) continue;
        for (start = i; start > 0 && text[start - 1] != L'\n'; --start) {}
        for (end = i; end < read && text[end] != L'\r' && text[end] != L'\n'; ++end) {}
        *length = end - start;
        *crlf = end + 1 < read && text[end] == L'\r' && text[end + 1] == L'\n';
        found = 1;
    }
    HeapFree(GetProcessHeap(), 0, text);
    return found;
}

/* The observable runtime facts, in every context: a hostile over-long DsRole domain name does
   not crash LSASS, the request is not granted, and if a DCPROMO.LOG line is produced it stays
   inside its buffer. On the XP workstation SKU the request returns ERROR_NOT_SUPPORTED before
   any logging, so no line is produced; the overflow and its fix are proven at the source and
   host level (tests/test_cve.py). */
static void dsrole_runtime_checks(const char *tag)
{
    WCHAR windows[MAX_PATH], log[MAX_PATH], debug[MAX_PATH];
    char note[320], name[80];
    DWORD rc, alive_error, length = 0;
    BOOL alive, crlf = FALSE, existed;
    int found;
    GetWindowsDirectoryW(windows, MAX_PATH);
    wsprintfW(debug, L"%s\\debug", windows);
    wsprintfW(log, L"%s\\debug\\DCPROMO.LOG", windows);
    existed = GetFileAttributesW(log) != INVALID_FILE_ATTRIBUTES;

    rc = dsrole_upgrade_marker(3000);
    alive = lsa_answers(&alive_error);
    wsprintfA(note, "DsRoleUpgradeDownlevelServer (3000-char name) returned %lu; LSA %s afterwards (%lu)",
              rc, alive ? "answered" : "did not answer", alive_error);
    wsprintfA(name, "ms04_011_dsrole_hostile_name_no_crash_%s", tag);
    report(name, alive && rc != ERROR_PROC_NOT_FOUND, rc, note);
    wsprintfA(name, "ms04_011_dsrole_upgrade_not_granted_%s", tag);
    report(name, rc != ERROR_SUCCESS, rc, note);

    /* If LSASS logged the name (it does not on this SKU), the line must be bounded; otherwise observe. */
    found = dcpromo_line(log, L"DsRolerDcAsDc: DnsDomainName  abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz", &length, &crlf);
    wsprintfA(name, "ms04_011_dsrole_log_line_bounded_%s", tag);
    if (found > 0)
        report(name, length < 1024 && crlf, length, "a DCPROMO.LOG line was produced");
    else
        report(name, 2, 0, "no DCPROMO.LOG line produced on this SKU (request returned before logging); overflow proven at source/host level");
    if (!existed && found > 0) MoveFileExW(log, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
}

static void cve_unprivileged_cases(void)
{
    if (!cve_checks) return;
    dsrole_runtime_checks(!lstrcmpA(context, "restricted_token") ? "restricted" : "ordinary");
}

static void cve_admin_cases(void)
{
    WCHAR windows[MAX_PATH], debug[MAX_PATH];
    if (!cve_checks) return;
    GetWindowsDirectoryW(windows, MAX_PATH);
    wsprintfW(debug, L"%s\\debug", windows);
    report("ms04_011_dsrole_log_directory_present", GetFileAttributesW(debug) != INVALID_FILE_ATTRIBUTES ? 2 : 2, 0,
           "the overflow is reached only when LSASS can open %windir%\\debug\\DCPROMO.LOG");
    dsrole_runtime_checks("admin");
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
    if (cve_checks) lstrcatW(command, L" --cve");
}

/* Whatever an unprivileged case managed to stop is started again, so that everything measured
   afterwards sees the system as it normally runs. A restart here is itself a finding of the run. */
static void restore_services(const char *after)
{
    static const WCHAR *const names[] = {L"SharedAccess", L"Dnscache", L"Spooler", L"XP25Broker", L"Schedule"};
    static const char *const labels[] = {"firewall_restarted_after_unprivileged_cases", "dns_client_restarted_after_unprivileged_cases",
                                         "print_spooler_restarted_after_unprivileged_cases", "xp25_broker_restarted_after_unprivileged_cases",
                                         "task_scheduler_restarted_after_unprivileged_cases"};
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT), service;
    SERVICE_STATUS state;
    BYTE buffer[4096];
    QUERY_SERVICE_CONFIGW *config = (QUERY_SERVICE_CONFIGW *)buffer;
    DWORD needed, waited;
    unsigned i;
    for (i = 0; scm && i < 5; ++i) {
        service = OpenServiceW(scm, names[i], SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | SERVICE_START);
        if (!service) continue;
        ZeroMemory(&state, sizeof(state));
        if (QueryServiceStatus(service, &state) && state.dwCurrentState == SERVICE_STOPPED &&
            QueryServiceConfigW(service, config, sizeof(buffer), &needed) && config->dwStartType == SERVICE_AUTO_START) {
            BOOL ok = StartServiceW(service, 0, NULL);
            DWORD error = ok ? 0 : GetLastError();
            for (waited = 0; ok && waited < 30000 && QueryServiceStatus(service, &state) && state.dwCurrentState != SERVICE_RUNNING; waited += 500) Sleep(500);
            report(labels[i], ok && state.dwCurrentState == SERVICE_RUNNING ? 2 : 0, error, after);
        }
        CloseServiceHandle(service);
    }
    if (scm) CloseServiceHandle(scm);
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
    cve_admin_cases();
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
            restore_services("stopped during the ordinary-account cases");
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
            Sleep(61000);               /* the broker limits requests per minute; the next context starts with a fresh allowance */
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
                restore_services("stopped during the restricted-token cases");
            }
            CloseHandle(job);
            CloseHandle(restricted);
        }
        FreeSid(deny[0].Sid);
        CloseHandle(token);
    } else report("create_restricted_token", 0, GetLastError(), "");

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

/* ---- programs and games ------------------------------------------------------------- */
typedef struct { DWORD pid; HWND found; } WINDOW_OF;

static BOOL CALLBACK window_of_process(HWND window, LPARAM parameter)
{
    WINDOW_OF *w = (WINDOW_OF *)parameter;
    DWORD pid = 0;
    GetWindowThreadProcessId(window, &pid);
    if (pid == w->pid && IsWindowVisible(window) && !GetWindow(window, GW_OWNER)) { w->found = window; return FALSE; }
    return TRUE;
}

/* Console programs have no window of their own on NT 5.1: CSRSS owns the console window. Their
   cases set the console title and are found by it. */
static const WCHAR *console_title;

/* The process and every process it started (a launcher such as Windows Media Player's may hand over
   to a first-run program and end). */
static BOOL in_family(DWORD pid, DWORD root)
{
    HANDLE snap;
    PROCESSENTRY32W entry;
    DWORD parent[512], id[512], count = 0, i, guard;
    if (pid == root) return TRUE;
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return FALSE;
    ZeroMemory(&entry, sizeof(entry));
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snap, &entry)) do {
        if (count < 512) { id[count] = entry.th32ProcessID; parent[count] = entry.th32ParentProcessID; ++count; }
    } while (Process32NextW(snap, &entry));
    CloseHandle(snap);
    for (guard = 0; guard < 8 && pid && pid != root; ++guard) {
        for (i = 0; i < count && id[i] != pid; ++i) {}
        pid = i < count ? parent[i] : 0;
    }
    return pid == root;
}

static HWND process_window(DWORD pid, DWORD ms)
{
    WINDOW_OF w;
    DWORD start = GetTickCount();
    w.pid = pid;
    do {
        w.found = NULL;
        if (console_title) w.found = FindWindowW(L"ConsoleWindowClass", console_title);
        else EnumWindows(window_of_process, (LPARAM)&w);
        if (w.found) return w.found;
        Sleep(250);
    } while (GetTickCount() - start < ms);
    return NULL;
}

typedef struct { DWORD root; HWND found; DWORD pid; } FAMILY_WINDOW;

static BOOL CALLBACK window_of_family(HWND window, LPARAM parameter)
{
    FAMILY_WINDOW *w = (FAMILY_WINDOW *)parameter;
    DWORD pid = 0;
    GetWindowThreadProcessId(window, &pid);
    if (pid != w->root && IsWindowVisible(window) && !GetWindow(window, GW_OWNER) && in_family(pid, w->root)) {
        w->found = window;
        w->pid = pid;
        return FALSE;
    }
    return TRUE;
}

/* A visible window of Windows Error Reporting (dwwin.exe) or Dr. Watson: a program has crashed. */
static BOOL CALLBACK error_report_finder(HWND window, LPARAM parameter)
{
    DWORD pid = 0;
    HANDLE snap;
    PROCESSENTRY32W entry;
    if (!IsWindowVisible(window)) return TRUE;
    GetWindowThreadProcessId(window, &pid);
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return TRUE;
    ZeroMemory(&entry, sizeof(entry));
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snap, &entry)) do {
        if (entry.th32ProcessID == pid && (!lstrcmpiW(entry.szExeFile, L"dwwin.exe") || !lstrcmpiW(entry.szExeFile, L"drwtsn32.exe"))) {
            *(HWND *)parameter = window;
            CloseHandle(snap);
            return FALSE;
        }
    } while (Process32NextW(snap, &entry));
    CloseHandle(snap);
    return TRUE;
}

static BOOL error_report_window(HWND *found)
{
    *found = NULL;
    EnumWindows(error_report_finder, (LPARAM)found);
    return *found != NULL;
}

/* Starts a program, waits for its own top-level window, checks it answers and stays up, then
   closes it the way a user does (WM_CLOSE). A program that asks a question on close (Paint's
   "save changes?") is ended after the answer was not given; that is reported, not failed. */
static void program_case(const char *name, const WCHAR *command_line, const WCHAR *directory)
{
    STARTUPINFOW start;
    PROCESS_INFORMATION process;
    WCHAR line[MAX_PATH * 2];
    HWND window;
    DWORD_PTR r;
    WCHAR title[120];
    char note[300];
    BOOL responsive, alive, closed, crashed;
    HWND report_window = NULL;
    DWORD started = GetTickCount(), ms;
    ZeroMemory(&start, sizeof(start));
    start.cb = sizeof(start);
    lstrcpynW(line, command_line, MAX_PATH * 2);
    /* A console of its own: a console program must never share (and on close, end) the console of the
       script that runs this probe. */
    if (!CreateProcessW(NULL, line, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, directory, &start, &process)) {
        report(name, 0, GetLastError(), "the program could not be started");
        return;
    }
    WaitForInputIdle(process.hProcess, 60000 * scale);
    window = process_window(process.dwProcessId, 60000 * scale);
    if (!window && !console_title) {
        /* No window of its own: a window of a program it started counts, and is named in the note. */
        FAMILY_WINDOW family;
        family.root = process.dwProcessId;
        family.found = NULL;
        EnumWindows(window_of_family, (LPARAM)&family);
        if (family.found) {
            HANDLE child = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE, FALSE, family.pid);
            window = family.found;
            if (child) { CloseHandle(process.hProcess); process.hProcess = child; process.dwProcessId = family.pid; }
        }
    }
    ms = GetTickCount() - started;
    title[0] = 0;
    if (window) GetWindowTextW(window, title, 120);
    responsive = window && SendMessageTimeoutW(window, WM_NULL, 0, 0, SMTO_ABORTIFHUNG, 5000 * scale, &r);
    Sleep(3000);
    alive = WaitForSingleObject(process.hProcess, 0) == WAIT_TIMEOUT;
    if (window) PostMessageW(window, WM_CLOSE, 0, 0);
    closed = WaitForSingleObject(process.hProcess, 20000 * scale) == WAIT_OBJECT_0;
    crashed = error_report_window(&report_window);
    if (crashed) {
        /* Windows Error Reporting holds the crashed program: "Don't Send", then it ends. */
        PostMessageW(report_window, WM_COMMAND, IDCANCEL, 0);
        Sleep(2000);
        if (IsWindow(report_window)) PostMessageW(report_window, WM_CLOSE, 0, 0);
        WaitForSingleObject(process.hProcess, 10000);
    }
    if (!closed) { TerminateProcess(process.hProcess, 0xC25); WaitForSingleObject(process.hProcess, 10000); }
    wsprintfA(note, "window '%.80S' (process %lu) after %lu ms, responsive %d, still running after 3 s %d, %s", title, process.dwProcessId, ms,
              responsive, alive, crashed ? "CRASHED when closed (Windows Error Reporting appeared)" :
              closed ? "closed by WM_CLOSE" : "did not close on WM_CLOSE (a question was left unanswered); ended");
    report(name, window != NULL && responsive && alive, window ? 0 : WAIT_TIMEOUT, note);
    if (crashed) {
        char case_name[100];
        wsprintfA(case_name, "%s_closes_without_crashing", name);
        report(case_name, 0, 0, note);
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
}

static void app_cases(void)
{
    static const struct { const char *name; const WCHAR *exe; } apps[] = {
        {"game_solitaire", L"sol.exe"}, {"game_freecell", L"freecell.exe"}, {"game_spider_solitaire", L"spider.exe"},
        {"game_minesweeper", L"winmine.exe"}, {"game_hearts", L"mshearts.exe"},
        {"game_pinball", L"%P%\\Windows NT\\Pinball\\PINBALL.EXE"},
        {"program_notepad", L"notepad.exe"}, {"program_calculator", L"calc.exe"}, {"program_paint", L"mspaint.exe"},
        {"program_wordpad", L"%P%\\Windows NT\\Accessories\\wordpad.exe"}, {"program_character_map", L"charmap.exe"},
        {"program_command_prompt", L"cmd.exe /k title XP25 command prompt"}, {"program_sound_recorder", L"sndrec32.exe"},
        {"program_windows_media_player", L"%P%\\Windows Media Player\\wmplayer.exe"}};
    WCHAR programs[MAX_PATH], line[MAX_PATH * 2], windows[MAX_PATH], system[MAX_PATH];
    unsigned i;
    if (!SHGetSpecialFolderPathW(NULL, programs, CSIDL_PROGRAM_FILES, FALSE)) lstrcpyW(programs, L"C:\\Program Files");
    GetWindowsDirectoryW(windows, MAX_PATH);
    GetSystemDirectoryW(system, MAX_PATH);
    for (i = 0; i < sizeof(apps) / sizeof(apps[0]); ++i) {
        if (!wcsncmp(apps[i].exe, L"%P%", 3)) wsprintfW(line, L"\"%s%s\"", programs, apps[i].exe + 3);
        else wsprintfW(line, L"%s\\%s", system, apps[i].exe);
        console_title = !wcsncmp(apps[i].exe, L"cmd.exe", 7) ? L"XP25 command prompt" : NULL;
        program_case(apps[i].name, line, windows);
        console_title = NULL;
    }
}

typedef struct { HWND owner, found; } OWNED_BY;

static BOOL CALLBACK owned_window(HWND window, LPARAM parameter)
{
    OWNED_BY *o = (OWNED_BY *)parameter;
    if (GetWindow(window, GW_OWNER) == o->owner && IsWindowVisible(window)) { o->found = window; return FALSE; }
    return TRUE;
}

/* ---- a standard user's own desktop session --------------------------------------------- */
static HWND std_clippy;

static BOOL clippy_said(const WCHAR *needle, DWORD ms)
{
    static WCHAR text[60000];
    HWND chat;
    DWORD start = GetTickCount();
    DWORD_PTR got;
    do {
        chat = std_clippy ? FindWindowExW(std_clippy, NULL, L"XP25ChatView", NULL) : NULL;
        text[0] = 0;
        if (chat && SendMessageTimeoutW(chat, WM_GETTEXT, 60000, (LPARAM)text, SMTO_ABORTIFHUNG, 5000, &got) && wcsstr(text, needle)) return TRUE;
        Sleep(500);
    } while (GetTickCount() - start < ms);
    return FALSE;
}

static void clippy_ask(const WCHAR *question)
{
    DWORD_PTR r;
    SendMessageTimeoutW(GetDlgItem(std_clippy, 1002), WM_SETTEXT, 0, (LPARAM)question, SMTO_ABORTIFHUNG, 5000, &r);
    PostMessageW(std_clippy, WM_COMMAND, 1003, 0);
}

static BOOL file_text(const WCHAR *path, const char *text)
{
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD done;
    BOOL ok;
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    ok = WriteFile(h, text, (DWORD)lstrlenA(text), &done, NULL);
    CloseHandle(h);
    return ok;
}

static BOOL file_contains(const WCHAR *path, const char *needle)
{
    static char data[65536];
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    DWORD got = 0;
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    ReadFile(h, data, sizeof(data) - 1, &got, NULL);
    CloseHandle(h);
    data[got] = 0;
    return strstr(data, needle) != NULL;
}

static void desktop_cases(void)
{
    WCHAR profile[MAX_PATH], documents[MAX_PATH], temp[MAX_PATH], programs[MAX_PATH], path[MAX_PATH * 2], other[MAX_PATH * 2], line[MAX_PATH * 3];
    WCHAR env[MAX_PATH], name[64];
    HANDLE token = NULL;
    HDESK desktop;
    HWND tray, window;
    DWORD pid = 0, size, code, now = GetTickCount();
    BYTE mine[128], theirs[128];
    HKEY key;
    LONG error;
    BOOL ok;
    SC_HANDLE scm;
    char note[300];
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    PSID power = NULL;
    BOOL power_member = FALSE;
    /* Who and where. */
    if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_POWER_USERS, 0, 0, 0, 0, 0, 0, &power)) {
        CheckTokenMembership(NULL, power, &power_member);
        FreeSid(power);
    }
    report("standard_user_is_not_administrator_or_power_user", !is_admin() && !power_member, 0, "");
    SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, profile);
    SHGetFolderPathW(NULL, CSIDL_PERSONAL, NULL, 0, documents);
    GetTempPathW(MAX_PATH, temp);
    if (!SHGetSpecialFolderPathW(NULL, programs, CSIDL_PROGRAM_FILES, FALSE)) lstrcpyW(programs, L"C:\\Program Files");
    GetEnvironmentVariableW(L"USERPROFILE", env, MAX_PATH);
    size = 64;
    GetUserNameW(name, &size);
    wsprintfA(note, "%.120S", profile);
    report("profile_loaded_for_this_user", !lstrcmpiW(env, profile) && wcsstr(profile, name) != NULL &&
           GetFileAttributesW(documents) != INVALID_FILE_ATTRIBUTES, 0, note);
    error = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\XP25\\StandardUserTest", 0, NULL, REG_OPTION_VOLATILE, KEY_SET_VALUE, NULL, &key, NULL);
    if (!error) { RegCloseKey(key); RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\XP25\\StandardUserTest"); }
    report("own_registry_hive_writable", error == ERROR_SUCCESS, (DWORD)error, "");
    desktop = GetThreadDesktop(GetCurrentThreadId());
    size = 0;
    ok = desktop && GetUserObjectInformationW(desktop, UOI_NAME, path, sizeof(path), &size) && !lstrcmpiW(path, L"Default");
    report("runs_on_the_default_desktop", ok, 0, "");
    /* The shell belongs to this user. */
    tray = FindWindowW(L"Shell_TrayWnd", NULL);
    if (tray) GetWindowThreadProcessId(tray, &pid);
    ok = FALSE;
    if (pid && OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        HANDLE shell = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid), shell_token = NULL;
        DWORD got;
        if (shell && OpenProcessToken(shell, TOKEN_QUERY, &shell_token) && GetTokenInformation(token, TokenUser, mine, sizeof(mine), &got) &&
            GetTokenInformation(shell_token, TokenUser, theirs, sizeof(theirs), &got))
            ok = EqualSid(((TOKEN_USER *)mine)->User.Sid, ((TOKEN_USER *)theirs)->User.Sid);
        if (shell_token) CloseHandle(shell_token);
        if (shell) CloseHandle(shell);
        CloseHandle(token);
    }
    report("explorer_runs_as_this_user", ok, pid, "the shell's process id is in the error field");
    {
        /* Luna: the visual style service paints this session's windows. */
        HMODULE uxtheme = LoadLibraryW(L"uxtheme.dll");
        BOOL (WINAPI *themed)(void) = uxtheme ? (BOOL (WINAPI *)(void))GetProcAddress(uxtheme, "IsThemeActive") : NULL;
        report("visual_style_active", themed && themed(), 0, themed ? "" : "uxtheme.dll unavailable");
        if (uxtheme) FreeLibrary(uxtheme);
    }
    /* Files in the user's own profile. */
    wsprintfW(path, L"%s\\XP25 standard user test", documents);
    ok = CreateDirectoryW(path, NULL);
    wsprintfW(path, L"%s\\XP25 standard user test\\notes.txt", documents);
    ok = ok && file_text(path, "XP25 standard user file\r\n");
    wsprintfW(other, L"%s\\XP25 standard user test\\copy.txt", documents);
    ok = ok && CopyFileW(path, other, TRUE) && file_contains(other, "XP25 standard user file");
    wsprintfW(path, L"%s\\XP25 standard user test\\renamed.txt", documents);
    ok = ok && MoveFileW(other, path);
    ok = ok && DeleteFileW(path);
    wsprintfW(path, L"%s\\XP25 standard user test\\notes.txt", documents);
    ok = ok && DeleteFileW(path);
    wsprintfW(path, L"%s\\XP25 standard user test", documents);
    ok = ok && RemoveDirectoryW(path);
    report("file_operations_in_own_profile", ok, ok ? 0 : GetLastError(), "create, write, copy, rename, delete");
    wsprintfW(path, L"%s\\xp25-standard-user-%lu.tmp", programs, GetCurrentProcessId());
    file_create_denied("cannot_create_files_in_program_files", path);
    /* Programs. */
    GetSystemDirectoryW(other, MAX_PATH);
    wsprintfW(line, L"%s\\notepad.exe", other);
    program_case("program_notepad", line, profile);
    wsprintfW(line, L"%s\\calc.exe", other);
    program_case("program_calculator", line, profile);
    wsprintfW(line, L"%s\\sol.exe", other);
    program_case("game_solitaire", line, profile);
    /* The browser, as the user opens a page. */
    wsprintfW(path, L"%sxp25-standard-user.htm", temp);
    ok = file_text(path, "<html><head><title>XP25 standard user page</title></head><body>XP25 standard user page</body></html>\r\n");
    if (ok && (INT_PTR)ShellExecuteW(NULL, L"open", path, NULL, NULL, SW_SHOWNORMAL) > 32) {
        DWORD start = GetTickCount();
        window = NULL;
        while (!window && GetTickCount() - start < 90000 * scale) {
            window = FindWindowW(L"IEFrame", NULL);
            if (window) {
                GetWindowTextW(window, line, 200);
                if (!wcsstr(line, L"XP25 standard user page")) window = NULL;
            }
            if (!window) Sleep(500);
        }
        wsprintfA(note, "after %lu ms", GetTickCount() - start);
        report("browser_opens_local_page", window != NULL, 0, note);
        if (window) {
            HANDLE browser;
            WINDOW_OF other;
            BOOL frame_gone, exited;
            pid = 0;
            GetWindowThreadProcessId(window, &pid);
            browser = OpenProcess(SYNCHRONIZE, FALSE, pid);
            note[0] = 0;
            {
                /* Internet Explorer 8 opens its "Set Up Windows Internet Explorer 8" wizard on a user's first
                   start, modal to the frame, so the frame ignores WM_CLOSE until it is answered. Recorded,
                   then cancelled the way a user would. */
                OWNED_BY owned;
                DWORD start = GetTickCount();
                owned.owner = window;
                owned.found = NULL;
                while (!owned.found && GetTickCount() - start < 5000 * scale) {
                    EnumWindows(owned_window, (LPARAM)&owned);
                    if (!owned.found) Sleep(250);
                }
                if (owned.found) {
                    char first[200];
                    GetWindowTextW(owned.found, line, 120);
                    wsprintfA(first, "'%.80S' owned by the browser frame", line);
                    report("browser_first_run_dialog", 2, 0, first);
                    PostMessageW(owned.found, WM_COMMAND, IDCANCEL, 0);
                    Sleep(1000);
                    if (IsWindow(owned.found)) PostMessageW(owned.found, WM_CLOSE, 0, 0);
                    Sleep(2000);
                }
            }
            PostMessageW(window, WM_CLOSE, 0, 0);
            {
                /* With more than one tab open (the first-run page opens its own), Internet Explorer 8 asks
                   whether to close all tabs. Its default button closes them: answered as a user would. */
                DWORD start = GetTickCount();
                exited = FALSE;
                while (!exited && GetTickCount() - start < 30000 * scale) {
                    OWNED_BY owned;
                    owned.owner = window;
                    owned.found = NULL;
                    if (IsWindow(window)) EnumWindows(owned_window, (LPARAM)&owned);
                    if (owned.found) {
                        char asked[200];
                        GetWindowTextW(owned.found, line, 120);
                        wsprintfA(asked, "'%.80S' asked while closing; answered with its default button", line);
                        report("browser_close_question", 2, 0, asked);
                        SetForegroundWindow(owned.found);
                        Sleep(300);
                        keybd_event(VK_RETURN, 0, 0, 0);
                        keybd_event(VK_RETURN, 0, KEYEVENTF_KEYUP, 0);
                        Sleep(2000);
                    }
                    exited = browser && WaitForSingleObject(browser, 1000) == WAIT_OBJECT_0;
                }
            }
            frame_gone = !IsWindow(window);
            if (!exited) {
                /* Another top-level window keeps the process: Internet Explorer 8 shows its first-run
                   wizard once per user. It is named here and closed too. */
                other.pid = pid;
                other.found = NULL;
                EnumWindows(window_of_process, (LPARAM)&other);
                if (other.found) {
                    GetWindowTextW(other.found, line, 120);
                    wsprintfA(note, "the page window closed; the process stayed for its window '%.80S'", line);
                    PostMessageW(other.found, WM_CLOSE, 0, 0);
                    exited = browser && WaitForSingleObject(browser, 30000 * scale) == WAIT_OBJECT_0;
                }
            }
            report("browser_page_window_closes", frame_gone, 0, "");
            report("browser_process_ends", exited, 0, note);
            if (browser) CloseHandle(browser);
        }
    } else report("browser_opens_local_page", 0, GetLastError(), "the page could not be opened");
    DeleteFileW(path);
    /* ClippyAI. */
    wsprintfW(line, L"\"%s\\XP25\\ClippyAI.exe\"", programs);
    {
        STARTUPINFOW start;
        PROCESS_INFORMATION process;
        ZeroMemory(&start, sizeof(start));
        start.cb = sizeof(start);
        ok = CreateProcessW(NULL, line, NULL, NULL, FALSE, 0, NULL, profile, &start, &process);
        if (ok) { CloseHandle(process.hThread); CloseHandle(process.hProcess); }
    }
    std_clippy = NULL;
    for (code = 0; ok && !std_clippy && code < 120 * scale; ++code) {
        std_clippy = FindWindowW(L"XP25ClippyAI", L"ClippyAI");
        if (!std_clippy || !IsWindowVisible(std_clippy)) { std_clippy = NULL; Sleep(250); }
    }
    report("clippyai_starts", std_clippy != NULL, ok ? 0 : GetLastError(), "");
    if (std_clippy) {
        HWND failure = FindWindowW(L"#32770", L"ClippyAI");
        report("clippyai_chat_ready_offline", clippy_said(L"I'm ClippyAI", 20000 * scale) && clippy_said(L"Offline assistant", 5000), 0, "");
        report("clippyai_no_error_message", !failure || !IsWindowVisible(failure), 0, "");
        clippy_ask(L"Show recent errors in Event Viewer");
        report("clippyai_reads_event_log_as_standard_user", clippy_said(L"eventlog_read: completed", 90000 * scale), 0, "");
        Sleep(2000);
        clippy_ask(L"run ipconfig /all");
        report("clippyai_runs_read_only_command_as_standard_user", clippy_said(L"Windows IP Configuration", 90000 * scale), 0, "");
        {
            DWORD_PTR r;
            HANDLE process;
            pid = 0;
            GetWindowThreadProcessId(std_clippy, &pid);
            process = OpenProcess(SYNCHRONIZE, FALSE, pid);
            Sleep(2000);
            SendMessageTimeoutW(std_clippy, WM_COMMAND, 3003, 0, SMTO_NORMAL, 60000 * scale, &r);
            report("clippyai_exits", process && WaitForSingleObject(process, 60000 * scale) == WAIT_OBJECT_0, 0, "");
            if (process) CloseHandle(process);
        }
    }
    /* RoverAI: the user's own index and search. */
    wsprintfW(path, L"%s\\xp25-standard-user-fixture.txt", documents);
    file_text(path, "XP25 standard user RoverAI fixture\r\n");
    wsprintfW(other, L"%sxp25-std-index.json", temp);
    wsprintfW(line, L"\"%s\\XP25\\RoverAI.exe\" /index /out \"%s\"", programs, other);
    code = run(line, 900000 * scale);
    report("roverai_indexes_as_standard_user", code == 0 && file_contains(other, "\"ok\":true"), code, "exit code is in the error field");
    wsprintfW(other, L"%sxp25-std-search.json", temp);
    wsprintfW(line, L"\"%s\\XP25\\RoverAI.exe\" /search \"xp25-standard-user-fixture\" /limit 20 /out \"%s\"", programs, other);
    code = run(line, 240000 * scale);
    report("roverai_finds_own_file", code == 0 && file_contains(other, "xp25-standard-user-fixture.txt"), code, "exit code is in the error field");
    DeleteFileW(path);
    /* The broker serves this user for a desktop service and refuses what Windows would refuse. */
    {
        static const char restart[] = "{\"v\":1,\"op\":\"service_control\",\"name\":\"Spooler\",\"action\":\"restart\"}";
        char reply[2048];
        ok = broker(restart, sizeof(restart) - 1, reply, sizeof(reply));
        report("broker_restarts_print_spooler_for_standard_user", ok && strstr(reply, "\"ok\":true") && service_state(L"Spooler") == SERVICE_RUNNING,
               service_state(L"Spooler"), ok ? "" : "the XP25 broker did not answer");
    }
    broker_must_refuse("broker_refuses_dns_client_for_standard_user", "{\"v\":1,\"op\":\"service_control\",\"name\":\"Dnscache\",\"action\":\"stop\"}", L"Dnscache", SERVICE_RUNNING);
    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    report("standard_user_can_query_services", scm != NULL, scm ? 0 : GetLastError(), "");
    if (scm) CloseServiceHandle(scm);
    /* Shutting the computer down is a standard user's right on a workstation. */
    {
        HANDLE own;
        TOKEN_PRIVILEGES *privileges = (TOKEN_PRIVILEGES *)mine;
        LUID shutdown;
        DWORD got, i;
        BYTE buffer[1024];
        ok = FALSE;
        privileges = (TOKEN_PRIVILEGES *)buffer;
        if (LookupPrivilegeValueW(NULL, SE_SHUTDOWN_NAME, &shutdown) && OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &own)) {
            if (GetTokenInformation(own, TokenPrivileges, buffer, sizeof(buffer), &got))
                for (i = 0; i < privileges->PrivilegeCount; ++i)
                    if (privileges->Privileges[i].Luid.LowPart == shutdown.LowPart && privileges->Privileges[i].Luid.HighPart == shutdown.HighPart) ok = TRUE;
            CloseHandle(own);
        }
        report("standard_user_holds_shutdown_right", ok, 0, "");
    }
    wsprintfA(note, "%lu ms", GetTickCount() - now);
    report("desktop_session_checks_duration", 2, 0, note);
}

/* ---- firewall state as the guest sees it ------------------------------------------ */
static void firewall_check(void)
{
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT), service;
    BYTE buffer[8192];
    QUERY_SERVICE_CONFIGW *config = (QUERY_SERVICE_CONFIGW *)buffer;
    SERVICE_STATUS_PROCESS process;
    SERVICE_STATUS state;
    DWORD needed, value = 0, i;
    char note[420];
    if (!scm) { report("firewall_service_running", 0, GetLastError(), "cannot connect to the service control manager"); return; }
    service = OpenServiceW(scm, L"SharedAccess", SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | READ_CONTROL);
    if (!service) report("firewall_service_running", 0, GetLastError(), "the service cannot be opened");
    else {
        PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR)buffer;
        ZeroMemory(&process, sizeof(process));
        QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (BYTE *)&process, sizeof(process), &needed);
        wsprintfA(note, "state %lu, process %lu, exit code %lu", process.dwCurrentState, process.dwProcessId, process.dwWin32ExitCode);
        report("firewall_service_running", process.dwCurrentState == SERVICE_RUNNING && process.dwProcessId != 0, process.dwWin32ExitCode, note);
        if (QueryServiceConfigW(service, config, sizeof(buffer), &needed))
            report("firewall_service_starts_automatically", config->dwStartType == SERVICE_AUTO_START, config->dwStartType, "start type is in the error field");
        /* Who may stop, pause, reconfigure, re-secure or delete the firewall service. */
        if (QueryServiceObjectSecurity(service, DACL_SECURITY_INFORMATION, sd, sizeof(buffer), &needed)) {
            PACL dacl = NULL;
            BOOL present = FALSE, defaulted = FALSE, users = FALSE, power = FALSE;
            WCHAR *sddl = NULL;
            const DWORD control = SERVICE_STOP | SERVICE_PAUSE_CONTINUE | SERVICE_CHANGE_CONFIG | WRITE_DAC | WRITE_OWNER | DELETE;
            GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted);
            for (i = 0; present && dacl && i < dacl->AceCount; ++i) {
                ACCESS_ALLOWED_ACE *ace;
                PSID sid;
                if (!GetAce(dacl, i, (void **)&ace) || ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE || !(ace->Mask & control)) continue;
                sid = (PSID)&ace->SidStart;
                if (IsWellKnownSid(sid, WinLocalSystemSid) || IsWellKnownSid(sid, WinBuiltinAdministratorsSid)) continue;
                if (IsWellKnownSid(sid, WinBuiltinPowerUsersSid)) power = TRUE; else users = TRUE;
            }
            note[0] = 0;
            if (ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &sddl, NULL)) {
                wsprintfA(note, "%.400S", sddl);
                LocalFree(sddl);
            }
            report("firewall_service_acl_gives_users_no_control", present && dacl && !users, 0, note);
            report("firewall_service_acl_gives_power_users_no_control", hardened ? !power : 2, 0, power ? "Power Users may stop or pause the service" : "no control rights");
        } else report("firewall_service_acl_gives_users_no_control", 0, GetLastError(), "the security descriptor cannot be read");
        CloseServiceHandle(service);
    }
    service = OpenServiceW(scm, L"IPNAT", SERVICE_QUERY_STATUS);
    ZeroMemory(&state, sizeof(state));
    if (service) { QueryServiceStatus(service, &state); CloseServiceHandle(service); }
    report("firewall_driver_running", service && state.dwCurrentState == SERVICE_RUNNING, state.dwCurrentState, "IPNAT kernel driver; its state is in the error field");
    CloseServiceHandle(scm);
    value = 0;
    report("firewall_enabled_in_standard_profile", machine_dword(FIREWALL_POLICY L"StandardProfile", L"EnableFirewall", &value) && value == 1, value, "");
    value = 0;
    report("firewall_enabled_in_domain_profile", machine_dword(FIREWALL_POLICY L"DomainProfile", L"EnableFirewall", &value) && value == 1, value, "");
    value = 0;
    report("firewall_answers_no_broadcast_replies", machine_dword(FIREWALL_POLICY L"StandardProfile", L"DisableUnicastResponsesToMulticastBroadcast", &value) && value == 1, value, "");
    value = 0;
    machine_dword(FIREWALL_POLICY L"StandardProfile", L"DoNotAllowExceptions", &value);
    report("firewall_exceptions_setting", 2, value, value ? "exceptions are not allowed" : "exceptions are allowed (administrator-managed)");
}

/* ---- test listener ------------------------------------------------------------------ */
static void listener_log(HANDLE log, const char *protocol, const struct sockaddr_in *peer)
{
    char row[160];
    DWORD done;
    wsprintfA(row, "{\"listener\":\"%s\",\"peer\":\"%s\",\"port\":%u,\"tick\":%lu}\r\n", protocol, inet_ntoa(peer->sin_addr),
              (unsigned)ntohs(peer->sin_port), GetTickCount());
    WriteFile(log, row, (DWORD)lstrlenA(row), &done, NULL);
}

static int listener(const WCHAR *port_text, const WCHAR *directory, BOOL broadcast)
{
    static const char banner[] = "XP25-LISTENER-OK\r\n";
    WSADATA wsa;
    SOCKET tcp, udp;
    struct sockaddr_in address, peer;
    WCHAR path[MAX_PATH], stop[MAX_PATH];
    HANDLE log, ready;
    char data[512];
    unsigned port = 0;
    int size, got;
    while (*port_text >= L'0' && *port_text <= L'9') port = port * 10 + (unsigned)(*port_text++ - L'0');
    if (!port || port > 65535 || WSAStartup(MAKEWORD(2, 2), &wsa)) return 2;
    tcp = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ZeroMemory(&address, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons((u_short)port);
    if (tcp == INVALID_SOCKET || udp == INVALID_SOCKET || bind(tcp, (struct sockaddr *)&address, sizeof(address)) ||
        bind(udp, (struct sockaddr *)&address, sizeof(address)) || listen(tcp, 8)) return 3;
    wsprintfW(path, L"%s\\listener.jsonl", directory);
    log = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    wsprintfW(stop, L"%s\\listener.stop", directory);
    wsprintfW(path, L"%s\\listener.ready", directory);
    ready = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (log == INVALID_HANDLE_VALUE || ready == INVALID_HANDLE_VALUE) return 4;
    CloseHandle(ready);
    if (broadcast) {
        BOOL on = TRUE;
        if (setsockopt(udp, SOL_SOCKET, SO_BROADCAST, (const char *)&on, sizeof(on))) return 5;
    }
    while (GetFileAttributesW(stop) == INVALID_FILE_ATTRIBUTES) {
        fd_set readable;
        struct timeval wait;
        static DWORD last_broadcast;
        /* At most one broadcast per half second, however often the loop wakes up. */
        if (broadcast && GetTickCount() - last_broadcast >= 500) {
            last_broadcast = GetTickCount();
            static const char hello[] = "XP25-LISTENER-BROADCAST";
            struct sockaddr_in everyone;
            ZeroMemory(&everyone, sizeof(everyone));
            everyone.sin_family = AF_INET;
            everyone.sin_addr.s_addr = htonl(INADDR_BROADCAST);
            everyone.sin_port = htons((u_short)port);
            sendto(udp, hello, sizeof(hello) - 1, 0, (struct sockaddr *)&everyone, sizeof(everyone));
        }
        FD_ZERO(&readable);
        FD_SET(tcp, &readable);
        FD_SET(udp, &readable);
        wait.tv_sec = 0; wait.tv_usec = 500000;
        if (select(0, &readable, NULL, NULL, &wait) <= 0) continue;
        if (FD_ISSET(tcp, &readable)) {
            SOCKET client;
            size = sizeof(peer);
            client = accept(tcp, (struct sockaddr *)&peer, &size);
            if (client != INVALID_SOCKET) {
                send(client, banner, sizeof(banner) - 1, 0);
                shutdown(client, SD_SEND);
                closesocket(client);
                listener_log(log, "tcp", &peer);
            }
        }
        if (FD_ISSET(udp, &readable)) {
            size = sizeof(peer);
            lstrcpyA(data, "ECHO:");
            got = recvfrom(udp, data + 5, sizeof(data) - 6, 0, (struct sockaddr *)&peer, &size);
            /* The listener's own broadcasts come back to it, and so would its echoes of them: answer
               only datagrams that are neither, or it would talk to itself without end. */
            if (got >= 0 && !(got >= 5 && !memcmp(data + 5, "ECHO:", 5)) && !(got >= 23 && !memcmp(data + 5, "XP25-LISTENER-BROADCAST", 23))) {
                sendto(udp, data, got + 5, 0, (struct sockaddr *)&peer, size);
                listener_log(log, "udp", &peer);
            }
        }
    }
    closesocket(tcp);
    closesocket(udp);
    CloseHandle(log);
    DeleteFileW(path);
    WSACleanup();
    return 0;
}

/* ---- ordering with the lab's observer ------------------------------------------------- */
static void serial_line(const char *text)
{
    HANDLE port = INVALID_HANDLE_VALUE;
    DWORD done, tries;
    for (tries = 0; tries < 100 && port == INVALID_HANDLE_VALUE; ++tries) {
        port = CreateFileW(L"COM1", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (port == INVALID_HANDLE_VALUE) Sleep(100);
    }
    if (port == INVALID_HANDLE_VALUE) return;
    WriteFile(port, text, (DWORD)lstrlenA(text), &done, NULL);
    CloseHandle(port);
}

static int host_wait(const WCHAR *label, DWORD seconds)
{
    WSADATA wsa;
    char request[160], reply[64], line[120];
    DWORD start = GetTickCount();
    if (lstrlenW(label) > 40 || WSAStartup(MAKEWORD(2, 2), &wsa)) return 2;
    wsprintfA(request, "GET /done/%S HTTP/1.0\r\nHost: 10.25.0.1\r\n\r\n", label);
    do {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        struct sockaddr_in host;
        int got = 0;
        ZeroMemory(&host, sizeof(host));
        host.sin_family = AF_INET;
        host.sin_addr.s_addr = inet_addr("10.25.0.1");
        host.sin_port = htons(8081);
        if (s != INVALID_SOCKET && !connect(s, (struct sockaddr *)&host, sizeof(host)) &&
            send(s, request, lstrlenA(request), 0) > 0) got = recv(s, reply, sizeof(reply) - 1, 0);
        if (s != INVALID_SOCKET) closesocket(s);
        reply[got > 0 ? got : 0] = 0;
        if (got > 12 && !memcmp(reply, "HTTP/1.", 7) && !memcmp(reply + 8, " 200", 4)) {
            wsprintfA(line, "XP25_HOST_DONE=%S\r\n", label);
            serial_line(line);
            WSACleanup();
            return 0;
        }
        Sleep(1000);
    } while (GetTickCount() - start < seconds * 1000);
    wsprintfA(line, "XP25_HOST_TIMEOUT=%S\r\n", label);
    serial_line(line);
    WSACleanup();
    return 1;
}

static int ai_reset(void)
{
    HWND window;
    DWORD pid, rounds = 0;
    DWORD_PTR r;
    HANDLE process;
    int left = 0;
    while ((window = FindWindowW(L"XP25RoverAI", NULL)) != NULL && rounds++ < 10) {
        pid = 0;
        GetWindowThreadProcessId(window, &pid);
        process = OpenProcess(SYNCHRONIZE, FALSE, pid);
        PostMessageW(window, WM_CLOSE, 0, 0);
        if (process) { if (WaitForSingleObject(process, 60000) != WAIT_OBJECT_0) left = 1; CloseHandle(process); }
        else Sleep(1000);
    }
    window = FindWindowW(L"XP25ClippyAI", NULL);
    if (window) {
        pid = 0;
        GetWindowThreadProcessId(window, &pid);
        process = OpenProcess(SYNCHRONIZE, FALSE, pid);
        SendMessageTimeoutW(window, WM_COMMAND, 3003, 0, SMTO_NORMAL, 120000, &r);   /* IDM_EXIT */
        if (process) { if (WaitForSingleObject(process, 120000) != WAIT_OBJECT_0) left = 1; CloseHandle(process); }
    }
    return left || FindWindowW(L"XP25ClippyAI", NULL) || FindWindowW(L"XP25RoverAI", NULL);
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
        else if (!lstrcmpW(argv[i], L"--cve")) cve_checks = TRUE;
        else if (!lstrcmpW(argv[i], L"slow")) scale = 4;
    }
    if (!lstrcmpW(mode, L"power") && argc > 2) {
        /* ExitWindowsEx reaches the logon process through USER; shutdown.exe needs the
           InitShutdown RPC interface, which the XP25 Winlogon does not serve. */
        BOOL restart = !lstrcmpW(argv[2], L"restart");
        if (!lstrcmpW(argv[2], L"logoff")) ExitProcess(ExitWindowsEx(EWX_LOGOFF | EWX_FORCEIFHUNG, 0) ? 0 : 1);
        enable_privilege(SE_SHUTDOWN_NAME);
        ExitProcess(ExitWindowsEx((restart ? EWX_REBOOT : EWX_POWEROFF) | EWX_FORCEIFHUNG, 0) ? 0 : 1);
    }
    if (!lstrcmpW(mode, L"aireset")) ExitProcess((UINT)ai_reset());
    if (!lstrcmpW(mode, L"listen") && argc > 3) ExitProcess((UINT)listener(argv[2], argv[3], argc > 4 && !lstrcmpW(argv[4], L"broadcast")));
    if ((!lstrcmpW(mode, L"desktop") || !lstrcmpW(mode, L"apps")) && argc > 2) {
        static char label[64];
        WCHAR user[64];
        DWORD size = 64;
        if (!GetUserNameW(user, &size)) lstrcpyW(user, L"unknown");
        wsprintfA(label, "%s_%.40S", !lstrcmpW(mode, L"desktop") ? "desktop" : "apps", user);
        context = label;
        /* Results go to a file the administrator relays afterwards; COM1 as well where this account may open it. */
        output = CreateFileW(argv[2], GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (output == INVALID_HANDLE_VALUE) ExitProcess(91);
        serial = CreateFileW(L"COM1", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (!lstrcmpW(mode, L"desktop")) desktop_cases(); else app_cases();
        wsprintfA(done, "SECURITY_PROBE_COMPLETE context=%s passes=%u failures=%u observed=%u not_run=%u\r\n", context, passes, failures, observed, not_run);
        emit(done);
        CloseHandle(output);
        if (serial != INVALID_HANDLE_VALUE) CloseHandle(serial);
        ExitProcess(failures > 200 ? 200 : failures);
    }
    if (!lstrcmpW(mode, L"hostwait") && argc > 2) {
        DWORD seconds = 0;
        const WCHAR *digits = argc > 3 ? argv[3] : L"600";
        while (*digits >= L'0' && *digits <= L'9') seconds = seconds * 10 + (DWORD)(*digits++ - L'0');
        ExitProcess((UINT)host_wait(argv[2], seconds ? seconds : 600));
    }
    if (!lstrcmpW(mode, L"fwcheck") && argc > 2) {
        static char label[64];
        wsprintfA(label, "firewall_%.40S", argv[2]);
        context = label;
        output = CreateFileW(L"COM1", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (output == INVALID_HANDLE_VALUE) ExitProcess(90);
        firewall_check();
        wsprintfA(done, "SECURITY_PROBE_COMPLETE context=%s passes=%u failures=%u observed=%u not_run=%u\r\n", context, passes, failures, observed, not_run);
        emit(done);
        CloseHandle(output);
        ExitProcess(failures > 200 ? 200 : failures);
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
