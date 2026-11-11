/* XP25Broker.exe: narrowly scoped privileged broker (LocalSystem service).
   Scope: start/stop/restart of services on the administrator's allowlist
   (HKLM\SOFTWARE\XP25\Agent\Policy\ServiceAllowlist, else the built-in
   default); critical services are always refused. The caller is
   authenticated by Windows through named-pipe impersonation and must be an
   interactive user. Every request and decision is written to the
   Application event log and to a machine audit file. Nothing else is
   offered: no commands, files or registry writes. */
#include <windows.h>
#include <sddl.h>
#include <shlobj.h>
#include <string.h>
#include "../runtime/xp25_win.h"
#include "../tools/win_tools.h"

#define SERVICE_NAME L"XP25Broker"

int xp25w_service_change(const char *name, const char *action, XP25_BUF *out);

static SERVICE_STATUS_HANDLE status_handle;
static SERVICE_STATUS status;
static HANDLE stop_event;
static DWORD window_start, window_count;

static void report(DWORD state)
{
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = state;
    status.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
    status.dwWin32ExitCode = NO_ERROR;
    status.dwWaitHint = 3000;
    SetServiceStatus(status_handle, &status);
}

static DWORD WINAPI control(DWORD code, DWORD type, void *data, void *context)
{
    (void)type; (void)data; (void)context;
    if (code == SERVICE_CONTROL_STOP || code == SERVICE_CONTROL_SHUTDOWN) {
        report(SERVICE_STOP_PENDING);
        SetEvent(stop_event);
    }
    return NO_ERROR;
}

static void audit(const char *user, const char *request, const char *decision, const char *reply)
{
    WCHAR dir[MAX_PATH], file[MAX_PATH + 32];
    HANDLE log, h;
    XP25_BUF line;
    XP25_JW w;
    FILETIME now;
    char stamp[20];
    WCHAR *strings[1];
    DWORD written;
    GetSystemTimeAsFileTime(&now);
    xp25w_format_filetime(&now, stamp);
    xp25_buf_init(&line);
    xp25_jw_init(&w, &line);
    xp25_jw_obj(&w);
    xp25_jw_key(&w, "time"); xp25_jw_str(&w, stamp);
    xp25_jw_key(&w, "user"); xp25_jw_str(&w, user);
    xp25_jw_key(&w, "decision"); xp25_jw_str(&w, decision);
    xp25_jw_key(&w, "request"); xp25_jw_strn(&w, request, xp25_utf8_clip(request, 1000));
    xp25_jw_key(&w, "reply"); xp25_jw_strn(&w, reply, xp25_utf8_clip(reply, 1000));
    xp25_jw_end(&w);
    log = RegisterEventSourceW(NULL, SERVICE_NAME);
    if (log) {
        strings[0] = xp25w_wide(xp25_buf_cstr(&line));
        if (strings[0]) {
            ReportEventW(log, (WORD)(strcmp(decision, "performed") ? EVENTLOG_WARNING_TYPE : EVENTLOG_INFORMATION_TYPE),
                         0, 1, NULL, 1, 0, (const WCHAR **)strings, NULL);
            xp25_free(strings[0]);
        }
        DeregisterEventSource(log);
    }
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, 0, dir)) && lstrlenW(dir) < MAX_PATH - 1) {
        lstrcpyW(file, dir);
        lstrcatW(file, L"\\XP25");
        CreateDirectoryW(file, NULL);
        lstrcatW(file, L"\\broker-audit.jsonl");
        xp25_buf_puts(&line, "\r\n");
        h = CreateFileW(file, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            WriteFile(h, line.data, (DWORD)line.len, &written, NULL);
            CloseHandle(h);
        }
    }
    xp25_buf_free(&line);
}

/* The client must be an interactive user; returns its account name. */
static int client_identity(HANDLE pipe, char *user, size_t size)
{
    HANDLE token;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    PSID interactive = NULL;
    BOOL member = FALSE;
    BYTE buffer[256];
    DWORD got;
    int ok = 0;
    lstrcpynA(user, "unknown", (int)size);
    if (!ImpersonateNamedPipeClient(pipe)) return 0;
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token)) {
        if (AllocateAndInitializeSid(&nt, 1, SECURITY_INTERACTIVE_RID, 0, 0, 0, 0, 0, 0, 0, &interactive)) {
            ok = CheckTokenMembership(token, interactive, &member) && member;
            FreeSid(interactive);
        }
        if (GetTokenInformation(token, TokenUser, buffer, sizeof(buffer), &got)) {
            WCHAR name[128], domain[128];
            DWORD n = 128, d = 128;
            SID_NAME_USE use;
            if (LookupAccountSidW(NULL, ((TOKEN_USER *)buffer)->User.Sid, name, &n, domain, &d, &use)) {
                char u[400];
                xp25w_copy_utf8(u, sizeof(u), domain);
                lstrcatA(u, "\\");
                xp25w_copy_utf8(u + lstrlenA(u), sizeof(u) - (size_t)lstrlenA(u), name);
                lstrcpynA(user, u, (int)size);
            }
        }
        CloseHandle(token);
    }
    RevertToSelf();
    return ok;
}

static void handle(HANDLE pipe)
{
    char request[8193], user[256], reason[200], allowlist[600];
    DWORD got = 0, written;
    XP25_JDOC doc;
    XP25_BUF reply;
    const char *decision = "refused";
    xp25_buf_init(&reply);
    if (!ReadFile(pipe, request, sizeof(request) - 1, &got, NULL)) got = 0;
    request[got] = 0;
    if (GetTickCount() - window_start > 60000) { window_start = GetTickCount(); window_count = 0; }
    if (!client_identity(pipe, user, sizeof(user))) {
        xp25_result_error(&reply, "broker_refused", "Only interactive users may use the XP25 broker.");
    } else if (++window_count > 20) {
        xp25_result_error(&reply, "broker_busy", "Too many broker requests; try again in a minute.");
    } else if (!xp25_json_parse(&doc, request, got) || doc.root->type != XP25_JOBJ) {
        xp25_result_error(&reply, "broker_malformed", "The request is not valid JSON.");
        xp25_json_free(&doc);
    } else {
        const char *op = xp25_json_string(doc.root, "op"), *name = xp25_json_string(doc.root, "name");
        const char *action = xp25_json_string(doc.root, "action");
        xp25_i64 version = 0;
        XP25_CONFIG config;
        /* The allowlist comes from the broker's own machine policy, never from the request. */
        xp25w_config_defaults(&config);
        lstrcpynA(allowlist, config.service_allowlist, sizeof(allowlist));
        {
            HKEY key;
            WCHAR value[600];
            DWORD type, bytes = sizeof(value) - sizeof(WCHAR);
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\XP25\\Agent\\Policy", 0, KEY_READ, &key) == ERROR_SUCCESS) {
                if (RegQueryValueExW(key, L"ServiceAllowlist", NULL, &type, (BYTE *)value, &bytes) == ERROR_SUCCESS && type == REG_SZ) {
                    value[bytes / sizeof(WCHAR)] = 0;
                    xp25w_copy_utf8(allowlist, sizeof(allowlist), value);
                }
                RegCloseKey(key);
            }
        }
        if (!xp25_json_i64(doc.root, "v", &version) || version != 1 || !op || strcmp(op, "service_control")) {
            xp25_result_error(&reply, "broker_unsupported", "The XP25 broker only starts, stops or restarts authorized services.");
        } else if (xp25_policy_service(name, action, allowlist, 1, reason, sizeof(reason)) != XP25_PERM_APPROVAL) {
            xp25_result_error(&reply, "permission_denied", reason);
        } else {
            decision = xp25w_service_change(name, action, &reply) ? "performed" : "failed";
        }
        xp25_json_free(&doc);
    }
    audit(user, request, decision, xp25_buf_cstr(&reply));
    WriteFile(pipe, xp25_buf_cstr(&reply), (DWORD)reply.len, &written, NULL);
    FlushFileBuffers(pipe);
    xp25_buf_free(&reply);
}

static void serve(void)
{
    PSECURITY_DESCRIPTOR sd = NULL;
    SECURITY_ATTRIBUTES sa;
    OVERLAPPED ov;
    HANDLE events[2];
    /* SYSTEM and Administrators full control; interactive users read/write. */
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)",
                                                             SDDL_REVISION_1, &sd, NULL)) return;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = sd;
    sa.bInheritHandle = FALSE;
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    events[0] = stop_event;
    events[1] = ov.hEvent;
    for (;;) {
        HANDLE pipe = CreateNamedPipeW(XP25_BROKER_PIPE, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                                       PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1, 16384, 16384, 0, &sa);
        DWORD wait;
        BOOL connected;
        if (pipe == INVALID_HANDLE_VALUE) break;
        ResetEvent(ov.hEvent);
        connected = ConnectNamedPipe(pipe, &ov);
        if (!connected && GetLastError() == ERROR_IO_PENDING) {
            wait = WaitForMultipleObjects(2, events, FALSE, INFINITE);
            if (wait == WAIT_OBJECT_0) { CancelIo(pipe); CloseHandle(pipe); break; }
            connected = TRUE;
        } else if (!connected && GetLastError() == ERROR_PIPE_CONNECTED) connected = TRUE;
        if (connected) handle(pipe);
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
        if (WaitForSingleObject(stop_event, 0) == WAIT_OBJECT_0) break;
    }
    CloseHandle(ov.hEvent);
    LocalFree(sd);
}

static void WINAPI service_main(DWORD argc, WCHAR **argv)
{
    (void)argc; (void)argv;
    status_handle = RegisterServiceCtrlHandlerExW(SERVICE_NAME, control, NULL);
    if (!status_handle) return;
    stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    report(SERVICE_RUNNING);
    serve();
    report(SERVICE_STOPPED);
}

static int install(int remove)
{
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE), svc;
    WCHAR path[MAX_PATH + 2], quoted[MAX_PATH + 4];
    SERVICE_DESCRIPTIONW description;
    int ok = 0;
    if (!scm) return 0;
    if (remove) {
        svc = OpenServiceW(scm, SERVICE_NAME, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
        if (svc) {
            SERVICE_STATUS st;
            ControlService(svc, SERVICE_CONTROL_STOP, &st);
            ok = DeleteService(svc) != 0;
            CloseServiceHandle(svc);
        }
        CloseServiceHandle(scm);
        return ok;
    }
    GetModuleFileNameW(NULL, path, MAX_PATH);
    lstrcpyW(quoted, L"\"");
    lstrcatW(quoted, path);
    lstrcatW(quoted, L"\"");
    svc = CreateServiceW(scm, SERVICE_NAME, L"XP25 Privileged Broker", SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                         SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, quoted, NULL, NULL, NULL, NULL, NULL);
    if (svc) {
        description.lpDescription = L"Performs administrator-approved XP25 assistant changes to authorized services. "
                                    L"Refuses every other operation.";
        ChangeServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, &description);
        ok = StartServiceW(svc, 0, NULL) || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    return ok;
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE previous, LPWSTR command_line, int show)
{
    SERVICE_TABLE_ENTRYW table[2];
    (void)instance; (void)previous; (void)show;
    if (command_line && !lstrcmpiW(command_line, L"/install")) return install(0) ? 0 : 1;
    if (command_line && !lstrcmpiW(command_line, L"/uninstall")) return install(1) ? 0 : 1;
    table[0].lpServiceName = SERVICE_NAME;
    table[0].lpServiceProc = service_main;
    table[1].lpServiceName = NULL;
    table[1].lpServiceProc = NULL;
    return StartServiceCtrlDispatcherW(table) ? 0 : 1;
}
