/* XP25Broker.exe: narrowly scoped privileged broker (LocalSystem service).
   Scope: start/stop/restart of services. Critical services are always
   refused. What else may be controlled depends on who asks:
     - an administrator's explicit list for everyone
       (HKLM\SOFTWARE\XP25\Agent\Policy\ServiceAllowlist), when present;
     - otherwise the built-in list for administrators, and for standard users
       only the short built-in list of desktop services (xp25_policy.c).
   The caller is authenticated by Windows through named-pipe impersonation.
   It must be a genuine interactive user: restricted tokens, tokens with
   deny-only groups (how the XP25 browser is contained) and guests are
   refused, because a contained process must not be able to have SYSTEM act
   for it. The pipe is one instance created first and kept for the life of
   the service, so its name can never be served by another process while the
   broker runs, and a client that does not send its request in time is
   dropped. Every request and decision is written to the Application event
   log and to an audit file only SYSTEM and administrators can open. Nothing
   else is offered: no commands, files or registry writes. */
#include <windows.h>
#include <sddl.h>
#include <string.h>
#include "../runtime/xp25_win.h"
#include "../tools/win_tools.h"

#define SERVICE_NAME L"XP25Broker"

int xp25w_service_change(const char *name, const char *action, XP25_BUF *out);

#ifndef FILE_FLAG_FIRST_PIPE_INSTANCE
#define FILE_FLAG_FIRST_PIPE_INSTANCE 0x00080000
#endif
#define REQUEST_WAIT_MS 5000            /* a connected client must send its request within this time */
#define REQUESTS_PER_MINUTE 20          /* per caller */
#define AUDIT_FILE_LIMIT (4 * 1024 * 1024)

static SERVICE_STATUS_HANDLE status_handle;
static SERVICE_STATUS status;
static HANDLE stop_event;
/* Request allowance per caller, so that one account cannot use up another's. */
static struct { BYTE sid[SECURITY_MAX_SID_SIZE]; DWORD window_start, count; } callers[16];

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
    WCHAR dir[MAX_PATH], file[MAX_PATH + 40];
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
    /* %SystemRoot%\XP25\Broker: only administrators can create anything below the Windows directory,
       and the directory itself is for SYSTEM and administrators alone. */
    if (GetWindowsDirectoryW(dir, MAX_PATH) && lstrlenW(dir) < MAX_PATH - 40) {
        PSECURITY_DESCRIPTOR sd = NULL;
        SECURITY_ATTRIBUTES sa;
        DWORD attributes;
        lstrcpyW(file, dir);
        lstrcatW(file, L"\\XP25");
        CreateDirectoryW(file, NULL);
        lstrcatW(file, L"\\Broker");
        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", SDDL_REVISION_1, &sd, NULL)) {
            sa.nLength = sizeof(sa);
            sa.lpSecurityDescriptor = sd;
            sa.bInheritHandle = FALSE;
            CreateDirectoryW(file, &sa);
            LocalFree(sd);
        }
        attributes = GetFileAttributesW(file);
        if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) && !(attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
            WIN32_FILE_ATTRIBUTE_DATA info;
            WCHAR old[MAX_PATH + 40];
            lstrcatW(file, L"\\broker-audit.jsonl");
            if (GetFileAttributesExW(file, GetFileExInfoStandard, &info) && (info.nFileSizeHigh || info.nFileSizeLow > AUDIT_FILE_LIMIT)) {
                lstrcpyW(old, file);
                lstrcatW(old, L".1");
                MoveFileExW(file, old, MOVEFILE_REPLACE_EXISTING);     /* one earlier file is kept */
            }
            xp25_buf_puts(&line, "\r\n");
            h = CreateFileW(file, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (h != INVALID_HANDLE_VALUE) {
                WriteFile(h, line.data, (DWORD)line.len, &written, NULL);
                CloseHandle(h);
            }
        }
    }
    xp25_buf_free(&line);
}

static int member(HANDLE token, DWORD authority_rid, DWORD alias_rid)
{
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    PSID sid = NULL;
    BOOL is_member = FALSE;
    if (!AllocateAndInitializeSid(&nt, (BYTE)(alias_rid ? 2 : 1), authority_rid, alias_rid, 0, 0, 0, 0, 0, 0, &sid)) return 0;
    if (!CheckTokenMembership(token, sid, &is_member)) is_member = FALSE;
    FreeSid(sid);
    return is_member != FALSE;
}

/* Who is asking. Returns 1 for a genuine interactive user and sets *admin; otherwise 0 with the
   reason. The account name and SID are filled in whenever Windows could tell them. */
static int client_identity(HANDLE pipe, char *user, size_t size, BYTE *sid, int *admin, const char **why)
{
    HANDLE token;
    BYTE buffer[256];
    static BYTE groups[16384];
    DWORD got, i;
    int ok = 0;
    lstrcpynA(user, "unknown", (int)size);
    memset(sid, 0, SECURITY_MAX_SID_SIZE);
    *admin = 0;
    *why = "The caller could not be identified.";
    /* The client connects at identification level: its token can be queried, never used. Everything
       below runs as the broker again, with only the token handle. */
    if (!ImpersonateNamedPipeClient(pipe)) return 0;
    ok = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token);
    RevertToSelf();
    if (ok) {
        if (GetTokenInformation(token, TokenUser, buffer, sizeof(buffer), &got)) {
            WCHAR name[128], domain[128];
            DWORD n = 128, d = 128;
            SID_NAME_USE use;
            PSID owner = ((TOKEN_USER *)buffer)->User.Sid;
            if (GetLengthSid(owner) <= SECURITY_MAX_SID_SIZE) CopySid(SECURITY_MAX_SID_SIZE, (PSID)sid, owner);
            if (LookupAccountSidW(NULL, owner, name, &n, domain, &d, &use)) {
                char u[400];
                xp25w_copy_utf8(u, sizeof(u), domain);
                lstrcatA(u, "\\");
                xp25w_copy_utf8(u + lstrlenA(u), sizeof(u) - (size_t)lstrlenA(u), name);
                lstrcpynA(user, u, (int)size);
            }
        }
        ok = 1;
        if (!member(token, SECURITY_INTERACTIVE_RID, 0)) { ok = 0; *why = "Only interactive users may use the XP25 broker."; }
        else if (IsTokenRestricted(token)) { ok = 0; *why = "A restricted process may not use the XP25 broker."; }
        else if (member(token, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_GUESTS)) { ok = 0; *why = "Guests may not use the XP25 broker."; }
        else if (!GetTokenInformation(token, TokenGroups, groups, sizeof(groups), &got)) { ok = 0; *why = "The caller's groups could not be read."; }
        else {
            /* A token from which groups were taken away (deny-only) belongs to a contained process. */
            const TOKEN_GROUPS *list = (const TOKEN_GROUPS *)groups;
            for (i = 0; i < list->GroupCount; ++i)
                if (list->Groups[i].Attributes & SE_GROUP_USE_FOR_DENY_ONLY) { ok = 0; *why = "A contained process may not use the XP25 broker."; break; }
        }
        if (ok) *admin = member(token, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS);
        CloseHandle(token);
    }
    return ok;
}

/* 1 while the caller is within its allowance for the current minute. */
static int allowance(const BYTE *sid)
{
    DWORD now = GetTickCount(), i, slot = 0, oldest = 0;
    for (i = 0; i < sizeof(callers) / sizeof(callers[0]); ++i) {
        if (callers[i].count && !memcmp(callers[i].sid, sid, SECURITY_MAX_SID_SIZE)) { slot = i; break; }
        if (now - callers[i].window_start >= oldest) { oldest = now - callers[i].window_start; slot = i; }
    }
    if (i == sizeof(callers) / sizeof(callers[0]) || now - callers[slot].window_start > 60000) {
        memcpy(callers[slot].sid, sid, SECURITY_MAX_SID_SIZE);
        callers[slot].window_start = now;
        callers[slot].count = 0;
    }
    return ++callers[slot].count <= REQUESTS_PER_MINUTE;
}

/* One read or write on the pipe that may take at most REQUEST_WAIT_MS: a client that connects and
   stays silent, or never takes its reply, cannot hold the broker. */
static BOOL pipe_io(HANDLE pipe, OVERLAPPED *ov, BOOL read, void *data, DWORD size, DWORD *done)
{
    HANDLE events[2];
    *done = 0;
    events[0] = stop_event;
    events[1] = ov->hEvent;
    ResetEvent(ov->hEvent);
    if (read ? ReadFile(pipe, data, size, done, ov) : WriteFile(pipe, data, size, done, ov)) return TRUE;
    if (GetLastError() != ERROR_IO_PENDING) return FALSE;       /* includes ERROR_MORE_DATA: larger than any valid request */
    if (WaitForMultipleObjects(2, events, FALSE, REQUEST_WAIT_MS) != WAIT_OBJECT_0 + 1) {
        CancelIo(pipe);
        GetOverlappedResult(pipe, ov, done, TRUE);
        *done = 0;
        return FALSE;
    }
    return GetOverlappedResult(pipe, ov, done, FALSE);
}

static void handle(HANDLE pipe, OVERLAPPED *ov)
{
    char request[8193], user[256], reason[200], policy[600], drain[16];
    BYTE sid[SECURITY_MAX_SID_SIZE];
    DWORD got, written;
    XP25_JDOC doc;
    XP25_BUF reply;
    const char *decision = "refused", *why;
    int admin, has_policy = 0;
    xp25_buf_init(&reply);
    memset(&doc, 0, sizeof(doc));
    if (!pipe_io(pipe, ov, TRUE, request, sizeof(request) - 1, &got)) got = 0;
    request[got] = 0;
    if (!client_identity(pipe, user, sizeof(user), sid, &admin, &why)) {
        xp25_result_error(&reply, "broker_refused", why);
    } else if (!allowance(sid)) {
        xp25_result_error(&reply, "broker_busy", "Too many broker requests; try again in a minute.");
    } else if (!got || !xp25_json_parse(&doc, request, got) || doc.root->type != XP25_JOBJ) {
        xp25_result_error(&reply, "broker_malformed", "The request is not valid JSON.");
        xp25_json_free(&doc);
    } else {
        const char *op = xp25_json_string(doc.root, "op"), *name = xp25_json_string(doc.root, "name");
        const char *action = xp25_json_string(doc.root, "action");
        xp25_i64 version = 0;
        XP25_PERM perm;
        /* An administrator's list comes from the broker's own machine policy, never from the request. */
        {
            HKEY key;
            WCHAR value[600];
            DWORD type, bytes = sizeof(value) - sizeof(WCHAR);
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\XP25\\Agent\\Policy", 0, KEY_READ, &key) == ERROR_SUCCESS) {
                if (RegQueryValueExW(key, L"ServiceAllowlist", NULL, &type, (BYTE *)value, &bytes) == ERROR_SUCCESS && type == REG_SZ) {
                    value[bytes / sizeof(WCHAR)] = 0;
                    xp25w_copy_utf8(policy, sizeof(policy), value);
                    has_policy = policy[0] != 0;
                }
                RegCloseKey(key);
            }
        }
        if (!xp25_json_i64(doc.root, "v", &version) || version != 1 || !op || strcmp(op, "service_control")) {
            xp25_result_error(&reply, "broker_unsupported", "The XP25 broker only starts, stops or restarts authorized services.");
        } else if ((perm = xp25_policy_service(name, action, has_policy ? policy : NULL, admin, reason, sizeof(reason))) != XP25_PERM_APPROVAL &&
                   perm != XP25_PERM_PRIVILEGED) {
            xp25_result_error(&reply, "permission_denied", reason);
        } else {
            decision = xp25w_service_change(name, action, &reply) ? "performed" : "failed";
        }
        xp25_json_free(&doc);
    }
    audit(user, request, decision, xp25_buf_cstr(&reply));
    /* The reply, then time for the client to take it: the next read ends when the client closes
       its end (or after the allowed wait), and only then is the instance taken back. */
    if (pipe_io(pipe, ov, FALSE, reply.data, (DWORD)reply.len, &written)) pipe_io(pipe, ov, TRUE, drain, sizeof(drain), &written);
    xp25_buf_free(&reply);
}

/* Returns 0 when the pipe could not be created as its first instance: another process already
   serves the name, and the broker must not share it. */
static int serve(void)
{
    PSECURITY_DESCRIPTOR sd = NULL;
    SECURITY_ATTRIBUTES sa;
    OVERLAPPED ov;
    HANDLE events[2], pipe;
    /* SYSTEM and Administrators full control. Interactive users may connect, read and write
       (0x12019b: no FILE_CREATE_PIPE_INSTANCE, so they cannot add an instance of their own). */
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;IU)",
                                                             SDDL_REVISION_1, &sd, NULL)) return 0;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = sd;
    sa.bInheritHandle = FALSE;
    /* One instance, created first and never closed: clients are served one after another on it. */
    pipe = CreateNamedPipeW(XP25_BROKER_PIPE, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1, 16384, 16384, 0, &sa);
    LocalFree(sd);
    if (pipe == INVALID_HANDLE_VALUE) return 0;
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    events[0] = stop_event;
    events[1] = ov.hEvent;
    while (ov.hEvent && WaitForSingleObject(stop_event, 0) != WAIT_OBJECT_0) {
        BOOL connected;
        ResetEvent(ov.hEvent);
        connected = ConnectNamedPipe(pipe, &ov);
        if (!connected && GetLastError() == ERROR_IO_PENDING) {
            if (WaitForMultipleObjects(2, events, FALSE, INFINITE) == WAIT_OBJECT_0) { CancelIo(pipe); break; }
            connected = TRUE;
        } else if (!connected && GetLastError() == ERROR_PIPE_CONNECTED) connected = TRUE;
        if (connected) handle(pipe, &ov);
        DisconnectNamedPipe(pipe);
    }
    if (ov.hEvent) CloseHandle(ov.hEvent);
    CloseHandle(pipe);
    return 1;
}

static void WINAPI service_main(DWORD argc, WCHAR **argv)
{
    (void)argc; (void)argv;
    status_handle = RegisterServiceCtrlHandlerExW(SERVICE_NAME, control, NULL);
    if (!status_handle) return;
    stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    report(SERVICE_RUNNING);
    if (!serve()) {
        /* Fail closed, and say why where an administrator will look. */
        HANDLE log = RegisterEventSourceW(NULL, SERVICE_NAME);
        const WCHAR *text = L"XP25Broker did not start: its pipe name is already served by another process.";
        if (log) { ReportEventW(log, EVENTLOG_ERROR_TYPE, 0, 2, NULL, 1, 0, &text, NULL); DeregisterEventSource(log); }
        status.dwWin32ExitCode = ERROR_PIPE_BUSY;
        status.dwCurrentState = SERVICE_STOPPED;
        status.dwControlsAccepted = 0;
        SetServiceStatus(status_handle, &status);
        return;
    }
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
