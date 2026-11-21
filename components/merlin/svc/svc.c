/* MerlinSvc.exe: the MerlinAI service (LocalSystem, automatic start).

   1. After every boot it reports the system's health to the host
      deployment agent (POST /deploy/v1/health, XP25-MERLIN-DEPLOY1, signed
      with the installation's deployment key, which only SYSTEM and
      Administrators can read): the image revision, whether Winlogon, the
      event log, RPC and the Windows Firewall are running, and whether the
      system volume is marked dirty. After an update the agent keeps the new
      system image only if this report arrives and is healthy; otherwise it
      restores the previous image. It retries for 15 minutes.
   2. When automatic collection is enabled it looks for local problems at
      start and then every CollectMinutes (MerlinCollect). Collected problems
      stay on this computer: the service never transmits diagnostics.

   MerlinSvc.exe /install | /uninstall  register or remove the service
   MerlinSvc.exe /health                one health report now (lab use) */
#include <windows.h>
#include <tlhelp32.h>
#include <winioctl.h>
#include "../client/merlin_client.h"

#define SERVICE_NAME L"MerlinSvc"
#define DISPLAY_NAME L"MerlinAI Service"

static SERVICE_STATUS_HANDLE status_handle;
static SERVICE_STATUS status;
static HANDLE stop_event;

static void serial(const char *line)
{
    HANDLE port = CreateFileW(L"COM1", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    DWORD wrote;
    int tries;
    for (tries = 0; port == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED && tries < 40; ++tries) {
        Sleep(50);
        port = CreateFileW(L"COM1", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    }
    if (port == INVALID_HANDLE_VALUE) return;
    WriteFile(port, line, (DWORD)lstrlenA(line), &wrote, NULL);
    WriteFile(port, "\r\n", 2, &wrote, NULL);
    CloseHandle(port);
}

static BOOL process_running(const WCHAR *name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W row;
    BOOL found = FALSE;
    if (snap == INVALID_HANDLE_VALUE) return FALSE;
    row.dwSize = sizeof(row);
    if (Process32FirstW(snap, &row))
        do {
            if (!lstrcmpiW(row.szExeFile, name)) found = TRUE;
        } while (!found && Process32NextW(snap, &row));
    CloseHandle(snap);
    return found;
}

static BOOL service_running(SC_HANDLE scm, const WCHAR *name)
{
    SC_HANDLE s = OpenServiceW(scm, name, SERVICE_QUERY_STATUS);
    SERVICE_STATUS st;
    BOOL running = FALSE;
    if (!s) return FALSE;
    if (QueryServiceStatus(s, &st)) running = st.dwCurrentState == SERVICE_RUNNING;
    CloseServiceHandle(s);
    return running;
}

/* 1 dirty, 0 clean, -1 unknown. */
static int volume_dirty(void)
{
    HANDLE v = CreateFileW(L"\\\\.\\C:", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    ULONG flags = 0;
    DWORD got;
    int result = -1;
    if (v == INVALID_HANDLE_VALUE) return -1;
    if (DeviceIoControl(v, FSCTL_IS_VOLUME_DIRTY, NULL, 0, &flags, sizeof(flags), &got, NULL)) result = (flags & 1) ? 1 : 0;
    CloseHandle(v);
    return result;
}

static void revision(char *out, int size)
{
    HANDLE f = CreateFileW(L"C:\\xp25\\image-revision.txt", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    DWORD got = 0;
    int i;
    out[0] = 0;
    if (f == INVALID_HANDLE_VALUE) return;
    ReadFile(f, out, (DWORD)size - 1, &got, NULL);
    CloseHandle(f);
    out[got] = 0;
    for (i = 0; out[i]; ++i)
        if (out[i] == '\r' || out[i] == '\n') out[i] = 0;
    merlin_sanitize_line(out);
}

/* Build and send one health report; returns the Win32 error (0 = accepted by the agent). */
static DWORD health_report(char *detail, int detail_size)
{
    MERLIN_JSON_OUT j;
    MERLIN_REPLY reply;
    char body[2048], rev[160];
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    BOOL winlogon = process_running(L"winlogon.exe"), eventlog = FALSE, rpc = FALSE, firewall = FALSE;
    int dirty = volume_dirty();
    DWORD error;
    if (scm) {
        eventlog = service_running(scm, L"Eventlog");
        rpc = service_running(scm, L"RpcSs");
        firewall = service_running(scm, L"SharedAccess");
        CloseServiceHandle(scm);
    }
    revision(rev, sizeof(rev));
    merlin_json_begin(&j, body, sizeof(body));
    merlin_json_object(&j);
    merlin_json_key(&j, "revision");
    merlin_json_string(&j, rev);
    merlin_json_key(&j, "uptime_seconds");
    merlin_json_ulong(&j, GetTickCount() / 1000);
    merlin_json_key(&j, "winlogon_running");
    merlin_json_bool(&j, winlogon);
    merlin_json_key(&j, "eventlog_running");
    merlin_json_bool(&j, eventlog);
    merlin_json_key(&j, "rpc_running");
    merlin_json_bool(&j, rpc);
    merlin_json_key(&j, "firewall_running");
    merlin_json_bool(&j, firewall);
    merlin_json_key(&j, "volume_dirty");
    merlin_json_ulong(&j, dirty < 0 ? 2 : (unsigned long)dirty);
    merlin_json_end_object(&j);
    error = MerlinDeployCall("POST", "/health", body, (DWORD)j.used, &reply);
    merlin_copy(detail, detail_size, rev);
    merlin_append(detail, detail_size, winlogon && eventlog && rpc ? " core=1" : " core=0");
    merlin_append(detail, detail_size, firewall ? " firewall=1" : " firewall=0");
    merlin_append(detail, detail_size, dirty == 0 ? " dirty=0" : dirty == 1 ? " dirty=1" : " dirty=unknown");
    merlin_append(detail, detail_size, " status=");
    merlin_append_ulong(detail, detail_size, (unsigned long)reply.status);
    if (error) {
        merlin_append(detail, detail_size, " ");
        merlin_append(detail, detail_size, reply.error);
    }
    if (!error && reply.status != 200) error = ERROR_NOT_READY;
    MerlinFreeReply(&reply);
    return error;
}

static void set_state(DWORD state)
{
    status.dwCurrentState = state;
    status.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
    SetServiceStatus(status_handle, &status);
}

static DWORD WINAPI control(DWORD code, DWORD type, LPVOID data, LPVOID context)
{
    (void)type;
    (void)data;
    (void)context;
    if (code == SERVICE_CONTROL_STOP || code == SERVICE_CONTROL_SHUTDOWN) {
        set_state(SERVICE_STOP_PENDING);
        SetEvent(stop_event);
    }
    return NO_ERROR;
}

static void WINAPI service_main(DWORD argc, LPWSTR *argv)
{
    MERLIN_CONFIG config;
    char detail[400], line[480];
    DWORD started = GetTickCount(), next_collect = 0, wait_ms;
    BOOL reported = FALSE;
    int attempts = 0;
    (void)argc;
    (void)argv;
    status_handle = RegisterServiceCtrlHandlerExW(SERVICE_NAME, control, NULL);
    if (!status_handle) return;
    ZeroMemory(&status, sizeof(status));
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    set_state(SERVICE_RUNNING);
    MerlinGetConfig(&config);
    for (;;) {
        MERLIN_COLLECT_STATS stats;
        if (!reported && config.deploy[0] && GetTickCount() - started < 15 * 60 * 1000) {
            DWORD e = health_report(detail, sizeof(detail));
            ++attempts;
            merlin_copy(line, sizeof(line), "XP25_MERLIN_HEALTH_REPORT=");
            merlin_append_ulong(line, sizeof(line), e);
            merlin_append(line, sizeof(line), " attempt=");
            merlin_append_ulong(line, sizeof(line), (unsigned long)attempts);
            merlin_append(line, sizeof(line), " ");
            merlin_append(line, sizeof(line), detail);
            serial(line);
            reported = e == 0;
        }
        if (config.auto_collect && GetTickCount() >= next_collect) {
            MerlinCollect(&stats);
            next_collect = GetTickCount() + (config.collect_minutes ? config.collect_minutes : 60) * 60000;
        }
        wait_ms = !reported && config.deploy[0] ? 30000 : 60000;
        if (WaitForSingleObject(stop_event, wait_ms) == WAIT_OBJECT_0) break;
    }
    set_state(SERVICE_STOPPED);
}

static DWORD install(BOOL remove)
{
    WCHAR path[MAX_PATH + 2], command[MAX_PATH + 8];
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS), s;
    SERVICE_DESCRIPTIONW description;
    DWORD e = 0;
    if (!scm) return GetLastError();
    if (remove) {
        SERVICE_STATUS st;
        s = OpenServiceW(scm, SERVICE_NAME, SERVICE_STOP | DELETE);
        if (s) {
            ControlService(s, SERVICE_CONTROL_STOP, &st);
            if (!DeleteService(s)) e = GetLastError();
            CloseServiceHandle(s);
        } else e = GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST ? 0 : GetLastError();
        CloseServiceHandle(scm);
        return e;
    }
    GetModuleFileNameW(NULL, path, MAX_PATH);
    lstrcpyW(command, L"\"");
    lstrcatW(command, path);
    lstrcatW(command, L"\"");
    s = CreateServiceW(scm, SERVICE_NAME, DISPLAY_NAME, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
                       SERVICE_ERROR_NORMAL, command, NULL, NULL, L"Eventlog\0Tcpip\0", NULL, NULL);
    if (!s && GetLastError() == ERROR_SERVICE_EXISTS) s = OpenServiceW(scm, SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (!s) e = GetLastError();
    else {
        description.lpDescription = L"Reports MerlinAI health after updates and looks for local problems. It never sends diagnostics.";
        ChangeServiceConfig2W(s, SERVICE_CONFIG_DESCRIPTION, &description);
        CloseServiceHandle(s);
    }
    CloseServiceHandle(scm);
    return e;
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE previous, LPWSTR command_line, int show)
{
    SERVICE_TABLE_ENTRYW table[2];
    char line[480], detail[400];
    DWORD e;
    (void)instance;
    (void)previous;
    (void)show;
    if (command_line && command_line[0]) {
        if (!lstrcmpiW(command_line, L"/install") || !lstrcmpiW(command_line, L"/uninstall")) {
            e = install(command_line[1] == L'u' || command_line[1] == L'U');
            merlin_copy(line, sizeof(line), command_line[1] == L'u' || command_line[1] == L'U' ? "XP25_MERLIN_SERVICE_UNINSTALL=" : "XP25_MERLIN_SERVICE_INSTALL=");
            merlin_append_ulong(line, sizeof(line), e);
            serial(line);
            return (int)e;
        }
        if (!lstrcmpiW(command_line, L"/health")) {
            e = health_report(detail, sizeof(detail));
            merlin_copy(line, sizeof(line), "XP25_MERLIN_HEALTH_REPORT=");
            merlin_append_ulong(line, sizeof(line), e);
            merlin_append(line, sizeof(line), " ");
            merlin_append(line, sizeof(line), detail);
            serial(line);
            return (int)e;
        }
        return ERROR_INVALID_PARAMETER;
    }
    table[0].lpServiceName = SERVICE_NAME;
    table[0].lpServiceProc = service_main;
    table[1].lpServiceName = NULL;
    table[1].lpServiceProc = NULL;
    return StartServiceCtrlDispatcherW(table) ? 0 : (int)GetLastError();
}
