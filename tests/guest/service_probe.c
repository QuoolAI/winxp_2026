/* Disposable service fixtures: exercise the actual SCM RPC and service dispatch. */
#define WINVER 0x0501
#define _WIN32_WINNT 0x0501
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>

static HANDLE serial, stop_event;
static SERVICE_STATUS_HANDLE status_handle;
static SERVICE_STATUS worker_status;
static unsigned failures;
static BOOL shutdown_fixture;
static void image_identity(void)
{
    HANDLE snapshot, process = NULL, token = NULL;
    PROCESSENTRY32 entry = {0}; MODULEENTRY32 module = {0};
    TOKEN_PRIVILEGES privileges = {0};
    DWORD pid = 0, pe = 0, checksum = 0, written;
    SIZE_T bytes;
    char line[240]; BOOL ok = FALSE;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        privileges.PrivilegeCount = 1;
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &privileges.Privileges[0].Luid))
            AdjustTokenPrivileges(token, FALSE, &privileges, 0, NULL, NULL);
        CloseHandle(token);
    }
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    entry.dwSize = sizeof(entry);
    if (snapshot != INVALID_HANDLE_VALUE) {
        if (Process32First(snapshot, &entry)) do {
            if (lstrcmpiA(entry.szExeFile, "services.exe") == 0) { pid = entry.th32ProcessID; break; }
        } while (Process32Next(snapshot, &entry));
        CloseHandle(snapshot);
    }
    snapshot = pid ? CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid) : INVALID_HANDLE_VALUE;
    module.dwSize = sizeof(module);
    if (snapshot != INVALID_HANDLE_VALUE) {
        if (Module32First(snapshot, &module)) {
            process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
            ok = process && lstrcmpiA(module.szModule, "services.exe") == 0 &&
                 ReadProcessMemory(process, module.modBaseAddr + 60, &pe, sizeof(pe), &bytes) && bytes == sizeof(pe) &&
                 pe < 4096 && ReadProcessMemory(process, module.modBaseAddr + pe + 24 + 64,
                 &checksum, sizeof(checksum), &bytes) && bytes == sizeof(checksum);
        }
        CloseHandle(snapshot);
    }
    if (process) CloseHandle(process);
    wsprintfA(line, "{\"event\":\"scm_image_identity\",\"pid\":%lu,\"pe_checksum\":%lu,\"read\":%s}\r\n",
              pid, checksum, ok ? "true" : "false");
    WriteFile(serial, line, lstrlenA(line), &written, NULL);
    if (!ok) ++failures;
}
static void report(const char *name, BOOL pass, DWORD error)
{
    char line[240]; DWORD written;
    if (!pass) ++failures;
    wsprintfA(line, "{\"case\":\"%s\",\"status\":\"%s\",\"error\":%lu}\r\n",
              name, pass ? "pass" : "fail", pass ? 0 : error);
    WriteFile(serial, line, lstrlenA(line), &written, NULL);
}
static void WINAPI control(DWORD code)
{
    if (code == SERVICE_CONTROL_STOP || code == SERVICE_CONTROL_SHUTDOWN) {
        if (shutdown_fixture && code == SERVICE_CONTROL_SHUTDOWN) {
            DWORD written;
            HANDLE proof = CreateFileA("C:\\xp25\\service-shutdown.txt", GENERIC_WRITE,
                FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (proof != INVALID_HANDLE_VALUE) {
                const char marker[] = "SCM_SERVICE_CONTROL_SHUTDOWN\r\n";
                WriteFile(proof, marker, sizeof(marker) - 1, &written, NULL);
                FlushFileBuffers(proof);
                CloseHandle(proof);
            }
        }
        worker_status.dwCurrentState = SERVICE_STOP_PENDING;
        worker_status.dwControlsAccepted = 0;
        worker_status.dwWaitHint = 2000;
        SetServiceStatus(status_handle, &worker_status);
        SetEvent(stop_event);
    } else SetServiceStatus(status_handle, &worker_status);
}
static void WINAPI worker(DWORD argc, LPSTR *argv)
{
    (void)argc;
    shutdown_fixture = lstrcmpiA(argv[0], "XP25ShutdownProbe") == 0;
    stop_event = CreateEventA(NULL, TRUE, FALSE, NULL);
    status_handle = RegisterServiceCtrlHandlerA(argv[0], control);
    if (!status_handle || !stop_event) return;
    worker_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    worker_status.dwCurrentState = SERVICE_RUNNING;
    worker_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    SetServiceStatus(status_handle, &worker_status);
    WaitForSingleObject(stop_event, shutdown_fixture ? INFINITE : 45000);
    worker_status.dwCurrentState = SERVICE_STOPPED;
    worker_status.dwControlsAccepted = 0;
    worker_status.dwWaitHint = 0;
    SetServiceStatus(status_handle, &worker_status);
    CloseHandle(stop_event);
}
static BOOL state(SC_HANDLE svc, DWORD expected)
{
    SERVICE_STATUS status; DWORD start = GetTickCount();
    do {
        if (!QueryServiceStatus(svc, &status)) return FALSE;
        if (status.dwCurrentState == expected) return TRUE;
        Sleep(50);
    } while (GetTickCount() - start < 10000);
    return FALSE;
}
static BOOL stop(SC_HANDLE svc)
{
    SERVICE_STATUS status;
    if (!svc || !QueryServiceStatus(svc, &status)) return FALSE;
    if (status.dwCurrentState == SERVICE_STOPPED) return TRUE;
    return ControlService(svc, SERVICE_CONTROL_STOP, &status) && state(svc, SERVICE_STOPPED);
}
static BOOL absent(SC_HANDLE manager, const char *name)
{
    DWORD start = GetTickCount();
    do {
        SC_HANDLE handle = OpenServiceA(manager, name, SERVICE_QUERY_STATUS);
        DWORD error = GetLastError();
        if (handle) CloseServiceHandle(handle);
        else if (error == ERROR_SERVICE_DOES_NOT_EXIST) return TRUE;
        Sleep(50);
    } while (GetTickCount() - start < 10000);
    return FALSE;
}
void WINAPI ProbeMain(void)
{
    SERVICE_TABLE_ENTRYA table[] = {{"", worker}, {NULL, NULL}};
    SC_HANDLE manager, a = NULL, b = NULL, exists;
    char executable[MAX_PATH], path[MAX_PATH + 32];
    static BYTE config_buffer[4096];
    QUERY_SERVICE_CONFIGA *config = (QUERY_SERVICE_CONFIGA *)config_buffer;
    SERVICE_STATUS status; DWORD needed, error, written;
    BOOL ok;
    if (lstrcmpA(GetCommandLineA() + lstrlenA(GetCommandLineA()) - 8, "--worker") == 0) {
        ExitProcess(StartServiceCtrlDispatcherA(table) ? 0 : 90);
    }
    serial = CreateFileA("COM1", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (serial == INVALID_HANDLE_VALUE) ExitProcess(90);
    WriteFile(serial, "SERVICE_PROBE_STARTED\r\n", 23, &written, NULL);
    image_identity();
    manager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    report("scm_manager_access", manager != NULL, GetLastError());
    if (!manager) goto finish;
    if (lstrlenA(GetCommandLineA()) >= 14 &&
        lstrcmpA(GetCommandLineA() + lstrlenA(GetCommandLineA()) - 14, "--shutdown-arm") == 0) {
        GetModuleFileNameA(NULL, executable, sizeof(executable));
        wsprintfA(path, "\"%s\" --worker", executable);
        a = CreateServiceA(manager, "XP25ShutdownProbe", "XP25 shutdown notification fixture",
            SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL, path, NULL, NULL, NULL, NULL, NULL);
        ok = a && StartServiceA(a, 0, NULL) && state(a, SERVICE_RUNNING);
        report("shutdown_fixture_running", ok, GetLastError());
        /* Mark it for deletion now; SCM removes the fixture when shutdown stops it. */
        if (a) { report("shutdown_fixture_marked_for_cleanup", DeleteService(a), GetLastError()); CloseServiceHandle(a); }
        CloseServiceHandle(manager);
        goto finish;
    }
    exists = OpenServiceA(manager, "XP25ProbeA", SERVICE_QUERY_STATUS);
    error = GetLastError();
    if (exists) { CloseServiceHandle(exists); report("fixture_names_unused", FALSE, ERROR_SERVICE_EXISTS); goto cleanup; }
    ok = error == ERROR_SERVICE_DOES_NOT_EXIST;
    exists = OpenServiceA(manager, "XP25ProbeB", SERVICE_QUERY_STATUS);
    error = GetLastError();
    if (exists) { CloseServiceHandle(exists); report("fixture_names_unused", FALSE, ERROR_SERVICE_EXISTS); goto cleanup; }
    ok = ok && error == ERROR_SERVICE_DOES_NOT_EXIST;
    report("fixture_names_unused", ok, error);
    if (!ok) goto cleanup;
    GetModuleFileNameA(NULL, executable, sizeof(executable));
    wsprintfA(path, "\"%s\" --worker", executable);
    a = CreateServiceA(manager, "XP25ProbeA", "XP25 disposable service A", SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, path,
        NULL, NULL, NULL, NULL, NULL);
    b = CreateServiceA(manager, "XP25ProbeB", "XP25 disposable dependent B", SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, path,
        NULL, NULL, "XP25ProbeA\0", NULL, NULL);
    report("create_service_pair", a && b, GetLastError());
    if (!a || !b) goto cleanup;
    ok = QueryServiceConfigA(b, config, sizeof(config_buffer), &needed);
    report("dependency_configuration", ok && config->lpDependencies &&
           lstrcmpA(config->lpDependencies, "XP25ProbeA") == 0, GetLastError());
    ok = StartServiceA(b, 0, NULL) && state(b, SERVICE_RUNNING) && state(a, SERVICE_RUNNING);
    report("dependent_start_starts_prerequisite", ok, GetLastError());
    ok = !ControlService(a, SERVICE_CONTROL_STOP, &status);
    error = GetLastError();
    report("active_dependency_stop_rejected", ok && error == ERROR_DEPENDENT_SERVICES_RUNNING, error);
    report("dependent_stop", stop(b), GetLastError());
    report("prerequisite_stop", stop(a), GetLastError());
    ok = StartServiceA(a, 0, NULL) && state(a, SERVICE_RUNNING);
    report("service_restart", ok, GetLastError());
    report("restarted_service_stop", stop(a), GetLastError());
cleanup:
    if (b) { stop(b); report("delete_dependent", DeleteService(b), GetLastError()); CloseServiceHandle(b); }
    if (a) { stop(a); report("delete_prerequisite", DeleteService(a), GetLastError()); CloseServiceHandle(a); }
    if (a && b) {
        ok = absent(manager, "XP25ProbeB") && absent(manager, "XP25ProbeA");
        report("fixture_cleanup", ok, GetLastError());
    }
    CloseServiceHandle(manager);
finish:
    report("service_probe_complete", failures == 0, failures);
    CloseHandle(serial);
    ExitProcess(failures ? 1 : 0);
}
