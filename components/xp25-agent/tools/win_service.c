/* XP25 AI runtime: service_list and service_control (Service Control Manager),
   plus the client side of the privileged broker pipe. */
#include <windows.h>
#include <string.h>
#include "win_tools.h"

static const char *state_name(DWORD state)
{
    switch (state) {
    case SERVICE_STOPPED: return "stopped";
    case SERVICE_START_PENDING: return "starting";
    case SERVICE_STOP_PENDING: return "stopping";
    case SERVICE_RUNNING: return "running";
    case SERVICE_CONTINUE_PENDING: return "continuing";
    case SERVICE_PAUSE_PENDING: return "pausing";
    case SERVICE_PAUSED: return "paused";
    default: return "unknown";
    }
}

static const char *start_name(DWORD type)
{
    switch (type) {
    case SERVICE_BOOT_START: return "boot";
    case SERVICE_SYSTEM_START: return "system";
    case SERVICE_AUTO_START: return "automatic";
    case SERVICE_DEMAND_START: return "manual";
    case SERVICE_DISABLED: return "disabled";
    default: return "unknown";
    }
}

int tool_service_list(const XP25_TOOL *tool, const XP25_JNODE *args, XP25_BUF *out, XP25_EGRESS *egress)
{
    const char *want = tool_arg(args, "state", "all"), *filter = tool_arg(args, "filter", "");
    long limit = tool_int(args, "limit", 80, 1, 300), shown = 0;
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT);
    DWORD needed = 0, count = 0, resume = 0, i, running = 0, size = 64 * 1024;
    ENUM_SERVICE_STATUS_PROCESSW *list = NULL;
    DWORD states = !strcmp(want, "running") ? SERVICE_ACTIVE : !strcmp(want, "stopped") ? SERVICE_INACTIVE : SERVICE_STATE_ALL;
    XP25_JW w;
    (void)tool; (void)egress;
    if (!scm) return tool_win32_error(out, "scm_unavailable", "Could not open the Service Control Manager", GetLastError());
    for (;;) {
        BOOL ok;
        list = (ENUM_SERVICE_STATUS_PROCESSW *)xp25_alloc(size);
        if (!list) { CloseServiceHandle(scm); xp25_result_error(out, "out_of_memory", "Out of memory."); return 0; }
        resume = 0;
        ok = EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, states, (BYTE *)list, size,
                                   &needed, &count, &resume, NULL);
        if (ok) break;
        xp25_free(list);
        list = NULL;
        if (GetLastError() != ERROR_MORE_DATA || size >= 4 * 1024 * 1024) {
            DWORD error = GetLastError();
            CloseServiceHandle(scm);
            return tool_win32_error(out, "enum_failed", "Could not list services", error);
        }
        size = needed + size;
    }
    tool_ok_begin(&w, out);
    for (i = 0; i < count; ++i) if (list[i].ServiceStatusProcess.dwCurrentState == SERVICE_RUNNING) ++running;
    xp25_jw_key(&w, "total"); xp25_jw_u64(&w, count);
    xp25_jw_key(&w, "running"); xp25_jw_u64(&w, running);
    xp25_jw_key(&w, "services");
    xp25_jw_arr(&w);
    for (i = 0; i < count && shown < limit; ++i) {
        char name[512], display[768];
        SC_HANDLE svc;
        xp25w_copy_utf8(name, sizeof(name), list[i].lpServiceName);
        xp25w_copy_utf8(display, sizeof(display), list[i].lpDisplayName);
        if (*filter && !xp25_stristr(name, filter) && !xp25_stristr(display, filter)) continue;
        xp25_jw_obj(&w);
        xp25_jw_key(&w, "name"); xp25_jw_str(&w, name);
        xp25_jw_key(&w, "display_name"); xp25_jw_str(&w, display);
        xp25_jw_key(&w, "state"); xp25_jw_str(&w, state_name(list[i].ServiceStatusProcess.dwCurrentState));
        xp25_jw_key(&w, "pid"); xp25_jw_u64(&w, list[i].ServiceStatusProcess.dwProcessId);
        xp25_jw_key(&w, "shared_process");
        xp25_jw_bool(&w, (list[i].ServiceStatusProcess.dwServiceType & SERVICE_WIN32_SHARE_PROCESS) != 0);
        svc = OpenServiceW(scm, list[i].lpServiceName, SERVICE_QUERY_CONFIG);
        if (svc) {
            BYTE buffer[8192];
            DWORD got;
            if (QueryServiceConfigW(svc, (QUERY_SERVICE_CONFIGW *)buffer, sizeof(buffer), &got)) {
                xp25_jw_key(&w, "start_type");
                xp25_jw_str(&w, start_name(((QUERY_SERVICE_CONFIGW *)buffer)->dwStartType));
            }
            CloseServiceHandle(svc);
        }
        xp25_jw_end(&w);
        ++shown;
    }
    xp25_jw_end(&w);
    xp25_free(list);
    CloseServiceHandle(scm);
    return tool_finish(&w, out);
}

static int display_name(const char *name, char *out, size_t size)
{
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    WCHAR *wide = xp25w_wide(name), display[256];
    DWORD n = 256;
    int ok = 0;
    out[0] = 0;
    if (scm && wide && GetServiceDisplayNameW(scm, wide, display, &n)) {
        xp25w_copy_utf8(out, size, display);
        ok = 1;
    }
    if (scm) CloseServiceHandle(scm);
    xp25_free(wide);
    return ok;
}

int classify_service_control(const XP25_TOOL *tool, const XP25_JNODE *args, XP25_PROPOSAL *p)
{
    XP25W_TOOLS *ctx = TOOL_CONTEXT(tool);
    const char *name = tool_arg(args, "name", ""), *action = tool_arg(args, "action", "");
    char reason[200], display[512];
    XP25_BUF command, effects;
    p->perm = xp25_policy_service(name, action, ctx->config->service_allowlist, xp25w_is_admin(), reason, sizeof(reason));
    if (p->perm == XP25_PERM_DENIED) { xp25_proposal_deny(p, reason); return 1; }
    if (!display_name(name, display, sizeof(display))) {
        xp25_proposal_deny(p, "No installed service has this name.");
        return 1;
    }
    xp25_buf_init(&command);
    xp25_buf_init(&effects);
    xp25_buf_puts(&command, !strcmp(action, "restart") ? "Restart" : !strcmp(action, "stop") ? "Stop" : "Start");
    xp25_buf_puts(&command, " service ");
    xp25_buf_puts(&command, display);
    xp25_buf_puts(&command, " (");
    xp25_buf_puts(&command, name);
    xp25_buf_puts(&command, ")");
    xp25_buf_puts(&effects, reason);
    if (!strcmp(action, "stop")) xp25_buf_puts(&effects, " Features that depend on it stop working until it is started again.");
    if (!strcmp(action, "restart")) xp25_buf_puts(&effects, " The service is briefly unavailable while it restarts.");
    tool_proposal(p, p->perm == XP25_PERM_PRIVILEGED ? "Change a service (administrator broker)" : "Change a service",
                  xp25_buf_cstr(&command), name, xp25_buf_cstr(&effects));
    xp25_buf_free(&command);
    xp25_buf_free(&effects);
    return 1;
}

static DWORD wait_state(SC_HANDLE svc, DWORD target, DWORD timeout_ms)
{
    SERVICE_STATUS status;
    DWORD start = GetTickCount();
    for (;;) {
        if (!QueryServiceStatus(svc, &status)) return 0;
        if (status.dwCurrentState == target || GetTickCount() - start > timeout_ms) return status.dwCurrentState;
        Sleep(250);
    }
}

/* Shared by the tool and by XP25Broker.exe (which links this file). */
int xp25w_service_change(const char *name, const char *action, XP25_BUF *out)
{
    SC_HANDLE scm, svc;
    WCHAR *wide = xp25w_wide(name);
    SERVICE_STATUS status;
    DWORD before = 0, after;
    XP25_JW w;
    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm || !wide) {
        xp25_free(wide);
        return tool_win32_error(out, "scm_unavailable", "Could not open the Service Control Manager", GetLastError());
    }
    svc = OpenServiceW(scm, wide, SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS);
    xp25_free(wide);
    if (!svc) {
        DWORD error = GetLastError();
        CloseServiceHandle(scm);
        return tool_win32_error(out, error == ERROR_ACCESS_DENIED ? "access_denied" : "open_failed",
                                "Could not open the service", error);
    }
    if (QueryServiceStatus(svc, &status)) before = status.dwCurrentState;
    if ((!strcmp(action, "stop") || !strcmp(action, "restart")) && before != SERVICE_STOPPED) {
        if (!ControlService(svc, SERVICE_CONTROL_STOP, &status)) {
            DWORD error = GetLastError();
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return tool_win32_error(out, "stop_failed", "The service did not accept the stop request", error);
        }
        if (wait_state(svc, SERVICE_STOPPED, 30000) != SERVICE_STOPPED) {
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            xp25_result_error(out, "stop_timeout", "The service did not stop within 30 seconds.");
            return 0;
        }
    }
    if (!strcmp(action, "start") || !strcmp(action, "restart")) {
        if (!StartServiceW(svc, 0, NULL) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
            DWORD error = GetLastError();
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return tool_win32_error(out, "start_failed", "The service could not be started", error);
        }
        wait_state(svc, SERVICE_RUNNING, 30000);
    }
    after = QueryServiceStatus(svc, &status) ? status.dwCurrentState : 0;
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    tool_ok_begin(&w, out);
    xp25_jw_key(&w, "name"); xp25_jw_str(&w, name);
    xp25_jw_key(&w, "action"); xp25_jw_str(&w, action);
    xp25_jw_key(&w, "previous_state"); xp25_jw_str(&w, state_name(before));
    xp25_jw_key(&w, "state"); xp25_jw_str(&w, state_name(after));
    return tool_finish(&w, out);
}

int tool_service_control(const XP25_TOOL *tool, const XP25_JNODE *args, XP25_BUF *out, XP25_EGRESS *egress)
{
    XP25W_TOOLS *ctx = TOOL_CONTEXT(tool);
    const char *name = tool_arg(args, "name", ""), *action = tool_arg(args, "action", "");
    char reason[200];
    (void)egress;
    if (xp25_policy_service(name, action, ctx->config->service_allowlist, xp25w_is_admin(), reason, sizeof(reason)) ==
        XP25_PERM_PRIVILEGED) {
        XP25_BUF request;
        XP25_JW w;
        int ok;
        xp25_buf_init(&request);
        xp25_jw_init(&w, &request);
        xp25_jw_obj(&w);
        xp25_jw_key(&w, "v"); xp25_jw_i64(&w, 1);
        xp25_jw_key(&w, "op"); xp25_jw_str(&w, "service_control");
        xp25_jw_key(&w, "name"); xp25_jw_str(&w, name);
        xp25_jw_key(&w, "action"); xp25_jw_str(&w, action);
        xp25_jw_end(&w);
        ok = xp25w_broker_call(xp25_buf_cstr(&request), out);
        xp25_buf_free(&request);
        return ok;
    }
    return xp25w_service_change(name, action, out);
}

int xp25w_broker_call(const char *request_json, XP25_BUF *reply)
{
    char buffer[16384];
    DWORD got = 0;
    XP25_JDOC doc;
    int ok;
    if (!WaitNamedPipeW(XP25_BROKER_PIPE, 3000)) {
        xp25_result_error(reply, "broker_unavailable",
                          "This change needs administrator rights and the XP25 privileged broker service is not running.");
        return 0;
    }
    if (!CallNamedPipeW(XP25_BROKER_PIPE, (void *)request_json, (DWORD)strlen(request_json), buffer,
                        sizeof(buffer) - 1, &got, 60000))
        return tool_win32_error(reply, "broker_failed", "The XP25 broker did not answer", GetLastError());
    buffer[got] = 0;
    if (!xp25_json_parse(&doc, buffer, got) || doc.root->type != XP25_JOBJ) {
        xp25_json_free(&doc);
        xp25_result_error(reply, "broker_malformed", "The XP25 broker returned an invalid reply.");
        return 0;
    }
    ok = xp25_json_flag(doc.root, "ok", 0);
    xp25_json_free(&doc);
    xp25_buf_reset(reply);
    xp25_buf_append(reply, buffer, got);
    return ok;
}
