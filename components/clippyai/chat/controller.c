/* ClippyAI controller: runs agent turns on a worker thread. Events are
   posted to the UI thread; approvals and sharing decisions are sent
   synchronously so the worker waits for the user's answer. */
#include <windows.h>
#include <objbase.h>
#include <string.h>
#include "../app/clippyai.h"

typedef struct { const char *tool, *provider, *preview; } SHARE_REQUEST;

static void host_event(void *ctx, const XP25_EVENT *e)
{
    XP25_EVENT *copy = (XP25_EVENT *)xp25_alloc(sizeof(XP25_EVENT));
    (void)ctx;
    if (!copy) return;
    copy->kind = e->kind;
    copy->ok = e->ok;
    copy->tool = xp25_strdup(e->tool);
    copy->text = xp25_strdup(e->text);
    copy->detail = xp25_strdup(e->detail);
    if (!PostMessageW(g_app.window, WM_CLIPPY_EVENT, 0, (LPARAM)copy)) controller_free_event(copy);
}

void controller_free_event(XP25_EVENT *e)
{
    xp25_free((void *)e->tool);
    xp25_free((void *)e->text);
    xp25_free((void *)e->detail);
    xp25_free(e);
}

static int host_approve(void *ctx, const char *tool, const XP25_PROPOSAL *p)
{
    (void)ctx;
    return (int)SendMessageW(g_app.window, WM_CLIPPY_APPROVE, (WPARAM)tool, (LPARAM)p);
}

static int host_share(void *ctx, const char *tool, const char *provider, const char *preview)
{
    SHARE_REQUEST r;
    (void)ctx;
    r.tool = tool;
    r.provider = provider;
    r.preview = preview;
    return (int)SendMessageW(g_app.window, WM_CLIPPY_SHARE, 0, (LPARAM)&r);
}

static int host_cancelled(void *ctx) { (void)ctx; return g_app.cancel != 0; }
static void host_audit(void *ctx, const char *line) { (void)ctx; xp25w_audit("ClippyAI", line); }

int controller_init(void)
{
    memset(&g_app.registry, 0, sizeof(g_app.registry));
    g_app.tool_context.paths = &g_app.paths;
    g_app.tool_context.config = &g_app.config;
    g_app.tool_context.self_pid = GetCurrentProcessId();
    if (!xp25w_register_tools(&g_app.registry, &g_app.tool_context)) return 0;
    memset(&g_app.offline_settings, 0, sizeof(g_app.offline_settings));
    g_app.offline_settings.self_pid = GetCurrentProcessId();
    xp25_offline_init(&g_app.offline, &g_app.offline_settings);
    xp25_agent_init(&g_app.agent, &g_app.registry, &g_app.offline);
    g_app.agent.fallback = &g_app.offline;
    g_app.agent.max_steps = 12;
    g_app.agent.host.event = host_event;
    g_app.agent.host.approve = host_approve;
    g_app.agent.host.share = host_share;
    g_app.agent.host.cancelled = host_cancelled;
    g_app.agent.host.audit = host_audit;
    controller_reconfigure();
    return 1;
}

void controller_reconfigure(void)
{
    char reason[300];
    XP25_BUF status;
    if (g_app.busy) return;
    if (g_app.remote) xp25w_provider_destroy(g_app.remote);
    g_app.remote = xp25w_provider_create(&g_app.config, reason, sizeof(reason));
    g_app.tool_context.provider = g_app.remote;
    g_app.agent.provider = g_app.remote ? g_app.remote : &g_app.offline;
    g_app.agent.share_remembered = 0;
    xp25_buf_init(&status);
    if (g_app.remote) {
        xp25_buf_puts(&status, "AI provider: ");
        xp25_buf_puts(&status, g_app.remote->name);
        xp25_buf_puts(&status, " (");
        xp25_buf_puts(&status, g_app.config.model);
        xp25_buf_puts(&status, "); offline assistant is the fallback.");
    } else if (g_app.config.provider == XP25_PROVIDER_OFFLINE) {
        xp25_buf_puts(&status, "Offline assistant: no data leaves this computer.");
    } else {
        xp25_buf_puts(&status, "Offline assistant (AI provider not available: ");
        xp25_buf_puts(&status, reason);
        xp25_buf_puts(&status, ")");
    }
    lstrcpynA(g_app.provider_note, xp25_buf_cstr(&status), sizeof(g_app.provider_note));
    app_set_status(g_app.provider_note);
    xp25_buf_free(&status);
}

static DWORD WINAPI worker(void *param)
{
    char *text = (char *)param;
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    xp25_agent_turn(&g_app.agent, text);
    xp25_free(text);
    CoUninitialize();
    PostMessageW(g_app.window, WM_CLIPPY_DONE, 0, 0);
    return 0;
}

void controller_send(const char *utf8)
{
    DWORD id;
    char *copy;
    if (g_app.busy || !utf8 || !*utf8) return;
    copy = xp25_strdup(utf8);
    if (!copy) return;
    chat_add(g_app.chat, CK_USER, NULL, utf8, NULL, 1);
    g_app.busy = 1;
    InterlockedExchange(&g_app.cancel, 0);
    EnableWindow(g_app.send, FALSE);
    EnableWindow(g_app.stop, TRUE);
    if (g_app.mascot) g_app.mascot->set_state(g_app.mascot, MASCOT_THINKING);
    g_app.worker = CreateThread(NULL, 0, worker, copy, 0, &id);
    if (!g_app.worker) {
        xp25_free(copy);
        g_app.busy = 0;
        EnableWindow(g_app.send, TRUE);
        EnableWindow(g_app.stop, FALSE);
        chat_add(g_app.chat, CK_ERROR, "Problem", "Could not start the assistant thread.", NULL, 0);
    }
}

void controller_stop(void) { InterlockedExchange(&g_app.cancel, 1); }

void controller_shutdown(void)
{
    controller_stop();
    if (g_app.worker) {
        WaitForSingleObject(g_app.worker, 15000);
        CloseHandle(g_app.worker);
        g_app.worker = NULL;
    }
    if (g_app.remote) xp25w_provider_destroy(g_app.remote);
    g_app.remote = NULL;
    xp25_agent_free(&g_app.agent);
    xp25_registry_free(&g_app.registry);
}

/* One-line, human summary of a tool result for the collapsed chat item. */
static void summarize(const char *tool, const char *json, XP25_BUF *out)
{
    XP25_JDOC doc;
    const XP25_JNODE *r, *error;
    xp25_i64 v = 0;
    if (!json || !xp25_json_parse(&doc, json, strlen(json)) || doc.root->type != XP25_JOBJ) {
        xp25_buf_puts(out, "Result could not be read.");
        xp25_json_free(&doc);
        return;
    }
    r = doc.root;
    error = xp25_json_get(r, "error");
    if (!strcmp(tool, "cmd_execute") && xp25_json_get(r, "exit_code")) {
        const char *output = xp25_json_string(r, "output");
        xp25_json_i64(r, "exit_code", &v);
        xp25_buf_puts(out, xp25_json_flag(r, "ok", 0) ? "Command finished, exit code " : "Command FAILED, exit code ");
        xp25_buf_i64(out, v);
        if (xp25_json_flag(r, "timed_out", 0)) xp25_buf_puts(out, " (time limit reached)");
        if (output && *output) {
            xp25_buf_puts(out, ". Output: ");
            xp25_buf_append(out, output, xp25_utf8_clip(output, 240));
        }
    } else if (error) {
        xp25_buf_puts(out, xp25_json_string(error, "message") ? xp25_json_string(error, "message") : "The tool failed.");
    } else if (!strcmp(tool, "eventlog_read")) {
        const XP25_JNODE *counts = xp25_json_get(r, "counts");
        const XP25_JNODE *records = xp25_json_get(r, "records");
        xp25_buf_puts(out, xp25_json_string(r, "log") ? xp25_json_string(r, "log") : "Event");
        xp25_buf_puts(out, " log: ");
        xp25_buf_u64(out, records ? (xp25_u64)records->count : 0);
        xp25_buf_puts(out, " records shown; ");
        xp25_json_i64(counts, "error", &v); xp25_buf_i64(out, v); xp25_buf_puts(out, " errors, ");
        xp25_json_i64(counts, "warning", &v); xp25_buf_i64(out, v); xp25_buf_puts(out, " warnings in the period.");
        if (records && records->child) {
            const char *m = xp25_json_string(records->child, "message");
            xp25_buf_puts(out, " Latest: ");
            xp25_buf_puts(out, xp25_json_string(records->child, "source") ? xp25_json_string(records->child, "source") : "");
            xp25_buf_puts(out, " - ");
            if (m) xp25_buf_append(out, m, xp25_utf8_clip(m, 160));
        }
    } else if (!strcmp(tool, "process_list")) {
        const XP25_JNODE *first = xp25_json_at(xp25_json_get(r, "processes"), 0);
        xp25_json_i64(r, "total", &v);
        xp25_buf_i64(out, v);
        xp25_buf_puts(out, " processes; CPU ");
        xp25_json_i64(r, "cpu_busy_percent", &v);
        xp25_buf_i64(out, v);
        xp25_buf_puts(out, "% busy");
        if (first) {
            xp25_buf_puts(out, "; busiest ");
            xp25_buf_puts(out, xp25_json_string(first, "name") ? xp25_json_string(first, "name") : "?");
            xp25_json_i64(first, "cpu_percent", &v);
            xp25_buf_puts(out, " (");
            xp25_buf_i64(out, v);
            xp25_buf_puts(out, "%)");
        }
    } else if (!strcmp(tool, "file_search")) {
        xp25_json_i64(r, "total", &v);
        xp25_buf_i64(out, v);
        xp25_buf_puts(out, v == 1 ? " file found: " : " files found: ");
        xp25_buf_puts(out, xp25_json_string(r, "description") ? xp25_json_string(r, "description") : "");
    } else {
        size_t n = xp25_utf8_clip(json, 200);
        xp25_buf_append(out, json, n);
        if (n < strlen(json)) xp25_buf_puts(out, "...");
    }
    xp25_json_free(&doc);
}

void controller_event(XP25_EVENT *e)
{
    XP25_BUF title, text;
    xp25_buf_init(&title);
    xp25_buf_init(&text);
    switch (e->kind) {
    case XP25_EV_THINKING:
        xp25_buf_puts(&text, "Thinking (");
        xp25_buf_puts(&text, e->text);
        xp25_buf_puts(&text, ")...");
        app_set_status(xp25_buf_cstr(&text));
        if (g_app.mascot) g_app.mascot->set_state(g_app.mascot, MASCOT_THINKING);
        break;
    case XP25_EV_TOOL_START:
        xp25_buf_puts(&text, "Running ");
        xp25_buf_puts(&text, e->tool);
        xp25_buf_puts(&text, ": ");
        xp25_buf_puts(&text, e->detail ? e->detail : e->text);
        app_set_status(xp25_buf_cstr(&text));
        if (g_app.mascot) g_app.mascot->set_state(g_app.mascot, MASCOT_WORKING);
        break;
    case XP25_EV_TOOL_DONE:
        xp25_buf_puts(&title, e->tool);
        xp25_buf_puts(&title, e->ok ? ": completed" : ": failed");
        summarize(e->tool, e->detail, &text);
        chat_add(g_app.chat, CK_TOOL, xp25_buf_cstr(&title), xp25_buf_cstr(&text), e->detail, e->ok);
        break;
    case XP25_EV_TOOL_DENIED:
        xp25_buf_puts(&title, e->tool ? e->tool : "tool");
        xp25_buf_puts(&title, ": not run");
        xp25_buf_puts(&text, e->text);
        if (e->detail) { xp25_buf_puts(&text, "\nRequested: "); xp25_buf_puts(&text, e->detail); }
        chat_add(g_app.chat, CK_DENIED, xp25_buf_cstr(&title), xp25_buf_cstr(&text), NULL, 0);
        break;
    case XP25_EV_ASSISTANT:
        chat_add(g_app.chat, CK_ASSISTANT, NULL, e->text, NULL, 1);
        if (g_app.mascot) g_app.mascot->set_state(g_app.mascot, MASCOT_SUCCESS);
        break;
    case XP25_EV_ERROR:
        chat_add(g_app.chat, CK_ERROR, "Problem", e->text, NULL, 0);
        if (g_app.mascot) g_app.mascot->set_state(g_app.mascot, MASCOT_ERROR);
        break;
    case XP25_EV_NOTICE:
        chat_add(g_app.chat, CK_NOTICE, NULL, e->text, NULL, e->ok);
        break;
    }
    xp25_buf_free(&title);
    xp25_buf_free(&text);
}

/* UI-thread handlers for the synchronous worker requests. */
LRESULT controller_approve_message(WPARAM wp, LPARAM lp)
{
    int ok;
    if (g_app.mascot) g_app.mascot->set_state(g_app.mascot, MASCOT_ATTENTION);
    ok = dialog_approval(g_app.window, (const char *)wp, (const XP25_PROPOSAL *)lp);
    if (g_app.mascot) g_app.mascot->set_state(g_app.mascot, ok ? MASCOT_WORKING : MASCOT_IDLE);
    return ok;
}

LRESULT controller_share_message(LPARAM lp)
{
    SHARE_REQUEST *r = (SHARE_REQUEST *)lp;
    return dialog_share(g_app.window, r->tool, r->provider, r->preview);
}
