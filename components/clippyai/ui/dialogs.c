/* ClippyAI dialogs: approval, data sharing, settings and about. */
#include <windows.h>
#include <string.h>
#include "../app/clippyai.h"

typedef struct { const char *tool; const XP25_PROPOSAL *proposal; } APPROVAL;
typedef struct { const char *tool, *provider, *preview; } SHARE;

static void set_text(HWND dlg, int id, const char *utf8)
{
    WCHAR *w = xp25w_wide(utf8 ? utf8 : "");
    SetDlgItemTextW(dlg, id, w ? w : L"");
    xp25_free(w);
}

/* Edit controls need CRLF line breaks. */
static void set_multiline(HWND dlg, int id, const char *utf8)
{
    XP25_BUF b;
    const char *p;
    xp25_buf_init(&b);
    for (p = utf8 ? utf8 : ""; *p; ++p) {
        if (*p == '\n' && (p == utf8 || p[-1] != '\r')) xp25_buf_putc(&b, '\r');
        xp25_buf_putc(&b, *p);
    }
    set_text(dlg, id, xp25_buf_cstr(&b));
    xp25_buf_free(&b);
}

static INT_PTR CALLBACK approval_proc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
    if (msg == WM_INITDIALOG) {
        APPROVAL *a = (APPROVAL *)lp;
        const XP25_PROPOSAL *p = a->proposal;
        set_text(dlg, IDC_AP_TOOL, a->tool);
        set_text(dlg, IDC_AP_ACTION, p->action[0] ? p->action : a->tool);
        set_multiline(dlg, IDC_AP_COMMAND, p->command);
        set_text(dlg, IDC_AP_TARGET, p->target);
        set_multiline(dlg, IDC_AP_EFFECTS, p->effects);
        set_text(dlg, IDC_AP_LEVEL, p->perm == XP25_PERM_PRIVILEGED ?
                 "Privileged: performed by the XP25 administrator broker after your approval" :
                 "Requires your approval: nothing has been changed yet");
        set_text(dlg, IDC_AP_DIGEST, p->digest);
        MessageBeep(MB_ICONEXCLAMATION);
        SetForegroundWindow(dlg);
        SetFocus(GetDlgItem(dlg, IDCANCEL));
        return FALSE;
    }
    if (msg == WM_COMMAND && (LOWORD(wp) == IDOK || LOWORD(wp) == IDCANCEL)) {
        EndDialog(dlg, LOWORD(wp) == IDOK ? 1 : 0);
        return TRUE;
    }
    return FALSE;
}

int dialog_approval(HWND owner, const char *tool, const XP25_PROPOSAL *proposal)
{
    APPROVAL a;
    a.tool = tool;
    a.proposal = proposal;
    if (!IsWindowVisible(owner)) { ShowWindow(owner, SW_SHOW); SetForegroundWindow(owner); }
    return DialogBoxParamW(g_app.instance, MAKEINTRESOURCEW(IDD_APPROVAL), owner, approval_proc, (LPARAM)&a) == 1;
}

static INT_PTR CALLBACK share_proc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
    if (msg == WM_INITDIALOG) {
        SHARE *s = (SHARE *)lp;
        XP25_BUF text;
        size_t n = xp25_utf8_clip(s->preview ? s->preview : "", 3000);
        char *clip = xp25_strndup(s->preview ? s->preview : "", n);
        xp25_buf_init(&text);
        xp25_buf_puts(&text, "The result of \"");
        xp25_buf_puts(&text, s->tool);
        xp25_buf_puts(&text, "\" may contain logs, file content or command output. Send it to the configured AI provider (");
        xp25_buf_puts(&text, s->provider);
        xp25_buf_puts(&text, ") so it can be analyzed? It is never sent unless you choose to.");
        set_text(dlg, IDC_SH_TEXT, xp25_buf_cstr(&text));
        set_multiline(dlg, IDC_SH_PREVIEW, clip);
        xp25_buf_free(&text);
        xp25_free(clip);
        SetFocus(GetDlgItem(dlg, IDCANCEL));
        return FALSE;
    }
    if (msg == WM_COMMAND) {
        switch (LOWORD(wp)) {
        case IDOK: EndDialog(dlg, XP25_SHARE_ONCE); return TRUE;
        case IDC_SH_ALWAYS: EndDialog(dlg, XP25_SHARE_CONVERSATION); return TRUE;
        case IDCANCEL: EndDialog(dlg, XP25_SHARE_DENY); return TRUE;
        }
    }
    return FALSE;
}

int dialog_share(HWND owner, const char *tool, const char *provider, const char *preview)
{
    SHARE s;
    s.tool = tool;
    s.provider = provider;
    s.preview = preview;
    return (int)DialogBoxParamW(g_app.instance, MAKEINTRESOURCEW(IDD_SHARE), owner, share_proc, (LPARAM)&s);
}

static void get_text(HWND dlg, int id, char *out, size_t size)
{
    WCHAR w[1200];
    GetDlgItemTextW(dlg, id, w, 1200);
    xp25w_copy_utf8(out, size, w);
}

static void settings_read(HWND dlg, XP25_CONFIG *c)
{
    char number[16];
    xp25_u64 v;
    c->provider = (XP25_PROVIDER_KIND)SendDlgItemMessageW(dlg, IDC_ST_PROVIDER, CB_GETCURSEL, 0, 0);
    c->api = (int)SendDlgItemMessageW(dlg, IDC_ST_API, CB_GETCURSEL, 0, 0);
    get_text(dlg, IDC_ST_ENDPOINT, c->endpoint, sizeof(c->endpoint));
    get_text(dlg, IDC_ST_MODEL, c->model, sizeof(c->model));
    get_text(dlg, IDC_ST_CLIENT, c->gateway_client, sizeof(c->gateway_client));
    get_text(dlg, IDC_ST_MASCOT, c->mascot, sizeof(c->mascot));
    get_text(dlg, IDC_ST_TIMEOUT, number, sizeof(number));
    if (xp25_parse_u64(number, strlen(number), &v) && v >= 5 && v <= 600) c->timeout_seconds = (long)v;
    get_text(dlg, IDC_ST_RETRIES, number, sizeof(number));
    if (xp25_parse_u64(number, strlen(number), &v) && v <= 5) c->retries = (long)v;
    c->ai_query_interpretation = IsDlgButtonChecked(dlg, IDC_ST_ROVERAI) == BST_CHECKED;
}

static void store_secret(HWND dlg, int id, const WCHAR *name)
{
    WCHAR w[600];
    char u[1800];
    GetDlgItemTextW(dlg, id, w, 600);
    if (!w[0]) return;              /* blank keeps the stored value */
    xp25w_copy_utf8(u, sizeof(u), w);
    xp25w_secret_set(name, (const unsigned char *)u, (DWORD)strlen(u));
    xp25w_wipe(u, sizeof(u));
    xp25w_wipe(w, sizeof(w));
    SetDlgItemTextW(dlg, id, L"");
}

static INT_PTR CALLBACK settings_proc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
    (void)lp;
    if (msg == WM_INITDIALOG) {
        XP25_CONFIG *c = &g_app.config;
        char number[16];
        XP25_BUF b;
        SendDlgItemMessageW(dlg, IDC_ST_PROVIDER, CB_ADDSTRING, 0, (LPARAM)L"Offline assistant (no network)");
        SendDlgItemMessageW(dlg, IDC_ST_PROVIDER, CB_ADDSTRING, 0, (LPARAM)L"XP25 gateway to OpenAI (authenticated)");
        SendDlgItemMessageW(dlg, IDC_ST_PROVIDER, CB_ADDSTRING, 0, (LPARAM)L"Local OpenAI-compatible server (plain HTTP)");
        SendDlgItemMessageW(dlg, IDC_ST_PROVIDER, CB_ADDSTRING, 0, (LPARAM)L"OpenAI direct HTTPS (unavailable on XP)");
        SendDlgItemMessageW(dlg, IDC_ST_PROVIDER, CB_SETCURSEL, (WPARAM)c->provider, 0);
        SendDlgItemMessageW(dlg, IDC_ST_API, CB_ADDSTRING, 0, (LPARAM)L"Responses API");
        SendDlgItemMessageW(dlg, IDC_ST_API, CB_ADDSTRING, 0, (LPARAM)L"Chat Completions API");
        SendDlgItemMessageW(dlg, IDC_ST_API, CB_SETCURSEL, (WPARAM)c->api, 0);
        set_text(dlg, IDC_ST_ENDPOINT, c->endpoint);
        set_text(dlg, IDC_ST_MODEL, c->model);
        set_text(dlg, IDC_ST_CLIENT, c->gateway_client);
        set_text(dlg, IDC_ST_MASCOT, c->mascot);
        xp25_buf_init(&b);
        xp25_buf_i64(&b, c->timeout_seconds);
        lstrcpynA(number, xp25_buf_cstr(&b), sizeof(number));
        set_text(dlg, IDC_ST_TIMEOUT, number);
        xp25_buf_reset(&b);
        xp25_buf_i64(&b, c->retries);
        lstrcpynA(number, xp25_buf_cstr(&b), sizeof(number));
        set_text(dlg, IDC_ST_RETRIES, number);
        xp25_buf_free(&b);
        CheckDlgButton(dlg, IDC_ST_ROVERAI, c->ai_query_interpretation ? BST_CHECKED : BST_UNCHECKED);
        CheckDlgButton(dlg, IDC_ST_AUTOSTART, app_autostart(0, 0) ? BST_CHECKED : BST_UNCHECKED);
        set_text(dlg, IDC_ST_RESULT, g_app.provider_note);
        return TRUE;
    }
    if (msg != WM_COMMAND) return FALSE;
    switch (LOWORD(wp)) {
    case IDC_ST_TEST: {
        XP25_CONFIG test = g_app.config;
        XP25_PROVIDER *p;
        XP25_REPLY reply;
        char reason[300];
        HCURSOR old = SetCursor(LoadCursor(NULL, IDC_WAIT));
        settings_read(dlg, &test);
        store_secret(dlg, IDC_ST_SECRET, L"GatewaySecret");
        store_secret(dlg, IDC_ST_KEY, L"LocalApiKey");
        p = xp25w_provider_create(&test, reason, sizeof(reason));
        if (!p) set_text(dlg, IDC_ST_RESULT, reason);
        else {
            memset(&reply, 0, sizeof(reply));
            if (xp25w_provider_ask(p, "Reply with the single word READY.", "Connection test from ClippyAI.", &reply) && reply.text) {
                XP25_BUF b;
                xp25_buf_init(&b);
                xp25_buf_puts(&b, "Connected. The model replied: ");
                xp25_buf_append(&b, reply.text, xp25_utf8_clip(reply.text, 120));
                set_text(dlg, IDC_ST_RESULT, xp25_buf_cstr(&b));
                xp25_buf_free(&b);
            } else {
                XP25_BUF b;
                xp25_buf_init(&b);
                xp25_buf_puts(&b, "Failed [");
                xp25_buf_puts(&b, reply.error_code);
                xp25_buf_puts(&b, "]: ");
                xp25_buf_puts(&b, reply.error_message ? reply.error_message : "no answer");
                set_text(dlg, IDC_ST_RESULT, xp25_buf_cstr(&b));
                xp25_buf_free(&b);
            }
            xp25_reply_free(&reply);
            xp25w_provider_destroy(p);
        }
        SetCursor(old);
        return TRUE;
    }
    case IDOK:
        settings_read(dlg, &g_app.config);
        store_secret(dlg, IDC_ST_SECRET, L"GatewaySecret");
        store_secret(dlg, IDC_ST_KEY, L"LocalApiKey");
        xp25w_config_save(&g_app.config);
        app_autostart(1, IsDlgButtonChecked(dlg, IDC_ST_AUTOSTART) == BST_CHECKED);
        EndDialog(dlg, 1);
        return TRUE;
    case IDCANCEL:
        EndDialog(dlg, 0);
        return TRUE;
    }
    return FALSE;
}

int dialog_settings(HWND owner)
{
    return DialogBoxParamW(g_app.instance, MAKEINTRESOURCEW(IDD_SETTINGS), owner, settings_proc, 0) == 1;
}

static INT_PTR CALLBACK about_proc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
    (void)lp;
    if (msg == WM_INITDIALOG) return TRUE;
    if (msg == WM_COMMAND && (LOWORD(wp) == IDOK || LOWORD(wp) == IDCANCEL)) { EndDialog(dlg, 0); return TRUE; }
    return FALSE;
}

void dialog_about(HWND owner)
{
    DialogBoxParamW(g_app.instance, MAKEINTRESOURCEW(IDD_ABOUT), owner, about_proc, 0);
}
