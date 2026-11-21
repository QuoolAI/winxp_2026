/* MerlinAI.exe dialogs: settings, text view, build confirmation, build
   review and the explicit approval for Apply Update / Roll Back. Builder
   replies are untrusted: they are parsed with the bounded JSON reader and
   shown only as text in read-only edit controls. */
#include <windows.h>
#include <string.h>
#include "app.h"

static void set_utf8(HWND dlg, int id, const char *text)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, text, -1, NULL, 0);
    WCHAR *w = n > 0 ? (WCHAR *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)n * sizeof(WCHAR)) : NULL;
    if (!w) return;
    MultiByteToWideChar(CP_UTF8, 0, text, -1, w, n);
    SetDlgItemTextW(dlg, id, w);
    HeapFree(GetProcessHeap(), 0, w);
}

/* ---- text ---- */
typedef struct {
    const WCHAR *title;
    const char *text;
} TEXT_ARGS;

static INT_PTR CALLBACK text_proc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
    if (msg == WM_INITDIALOG) {
        TEXT_ARGS *a = (TEXT_ARGS *)lp;
        SetWindowTextW(dlg, a->title);
        set_utf8(dlg, IDC_TEXT, a->text);
        return TRUE;
    }
    if (msg == WM_COMMAND && (LOWORD(wp) == IDOK || LOWORD(wp) == IDCANCEL)) {
        EndDialog(dlg, IDOK);
        return TRUE;
    }
    return FALSE;
}

void merlin_text_dialog(HWND owner, const WCHAR *title, const char *utf8)
{
    TEXT_ARGS a;
    a.title = title;
    a.text = utf8;
    DialogBoxParamW(merlin_instance, MAKEINTRESOURCEW(IDD_TEXT), owner, text_proc, (LPARAM)&a);
}

/* ---- settings ---- */
static INT_PTR CALLBACK settings_proc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
    MERLIN_CONFIG c;
    MERLIN_IDENTITY id;
    (void)lp;
    switch (msg) {
    case WM_INITDIALOG: {
        WCHAR w[80];
        MerlinGetConfig(&c);
        SetDlgItemTextW(dlg, IDC_BUILDER, c.builder);
        SetDlgItemTextW(dlg, IDC_DEPLOY, c.deploy);
        CheckDlgButton(dlg, IDC_AUTO_COLLECT, c.auto_collect ? BST_CHECKED : BST_UNCHECKED);
        CheckDlgButton(dlg, IDC_NOTIFY, c.notify_jobs ? BST_CHECKED : BST_UNCHECKED);
        CheckDlgButton(dlg, IDC_DUMPS, c.collect_dumps ? BST_CHECKED : BST_UNCHECKED);
        SetDlgItemInt(dlg, IDC_INTERVAL, c.collect_minutes, FALSE);
        SetDlgItemInt(dlg, IDC_RETENTION, c.retention_days, FALSE);
        if (!MerlinIsAdmin()) {
            SetDlgItemTextW(dlg, IDC_IDENTITY_STATE, L"Only administrators can change these settings or see the credentials.");
            EnableWindow(GetDlgItem(dlg, IDOK), FALSE);
        } else if (!MerlinGetIdentity(&id)) {
            MerlinUtf8ToWide(id.installation, w, 80);
            SetDlgItemTextW(dlg, IDC_INSTALLATION, w);
            SetDlgItemTextW(dlg, IDC_IDENTITY_STATE, id.has_builder_key && id.has_deploy_key
                                                         ? L"Builder and deployment keys are stored (readable only by administrators). Leave the key fields empty to keep them."
                                                         : L"A key is missing. Paste the keys the builder and the deployment agent issued for this installation.");
            SecureZeroMemory(&id, sizeof(id));
        } else
            SetDlgItemTextW(dlg, IDC_IDENTITY_STATE, L"No installation identity yet. Enter the ID and the keys issued for this installation.");
        return TRUE;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDOK) {
            WCHAR inst[80], bkey[80], dkey[80];
            char inst8[80], bkey8[80], dkey8[80];
            BOOL ok;
            DWORD e;
            ZeroMemory(&c, sizeof(c));
            GetDlgItemTextW(dlg, IDC_BUILDER, c.builder, 256);
            GetDlgItemTextW(dlg, IDC_DEPLOY, c.deploy, 256);
            c.auto_collect = IsDlgButtonChecked(dlg, IDC_AUTO_COLLECT) == BST_CHECKED;
            c.notify_jobs = IsDlgButtonChecked(dlg, IDC_NOTIFY) == BST_CHECKED;
            c.collect_dumps = IsDlgButtonChecked(dlg, IDC_DUMPS) == BST_CHECKED;
            c.collect_minutes = GetDlgItemInt(dlg, IDC_INTERVAL, &ok, FALSE);
            if (!ok) c.collect_minutes = 30;
            c.retention_days = GetDlgItemInt(dlg, IDC_RETENTION, &ok, FALSE);
            if (!ok) c.retention_days = 90;
            e = MerlinSetConfig(&c);
            if (e) {
                MessageBoxW(dlg, e == ERROR_INVALID_PARAMETER ? L"Check the values: endpoints must be http://host:port, the interval 0-1440 minutes and retention 1-3650 days."
                                                              : L"The settings could not be saved.",
                            L"MerlinAI", MB_OK | MB_ICONWARNING);
                return TRUE;
            }
            GetDlgItemTextW(dlg, IDC_INSTALLATION, inst, 80);
            GetDlgItemTextW(dlg, IDC_BUILDER_KEY, bkey, 80);
            GetDlgItemTextW(dlg, IDC_DEPLOY_KEY, dkey, 80);
            MerlinWideToUtf8(inst, inst8, sizeof(inst8));
            MerlinWideToUtf8(bkey, bkey8, sizeof(bkey8));
            MerlinWideToUtf8(dkey, dkey8, sizeof(dkey8));
            if (inst8[0]) {
                e = MerlinSetIdentity(inst8, bkey8, dkey8);
                if (e) {
                    MessageBoxW(dlg, L"The installation identity was not saved: the ID must be letters, digits, '-' or '_', and each key 64 lowercase hexadecimal characters.",
                                L"MerlinAI", MB_OK | MB_ICONWARNING);
                    SecureZeroMemory(bkey, sizeof(bkey));
                    SecureZeroMemory(dkey, sizeof(dkey));
                    SecureZeroMemory(bkey8, sizeof(bkey8));
                    SecureZeroMemory(dkey8, sizeof(dkey8));
                    return TRUE;
                }
            }
            SecureZeroMemory(bkey, sizeof(bkey));
            SecureZeroMemory(dkey, sizeof(dkey));
            SecureZeroMemory(bkey8, sizeof(bkey8));
            SecureZeroMemory(dkey8, sizeof(dkey8));
            EndDialog(dlg, IDOK);
            return TRUE;
        }
        if (LOWORD(wp) == IDCANCEL) {
            EndDialog(dlg, IDCANCEL);
            return TRUE;
        }
        break;
    }
    return FALSE;
}

void merlin_settings_dialog(HWND owner)
{
    DialogBoxParamW(merlin_instance, MAKEINTRESOURCEW(IDD_SETTINGS), owner, settings_proc, 0);
}

/* ---- build confirmation ---- */
typedef struct {
    const MERLIN_PROBLEM *const *problems;
    int count;
    char *explanation;
    int size;
} BUILD_ARGS;

static INT_PTR CALLBACK build_proc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
    static BUILD_ARGS *a;
    switch (msg) {
    case WM_INITDIALOG: {
        int i;
        a = (BUILD_ARGS *)lp;
        for (i = 0; i < a->count; ++i) {
            WCHAR w[400];
            char line[400];
            merlin_copy(line, sizeof(line), a->problems[i]->title);
            merlin_append(line, sizeof(line), "  [");
            merlin_append(line, sizeof(line), a->problems[i]->component);
            merlin_append(line, sizeof(line), ", ");
            merlin_append_ulong(line, sizeof(line), a->problems[i]->count);
            merlin_append(line, sizeof(line), " occurrence(s)]");
            MerlinUtf8ToWide(line, w, 400);
            SendDlgItemMessageW(dlg, IDC_BUILD_LIST, LB_ADDSTRING, 0, (LPARAM)w);
        }
        SetDlgItemTextW(dlg, IDC_BUILD_EXPLAIN,
                        L"The MerlinAI Builder will: identify the XP25 components involved; map them to their source and build "
                        L"provenance; investigate each failure (which may be caused by another program, the configuration, the "
                        L"virtual hardware or missing resources rather than XP25); change XP25 source only where a change is "
                        L"justified, in a workspace for this computer alone; rebuild the changed components with the NT toolchain; "
                        L"assemble a candidate system image for this computer; and test it, before and after, against these problems "
                        L"and the regression suites.\r\n\r\nThis computer is not changed. You will review the result and decide "
                        L"whether to apply it.");
        return TRUE;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDOK) {
            WCHAR note[512];
            GetDlgItemTextW(dlg, IDC_BUILD_NOTE, note, 512);
            MerlinWideToUtf8(note, a->explanation, a->size);
            merlin_sanitize_line(a->explanation);
            EndDialog(dlg, IDOK);
            return TRUE;
        }
        if (LOWORD(wp) == IDCANCEL) {
            EndDialog(dlg, IDCANCEL);
            return TRUE;
        }
        break;
    }
    return FALSE;
}

int merlin_confirm_build(HWND owner, const MERLIN_PROBLEM *const *problems, int count, char *explanation, int size)
{
    BUILD_ARGS a;
    a.problems = problems;
    a.count = count;
    a.explanation = explanation;
    a.size = size;
    explanation[0] = 0;
    return (int)DialogBoxParamW(merlin_instance, MAKEINTRESOURCEW(IDD_BUILD), owner, build_proc, (LPARAM)&a);
}

/* ---- job record rendering ---- */
static void add(char *out, int size, const char *a, const char *b)
{
    merlin_append(out, size, a);
    if (b) merlin_append(out, size, b);
}

static void string_list(const MERLIN_JSON_DOC *doc, int node, char *out, int size, const char *empty)
{
    int i;
    char item[MERLIN_LONG];
    if (merlin_json_element(doc, node, 0) < 0) {
        add(out, size, "  ", empty);
        add(out, size, "\r\n", NULL);
        return;
    }
    for (i = 0; merlin_json_get_string(doc, merlin_json_element(doc, node, i), item, sizeof(item)); ++i) {
        merlin_sanitize_line(item);
        add(out, size, "  - ", item);
        add(out, size, "\r\n", NULL);
    }
}

void merlin_job_text(const char *json, char *out, int size)
{
    MERLIN_JSON_DOC *doc = (MERLIN_JSON_DOC *)HeapAlloc(GetProcessHeap(), 0, sizeof(MERLIN_JSON_DOC));
    char v[MERLIN_LONG], w[MERLIN_LONG];
    int node, i, row, ready = 0;
    out[0] = 0;
    if (!doc || !merlin_json_parse(doc, json, (size_t)lstrlenA(json))) {
        merlin_copy(out, size, "The builder sent a record MerlinAI cannot read.");
        if (doc) HeapFree(GetProcessHeap(), 0, doc);
        return;
    }
#define FIELD(key) (merlin_json_member_string(doc, 0, key, v, sizeof(v)) ? (merlin_sanitize_line(v), v) : "")
    add(out, size, "Build ", FIELD("job"));
    add(out, size, "\r\nStatus: ", FIELD("status"));
    add(out, size, " (", FIELD("stage"));
    add(out, size, ")\r\nRequested: ", FIELD("created"));
    add(out, size, "   Last update: ", FIELD("updated"));
    node = merlin_json_member(doc, 0, "investigator");
    add(out, size, "\r\nInvestigated by: ", merlin_json_member_string(doc, node, "description", w, sizeof(w)) ? w : "unknown");
    add(out, size, "\r\n\r\nPROBLEMS INVESTIGATED\r\n", NULL);
    node = merlin_json_member(doc, 0, "problems");
    for (i = 0; (row = merlin_json_element(doc, node, i)) >= 0; ++i) {
        merlin_json_member_string(doc, row, "title", w, sizeof(w));
        merlin_sanitize_line(w);
        add(out, size, "  - ", w);
        merlin_json_member_string(doc, row, "result", w, sizeof(w));
        merlin_sanitize_line(w);
        add(out, size, "\r\n      Result: ", w);
        if (merlin_json_member_string(doc, row, "conclusion", w, sizeof(w))) {
            merlin_sanitize_line(w);
            add(out, size, "\r\n      Conclusion: ", w);
        }
        add(out, size, "\r\n", NULL);
    }
    add(out, size, "\r\nANALYSIS\r\n  ", FIELD("analysis"));
    add(out, size, "\r\n\r\nCHANGES MADE\r\n", NULL);
    node = merlin_json_member(doc, 0, "changes");
    if (merlin_json_element(doc, node, 0) < 0) add(out, size, "  No source change was made.\r\n", NULL);
    for (i = 0; (row = merlin_json_element(doc, node, i)) >= 0; ++i) {
        merlin_json_member_string(doc, row, "file", w, sizeof(w));
        merlin_sanitize_line(w);
        add(out, size, "  - ", w);
        if (merlin_json_member_string(doc, row, "summary", w, sizeof(w))) {
            merlin_sanitize_line(w);
            add(out, size, ": ", w);
        }
        add(out, size, "\r\n", NULL);
    }
    add(out, size, "\r\nSOURCE FILES MODIFIED\r\n", NULL);
    string_list(doc, merlin_json_member(doc, 0, "source_files"), out, size, "none");
    add(out, size, "\r\nCOMPONENTS REBUILT\r\n", NULL);
    string_list(doc, merlin_json_member(doc, 0, "rebuilt"), out, size, "none");
    add(out, size, "\r\nTESTS EXECUTED\r\n", NULL);
    node = merlin_json_member(doc, 0, "tests");
    if (merlin_json_element(doc, node, 0) < 0) add(out, size, "  none yet\r\n", NULL);
    for (i = 0; (row = merlin_json_element(doc, node, i)) >= 0; ++i) {
        merlin_json_member_string(doc, row, "name", w, sizeof(w));
        merlin_sanitize_line(w);
        add(out, size, "  - ", w);
        if (merlin_json_member_string(doc, row, "mode", w, sizeof(w)) && w[0]) {
            merlin_sanitize_line(w);
            add(out, size, " [", w);
            add(out, size, "]", NULL);
        }
        merlin_json_member_string(doc, row, "result", w, sizeof(w));
        merlin_sanitize_line(w);
        add(out, size, ": ", w);
        if (merlin_json_member_string(doc, row, "detail", w, sizeof(w)) && w[0]) {
            merlin_sanitize_line(w);
            add(out, size, " \x2d ", w);
        }
        add(out, size, "\r\n", NULL);
    }
    add(out, size, "\r\nPROBLEMS FIXED\r\n", NULL);
    string_list(doc, merlin_json_member(doc, 0, "fixed"), out, size, "none verified");
    add(out, size, "\r\nKNOWN LIMITATIONS\r\n", NULL);
    string_list(doc, merlin_json_member(doc, 0, "limitations"), out, size, "none reported");
    add(out, size, "\r\nCOMPATIBILITY RISKS\r\n", NULL);
    string_list(doc, merlin_json_member(doc, 0, "risks"), out, size, "none reported");
    add(out, size, "\r\nUSER DATA\r\n  ", FIELD("data_migration"));
    add(out, size, "\r\n\r\nROLLBACK\r\n  ", FIELD("rollback"));
    node = merlin_json_member(doc, 0, "candidate");
    add(out, size, "\r\n\r\nCANDIDATE IMAGE\r\n  Revision: ", merlin_json_member_string(doc, node, "revision", w, sizeof(w)) ? w : "-");
    add(out, size, "\r\n  Image SHA-256: ", merlin_json_member_string(doc, node, "sha256", w, sizeof(w)) ? w : "-");
    add(out, size, "\r\n  Update content SHA-256: ", merlin_json_member_string(doc, node, "delta_sha256", w, sizeof(w)) ? w : "-");
    add(out, size, "\r\n  Built on baseline: ", merlin_json_member_string(doc, node, "base", w, sizeof(w)) ? w : "-");
    merlin_json_get_bool(doc, merlin_json_member(doc, 0, "ready_to_apply"), &ready);
    add(out, size, "\r\n\r\nREADY TO APPLY: ", ready ? "yes" : "no");
    if (merlin_json_member_string(doc, 0, "not_ready_reason", w, sizeof(w)) && w[0]) {
        merlin_sanitize_line(w);
        add(out, size, " \x2d ", w);
    }
    add(out, size, "\r\n", NULL);
#undef FIELD
    HeapFree(GetProcessHeap(), 0, doc);
}

static int job_ready(const char *json, char *job, int job_size, char *sha, int sha_size)
{
    MERLIN_JSON_DOC *doc = (MERLIN_JSON_DOC *)HeapAlloc(GetProcessHeap(), 0, sizeof(MERLIN_JSON_DOC));
    int ready = 0, cand;
    job[0] = sha[0] = 0;
    if (doc && merlin_json_parse(doc, json, (size_t)lstrlenA(json))) {
        merlin_json_get_bool(doc, merlin_json_member(doc, 0, "ready_to_apply"), &ready);
        merlin_json_member_string(doc, 0, "job", job, job_size);
        cand = merlin_json_member(doc, 0, "candidate");
        merlin_json_member_string(doc, cand, "delta_sha256", sha, sha_size);
        if (!merlin_token_valid(job, MERLIN_ID_SIZE - 1) || !merlin_hex_valid(sha, 64)) ready = 0;
    }
    if (doc) HeapFree(GetProcessHeap(), 0, doc);
    return ready;
}

/* ---- review ---- */
typedef struct {
    const char *json;
    int allow_apply;
} REVIEW_ARGS;

static INT_PTR CALLBACK review_proc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
    if (msg == WM_INITDIALOG) {
        REVIEW_ARGS *a = (REVIEW_ARGS *)lp;
        char *text = (char *)HeapAlloc(GetProcessHeap(), 0, 65536);
        char job[MERLIN_ID_SIZE], sha[80];
        if (text) {
            merlin_job_text(a->json, text, 65536);
            set_utf8(dlg, IDC_REVIEW_TEXT, text);
            HeapFree(GetProcessHeap(), 0, text);
        }
        EnableWindow(GetDlgItem(dlg, IDC_REVIEW_APPLY), a->allow_apply && job_ready(a->json, job, sizeof(job), sha, sizeof(sha)));
        merlin_serial("XP25_MERLIN_UI_REVIEW_SHOWN");
        return TRUE;
    }
    if (msg == WM_COMMAND && (LOWORD(wp) == IDOK || LOWORD(wp) == IDCANCEL || LOWORD(wp) == IDC_REVIEW_APPLY)) {
        EndDialog(dlg, LOWORD(wp));
        return TRUE;
    }
    return FALSE;
}

int merlin_review_job(HWND owner, const char *json, int allow_apply)
{
    REVIEW_ARGS a;
    a.json = json;
    a.allow_apply = allow_apply;
    return (int)DialogBoxParamW(merlin_instance, MAKEINTRESOURCEW(IDD_REVIEW), owner, review_proc, (LPARAM)&a);
}

/* ---- approval ---- */
typedef struct {
    const char *json;
    char *approval;
    int size;
    BOOL rollback;
    char job[MERLIN_ID_SIZE];
    char sha[80];
} APPROVE_ARGS;

static INT_PTR CALLBACK approve_proc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
    static APPROVE_ARGS *a;
    switch (msg) {
    case WM_INITDIALOG: {
        char text[1500];
        a = (APPROVE_ARGS *)lp;
        if (a->rollback) {
            SetWindowTextW(dlg, L"Roll Back to the Previous System");
            SetDlgItemTextW(dlg, IDC_APPROVE_CHECK, L"I want to return this computer to the previous system image.");
            SetDlgItemTextW(dlg, IDOK, L"&Roll Back");
            merlin_copy(text, sizeof(text),
                        "The deployment agent will shut Windows down and start this computer from the system image it kept before "
                        "the last update. Changes made to this computer since that update (documents, settings, installed "
                        "programs) are kept by the agent with the newer image but are not visible after rolling back.");
        } else {
            merlin_copy(text, sizeof(text), "Build ");
            merlin_append(text, sizeof(text), a->job);
            merlin_append(text, sizeof(text), " will replace this computer's system image.\r\n\r\nUpdate content SHA-256: ");
            merlin_append(text, sizeof(text), a->sha);
            merlin_append(text, sizeof(text),
                          "\r\n\r\nThe deployment agent on the host keeps the current system image and this computer's settings, "
                          "verifies the update against this build record, shuts Windows down, applies only the changed system files to "
                          "a new image layered on the current one (your documents, settings and programs stay), starts it and checks "
                          "that it is healthy. If the check fails, the agent restores the current system automatically.");
        }
        set_utf8(dlg, IDC_APPROVE_TEXT, text);
        EnableWindow(GetDlgItem(dlg, IDOK), FALSE);
        return TRUE;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDC_APPROVE_CHECK) {
            EnableWindow(GetDlgItem(dlg, IDOK), IsDlgButtonChecked(dlg, IDC_APPROVE_CHECK) == BST_CHECKED);
            return TRUE;
        }
        if (LOWORD(wp) == IDOK && IsDlgButtonChecked(dlg, IDC_APPROVE_CHECK) == BST_CHECKED) {
            MERLIN_JSON_OUT j;
            WCHAR who[128];
            DWORD n = 128;
            char user[128], time[MERLIN_TIME_SIZE];
            FILETIME ft;
            ULARGE_INTEGER v;
            user[0] = 0;
            if (GetUserNameW(who, &n)) MerlinWideToUtf8(who, user, sizeof(user));
            GetSystemTimeAsFileTime(&ft);
            v.LowPart = ft.dwLowDateTime;
            v.HighPart = ft.dwHighDateTime;
            merlin_format_time((unsigned long)(v.QuadPart / 10000000 - (ULONGLONG)116444736 * 100), time);
            merlin_json_begin(&j, a->approval, (size_t)a->size);
            merlin_json_object(&j);
            if (!a->rollback) {
                merlin_json_key(&j, "job");
                merlin_json_string(&j, a->job);
                merlin_json_key(&j, "delta_sha256");
                merlin_json_string(&j, a->sha);
            }
            merlin_json_key(&j, "approved_by");
            merlin_json_string(&j, user);
            merlin_json_key(&j, "approved_at");
            merlin_json_string(&j, time);
            merlin_json_key(&j, "statement");
            merlin_json_string(&j, a->rollback ? "The user asked to return to the previous system image."
                                               : "The user reviewed this build and approved replacing the system image.");
            merlin_json_end_object(&j);
            EndDialog(dlg, merlin_json_done(&j) ? IDOK : IDCANCEL);
            return TRUE;
        }
        if (LOWORD(wp) == IDCANCEL) {
            EndDialog(dlg, IDCANCEL);
            return TRUE;
        }
        break;
    }
    return FALSE;
}

int merlin_approve(HWND owner, const char *json, char *approval, int size, BOOL rollback)
{
    APPROVE_ARGS a;
    ZeroMemory(&a, sizeof(a));
    a.json = json;
    a.approval = approval;
    a.size = size;
    a.rollback = rollback;
    approval[0] = 0;
    if (!rollback && (!json || !job_ready(json, a.job, sizeof(a.job), a.sha, sizeof(a.sha)))) {
        MessageBoxW(owner, L"This build is not ready to apply. Review it for the reason.", L"MerlinAI", MB_OK | MB_ICONINFORMATION);
        return IDCANCEL;
    }
    return (int)DialogBoxParamW(merlin_instance, MAKEINTRESOURCEW(IDD_APPROVE), owner, approve_proc, (LPARAM)&a);
}
