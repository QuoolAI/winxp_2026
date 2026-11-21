/* MerlinAI.exe main window: "MerlinAI — System Health & Updates".

   Four sections as tabs:
     A System Health    observations from the local queue and the image
     B Problem Queue    every discovered and submitted problem, with selection
     C Build an Update  the selected problems and the button that requests a
                        build job (a job, never an installation)
     D Previous Builds  build jobs from the builder: review, apply, discard,
                        roll back
   Network operations run on a worker thread and post WM_MERLIN_DONE. */
#include <windows.h>
#include <commctrl.h>
#include <ole2.h>
#include <string.h>
#include "app.h"

#define TIMER_POLL 1
#define TIMER_COLLECT 2
#define MAX_JOBS 64

static HWND main_window, tabs, status_line, subtitle;
static HWND pages[4][8];
static int page_controls[4];
static HWND health_list, queue_list, filter_box, build_selected, build_status, jobs_list, deploy_state;
static MERLIN_LIST queue;
static int shown[400], shown_count;
static BOOL busy, admin;
static MERLIN_CONFIG config;
static HFONT big_font, bold_font;

typedef struct {
    char job[MERLIN_ID_SIZE];
    char status[24];
    char stage[64];
    char revision[64];
    char created[MERLIN_TIME_SIZE];
    char problems[256];
    int candidate;
} JOB_ROW;
static JOB_ROW jobs[MAX_JOBS];
static int job_count;
static char *job_detail;                 /* last fetched job record (UTF-8 JSON) */
static char last_repair[96];
static char deploy_text[512];

static void request(OPERATION_KIND kind, const char *id);
static void refresh_build_page(void);

static void status(const char *utf8)
{
    WCHAR w[600];
    MerlinUtf8ToWide(utf8, w, 600);
    SetWindowTextW(status_line, w);
}

static void status_error(const char *what, DWORD error, const char *detail)
{
    char text[512];
    merlin_copy(text, sizeof(text), what);
    merlin_append(text, sizeof(text), " (");
    merlin_append(text, sizeof(text), detail && detail[0] ? detail : "error ");
    if (!detail || !detail[0]) merlin_append_ulong(text, sizeof(text), error);
    merlin_append(text, sizeof(text), ")");
    status(text);
}

/* ---- worker ---- */
static DWORD WINAPI worker(LPVOID param)
{
    OPERATION *op = (OPERATION *)param;
    char path[160];
    switch (op->kind) {
    case OpCollect:
        op->error = MerlinCollect(&op->stats);
        break;
    case OpTransfer: {
        const char *ids[64];
        int i;
        for (i = 0; i < op->id_count; ++i) ids[i] = op->ids[i];
        op->error = MerlinTransfer(ids, op->id_count, op->message, sizeof(op->message));
        break;
    }
    case OpBuild: {
        char *body = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 512 * 1024), *manifest;
        MERLIN_PROBLEM *p = (MERLIN_PROBLEM *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(MERLIN_PROBLEM));
        MERLIN_JSON_OUT j;
        WCHAR who[128];
        DWORD n = 128;
        char user[128], time[MERLIN_TIME_SIZE];
        SYSTEMTIME st;
        FILETIME ft;
        ULARGE_INTEGER v;
        int i;
        manifest = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 64 * 1024);
        if (!body || !p || !manifest) {
            op->error = ERROR_NOT_ENOUGH_MEMORY;
            if (body) HeapFree(GetProcessHeap(), 0, body);
            if (p) HeapFree(GetProcessHeap(), 0, p);
            if (manifest) HeapFree(GetProcessHeap(), 0, manifest);
            break;
        }
        user[0] = 0;
        if (GetUserNameW(who, &n)) MerlinWideToUtf8(who, user, sizeof(user));
        GetSystemTime(&st);
        SystemTimeToFileTime(&st, &ft);
        v.LowPart = ft.dwLowDateTime;
        v.HighPart = ft.dwHighDateTime;
        merlin_format_time((unsigned long)(v.QuadPart / 10000000 - (ULONGLONG)116444736 * 100), time);
        MerlinManifestJson(manifest, 64 * 1024);
        merlin_json_begin(&j, body, 512 * 1024);
        merlin_json_object(&j);
        merlin_json_key(&j, "schema");
        merlin_json_string(&j, "xp25-merlin-build/1");
        merlin_json_key(&j, "request");
        merlin_json_object(&j);
        merlin_json_key(&j, "explanation");
        merlin_json_string(&j, op->text);
        merlin_json_key(&j, "requested_by");
        MerlinRedact(user, sizeof(user));
        merlin_json_string(&j, user);
        merlin_json_key(&j, "requested_at");
        merlin_json_string(&j, time);
        merlin_json_end_object(&j);
        merlin_json_key(&j, "problems");
        merlin_json_array(&j);
        for (i = 0; i < op->id_count; ++i) {
            unsigned k;
            if (MerlinQueueLoad(op->ids[i], p)) continue;
            MerlinRedact(p->title, sizeof(p->title));
            MerlinRedact(p->component, sizeof(p->component));
            MerlinRedact(p->impact, sizeof(p->impact));
            MerlinRedact(p->app, sizeof(p->app));
            MerlinRedact(p->module, sizeof(p->module));
            for (k = 0; k < p->evidence_count; ++k) MerlinRedact(p->evidence[k], MERLIN_TEXT);
            merlin_json_problem(&j, p);
        }
        merlin_json_end_array(&j);
        merlin_json_end_object(&j);
        /* The manifest is appended as a raw member: it is JSON already. */
        if (merlin_json_done(&j) && j.used > 1 && lstrlenA(manifest) + j.used + 16 < 512 * 1024) {
            body[j.used - 1] = 0;
            lstrcatA(body, ",\"manifest\":");
            lstrcatA(body, manifest[0] ? manifest : "{}");
            lstrcatA(body, "}");
            op->error = MerlinBuilderCall("POST", "/jobs", body, (DWORD)lstrlenA(body), "application/json", &op->reply);
        } else op->error = ERROR_INSUFFICIENT_BUFFER;
        HeapFree(GetProcessHeap(), 0, body);
        HeapFree(GetProcessHeap(), 0, p);
        HeapFree(GetProcessHeap(), 0, manifest);
        break;
    }
    case OpJobs:
        op->error = MerlinBuilderCall("GET", "/jobs", NULL, 0, NULL, &op->reply);
        break;
    case OpJob:
    case OpCancel:
    case OpDiscard:
        merlin_copy(path, sizeof(path), "/jobs/");
        merlin_append(path, sizeof(path), op->ids[0]);
        if (op->kind == OpJob) op->error = MerlinBuilderCall("GET", path, NULL, 0, NULL, &op->reply);
        else {
            merlin_append(path, sizeof(path), op->kind == OpCancel ? "/cancel" : "/discard");
            op->error = MerlinBuilderCall("POST", path, "{}", 2, "application/json", &op->reply);
        }
        break;
    case OpApply:
        op->error = MerlinDeployCall("POST", "/apply", op->text, (DWORD)lstrlenA(op->text), &op->reply);
        break;
    case OpRollback:
        op->error = MerlinDeployCall("POST", "/rollback", op->text, (DWORD)lstrlenA(op->text), &op->reply);
        break;
    case OpDeployStatus:
        op->error = MerlinDeployCall("GET", "/status", NULL, 0, &op->reply);
        break;
    }
    PostMessageW(op->notify, WM_MERLIN_DONE, (WPARAM)op->kind, (LPARAM)op);
    return 0;
}

BOOL merlin_start(OPERATION *op)
{
    HANDLE thread;
    if (busy) {
        HeapFree(GetProcessHeap(), 0, op);
        status("MerlinAI is still busy with the previous request.");
        return FALSE;
    }
    op->notify = main_window;
    thread = CreateThread(NULL, 0, worker, op, 0, NULL);
    if (!thread) {
        HeapFree(GetProcessHeap(), 0, op);
        return FALSE;
    }
    CloseHandle(thread);
    busy = TRUE;
    return TRUE;
}

static OPERATION *new_op(OPERATION_KIND kind)
{
    OPERATION *op = (OPERATION *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(OPERATION));
    if (op) op->kind = kind;
    return op;
}

/* ---- helpers ---- */
static void list_columns(HWND list, const WCHAR *const *names, const int *widths, int count)
{
    LVCOLUMNW col;
    int i;
    ZeroMemory(&col, sizeof(col));
    col.mask = LVCF_TEXT | LVCF_WIDTH;
    for (i = 0; i < count; ++i) {
        col.pszText = (LPWSTR)names[i];
        col.cx = widths[i];
        SendMessageW(list, LVM_INSERTCOLUMNW, (WPARAM)i, (LPARAM)&col);
    }
}

static void list_set(HWND list, int row, int col, const char *utf8)
{
    WCHAR w[600];
    LVITEMW item;
    MerlinUtf8ToWide(utf8, w, 600);
    ZeroMemory(&item, sizeof(item));
    item.iItem = row;
    item.iSubItem = col;
    item.mask = LVIF_TEXT;
    item.pszText = w;
    if (!col) {
        item.iItem = (int)SendMessageW(list, LVM_GETITEMCOUNT, 0, 0);
        SendMessageW(list, LVM_INSERTITEMW, 0, (LPARAM)&item);
    } else SendMessageW(list, LVM_SETITEMW, 0, (LPARAM)&item);
}

static HWND control(int page, const WCHAR *cls, const WCHAR *text, DWORD style, int x, int y, int w, int h, int id)
{
    HWND c = CreateWindowExW(!lstrcmpW(cls, WC_LISTVIEWW) ? WS_EX_CLIENTEDGE : 0, cls, text, WS_CHILD | style, x, y, w, h,
                             main_window, (HMENU)(INT_PTR)id, merlin_instance, NULL);
    SendMessageW(c, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
    if (page >= 0 && page_controls[page] < 8) pages[page][page_controls[page]++] = c;
    return c;
}

static void show_page(int page)
{
    int p, i;
    for (p = 0; p < 4; ++p)
        for (i = 0; i < page_controls[p]; ++i) ShowWindow(pages[p][i], p == page ? SW_SHOW : SW_HIDE);
}

/* Ctrl+1..4: switch to a section and put the focus on its main control. */
static void select_page(int page)
{
    HWND focus[4];
    focus[0] = health_list;
    focus[1] = queue_list;
    focus[2] = GetDlgItem(main_window, IDC_BUILD_BUTTON);
    focus[3] = jobs_list;
    SendMessageW(tabs, TCM_SETCURSEL, (WPARAM)page, 0);
    show_page(page);
    if (page == 2) refresh_build_page();
    if (page == 3 && admin && !busy) request(OpJobs, NULL);
    SetFocus(IsWindowEnabled(focus[page]) ? focus[page] : tabs);
    if ((page == 1 || page == 3) && SendMessageW(focus[page], LVM_GETNEXTITEM, (WPARAM)-1, LVNI_FOCUSED) < 0)
        ListView_SetItemState(focus[page], 0, LVIS_FOCUSED | LVIS_SELECTED, LVIS_FOCUSED | LVIS_SELECTED);
}

static BOOL problem_matches(const MERLIN_PROBLEM *p, int filter)
{
    switch (filter) {
    case 1: return p->submitted;
    case 2: return !p->submitted;
    case 3: return !lstrcmpA(p->kind, "crash") || !lstrcmpA(p->kind, "hang");
    case 4: return !lstrcmpA(p->kind, "service") || !lstrcmpA(p->kind, "driver") || !lstrcmpA(p->kind, "storage");
    case 5: return !lstrcmpA(p->kind, "security");
    case 6: return !lstrcmpA(p->status, "excluded");
    default: return lstrcmpA(p->status, "excluded") != 0;
    }
}

static int checked_problems(char ids[][MERLIN_ID_SIZE], int max)
{
    int i, n = 0;
    for (i = 0; i < shown_count && n < max; ++i)
        if (ListView_GetCheckState(queue_list, i)) merlin_copy(ids[n++], MERLIN_ID_SIZE, queue.items[shown[i]].id);
    return n;
}

static void refresh_build_page(void)
{
    char ids[64][MERLIN_ID_SIZE], text[4096];
    int n = checked_problems(ids, 64), i, j;
    WCHAR w[4096];
    text[0] = 0;
    if (!n) merlin_copy(text, sizeof(text), "No problems selected. Tick problems in the Problem Queue first.");
    for (i = 0; i < n; ++i)
        for (j = 0; j < queue.count; ++j)
            if (!lstrcmpA(queue.items[j].id, ids[i])) {
                merlin_append(text, sizeof(text), "- ");
                merlin_append(text, sizeof(text), queue.items[j].title);
                merlin_append(text, sizeof(text), " (");
                merlin_append(text, sizeof(text), queue.items[j].component);
                merlin_append(text, sizeof(text), ")\r\n");
            }
    MultiByteToWideChar(CP_UTF8, 0, text, -1, w, 4096);
    SetWindowTextW(build_selected, w);
    EnableWindow(GetDlgItem(main_window, IDC_BUILD_BUTTON), n > 0 && admin && !busy);
}

static void fill_queue(void)
{
    int i, filter = (int)SendMessageW(filter_box, CB_GETCURSEL, 0, 0);
    char number[24];
    SendMessageW(queue_list, LVM_DELETEALLITEMS, 0, 0);
    shown_count = 0;
    for (i = 0; i < queue.count; ++i) {
        MERLIN_PROBLEM *p = &queue.items[i];
        char impact[300];
        if (!problem_matches(p, filter < 0 ? 0 : filter)) continue;
        shown[shown_count] = i;
        list_set(queue_list, shown_count, 0, p->title);
        list_set(queue_list, shown_count, 1, p->component);
        number[0] = 0;
        merlin_append_ulong(number, sizeof(number), p->count);
        list_set(queue_list, shown_count, 2, number);
        merlin_copy(impact, sizeof(impact), p->severity);
        merlin_append(impact, sizeof(impact), ": ");
        merlin_append(impact, sizeof(impact), p->impact);
        list_set(queue_list, shown_count, 3, impact);
        list_set(queue_list, shown_count, 4, p->status);
        list_set(queue_list, shown_count, 5, p->submitted ? (p->transferred ? "yes, transferred" : "yes") : "discovered");
        list_set(queue_list, shown_count, 6, p->analysis[0] ? p->analysis : (p->job[0] ? p->job : ""));
        ++shown_count;
    }
    {
        char line[96];
        merlin_copy(line, sizeof(line), "XP25_MERLIN_UI_QUEUE_ROWS=");
        merlin_append_ulong(line, sizeof(line), (unsigned long)SendMessageW(queue_list, LVM_GETITEMCOUNT, 0, 0));
        merlin_append(line, sizeof(line), " problems=");
        merlin_append_ulong(line, sizeof(line), (unsigned long)queue.count);
        merlin_serial(line);
    }
    refresh_build_page();
}

static void read_revision(char *out, int size)
{
    HANDLE f = CreateFileW(L"C:\\xp25\\image-revision.txt", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    DWORD got = 0;
    int i;
    out[0] = 0;
    if (f == INVALID_HANDLE_VALUE) {
        merlin_copy(out, size, "not recorded");
        return;
    }
    ReadFile(f, out, (DWORD)size - 1, &got, NULL);
    CloseHandle(f);
    out[got] = 0;
    for (i = 0; out[i]; ++i)
        if (out[i] == '\r' || out[i] == '\n') out[i] = 0;
    merlin_sanitize_line(out);
}

static void fill_health(void)
{
    unsigned long now, last, critical = 0, errors = 0, warnings = 0, crashes = 0, services = 0, security = 0, open = 0;
    char text[300], number[24], revision[128];
    FILETIME ft;
    ULARGE_INTEGER v;
    int i;
    GetSystemTimeAsFileTime(&ft);
    v.LowPart = ft.dwLowDateTime;
    v.HighPart = ft.dwHighDateTime;
    now = (unsigned long)(v.QuadPart / 10000000 - (ULONGLONG)116444736 * 100);
    for (i = 0; i < queue.count; ++i) {
        MERLIN_PROBLEM *p = &queue.items[i];
        BOOL recent = merlin_parse_time(p->last, &last) && now >= last && now - last <= 7UL * 86400UL;
        if (!lstrcmpA(p->status, "excluded") || !lstrcmpA(p->status, "fixed") || !lstrcmpA(p->status, "not_applicable")) continue;
        ++open;
        if (!lstrcmpA(p->severity, "critical")) ++critical;
        else if (!lstrcmpA(p->severity, "error")) ++errors;
        else ++warnings;
        if (recent && (!lstrcmpA(p->kind, "crash") || !lstrcmpA(p->kind, "hang"))) crashes += p->count;
        if (recent && (!lstrcmpA(p->kind, "service") || !lstrcmpA(p->kind, "driver"))) ++services;
        if (!lstrcmpA(p->kind, "security")) ++security;
    }
    SendMessageW(health_list, LVM_DELETEALLITEMS, 0, 0);
    list_set(health_list, 0, 0, "System health");
    list_set(health_list, 0, 1, critical ? "Critical problems need attention" : open ? "Problems need attention" : "No outstanding problems");
    text[0] = 0;
    merlin_append_ulong(text, sizeof(text), open);
    merlin_append(text, sizeof(text), " (critical ");
    merlin_append_ulong(text, sizeof(text), critical);
    merlin_append(text, sizeof(text), ", error ");
    merlin_append_ulong(text, sizeof(text), errors);
    merlin_append(text, sizeof(text), ", warning ");
    merlin_append_ulong(text, sizeof(text), warnings);
    merlin_append(text, sizeof(text), ")");
    list_set(health_list, 1, 0, "Outstanding problems");
    list_set(health_list, 1, 1, text);
    number[0] = 0;
    merlin_append_ulong(number, sizeof(number), crashes);
    list_set(health_list, 2, 0, "Application crashes and hangs (7 days)");
    list_set(health_list, 2, 1, number);
    number[0] = 0;
    merlin_append_ulong(number, sizeof(number), services);
    list_set(health_list, 3, 0, "Failed services and drivers (7 days)");
    list_set(health_list, 3, 1, number);
    number[0] = 0;
    merlin_append_ulong(number, sizeof(number), security);
    list_set(health_list, 4, 0, "Security component findings");
    list_set(health_list, 4, 1, number);
    list_set(health_list, 5, 0, "Last successful repair build");
    list_set(health_list, 5, 1, last_repair[0] ? last_repair : "none yet");
    read_revision(revision, sizeof(revision));
    list_set(health_list, 6, 0, "Current XP25 image revision");
    list_set(health_list, 6, 1, revision);
    list_set(health_list, 7, 0, "MerlinAI Builder");
    list_set(health_list, 7, 1, config.builder[0] ? "configured" : "not configured (Settings)");
    list_set(health_list, 8, 0, "Deployment agent");
    list_set(health_list, 8, 1, config.deploy[0] ? (deploy_text[0] ? deploy_text : "configured") : "not configured (Settings)");
    if (!admin) {
        list_set(health_list, 9, 0, "Your view");
        list_set(health_list, 9, 1, "Only your own reports. System-wide problems, builds and updates need an administrator.");
    }
    {
        char sub[300];
        merlin_copy(sub, sizeof(sub), open ? "" : "No outstanding problems. ");
        if (open) {
            merlin_append_ulong(sub, sizeof(sub), open);
            merlin_append(sub, sizeof(sub), " outstanding problem(s). ");
        }
        merlin_append(sub, sizeof(sub), "Image revision: ");
        merlin_append(sub, sizeof(sub), revision);
        {
            WCHAR w[300];
            MerlinUtf8ToWide(sub, w, 300);
            SetWindowTextW(subtitle, w);
        }
    }
}

static void reload_queue(void)
{
    MerlinFreeList(&queue);
    if (MerlinQueueList(&queue)) queue.count = 0;
    fill_queue();
    fill_health();
}

static void fill_jobs(void)
{
    int i;
    SendMessageW(jobs_list, LVM_DELETEALLITEMS, 0, 0);
    for (i = 0; i < job_count; ++i) {
        list_set(jobs_list, i, 0, jobs[i].job);
        list_set(jobs_list, i, 1, jobs[i].status);
        list_set(jobs_list, i, 2, jobs[i].problems);
        list_set(jobs_list, i, 3, jobs[i].revision);
        list_set(jobs_list, i, 4, jobs[i].candidate ? "available" : "-");
        list_set(jobs_list, i, 5, jobs[i].created);
    }
}

static const char *character_state(const char *job_status)
{
    if (!lstrcmpA(job_status, "investigating") || !lstrcmpA(job_status, "queued")) return "investigating";
    if (!lstrcmpA(job_status, "building") || !lstrcmpA(job_status, "packaging")) return "building";
    if (!lstrcmpA(job_status, "testing")) return "testing";
    if (!lstrcmpA(job_status, "ready") || !lstrcmpA(job_status, "applied")) return "complete";
    if (!lstrcmpA(job_status, "failed")) return "failed";
    return "idle";
}

static BOOL job_active(const char *s)
{
    return !lstrcmpA(s, "queued") || !lstrcmpA(s, "investigating") || !lstrcmpA(s, "building") || !lstrcmpA(s, "packaging") ||
           !lstrcmpA(s, "testing");
}

static void parse_jobs(const char *json, DWORD len)
{
    MERLIN_JSON_DOC *doc = (MERLIN_JSON_DOC *)HeapAlloc(GetProcessHeap(), 0, sizeof(MERLIN_JSON_DOC));
    int list, i, row, old_count = job_count;
    JOB_ROW old[MAX_JOBS];
    BOOL active = FALSE;
    if (!doc) return;
    CopyMemory(old, jobs, sizeof(old));
    job_count = 0;
    if (merlin_json_parse(doc, json, len) && (list = merlin_json_member(doc, 0, "jobs")) >= 0) {
        for (i = 0; (row = merlin_json_element(doc, list, i)) >= 0 && job_count < MAX_JOBS; ++i) {
            JOB_ROW *j = &jobs[job_count];
            int cand, k, problems;
            ZeroMemory(j, sizeof(*j));
            if (!merlin_json_member_string(doc, row, "job", j->job, sizeof(j->job)) || !merlin_token_valid(j->job, MERLIN_ID_SIZE - 1))
                continue;
            merlin_json_member_string(doc, row, "status", j->status, sizeof(j->status));
            merlin_json_member_string(doc, row, "stage", j->stage, sizeof(j->stage));
            merlin_json_member_string(doc, row, "revision", j->revision, sizeof(j->revision));
            merlin_json_member_string(doc, row, "created", j->created, sizeof(j->created));
            cand = merlin_json_member(doc, row, "candidate_available");
            merlin_json_get_bool(doc, cand, &j->candidate);
            problems = merlin_json_member(doc, row, "problems");
            for (k = 0; k < 6; ++k) {
                char t[MERLIN_TEXT];
                if (!merlin_json_get_string(doc, merlin_json_element(doc, problems, k), t, sizeof(t))) break;
                if (k) merlin_append(j->problems, sizeof(j->problems), "; ");
                merlin_append(j->problems, sizeof(j->problems), t);
            }
            merlin_sanitize_line(j->status);
            merlin_sanitize_line(j->problems);
            if (job_active(j->status)) active = TRUE;
            if ((!lstrcmpA(j->status, "ready") || !lstrcmpA(j->status, "applied")) && !last_repair[0]) {
                merlin_copy(last_repair, sizeof(last_repair), j->job);
                merlin_append(last_repair, sizeof(last_repair), " (");
                merlin_append(last_repair, sizeof(last_repair), j->status);
                merlin_append(last_repair, sizeof(last_repair), ")");
            }
            /* Notify about status changes since the previous poll. */
            for (k = 0; k < old_count; ++k)
                if (!lstrcmpA(old[k].job, j->job) && lstrcmpA(old[k].status, j->status)) {
                    char text[200];
                    merlin_copy(text, sizeof(text), "Build ");
                    merlin_append(text, sizeof(text), j->job);
                    merlin_append(text, sizeof(text), " is now ");
                    merlin_append(text, sizeof(text), j->status);
                    if (j->stage[0]) {
                        merlin_append(text, sizeof(text), ": ");
                        merlin_append(text, sizeof(text), j->stage);
                    }
                    status(text);
                    if (config.notify_jobs) {
                        MessageBeep(MB_ICONASTERISK);
                        merlin_character_state(character_state(j->status), text);
                    }
                }
            ++job_count;
        }
    }
    HeapFree(GetProcessHeap(), 0, doc);
    fill_jobs();
    if (active) SetTimer(main_window, TIMER_POLL, 15000, NULL);
    else KillTimer(main_window, TIMER_POLL);
}

static int selected_job(void)
{
    int sel = (int)SendMessageW(jobs_list, LVM_GETNEXTITEM, (WPARAM)-1, LVNI_SELECTED);
    return sel >= 0 && sel < job_count ? sel : -1;
}

static void request(OPERATION_KIND kind, const char *id)
{
    OPERATION *op = new_op(kind);
    if (!op) return;
    if (id) {
        merlin_copy(op->ids[0], MERLIN_ID_SIZE, id);
        op->id_count = 1;
    }
    if (merlin_start(op)) {
        if (kind == OpJobs) status("Asking the MerlinAI Builder for your builds...");
        else if (kind == OpJob) status("Fetching the build record...");
        else if (kind == OpDeployStatus) status("Asking the deployment agent for the update state...");
    }
}

static void on_done(OPERATION *op)
{
    char text[600];
    busy = FALSE;
    switch (op->kind) {
    case OpCollect:
        if (op->error) status_error("Checking for problems failed", op->error, NULL);
        else {
            merlin_copy(text, sizeof(text), "Checked for problems: ");
            merlin_append_ulong(text, sizeof(text), op->stats.new_problems);
            merlin_append(text, sizeof(text), " new problem(s), ");
            merlin_append_ulong(text, sizeof(text), op->stats.new_occurrences);
            merlin_append(text, sizeof(text), " new occurrence(s) from ");
            merlin_append_ulong(text, sizeof(text), op->stats.events_read);
            merlin_append(text, sizeof(text), " event records. Nothing was sent.");
            status(text);
            merlin_serial("XP25_MERLIN_UI_COLLECTED");
        }
        reload_queue();
        break;
    case OpTransfer:
        status(op->message[0] ? op->message : "Transfer finished.");
        reload_queue();
        break;
    case OpBuild: {
        MERLIN_JSON_DOC *doc = (MERLIN_JSON_DOC *)HeapAlloc(GetProcessHeap(), 0, sizeof(MERLIN_JSON_DOC));
        char job[MERLIN_ID_SIZE];
        if (!op->error && (op->reply.status == 202 || op->reply.status == 200) && doc &&
            merlin_json_parse(doc, op->reply.body, op->reply.body_len) &&
            merlin_json_member_string(doc, 0, "job", job, sizeof(job)) && merlin_token_valid(job, MERLIN_ID_SIZE - 1)) {
            int i;
            MERLIN_PROBLEM *p = (MERLIN_PROBLEM *)HeapAlloc(GetProcessHeap(), 0, sizeof(MERLIN_PROBLEM));
            for (i = 0; p && i < op->id_count; ++i)
                if (!MerlinQueueLoad(op->ids[i], p)) {
                    merlin_copy(p->status, sizeof(p->status), "included");
                    merlin_copy(p->job, sizeof(p->job), job);
                    MerlinQueueSave(p);
                }
            if (p) HeapFree(GetProcessHeap(), 0, p);
            merlin_copy(text, sizeof(text), "Build job ");
            merlin_append(text, sizeof(text), job);
            merlin_append(text, sizeof(text), " was started on the MerlinAI Builder. Nothing will be installed until you apply it.");
            status(text);
            SetWindowTextW(build_status, L"");
            {
                WCHAR w[600];
                MerlinUtf8ToWide(text, w, 600);
                SetWindowTextW(build_status, w);
            }
            merlin_serial("XP25_MERLIN_UI_BUILD_REQUESTED");
            merlin_character_state("investigating", "I'll investigate these problems in the MerlinAI Builder.");
            reload_queue();
            request(OpJobs, NULL);
        } else {
            char marker[200];
            status_error("The build request was not accepted", op->error, op->error ? op->reply.error : op->reply.body);
            merlin_copy(marker, sizeof(marker), "XP25_MERLIN_UI_BUILD_FAILED=");
            merlin_append_ulong(marker, sizeof(marker), op->error);
            merlin_append(marker, sizeof(marker), " status=");
            merlin_append_ulong(marker, sizeof(marker), (unsigned long)op->reply.status);
            merlin_append(marker, sizeof(marker), " ");
            merlin_append(marker, sizeof(marker), op->reply.error);
            merlin_serial(marker);
            merlin_character_state("failed", "The builder did not accept the request.");
        }
        if (doc) HeapFree(GetProcessHeap(), 0, doc);
        break;
    }
    case OpJobs:
        if (!op->error && op->reply.status == 200) {
            parse_jobs(op->reply.body, op->reply.body_len);
            merlin_copy(text, sizeof(text), "Builds refreshed: ");
            merlin_append_ulong(text, sizeof(text), (unsigned long)job_count);
            merlin_append(text, sizeof(text), " build job(s).");
            status(text);
        } else status_error("Could not list builds", op->error, op->error ? op->reply.error : NULL);
        fill_health();
        break;
    case OpJob:
        if (!op->error && op->reply.status == 200) {
            if (job_detail) HeapFree(GetProcessHeap(), 0, job_detail);
            job_detail = (char *)HeapAlloc(GetProcessHeap(), 0, op->reply.body_len + 1);
            if (job_detail) {
                CopyMemory(job_detail, op->reply.body, op->reply.body_len + 1);
                status("Build record received.");
                if (merlin_review_job(main_window, job_detail, admin) == IDC_REVIEW_APPLY)
                    PostMessageW(main_window, WM_COMMAND, IDC_APPLY_BUTTON, 0);
            }
        } else status_error("Could not fetch the build", op->error, op->error ? op->reply.error : NULL);
        break;
    case OpCancel:
    case OpDiscard:
        if (!op->error && op->reply.status == 200) status(op->kind == OpCancel ? "The build was cancelled." : "The build was discarded. Its failed evidence is kept by the builder.");
        else status_error("The builder refused", op->error, op->error ? op->reply.error : op->reply.body);
        request(OpJobs, NULL);
        break;
    case OpApply:
    case OpRollback:
        if (!op->error && (op->reply.status == 202 || op->reply.status == 200)) {
            HANDLE token;
            TOKEN_PRIVILEGES tp;
            merlin_serial(op->kind == OpApply ? "XP25_MERLIN_UI_APPLY_ACCEPTED" : "XP25_MERLIN_UI_ROLLBACK_ACCEPTED");
            MessageBoxW(main_window,
                        op->kind == OpApply
                            ? L"The deployment agent accepted the update and staged it.\n\nWindows will now shut down. The agent keeps the current system image, switches this computer to the tested image and starts it again. If the new system does not report healthy, it restores the current one."
                            : L"The deployment agent accepted the rollback.\n\nWindows will now shut down. The agent switches this computer back to the previous system image and starts it again.",
                        L"MerlinAI", MB_OK | MB_ICONINFORMATION);
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
                tp.PrivilegeCount = 1;
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                if (LookupPrivilegeValueW(NULL, SE_SHUTDOWN_NAME, &tp.Privileges[0].Luid))
                    AdjustTokenPrivileges(token, FALSE, &tp, 0, NULL, NULL);
                CloseHandle(token);
            }
            ExitWindowsEx(EWX_SHUTDOWN | EWX_POWEROFF | EWX_FORCEIFHUNG, 0);
        } else {
            status_error(op->kind == OpApply ? "The update was not applied" : "The rollback was refused", op->error,
                         op->error ? op->reply.error : op->reply.body);
            merlin_character_state("failed", "The deployment agent refused the request.");
        }
        break;
    case OpDeployStatus:
        if (!op->error && op->reply.status == 200) {
            MERLIN_JSON_DOC *doc = (MERLIN_JSON_DOC *)HeapAlloc(GetProcessHeap(), 0, sizeof(MERLIN_JSON_DOC));
            char current[96], previous[96], state[64];
            current[0] = previous[0] = state[0] = 0;
            if (doc && merlin_json_parse(doc, op->reply.body, op->reply.body_len)) {
                merlin_json_member_string(doc, 0, "current", current, sizeof(current));
                merlin_json_member_string(doc, 0, "previous", previous, sizeof(previous));
                merlin_json_member_string(doc, 0, "state", state, sizeof(state));
            }
            if (doc) HeapFree(GetProcessHeap(), 0, doc);
            merlin_copy(deploy_text, sizeof(deploy_text), state[0] ? state : "ready");
            merlin_append(deploy_text, sizeof(deploy_text), "; current system ");
            merlin_append(deploy_text, sizeof(deploy_text), current[0] ? current : "unknown");
            merlin_append(deploy_text, sizeof(deploy_text), previous[0] ? "; previous system kept: " : "; no previous system to roll back to");
            merlin_append(deploy_text, sizeof(deploy_text), previous);
            merlin_sanitize_line(deploy_text);
            {
                WCHAR w[600];
                MerlinUtf8ToWide(deploy_text, w, 600);
                SetWindowTextW(deploy_state, w);
            }
            EnableWindow(GetDlgItem(main_window, IDC_ROLLBACK), admin && previous[0]);
            status("Deployment state refreshed.");
            fill_health();
        } else status_error("The deployment agent did not answer", op->error, op->error ? op->reply.error : NULL);
        break;
    }
    MerlinFreeReply(&op->reply);
    HeapFree(GetProcessHeap(), 0, op);
    refresh_build_page();
}

static void create_controls(HWND hwnd)
{
    static const WCHAR *const health_cols[] = { L"Observation", L"Value" };
    static const int health_w[] = { 220, 350 };
    static const WCHAR *const queue_cols[] = { L"Problem", L"Component", L"Occurrences", L"Impact", L"Status", L"Submitted", L"MerlinAI analysis" };
    static const int queue_w[] = { 190, 100, 50, 160, 60, 70, 140 };
    static const WCHAR *const job_cols[] = { L"Build", L"Status", L"Problems addressed", L"Image revision", L"Candidate image", L"Requested" };
    static const int job_w[] = { 140, 70, 160, 90, 70, 110 };
    static const WCHAR *const filters[] = { L"All open problems", L"Submitted by you", L"Discovered automatically", L"Crashes and hangs",
                                            L"Services, drivers and storage", L"Security components", L"Excluded problems" };
    TCITEMW item;
    HWND banner, b;
    int i, x = 16, y = 90;
    LOGFONTW lf;
    main_window = hwnd;
    ZeroMemory(&lf, sizeof(lf));
    lf.lfHeight = -19;
    lf.lfWeight = FW_BOLD;
    lstrcpyW(lf.lfFaceName, L"Trebuchet MS");
    big_font = CreateFontIndirectW(&lf);
    lf.lfHeight = -13;
    bold_font = CreateFontIndirectW(&lf);
    b = CreateWindowExW(0, L"STATIC", NULL, WS_CHILD | WS_VISIBLE | SS_ICON, 12, 10, 32, 32, hwnd, NULL, merlin_instance, NULL);
    SendMessageW(b, STM_SETICON, (WPARAM)LoadIconW(merlin_instance, MAKEINTRESOURCEW(IDI_MERLIN)), 0);
    banner = CreateWindowExW(0, L"STATIC", L"MerlinAI \x2014 System Health & Updates", WS_CHILD | WS_VISIBLE | SS_NOPREFIX, 52, 6, 560, 26, hwnd,
                             (HMENU)IDC_BANNER, merlin_instance, NULL);
    SendMessageW(banner, WM_SETFONT, (WPARAM)big_font, TRUE);
    subtitle = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_NOPREFIX, 52, 34, 560, 18, hwnd, (HMENU)IDC_SUBTITLE, merlin_instance, NULL);
    SendMessageW(subtitle, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
    tabs = CreateWindowExW(0, WC_TABCONTROLW, NULL, WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS, 6, 58, 616, 336, hwnd, (HMENU)IDC_TABS,
                           merlin_instance, NULL);
    SendMessageW(tabs, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
    ZeroMemory(&item, sizeof(item));
    item.mask = TCIF_TEXT;
    item.pszText = L"System Health";
    SendMessageW(tabs, TCM_INSERTITEMW, 0, (LPARAM)&item);
    item.pszText = L"Problem Queue";
    SendMessageW(tabs, TCM_INSERTITEMW, 1, (LPARAM)&item);
    item.pszText = L"Build an Update";
    SendMessageW(tabs, TCM_INSERTITEMW, 2, (LPARAM)&item);
    item.pszText = L"Previous Builds";
    SendMessageW(tabs, TCM_INSERTITEMW, 3, (LPARAM)&item);
    /* A: System Health */
    health_list = control(0, WC_LISTVIEWW, NULL, LVS_REPORT | LVS_NOSORTHEADER | LVS_SINGLESEL, x, y, 590, 250, IDC_HEALTH_LIST);
    list_columns(health_list, health_cols, health_w, 2);
    SendMessageW(health_list, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT);
    control(0, L"BUTTON", L"&Check for problems now", BS_PUSHBUTTON | WS_TABSTOP, x, y + 260, 170, 26, IDC_COLLECT);
    /* B: Problem Queue */
    filter_box = control(1, WC_COMBOBOXW, NULL, CBS_DROPDOWNLIST | WS_VSCROLL | WS_TABSTOP, x, y, 260, 200, IDC_FILTER);
    for (i = 0; i < 7; ++i) SendMessageW(filter_box, CB_ADDSTRING, 0, (LPARAM)filters[i]);
    SendMessageW(filter_box, CB_SETCURSEL, 0, 0);
    queue_list = control(1, WC_LISTVIEWW, NULL, LVS_REPORT | LVS_SHOWSELALWAYS | LVS_SINGLESEL | WS_TABSTOP, x, y + 28, 590, 224, IDC_QUEUE_LIST);
    list_columns(queue_list, queue_cols, queue_w, 7);
    SendMessageW(queue_list, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT | LVS_EX_CHECKBOXES);
    control(1, L"BUTTON", L"&Details...", BS_PUSHBUTTON | WS_TABSTOP, x, y + 260, 90, 26, IDC_DETAILS);
    control(1, L"BUTTON", L"E&xclude / Include", BS_PUSHBUTTON | WS_TABSTOP, x + 98, y + 260, 120, 26, IDC_EXCLUDE);
    control(1, L"BUTTON", L"&Remove", BS_PUSHBUTTON | WS_TABSTOP, x + 226, y + 260, 80, 26, IDC_REMOVE);
    control(1, L"BUTTON", L"&Transfer to builder...", BS_PUSHBUTTON | WS_TABSTOP, x + 314, y + 260, 140, 26, IDC_SENDREP);
    /* C: Build an Update */
    control(2, L"STATIC",
            L"MerlinAI sends the selected problems (redacted, with this computer's component list) to the MerlinAI Builder. "
            L"In an isolated workspace it investigates them against the XP25 source, decides whether a source change is justified, "
            L"rebuilds what it changes, assembles a candidate system image and tests it. It may conclude that no change to XP25 is "
            L"justified. Nothing is installed: you review the result and choose Apply Update yourself.",
            SS_LEFT, x, y, 590, 84, IDC_BUILD_INFO);
    build_selected = control(2, L"EDIT", NULL, ES_MULTILINE | ES_READONLY | WS_VSCROLL | WS_BORDER, x, y + 88, 590, 118, IDC_BUILD_SELECTED);
    b = control(2, L"BUTTON", L"&Build an Update", BS_DEFPUSHBUTTON | WS_TABSTOP, x, y + 214, 200, 40, IDC_BUILD_BUTTON);
    SendMessageW(b, WM_SETFONT, (WPARAM)bold_font, TRUE);
    build_status = control(2, L"STATIC", L"", SS_LEFT | SS_NOPREFIX, x + 212, y + 214, 378, 70, IDC_BUILD_STATUS);
    /* D: Previous Builds */
    jobs_list = control(3, WC_LISTVIEWW, NULL, LVS_REPORT | LVS_SHOWSELALWAYS | LVS_SINGLESEL | WS_TABSTOP, x, y, 590, 206, IDC_JOBS_LIST);
    list_columns(jobs_list, job_cols, job_w, 6);
    SendMessageW(jobs_list, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT);
    deploy_state = control(3, L"STATIC", L"Deployment agent: not asked yet.", SS_LEFT | SS_NOPREFIX, x, y + 210, 590, 30, IDC_DEPLOY_STATE);
    control(3, L"BUTTON", L"Re&view Build...", BS_PUSHBUTTON | WS_TABSTOP, x, y + 260, 96, 26, IDC_REVIEW);
    control(3, L"BUTTON", L"&Apply Update...", BS_PUSHBUTTON | WS_TABSTOP, x + 99, y + 260, 96, 26, IDC_APPLY_BUTTON);
    control(3, L"BUTTON", L"&Discard Build", BS_PUSHBUTTON | WS_TABSTOP, x + 198, y + 260, 96, 26, IDC_DISCARD);
    control(3, L"BUTTON", L"&Cancel Build", BS_PUSHBUTTON | WS_TABSTOP, x + 297, y + 260, 96, 26, IDC_CANCEL_JOB);
    control(3, L"BUTTON", L"R&oll Back...", BS_PUSHBUTTON | WS_TABSTOP, x + 396, y + 260, 96, 26, IDC_ROLLBACK);
    control(3, L"BUTTON", L"Re&fresh", BS_PUSHBUTTON | WS_TABSTOP, x + 495, y + 260, 95, 26, IDC_REFRESH);
    status_line = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_LEFTNOWORDWRAP | SS_NOPREFIX, 8, 400, 500, 22, hwnd, (HMENU)IDC_STATUS,
                                  merlin_instance, NULL);
    SendMessageW(status_line, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
    b = CreateWindowExW(0, L"BUTTON", L"&Settings...", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP, 526, 398, 96, 26, hwnd,
                        (HMENU)IDC_SETTINGS, merlin_instance, NULL);
    SendMessageW(b, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
    /* The tab control is a sibling of the page controls: keep it below them, or it paints over them. */
    SetWindowPos(tabs, HWND_BOTTOM, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    show_page(0);
    if (!admin) {
        EnableWindow(GetDlgItem(hwnd, IDC_COLLECT), FALSE);
        EnableWindow(GetDlgItem(hwnd, IDC_APPLY_BUTTON), FALSE);
        EnableWindow(GetDlgItem(hwnd, IDC_ROLLBACK), FALSE);
        EnableWindow(GetDlgItem(hwnd, IDC_DISCARD), FALSE);
        EnableWindow(GetDlgItem(hwnd, IDC_CANCEL_JOB), FALSE);
        EnableWindow(GetDlgItem(hwnd, IDC_SENDREP), FALSE);
    }
    EnableWindow(GetDlgItem(hwnd, IDC_ROLLBACK), FALSE);
}

static void on_command(HWND hwnd, int id)
{
    int sel;
    switch (id) {
    case IDC_COLLECT: {
        OPERATION *op = new_op(OpCollect);
        if (op && merlin_start(op)) status("Checking event logs, the Winlogon log and crash reports...");
        break;
    }
    case IDC_FILTER:
        fill_queue();
        break;
    case IDC_DETAILS:
        sel = (int)SendMessageW(queue_list, LVM_GETNEXTITEM, (WPARAM)-1, LVNI_SELECTED);
        if (sel >= 0 && sel < shown_count) {
            char *text = (char *)HeapAlloc(GetProcessHeap(), 0, 16384);
            if (text) {
                MerlinReportText(&queue.items[shown[sel]], text, 16384);
                merlin_text_dialog(hwnd, L"Problem details (redacted, as it would be sent)", text);
                HeapFree(GetProcessHeap(), 0, text);
            }
        } else status("Select a problem first.");
        break;
    case IDC_EXCLUDE:
    case IDC_REMOVE:
        sel = (int)SendMessageW(queue_list, LVM_GETNEXTITEM, (WPARAM)-1, LVNI_SELECTED);
        if (sel < 0 || sel >= shown_count) {
            status("Select a problem first.");
            break;
        }
        {
            MERLIN_PROBLEM *p = &queue.items[shown[sel]];
            DWORD e;
            if (id == IDC_REMOVE) {
                if (MessageBoxW(hwnd, L"Remove this problem and its local reports and memory dumps from the queue?", L"MerlinAI",
                                MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) != IDYES)
                    break;
                e = MerlinQueueRemove(p->id);
            } else {
                merlin_copy(p->status, sizeof(p->status), lstrcmpA(p->status, "excluded") ? "excluded" : "new");
                e = MerlinQueueSave(p);
            }
            if (e) status_error(id == IDC_REMOVE ? "The problem was not removed" : "The problem was not changed", e, NULL);
            else status(id == IDC_REMOVE ? "Removed from the queue." : "Changed.");
            reload_queue();
        }
        break;
    case IDC_SENDREP: {
        OPERATION *op;
        char ids[64][MERLIN_ID_SIZE];
        int n = checked_problems(ids, 64), i;
        if (!n) {
            status("Tick the problems to transfer first.");
            break;
        }
        if (MessageBoxW(hwnd,
                        L"Transfer the ticked reports to the MerlinAI Builder?\n\nThey are redacted first (your account name, profile paths, "
                        L"e-mail addresses and credentials are removed). Memory dumps are only sent for reports where you allowed it. "
                        L"No update is built by this.",
                        L"MerlinAI", MB_YESNO | MB_ICONQUESTION) != IDYES)
            break;
        op = new_op(OpTransfer);
        if (!op) break;
        for (i = 0; i < n; ++i) {
            MERLIN_PROBLEM *p = (MERLIN_PROBLEM *)HeapAlloc(GetProcessHeap(), 0, sizeof(MERLIN_PROBLEM));
            if (p && !MerlinQueueLoad(ids[i], p)) {
                p->transfer_consent = 1;                  /* the consent the user just gave */
                MerlinQueueSave(p);
            }
            if (p) HeapFree(GetProcessHeap(), 0, p);
            merlin_copy(op->ids[i], MERLIN_ID_SIZE, ids[i]);
        }
        op->id_count = n;
        if (merlin_start(op)) status("Transferring reports...");
        break;
    }
    case IDC_BUILD_BUTTON: {
        const MERLIN_PROBLEM *selected[64];
        char ids[64][MERLIN_ID_SIZE];
        OPERATION *op;
        int n = checked_problems(ids, 64), i, j, k = 0;
        if (!n) {
            status("Tick at least one problem in the Problem Queue.");
            break;
        }
        for (i = 0; i < n; ++i)
            for (j = 0; j < queue.count; ++j)
                if (!lstrcmpA(queue.items[j].id, ids[i])) selected[k++] = &queue.items[j];
        op = new_op(OpBuild);
        if (!op) break;
        if (merlin_confirm_build(hwnd, selected, k, op->text, sizeof(op->text)) != IDOK) {
            HeapFree(GetProcessHeap(), 0, op);
            status("No build was requested.");
            break;
        }
        for (i = 0; i < n; ++i) merlin_copy(op->ids[i], MERLIN_ID_SIZE, ids[i]);
        op->id_count = n;
        if (merlin_start(op)) {
            status("Sending the build request to the MerlinAI Builder...");
            merlin_character_state("investigating", "Let me look into that.");
        }
        break;
    }
    case IDC_REFRESH:
        request(OpJobs, NULL);
        break;
    case IDC_REVIEW:
        sel = selected_job();
        if (sel >= 0) request(OpJob, jobs[sel].job);
        else status("Select a build first.");
        break;
    case IDC_APPLY_BUTTON: {
        OPERATION *op;
        sel = selected_job();
        if (sel < 0) {
            status("Select a build first.");
            break;
        }
        if (!job_detail || !strstr(job_detail, jobs[sel].job)) {
            request(OpJob, jobs[sel].job);
            break;
        }
        op = new_op(OpApply);
        if (!op) break;
        if (merlin_approve(hwnd, job_detail, op->text, sizeof(op->text), FALSE) != IDOK) {
            HeapFree(GetProcessHeap(), 0, op);
            status("The update was not applied.");
            break;
        }
        if (merlin_start(op)) {
            status("Sending your approval to the deployment agent...");
            merlin_serial("XP25_MERLIN_UI_APPLY_APPROVED");
        }
        break;
    }
    case IDC_ROLLBACK: {
        OPERATION *op = new_op(OpRollback);
        if (!op) break;
        if (merlin_approve(hwnd, NULL, op->text, sizeof(op->text), TRUE) != IDOK) {
            HeapFree(GetProcessHeap(), 0, op);
            break;
        }
        if (merlin_start(op)) status("Sending the rollback request to the deployment agent...");
        break;
    }
    case IDC_DISCARD:
    case IDC_CANCEL_JOB:
        sel = selected_job();
        if (sel < 0) {
            status("Select a build first.");
            break;
        }
        if (MessageBoxW(hwnd, id == IDC_DISCARD ? L"Discard this build? Its candidate image will not be offered again; the builder keeps its evidence."
                                                : L"Cancel this build? The builder stops the job and keeps what it recorded.",
                        L"MerlinAI", MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) == IDYES)
            request(id == IDC_DISCARD ? OpDiscard : OpCancel, jobs[sel].job);
        break;
    case IDC_SETTINGS:
        merlin_settings_dialog(hwnd);
        MerlinGetConfig(&config);
        fill_health();
        break;
    }
}

static LRESULT CALLBACK window_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE:
        create_controls(hwnd);
        reload_queue();
        if (admin && config.auto_collect) PostMessageW(hwnd, WM_COMMAND, IDC_COLLECT, 0);
        if (admin && config.collect_minutes && config.auto_collect) SetTimer(hwnd, TIMER_COLLECT, config.collect_minutes * 60000, NULL);
        merlin_character_start(hwnd);
        merlin_serial("XP25_MERLIN_UI_READY");
        return 0;
    case WM_NOTIFY: {
        NMHDR *n = (NMHDR *)lp;
        if (n->idFrom == IDC_TABS && n->code == TCN_SELCHANGE) {
            int page = (int)SendMessageW(tabs, TCM_GETCURSEL, 0, 0);
            show_page(page);
            if (page == 2) refresh_build_page();
            if (page == 3 && admin && !busy) request(OpJobs, NULL);
        } else if (n->idFrom == IDC_QUEUE_LIST && n->code == LVN_ITEMCHANGED)
            refresh_build_page();
        else if (n->idFrom == IDC_JOBS_LIST && n->code == NM_DBLCLK)
            PostMessageW(hwnd, WM_COMMAND, IDC_REVIEW, 0);
        return 0;
    }
    case WM_COMMAND:
        if (HIWORD(wp) == CBN_SELCHANGE && LOWORD(wp) == IDC_FILTER) fill_queue();
        else if (HIWORD(wp) == BN_CLICKED || HIWORD(wp) == 0) on_command(hwnd, LOWORD(wp));
        return 0;
    case WM_TIMER:
        if (wp == TIMER_POLL && !busy) request(OpJobs, NULL);
        if (wp == TIMER_COLLECT && !busy) {
            OPERATION *op = new_op(OpCollect);
            if (op) merlin_start(op);
        }
        return 0;
    case WM_MERLIN_DONE:
        on_done((OPERATION *)lp);
        if (wp == OpJobs && admin && config.deploy[0] && !busy) request(OpDeployStatus, NULL);
        return 0;
    case WM_CTLCOLORSTATIC:
        if ((HWND)lp == GetDlgItem(hwnd, IDC_BANNER)) {
            SetTextColor((HDC)wp, RGB(0, 51, 153));
            SetBkMode((HDC)wp, TRANSPARENT);
            return (LRESULT)GetSysColorBrush(COLOR_BTNFACE);
        }
        break;
    case WM_DESTROY:
        merlin_character_stop();
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int merlin_run_ui(int show)
{
    WNDCLASSEXW wc;
    INITCOMMONCONTROLSEX icc;
    HWND hwnd;
    MSG msg;
    HANDLE single = CreateMutexW(NULL, TRUE, L"XP25MerlinAIWindow");
    if (single && GetLastError() == ERROR_ALREADY_EXISTS) {
        HWND other = FindWindowW(L"XP25MerlinAI", NULL);
        if (other) {
            ShowWindow(other, SW_RESTORE);
            SetForegroundWindow(other);
        }
        CloseHandle(single);
        return 0;
    }
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_TAB_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);
    OleInitialize(NULL);
    admin = MerlinIsAdmin();
    MerlinGetConfig(&config);
    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = window_proc;
    wc.hInstance = merlin_instance;
    wc.hIcon = LoadIconW(merlin_instance, MAKEINTRESOURCEW(IDI_MERLIN));
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"XP25MerlinAI";
    RegisterClassExW(&wc);
    hwnd = CreateWindowExW(0, L"XP25MerlinAI", L"MerlinAI System Health & Updates",
                           (WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_THICKFRAME) | WS_CLIPCHILDREN,
                           CW_USEDEFAULT, CW_USEDEFAULT, 636, 456, NULL, NULL, merlin_instance, NULL);
    if (!hwnd) return 1;
    ShowWindow(hwnd, show);
    UpdateWindow(hwnd);
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        if (msg.message == WM_KEYDOWN && msg.wParam >= '1' && msg.wParam <= '4' && GetKeyState(VK_CONTROL) < 0 &&
            (msg.hwnd == hwnd || IsChild(hwnd, msg.hwnd))) {
            select_page((int)(msg.wParam - '1'));
            continue;
        }
        if (!IsDialogMessageW(hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    MerlinFreeList(&queue);
    OleUninitialize();
    if (single) CloseHandle(single);
    return 0;
}
