/* RoverAI search panel: XP Search Companion-style pane with a natural
   language box, filters and a results list. Searches run on a worker
   thread through the shared XP25 runtime; every result is a file that was
   found in the local index or a live folder scan. */
#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <objbase.h>
#include <string.h>
#include "panel.h"
#include "../indexer/rover_win.h"
#include "../../xp25-agent/runtime/xp25_msagent.h"
#include "../../xp25-agent/ipc/xp25_ipc.h"

#define WM_ROVER_RESULTS (WM_APP + 40)
#define WM_ROVER_ROVER (WM_APP + 41)

typedef struct {
    HWND hwnd, title, query, go, scope, date, type, size, location, ai, status, list, open, folder, explain, rover_area;
    HWND labels[6];
    HFONT font, bold;
    int band_mode;
    WCHAR folder_path[MAX_PATH];
    ROVER_RESULTS results;
    int have_results;
    int sort_column, sort_desc;
    HANDLE worker;
    volatile LONG generation;
    XP25_AGENTCHAR *rover;
    int rover_tried;
    XP25W_PATHS paths;
    XP25_CONFIG config;
} PANEL;

typedef struct {
    HWND panel;
    LONG generation;
    char *query, *scope;
    int ai;
    ROVER_RESULTS results;
    int ok;
} JOB;

static PANEL *get(HWND hwnd) { return (PANEL *)GetWindowLongPtrW(hwnd, GWLP_USERDATA); }

static HWND child(PANEL *p, const WCHAR *cls, const WCHAR *text, DWORD style, int id)
{
    HWND h = CreateWindowExW(!lstrcmpW(cls, L"EDIT") ? WS_EX_CLIENTEDGE : 0, cls, text, WS_CHILD | WS_VISIBLE | style,
                             0, 0, 10, 10, p->hwnd, (HMENU)(INT_PTR)id, (HINSTANCE)GetWindowLongPtrW(p->hwnd, GWLP_HINSTANCE), NULL);
    SendMessageW(h, WM_SETFONT, (WPARAM)p->font, FALSE);
    return h;
}

static void fill_combo(HWND combo, const WCHAR *const *items)
{
    for (; *items; ++items) SendMessageW(combo, CB_ADDSTRING, 0, (LPARAM)*items);
    SendMessageW(combo, CB_SETCURSEL, 0, 0);
}

static const WCHAR *const scope_items[] = { L"Current folder", L"Entire computer", L"My Documents", L"Desktop", NULL };
static const WCHAR *const date_items[] = { L"Any time", L"Today", L"Yesterday", L"This week", L"Last week",
                                           L"This month", L"This year", L"Last year", NULL };
static const char *const date_words[] = { "", " today", " yesterday", " this week", " last week", " this month",
                                          " this year", " last year" };
static const WCHAR *const type_items[] = { L"Any type", L"Documents", L"Pictures", L"Music", L"Videos", L"PDF files",
                                           L"Text files", L"Spreadsheets", L"Programs", L"Folders", NULL };
static const char *const type_words[] = { "", " documents", " pictures", " music", " videos", " pdf", " text files",
                                          " spreadsheets", " programs", " folders" };
static const WCHAR *const size_items[] = { L"Any size", L"Small (under 100 KB)", L"Large (over 10 MB)",
                                           L"Huge (over 100 MB)", NULL };
static const char *const size_words[] = { "", " small", " large", " huge" };

static void column(HWND list, int index, const WCHAR *name, int width)
{
    LVCOLUMNW c;
    memset(&c, 0, sizeof(c));
    c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    c.pszText = (WCHAR *)name;
    c.cx = width;
    c.iSubItem = index;
    SendMessageW(list, LVM_INSERTCOLUMNW, (WPARAM)index, (LPARAM)&c);
}

static void build(PANEL *p)
{
    static const WCHAR *const labels[] = { L"Look in:", L"When was it modified?", L"What kind of file?",
                                           L"What size is it?", L"Folder name contains:", NULL };
    SHFILEINFOW sfi;
    HIMAGELIST images;
    int i;
    p->title = child(p, L"STATIC", L"What do you want to find? Ask Rover in your own words:", 0, IDC_RV_TITLE);
    SendMessageW(p->title, WM_SETFONT, (WPARAM)p->bold, FALSE);
    p->query = child(p, L"EDIT", L"", WS_TABSTOP | ES_AUTOHSCROLL, IDC_RV_QUERY);
    p->go = child(p, L"BUTTON", L"&Search", WS_TABSTOP | BS_DEFPUSHBUTTON, IDC_RV_GO);
    for (i = 0; labels[i]; ++i) p->labels[i] = child(p, L"STATIC", labels[i], 0, IDC_RV_LABEL + i);
    p->scope = child(p, L"COMBOBOX", L"", WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL, IDC_RV_SCOPE);
    p->date = child(p, L"COMBOBOX", L"", WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL, IDC_RV_DATE);
    p->type = child(p, L"COMBOBOX", L"", WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL, IDC_RV_TYPE);
    p->size = child(p, L"COMBOBOX", L"", WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL, IDC_RV_SIZE);
    p->location = child(p, L"EDIT", L"", WS_TABSTOP | ES_AUTOHSCROLL, IDC_RV_LOCATION);
    p->ai = child(p, L"BUTTON", L"Let the AI provider interpret my question (wording only)", WS_TABSTOP | BS_AUTOCHECKBOX, IDC_RV_AI);
    p->status = child(p, L"STATIC", L"Rover is ready. Type a description such as \"the PDF I edited yesterday\".", SS_NOPREFIX, IDC_RV_STATUS);
    p->list = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT |
                              LVS_SHOWSELALWAYS | LVS_SINGLESEL | LVS_SHAREIMAGELISTS, 0, 0, 10, 10, p->hwnd,
                              (HMENU)IDC_RV_RESULTS, (HINSTANCE)GetWindowLongPtrW(p->hwnd, GWLP_HINSTANCE), NULL);
    SendMessageW(p->list, WM_SETFONT, (WPARAM)p->font, FALSE);
    SendMessageW(p->list, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT | LVS_EX_LABELTIP);
    column(p->list, 0, L"Name", 170);
    column(p->list, 1, L"In Folder", 220);
    column(p->list, 2, L"Size", 70);
    column(p->list, 3, L"Type", 110);
    column(p->list, 4, L"Date Modified", 110);
    images = (HIMAGELIST)SHGetFileInfoW(L"C:\\", 0, &sfi, sizeof(sfi), SHGFI_SYSICONINDEX | SHGFI_SMALLICON);
    if (images) SendMessageW(p->list, LVM_SETIMAGELIST, LVSIL_SMALL, (LPARAM)images);
    p->open = child(p, L"BUTTON", L"&Open", WS_TABSTOP | WS_DISABLED, IDC_RV_OPEN);
    p->folder = child(p, L"BUTTON", L"Open containing &folder", WS_TABSTOP | WS_DISABLED, IDC_RV_FOLDER);
    p->explain = child(p, L"BUTTON", L"Ask &ClippyAI", WS_TABSTOP | WS_DISABLED, IDC_RV_EXPLAIN);
    p->rover_area = child(p, L"STATIC", L"", SS_NOTIFY, IDC_RV_ROVER);
    fill_combo(p->scope, scope_items);
    fill_combo(p->date, date_items);
    fill_combo(p->type, type_items);
    fill_combo(p->size, size_items);
    if (!p->band_mode) SendMessageW(p->scope, CB_SETCURSEL, 1, 0);
    if (p->config.provider == XP25_PROVIDER_OFFLINE) EnableWindow(p->ai, FALSE);
    else if (p->config.ai_query_interpretation) SendMessageW(p->ai, BM_SETCHECK, BST_CHECKED, 0);
}

static void place(HWND h, int x, int y, int w, int hgt) { MoveWindow(h, x, y, w > 0 ? w : 1, hgt > 0 ? hgt : 1, TRUE); }

static void anchor_rover(PANEL *p)
{
    RECT r;
    long w, h;
    if (!p->rover) return;
    GetWindowRect(p->rover_area, &r);
    xp25w_agentchar_size(p->rover, &w, &h);
    xp25w_agentchar_move(p->rover, (int)(r.left + ((r.right - r.left) - w) / 2), (int)(r.bottom - h));
}

static void layout(PANEL *p)
{
    RECT rc;
    int w, h, col, x = 8, y = 8, i, list_x, list_w, rover_h;
    GetClientRect(p->hwnd, &rc);
    w = rc.right;
    h = rc.bottom;
    col = p->band_mode ? w - 16 : 250;
    rover_h = p->band_mode ? 0 : 110;
    place(p->title, x, y, col, 28); y += 30;
    place(p->query, x, y, col - 70, 21);
    place(p->go, x + col - 64, y, 64, 23); y += 30;
    {
        HWND controls[5];
        controls[0] = p->scope; controls[1] = p->date; controls[2] = p->type; controls[3] = p->size; controls[4] = p->location;
        for (i = 0; i < 5; ++i) {
            place(p->labels[i], x, y, col, 14); y += 15;
            place(controls[i], x, y, col, i < 4 ? 200 : 21); y += 26;
        }
    }
    place(p->ai, x, y, col, 30); y += 34;
    if (p->band_mode) {
        place(p->status, x, y, col, 42); y += 46;
        place(p->list, x, y, col, h - y - 70 > 60 ? h - y - 70 : 60);
        y = h - 64 > y + 60 ? h - 64 : y + 64;
        place(p->open, x, y, (col - 6) / 2, 23);
        place(p->folder, x + (col - 6) / 2 + 6, y, (col - 6) / 2, 23); y += 28;
        place(p->explain, x, y, col, 23);
        place(p->rover_area, 0, 0, 0, 0);
    } else {
        place(p->rover_area, x, h - rover_h - 8, col, rover_h);
        list_x = col + 20;
        list_w = w - list_x - 8;
        place(p->status, list_x, 8, list_w, 30);
        place(p->list, list_x, 40, list_w, h - 40 - 40);
        place(p->open, list_x, h - 32, 90, 24);
        place(p->folder, list_x + 96, h - 32, 160, 24);
        place(p->explain, list_x + 262, h - 32, 110, 24);
    }
    anchor_rover(p);
}

static void rover_play(PANEL *p, const WCHAR *animation)
{
    if (p->rover) xp25w_agentchar_play(p->rover, animation);
}

void rover_panel_show_rover(HWND panel, int visible)
{
    PANEL *p = get(panel);
    WCHAR path[MAX_PATH];
    char error[96];
    if (!p) return;
    if (visible && !p->rover && !p->rover_tried) {
        /* Rover from Windows XP's own Search Companion characters. */
        p->rover_tried = 1;
        if (lstrlenW(p->paths.windows) < MAX_PATH - 40) {
            lstrcpyW(path, p->paths.windows);
            lstrcatW(path, L"\\srchasst\\chars\\rover.acs");
            p->rover = xp25w_agentchar_load(path, error, sizeof(error));
        }
        if (p->rover) { anchor_rover(p); xp25w_agentchar_show(p->rover, 1); rover_play(p, L"Greet"); }
    } else if (p->rover) {
        anchor_rover(p);
        xp25w_agentchar_show(p->rover, visible);
    }
}

static void set_status(PANEL *p, const char *utf8)
{
    WCHAR *w = xp25w_wide(utf8);
    SetWindowTextW(p->status, w ? w : L"");
    xp25_free(w);
}

static DWORD WINAPI search_thread(void *param)
{
    JOB *job = (JOB *)param;
    XP25W_PATHS paths;
    XP25_CONFIG config;
    ROVER_SETTINGS settings;
    XP25_PROVIDER *provider = NULL;
    char reason[200];
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    xp25w_paths(&paths);
    xp25w_config_load(&config);
    if (job->ai) provider = xp25w_provider_create(&config, reason, sizeof(reason));
    if (rover_settings_init(&settings, &config, &paths)) {
        job->ok = rover_query_run(job->query, job->scope, 300, job->ai ? ROVER_AI_AUTO : ROVER_AI_NEVER, provider,
                                  &settings, &job->results);
        rover_settings_free(&settings);
    }
    if (provider) xp25w_provider_destroy(provider);
    CoUninitialize();
    if (!PostMessageW(job->panel, WM_ROVER_RESULTS, 0, (LPARAM)job)) {
        rover_results_free(&job->results);
        xp25_free(job->query);
        xp25_free(job->scope);
        xp25_free(job);
    }
    return 0;
}

static char *text_of(HWND h)
{
    int n = GetWindowTextLengthW(h);
    WCHAR *w = (WCHAR *)xp25_alloc(((size_t)n + 1) * sizeof(WCHAR));
    char *u;
    if (!w) return NULL;
    GetWindowTextW(h, w, n + 1);
    u = xp25w_utf8(w);
    xp25_free(w);
    return u;
}

static void start_search(PANEL *p)
{
    JOB *job;
    XP25_BUF q;
    char *typed = text_of(p->query), *location = text_of(p->location);
    int scope = (int)SendMessageW(p->scope, CB_GETCURSEL, 0, 0), sel;
    DWORD id;
    HANDLE thread;
    xp25_buf_init(&q);
    xp25_buf_puts(&q, typed ? typed : "");
    sel = (int)SendMessageW(p->date, CB_GETCURSEL, 0, 0);
    if (sel > 0 && sel < 8) xp25_buf_puts(&q, date_words[sel]);
    sel = (int)SendMessageW(p->type, CB_GETCURSEL, 0, 0);
    if (sel > 0 && sel < 10) xp25_buf_puts(&q, type_words[sel]);
    sel = (int)SendMessageW(p->size, CB_GETCURSEL, 0, 0);
    if (sel > 0 && sel < 4) xp25_buf_puts(&q, size_words[sel]);
    if (location && *location) { xp25_buf_puts(&q, " in "); xp25_buf_puts(&q, location); xp25_buf_puts(&q, " folder"); }
    xp25_free(typed);
    xp25_free(location);
    if (!q.len) { set_status(p, "Type what you are looking for, or choose a filter."); xp25_buf_free(&q); return; }
    job = (JOB *)xp25_alloc(sizeof(JOB));
    if (!job) { xp25_buf_free(&q); return; }
    job->panel = p->hwnd;
    job->generation = InterlockedIncrement(&p->generation);
    job->query = xp25_buf_detach(&q);
    job->ai = SendMessageW(p->ai, BM_GETCHECK, 0, 0) == BST_CHECKED;
    if (scope == 0 && p->folder_path[0]) job->scope = xp25w_utf8(p->folder_path);
    else if (scope == 2) job->scope = xp25w_utf8(p->paths.documents);
    else if (scope == 3) job->scope = xp25w_utf8(p->paths.desktop);
    else job->scope = xp25_strdup("computer");
    {
        XP25_BUF s;
        xp25_buf_init(&s);
        xp25_buf_puts(&s, "Rover is searching for: ");
        xp25_buf_puts(&s, job->query);
        set_status(p, xp25_buf_cstr(&s));
        xp25_buf_free(&s);
    }
    rover_play(p, L"Searching");
    EnableWindow(p->go, FALSE);
    thread = CreateThread(NULL, 0, search_thread, job, 0, &id);
    if (thread) CloseHandle(thread);
    else {
        xp25_free(job->query);
        xp25_free(job->scope);
        xp25_free(job);
        EnableWindow(p->go, TRUE);
    }
}

static int CALLBACK compare(LPARAM a, LPARAM b, LPARAM ctx)
{
    PANEL *p = (PANEL *)ctx;
    const ROVER_RESULT *x = &p->results.items[a], *y = &p->results.items[b];
    int r = 0;
    switch (p->sort_column) {
    case 1: r = rover_path_compare(x->path, y->path); break;
    case 2: r = x->size < y->size ? -1 : x->size > y->size; break;
    case 3: r = lstrcmpiA(rover_type_name(x->path + x->name, (x->attrs & ROVER_ATTR_DIRECTORY) != 0),
                          rover_type_name(y->path + y->name, (y->attrs & ROVER_ATTR_DIRECTORY) != 0)); break;
    case 4: r = x->mtime < y->mtime ? -1 : x->mtime > y->mtime; break;
    default: r = rover_path_compare(x->path + x->name, y->path + y->name); break;
    }
    return p->sort_desc ? -r : r;
}

static void show_results(PANEL *p)
{
    size_t i;
    long bias = xp25w_bias_minutes();
    SendMessageW(p->list, LVM_DELETEALLITEMS, 0, 0);
    for (i = 0; i < p->results.count; ++i) {
        const ROVER_RESULT *r = &p->results.items[i];
        LVITEMW item;
        SHFILEINFOW sfi;
        WCHAR *path = xp25w_wide(r->path), *name, *folder, text[64];
        char stamp[20];
        XP25_BUF size;
        int directory = (r->attrs & ROVER_ATTR_DIRECTORY) != 0;
        if (!path) continue;
        name = path + lstrlenW(path);
        while (name > path && name[-1] != L'\\') --name;
        memset(&sfi, 0, sizeof(sfi));
        SHGetFileInfoW(path, r->attrs, &sfi, sizeof(sfi), SHGFI_SYSICONINDEX | SHGFI_SMALLICON |
                       (xp25_ends_with_i(r->path, ".exe") || xp25_ends_with_i(r->path, ".lnk") || xp25_ends_with_i(r->path, ".ico")
                        ? 0 : SHGFI_USEFILEATTRIBUTES));
        memset(&item, 0, sizeof(item));
        item.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM;
        item.iItem = (int)i;
        item.pszText = name;
        item.iImage = sfi.iIcon;
        item.lParam = (LPARAM)i;
        item.iItem = (int)SendMessageW(p->list, LVM_INSERTITEMW, 0, (LPARAM)&item);
        folder = (WCHAR *)xp25_alloc(((size_t)(name - path) + 1) * sizeof(WCHAR));
        if (folder) {
            memcpy(folder, path, (size_t)(name - path) * sizeof(WCHAR));
            folder[name - path > 3 ? name - path - 1 : name - path] = 0;
            item.mask = LVIF_TEXT;
            item.iSubItem = 1;
            item.pszText = folder;
            SendMessageW(p->list, LVM_SETITEMTEXTW, (WPARAM)item.iItem, (LPARAM)&item);
            xp25_free(folder);
        }
        xp25_buf_init(&size);
        if (!directory) xp25_buf_size(&size, r->size);
        xp25w_copy_wide(text, 64, xp25_buf_cstr(&size));
        xp25_buf_free(&size);
        item.iSubItem = 2; item.pszText = text;
        SendMessageW(p->list, LVM_SETITEMTEXTW, (WPARAM)item.iItem, (LPARAM)&item);
        xp25w_copy_wide(text, 64, rover_type_name(r->path + r->name, directory));
        item.iSubItem = 3; item.pszText = text;
        SendMessageW(p->list, LVM_SETITEMTEXTW, (WPARAM)item.iItem, (LPARAM)&item);
        rover_format_local(r->mtime, bias, stamp);
        xp25w_copy_wide(text, 64, stamp);
        item.iSubItem = 4; item.pszText = text;
        SendMessageW(p->list, LVM_SETITEMTEXTW, (WPARAM)item.iItem, (LPARAM)&item);
        xp25_free(path);
    }
}

static const ROVER_RESULT *selected(PANEL *p)
{
    int index = (int)SendMessageW(p->list, LVM_GETNEXTITEM, (WPARAM)-1, LVNI_SELECTED);
    LVITEMW item;
    if (index < 0) return NULL;
    memset(&item, 0, sizeof(item));
    item.mask = LVIF_PARAM;
    item.iItem = index;
    if (!SendMessageW(p->list, LVM_GETITEMW, 0, (LPARAM)&item) || (size_t)item.lParam >= p->results.count) return NULL;
    return &p->results.items[item.lParam];
}

static void act(PANEL *p, int command)
{
    const ROVER_RESULT *r = selected(p);
    WCHAR *path;
    if (!r) return;
    path = xp25w_wide(r->path);
    if (!path) return;
    if (command == IDC_RV_OPEN) {
        SHELLEXECUTEINFOW sei;
        memset(&sei, 0, sizeof(sei));
        sei.cbSize = sizeof(sei);
        sei.hwnd = p->hwnd;
        sei.lpFile = path;
        sei.nShow = SW_SHOWNORMAL;
        if (!ShellExecuteExW(&sei)) set_status(p, "Windows could not open this item.");
    } else if (command == IDC_RV_FOLDER) {
        WCHAR *args = (WCHAR *)xp25_alloc(((size_t)lstrlenW(path) + 16) * sizeof(WCHAR));
        if (args) {
            lstrcpyW(args, L"/select,\"");
            lstrcatW(args, path);
            lstrcatW(args, L"\"");
            ShellExecuteW(p->hwnd, L"open", L"explorer.exe", args, NULL, SW_SHOWNORMAL);
            xp25_free(args);
        }
    } else if (command == IDC_RV_EXPLAIN) {
        if (!xp25w_clippy_request("explain_file", r->path)) set_status(p, "ClippyAI could not be started.");
    }
    xp25_free(path);
}

static void results_arrived(PANEL *p, JOB *job)
{
    XP25_BUF s;
    char stamp[20];
    EnableWindow(p->go, TRUE);
    if (job->generation != p->generation) {      /* a newer search replaced this one */
        rover_results_free(&job->results);
        return;
    }
    if (p->have_results) rover_results_free(&p->results);
    p->results = job->results;
    p->have_results = 1;
    show_results(p);
    xp25_buf_init(&s);
    if (!job->ok) {
        xp25_buf_puts(&s, "The search could not run: ");
        xp25_buf_puts(&s, p->results.note[0] ? p->results.note : "unknown error");
        rover_play(p, L"Embarrassed");
    } else {
        xp25_buf_u64(&s, (xp25_u64)p->results.total);
        xp25_buf_puts(&s, p->results.total == 1 ? " result" : " results");
        if (p->results.total > p->results.count) { xp25_buf_puts(&s, " (showing "); xp25_buf_u64(&s, (xp25_u64)p->results.count); xp25_buf_puts(&s, ")"); }
        xp25_buf_puts(&s, " - ");
        xp25_buf_puts(&s, p->results.description);
        if (p->results.by_ai) xp25_buf_puts(&s, " [interpreted by AI]");
        if (p->results.relaxed) xp25_buf_puts(&s, ". No file matched every word, so the other criteria were used");
        if (p->results.live_scan) xp25_buf_puts(&s, ". Folder scanned now");
        else {
            rover_format_local(p->results.index_updated, xp25w_bias_minutes(), stamp);
            xp25_buf_puts(&s, ". Index updated ");
            xp25_buf_puts(&s, stamp);
        }
        if (p->results.note[0]) { xp25_buf_puts(&s, ". "); xp25_buf_puts(&s, p->results.note); }
        rover_play(p, p->results.total ? L"Pleased" : L"Embarrassed");
    }
    set_status(p, xp25_buf_cstr(&s));
    xp25_buf_free(&s);
}

static LRESULT CALLBACK panel_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    PANEL *p = get(hwnd);
    switch (msg) {
    case WM_CREATE: {
        CREATESTRUCTW *cs = (CREATESTRUCTW *)lp;
        NONCLIENTMETRICSW ncm;
        LOGFONTW lf;
        p = (PANEL *)xp25_alloc(sizeof(PANEL));
        if (!p) return -1;
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)p);
        p->hwnd = hwnd;
        p->band_mode = cs->lpCreateParams != NULL;
        p->sort_column = -1;
        xp25w_paths(&p->paths);
        xp25w_config_load(&p->config);
        memset(&ncm, 0, sizeof(ncm));
        ncm.cbSize = sizeof(ncm);
        SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0);
        p->font = CreateFontIndirectW(&ncm.lfMessageFont);
        lf = ncm.lfMessageFont;
        lf.lfWeight = FW_BOLD;
        p->bold = CreateFontIndirectW(&lf);
        build(p);
        return 0;
    }
    case WM_SIZE:
        layout(p);
        return 0;
    case WM_MOVE:
    case WM_WINDOWPOSCHANGED:
        if (p) anchor_rover(p);
        break;
    case WM_CTLCOLORSTATIC:
        SetBkMode((HDC)wp, TRANSPARENT);
        return (LRESULT)GetSysColorBrush(COLOR_WINDOW);
    case WM_ERASEBKGND: {
        RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect((HDC)wp, &rc, GetSysColorBrush(COLOR_WINDOW));
        return 1;
    }
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDC_RV_GO: case IDOK: start_search(p); return 0;
        case IDC_RV_OPEN: case IDC_RV_FOLDER: case IDC_RV_EXPLAIN: act(p, LOWORD(wp)); return 0;
        }
        break;
    case WM_NOTIFY: {
        NMHDR *n = (NMHDR *)lp;
        if (n->idFrom != IDC_RV_RESULTS) break;
        if (n->code == LVN_ITEMCHANGED) {
            int any = SendMessageW(p->list, LVM_GETSELECTEDCOUNT, 0, 0) > 0;
            EnableWindow(p->open, any);
            EnableWindow(p->folder, any);
            EnableWindow(p->explain, any);
        } else if (n->code == NM_DBLCLK || n->code == NM_RETURN) act(p, IDC_RV_OPEN);
        else if (n->code == LVN_COLUMNCLICK) {
            int col = ((NMLISTVIEW *)lp)->iSubItem;
            p->sort_desc = p->sort_column == col ? !p->sort_desc : (col == 2 || col == 4);
            p->sort_column = col;
            SendMessageW(p->list, LVM_SORTITEMS, (WPARAM)p, (LPARAM)compare);
        } else if (n->code == NM_RCLICK && selected(p)) {
            HMENU menu = CreatePopupMenu();
            POINT pt;
            int cmd;
            AppendMenuW(menu, MF_STRING | MF_DEFAULT, IDC_RV_OPEN, L"&Open");
            AppendMenuW(menu, MF_STRING, IDC_RV_FOLDER, L"Open containing &folder");
            AppendMenuW(menu, MF_STRING, IDC_RV_EXPLAIN, L"Ask &ClippyAI about this file");
            GetCursorPos(&pt);
            cmd = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
            DestroyMenu(menu);
            if (cmd) act(p, cmd);
        }
        return 0;
    }
    case WM_ROVER_RESULTS: {
        JOB *job = (JOB *)lp;
        results_arrived(p, job);
        xp25_free(job->query);
        xp25_free(job->scope);
        xp25_free(job);
        return 0;
    }
    case WM_SHOWWINDOW:
        rover_panel_show_rover(hwnd, wp != 0);
        break;
    case WM_DESTROY:
        if (p) {
            InterlockedIncrement(&p->generation);
            if (p->rover) xp25w_agentchar_free(p->rover);
            if (p->have_results) rover_results_free(&p->results);
            DeleteObject(p->font);
            DeleteObject(p->bold);
            xp25_free(p);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        }
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

HWND rover_panel_create(HWND parent, HINSTANCE instance, int band_mode, int id)
{
    static ATOM atom;
    if (!atom) {
        WNDCLASSW wc;
        memset(&wc, 0, sizeof(wc));
        wc.lpfnWndProc = panel_proc;
        wc.hInstance = instance;
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.lpszClassName = ROVER_PANEL_CLASS;
        atom = RegisterClassW(&wc);
        if (!atom && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) return NULL;
    }
    return CreateWindowExW(WS_EX_CONTROLPARENT, ROVER_PANEL_CLASS, L"RoverAI", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
                           0, 0, 300, 400, parent, (HMENU)(INT_PTR)id, instance, band_mode ? (void *)1 : NULL);
}

void rover_panel_set_folder(HWND panel, const WCHAR *folder)
{
    PANEL *p = get(panel);
    WCHAR label[MAX_PATH + 32];
    if (!p || !folder) return;
    lstrcpynW(p->folder_path, folder, MAX_PATH);
    lstrcpyW(label, L"Current folder (");
    lstrcatW(label, wcsrchr(folder, L'\\') && wcsrchr(folder, L'\\')[1] ? wcsrchr(folder, L'\\') + 1 : folder);
    lstrcatW(label, L")");
    SendMessageW(p->scope, CB_DELETESTRING, 0, 0);
    SendMessageW(p->scope, CB_INSERTSTRING, 0, (LPARAM)label);
    if (SendMessageW(p->scope, CB_GETCURSEL, 0, 0) < 0) SendMessageW(p->scope, CB_SETCURSEL, 0, 0);
}

void rover_panel_set_query(HWND panel, const WCHAR *query, int run)
{
    PANEL *p = get(panel);
    if (!p) return;
    SetWindowTextW(p->query, query);
    if (run) start_search(p);
}

void rover_panel_activate(HWND panel)
{
    PANEL *p = get(panel);
    if (p) { SetFocus(p->query); SendMessageW(p->query, EM_SETSEL, 0, -1); }
}

int rover_panel_owns(HWND panel, HWND hwnd)
{
    return hwnd && (hwnd == panel || IsChild(panel, hwnd));
}
