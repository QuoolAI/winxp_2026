/* XP25 AI guest acceptance probe: drives the installed ClippyAI, RoverAI and
   the RoverAI Explorer bar through their real windows, dialogs and command
   lines, and reports one JSON record per case to COM1 and C:\xp25\ai.
   No C runtime. Usage: ai_probe.exe suite [slow] | ai_probe.exe burn |
   ai_probe.exe provider <secret> [slow] | ai_probe.exe dpapi | ai_probe.exe cpu.
   Exit code = failed cases. */
#define WINVER 0x0501
#define _WIN32_WINNT 0x0501
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <wincred.h>

#define APP L"C:\\Program Files\\XP25"
#define WORK L"C:\\xp25\\ai"
#define LVM_GETITEMCOUNT_ (0x1000 + 4)
#define LVM_GETITEMTEXTW_ (0x1000 + 115)
#define LVM_SETITEMSTATE_ (0x1000 + 43)
#define CMD_SEARCH_BAR 0xA231
#define IDC_INPUT 1002
#define IDC_SEND 1003
#define IDC_AP_COMMAND 2003
#define IDM_SETTINGS 3010
#define IDM_TRAY_OPEN 3030
#define IDC_ST_PROVIDER 2201
#define IDC_ST_ENDPOINT 2203
#define IDC_ST_MODEL 2204
#define IDC_ST_CLIENT 2205
#define IDC_ST_SECRET 2206
#define IDC_ST_RESULT 2214
#define IDC_RV_QUERY 4002
#define IDC_RV_GO 4003
#define IDC_RV_SCOPE 4004
#define IDC_RV_RESULTS 4011
#define IDC_RV_OPEN 4012
#define IDC_RV_FOLDER 4013
#define IDC_RV_EXPLAIN 4014

static HANDLE serial, results;
static unsigned failures, passes;
static DWORD scale = 1;
static WCHAR docs[MAX_PATH], fixtures[MAX_PATH];

static void zero(void *p, DWORD n) { volatile BYTE *b = (volatile BYTE *)p; while (n--) *b++ = 0; }

static void emit(const char *line)
{
    DWORD n;
    if (serial != INVALID_HANDLE_VALUE) WriteFile(serial, line, (DWORD)lstrlenA(line), &n, NULL);
    if (results != INVALID_HANDLE_VALUE) WriteFile(results, line, (DWORD)lstrlenA(line), &n, NULL);
}

/* detail must not contain quotes or backslashes (kept to plain words). */
static void report(const char *name, BOOL ok, const char *detail)
{
    char row[600];
    if (ok) ++passes; else ++failures;
    wsprintfA(row, "{\"ai_case\":\"%s\",\"status\":\"%s\",\"detail\":\"%s\"}\r\n", name, ok ? "pass" : "fail", detail ? detail : "");
    emit(row);
}

static void note(const char *name, const char *detail)
{
    char row[700];
    wsprintfA(row, "{\"ai_note\":\"%s\",\"detail\":\"%s\"}\r\n", name, detail);
    emit(row);
}

static void cat(WCHAR *dst, const WCHAR *a, const WCHAR *b) { lstrcpyW(dst, a); lstrcatW(dst, b); }

/* SetWindowText/GetWindowText cannot reach a control in another process;
   send WM_SETTEXT/WM_GETTEXT, which user32 marshals across processes. */
static void put_text(HWND parent, int id, const WCHAR *text)
{
    DWORD_PTR r;
    SendMessageTimeoutW(GetDlgItem(parent, id), WM_SETTEXT, 0, (LPARAM)text, SMTO_ABORTIFHUNG, 5000, &r);
}

static void take_text(HWND parent, int id, WCHAR *out, int size)
{
    DWORD_PTR r;
    out[0] = 0;
    SendMessageTimeoutW(GetDlgItem(parent, id), WM_GETTEXT, (WPARAM)size, (LPARAM)out, SMTO_ABORTIFHUNG, 5000, &r);
}

/* Plain ASCII copy for report details: quotes, backslashes and controls become spaces. */
static void plain(char *out, int size, const WCHAR *text)
{
    int i;
    for (i = 0; i < size - 1 && text && text[i]; ++i)
        out[i] = (char)(text[i] < 32 || text[i] > 126 || text[i] == '"' || text[i] == '\\' ? ' ' : text[i]);
    out[i] = 0;
}

static const WCHAR *find_w(const WCHAR *hay, const WCHAR *needle)
{
    int n = lstrlenW(needle);
    for (; hay && *hay; ++hay) {
        int i;
        for (i = 0; i < n; ++i) {
            WCHAR a = hay[i], b = needle[i];
            if (a >= 'A' && a <= 'Z') a = (WCHAR)(a + 32);
            if (b >= 'A' && b <= 'Z') b = (WCHAR)(b + 32);
            if (a != b) break;
        }
        if (i == n) return hay;
    }
    return NULL;
}

static const char *find_a(const char *hay, const char *needle)
{
    int n = lstrlenA(needle);
    for (; hay && *hay; ++hay) {
        int i;
        for (i = 0; i < n && hay[i] == needle[i]; ++i) {}
        if (i == n) return hay;
    }
    return NULL;
}

static DWORD run(const WCHAR *command_line, DWORD timeout_ms)
{
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    WCHAR line[1600];
    DWORD code = 0xFFFF;
    zero(&si, sizeof(si));
    si.cb = sizeof(si);
    lstrcpynW(line, command_line, 1600);
    if (!CreateProcessW(NULL, line, NULL, NULL, FALSE, 0, NULL, WORK, &si, &pi)) return 0xFFFE;
    if (WaitForSingleObject(pi.hProcess, timeout_ms * scale) == WAIT_OBJECT_0) GetExitCodeProcess(pi.hProcess, &code);
    else TerminateProcess(pi.hProcess, 0xFFFD);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return code;
}

static HANDLE start(const WCHAR *command_line, DWORD *pid)
{
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    WCHAR line[1600];
    zero(&si, sizeof(si));
    si.cb = sizeof(si);
    lstrcpynW(line, command_line, 1600);
    if (!CreateProcessW(NULL, line, NULL, NULL, FALSE, 0, NULL, WORK, &si, &pi)) return NULL;
    CloseHandle(pi.hThread);
    if (pid) *pid = pi.dwProcessId;
    return pi.hProcess;
}

/* Read a whole file (max 4 MB) into a NUL-terminated heap buffer. */
static char *slurp(const WCHAR *path)
{
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    DWORD size, got = 0;
    char *data;
    if (h == INVALID_HANDLE_VALUE) return NULL;
    size = GetFileSize(h, NULL);
    if (size > 4 * 1024 * 1024) size = 4 * 1024 * 1024;
    data = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size + 2);
    if (data) ReadFile(h, data, size, &got, NULL);
    CloseHandle(h);
    return data;
}

static BOOL write_text(const WCHAR *path, const char *text)
{
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD n;
    BOOL ok;
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    ok = WriteFile(h, text, (DWORD)lstrlenA(text), &n, NULL);
    CloseHandle(h);
    return ok;
}

static void age(const WCHAR *path, DWORD days_ago, const SYSTEMTIME *exact)
{
    HANDLE h = CreateFileW(path, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                           FILE_FLAG_BACKUP_SEMANTICS, NULL);
    FILETIME ft, local;
    ULARGE_INTEGER v;
    if (h == INVALID_HANDLE_VALUE) return;
    if (exact) { SystemTimeToFileTime(exact, &local); LocalFileTimeToFileTime(&local, &ft); }
    else {
        GetSystemTimeAsFileTime(&ft);
        v.LowPart = ft.dwLowDateTime;
        v.HighPart = ft.dwHighDateTime;
        v.QuadPart -= (ULONGLONG)days_ago * 864000000000ULL;
        ft.dwLowDateTime = v.LowPart;
        ft.dwHighDateTime = v.HighPart;
    }
    SetFileTime(h, &ft, NULL, &ft);
    CloseHandle(h);
}

static BOOL sized(const WCHAR *path, DWORD bytes)
{
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    BOOL ok;
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    ok = SetFilePointer(h, (LONG)bytes, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER && SetEndOfFile(h);
    CloseHandle(h);
    return ok;
}

static void fx(WCHAR *out, const WCHAR *relative) { cat(out, fixtures, L"\\"); lstrcatW(out, relative); }

static void section_fixtures(void)
{
    WCHAR p[MAX_PATH];
    SYSTEMTIME july;
    BOOL ok = TRUE;
    zero(&july, sizeof(july));
    july.wYear = 2024; july.wMonth = 7; july.wDay = 14; july.wHour = 12;
    CreateDirectoryW(fixtures, NULL);
    fx(p, L"Vacation 2024"); ok &= CreateDirectoryW(p, NULL) || GetLastError() == ERROR_ALREADY_EXISTS;
    fx(p, L"Videos"); ok &= CreateDirectoryW(p, NULL) || GetLastError() == ERROR_ALREADY_EXISTS;
    fx(p, L"Projects"); ok &= CreateDirectoryW(p, NULL) || GetLastError() == ERROR_ALREADY_EXISTS;
    fx(p, L"Network"); ok &= CreateDirectoryW(p, NULL) || GetLastError() == ERROR_ALREADY_EXISTS;
    fx(p, L"report-q3.pdf"); ok &= write_text(p, "%PDF-1.4\n% XP25 quarterly report fixture\n"); age(p, 1, NULL);
    fx(p, L"Vacation 2024\\beach.jpg"); ok &= sized(p, 180000); age(p, 0, &july);
    fx(p, L"Videos\\big-clip.avi"); ok &= sized(p, 30 * 1024 * 1024); age(p, 10, NULL);
    fx(p, L"Videos\\small-clip.wmv"); ok &= sized(p, 3 * 1024 * 1024); age(p, 10, NULL);
    fx(p, L"Insurance_Policy.doc"); ok &= write_text(p, "XP25 fixture: insurance policy document"); age(p, 5, NULL);
    fx(p, L"home-notes.txt"); ok &= write_text(p, "Home insurance policy number 77 for the house.\r\nRenew in March.\r\n"); age(p, 6, NULL);
    fx(p, L"Projects\\main.c"); ok &= write_text(p, "int main(void) { return 0; }\r\n"); age(p, 3, NULL);
    fx(p, L"Network\\network-config.ini");
    ok &= write_text(p, "[Network]\r\nIPAddress=192.168.1.50\r\nSubnetMask=255.255.255.0\r\nGateway=10.0.0.1\r\nDNS1=192.168.1.1\r\n");
    ok &= write_text(WORK L"\\keep-me.txt", "XP25 deny-test fixture: must survive.\r\n");
    report("fixtures_created", ok, "");
}

static BOOL search_cli(const char *name, const WCHAR *query, const char *expect, const char *absent, const char *before)
{
    WCHAR line[1200], out[MAX_PATH];
    char *json, detail[200];
    DWORD code;
    BOOL ok;
    wsprintfW(out, L"%s\\search-%S.json", WORK, name);
    wsprintfW(line, L"\"%s\\RoverAI.exe\" /search \"%s\" /limit 50 /out \"%s\"", APP, query, out);
    code = run(line, 240000);
    json = slurp(out);
    ok = code == 0 && json && find_a(json, "\"ok\":true") && (!expect || find_a(json, expect)) && (!absent || !find_a(json, absent));
    if (ok && before) ok = find_a(json, expect) < find_a(json, before) || !find_a(json, before);
    wsprintfA(detail, "exit %lu", code);
    report(name, ok, detail);
    if (json) HeapFree(GetProcessHeap(), 0, json);
    return ok;
}

static void section_rover_cli(void)
{
    WCHAR line[600], from[MAX_PATH], to[MAX_PATH];
    char *json, detail[200];
    DWORD code, start = GetTickCount();
    wsprintfW(line, L"\"%s\\RoverAI.exe\" /index /out \"%s\\index-1.json\"", APP, WORK);
    code = run(line, 900000);
    json = slurp(WORK L"\\index-1.json");
    wsprintfA(detail, "exit %lu in %lu ms", code, GetTickCount() - start);
    report("rover_index_created", code == 0 && json && find_a(json, "\"ok\":true") && !find_a(json, "\"entries\":0,"), detail);
    if (json) HeapFree(GetProcessHeap(), 0, json);
    search_cli("rover_filename_search", L"network-config", "network-config.ini", NULL, NULL);
    search_cli("rover_nl_pdf_yesterday", L"Find the PDF I edited yesterday.", "report-q3.pdf", NULL, NULL);
    search_cli("rover_nl_vacation_2024", L"Where are my vacation photos from 2024?", "beach.jpg", NULL, NULL);
    search_cli("rover_nl_largest_videos", L"Show me the largest video files.", "big-clip.avi", NULL, "small-clip.wmv");
    search_cli("rover_nl_insurance_document", L"Find the document about my insurance.", "Insurance_Policy.doc", NULL, NULL);
    search_cli("rover_content_match", L"Find the document about my insurance.", "home-notes.txt", NULL, NULL);
    search_cli("rover_nl_project_last_week", L"Show me the project files I worked on last week.", "main.c", NULL, NULL);
    search_cli("rover_filter_date_type", L"pdf modified yesterday", "report-q3.pdf", "beach.jpg", NULL);
    search_cli("rover_filter_size", L"files over 20 mb", "big-clip.avi", "small-clip.wmv", NULL);
    /* Incremental update after a rename and a deletion. */
    fx(from, L"home-notes.txt");
    fx(to, L"house-notes.txt");
    MoveFileW(from, to);
    fx(from, L"Videos\\small-clip.wmv");
    DeleteFileW(from);
    wsprintfW(line, L"\"%s\\RoverAI.exe\" /index /out \"%s\\index-2.json\"", APP, WORK);
    code = run(line, 900000);
    json = slurp(WORK L"\\index-2.json");
    /* The background indexer may already have saved these changes; the rescan must succeed and save. */
    report("rover_incremental_update", code == 0 && json && find_a(json, "\"ok\":true"), "");
    if (json) HeapFree(GetProcessHeap(), 0, json);
    search_cli("rover_rename_reflected", L"house-notes", "house-notes.txt", "home-notes.txt", NULL);
    search_cli("rover_delete_reflected", L"small-clip", NULL, "small-clip.wmv", NULL);
    search_cli("rover_kept_after_delete", L"big-clip", "big-clip.avi", NULL, NULL);
}

/* Real-time updates from the RoverAI background indexer (ReadDirectoryChangesW):
   the CLI searches load the saved index without rescanning; the measured
   delay until the change is visible is reported. */
static BOOL watch_until(const char *name, const WCHAR *query, const char *expect, const char *absent)
{
    WCHAR line[1200], out[MAX_PATH];
    char *json, detail[120];
    DWORD t0 = GetTickCount();
    BOOL ok = FALSE;
    wsprintfW(out, L"%s\\watch-%S.json", WORK, name);
    wsprintfW(line, L"\"%s\\RoverAI.exe\" /search \"%s\" /limit 50 /out \"%s\"", APP, query, out);
    do {
        Sleep(2000);
        json = run(line, 240000) == 0 ? slurp(out) : NULL;
        ok = json && find_a(json, "\"ok\":true") && (!expect || find_a(json, expect)) && (!absent || !find_a(json, absent));
        if (json) HeapFree(GetProcessHeap(), 0, json);
    } while (!ok && GetTickCount() - t0 < 90000 * scale);
    wsprintfA(detail, "visible after %lu ms", GetTickCount() - t0);
    report(name, ok, detail);
    return ok;
}

static void section_watcher(void)
{
    WCHAR a[MAX_PATH], b[MAX_PATH];
    fx(a, L"watch-me-xp25.txt");
    fx(b, L"watched-renamed-xp25.txt");
    write_text(a, "watcher fixture\r\n");
    watch_until("rover_watcher_sees_new_file", L"watch-me-xp25", "watch-me-xp25.txt", NULL);
    MoveFileW(a, b);
    watch_until("rover_watcher_sees_rename", L"watched-renamed-xp25", "watched-renamed-xp25.txt", "watch-me-xp25.txt");
    DeleteFileW(b);
    watch_until("rover_watcher_sees_delete", L"watched-renamed-xp25", NULL, "watched-renamed-xp25.txt");
}

typedef struct { const WCHAR *cls; HWND found; DWORD pid; } FINDER;

static BOOL CALLBACK find_child(HWND w, LPARAM lp)
{
    FINDER *f = (FINDER *)lp;
    WCHAR cls[80];
    GetClassNameW(w, cls, 80);
    if (!lstrcmpW(cls, f->cls)) { f->found = w; return FALSE; }
    return TRUE;
}

static HWND descendant(HWND parent, const WCHAR *cls)
{
    FINDER f;
    f.cls = cls;
    f.found = NULL;
    EnumChildWindows(parent, find_child, (LPARAM)&f);
    return f.found;
}

static HWND wait_window(const WCHAR *cls, const WCHAR *title, DWORD ms)
{
    DWORD t0 = GetTickCount();
    HWND w;
    do {
        w = FindWindowW(cls, title);
        if (w && IsWindowVisible(w)) return w;
        Sleep(250);
    } while (GetTickCount() - t0 < ms * scale);
    return NULL;
}

/* List view text across processes: the item buffers live in the owner. */
static BOOL list_text(HWND list, int item, int column, WCHAR *out, int size)
{
    DWORD pid;
    HANDLE process;
    BYTE *remote;
    LVITEMW lv;
    SIZE_T done;
    BOOL ok = FALSE;
    GetWindowThreadProcessId(list, &pid);
    process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid);
    if (!process) return FALSE;
    remote = (BYTE *)VirtualAllocEx(process, NULL, sizeof(lv) + 1024, MEM_COMMIT, PAGE_READWRITE);
    if (remote) {
        zero(&lv, sizeof(lv));
        lv.iSubItem = column;
        lv.pszText = (WCHAR *)(remote + sizeof(lv));
        lv.cchTextMax = 500;
        if (WriteProcessMemory(process, remote, &lv, sizeof(lv), &done) &&
            SendMessageW(list, LVM_GETITEMTEXTW_, (WPARAM)item, (LPARAM)remote) >= 0 &&
            ReadProcessMemory(process, remote + sizeof(lv), out, (SIZE_T)size * sizeof(WCHAR), &done)) {
            out[size - 1] = 0;
            ok = TRUE;
        }
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    }
    CloseHandle(process);
    return ok;
}

static BOOL list_select(HWND list, int item)
{
    DWORD pid;
    HANDLE process;
    BYTE *remote;
    LVITEMW lv;
    SIZE_T done;
    BOOL ok = FALSE;
    GetWindowThreadProcessId(list, &pid);
    process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid);
    if (!process) return FALSE;
    remote = (BYTE *)VirtualAllocEx(process, NULL, sizeof(lv), MEM_COMMIT, PAGE_READWRITE);
    if (remote) {
        zero(&lv, sizeof(lv));
        lv.stateMask = LVIS_SELECTED | LVIS_FOCUSED;
        lv.state = LVIS_SELECTED | LVIS_FOCUSED;
        ok = WriteProcessMemory(process, remote, &lv, sizeof(lv), &done) &&
             SendMessageW(list, LVM_SETITEMSTATE_, (WPARAM)item, (LPARAM)remote);
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    }
    CloseHandle(process);
    return ok;
}

static int wait_items(HWND list, DWORD ms)
{
    DWORD t0 = GetTickCount();
    int n = 0;
    do {
        n = (int)SendMessageW(list, LVM_GETITEMCOUNT_, 0, 0);
        if (n > 0) return n;
        Sleep(300);
    } while (GetTickCount() - t0 < ms * scale);
    return n;
}

static int item_named(HWND list, const WCHAR *name)
{
    int i, n = (int)SendMessageW(list, LVM_GETITEMCOUNT_, 0, 0);
    WCHAR text[260];
    for (i = 0; i < n; ++i) if (list_text(list, i, 0, text, 260) && !lstrcmpiW(text, name)) return i;
    return -1;
}

static HWND top_with_title(const WCHAR *part, DWORD ms);

static BOOL CALLBACK title_finder(HWND w, LPARAM lp)
{
    FINDER *f = (FINDER *)lp;
    WCHAR title[300];
    if (!IsWindowVisible(w)) return TRUE;
    GetWindowTextW(w, title, 300);
    if (find_w(title, f->cls)) { f->found = w; return FALSE; }
    return TRUE;
}

static HWND top_with_title(const WCHAR *part, DWORD ms)
{
    DWORD t0 = GetTickCount();
    FINDER f;
    do {
        f.cls = part;
        f.found = NULL;
        EnumWindows(title_finder, (LPARAM)&f);
        if (f.found) return f.found;
        Sleep(300);
    } while (GetTickCount() - t0 < ms * scale);
    return NULL;
}

static void section_rover_ui(void)
{
    WCHAR line[600], name[260];
    HWND window, panel, list, notepad, folder;
    HANDLE process;
    int n, index;
    wsprintfW(line, L"\"%s\\RoverAI.exe\" /query \"house-notes\"", APP);
    process = start(line, NULL);
    window = wait_window(L"XP25RoverAI", NULL, 30000);
    report("rover_window_starts", window != NULL, "");
    if (!window) { if (process) CloseHandle(process); return; }
    panel = descendant(window, L"XP25RoverAIPanel");
    list = panel ? GetDlgItem(panel, IDC_RV_RESULTS) : NULL;
    n = list ? wait_items(list, 60000) : 0;
    index = list ? item_named(list, L"house-notes.txt") : -1;
    report("rover_ui_results_shown", n > 0 && index >= 0, "");
    if (index >= 0 && list_select(list, index)) {
        PostMessageW(panel, WM_COMMAND, IDC_RV_OPEN, 0);
        notepad = top_with_title(L"house-notes", 20000);   /* "house-notes - Notepad" with extensions hidden */
        report("rover_open_file", notepad != NULL, "");
        if (notepad) PostMessageW(notepad, WM_CLOSE, 0, 0);
        PostMessageW(panel, WM_COMMAND, IDC_RV_FOLDER, 0);
        folder = top_with_title(L"XP25AI-Fixtures", 20000);
        report("rover_open_containing_folder", folder != NULL, "");
        if (folder) PostMessageW(folder, WM_CLOSE, 0, 0);
        list_text(list, index, 1, name, 260);
        report("rover_result_path_column", find_w(name, L"XP25AI-Fixtures") != NULL, "");
    }
    PostMessageW(window, WM_CLOSE, 0, 0);
    if (process) {
        report("rover_window_closes", WaitForSingleObject(process, 15000 * scale) == WAIT_OBJECT_0, "");
        CloseHandle(process);
    }
}

static DWORD shell_pid(void)
{
    DWORD pid = 0;
    HWND tray = FindWindowW(L"Shell_TrayWnd", NULL);
    if (tray) GetWindowThreadProcessId(tray, &pid);
    return pid;
}

static void section_explorer(void)
{
    DWORD before = shell_pid(), t0;
    HWND cabinet, panel = NULL, list;
    HANDLE shell;
    int n = 0;
    char detail[120];
    report("explorer_shell_running", before != 0, "");
    ShellExecuteW(NULL, L"open", docs, NULL, NULL, SW_SHOWNORMAL);
    cabinet = top_with_title(L"My Documents", 30000);
    report("explorer_folder_window", cabinet != NULL, "");
    if (!cabinet) return;
    /* Explorer's Search command (toolbar button, View > Explorer Bar > Search). */
    PostMessageW(cabinet, WM_COMMAND, CMD_SEARCH_BAR, 0);
    t0 = GetTickCount();
    while (!(panel = descendant(cabinet, L"XP25RoverAIPanel")) && GetTickCount() - t0 < 20000 * scale) Sleep(300);
    note("explorer_search_command", panel ? "RoverAI panel shown" : "no RoverAI panel");
    if (!panel) {
        /* F3, exactly as a user presses it in the folder window. */
        SetForegroundWindow(cabinet);
        Sleep(1000);
        keybd_event(VK_F3, 0, 0, 0);
        keybd_event(VK_F3, 0, KEYEVENTF_KEYUP, 0);
        t0 = GetTickCount();
        while (!(panel = descendant(cabinet, L"XP25RoverAIPanel")) && GetTickCount() - t0 < 20000 * scale) Sleep(300);
        note("explorer_f3", panel ? "RoverAI panel shown" : "no RoverAI panel");
    }
    /* Explorer creates the band hidden and shows it with ShowDW; wait for that. */
    t0 = GetTickCount();
    while (panel && !IsWindowVisible(panel) && GetTickCount() - t0 < 20000 * scale) Sleep(300);
    report("explorer_search_opens_roverai", panel != NULL && IsWindowVisible(panel), "");
    if (panel) {
        put_text(panel, IDC_RV_QUERY, L"report-q3");
        PostMessageW(panel, WM_COMMAND, IDC_RV_GO, 0);
        list = GetDlgItem(panel, IDC_RV_RESULTS);
        n = list ? wait_items(list, 120000) : 0;
        wsprintfA(detail, "%d items", n);
        report("explorer_roverai_search_results", n > 0 && item_named(list, L"report-q3.pdf") >= 0, detail);
        PostMessageW(cabinet, WM_COMMAND, CMD_SEARCH_BAR, 0);
        Sleep(3000);
        report("explorer_roverai_closes", !descendant(cabinet, L"XP25RoverAIPanel") ||
               !IsWindowVisible(descendant(cabinet, L"XP25RoverAIPanel")), "");
    }
    PostMessageW(cabinet, WM_CLOSE, 0, 0);
    Sleep(4000);
    shell = OpenProcess(SYNCHRONIZE, FALSE, before);
    report("explorer_stable_after_roverai", shell && WaitForSingleObject(shell, 0) == WAIT_TIMEOUT && shell_pid() == before, "");
    if (shell) CloseHandle(shell);
    ShellExecuteW(NULL, L"open", fixtures, NULL, NULL, SW_SHOWNORMAL);
    cabinet = top_with_title(L"XP25AI-Fixtures", 30000);
    report("explorer_navigation_after_roverai", cabinet != NULL && shell_pid() == before, "");
    if (cabinet) PostMessageW(cabinet, WM_CLOSE, 0, 0);
}

static HWND clippy;

static int chat_text(WCHAR *out, int size)
{
    HWND chat = clippy ? FindWindowExW(clippy, NULL, L"XP25ChatView", NULL) : NULL;
    DWORD_PTR got = 0;
    out[0] = 0;
    if (!chat || !SendMessageTimeoutW(chat, WM_GETTEXT, (WPARAM)size, (LPARAM)out, SMTO_ABORTIFHUNG, 5000, &got)) return 0;
    return (int)got;
}

static WCHAR *chat_buffer;
#define CHAT_CHARS 200000

static BOOL wait_chat(const WCHAR *needle, DWORD ms)
{
    DWORD t0 = GetTickCount();
    do {
        if (chat_text(chat_buffer, CHAT_CHARS) && find_w(chat_buffer, needle)) return TRUE;
        Sleep(500);
    } while (GetTickCount() - t0 < ms * scale);
    return FALSE;
}

/* Note the first transcript line containing needle after the latest anchor. */
static void note_chat_line(const char *name, const WCHAR *anchor, const WCHAR *needle)
{
    const WCHAR *p, *from = NULL, *hit;
    WCHAR line[300];
    char detail[300];
    int i;
    chat_text(chat_buffer, CHAT_CHARS);
    for (p = chat_buffer; (p = find_w(p, anchor)) != NULL; ++p) from = p;
    hit = from ? find_w(from, needle) : NULL;
    if (!hit) { note(name, "not in transcript"); return; }
    while (hit > chat_buffer && hit[-1] != L'\n') --hit;
    for (i = 0; i < 299 && hit[i] && hit[i] != L'\r' && hit[i] != L'\n'; ++i) line[i] = hit[i];
    line[i] = 0;
    plain(detail, sizeof(detail), line);
    note(name, detail);
}

static int chat_count(const WCHAR *needle)
{
    const WCHAR *p;
    int n = 0;
    chat_text(chat_buffer, CHAT_CHARS);
    for (p = chat_buffer; (p = find_w(p, needle)) != NULL; ++p) ++n;
    return n;
}

static void ask(const WCHAR *text)
{
    put_text(clippy, IDC_INPUT, text);
    PostMessageW(clippy, WM_COMMAND, IDC_SEND, 0);
}

/* Answer the next approval dialog; returns its exact command text. */
static BOOL approval(BOOL approve, WCHAR *command, int size, DWORD ms)
{
    HWND dlg = wait_window(L"#32770", L"ClippyAI - Approval Required", ms);
    if (command) command[0] = 0;
    if (!dlg) return FALSE;
    if (command) take_text(dlg, IDC_AP_COMMAND, command, size);
    Sleep(300);
    PostMessageW(dlg, WM_COMMAND, approve ? IDOK : IDCANCEL, 0);
    Sleep(500);
    return TRUE;
}

static BOOL wait_idle(DWORD ms)
{
    DWORD t0 = GetTickCount();
    HWND send = GetDlgItem(clippy, IDC_SEND);
    Sleep(500);
    do {
        if (IsWindowEnabled(send)) return TRUE;
        Sleep(300);
    } while (GetTickCount() - t0 < ms * scale);
    return FALSE;
}

static void section_clippy(void)
{
    WCHAR line[600], command[1000];
    char detail[300], *proof;
    HANDLE process;
    int before;
    wsprintfW(line, L"\"%s\\ClippyAI.exe\"", APP);
    process = start(line, NULL);
    clippy = wait_window(L"XP25ClippyAI", L"ClippyAI", 30000);
    report("clippy_starts", clippy != NULL, "");
    if (process) CloseHandle(process);
    if (!clippy) return;
    report("clippy_chat_ui_renders", FindWindowExW(clippy, NULL, L"XP25ChatView", NULL) && GetDlgItem(clippy, IDC_INPUT) &&
           GetDlgItem(clippy, IDC_SEND) && wait_chat(L"I'm ClippyAI", 10000), "");
    report("clippy_offline_by_default", wait_chat(L"Offline assistant", 5000), "");
    report("desktop_shortcut_present", GetFileAttributesW(L"C:\\Documents and Settings\\XP25\\Desktop\\ClippyAI.lnk") !=
           INVALID_FILE_ATTRIBUTES, "");
    ask(L"Show recent errors in Event Viewer");
    report("clippy_eventlog_tool", wait_chat(L"eventlog_read: completed", 60000), "");
    report("clippy_eventlog_answer", wait_chat(L"Event Viewer, last 7 days", 30000) && wait_idle(30000), "");
    ask(L"run ipconfig /all");
    report("clippy_cmd_readonly_runs", wait_chat(L"Windows IP Configuration", 60000) && wait_idle(30000), "");
    before = chat_count(L"cmd_execute: completed");
    ask(L"run echo XP25-APPROVED-CMD> C:\\xp25\\ai\\cmd-proof.txt");
    report("clippy_cmd_approval_dialog", approval(TRUE, command, 1000, 30000) &&
           find_w(command, L"cmd.exe /d /c echo XP25-APPROVED-CMD> C:\\xp25\\ai\\cmd-proof.txt") != NULL, "");
    wait_idle(60000);
    proof = slurp(WORK L"\\cmd-proof.txt");
    report("clippy_cmd_approved_executes", proof && find_a(proof, "XP25-APPROVED-CMD") && chat_count(L"cmd_execute: completed") > before, "");
    if (proof) HeapFree(GetProcessHeap(), 0, proof);
    ask(L"run del C:\\xp25\\ai\\keep-me.txt");
    report("clippy_cmd_deny_dialog", approval(FALSE, command, 1000, 30000) && find_w(command, L"keep-me.txt") != NULL, "");
    wait_idle(60000);
    report("clippy_denied_nothing_changed", GetFileAttributesW(WORK L"\\keep-me.txt") != INVALID_FILE_ATTRIBUTES &&
           wait_chat(L"you declined it", 10000), "");
    ask(L"run dir C:\\xp25-does-not-exist");
    report("clippy_failed_command_reported", wait_chat(L"Command FAILED, exit code 1", 60000) &&
           wait_chat(L"The command failed", 20000), "");
    wait_idle(30000);
    plain(detail, sizeof(detail), command);
    note("last_approval_command", detail);
}

static volatile LONG burning = 1;

static DWORD WINAPI burn_thread(void *p)
{
    volatile DWORD x = 0;
    (void)p;
    while (burning) ++x;
    return x;
}

static ULONGLONG ft(const FILETIME *f) { return ((ULONGLONG)f->dwHighDateTime << 32) | f->dwLowDateTime; }

/* One 1.5 s sample of a process, computed like the process_list tool
   (process time over GetTickCount wall time and all processors). */
static void sample_note(const char *name, HANDLE process, const char *label)
{
    FILETIME c, e, k1, u1, k2, u2, i1, sk1, su1, i2, sk2, su2;
    SYSTEM_INFO si;
    DWORD t1, t2, wall;
    ULONGLONG proc, idle, total;
    char detail[220];
    GetSystemInfo(&si);
    GetProcessTimes(process, &c, &e, &k1, &u1);
    GetSystemTimes(&i1, &sk1, &su1);
    t1 = GetTickCount();
    Sleep(1500);
    t2 = GetTickCount();
    GetProcessTimes(process, &c, &e, &k2, &u2);
    GetSystemTimes(&i2, &sk2, &su2);
    wall = t2 - t1 ? t2 - t1 : 1;
    proc = ft(&k2) + ft(&u2) - ft(&k1) - ft(&u1);
    idle = ft(&i2) - ft(&i1);
    total = ft(&sk2) + ft(&su2) - ft(&sk1) - ft(&su1);
    wsprintfA(detail, "%s: wall %lu ms, process %lu ms = %lu%% of %lu processors, system busy %lu%%", label, wall,
              (DWORD)(proc / 10000), (DWORD)(proc / 100 / ((ULONGLONG)wall * si.dwNumberOfProcessors)),
              si.dwNumberOfProcessors, total ? (DWORD)(100 - idle * 100 / total) : 0);
    note(name, detail);
}

/* Diagnostic mode "cpu": how one busy thread is accounted on this guest,
   unpinned and then pinned to each processor. Notes only. */
static void section_cpu(void)
{
    WCHAR self[MAX_PATH], line[MAX_PATH + 16];
    SYSTEM_INFO si;
    HANDLE hog;
    DWORD pass, round;
    char label[40];
    GetSystemInfo(&si);
    GetModuleFileNameW(NULL, self, MAX_PATH);
    wsprintfW(line, L"\"%s\" burn", self);
    hog = start(line, NULL);
    if (!hog) { note("cpu_sample", "burn child did not start"); return; }
    Sleep(2000);
    for (pass = 0; pass <= si.dwNumberOfProcessors && pass <= 2; ++pass) {
        if (pass && !SetProcessAffinityMask(hog, (DWORD_PTR)1 << (pass - 1))) continue;
        Sleep(1000);
        for (round = 0; round < 4; ++round) {
            wsprintfA(label, "%s round %lu", !pass ? "unpinned" : pass == 1 ? "pinned CPU0" : "pinned CPU1", round + 1);
            sample_note("cpu_sample", hog, label);
        }
    }
    TerminateProcess(hog, 0);
    CloseHandle(hog);
}

static void section_slow(void)
{
    WCHAR line[600], command[1000];
    HANDLE hog;
    DWORD pid = 0;
    char detail[400];
    CopyFileW(WORK L"\\ai_probe.exe", WORK L"\\ai_cpuhog.exe", FALSE);
    wsprintfW(line, L"\"%s\\ai_cpuhog.exe\" burn", WORK);
    hog = start(line, &pid);
    report("slow_fixture_started", hog != NULL, "");
    if (!hog) return;
    Sleep(4000);
    sample_note("slow_hog_sample", hog, "before asking");
    ask(L"My computer is running slowly. Fix it.");
    report("slow_workflow_proposes_fix", approval(TRUE, command, 1000, 120000) && find_w(command, L"ai_cpuhog.exe") != NULL, "");
    plain(detail, sizeof(detail), command);
    note("slow_proposal", detail);
    report("slow_workflow_resolved", wait_chat(L"The problem is resolved", 120000) &&
           WaitForSingleObject(hog, 5000) == WAIT_OBJECT_0, "");
    report("slow_workflow_used_real_tools", wait_chat(L"system_info: completed", 1000) && wait_chat(L"process_list: completed", 1000) &&
           wait_chat(L"eventlog_read: completed", 1000) && wait_chat(L"disk_diagnostics: completed", 1000) &&
           wait_chat(L"process_control: completed", 1000), "");
    note_chat_line("slow_processor", L"I checked this computer's processor", L"% busy");
    note_chat_line("slow_hog_measured", L"I checked this computer's processor", L"ai_cpuhog.exe (PID");
    note_chat_line("slow_likely_cause", L"I checked this computer's processor", L"Likely cause:");
    TerminateProcess(hog, 0);
    CloseHandle(hog);
    wait_idle(30000);
}

static void section_find(void)
{
    WCHAR command[1000], p[MAX_PATH], bak[MAX_PATH];
    char *now;
    ask(L"Find my network configuration file and explain what's wrong.");
    report("find_explain_read_approval", approval(TRUE, command, 1000, 180000) && find_w(command, L"network-config.ini") != NULL, "");
    report("find_explain_fix_proposed", approval(TRUE, command, 1000, 60000) && find_w(command, L"Edit line 4") != NULL, "");
    report("find_explain_reported", wait_chat(L"outside this computer's subnet", 60000) &&
           wait_chat(L"Fix applied with your approval", 30000), "");
    fx(p, L"Network\\network-config.ini");
    lstrcpyW(bak, p);
    lstrcatW(bak, L".bak");
    now = slurp(p);
    report("find_explain_file_fixed", now && find_a(now, "Gateway=192.168.1.1") && GetFileAttributesW(bak) != INVALID_FILE_ATTRIBUTES, "");
    if (now) HeapFree(GetProcessHeap(), 0, now);
    wait_idle(30000);
}

static void section_handoff(void)
{
    WCHAR line[600], command[1000];
    HWND window, panel, list;
    HANDLE process;
    int index;
    wsprintfW(line, L"\"%s\\RoverAI.exe\" /query \"house-notes\"", APP);
    process = start(line, NULL);
    window = wait_window(L"XP25RoverAI", NULL, 30000);
    panel = window ? descendant(window, L"XP25RoverAIPanel") : NULL;
    list = panel ? GetDlgItem(panel, IDC_RV_RESULTS) : NULL;
    index = list && wait_items(list, 60000) > 0 ? item_named(list, L"house-notes.txt") : -1;
    if (index >= 0 && list_select(list, index)) PostMessageW(panel, WM_COMMAND, IDC_RV_EXPLAIN, 0);
    report("handoff_rover_to_clippy_request", index >= 0 && approval(TRUE, command, 1000, 60000) &&
           find_w(command, L"house-notes.txt") != NULL, "");
    report("handoff_clippy_explains", wait_chat(L"I read C:\\Documents and Settings\\XP25\\My Documents\\XP25AI-Fixtures\\house-notes.txt", 60000), "");
    if (window) PostMessageW(window, WM_CLOSE, 0, 0);
    if (process) { WaitForSingleObject(process, 10000); CloseHandle(process); }
    wait_idle(30000);
}

static void section_tray(void)
{
    PostMessageW(clippy, WM_SYSCOMMAND, SC_MINIMIZE, 0);
    Sleep(2000);
    report("clippy_minimizes_to_tray", !IsWindowVisible(clippy) && IsWindow(clippy), "");
    PostMessageW(clippy, WM_COMMAND, IDM_TRAY_OPEN, 0);
    Sleep(2000);
    report("clippy_restores_from_tray", IsWindowVisible(clippy), "");
}

static BOOL configure(int provider, const WCHAR *endpoint, const WCHAR *secret)
{
    HWND dlg;
    PostMessageW(clippy, WM_COMMAND, IDM_SETTINGS, 0);
    dlg = wait_window(L"#32770", L"ClippyAI Settings", 20000);
    if (!dlg) return FALSE;
    SendDlgItemMessageW(dlg, IDC_ST_PROVIDER, CB_SETCURSEL, (WPARAM)provider, 0);
    put_text(dlg, IDC_ST_ENDPOINT, endpoint);
    put_text(dlg, IDC_ST_MODEL, L"xp25-mock-model");
    put_text(dlg, IDC_ST_CLIENT, L"xp25");
    /* The key field is a password edit, which does not accept text from another
       process; type it the way a user does, then confirm. */
    {
        HWND key = GetDlgItem(dlg, IDC_ST_SECRET);
        const WCHAR *c;
        for (c = secret; *c; ++c) PostMessageW(key, WM_CHAR, (WPARAM)*c, 1);
    }
    PostMessageW(dlg, WM_COMMAND, IDOK, 0);
    Sleep(1500);
    if (IsWindow(dlg)) {
        WCHAR why[400];
        char detail[400];
        take_text(dlg, IDC_ST_RESULT, why, 400);
        plain(detail, sizeof(detail), why);
        note("settings_not_accepted", detail);
        PostMessageW(dlg, WM_COMMAND, IDCANCEL, 0);
        Sleep(500);
        return FALSE;
    }
    return TRUE;
}

/* DPAPI in this logon session, as ClippyAI uses it. */
static void section_dpapi(void)
{
    static const char entropy_text[] = "XP25-Agent-Protected-v1";
    DATA_BLOB in, out, entropy, back;
    char detail[160];
    BOOL protect, unprotect = FALSE;
    in.pbData = (BYTE *)"probe-secret";
    in.cbData = 12;
    entropy.pbData = (BYTE *)entropy_text;
    entropy.cbData = sizeof(entropy_text) - 1;
    protect = CryptProtectData(&in, L"probe", &entropy, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &out);
    wsprintfA(detail, "protect %d error %lu", protect, protect ? 0 : GetLastError());
    if (protect) {
        unprotect = CryptUnprotectData(&out, NULL, &entropy, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &back);
        wsprintfA(detail + lstrlenA(detail), " unprotect %d error %lu", unprotect, unprotect ? 0 : GetLastError());
        if (unprotect) LocalFree(back.pbData);
        LocalFree(out.pbData);
    }
    note(protect && unprotect ? "dpapi_round_trip_ok" : "dpapi_round_trip_failed", detail);
    protect = CryptProtectData(&in, NULL, NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE, &out);
    wsprintfA(detail, "machine scope protect %d error %lu", protect, protect ? 0 : GetLastError());
    if (protect) LocalFree(out.pbData);
    note("dpapi_machine_scope", detail);
    {
        CREDENTIALW cred, *read = NULL;
        BOOL wrote, got = FALSE;
        zero(&cred, sizeof(cred));
        cred.Type = CRED_TYPE_GENERIC;
        cred.TargetName = L"XP25AI-probe";
        cred.CredentialBlobSize = 12;
        cred.CredentialBlob = (BYTE *)"probe-secret";
        cred.Persist = CRED_PERSIST_LOCAL_MACHINE;
        cred.UserName = L"xp25";
        wrote = CredWriteW(&cred, 0);
        wsprintfA(detail, "credwrite %d error %lu", wrote, wrote ? 0 : GetLastError());
        if (wrote) {
            got = CredReadW(L"XP25AI-probe", CRED_TYPE_GENERIC, 0, &read);
            wsprintfA(detail + lstrlenA(detail), " credread %d error %lu", got, got ? 0 : GetLastError());
            if (got) CredFree(read);
            CredDeleteW(L"XP25AI-probe", CRED_TYPE_GENERIC, 0);
        }
        note("credential_manager", detail);
    }
}

static void section_provider(const WCHAR *secret)
{
    HWND share;
    report("provider_configured_gateway", configure(1, L"http://10.25.0.1:8443", secret) &&
           wait_chat(L"AI provider: XP25 gateway", 10000), "");
    ask(L"Show recent errors in Event Viewer");
    share = wait_window(L"#32770", L"ClippyAI - Share Data?", 90000);
    report("provider_tool_call_and_share_prompt", share != NULL && wait_chat(L"eventlog_read: completed", 5000), "");
    if (share) PostMessageW(share, WM_COMMAND, IDOK, 0);
    report("provider_openai_response_via_gateway", wait_chat(L"MOCK-OPENAI-RESPONSES", 90000), "");
    wait_idle(60000);
    report("provider_reconfigured_wrong_secret", configure(1, L"http://10.25.0.1:8443", L"00112233445566778899aabbccddeeff00112233"), "");
    ask(L"hello there");
    report("provider_auth_failure_reported", wait_chat(L"gateway_auth_failed", 90000) &&
           wait_chat(L"Continuing with the offline assistant", 30000), "");
    wait_idle(60000);
    configure(1, L"http://10.25.0.99:8443", secret);
    ask(L"How much disk space is free?");
    report("provider_unreachable_falls_back_offline", wait_chat(L"Disk diagnostics", 180000), "");
    wait_idle(60000);
    report("provider_restored_offline", configure(0, L"", L""), "");
}

static WCHAR *argv_at(int index)
{
    int argc = 0;
    WCHAR **argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    return argv && index < argc ? argv[index] : NULL;
}

void WINAPI ProbeMain(void)
{
    WCHAR *mode = argv_at(1), *arg2 = argv_at(2), *arg3 = argv_at(3);
    char row[200];
    if (mode && !lstrcmpiW(mode, L"burn")) {
        DWORD id;
        CreateThread(NULL, 0, burn_thread, NULL, 0, &id);
        Sleep(600000);
        ExitProcess(0);
    }
    serial = CreateFileA("COM1", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    CreateDirectoryW(WORK, NULL);
    results = CreateFileW(WORK L"\\results.jsonl", FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    chat_buffer = (WCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, CHAT_CHARS * sizeof(WCHAR));
    SHGetFolderPathW(NULL, CSIDL_PERSONAL, NULL, 0, docs);
    cat(fixtures, docs, L"\\XP25AI-Fixtures");
    if ((arg2 && !lstrcmpiW(arg2, L"slow")) || (arg3 && !lstrcmpiW(arg3, L"slow"))) scale = 4;
    emit("AI_PROBE_STARTED\r\n");
    if (mode && !lstrcmpiW(mode, L"cpu")) section_cpu();
    else if (mode && !lstrcmpiW(mode, L"dpapi")) section_dpapi();
    else if (mode && !lstrcmpiW(mode, L"provider") && arg2) {
        clippy = wait_window(L"XP25ClippyAI", L"ClippyAI", 30000);
        if (!clippy) report("provider_clippy_running", FALSE, "");
        else { section_dpapi(); section_provider(arg2); }
    } else {
        section_fixtures();
        section_rover_cli();
        section_watcher();
        section_rover_ui();
        section_explorer();
        section_clippy();
        if (clippy) {
            section_slow();
            section_find();
            section_handoff();
            section_tray();
        }
    }
    wsprintfA(row, "AI_PROBE_COMPLETE passes=%u failures=%u\r\n", passes, failures);
    emit(row);
    if (results != INVALID_HANDLE_VALUE) CloseHandle(results);
    if (serial != INVALID_HANDLE_VALUE) CloseHandle(serial);
    ExitProcess(failures);
}
