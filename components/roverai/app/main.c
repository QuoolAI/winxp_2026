/* RoverAI.exe: standalone RoverAI search window, background indexer and
   command line interface.
     RoverAI.exe                         search window
     RoverAI.exe /query "text"           search window, run the query
     RoverAI.exe /index [/out file]      update the local index now
     RoverAI.exe /search "text" [/scope folder] [/limit n] /out file
     RoverAI.exe /background             keep the index current (logon)
     RoverAI.exe /register | /unregister           Explorer bar
     RoverAI.exe /replace-search on|off            Search Companion redirect */
#include <windows.h>
#include <commctrl.h>
#include <objbase.h>
#include <shellapi.h>
#include <stdlib.h>
#include <string.h>
#include "../explorer/panel.h"
#include "../indexer/rover_win.h"

#define ROVER_WINDOW_CLASS L"XP25RoverAI"
#define IDI_ROVER 1

static HWND panel;

static int write_out(const WCHAR *out, const char *text)
{
    if (!out) return 1;
    return xp25w_write_file_atomic(out, text, (DWORD)strlen(text));
}

static int cli_index(const WCHAR *out)
{
    XP25W_PATHS paths;
    XP25_CONFIG config;
    ROVER_SETTINGS settings;
    ROVER_INDEX index;
    ROVER_SCAN_STATS stats;
    XP25_BUF json;
    XP25_JW w;
    DWORD start = GetTickCount();
    size_t i;
    int ok;
    xp25w_paths(&paths);
    xp25w_config_load(&config);
    if (!rover_settings_init(&settings, &config, &paths)) return 2;
    rover_index_init(&index);
    ok = rover_store_refresh(&index, &settings, 0, &stats);
    xp25_buf_init(&json);
    xp25_jw_init(&w, &json);
    xp25_jw_obj(&w);
    xp25_jw_key(&w, "ok"); xp25_jw_bool(&w, ok);
    xp25_jw_key(&w, "entries"); xp25_jw_u64(&w, (xp25_u64)index.count);
    xp25_jw_key(&w, "directories"); xp25_jw_u64(&w, stats.directories);
    xp25_jw_key(&w, "files"); xp25_jw_u64(&w, stats.files);
    xp25_jw_key(&w, "added"); xp25_jw_u64(&w, stats.added);
    xp25_jw_key(&w, "updated"); xp25_jw_u64(&w, stats.updated);
    xp25_jw_key(&w, "removed"); xp25_jw_u64(&w, stats.removed);
    xp25_jw_key(&w, "denied"); xp25_jw_u64(&w, stats.denied);
    xp25_jw_key(&w, "excluded"); xp25_jw_u64(&w, stats.excluded);
    xp25_jw_key(&w, "content_indexed"); xp25_jw_u64(&w, stats.content);
    xp25_jw_key(&w, "truncated"); xp25_jw_bool(&w, stats.truncated);
    xp25_jw_key(&w, "milliseconds"); xp25_jw_u64(&w, GetTickCount() - start);
    xp25_jw_key(&w, "roots"); xp25_jw_arr(&w);
    for (i = 0; i < settings.root_count; ++i) xp25_jw_str(&w, settings.roots[i]);
    xp25_jw_end(&w);
    xp25_jw_key(&w, "excludes"); xp25_jw_arr(&w);
    for (i = 0; i < settings.exclude_count; ++i) xp25_jw_str(&w, settings.excludes[i]);
    xp25_jw_end(&w);
    xp25_jw_end(&w);
    write_out(out, xp25_buf_cstr(&json));
    xp25_buf_free(&json);
    rover_index_free(&index);
    rover_settings_free(&settings);
    return ok ? 0 : 1;
}

static int cli_search(const char *query, const char *scope, int limit, const WCHAR *out)
{
    XP25W_PATHS paths;
    XP25_CONFIG config;
    ROVER_SETTINGS settings;
    ROVER_RESULTS results;
    XP25_BUF json;
    int ok;
    xp25w_paths(&paths);
    xp25w_config_load(&config);
    if (!rover_settings_init(&settings, &config, &paths)) return 2;
    ok = rover_query_run(query, scope, limit, ROVER_AI_NEVER, NULL, &settings, &results);
    xp25_buf_init(&json);
    if (ok) rover_results_json(&results, query, &json);
    else xp25_result_error(&json, "search_failed", results.note[0] ? results.note : "search failed");
    write_out(out, xp25_buf_cstr(&json));
    xp25_buf_free(&json);
    rover_results_free(&results);
    rover_settings_free(&settings);
    return ok ? 0 : 1;
}

static int band_call(const char *export_name, int argument)
{
    WCHAR dll[MAX_PATH], *slash;
    HMODULE module;
    HRESULT hr = E_FAIL;
    GetModuleFileNameW(NULL, dll, MAX_PATH);
    slash = wcsrchr(dll, L'\\');
    if (!slash) return 2;
    lstrcpyW(slash + 1, L"RoverAIBand.dll");
    module = LoadLibraryW(dll);
    if (!module) return 3;
    if (argument < 0) {
        HRESULT (STDAPICALLTYPE *fn)(void) = (HRESULT (STDAPICALLTYPE *)(void))GetProcAddress(module, export_name);
        if (fn) hr = fn();
    } else {
        HRESULT (STDAPICALLTYPE *fn)(BOOL) = (HRESULT (STDAPICALLTYPE *)(BOOL))GetProcAddress(module, export_name);
        if (fn) hr = fn(argument ? TRUE : FALSE);
    }
    FreeLibrary(module);
    return SUCCEEDED(hr) ? 0 : 1;
}

static int background(void)
{
    XP25W_PATHS paths;
    XP25_CONFIG config;
    ROVER_SETTINGS settings;
    ROVER_INDEX index;
    ROVER_SCAN_STATS stats;
    CRITICAL_SECTION lock;
    ROVER_WATCH *watch;
    HANDLE single = CreateMutexW(NULL, FALSE, L"Local\\XP25RoverAIBackground");
    MSG msg;
    if (GetLastError() == ERROR_ALREADY_EXISTS) return 0;
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
    xp25w_paths(&paths);
    xp25w_config_load(&config);
    if (!rover_settings_init(&settings, &config, &paths)) return 2;
    rover_index_init(&index);
    rover_store_refresh(&index, &settings, 300, &stats);
    InitializeCriticalSection(&lock);
    watch = rover_watch_start(&settings, &index, &lock);
    /* Message loop so logoff (WM_QUIT/end session) ends the indexer cleanly. */
    while (GetMessageW(&msg, NULL, 0, 0) > 0) DispatchMessageW(&msg);
    rover_watch_stop(watch);
    DeleteCriticalSection(&lock);
    rover_index_free(&index);
    rover_settings_free(&settings);
    CloseHandle(single);
    return 0;
}

static LRESULT CALLBACK window_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE:
        panel = rover_panel_create(hwnd, ((CREATESTRUCTW *)lp)->hInstance, 0, 1);
        return panel ? 0 : -1;
    case WM_SIZE:
        MoveWindow(panel, 0, 0, LOWORD(lp), HIWORD(lp), TRUE);
        return 0;
    case WM_MOVE:
        SendMessageW(panel, WM_MOVE, 0, 0);
        return 0;
    case WM_ACTIVATE:
        if (LOWORD(wp) != WA_INACTIVE) rover_panel_activate(panel);
        return 0;
    case WM_GETMINMAXINFO:
        ((MINMAXINFO *)lp)->ptMinTrackSize.x = 640;
        ((MINMAXINFO *)lp)->ptMinTrackSize.y = 480;
        return 0;
    case WM_SYSCOMMAND:
        if ((wp & 0xFFF0) == SC_MINIMIZE) rover_panel_show_rover(panel, 0);
        else if ((wp & 0xFFF0) == SC_RESTORE) PostMessageW(hwnd, WM_APP, 0, 0);
        break;
    case WM_APP:
        rover_panel_show_rover(panel, 1);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE previous, LPWSTR command_line, int show)
{
    int argc = 0, i, limit = 100, code;
    WCHAR **argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    WCHAR *out = NULL, *query = NULL;
    char *search = NULL, *scope = NULL;
    INITCOMMONCONTROLSEX icc;
    WNDCLASSEXW wc;
    HWND window;
    MSG msg;
    (void)previous;
    (void)command_line;
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    for (i = 1; argv && i < argc; ++i) {
        if (!lstrcmpiW(argv[i], L"/out") && i + 1 < argc) out = argv[++i];
        else if (!lstrcmpiW(argv[i], L"/scope") && i + 1 < argc) scope = xp25w_utf8(argv[++i]);
        else if (!lstrcmpiW(argv[i], L"/limit") && i + 1 < argc) { limit = _wtoi(argv[++i]); if (limit < 1 || limit > 500) limit = 100; }
        else if (!lstrcmpiW(argv[i], L"/search") && i + 1 < argc) search = xp25w_utf8(argv[++i]);
        else if (!lstrcmpiW(argv[i], L"/query") && i + 1 < argc) query = argv[++i];
    }
    for (i = 1; argv && i < argc; ++i) {
        code = -1;
        if (!lstrcmpiW(argv[i], L"/index")) code = cli_index(out);
        else if (!lstrcmpiW(argv[i], L"/background")) code = background();
        else if (!lstrcmpiW(argv[i], L"/register")) code = band_call("DllRegisterServer", -1);
        else if (!lstrcmpiW(argv[i], L"/unregister")) code = band_call("DllUnregisterServer", -1);
        else if (!lstrcmpiW(argv[i], L"/replace-search") && i + 1 < argc)
            code = band_call("RoverAIReplaceSearch", !lstrcmpiW(argv[i + 1], L"on"));
        else if (!lstrcmpiW(argv[i], L"/search") && search) code = cli_search(search, scope, limit, out);
        if (code >= 0) {
            xp25_free(search);
            xp25_free(scope);
            LocalFree(argv);
            CoUninitialize();
            return code;
        }
    }
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_WIN95_CLASSES;
    InitCommonControlsEx(&icc);
    memset(&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = window_proc;
    wc.hInstance = instance;
    wc.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(IDI_ROVER));
    wc.hIconSm = (HICON)LoadImageW(instance, MAKEINTRESOURCEW(IDI_ROVER), IMAGE_ICON, 16, 16, 0);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = ROVER_WINDOW_CLASS;
    RegisterClassExW(&wc);
    window = CreateWindowExW(WS_EX_CONTROLPARENT, ROVER_WINDOW_CLASS, L"RoverAI Search", WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
                             CW_USEDEFAULT, CW_USEDEFAULT, 820, 600, NULL, NULL, instance, NULL);
    if (!window) return 1;
    ShowWindow(window, show);
    UpdateWindow(window);
    rover_panel_show_rover(panel, 1);
    if (query) rover_panel_set_query(panel, query, 1);
    else rover_panel_activate(panel);
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        if (IsDialogMessageW(panel, &msg)) continue;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    xp25_free(search);
    xp25_free(scope);
    if (argv) LocalFree(argv);
    CoUninitialize();
    return (int)msg.wParam;
}
