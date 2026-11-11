/* ClippyAI: XP25 desktop assistant. Window, tray icon, single instance,
   command line and shortcuts. Agent work happens in chat/controller.c. */
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <shlobj.h>
#include <objbase.h>
#include <string.h>
#include "clippyai.h"

CLIPPY_APP g_app;
static NOTIFYICONDATAW tray;
static const CLSID clsid_shell_link = { 0x00021401, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static const IID iid_shell_link_w = { 0x000214f9, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static const IID iid_persist_file = { 0x0000010b, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static UINT taskbar_created;

LRESULT controller_approve_message(WPARAM wp, LPARAM lp);
LRESULT controller_share_message(LPARAM lp);

void app_set_status(const char *text)
{
    WCHAR *w = xp25w_wide(text);
    if (g_app.status && w) SendMessageW(g_app.status, SB_SETTEXTW, 0, (LPARAM)w);
    xp25_free(w);
}

int app_autostart(int set, int enable)
{
    HKEY key;
    WCHAR exe[MAX_PATH], value[MAX_PATH + 16];
    DWORD type, size = sizeof(value);
    int present;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, NULL, 0,
                        KEY_READ | KEY_WRITE, NULL, &key, NULL) != ERROR_SUCCESS) return 0;
    present = RegQueryValueExW(key, L"XP25 ClippyAI", NULL, &type, (BYTE *)value, &size) == ERROR_SUCCESS;
    if (set) {
        if (enable) {
            GetModuleFileNameW(NULL, exe, MAX_PATH);
            lstrcpyW(value, L"\"");
            lstrcatW(value, exe);
            lstrcatW(value, L"\" /tray");
            RegSetValueExW(key, L"XP25 ClippyAI", 0, REG_SZ, (const BYTE *)value, (DWORD)((lstrlenW(value) + 1) * sizeof(WCHAR)));
        } else RegDeleteValueW(key, L"XP25 ClippyAI");
        present = enable;
    }
    RegCloseKey(key);
    return present;
}

static int shortcut(int csidl, const WCHAR *folder, const WCHAR *name, const WCHAR *target, const WCHAR *args,
                    const WCHAR *description)
{
    WCHAR path[MAX_PATH];
    IShellLinkW *link;
    IPersistFile *file;
    HRESULT hr;
    if (FAILED(SHGetFolderPathW(NULL, csidl, NULL, 0, path))) return 0;
    if (folder) {
        lstrcatW(path, L"\\");
        lstrcatW(path, folder);
        CreateDirectoryW(path, NULL);
    }
    lstrcatW(path, L"\\");
    lstrcatW(path, name);
    hr = CoCreateInstance(&clsid_shell_link, NULL, CLSCTX_INPROC_SERVER, &iid_shell_link_w, (void **)&link);
    if (FAILED(hr)) return 0;
    link->lpVtbl->SetPath(link, target);
    if (args) link->lpVtbl->SetArguments(link, args);
    link->lpVtbl->SetDescription(link, description);
    link->lpVtbl->SetIconLocation(link, target, 0);
    hr = link->lpVtbl->QueryInterface(link, &iid_persist_file, (void **)&file);
    if (SUCCEEDED(hr)) {
        hr = file->lpVtbl->Save(file, path, TRUE);
        file->lpVtbl->Release(file);
    }
    link->lpVtbl->Release(link);
    return SUCCEEDED(hr);
}

static int install(int remove)
{
    WCHAR exe[MAX_PATH], rover[MAX_PATH], *slash, path[MAX_PATH];
    int ok = 1;
    GetModuleFileNameW(NULL, exe, MAX_PATH);
    lstrcpyW(rover, exe);
    slash = wcsrchr(rover, L'\\');
    if (slash) lstrcpyW(slash + 1, L"RoverAI.exe");
    if (remove) {
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, path))) { lstrcatW(path, L"\\ClippyAI.lnk"); DeleteFileW(path); }
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PROGRAMS, NULL, 0, path))) {
            lstrcatW(path, L"\\XP25 AI");
            lstrcatW(path, L"\\ClippyAI.lnk"); DeleteFileW(path);
            slash = wcsrchr(path, L'\\'); lstrcpyW(slash + 1, L"RoverAI Search.lnk"); DeleteFileW(path);
            *slash = 0; RemoveDirectoryW(path);
        }
        app_autostart(1, 0);
        return 1;
    }
    ok &= shortcut(CSIDL_DESKTOPDIRECTORY, NULL, L"ClippyAI.lnk", exe, NULL, L"ClippyAI - XP25 desktop assistant");
    ok &= shortcut(CSIDL_PROGRAMS, L"XP25 AI", L"ClippyAI.lnk", exe, NULL, L"ClippyAI - XP25 desktop assistant");
    if (GetFileAttributesW(rover) != INVALID_FILE_ATTRIBUTES)
        ok &= shortcut(CSIDL_PROGRAMS, L"XP25 AI", L"RoverAI Search.lnk", rover, NULL, L"RoverAI - search files on this computer");
    return ok;
}

static void tray_icon(int add)
{
    if (!add) { Shell_NotifyIconW(NIM_DELETE, &tray); return; }
    memset(&tray, 0, sizeof(tray));
    tray.cbSize = sizeof(tray);
    tray.hWnd = g_app.window;
    tray.uID = 1;
    tray.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    tray.uCallbackMessage = WM_CLIPPY_TRAY;
    tray.hIcon = (HICON)LoadImageW(g_app.instance, MAKEINTRESOURCEW(IDI_CLIPPY), IMAGE_ICON, 16, 16, 0);
    lstrcpynW(tray.szTip, L"ClippyAI", 64);
    Shell_NotifyIconW(NIM_ADD, &tray);
}

static void balloon(const WCHAR *title, const WCHAR *text)
{
    tray.uFlags = NIF_INFO;
    lstrcpynW(tray.szInfoTitle, title, 64);
    lstrcpynW(tray.szInfo, text, 256);
    tray.dwInfoFlags = NIIF_INFO;
    Shell_NotifyIconW(NIM_MODIFY, &tray);
}

static void restore(void)
{
    ShowWindow(g_app.window, IsIconic(g_app.window) ? SW_RESTORE : SW_SHOW);
    SetForegroundWindow(g_app.window);
    SetFocus(g_app.input);
}

static void hide_to_tray(void)
{
    ShowWindow(g_app.window, SW_HIDE);
    if (!g_app.tray_hint_shown) {
        balloon(L"ClippyAI", L"ClippyAI is still running here. Double-click the icon to open it; right-click to exit.");
        g_app.tray_hint_shown = 1;
    }
}

static void layout(void)
{
    RECT rc, sb;
    int w, h, left = 132, input_h = 58;
    GetClientRect(g_app.window, &rc);
    SendMessageW(g_app.status, WM_SIZE, 0, 0);
    GetWindowRect(g_app.status, &sb);
    w = rc.right;
    h = rc.bottom - (sb.bottom - sb.top);
    if (g_app.mascot && g_app.mascot->window) {
        RECT area;
        POINT pt;
        pt.x = 4; pt.y = h - 170 > 4 ? h - 170 : 4;
        ClientToScreen(g_app.window, &pt);
        SetRect(&area, pt.x, pt.y, pt.x + left - 8, pt.y + 166);
        g_app.mascot->place(g_app.mascot, &area);
    } else if (g_app.mascot) {
        RECT area;
        POINT pt;
        pt.x = 4; pt.y = 30;
        ClientToScreen(g_app.window, &pt);
        SetRect(&area, pt.x, pt.y, pt.x + left - 8, pt.y + h - 40);
        g_app.mascot->place(g_app.mascot, &area);
    }
    MoveWindow(g_app.mascot_text, 6, 6, left - 12, h - 190 > 40 ? h - 190 : 40, TRUE);
    MoveWindow(g_app.chat, left, 4, w - left - 4, h - input_h - 12, TRUE);
    MoveWindow(g_app.input, left, h - input_h - 4, w - left - 96, input_h, TRUE);
    MoveWindow(g_app.send, w - 88, h - input_h - 4, 84, 27, TRUE);
    MoveWindow(g_app.stop, w - 88, h - 31, 84, 27, TRUE);
}

static void send_input(void)
{
    int n = GetWindowTextLengthW(g_app.input);
    WCHAR *text;
    char *u;
    if (n <= 0 || g_app.busy) return;
    text = (WCHAR *)xp25_alloc(((size_t)n + 1) * sizeof(WCHAR));
    if (!text) return;
    GetWindowTextW(g_app.input, text, n + 1);
    u = xp25w_utf8(text);
    xp25_free(text);
    if (u) {
        SetWindowTextW(g_app.input, L"");
        controller_send(u);
        xp25_free(u);
    }
}

static void save_conversation(void)
{
    OPENFILENAMEW ofn;
    WCHAR file[MAX_PATH] = L"ClippyAI conversation.txt";
    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_app.window;
    ofn.lpstrFilter = L"Text files (*.txt)\0*.txt\0All files\0*.*\0";
    ofn.lpstrFile = file;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrDefExt = L"txt";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    if (GetSaveFileNameW(&ofn) && !chat_save(g_app.chat, file))
        MessageBoxW(g_app.window, L"The conversation could not be saved.", L"ClippyAI", MB_ICONERROR);
}

/* Requests from RoverAI or a second ClippyAI start (untrusted input). */
static void handle_request(const char *action, const char *value)
{
    if (!strcmp(action, "show")) { restore(); return; }
    if (!value || !*value || strlen(value) > 4000) return;
    restore();
    if (!strcmp(action, "ask")) controller_send(value);
    else if (!strcmp(action, "explain_file")) {
        WCHAR path[MAX_PATH];
        char u[MAX_PATH * 3];
        XP25_BUF text;
        if (!xp25w_full_path(value, path, MAX_PATH, u, sizeof(u)) || GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) {
            chat_add(g_app.chat, CK_ERROR, "Problem", "RoverAI asked about a file that does not exist.", value, 0);
            return;
        }
        xp25_buf_init(&text);
        xp25_buf_puts(&text, "Explain the file \"");
        xp25_buf_puts(&text, u);
        xp25_buf_puts(&text, "\" and check it for problems.");
        controller_send(xp25_buf_cstr(&text));
        xp25_buf_free(&text);
    }
}

static int copydata(const COPYDATASTRUCT *cds)
{
    XP25_JDOC doc;
    const char *action, *value;
    if (cds->dwData != XP25_IPC_MAGIC || !cds->lpData || cds->cbData > 16384) return 0;
    if (!xp25_json_parse(&doc, (const char *)cds->lpData, cds->cbData) || doc.root->type != XP25_JOBJ) {
        xp25_json_free(&doc);
        return 0;
    }
    action = xp25_json_string(doc.root, "action");
    value = xp25_json_string(doc.root, "value");
    if (action && (!strcmp(action, "show") || !strcmp(action, "ask") || !strcmp(action, "explain_file")))
        handle_request(action, value);
    xp25_json_free(&doc);
    return 1;
}

static LRESULT CALLBACK main_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    if (msg == taskbar_created && taskbar_created) { tray_icon(1); return 0; }
    switch (msg) {
    case WM_CREATE: {
        CREATESTRUCTW *cs = (CREATESTRUCTW *)lp;
        g_app.window = hwnd;
        g_app.status = CreateWindowExW(0, STATUSCLASSNAMEW, L"", WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP, 0, 0, 0, 0,
                                       hwnd, (HMENU)IDC_STATUSBAR, cs->hInstance, NULL);
        g_app.chat = CreateWindowExW(WS_EX_CLIENTEDGE, CHAT_CLASS, L"", WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_TABSTOP,
                                     0, 0, 0, 0, hwnd, (HMENU)IDC_CHAT, cs->hInstance, NULL);
        g_app.input = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL |
                                      ES_MULTILINE | ES_AUTOVSCROLL | ES_WANTRETURN, 0, 0, 0, 0, hwnd, (HMENU)IDC_INPUT,
                                      cs->hInstance, NULL);
        g_app.send = CreateWindowExW(0, L"BUTTON", L"&Send", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                                     0, 0, 0, 0, hwnd, (HMENU)IDC_SEND, cs->hInstance, NULL);
        g_app.stop = CreateWindowExW(0, L"BUTTON", L"S&top", WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_DISABLED,
                                     0, 0, 0, 0, hwnd, (HMENU)IDC_STOP, cs->hInstance, NULL);
        g_app.mascot_text = CreateWindowExW(0, L"STATIC", L"Hi! I'm ClippyAI. Ask me to check why the computer is slow, "
                                            L"show Event Viewer errors, run a command or find a file.",
                                            WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd, (HMENU)IDC_MASCOT_TEXT, cs->hInstance, NULL);
        SendMessageW(g_app.input, WM_SETFONT, (WPARAM)g_app.font, TRUE);
        SendMessageW(g_app.send, WM_SETFONT, (WPARAM)g_app.font, TRUE);
        SendMessageW(g_app.stop, WM_SETFONT, (WPARAM)g_app.font, TRUE);
        SendMessageW(g_app.mascot_text, WM_SETFONT, (WPARAM)g_app.font, TRUE);
        return 0;
    }
    case WM_SIZE:
        if (wp == SIZE_MINIMIZED) { hide_to_tray(); return 0; }
        layout();
        return 0;
    case WM_MOVE:
        if (g_app.mascot && !g_app.mascot->window) layout();
        return 0;
    case WM_SETFOCUS:
        SetFocus(g_app.input);      /* keyboard input goes to the request box after dialogs close */
        return 0;
    case WM_GETMINMAXINFO:
        ((MINMAXINFO *)lp)->ptMinTrackSize.x = 480;
        ((MINMAXINFO *)lp)->ptMinTrackSize.y = 360;
        return 0;
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDC_SEND: send_input(); return 0;
        case IDC_STOP: controller_stop(); app_set_status("Stopping after the current step..."); return 0;
        case IDM_SAVE: save_conversation(); return 0;
        case IDM_HIDE: hide_to_tray(); return 0;
        case IDM_EXIT: DestroyWindow(hwnd); return 0;
        case IDM_TRAY_OPEN: restore(); return 0;
        case IDM_SETTINGS:
            if (g_app.busy) { MessageBoxW(hwnd, L"Wait until the current request finishes.", L"ClippyAI", MB_ICONINFORMATION); return 0; }
            if (dialog_settings(hwnd)) {
                controller_reconfigure();
                chat_add(g_app.chat, CK_NOTICE, NULL, g_app.provider_note, NULL, 1);
            }
            return 0;
        case IDM_AUTOSTART:
            app_autostart(1, !app_autostart(0, 0));
            CheckMenuItem(GetMenu(hwnd), IDM_AUTOSTART, app_autostart(0, 0) ? MF_CHECKED : MF_UNCHECKED);
            return 0;
        case IDM_CLEAR:
            if (g_app.busy) return 0;
            chat_clear(g_app.chat);
            xp25_conversation_free(&g_app.agent.conversation);
            xp25_conversation_init(&g_app.agent.conversation);
            g_app.agent.share_remembered = 0;
            return 0;
        case IDM_AUDIT: {
            WCHAR file[MAX_PATH];
            lstrcpynW(file, g_app.paths.app_data, MAX_PATH - 16);
            lstrcatW(file, L"\\audit.jsonl");
            ShellExecuteW(hwnd, L"open", L"notepad.exe", file, NULL, SW_SHOWNORMAL);
            return 0;
        }
        case IDM_HELP: controller_send("help"); return 0;
        case IDM_ABOUT: dialog_about(hwnd); return 0;
        }
        break;
    case WM_CLIPPY_EVENT:
        controller_event((XP25_EVENT *)lp);
        controller_free_event((XP25_EVENT *)lp);
        return 0;
    case WM_CLIPPY_APPROVE:
        return controller_approve_message(wp, lp);
    case WM_CLIPPY_SHARE:
        return controller_share_message(lp);
    case WM_CLIPPY_DONE:
        if (g_app.worker) { CloseHandle(g_app.worker); g_app.worker = NULL; }
        g_app.busy = 0;
        EnableWindow(g_app.send, TRUE);
        EnableWindow(g_app.stop, FALSE);
        app_set_status(g_app.provider_note);
        if (!IsWindowVisible(hwnd)) balloon(L"ClippyAI", L"Your request is finished. Open ClippyAI to see the answer.");
        if (g_app.mascot) g_app.mascot->set_state(g_app.mascot, MASCOT_IDLE);
        return 0;
    case WM_CLIPPY_TRAY:
        if (lp == WM_LBUTTONDBLCLK || lp == WM_LBUTTONUP) restore();
        else if (lp == WM_RBUTTONUP) {
            HMENU menu = CreatePopupMenu();
            POINT pt;
            AppendMenuW(menu, MF_STRING | MF_DEFAULT, IDM_TRAY_OPEN, L"&Open ClippyAI");
            AppendMenuW(menu, MF_STRING, IDM_SETTINGS, L"&Settings...");
            AppendMenuW(menu, MF_SEPARATOR, 0, NULL);
            AppendMenuW(menu, MF_STRING, IDM_EXIT, L"E&xit");
            GetCursorPos(&pt);
            SetForegroundWindow(hwnd);
            TrackPopupMenu(menu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
            PostMessageW(hwnd, WM_NULL, 0, 0);
            DestroyMenu(menu);
        }
        return 0;
    case WM_COPYDATA:
        return copydata((const COPYDATASTRUCT *)lp);
    case WM_CLOSE:
        hide_to_tray();
        return 0;
    case WM_DESTROY:
        tray_icon(0);
        controller_shutdown();
        if (g_app.mascot) g_app.mascot->destroy(g_app.mascot);
        g_app.mascot = NULL;
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static void fonts(void)
{
    NONCLIENTMETRICSW ncm;
    LOGFONTW lf;
    memset(&ncm, 0, sizeof(ncm));
    ncm.cbSize = sizeof(ncm);
    SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0);
    g_app.font = CreateFontIndirectW(&ncm.lfMessageFont);
    lf = ncm.lfMessageFont;
    lf.lfWeight = FW_BOLD;
    g_app.bold = CreateFontIndirectW(&lf);
    g_app.mono = CreateFontW(-11, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, 0, FIXED_PITCH, L"Lucida Console");
}

static int forward_to_existing(const char *action, const char *value)
{
    HWND existing = FindWindowW(CLIPPY_CLASS, NULL);
    COPYDATASTRUCT cds;
    XP25_BUF json;
    XP25_JW w;
    DWORD_PTR result;
    if (!existing) return 0;
    xp25_buf_init(&json);
    xp25_jw_init(&w, &json);
    xp25_jw_obj(&w);
    xp25_jw_key(&w, "v"); xp25_jw_i64(&w, 1);
    xp25_jw_key(&w, "action"); xp25_jw_str(&w, action);
    if (value) { xp25_jw_key(&w, "value"); xp25_jw_str(&w, value); }
    xp25_jw_end(&w);
    cds.dwData = XP25_IPC_MAGIC;
    cds.cbData = (DWORD)json.len;
    cds.lpData = json.data;
    AllowSetForegroundWindow(ASFW_ANY);
    SendMessageTimeoutW(existing, WM_COPYDATA, 0, (LPARAM)&cds, SMTO_ABORTIFHUNG, 5000, &result);
    xp25_buf_free(&json);
    return 1;
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE previous, LPWSTR command_line, int show)
{
    int argc = 0, i, tray_only = 0;
    WCHAR **argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    char *action = NULL, *value = NULL;
    HANDLE single;
    INITCOMMONCONTROLSEX icc;
    WNDCLASSEXW wc;
    MSG msg;
    HACCEL accel = NULL;
    char note[200];
    (void)previous;
    (void)command_line;
    for (i = 1; argv && i < argc; ++i) {
        if (!lstrcmpiW(argv[i], L"/tray")) tray_only = 1;
        else if (!lstrcmpiW(argv[i], L"/install") || !lstrcmpiW(argv[i], L"/uninstall")) {
            int ok;
            CoInitialize(NULL);
            ok = install(!lstrcmpiW(argv[i], L"/uninstall"));
            CoUninitialize();
            return ok ? 0 : 1;
        } else if ((!lstrcmpiW(argv[i], L"/explain") || !lstrcmpiW(argv[i], L"/ask")) && i + 1 < argc) {
            action = xp25_strdup(!lstrcmpiW(argv[i], L"/explain") ? "explain_file" : "ask");
            value = xp25w_utf8(argv[++i]);
        }
    }
    if (argv) LocalFree(argv);
    single = CreateMutexW(NULL, FALSE, L"Local\\XP25ClippyAI.SingleInstance");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        forward_to_existing(action ? action : "show", value);
        xp25_free(action);
        xp25_free(value);
        return 0;
    }
    memset(&g_app, 0, sizeof(g_app));
    g_app.instance = instance;
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_BAR_CLASSES | ICC_WIN95_CLASSES;
    InitCommonControlsEx(&icc);
    fonts();
    xp25w_paths(&g_app.paths);
    xp25w_config_load(&g_app.config);
    chat_register(instance);
    memset(&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = main_proc;
    wc.hInstance = instance;
    wc.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(IDI_CLIPPY));
    wc.hIconSm = (HICON)LoadImageW(instance, MAKEINTRESOURCEW(IDI_CLIPPY), IMAGE_ICON, 16, 16, 0);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszMenuName = MAKEINTRESOURCEW(IDR_MAINMENU);
    wc.lpszClassName = CLIPPY_CLASS;
    if (!RegisterClassExW(&wc)) return 1;
    taskbar_created = RegisterWindowMessageW(L"TaskbarCreated");
    if (!CreateWindowExW(0, CLIPPY_CLASS, L"ClippyAI", WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, CW_USEDEFAULT, CW_USEDEFAULT,
                         660, 540, NULL, NULL, instance, NULL)) return 1;
    g_app.mascot = mascot_create(g_app.window, instance, g_app.config.mascot, note, sizeof(note));
    if (!controller_init()) {
        MessageBoxW(g_app.window, L"The XP25 agent runtime could not be initialized.", L"ClippyAI", MB_ICONERROR);
        return 1;
    }
    tray_icon(1);
    CheckMenuItem(GetMenu(g_app.window), IDM_AUTOSTART, app_autostart(0, 0) ? MF_CHECKED : MF_UNCHECKED);
    layout();
    chat_add(g_app.chat, CK_ASSISTANT, NULL,
             "Hello! I'm ClippyAI, your XP25 assistant. I can diagnose a slow computer, read Event Viewer, run commands "
             "you approve, check services, the network and disks, and find files with RoverAI. Nothing is changed "
             "without your approval.", NULL, 1);
    chat_add(g_app.chat, CK_NOTICE, NULL, g_app.provider_note, NULL, 1);
    if (note[0]) chat_add(g_app.chat, CK_NOTICE, NULL, note, NULL, 1);
    if (!tray_only) {
        ShowWindow(g_app.window, show == SW_SHOWMINNOACTIVE || show == SW_MINIMIZE ? SW_SHOWNORMAL : show);
        UpdateWindow(g_app.window);
        SetFocus(g_app.input);
    }
    if (action) handle_request(action, value);
    xp25_free(action);
    xp25_free(value);
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        if (msg.message == WM_KEYDOWN && msg.hwnd == g_app.input && msg.wParam == VK_RETURN &&
            !(GetKeyState(VK_SHIFT) & 0x8000)) {
            send_input();
            continue;
        }
        if (!accel || !TranslateAcceleratorW(g_app.window, accel, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    DeleteObject(g_app.font);
    DeleteObject(g_app.bold);
    DeleteObject(g_app.mono);
    CoUninitialize();
    CloseHandle(single);
    return (int)msg.wParam;
}
