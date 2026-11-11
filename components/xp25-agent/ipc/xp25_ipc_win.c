/* XP25 AI runtime: requests between XP25 agents (RoverAI -> ClippyAI). */
#include <windows.h>
#include <shellapi.h>
#include <string.h>
#include "xp25_ipc.h"
#include "../runtime/xp25_win.h"

extern HINSTANCE xp25w_module;

int xp25w_clippy_request(const char *action, const char *value)
{
    HWND clippy = FindWindowW(XP25_CLIPPY_WINDOW_CLASS, NULL);
    WCHAR exe[MAX_PATH], *slash, *args, *wvalue;
    int ok;
    if (clippy) {
        XP25_BUF json;
        XP25_JW w;
        COPYDATASTRUCT cds;
        DWORD_PTR result = 0;
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
        ok = SendMessageTimeoutW(clippy, WM_COPYDATA, 0, (LPARAM)&cds, SMTO_ABORTIFHUNG, 5000, &result) != 0 && result;
        xp25_buf_free(&json);
        return ok;
    }
    if (!GetModuleFileNameW(xp25w_module, exe, MAX_PATH)) return 0;
    slash = wcsrchr(exe, L'\\');
    if (!slash || slash - exe > MAX_PATH - 16) return 0;
    lstrcpyW(slash + 1, L"ClippyAI.exe");
    wvalue = xp25w_wide(value ? value : "");
    args = (WCHAR *)xp25_alloc(((size_t)lstrlenW(wvalue ? wvalue : L"") + 32) * sizeof(WCHAR));
    if (!args || !wvalue) { xp25_free(args); xp25_free(wvalue); return 0; }
    lstrcpyW(args, !strcmp(action, "explain_file") ? L"/explain \"" : !strcmp(action, "ask") ? L"/ask \"" : L"");
    if (args[0]) { lstrcatW(args, wvalue); lstrcatW(args, L"\""); }
    ok = (INT_PTR)ShellExecuteW(NULL, L"open", exe, args, NULL, SW_SHOWNORMAL) > 32;
    xp25_free(args);
    xp25_free(wvalue);
    return ok;
}
