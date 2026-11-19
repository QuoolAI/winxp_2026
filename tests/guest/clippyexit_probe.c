/* Milestone 8.4: ClippyAI exits while it is asking for an approval.
   ClippyAI shows its approval dialog on the UI thread while the agent's worker thread waits in
   SendMessage for the answer. Choosing Exit (here: WM_COMMAND IDM_EXIT posted to the main window,
   as the tray and window menus do) destroys the window from inside that dialog. The probe measures
   how long the process takes to end and how it ends, and checks that the proposed command never
   ran. Each cycle starts ClippyAI, asks for a command that needs approval, waits for the dialog and
   exits. Writes JSON records and CLIPPY_EXIT_PROBE_DONE to COM1. */
#define WINVER 0x0501
#define _WIN32_WINNT 0x0501
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define APP L"C:\\Program Files\\XP25"
#define PROOF L"C:\\xp25-exit-test.txt"
#define IDC_INPUT 1002
#define IDC_SEND 1003
#define IDM_EXIT 3003
#define CYCLES 3

static HANDLE serial;
static unsigned failures;

static void put(const char *s)
{
    DWORD n;
    WriteFile(serial, s, lstrlenA(s), &n, NULL);
}

static void report(const char *name, int cycle, BOOL ok, DWORD value)
{
    char s[240];
    if (!ok) ++failures;
    wsprintfA(s, "{\"clippy_exit_case\":\"%s\",\"cycle\":%d,\"status\":\"%s\",\"value\":%lu}\r\n", name, cycle,
              ok ? "pass" : "fail", value);
    put(s);
}

static HWND wait_window(const WCHAR *cls, const WCHAR *title, DWORD ms)
{
    DWORD t0 = GetTickCount();
    HWND w;
    do {
        w = FindWindowW(cls, title);
        if (w && IsWindowVisible(w)) return w;
        Sleep(200);
    } while (GetTickCount() - t0 < ms);
    return NULL;
}

static BOOL wait_idle(HWND clippy, DWORD ms)
{
    DWORD t0 = GetTickCount();
    HWND send = GetDlgItem(clippy, IDC_SEND);
    do {
        if (send && IsWindowEnabled(send)) return TRUE;
        Sleep(200);
    } while (GetTickCount() - t0 < ms);
    return FALSE;
}

static BOOL start_clippy(void)
{
    WCHAR line[300];
    static STARTUPINFOW si;    /* zero-initialized storage: the probe has no C runtime memset */
    PROCESS_INFORMATION pi;
    lstrcpyW(line, L"\"" APP L"\\ClippyAI.exe\"");
    si.cb = sizeof(si);
    if (!CreateProcessW(NULL, line, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) return FALSE;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return TRUE;
}

static void cycle(int c)
{
    HWND clippy = FindWindowW(L"XP25ClippyAI", L"ClippyAI"), dialog;
    HANDLE process = NULL;
    DWORD pid = 0, wait, elapsed, code = 0, t0;
    char s[200];
    if (!clippy || !IsWindowVisible(clippy)) {
        if (!clippy) start_clippy();
        else ShowWindow(clippy, SW_RESTORE);
        clippy = wait_window(L"XP25ClippyAI", L"ClippyAI", 60000);
    }
    report("clippy_window", c, clippy != NULL, GetLastError());
    if (!clippy) return;
    GetWindowThreadProcessId(clippy, &pid);
    process = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_INFORMATION, FALSE, pid);
    report("clippy_process_opened", c, process != NULL, GetLastError());
    if (!process) return;
    report("clippy_idle", c, wait_idle(clippy, 60000), 0);
    DeleteFileW(PROOF);
    SendMessageTimeoutW(GetDlgItem(clippy, IDC_INPUT), WM_SETTEXT, 0, (LPARAM)L"run echo XP25-EXIT-TEST> " PROOF,
                        SMTO_ABORTIFHUNG, 5000, NULL);
    PostMessageW(clippy, WM_COMMAND, IDC_SEND, 0);
    dialog = wait_window(L"#32770", L"ClippyAI - Approval Required", 60000);
    report("approval_dialog_open", c, dialog != NULL, 0);
    if (!dialog) { CloseHandle(process); return; }
    Sleep(500);
    t0 = GetTickCount();
    PostMessageW(clippy, WM_COMMAND, IDM_EXIT, 0);
    wait = WaitForSingleObject(process, 90000);
    elapsed = GetTickCount() - t0;
    GetExitCodeProcess(process, &code);
    wsprintfA(s, "{\"clippy_exit\":true,\"cycle\":%d,\"ended\":%u,\"exit_ms\":%lu,\"exit_code\":%lu}\r\n", c,
              wait == WAIT_OBJECT_0, elapsed, code);
    put(s);
    report("process_ended", c, wait == WAIT_OBJECT_0, elapsed);
    report("exit_code_zero", c, wait == WAIT_OBJECT_0 && code == 0, code);
    report("exit_within_5s", c, wait == WAIT_OBJECT_0 && elapsed < 5000, elapsed);
    report("declined_command_not_run", c, GetFileAttributesW(PROOF) == INVALID_FILE_ATTRIBUTES, 0);
    CloseHandle(process);
    Sleep(2000);
}

void WINAPI ProbeMain(void)
{
    char s[80];
    int c;
    serial = CreateFileA("COM1", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (serial == INVALID_HANDLE_VALUE) ExitProcess(90);
    put("CLIPPY_EXIT_PROBE_STARTED\r\n");
    for (c = 1; c <= CYCLES; ++c) cycle(c);
    wsprintfA(s, "CLIPPY_EXIT_PROBE_DONE failures=%u\r\n", failures);
    put(s);
    CloseHandle(serial);
    ExitProcess(failures ? 1 : 0);
}
