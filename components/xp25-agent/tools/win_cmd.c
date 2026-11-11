/* XP25 AI runtime: cmd_execute. One cmd.exe command with redirected output,
   a job object for the time limit (the whole process tree is ended), and no
   PowerShell. The command text is shown to the user before anything runs
   unless it is on the read-only allowlist. */
#include <windows.h>
#include <string.h>
#include "win_tools.h"

#define OUTPUT_LIMIT (64 * 1024)

int classify_cmd(const XP25_TOOL *tool, const XP25_JNODE *args, XP25_PROPOSAL *p)
{
    const char *command = tool_arg(args, "command", ""), *dir = tool_arg(args, "working_directory", NULL);
    char reason[200];
    XP25_BUF shown, target;
    XP25W_TOOLS *ctx = TOOL_CONTEXT(tool);
    p->perm = xp25_policy_command(command, reason, sizeof(reason));
    if (p->perm == XP25_PERM_DENIED) { xp25_proposal_deny(p, reason); return 1; }
    xp25_buf_init(&shown);
    xp25_buf_init(&target);
    xp25_buf_puts(&shown, "cmd.exe /d /c ");
    xp25_buf_puts(&shown, command);
    xp25_buf_puts(&target, "Command Prompt as ");
    xp25_buf_puts(&target, xp25w_is_admin() ? "administrator user, in " : "standard user, in ");
    xp25_buf_puts(&target, dir ? dir : ctx->paths->u_profile);
    tool_proposal(p, "Run a command", xp25_buf_cstr(&shown), xp25_buf_cstr(&target),
                  p->perm == XP25_PERM_READ ? "Read-only diagnostic command."
                                            : "This command can change files, settings or programs, or reveal private "
                                              "data. Approve only if you understand it.");
    xp25_buf_free(&shown);
    xp25_buf_free(&target);
    return 1;
}

static void append_oem(XP25_BUF *out, const char *bytes, DWORD n)
{
    WCHAR *wide;
    int count;
    if (!n) return;
    count = MultiByteToWideChar(CP_OEMCP, 0, bytes, (int)n, NULL, 0);
    wide = count > 0 ? (WCHAR *)xp25_alloc(((size_t)count + 1) * sizeof(WCHAR)) : NULL;
    if (!wide) return;
    MultiByteToWideChar(CP_OEMCP, 0, bytes, (int)n, wide, count);
    wide[count] = 0;
    xp25w_buf_wide(out, wide);
    xp25_free(wide);
}

int tool_cmd(const XP25_TOOL *tool, const XP25_JNODE *args, XP25_BUF *out, XP25_EGRESS *egress)
{
    XP25W_TOOLS *ctx = TOOL_CONTEXT(tool);
    const char *command = tool_arg(args, "command", "");
    const char *dir_utf8 = tool_arg(args, "working_directory", NULL);
    long timeout = tool_int(args, "timeout_seconds", 60, 1, 300);
    WCHAR system[MAX_PATH], exe[MAX_PATH + 16], dir[MAX_PATH], *line, *wcommand;
    SECURITY_ATTRIBUTES sa;
    HANDLE read_end = NULL, write_end = NULL, nul, job;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    char *raw;
    DWORD raw_len = 0, exit_code = 0, start, elapsed;
    int timed_out = 0, truncated = 0, ok;
    XP25_BUF text;
    XP25_JW w;
    *egress = XP25_EGRESS_SENSITIVE;
    if (!GetSystemDirectoryW(system, MAX_PATH)) return tool_win32_error(out, "no_system_directory", "System directory unavailable", GetLastError());
    lstrcpyW(exe, system);
    lstrcatW(exe, L"\\cmd.exe");
    if (dir_utf8) {
        if (!xp25w_full_path(dir_utf8, dir, MAX_PATH, NULL, 0) || !(GetFileAttributesW(dir) & FILE_ATTRIBUTE_DIRECTORY) ||
            GetFileAttributesW(dir) == INVALID_FILE_ATTRIBUTES) {
            xp25_result_error(out, "bad_directory", "The working directory does not exist.");
            return 0;
        }
    } else lstrcpyW(dir, ctx->paths->profile);
    wcommand = xp25w_wide(command);
    if (!wcommand) { xp25_result_error(out, "bad_command", "The command is not valid text."); return 0; }
    line = (WCHAR *)xp25_alloc(((size_t)lstrlenW(wcommand) + 32) * sizeof(WCHAR));
    if (!line) { xp25_free(wcommand); xp25_result_error(out, "out_of_memory", "Out of memory."); return 0; }
    lstrcpyW(line, L"cmd.exe /d /c ");
    lstrcatW(line, wcommand);
    xp25_free(wcommand);
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    if (!CreatePipe(&read_end, &write_end, &sa, 0)) {
        xp25_free(line);
        return tool_win32_error(out, "pipe_failed", "Could not create the output pipe", GetLastError());
    }
    SetHandleInformation(read_end, HANDLE_FLAG_INHERIT, 0);
    nul = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL);
    job = CreateJobObjectW(NULL, NULL);
    if (job) {
        memset(&limits, 0, sizeof(limits));
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits));
    }
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput = nul;
    si.hStdOutput = write_end;
    si.hStdError = write_end;
    start = GetTickCount();
    ok = CreateProcessW(exe, line, NULL, NULL, TRUE, CREATE_NO_WINDOW | CREATE_SUSPENDED, NULL, dir, &si, &pi) != 0;
    xp25_free(line);
    CloseHandle(write_end);
    if (nul != INVALID_HANDLE_VALUE) CloseHandle(nul);
    if (!ok) {
        DWORD error = GetLastError();
        CloseHandle(read_end);
        if (job) CloseHandle(job);
        return tool_win32_error(out, "start_failed", "cmd.exe could not be started", error);
    }
    if (job) AssignProcessToJobObject(job, pi.hProcess);
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    raw = (char *)xp25_alloc(OUTPUT_LIMIT + 1);
    for (;;) {
        DWORD avail = 0, got = 0;
        char sink[4096];
        int exited = WaitForSingleObject(pi.hProcess, 20) == WAIT_OBJECT_0;
        while (PeekNamedPipe(read_end, NULL, 0, NULL, &avail, NULL) && avail) {
            if (raw && raw_len < OUTPUT_LIMIT) {
                DWORD room = OUTPUT_LIMIT - raw_len;
                if (!ReadFile(read_end, raw + raw_len, avail < room ? avail : room, &got, NULL)) break;
                raw_len += got;
            } else {
                truncated = 1;
                if (!ReadFile(read_end, sink, avail < sizeof(sink) ? avail : sizeof(sink), &got, NULL)) break;
            }
        }
        if (exited) break;
        if (GetTickCount() - start > (DWORD)timeout * 1000) {
            timed_out = 1;
            if (job) TerminateJobObject(job, 1); else TerminateProcess(pi.hProcess, 1);
            WaitForSingleObject(pi.hProcess, 5000);
            break;
        }
    }
    elapsed = GetTickCount() - start;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(read_end);
    if (job) CloseHandle(job);
    xp25_buf_init(&text);
    if (raw) append_oem(&text, raw, raw_len);
    xp25_free(raw);
    ok = !timed_out && exit_code == 0;
    xp25_buf_reset(out);
    xp25_jw_init(&w, out);
    xp25_jw_obj(&w);
    xp25_jw_key(&w, "ok"); xp25_jw_bool(&w, ok);
    xp25_jw_key(&w, "command"); xp25_jw_str(&w, command);
    xp25_jw_key(&w, "exit_code"); xp25_jw_u64(&w, exit_code);
    xp25_jw_key(&w, "timed_out"); xp25_jw_bool(&w, timed_out);
    xp25_jw_key(&w, "duration_ms"); xp25_jw_u64(&w, elapsed);
    xp25_jw_key(&w, "truncated"); xp25_jw_bool(&w, truncated);
    xp25_jw_key(&w, "output"); xp25_jw_str(&w, xp25_buf_cstr(&text));
    if (!ok) {
        XP25_BUF message;
        xp25_buf_init(&message);
        if (timed_out) { xp25_buf_puts(&message, "Stopped after "); xp25_buf_i64(&message, timeout); xp25_buf_puts(&message, " seconds."); }
        else { xp25_buf_puts(&message, "The command exited with code "); xp25_buf_u64(&message, exit_code); xp25_buf_puts(&message, "."); }
        xp25_jw_key(&w, "error");
        xp25_jw_obj(&w);
        xp25_jw_key(&w, "code"); xp25_jw_str(&w, timed_out ? "command_timeout" : "command_failed");
        xp25_jw_key(&w, "message"); xp25_jw_str(&w, xp25_buf_cstr(&message));
        xp25_jw_end(&w);
        xp25_buf_free(&message);
    }
    xp25_buf_free(&text);
    return tool_finish(&w, out) && ok;
}
