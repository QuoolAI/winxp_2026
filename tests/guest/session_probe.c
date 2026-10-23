/* Observe the interactive account and Explorer token; never read credentials. */
#define WINVER 0x0501
#define _WIN32_WINNT 0x0501
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static HANDLE serial;
static unsigned failures;
static void emit(const char *line)
{
    DWORD written;
    WriteFile(serial, line, lstrlenA(line), &written, NULL);
}
static void report(const char *name, BOOL pass)
{
    char line[180];
    if (!pass) ++failures;
    wsprintfA(line, "{\"case\":\"%s\",\"status\":\"%s\"}\r\n", name, pass ? "pass" : "fail");
    emit(line);
}
void WINAPI ProbeMain(void)
{
    char user[128], line[256], desktop[128];
    DWORD size = sizeof(user), bytes, pid = 0;
    HANDLE token = NULL, shell_token = NULL, shell_process = NULL;
    TOKEN_STATISTICS own = {0}, shell = {0};
    USEROBJECTFLAGS flags = {0};
    BYTE own_user[256], shell_user[256];
    BOOL ok;
    serial = CreateFileA("COM1", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (serial == INVALID_HANDLE_VALUE) ExitProcess(90);
    ok = GetUserNameA(user, &size);
    report("account_name", ok && lstrcmpiA(user, "XP25") == 0);
    if (ok) {
        wsprintfA(line, "{\"event\":\"interactive_account\",\"name\":\"%s\"}\r\n", user);
        emit(line);
    }
    ok = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) &&
         GetTokenInformation(token, TokenStatistics, &own, sizeof(own), &bytes) &&
         GetTokenInformation(token, TokenUser, own_user, sizeof(own_user), &bytes);
    report("user_primary_logon_token", ok && own.TokenType == TokenPrimary &&
           (own.AuthenticationId.HighPart != 0 || own.AuthenticationId.LowPart > 0x3e7));
    if (ok) {
        wsprintfA(line, "{\"event\":\"authentication_id\",\"high\":%lu,\"low\":%lu}\r\n",
                  (DWORD)own.AuthenticationId.HighPart, own.AuthenticationId.LowPart);
        emit(line);
    }
    GetWindowThreadProcessId(GetShellWindow(), &pid);
    shell_process = pid ? OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid) : NULL;
    ok = ok && shell_process && OpenProcessToken(shell_process, TOKEN_QUERY, &shell_token) &&
         GetTokenInformation(shell_token, TokenStatistics, &shell, sizeof(shell), &bytes) &&
         GetTokenInformation(shell_token, TokenUser, shell_user, sizeof(shell_user), &bytes);
    report("explorer_same_user_and_logon_session", ok &&
           EqualSid(((TOKEN_USER *)own_user)->User.Sid, ((TOKEN_USER *)shell_user)->User.Sid) &&
           own.AuthenticationId.LowPart == shell.AuthenticationId.LowPart &&
           own.AuthenticationId.HighPart == shell.AuthenticationId.HighPart);
    report("visible_window_station", GetUserObjectInformationA(GetProcessWindowStation(),
           UOI_FLAGS, &flags, sizeof(flags), &bytes) && (flags.dwFlags & WSF_VISIBLE));
    report("default_interactive_desktop", GetUserObjectInformationA(GetThreadDesktop(GetCurrentThreadId()),
           UOI_NAME, desktop, sizeof(desktop), &bytes) && lstrcmpiA(desktop, "Default") == 0);
    if (shell_token) CloseHandle(shell_token);
    if (shell_process) CloseHandle(shell_process);
    if (token) CloseHandle(token);
    report("session_probe_complete", failures == 0);
    CloseHandle(serial);
    ExitProcess(failures ? 1 : 0);
}
