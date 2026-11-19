/* Milestone 8.4: what an idle session costs once the screen-saver timeout has passed.
   The XP25 Winlogon starts no screen saver, so USER re-sends LOGON_INPUT_TIMEOUT on every idle
   tick. The probe lowers this session's screen-saver timeout to 60 s (not saved), makes no input
   for 120 s, then for 60 s measures how often the exclusive COM1 port can be opened, how much
   native-winlogon.log grows and how much CPU time Winlogon uses. It restores the timeout, injects
   one Shift key press to end the idle period and reports one JSON record on COM1 (and in
   C:\xp25-idle.json). Exit 0 when COM1 stayed available (>= 90% of attempts) and the log grew by
   at most 1 KB in the measured minute. */
#define WINVER 0x0501
#define _WIN32_WINNT 0x0501
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>

#define LOG L"C:\\xp25\\native-winlogon.log"

static DWORD log_size(void)
{
    WIN32_FILE_ATTRIBUTE_DATA a;
    return GetFileAttributesExW(LOG, GetFileExInfoStandard, &a) ? a.nFileSizeLow : 0;
}

static DWORD winlogon_cpu_ms(void)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0), process;
    PROCESSENTRY32W p;
    FILETIME c, e, k, u;
    DWORD ms = 0, session = 0, mine = 0;
    p.dwSize = sizeof(p);
    ProcessIdToSessionId(GetCurrentProcessId(), &mine);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    if (Process32FirstW(snapshot, &p)) do {
        if (!lstrcmpiW(p.szExeFile, L"winlogon.exe") && ProcessIdToSessionId(p.th32ProcessID, &session) && session == mine) {
            process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, p.th32ProcessID);
            if (process && GetProcessTimes(process, &c, &e, &k, &u))
                ms = (k.dwLowDateTime + u.dwLowDateTime) / 10000;   /* low parts suffice for a delta of minutes */
            if (process) CloseHandle(process);
            break;
        }
    } while (Process32NextW(snapshot, &p));
    CloseHandle(snapshot);
    return ms;
}

static HANDLE open_com1(DWORD ms)
{
    DWORD t0 = GetTickCount();
    HANDLE h;
    do {
        h = CreateFileA("COM1", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE) return h;
        Sleep(50);
    } while (GetTickCount() - t0 < ms);
    return INVALID_HANDLE_VALUE;
}

void WINAPI ProbeMain(void)
{
    HANDLE token, serial, file;
    UINT timeout = 600;
    DWORD log0, log1, cpu0, cpu1, attempts = 0, opened = 0, t0, n;
    INPUT key[2];
    char s[300];
    int ok;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) AdjustTokenPrivileges(token, FALSE, &tp, 0, NULL, NULL);
        CloseHandle(token);
    }
    serial = open_com1(10000);
    if (serial != INVALID_HANDLE_VALUE) { WriteFile(serial, "IDLE_PROBE_STARTED\r\n", 20, &n, NULL); CloseHandle(serial); }
    SystemParametersInfoW(SPI_GETSCREENSAVETIMEOUT, 0, &timeout, 0);
    SystemParametersInfoW(SPI_SETSCREENSAVEACTIVE, TRUE, NULL, 0);
    SystemParametersInfoW(SPI_SETSCREENSAVETIMEOUT, 60, NULL, 0);
    Sleep(120000);
    log0 = log_size();
    cpu0 = winlogon_cpu_ms();
    t0 = GetTickCount();
    while (GetTickCount() - t0 < 60000) {
        HANDLE h = CreateFileA("COM1", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        ++attempts;
        if (h != INVALID_HANDLE_VALUE) { ++opened; CloseHandle(h); }
        Sleep(500);
    }
    log1 = log_size();
    cpu1 = winlogon_cpu_ms();
    SystemParametersInfoW(SPI_SETSCREENSAVETIMEOUT, timeout, NULL, 0);
    key[0].type = key[1].type = INPUT_KEYBOARD;
    key[0].ki.wVk = key[1].ki.wVk = VK_SHIFT;
    key[0].ki.wScan = key[1].ki.wScan = 0;
    key[0].ki.dwFlags = 0;
    key[1].ki.dwFlags = KEYEVENTF_KEYUP;
    key[0].ki.time = key[1].ki.time = 0;
    key[0].ki.dwExtraInfo = key[1].ki.dwExtraInfo = 0;
    SendInput(2, key, sizeof(INPUT));
    Sleep(3000);
    ok = opened * 10 >= attempts * 9 && log1 - log0 <= 1024;
    wsprintfA(s, "{\"idle_probe\":true,\"com1_opened\":%lu,\"com1_attempts\":%lu,\"winlogon_log_growth_bytes_per_min\":%lu,"
                 "\"winlogon_cpu_ms_per_min\":%lu,\"restored_timeout_s\":%u,\"passed\":%u}\r\n",
              opened, attempts, log1 - log0, cpu1 - cpu0, timeout, ok);
    file = CreateFileW(L"C:\\xp25-idle.json", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (file != INVALID_HANDLE_VALUE) { WriteFile(file, s, lstrlenA(s), &n, NULL); CloseHandle(file); }
    serial = open_com1(30000);
    if (serial != INVALID_HANDLE_VALUE) {
        WriteFile(serial, s, lstrlenA(s), &n, NULL);
        WriteFile(serial, "IDLE_PROBE_DONE\r\n", 17, &n, NULL);
        CloseHandle(serial);
    }
    ExitProcess(ok ? 0 : 1);
}
