/* Milestone 8.4: run-time evidence that /GS cookies are initialized in the XP25 AI binaries.
   Arguments are module=rva pairs (the RVA of __security_cookie from the build's PDB, see
   build/gs_check.py). For every running process that has such a module loaded, and for
   xp25agent.dll loaded into this probe, the cookie is read and compared with the value the
   compiler leaves before start-up initializes it. Writes JSON records and GSCOOKIE_PROBE_DONE to
   COM1. Cookie values are not printed, only whether they differ from the default and from each other. */
#define WINVER 0x0501
#define _WIN32_WINNT 0x0501
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <shellapi.h>

#define DEFAULT_COOKIE 0xBB40E64EUL
#define MAX_SEEN 32

static HANDLE serial;
static unsigned failures, checked;
static DWORD seen[MAX_SEEN];
static unsigned seen_count;

static void put(const char *s)
{
    DWORD n;
    WriteFile(serial, s, lstrlenA(s), &n, NULL);
}

static DWORD parse_hex(const WCHAR *s)
{
    DWORD v = 0;
    if (s[0] == L'0' && (s[1] == L'x' || s[1] == L'X')) s += 2;
    for (; *s; ++s) {
        int d = *s >= L'0' && *s <= L'9' ? *s - L'0' : *s >= L'a' && *s <= L'f' ? *s - L'a' + 10 :
                *s >= L'A' && *s <= L'F' ? *s - L'A' + 10 : -1;
        if (d < 0) break;
        v = v * 16 + (DWORD)d;
    }
    return v;
}

static void record(const WCHAR *module, DWORD pid, BOOL read, DWORD cookie)
{
    char s[240], name[64];
    unsigned i;
    BOOL distinct = TRUE;
    WideCharToMultiByte(CP_ACP, 0, module, -1, name, sizeof(name), NULL, NULL);
    for (i = 0; i < seen_count; ++i) if (seen[i] == cookie) distinct = FALSE;
    if (read && seen_count < MAX_SEEN) seen[seen_count++] = cookie;
    ++checked;
    if (!read || cookie == DEFAULT_COOKIE || cookie == 0) ++failures;
    wsprintfA(s, "{\"gscookie\":\"%s\",\"pid\":%lu,\"read\":%u,\"initialized\":%u,\"distinct_so_far\":%u}\r\n", name, pid, read,
              read && cookie != DEFAULT_COOKIE && cookie != 0, distinct);
    put(s);
}

static void scan(const WCHAR *module, DWORD rva)
{
    HANDLE processes = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W p;
    p.dwSize = sizeof(p);
    if (processes == INVALID_HANDLE_VALUE) return;
    if (Process32FirstW(processes, &p)) do {
        HANDLE modules;
        MODULEENTRY32W m;
        m.dwSize = sizeof(m);
        if (!p.th32ProcessID) continue;    /* a module snapshot of process 0 would list this probe's own modules */
        modules = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, p.th32ProcessID);
        if (modules == INVALID_HANDLE_VALUE) continue;
        if (Module32FirstW(modules, &m)) do {
            if (!lstrcmpiW(m.szModule, module)) {
                HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, p.th32ProcessID);
                DWORD cookie = 0;
                SIZE_T got = 0;
                BOOL ok = h && ReadProcessMemory(h, m.modBaseAddr + rva, &cookie, sizeof(cookie), &got) && got == sizeof(cookie);
                record(module, p.th32ProcessID, ok, cookie);
                if (h) CloseHandle(h);
            }
        } while (Module32NextW(modules, &m));
        CloseHandle(modules);
    } while (Process32NextW(processes, &p));
    CloseHandle(processes);
}

void WINAPI ProbeMain(void)
{
    int argc = 0, i;
    WCHAR **argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    char s[96];
    HANDLE token;
    serial = CreateFileA("COM1", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (serial == INVALID_HANDLE_VALUE) ExitProcess(90);
    put("GSCOOKIE_PROBE_STARTED\r\n");
    /* XP25Broker runs as SYSTEM: an administrator reads it with the debug privilege. */
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) AdjustTokenPrivileges(token, FALSE, &tp, 0, NULL, NULL);
        CloseHandle(token);
    }
    for (i = 1; argv && i < argc; ++i) {
        WCHAR *eq = argv[i];
        while (*eq && *eq != L'=') ++eq;
        if (!*eq) continue;
        *eq = 0;
        if (!lstrcmpiW(argv[i], L"xp25agent.dll")) {
            /* Loading the DLL here runs its CRT start-up in this process too. */
            HMODULE self = LoadLibraryW(L"C:\\Program Files\\XP25\\xp25agent.dll");
            if (self) record(L"xp25agent.dll(probe)", GetCurrentProcessId(), TRUE, *(DWORD *)((BYTE *)self + parse_hex(eq + 1)));
            else record(L"xp25agent.dll(probe)", GetCurrentProcessId(), FALSE, 0);
        }
        scan(argv[i], parse_hex(eq + 1));
    }
    wsprintfA(s, "GSCOOKIE_PROBE_DONE checked=%u failures=%u\r\n", checked, failures);
    put(s);
    CloseHandle(serial);
    ExitProcess(failures || !checked ? 1 : 0);
}
