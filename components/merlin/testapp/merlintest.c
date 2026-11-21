/* MerlinTest.exe: XP25 Display Greeting, a small test component installed
   with MerlinAI.

   It reads C:\xp25\merlintest.ini and shows the greeting it configures.
   It exists so that MerlinAI's crash reporting and repair pipeline can be
   demonstrated end to end on a component that is harmless to change. Its
   behaviour with the shipped settings file is part of the Milestone 9
   demonstration (docs/merlinai-milestone9.md).

   /check runs the same code without a window and reports on COM1; its own
   top-level exception filter turns a crash into exit code 2 so tests need
   no dialog. Without /check a crash reaches the system crash handler. */
#include <windows.h>

#define SETTINGS L"C:\\xp25\\merlintest.ini"

static BOOL check_mode;

static void serial(const char *line)
{
    HANDLE port = CreateFileW(L"COM1", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    DWORD wrote;
    int tries;
    /* COM1 is exclusive: Winlogon and other writers hold it briefly. */
    for (tries = 0; port == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED && tries < 40; ++tries) {
        Sleep(50);
        port = CreateFileW(L"COM1", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    }
    if (port == INVALID_HANDLE_VALUE) return;
    WriteFile(port, line, (DWORD)lstrlenA(line), &wrote, NULL);
    WriteFile(port, "\r\n", 2, &wrote, NULL);
    CloseHandle(port);
}

static LONG WINAPI check_filter(EXCEPTION_POINTERS *e)
{
    char line[96];
    wsprintfA(line, "XP25_MERLINTEST_CHECK=crash code=%08lx", (unsigned long)e->ExceptionRecord->ExceptionCode);
    serial(line);
    ExitProcess(2);
}

/* Settings file contents (ANSI), NUL-terminated; NULL if unreadable. */
static char *read_settings(void)
{
    HANDLE f = CreateFileW(SETTINGS, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    DWORD size, got = 0;
    char *text;
    if (f == INVALID_HANDLE_VALUE) return NULL;
    size = GetFileSize(f, NULL);
    if (size == INVALID_FILE_SIZE || size > 65536) {
        CloseHandle(f);
        return NULL;
    }
    text = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size + 1);
    if (text && !ReadFile(f, text, size, &got, NULL)) got = 0;
    CloseHandle(f);
    if (text) text[got] = 0;
    return text;
}

/* Value of "key=" on a line of its own, terminated in place; NULL if absent. */
static char *find_value(char *text, const char *key)
{
    int n = lstrlenA(key);
    char *line = text;
    while (line && *line) {
        char *end = line;
        while (*end && *end != '\r' && *end != '\n') ++end;
        if (end - line > n && line[n] == '=' && CompareStringA(LOCALE_SYSTEM_DEFAULT, NORM_IGNORECASE, line, n, key, n) == CSTR_EQUAL) {
            *end = 0;
            return line + n + 1;
        }
        line = end;
        while (*line == '\r' || *line == '\n') ++line;
    }
    return NULL;
}

static int text_length(const char *s)
{
    int n = 0;
    while (s[n]) ++n;
    return n;
}

/* Window title and greeting from the settings file. */
static int load_display(char *title, int title_size, char *greeting, int greeting_size)
{
    char *text = read_settings(), *t, *g;
    int n;
    if (!text) return 0;
    g = find_value(text, "Greeting");
    t = find_value(text, "Title");
    n = text_length(t);
    lstrcpynA(title, t, n + 1 < title_size ? n + 1 : title_size);
    lstrcpynA(greeting, g ? g : "Hello from XP25.", greeting_size);
    HeapFree(GetProcessHeap(), 0, text);
    return 1;
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE previous, LPWSTR command_line, int show)
{
    char title[128], greeting[256];
    (void)instance;
    (void)previous;
    (void)show;
    check_mode = command_line && lstrcmpiW(command_line, L"/check") == 0;
    if (check_mode) SetUnhandledExceptionFilter(check_filter);
    if (!load_display(title, sizeof(title), greeting, sizeof(greeting))) {
        if (check_mode) serial("XP25_MERLINTEST_CHECK=no_settings");
        else MessageBoxA(NULL, "The settings file C:\\xp25\\merlintest.ini is missing.", "XP25 Display Greeting", MB_OK | MB_ICONWARNING);
        return 1;
    }
    if (check_mode) {
        char line[200];
        wsprintfA(line, "XP25_MERLINTEST_CHECK=ok title_length=%d", lstrlenA(title));
        serial(line);
        return 0;
    }
    MessageBoxA(NULL, greeting, title, MB_OK | MB_ICONINFORMATION);
    return 0;
}
