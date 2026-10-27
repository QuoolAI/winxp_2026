/* Process entry for MinGW host builds of the XP25 AI executables. The native
   NT build uses the system msvcrt startup (UMENTRY=wwinmain) instead. */
#include <windows.h>

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE previous, LPWSTR command_line, int show);

void __stdcall XP25MingwEntry(void)
{
    WCHAR *line = GetCommandLineW();
    STARTUPINFOW si;
    int quoted = 0;
    /* Skip the program name exactly as the C runtime does. */
    while (*line && (quoted || (*line != L' ' && *line != L'\t'))) {
        if (*line == L'"') quoted = !quoted;
        ++line;
    }
    while (*line == L' ' || *line == L'\t') ++line;
    si.cb = sizeof(si);
    GetStartupInfoW(&si);
    ExitProcess((UINT)wWinMain(GetModuleHandleW(NULL), NULL, line,
                               (si.dwFlags & STARTF_USESHOWWINDOW) ? si.wShowWindow : SW_SHOWDEFAULT));
}
