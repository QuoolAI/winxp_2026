/* The IE removal (build/ie_removal.py), seen from the running guest after the boot
   that deleted the files. One JSON record per case on stdout (the suite sends it to
   COM1); exit code = number of failed cases.
     absent      every removed file is gone from system32, en-US, dllcache and the IE folder
     kept        the shared libraries Windows needs are still there, ieproxy.dll included
     engine      mshtml, jscript and vbscript do not load; their COM classes and
                 InternetExplorer.Application are not registered and cannot be created
     shell       ShellWindows and ShellLink still work (Explorer's own COM)
     handlers    http, https, .htm, .html and .url open through XP25Browser; .hta, .mht
                 and ftp have no open verb; iexplore.exe is not an App Path and does not start
     registry    the Internet client is Supermium's (key XP25Browser.exe) and no other; IE's Active Setup entries are gone; no
                 file operation is still pending
     users       xp25users.cpl answers as "User Accounts" and opens the classic dialog
     help        XP25Help is registered
   Run as an administrator in the interactive session. */
#define WINVER 0x0501
#define _WIN32_WINNT 0x0501
#define WIN32_LEAN_AND_MEAN
#define COBJMACROS
#include <windows.h>
#include <objbase.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <cpl.h>

static int failures;

static void out(const char *s)
{
    DWORD n;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), s, lstrlenA(s), &n, NULL);
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "\r\n", 2, &n, NULL);
}

static void report(const char *name, int passed, const char *detail)
{
    char row[700];
    wsprintfA(row, "{\"ie_case\":\"%s\",\"passed\":%d,\"detail\":\"%s\"}", name, passed, detail);
    out(row);
    if (!passed) ++failures;
}

static void narrow(char *to, const WCHAR *from, int size)
{
    int i;
    for (i = 0; from[i] && i < size - 1; ++i) to[i] = (char)(from[i] < 128 && from[i] != '"' && from[i] != '\\' ? from[i] : '?');
    to[i] = 0;
}

static const WCHAR *const removed[] = {
    L"%SystemRoot%\\system32\\mshtml.dll", L"%SystemRoot%\\system32\\mshtmled.dll", L"%SystemRoot%\\system32\\mshtmler.dll",
    L"%SystemRoot%\\system32\\mshtml.tlb", L"%SystemRoot%\\system32\\iepeers.dll", L"%SystemRoot%\\system32\\jscript.dll",
    L"%SystemRoot%\\system32\\vbscript.dll", L"%SystemRoot%\\system32\\jsproxy.dll", L"%SystemRoot%\\system32\\mshta.exe",
    L"%SystemRoot%\\system32\\inetcpl.cpl", L"%SystemRoot%\\system32\\ie4uinit.exe", L"%SystemRoot%\\system32\\ieudinit.exe",
    L"%SystemRoot%\\system32\\BrowserChoice.exe", L"%SystemRoot%\\system32\\en-US\\mshtml.dll.mui",
    L"%SystemRoot%\\system32\\en-US\\jscript.dll.mui", L"%SystemRoot%\\system32\\en-US\\vbscript.dll.mui",
    L"%SystemRoot%\\system32\\dllcache\\mshtml.dll", L"%SystemRoot%\\system32\\dllcache\\jscript.dll",
    L"%SystemRoot%\\system32\\dllcache\\vbscript.dll", L"%SystemRoot%\\system32\\dllcache\\mshta.exe",
    L"%SystemRoot%\\system32\\dllcache\\iexplore.exe", L"%SystemRoot%\\system32\\dllcache\\inetcpl.cpl",
    L"%ProgramFiles%\\Internet Explorer\\iexplore.exe", L"%ProgramFiles%\\Internet Explorer\\iedvtool.dll",
    L"%ProgramFiles%\\Internet Explorer\\SIGNUP",
};
static const WCHAR *const kept[] = {
    L"%SystemRoot%\\system32\\wininet.dll", L"%SystemRoot%\\system32\\urlmon.dll", L"%SystemRoot%\\system32\\shdocvw.dll",
    L"%SystemRoot%\\system32\\browseui.dll", L"%SystemRoot%\\system32\\ieframe.dll", L"%SystemRoot%\\system32\\iertutil.dll",
    L"%ProgramFiles%\\Internet Explorer\\ieproxy.dll", L"%SystemRoot%\\system32\\xp25users.cpl",
    L"%ProgramFiles%\\Supermium\\chrome.exe", L"%ProgramFiles%\\XP25Browser\\browserctl.exe",
};

static void files(void)
{
    WCHAR path[MAX_PATH], pattern[MAX_PATH];
    char name[MAX_PATH], detail[MAX_PATH + 40];
    WIN32_FIND_DATAW f;
    HANDLE h;
    unsigned i, extra = 0;
    int ok = 1;
    for (i = 0; i < sizeof(removed) / sizeof(removed[0]); ++i) {
        ExpandEnvironmentStringsW(removed[i], path, MAX_PATH);
        if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES) { narrow(name, path, MAX_PATH); report("absent", 0, name); ok = 0; }
    }
    /* Nothing but ieproxy.dll may remain in the IE folder. */
    ExpandEnvironmentStringsW(L"%ProgramFiles%\\Internet Explorer\\*", pattern, MAX_PATH);
    h = FindFirstFileW(pattern, &f);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!lstrcmpW(f.cFileName, L".") || !lstrcmpW(f.cFileName, L"..") || !lstrcmpiW(f.cFileName, L"ieproxy.dll")) continue;
            narrow(name, f.cFileName, MAX_PATH);
            wsprintfA(detail, "left in the IE folder: %s", name);
            report("absent", 0, detail);
            ok = 0;
            ++extra;
        } while (FindNextFileW(h, &f));
        FindClose(h);
    }
    if (ok) report("absent", 1, "all removed files are gone; the IE folder holds only ieproxy.dll");
    ok = 1;
    for (i = 0; i < sizeof(kept) / sizeof(kept[0]); ++i) {
        ExpandEnvironmentStringsW(kept[i], path, MAX_PATH);
        if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) { narrow(name, path, MAX_PATH); report("kept", 0, name); ok = 0; }
    }
    if (ok) report("kept", 1, "WinINet, URLMon, Shdocvw, BrowseUI, IEFrame, IERtUtil, ieproxy, xp25users.cpl, Supermium present");
}

static void engine(void)
{
    static const struct { const char *name; GUID clsid; } classes[] = {
        {"HTMLDocument", {0x25336920, 0x03F9, 0x11CF, {0x8F, 0xD0, 0x00, 0xAA, 0x00, 0x68, 0x6F, 0x13}}},
        {"InternetExplorer.Application", {0x0002DF01, 0x0000, 0x0000, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}},
        {"JScript", {0xF414C260, 0x6AC0, 0x11CF, {0xB6, 0xD1, 0x00, 0xAA, 0x00, 0xBB, 0xBB, 0x58}}},
        {"VBScript", {0xB54F3741, 0x5B07, 0x11CF, {0xA4, 0xB0, 0x00, 0xAA, 0x00, 0x4A, 0x55, 0xE8}}},
        {"HTMLApplication", {0x3050F4D8, 0x98B5, 0x11CF, {0xBB, 0x82, 0x00, 0xAA, 0x00, 0xBD, 0xCE, 0x0B}}},
    };
    static const WCHAR *const modules[] = {L"mshtml.dll", L"jscript.dll", L"vbscript.dll"};
    static const GUID unknown = {0x00000000, 0x0000, 0x0000, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
    char detail[200];
    unsigned i;
    for (i = 0; i < sizeof(modules) / sizeof(modules[0]); ++i) {
        HMODULE m = LoadLibraryW(modules[i]);
        char name[32];
        narrow(name, modules[i], sizeof(name));
        wsprintfA(detail, "LoadLibrary(%s): %s, error %lu", name, m ? "loaded" : "not found", m ? 0 : GetLastError());
        report("engine_module", m == NULL, detail);
        if (m) FreeLibrary(m);
    }
    for (i = 0; i < sizeof(classes) / sizeof(classes[0]); ++i) {
        IUnknown *object = NULL;
        HRESULT hr = CoCreateInstance(&classes[i].clsid, NULL, CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER, &unknown, (void **)&object);
        wsprintfA(detail, "CoCreateInstance(%s) = 0x%08lx", classes[i].name, (unsigned long)hr);
        report("engine_class", FAILED(hr), detail);
        if (object) IUnknown_Release(object);
    }
}

static void shell(void)
{
    static const struct { const char *name; GUID clsid; } classes[] = {
        {"ShellWindows", {0x9BA05972, 0xF6A8, 0x11CF, {0xA4, 0x42, 0x00, 0xA0, 0xC9, 0x0A, 0x8F, 0x39}}},
        {"ShellLink", {0x00021401, 0x0000, 0x0000, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}},
    };
    static const GUID unknown = {0x00000000, 0x0000, 0x0000, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
    char detail[200];
    unsigned i;
    for (i = 0; i < sizeof(classes) / sizeof(classes[0]); ++i) {
        IUnknown *object = NULL;
        HRESULT hr = CoCreateInstance(&classes[i].clsid, NULL, CLSCTX_ALL, &unknown, (void **)&object);
        wsprintfA(detail, "CoCreateInstance(%s) = 0x%08lx", classes[i].name, (unsigned long)hr);
        report("shell_class", SUCCEEDED(hr), detail);
        if (object) IUnknown_Release(object);
    }
}

static void handlers(void)
{
    static const struct { const WCHAR *what; const WCHAR *needle; } opens[] = {
        {L"http", L"XP25Browser.exe\" open-url"}, {L"https", L"XP25Browser.exe\" open-url"},
        {L".htm", L"XP25Browser.exe\" open-document"}, {L".html", L"XP25Browser.exe\" open-document"},
        {L".url", L"XP25Browser.exe\" open-shortcut"},
    };
    static const WCHAR *const none[] = {L".hta", L".mht", L"ftp"};
    WCHAR command[1024];
    char name[16], text[400], detail[500];
    DWORD size;
    unsigned i;
    SHELLEXECUTEINFOW s;
    for (i = 0; i < sizeof(opens) / sizeof(opens[0]); ++i) {
        HRESULT hr;
        size = 1024;
        hr = AssocQueryStringW(0, ASSOCSTR_COMMAND, opens[i].what, L"open", command, &size);
        narrow(name, opens[i].what, sizeof(name));
        narrow(text, SUCCEEDED(hr) ? command : L"(none)", sizeof(text));
        wsprintfA(detail, "%s: %s", name, text);
        report("handler", SUCCEEDED(hr) && StrStrIW(command, opens[i].needle) != NULL, detail);
    }
    for (i = 0; i < sizeof(none) / sizeof(none[0]); ++i) {
        HRESULT hr;
        size = 1024;
        hr = AssocQueryStringW(0, ASSOCSTR_COMMAND, none[i], L"open", command, &size);
        narrow(name, none[i], sizeof(name));
        narrow(text, SUCCEEDED(hr) ? command : L"(none)", sizeof(text));
        wsprintfA(detail, "%s has no open command: %s", name, text);
        report("handler_removed", FAILED(hr), detail);
    }
    s.cbSize = sizeof(s); s.fMask = SEE_MASK_FLAG_NO_UI | SEE_MASK_NOCLOSEPROCESS; s.hwnd = NULL; s.lpVerb = L"open";
    s.lpFile = L"iexplore.exe"; s.lpParameters = NULL; s.lpDirectory = NULL; s.nShow = SW_HIDE; s.hInstApp = NULL;
    s.lpIDList = NULL; s.lpClass = NULL; s.hkeyClass = NULL; s.dwHotKey = 0; s.hIcon = NULL; s.hProcess = NULL;
    if (ShellExecuteExW(&s)) {
        if (s.hProcess) { TerminateProcess(s.hProcess, 1); CloseHandle(s.hProcess); }
        report("iexplore_does_not_start", 0, "ShellExecute(iexplore.exe) started a process");
    } else {
        wsprintfA(detail, "ShellExecute(iexplore.exe) failed, error %lu", GetLastError());
        report("iexplore_does_not_start", 1, detail);
    }
}

static int key_exists(HKEY root, const WCHAR *path)
{
    HKEY k;
    if (RegOpenKeyExW(root, path, 0, KEY_READ, &k)) return 0;
    RegCloseKey(k);
    return 1;
}

static void registry(void)
{
    static const WCHAR *const gone[] = {
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\IEXPLORE.EXE",
        L"SOFTWARE\\Clients\\StartMenuInternet\\IEXPLORE.EXE",
        L"SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\{12d0ed0d-0ee0-4f90-8827-78cefb8f4988}",
        L"SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\{26923b43-4d38-484f-9b9e-de460746276c}",
        L"SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\{60B49E34-C7CC-11D0-8953-00A0C90347FF}",
        L"SOFTWARE\\Classes\\CLSID\\{25336920-03F9-11CF-8FD0-00AA00686F13}",
        L"SOFTWARE\\Classes\\CLSID\\{0002DF01-0000-0000-C000-000000000046}",
        L"SOFTWARE\\Classes\\CLSID\\{F414C260-6AC0-11CF-B6D1-00AA00BBBB58}",
        L"SOFTWARE\\Classes\\CLSID\\{B54F3741-5B07-11CF-A4B0-00AA004A55E8}",
        L"SOFTWARE\\Classes\\TypeLib\\{3050F1C5-98B5-11CF-BB82-00AA00BDCE0B}",
    };
    WCHAR value[260];
    char name[300], detail[400];
    DWORD size = sizeof(value), type;
    HKEY k;
    unsigned i;
    int ok = 1;
    for (i = 0; i < sizeof(gone) / sizeof(gone[0]); ++i) {
        if (key_exists(HKEY_LOCAL_MACHINE, gone[i])) { narrow(name, gone[i], sizeof(name)); report("registry_removed", 0, name); ok = 0; }
    }
    if (ok) report("registry_removed", 1, "App Path, Internet client, Active Setup, engine CLSIDs and MSHTML type library are gone");
    value[0] = 0;
    if (!RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Clients\\StartMenuInternet", 0, KEY_READ, &k)) {
        if (RegQueryValueExW(k, NULL, NULL, &type, (BYTE *)value, &size) || type != REG_SZ) value[0] = 0;
        RegCloseKey(k);
    }
    value[259] = 0;
    narrow(name, value, sizeof(name));
    wsprintfA(detail, "HKLM Internet client: %s", name);
    report("internet_client", !lstrcmpiW(value, L"XP25Browser.exe") &&
           !key_exists(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Clients\\StartMenuInternet\\Supermium"), detail);
    size = 0;
    if (!RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager", 0, KEY_READ, &k)) {
        if (RegQueryValueExW(k, L"PendingFileRenameOperations", NULL, &type, NULL, &size)) size = 0;
        RegCloseKey(k);
    }
    wsprintfA(detail, "PendingFileRenameOperations bytes: %lu", size);
    report("nothing_pending", size <= 4, detail);
    report("help_registered", key_exists(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\XP25Help.exe"),
           "XP25Help App Path");
}

static BOOL CALLBACK close_accounts(HWND w, LPARAM found)
{
    WCHAR title[64];
    DWORD pid;
    if (GetWindowTextW(w, title, 64) && !lstrcmpW(title, L"User Accounts") && IsWindowVisible(w)) {
        GetWindowThreadProcessId(w, &pid);
        *(DWORD *)found = pid;
        PostMessageW(w, WM_CLOSE, 0, 0);
    }
    return TRUE;
}

static void users(void)
{
    typedef LONG (APIENTRY *APPLET)(HWND, UINT, LPARAM, LPARAM);
    WCHAR path[MAX_PATH];
    char name[64], detail[200];
    HMODULE m;
    APPLET applet;
    NEWCPLINFOW info;
    CPLINFO inquire;
    DWORD found = 0, start;
    ExpandEnvironmentStringsW(L"%SystemRoot%\\system32\\xp25users.cpl", path, MAX_PATH);
    m = LoadLibraryW(path);
    applet = m ? (APPLET)(void *)GetProcAddress(m, "CPlApplet") : NULL;
    if (!applet) { report("users_applet", 0, "xp25users.cpl does not load"); if (m) FreeLibrary(m); return; }
    info.dwSize = 0; info.szName[0] = 0;
    inquire.idIcon = 0;
    if (!applet(NULL, CPL_INIT, 0, 0) || applet(NULL, CPL_GETCOUNT, 0, 0) != 1) { report("users_applet", 0, "CPL_INIT or CPL_GETCOUNT"); FreeLibrary(m); return; }
    applet(NULL, CPL_INQUIRE, 0, (LPARAM)&inquire);
    applet(NULL, CPL_NEWINQUIRE, 0, (LPARAM)&info);
    narrow(name, info.szName, sizeof(name));
    wsprintfA(detail, "name %s, dynamic %d, size %lu, icon %d", name, inquire.idIcon == CPL_DYNAMIC_RES, info.dwSize, info.hIcon != NULL);
    report("users_applet", inquire.idIcon == CPL_DYNAMIC_RES && info.dwSize == sizeof(info) && !lstrcmpW(info.szName, L"User Accounts") && info.hIcon, detail);
    applet(NULL, CPL_DBLCLK, 0, 0);
    start = GetTickCount();
    while (!found && GetTickCount() - start < 30000) { Sleep(500); EnumWindows(close_accounts, (LPARAM)&found); }
    wsprintfA(detail, "the classic User Accounts dialog %s (pid %lu)", found ? "opened and was closed" : "did not open", found);
    report("users_dialog", found != 0, detail);
    applet(NULL, CPL_EXIT, 0, 0);
    FreeLibrary(m);
}

void WINAPI ProbeMain(void)
{
    HRESULT hr = CoInitialize(NULL);
    files();
    engine();
    if (SUCCEEDED(hr)) shell(); else report("shell_class", 0, "CoInitialize failed");
    handlers();
    registry();
    users();
    {
        char row[80];
        wsprintfA(row, "{\"ie_probe\":\"done\",\"failures\":%d}", failures);
        out(row);
    }
    if (SUCCEEDED(hr)) CoUninitialize();
    ExitProcess((UINT)failures);
}
