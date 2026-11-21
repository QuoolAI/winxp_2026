/* MerlinAI.cpl: the Control Panel entry "MerlinAI Health and Updates" (NEWCPLINFO allows 31 characters;
   the shell drops "&" as a mnemonic marker, so the name avoids it).
   Installed into system32, the one machine-wide location the image's shell32 lists.
   It replaces the Security Center and Automatic Updates applets (hidden with
   the documented "don't load" list) and starts MerlinAI.exe from its own
   directory. */
#include <windows.h>
#include <cpl.h>
#include <shellapi.h>
#include "resource.h"

static HINSTANCE module;

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        module = instance;
        DisableThreadLibraryCalls(instance);
    }
    return TRUE;
}

static void start_merlin(HWND owner)
{
    WCHAR path[MAX_PATH], *slash = NULL, *p;
    HKEY key;
    DWORD type, size = sizeof(path) - 16 * sizeof(WCHAR);
    path[0] = 0;
    /* The applet lives in system32; MerlinAI.exe in the directory the installer recorded. */
    if (!RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\XP25\\MerlinAI", 0, KEY_QUERY_VALUE, &key)) {
        if (RegQueryValueExW(key, L"InstallDirectory", NULL, &type, (BYTE *)path, &size) || type != REG_SZ) path[0] = 0;
        else path[size / sizeof(WCHAR)] = 0;
        RegCloseKey(key);
    }
    if (path[0]) {
        lstrcatW(path, L"\\MerlinAI.exe");
    } else {
        if (!GetModuleFileNameW(module, path, MAX_PATH)) return;
        for (p = path; *p; ++p)
            if (*p == L'\\') slash = p;
        if (!slash || (slash - path) + 14 >= MAX_PATH) return;
        lstrcpyW(slash + 1, L"MerlinAI.exe");
    }
    if ((INT_PTR)ShellExecuteW(owner, NULL, path, NULL, NULL, SW_SHOWNORMAL) <= 32)
        MessageBoxW(owner, L"MerlinAI.exe could not be started. Reinstall MerlinAI.", L"MerlinAI", MB_OK | MB_ICONERROR);
}

LONG CALLBACK CPlApplet(HWND owner, UINT msg, LPARAM p1, LPARAM p2)
{
    (void)p1;
    switch (msg) {
    case CPL_INIT:
        return TRUE;
    case CPL_GETCOUNT:
        return 1;
    case CPL_INQUIRE: {
        CPLINFO *info = (CPLINFO *)p2;
        info->idIcon = IDI_MERLIN;
        info->idName = IDS_NAME;
        info->idInfo = IDS_INFO;
        info->lData = 0;
        return 0;
    }
    case CPL_NEWINQUIRE: {
        NEWCPLINFOW *info = (NEWCPLINFOW *)p2;
        ZeroMemory(info, sizeof(*info));
        info->dwSize = sizeof(*info);
        info->hIcon = LoadIconW(module, MAKEINTRESOURCEW(IDI_MERLIN));
        LoadStringW(module, IDS_NAME, info->szName, 32);
        LoadStringW(module, IDS_INFO, info->szInfo, 64);
        return 0;
    }
    case CPL_DBLCLK:
        start_merlin(owner);
        return 0;
    case CPL_STOP:
    case CPL_EXIT:
        return 0;
    }
    return 1;                                      /* not handled; 0 would claim CPL_NEWINQUIRE etc. */
}
