/* XP25 User Accounts applet (xp25users.cpl). Windows XP's own User Accounts panel,
 * nusrmgr.cpl, is an HTML application that mshta.exe runs on the IE engine, and
 * XP25 deletes both. This applet takes its place in the Control Panel and opens the
 * classic user accounts dialog of netplwiz.dll, the same dialog as
 * "control userpasswords2": add, remove and change accounts, groups and passwords.
 * The icon is read from nusrmgr.cpl as a resource; no code of it is run.
 * Native NT 5.1 APIs only, no C runtime. */
#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0501
#include <windows.h>
#include <shellapi.h>
#include <cpl.h>

static HINSTANCE module;

BOOL WINAPI Xp25UsersEntry(HINSTANCE instance,DWORD reason,LPVOID reserved) {
    (void)reserved;
    if(reason==DLL_PROCESS_ATTACH){module=instance;DisableThreadLibraryCalls(instance);}
    return TRUE;
}

static void open_classic(HWND owner) {
    WCHAR system[MAX_PATH],program[MAX_PATH];UINT n=GetSystemDirectoryW(system,MAX_PATH);
    if(!n || n+14>=MAX_PATH)return;
    lstrcpyW(program,system);lstrcatW(program,L"\\rundll32.exe");
    if((INT_PTR)ShellExecuteW(owner,L"open",program,L"netplwiz.dll,UsersRunDll",system,SW_SHOWNORMAL)<=32)
        MessageBoxW(owner,L"The User Accounts dialog could not be started.",L"User Accounts",MB_OK|MB_ICONERROR);
}

static HICON accounts_icon(void) {
    WCHAR path[MAX_PATH];UINT n=GetSystemDirectoryW(path,MAX_PATH);HICON icon=NULL;
    if(n && n+14<MAX_PATH){lstrcatW(path,L"\\nusrmgr.cpl");icon=ExtractIconW(module,path,0);}
    if(!icon || icon==(HICON)1)icon=LoadIconW(NULL,(LPCWSTR)IDI_APPLICATION);
    return icon;
}

LONG APIENTRY CPlApplet(HWND owner,UINT message,LPARAM first,LPARAM second) {
    (void)first;
    switch(message) {
    case CPL_INIT:return TRUE;
    case CPL_GETCOUNT:return 1;
    case CPL_INQUIRE: {
        /* Dynamic: the Control Panel then asks with CPL_NEWINQUIRE. */
        LPCPLINFO info=(LPCPLINFO)second;
        info->idIcon=CPL_DYNAMIC_RES;info->idName=CPL_DYNAMIC_RES;info->idInfo=CPL_DYNAMIC_RES;info->lData=0;
        return 0;
    }
    case CPL_NEWINQUIRE: {
        LPNEWCPLINFOW info=(LPNEWCPLINFOW)second;
        info->dwSize=sizeof(NEWCPLINFOW);info->dwFlags=0;info->dwHelpContext=0;info->lData=0;
        info->hIcon=accounts_icon();
        lstrcpynW(info->szName,L"User Accounts",32);
        lstrcpynW(info->szInfo,L"Add, remove and change user accounts, groups and passwords.",64);
        info->szHelpFile[0]=0;
        return 0;
    }
    case CPL_DBLCLK:open_classic(owner);return 0;
    case CPL_STARTWPARMSW:open_classic(owner);return TRUE;
    default:return 0;
    }
}
