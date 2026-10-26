/* XP25 browser shell adapter. Native NT 5.1 APIs; no scripting engine.
 * The diagnostic command records process/module metadata only, never profile data.
 *
 * Supermium has no renderer sandbox before Windows 10, so every XP25 entry
 * point starts it with SAFER's Normal User level: the Administrators group is
 * deny-only and privileges other than change-notify are removed. Browser child
 * processes inherit that token. This limits what a compromised browser can
 * change on the system; it is not a per-renderer sandbox, and the user's own
 * files and profile remain reachable. Launch fails closed without the token.
 * BrowserMain is the console tool; LauncherMain is the windowed XP25Browser.exe.
 */
#define UNICODE
#define _UNICODE
#define COBJMACROS
#define _WIN32_WINNT 0x0501
#include <windows.h>
#include <wchar.h>
#include <shellapi.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shlwapi.h>
#include <winsafer.h>

static HANDLE output;
static void line(const char *s) { DWORD n; WriteFile(output,s,lstrlenA(s),&n,NULL); WriteFile(output,"\r\n",2,&n,NULL); }
static void number(const char *label,DWORD n) { char b[512]; wsprintfA(b,"%s=%lu",label,n); line(b); }
static int equal(LPCWSTR a,LPCWSTR b) { return lstrcmpiW(a,b)==0; }
static int safe_url(LPCWSTR s) {
    DWORD i;
    if (!s || lstrlenW(s)>2048) return 0;
    if (StrCmpNIW(s,L"http://",7)!=0 &&
        StrCmpNIW(s,L"https://",8)!=0) return 0;
    for (i=0;s[i];i++) if (s[i]<32 || s[i]==L'"') return 0;
    return 1;
}
static LPCWSTR launch_arguments(void);
static int shortcut(LPCWSTR folder,LPCWSTR suffix,LPCWSTR target,LPCWSTR icon) {
    IShellLinkW *link=NULL; IPersistFile *pf=NULL; HRESULT hr; WCHAR path[MAX_PATH];
    if (lstrlenW(folder)+lstrlenW(suffix)>=MAX_PATH) return 1;
    lstrcpyW(path,folder);lstrcatW(path,suffix);
    hr=CoCreateInstance(&CLSID_ShellLink,NULL,CLSCTX_INPROC_SERVER,&IID_IShellLinkW,(void **)&link);
    if (SUCCEEDED(hr)) hr=IShellLinkW_SetPath(link,target);
    if (SUCCEEDED(hr)) hr=IShellLinkW_SetDescription(link,L"Supermium web browser for Windows XP25");
    if (SUCCEEDED(hr)) hr=IShellLinkW_SetIconLocation(link,icon,0);
    if (SUCCEEDED(hr)) hr=IShellLinkW_QueryInterface(link,&IID_IPersistFile,(void **)&pf);
    if (SUCCEEDED(hr)) hr=IPersistFile_Save(pf,path,TRUE);
    if(pf) IPersistFile_Release(pf);
    if(link) IShellLinkW_Release(link);
    return FAILED(hr);
}
static LPCWSTR launch_arguments(void) {
    HKEY key;DWORD value=0,size=sizeof(value),type=0;
    if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\XP25\\Browser",0,KEY_READ,&key)==ERROR_SUCCESS) {
        if(RegQueryValueExW(key,L"SoftwareRendering",NULL,&type,(BYTE *)&value,&size)!=ERROR_SUCCESS || type!=REG_DWORD || size!=sizeof(value))value=0;
        RegCloseKey(key);
    }
    return value==1?L"--no-first-run --disable-gpu --classic-omnibox --classic-omnibox-border --compact-ui --enable-features=SupermiumCustomTabs,ForceXpTheme":
        L"--no-first-run --classic-omnibox --classic-omnibox-border --compact-ui --enable-features=SupermiumCustomTabs,ForceXpTheme";
}
static HANDLE reduced_token(void) {
    SAFER_LEVEL_HANDLE level=NULL;HANDLE token=NULL;DWORD error;
    if(!SaferCreateLevel(SAFER_SCOPEID_USER,SAFER_LEVELID_NORMALUSER,SAFER_LEVEL_OPEN,&level,NULL))return NULL;
    if(!SaferComputeTokenFromLevel(level,NULL,&token,0,NULL))token=NULL;
    error=GetLastError();SaferCloseLevel(level);SetLastError(error);
    return token;
}
/* Target is NULL for a plain launch, otherwise an already validated URL/path. */
static int start_browser(LPCWSTR target) {
    WCHAR program[MAX_PATH];static WCHAR command[4096];STARTUPINFOW si;PROCESS_INFORMATION pi;HANDLE token;DWORD error;
    if(FAILED(SHGetFolderPathW(NULL,CSIDL_PROGRAM_FILES,NULL,0,program)))return 1;
    if(lstrlenW(program)+24>=MAX_PATH)return ERROR_BUFFER_OVERFLOW;
    lstrcatW(program,L"\\Supermium\\chrome.exe");
    if(lstrlenW(program)+lstrlenW(launch_arguments())+(target?lstrlenW(target):0)+10>=4096)return ERROR_BUFFER_OVERFLOW;
    lstrcpyW(command,L"\"");lstrcatW(command,program);lstrcatW(command,L"\" ");lstrcatW(command,launch_arguments());
    if(target){lstrcatW(command,L" \"");lstrcatW(command,target);lstrcatW(command,L"\"");}
    token=reduced_token();
    if(!token){error=GetLastError();number("reduced_token_error",error);return error?(int)error:ERROR_ACCESS_DENIED;}
    ZeroMemory(&si,sizeof(si));si.cb=sizeof(si);ZeroMemory(&pi,sizeof(pi));
    if(!CreateProcessAsUserW(token,program,command,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi)){error=GetLastError();CloseHandle(token);return error;}
    CloseHandle(token);number("browser_pid",pi.dwProcessId);CloseHandle(pi.hThread);CloseHandle(pi.hProcess);return 0;
}
static int launch_browser(LPCWSTR target,int document) {
    DWORD i,attrs;
    if(!target || !target[0] || lstrlenW(target)>2048)return 87;
    for(i=0;target[i];i++)if(target[i]<32 || target[i]==L'"')return 87;
    if(document) {
        LPCWSTR ext=PathFindExtensionW(target);
        if(!equal(ext,L".html") && !equal(ext,L".htm"))return 87;
        attrs=GetFileAttributesW(target);
        if(attrs==INVALID_FILE_ATTRIBUTES || (attrs&FILE_ATTRIBUTE_DIRECTORY))return ERROR_FILE_NOT_FOUND;
    } else if(!safe_url(target) || wcschr(target,L'\\'))return 87;
    return start_browser(target);
}
static int shortcuts(void) {
    WCHAR folder[MAX_PATH],program[MAX_PATH],launcher[MAX_PATH]; int failed=0;
    if (FAILED(SHGetFolderPathW(NULL,CSIDL_PROGRAM_FILES,NULL,0,program))) return 1;
    lstrcpyW(launcher,program);lstrcatW(launcher,L"\\XP25Browser\\XP25Browser.exe");
    lstrcatW(program,L"\\Supermium\\chrome.exe");
    if (GetFileAttributesW(program)==INVALID_FILE_ATTRIBUTES || GetFileAttributesW(launcher)==INVALID_FILE_ATTRIBUTES) return 1;
    CoInitialize(NULL);
    if (SUCCEEDED(SHGetFolderPathW(NULL,CSIDL_DESKTOPDIRECTORY,NULL,0,folder))) failed|=shortcut(folder,L"\\Supermium.lnk",launcher,program);else failed=1;
    if (SUCCEEDED(SHGetFolderPathW(NULL,CSIDL_PROGRAMS,NULL,0,folder))) failed|=shortcut(folder,L"\\Supermium.lnk",launcher,program);else failed=1;
    if (SUCCEEDED(SHGetFolderPathW(NULL,CSIDL_APPDATA,NULL,0,folder))) {
        lstrcatW(folder,L"\\Microsoft\\Internet Explorer\\Quick Launch");
        CreateDirectoryW(folder,NULL);failed|=shortcut(folder,L"\\Supermium.lnk",launcher,program);
    } else failed=1;
    SHChangeNotify(SHCNE_ASSOCCHANGED,SHCNF_IDLIST,NULL,NULL);CoUninitialize();return failed;
}
static int open_shortcut(LPCWSTR path) {
    WCHAR url[2050];DWORD n=GetPrivateProfileStringW(L"InternetShortcut",L"URL",L"",url,2050,path);
    if (!n || n>=2049 || !safe_url(url)) return 87;
    return launch_browser(url,0);
}
static BOOL CALLBACK close_browser(HWND w,LPARAM unused) {
    DWORD pid;HANDLE p;WCHAR path[MAX_PATH];(void)unused;
    GetWindowThreadProcessId(w,&pid);p=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,pid);
    if(p) { if(GetModuleFileNameExW(p,NULL,path,MAX_PATH) && wcsstr(path,L"\\Supermium\\chrome.exe")) PostMessageW(w,WM_CLOSE,0,0);CloseHandle(p); }
    return TRUE;
}
static void inventory(void) {
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);PROCESSENTRY32W p;char b[1024];
    p.dwSize=sizeof(p);if(snap==INVALID_HANDLE_VALUE){number("snapshot_error",GetLastError());return;}
    if(Process32FirstW(snap,&p)) do {
        if(equal(p.szExeFile,L"chrome.exe")||equal(p.szExeFile,L"explorer.exe")||equal(p.szExeFile,L"iexplore.exe")||equal(p.szExeFile,L"helpctr.exe")||equal(p.szExeFile,L"hh.exe")||equal(p.szExeFile,L"ClippyAI.exe")||equal(p.szExeFile,L"RoverAI.exe")) {
            char name[MAX_PATH];HANDLE proc,token,mods;PROCESS_MEMORY_COUNTERS pm;MODULEENTRY32W m;BOOL job=FALSE;
            WideCharToMultiByte(CP_UTF8,0,p.szExeFile,-1,name,sizeof(name),NULL,NULL);
            wsprintfA(b,"PROCESS pid=%lu parent=%lu name=%s threads=%lu",p.th32ProcessID,p.th32ParentProcessID,name,p.cntThreads);line(b);
            proc=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,p.th32ProcessID);
            if(proc) { pm.cb=sizeof(pm);if(GetProcessMemoryInfo(proc,&pm,sizeof(pm))) {wsprintfA(b,"MEMORY pid=%lu working_set=%lu peak=%lu pagefile=%lu",p.th32ProcessID,(DWORD)pm.WorkingSetSize,(DWORD)pm.PeakWorkingSetSize,(DWORD)pm.PagefileUsage);line(b);}
                if(OpenProcessToken(proc,TOKEN_QUERY,&token)){wsprintfA(b,"TOKEN pid=%lu restricted=%u",p.th32ProcessID,IsTokenRestricted(token));line(b);CloseHandle(token);}
                if(IsProcessInJob(proc,NULL,&job)){wsprintfA(b,"JOB pid=%lu member=%u",p.th32ProcessID,job);line(b);}CloseHandle(proc);
            }else number("open_process_error",GetLastError());
            mods=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,p.th32ProcessID);m.dwSize=sizeof(m);
            if(mods!=INVALID_HANDLE_VALUE){if(Module32FirstW(mods,&m))do {WideCharToMultiByte(CP_UTF8,0,m.szModule,-1,name,sizeof(name),NULL,NULL);wsprintfA(b,"MODULE pid=%lu name=%s",p.th32ProcessID,name);line(b);}while(Module32NextW(mods,&m));CloseHandle(mods);}else number("module_error",GetLastError());
        }
    }while(Process32NextW(snap,&p));CloseHandle(snap);
}

static int registry_snapshot(int restore,LPCWSTR rootname,LPCWSTR path,LPCWSTR id) {
    HKEY root,bk,src,dst;LONG e;DWORD disposition,exists=0,size=sizeof(exists),type;WCHAR backup[128];
    DWORD i; if(lstrlenW(id)>16 || !*id)return 87;
    for(i=0;id[i];i++)if(id[i]<L'0'||id[i]>L'9')return 87;
    root=equal(rootname,L"HKLM")?HKEY_LOCAL_MACHINE:equal(rootname,L"HKCU")?HKEY_CURRENT_USER:NULL;
    if(!root || !*path || lstrlenW(path)>500)return 87;
    lstrcpyW(backup,L"SOFTWARE\\XP25\\BrowserRollback\\");lstrcatW(backup,id);
    if(!restore) {
        e=RegCreateKeyExW(HKEY_LOCAL_MACHINE,backup,0,NULL,0,KEY_ALL_ACCESS,NULL,&bk,&disposition);
        if(e)return e;
        if(disposition!=REG_CREATED_NEW_KEY){RegCloseKey(bk);return ERROR_ALREADY_EXISTS;}
        e=RegOpenKeyExW(root,path,0,KEY_READ,&src);
        if(e==ERROR_SUCCESS){exists=1;e=RegCreateKeyExW(bk,L"Data",0,NULL,0,KEY_ALL_ACCESS,NULL,&dst,NULL);
            if(!e){e=SHCopyKeyW(src,NULL,dst,0);RegCloseKey(dst);}RegCloseKey(src);
        }else if(e==ERROR_FILE_NOT_FOUND)e=ERROR_SUCCESS;
        if(!e)e=RegSetValueExW(bk,L"Exists",0,REG_DWORD,(BYTE *)&exists,sizeof(exists));
        RegCloseKey(bk);if(e)SHDeleteKeyW(HKEY_LOCAL_MACHINE,backup);return e;
    }
    e=RegOpenKeyExW(HKEY_LOCAL_MACHINE,backup,0,KEY_READ,&bk);if(e)return e;
    e=RegQueryValueExW(bk,L"Exists",NULL,&type,(BYTE *)&exists,&size);
    if(e || type!=REG_DWORD || size!=sizeof(exists)){RegCloseKey(bk);return ERROR_INVALID_DATA;}
    e=SHDeleteKeyW(root,path);if(e==ERROR_FILE_NOT_FOUND)e=0;
    if(!e && exists){e=RegOpenKeyExW(bk,L"Data",0,KEY_READ,&src);
        if(!e){e=RegCreateKeyExW(root,path,0,NULL,0,KEY_ALL_ACCESS,NULL,&dst,NULL);
            if(!e){e=SHCopyKeyW(src,NULL,dst,0);RegCloseKey(dst);}RegCloseKey(src);}}
    RegCloseKey(bk);return e;
}
void WINAPI BrowserMain(void) {
    int argc=0,rc=87;WCHAR **argv=CommandLineToArgvW(GetCommandLineW(),&argc);output=GetStdHandle(STD_OUTPUT_HANDLE);
    if(argc>=2) {
        if((equal(argv[1],L"key-save")||equal(argv[1],L"key-restore"))&&argc==5)rc=registry_snapshot(equal(argv[1],L"key-restore"),argv[2],argv[3],argv[4]);
        else if(equal(argv[1],L"shortcuts"))rc=shortcuts();
        else if(equal(argv[1],L"open-shortcut")&&argc==3)rc=open_shortcut(argv[2]);
        else if(equal(argv[1],L"open-url")&&argc==3)rc=launch_browser(argv[2],0);
        else if(equal(argv[1],L"open-document")&&argc==3)rc=launch_browser(argv[2],1);
        else if(equal(argv[1],L"launch")&&argc==2)rc=start_browser(NULL);
        else if(equal(argv[1],L"inventory")){inventory();rc=0;}
        else if(equal(argv[1],L"close")){EnumWindows(close_browser,0);rc=0;}
        else if(equal(argv[1],L"shell")&&argc==3){SHELLEXECUTEINFOW s;ZeroMemory(&s,sizeof(s));s.cbSize=sizeof(s);s.fMask=SEE_MASK_NOCLOSEPROCESS|SEE_MASK_FLAG_NO_UI;s.lpVerb=L"open";s.lpFile=argv[2];s.nShow=SW_SHOWNORMAL;if(ShellExecuteExW(&s)){rc=0;if(s.hProcess){number("shell_pid",GetProcessId(s.hProcess));CloseHandle(s.hProcess);}}else {rc=1;number("shell_error",GetLastError());}}
        else if(equal(argv[1],L"refresh")){SHChangeNotify(SHCNE_ASSOCCHANGED,SHCNF_IDLIST,NULL,NULL);rc=0;}
    }
    number("browserctl_exit",rc);if(argv)LocalFree(argv);ExitProcess(rc);
}

/* Windowed entry for shortcuts and the Start menu: launch verbs only. */
void WINAPI LauncherMain(void) {
    int argc=0,rc=87;WCHAR **argv=CommandLineToArgvW(GetCommandLineW(),&argc);output=GetStdHandle(STD_OUTPUT_HANDLE);
    if(argc==1)rc=start_browser(NULL);
    else if(argc==3 && equal(argv[1],L"open-url"))rc=launch_browser(argv[2],0);
    else if(argc==3 && equal(argv[1],L"open-document"))rc=launch_browser(argv[2],1);
    else if(argc==3 && equal(argv[1],L"open-shortcut"))rc=open_shortcut(argv[2]);
    if(argv)LocalFree(argv);
    ExitProcess(rc);
}
