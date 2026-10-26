/* Native shell acceptance and diagnostic fixtures for XP25 browser integration. */
#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0501
#define COBJMACROS
#include <windows.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <tlhelp32.h>

static HANDLE loghandle;
static int failures;
static void check(LPCSTR name,int ok){char b[512];DWORD n;wsprintfA(b,"XP25_BROWSER_CASE %s %s\r\n",ok?"PASS":"FAIL",name);WriteFile(loghandle,b,lstrlenA(b),&n,NULL);if(!ok)failures++;}
static int contains(LPCWSTR s,LPCWSTR word){return StrStrIW(s,word)!=NULL;}
static int assoc(LPCWSTR type,LPCWSTR expected){WCHAR value[2048];DWORD size=2048;HRESULT h=AssocQueryStringW(ASSOCF_VERIFY,ASSOCSTR_COMMAND,type,L"open",value,&size);return SUCCEEDED(h)&&contains(value,expected)&&!contains(value,L"iexplore.exe")&&!contains(value,L"no-sandbox")&&!contains(value,L"ignore-certificate");}
static int link(LPCWSTR folder,LPCWSTR name){WCHAR file[MAX_PATH],target[MAX_PATH];IShellLinkW *s=NULL;IPersistFile *p=NULL;HRESULT h;int ok=0;
 if(lstrlenW(folder)+lstrlenW(name)>=MAX_PATH)return 0;
 lstrcpyW(file,folder);lstrcatW(file,name);
 h=CoCreateInstance(&CLSID_ShellLink,NULL,CLSCTX_INPROC_SERVER,&IID_IShellLinkW,(void **)&s);
 if(SUCCEEDED(h))h=IShellLinkW_QueryInterface(s,&IID_IPersistFile,(void **)&p);
 if(SUCCEEDED(h))h=IPersistFile_Load(p,file,STGM_READ);
 if(SUCCEEDED(h))h=IShellLinkW_GetPath(s,target,MAX_PATH,NULL,SLGP_RAWPATH);
 if(SUCCEEDED(h))ok=contains(target,L"\\XP25Browser\\XP25Browser.exe")&&GetFileAttributesW(target)!=INVALID_FILE_ATTRIBUTES;
 if(p)IPersistFile_Release(p);
 if(s)IShellLinkW_Release(s);
 return ok;
}
static int ie_running(void){HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);PROCESSENTRY32W p;int found=0;p.dwSize=sizeof(p);
 if(snap==INVALID_HANDLE_VALUE)return 1;
 if(Process32FirstW(snap,&p)) {
 do {if(!lstrcmpiW(p.szExeFile,L"iexplore.exe"))found=1;}while(Process32NextW(snap,&p));
 }
 CloseHandle(snap);return found;
}
void WINAPI ShellProbeMain(void){WCHAR folder[MAX_PATH],value[512];HKEY k;DWORD type,size=sizeof(value);OSVERSIONINFOW os;
 loghandle=GetStdHandle(STD_OUTPUT_HANDLE);CoInitialize(NULL);
 check("http_association",assoc(L"http",L"\\XP25Browser\\browserctl.exe"));
 check("https_association",assoc(L"https",L"\\XP25Browser\\browserctl.exe"));
 check("html_association",assoc(L".html",L"\\XP25Browser\\browserctl.exe"));
 check("htm_association",assoc(L".htm",L"\\XP25Browser\\browserctl.exe"));
 check("url_association",assoc(L".url",L"\\XP25Browser\\browserctl.exe"));
 check("legacy_htmlfile",assoc(L"htmlfile",L"\\XP25Browser\\browserctl.exe"));
 check("legacy_htmfile",assoc(L"htmfile",L"\\XP25Browser\\browserctl.exe"));
 check("desktop_shortcut",SUCCEEDED(SHGetFolderPathW(NULL,CSIDL_DESKTOPDIRECTORY,NULL,0,folder))&&link(folder,L"\\Supermium.lnk"));
 check("start_shortcut",SUCCEEDED(SHGetFolderPathW(NULL,CSIDL_PROGRAMS,NULL,0,folder))&&link(folder,L"\\Supermium.lnk"));
 if(SUCCEEDED(SHGetFolderPathW(NULL,CSIDL_APPDATA,NULL,0,folder))){lstrcatW(folder,L"\\Microsoft\\Internet Explorer\\Quick Launch");check("quick_launch_shortcut",link(folder,L"\\Supermium.lnk"));}else check("quick_launch_shortcut",0);
 if(RegOpenKeyExW(HKEY_CURRENT_USER,L"Software\\Clients\\StartMenuInternet",0,KEY_READ,&k)==ERROR_SUCCESS){LONG e=RegQueryValueExW(k,NULL,NULL,&type,(BYTE *)value,&size);check("start_menu_browser",!e&&type==REG_SZ&&!lstrcmpiW(value,L"Supermium"));RegCloseKey(k);}else check("start_menu_browser",0);
 {WCHAR p[MAX_PATH];int layout=0;if(SUCCEEDED(SHGetFolderPathW(NULL,CSIDL_PROGRAM_FILES,NULL,0,p))){lstrcatW(p,L"\\Supermium\\pwrp_k32_sm.dll");layout=GetFileAttributesW(p)!=INVALID_FILE_ATTRIBUTES;}check("watch_proxy_layout",layout);}
 size=sizeof(value);if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Policies\\Supermium\\URLBlocklist",0,KEY_READ,&k)==ERROR_SUCCESS){LONG e=RegQueryValueExW(k,L"1",NULL,&type,(BYTE *)value,&size);check("internet_blocklist_policy",!e&&type==REG_SZ&&!lstrcmpW(value,L"*"));RegCloseKey(k);}else check("internet_blocklist_policy",0);
 check("ie_not_running",!ie_running());ZeroMemory(&os,sizeof(os));os.dwOSVersionInfoSize=sizeof(os);check("nt_51",GetVersionExW(&os)&&os.dwMajorVersion==5&&os.dwMinorVersion==1);
 {char b[128];DWORD n;wsprintfA(b,"XP25_BROWSER_SHELL_FAILURES=%d\r\n",failures);WriteFile(loghandle,b,lstrlenA(b),&n,NULL);}
 CoUninitialize();ExitProcess(failures?1:0);
}
