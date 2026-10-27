/* Functional shell checks on the current interactive user's desktop. */
#define WINVER 0x0501
#define _WIN32_WINNT 0x0501
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>
#define LVM_GETITEMCOUNT (0x1000+4)
static HANDLE serial;static unsigned failures;static HWND folder,list;
static void report(const char *name,BOOL ok,DWORD error){char row[220];DWORD n;if(!ok)++failures;wsprintfA(row,"{\"shell_case\":\"%s\",\"status\":\"%s\",\"error\":%lu}\r\n",name,ok?"pass":"fail",ok?0:error);WriteFile(serial,row,lstrlenA(row),&n,NULL);}
static BOOL CALLBACK child(HWND w,LPARAM ignored){char cls[64];(void)ignored;GetClassNameA(w,cls,sizeof(cls));if(lstrcmpA(cls,"SysListView32")==0)list=w;return TRUE;}
static BOOL CALLBACK window(HWND w,LPARAM ignored){char cls[64],title[256];(void)ignored;GetClassNameA(w,cls,sizeof(cls));GetWindowTextA(w,title,sizeof(title));if((lstrcmpA(cls,"CabinetWClass")==0||lstrcmpA(cls,"ExploreWClass")==0)&&lstrcmpA(title,"XP25ShellNavigationFixture")==0){folder=w;EnumChildWindows(w,child,0);}return TRUE;}
static void key(BYTE vk){keybd_event(vk,0,0,0);keybd_event(vk,0,KEYEVENTF_KEYUP,0);}
void WINAPI ProbeMain(void){
 HWND tray=FindWindowA("Shell_TrayWnd",NULL),desktop=GetShellWindow(),menu;DWORD pid=0,n,offset=0,checksum=0,start;HANDLE snapshot,process;MODULEENTRY32 module={0};SIZE_T read;BOOL mapped=FALSE;HANDLE file;HMODULE theme;WCHAR theme_path[MAX_PATH],colors[64],size[64];
 typedef HRESULT(WINAPI *THEME)(LPWSTR,int,LPWSTR,int,LPWSTR,int);typedef BOOL(WINAPI *ACTIVE)(void);THEME current;ACTIVE active;HRESULT theme_result=E_FAIL;
 serial=CreateFileA("COM1",GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);if(serial==INVALID_HANDLE_VALUE)ExitProcess(90);WriteFile(serial,"SHELL_PROBE_STARTED\r\n",21,&n,NULL);
 if(tray){GetWindowThreadProcessId(tray,&pid);}report("desktop_and_taskbar_present",desktop&&tray&&pid,GetLastError());
 snapshot=pid?CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,pid):INVALID_HANDLE_VALUE;module.dwSize=sizeof(module);
 if(snapshot!=INVALID_HANDLE_VALUE&&Module32First(snapshot,&module))do{if(lstrcmpiA(module.szModule,"explorer.exe")==0){process=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,pid);if(process){mapped=ReadProcessMemory(process,module.modBaseAddr+60,&offset,4,&read)&&read==4&&ReadProcessMemory(process,module.modBaseAddr+offset+24+64,&checksum,4,&read)&&read==4;CloseHandle(process);}break;}}while(Module32Next(snapshot,&module));
 if(snapshot!=INVALID_HANDLE_VALUE){CloseHandle(snapshot);}{char row[160];wsprintfA(row,"{\"shell_image_identity\":true,\"pid\":%lu,\"read\":%u,\"pe_checksum\":%lu}\r\n",pid,mapped,checksum);WriteFile(serial,row,lstrlenA(row),&n,NULL);}report("live_explorer_image_read",mapped,GetLastError());
 key(VK_LWIN);start=GetTickCount();
 do{menu=FindWindowA("DV2ControlHost",NULL);if(!menu||!IsWindowVisible(menu))menu=FindWindowA("BaseBar",NULL);if(menu&&IsWindowVisible(menu))break;Sleep(100);}while(GetTickCount()-start<10000);
 {char row[100];wsprintfA(row,"{\"start_menu_wait_ms\":%lu}\r\n",GetTickCount()-start);WriteFile(serial,row,lstrlenA(row),&n,NULL);}
 report("start_menu_opens",menu&&IsWindowVisible(menu),GetLastError());key(VK_ESCAPE);
 theme=LoadLibraryA("uxtheme.dll");current=theme?(THEME)GetProcAddress(theme,"GetCurrentThemeName"):NULL;active=theme?(ACTIVE)GetProcAddress(theme,"IsThemeActive"):NULL;if(current)theme_result=current(theme_path,MAX_PATH,colors,64,size,64);{char row[180];wsprintfA(row,"{\"theme_result\":%lu,\"theme_active\":%u,\"theme_path_chars\":%lu}\r\n",(DWORD)theme_result,active?active():0,(DWORD)(SUCCEEDED(theme_result)?lstrlenW(theme_path):0));WriteFile(serial,row,lstrlenA(row),&n,NULL);}{
 HKEY configuration=NULL;DWORD bytes=sizeof(theme_path),type=0;BOOL configured=FALSE;
 if(RegOpenKeyExW(HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\ThemeManager",0,KEY_QUERY_VALUE,&configuration)==0){
  if(RegQueryValueExW(configuration,L"DllName",NULL,&type,(BYTE*)theme_path,&bytes)==0&&(type==REG_SZ||type==REG_EXPAND_SZ)){DWORD chars=lstrlenW(theme_path);configured=chars>=13&&lstrcmpiW(theme_path+chars-13,L"luna.msstyles")==0;}
  RegCloseKey(configuration);
 }
 report("luna_theme_active",active&&active()&&configured,theme_result);
}if(theme)FreeLibrary(theme);
 report("fixture_directory_unused",GetFileAttributesA("C:\\xp25\\XP25ShellNavigationFixture")==INVALID_FILE_ATTRIBUTES,GetLastError());if(GetFileAttributesA("C:\\xp25\\XP25ShellNavigationFixture")!=INVALID_FILE_ATTRIBUTES)goto done;
 report("fixture_directory_created",CreateDirectoryA("C:\\xp25\\XP25ShellNavigationFixture",NULL),GetLastError());
 file=CreateFileA("C:\\xp25\\XP25ShellNavigationFixture\\visible.txt",GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);report("fixture_file_created",file!=INVALID_HANDLE_VALUE,GetLastError());if(file!=INVALID_HANDLE_VALUE){WriteFile(file,"XP25 shell navigation",21,&n,NULL);CloseHandle(file);}
 report("open_folder_request",(INT_PTR)ShellExecuteA(NULL,"open","C:\\xp25\\XP25ShellNavigationFixture",NULL,NULL,SW_SHOWNORMAL)>32,GetLastError());
 start=GetTickCount();do{EnumWindows(window,0);if(folder&&list)break;Sleep(200);}while(GetTickCount()-start<30000);
 report("folder_window_and_list_view",folder&&list&&IsWindowVisible(folder),GetLastError());report("folder_displays_fixture",list&&SendMessageA(list,LVM_GETITEMCOUNT,0,0)>=1,GetLastError());
 if(folder){SendMessageA(folder,WM_CLOSE,0,0);Sleep(500);}report("fixture_file_removed",DeleteFileA("C:\\xp25\\XP25ShellNavigationFixture\\visible.txt"),GetLastError());report("fixture_directory_removed",RemoveDirectoryA("C:\\xp25\\XP25ShellNavigationFixture"),GetLastError());
 report("taskbar_survives_navigation",IsWindow(tray)&&IsWindowVisible(tray),GetLastError());
 done:report("shell_probe_complete",failures==0,failures);CloseHandle(serial);ExitProcess(failures?1:0);
}
