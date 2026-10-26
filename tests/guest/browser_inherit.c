/* Characterize Supermium's NT 5.1 emulation of PROC_THREAD_ATTRIBUTE_HANDLE_LIST
 * (pwrp_k32 InitializeProcThreadAttributeList / UpdateProcThreadAttribute /
 * CreateProcessW) against Chromium's child-launch pattern (base/process/launch_win.cc):
 * a shared-memory Section is marked inheritable and listed, then CreateProcessW runs
 * with bInheritHandles=TRUE and EXTENDED_STARTUPINFO_PRESENT. The child reports the
 * NT object type each inherited handle VALUE names, exactly as base::win::GetObjectTypeName
 * (NtQueryObject) does inside TakeHandleOfType. This reproduces the 0x842214 CHECK
 * condition without the browser. Nothing is translated, retried or faked.
 *
 * Usage: browser_inherit.exe <dir with pwrp_k32.dll and pwrp_k32_sm.dll>
 *        browser_inherit.exe child <section-value> <event-value> <mode>
 */
#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0501
#include <windows.h>
#include <shellapi.h>

typedef BOOL (WINAPI *INIT_LIST)(LPVOID,DWORD,DWORD,PSIZE_T);
typedef BOOL (WINAPI *UPDATE_LIST)(LPVOID,DWORD,DWORD_PTR,PVOID,SIZE_T,PVOID,PSIZE_T);
typedef VOID (WINAPI *DELETE_LIST)(LPVOID);
typedef BOOL (WINAPI *CREATE_PROCESS)(LPCWSTR,LPWSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCWSTR,LPVOID,LPPROCESS_INFORMATION);
typedef LONG (WINAPI *QUERY_OBJECT)(HANDLE,ULONG,PVOID,ULONG,PULONG);

#define XP25_EXTENDED_STARTUPINFO_PRESENT 0x00080000
#define XP25_PROC_THREAD_ATTRIBUTE_HANDLE_LIST 0x00020002
#define OBJECT_TYPE_INFORMATION 2
typedef struct {USHORT Length;USHORT MaximumLength;PWSTR Buffer;} XP25_USTRING;

static HANDLE output;
static WCHAR self[MAX_PATH];
static INIT_LIST init_list;static UPDATE_LIST update_list;static DELETE_LIST delete_list;static CREATE_PROCESS create_process;static QUERY_OBJECT query_object;
static HANDLE parse_handle(LPCWSTR s){DWORD v=0,i;for(i=0;s[i]>=L'0'&&s[i]<=L'9';i++)v=v*10+(DWORD)(s[i]-L'0');return (HANDLE)(UINT_PTR)v;}
static void line(const char *s){DWORD n;WriteFile(output,s,lstrlenA(s),&n,NULL);WriteFile(output,"\r\n",2,&n,NULL);}

/* Return the NT object type name for a handle VALUE, or NULL if invalid/untyped.
 * Mirrors base::win::GetObjectTypeName (NtQueryObject, ObjectTypeInformation). */
static int type_name(HANDLE handle,WCHAR *out,int cap){
 BYTE buffer[1024];ULONG got=0;LONG status;XP25_USTRING *name=(XP25_USTRING *)buffer;int i,len;
 status=query_object(handle,OBJECT_TYPE_INFORMATION,buffer,sizeof(buffer),&got);
 if(status<0 || !name->Buffer)return 0;
 len=name->Length/sizeof(WCHAR);if(len>=cap)len=cap-1;
 for(i=0;i<len;i++)out[i]=name->Buffer[i];
 out[len]=0;
 return len;
}

static int run_child(WCHAR **argv){
 HANDLE section=parse_handle(argv[2]);
 HANDLE event=parse_handle(argv[3]);
 WCHAR name[64];char text[512];int len;
 len=type_name(section,name,64);
 {char n[128];WideCharToMultiByte(CP_UTF8,0,name,-1,n,sizeof(n),NULL,NULL);
  wsprintfA(text,"CHILD mode=%S listed_section value=%ld type=%s len=%d is_section=%d",argv[4],(long)(DWORD)(UINT_PTR)section,len?n:"<invalid>",len,len==7 && !lstrcmpW(name,L"Section"));line(text);}
 len=type_name(event,name,64);
 {char n[128];WideCharToMultiByte(CP_UTF8,0,name,-1,n,sizeof(n),NULL,NULL);
  wsprintfA(text,"CHILD mode=%S unlisted_event value=%ld type=%s len=%d inherited=%d",argv[4],(long)(DWORD)(UINT_PTR)event,len?n:"<invalid>",len,len>0);line(text);}
 return 0;
}

/* One launch. list=1 uses the HANDLE_LIST attribute (only the Section listed);
 * list=0 is plain bInheritHandles=TRUE. The event is always left inheritable to
 * reveal whether the attribute list actually restricts the inherited set. */
static int launch(HANDLE section,HANDLE event,int list,const char *mode){
 BYTE attr[256];SIZE_T size=sizeof(attr);PROCESS_INFORMATION pi;DWORD flags=0,exit_code=999;
 struct {STARTUPINFOW si;PVOID list;} sx;WCHAR cmd[512];char text[256];
 ZeroMemory(&sx,sizeof(sx));sx.si.cb=list?sizeof(sx):sizeof(sx.si);
 if(list){
  if(!init_list(attr,1,0,&size)){wsprintfA(text,"LAUNCH mode=%s init_list_error=%lu",mode,GetLastError());line(text);return 1;}
  if(!update_list(attr,0,XP25_PROC_THREAD_ATTRIBUTE_HANDLE_LIST,&section,sizeof(HANDLE),NULL,NULL)){wsprintfA(text,"LAUNCH mode=%s update_error=%lu",mode,GetLastError());line(text);return 1;}
  sx.list=attr;flags|=XP25_EXTENDED_STARTUPINFO_PRESENT;
 }
 wsprintfW(cmd,L"\"%s\" child %ld %ld %S",self,(long)(DWORD)(UINT_PTR)section,(long)(DWORD)(UINT_PTR)event,mode);
 if(!create_process(self,cmd,NULL,NULL,TRUE,flags,NULL,NULL,list?(LPVOID)&sx:(LPVOID)&sx.si,&pi)){
  wsprintfA(text,"LAUNCH mode=%s create_error=%lu",mode,GetLastError());line(text);if(list)delete_list(attr);return 1;}
 WaitForSingleObject(pi.hProcess,10000);GetExitCodeProcess(pi.hProcess,&exit_code);
 CloseHandle(pi.hThread);CloseHandle(pi.hProcess);if(list)delete_list(attr);
 wsprintfA(text,"LAUNCH mode=%s child_exit=%lu section_value=%ld event_value=%ld",mode,exit_code,(long)(DWORD)(UINT_PTR)section,(long)(DWORD)(UINT_PTR)event);line(text);return 0;
}

void WINAPI InheritMain(void){
 int argc=0;WCHAR **argv=CommandLineToArgvW(GetCommandLineW(),&argc),path[MAX_PATH];
 HMODULE proxy,ntdll;SECURITY_ATTRIBUTES sa;HANDLE section,event;char text[256];DWORD i;
 output=GetStdHandle(STD_OUTPUT_HANDLE);GetModuleFileNameW(NULL,self,MAX_PATH);
 ntdll=GetModuleHandleW(L"ntdll.dll");query_object=(QUERY_OBJECT)(DWORD_PTR)GetProcAddress(ntdll,"NtQueryObject");
 if(argc>=5 && !lstrcmpW(argv[1],L"child")){int rc=run_child(argv);if(argv)LocalFree(argv);ExitProcess(rc);}
 if(argc!=2){line("INHERIT usage: browser_inherit.exe <dir>");ExitProcess(87);}
 /* Load the exact pwrp_k32 the browser uses, so the attribute-list functions and
  * CreateProcessW are Supermium's own NT 5.1 emulation, not XP's kernel32. */
 /* Load progwrp's real implementation directly by full path. The installed
  * proxy forwards these functions to pwrp_k32_sm unchanged, but a bare-name
  * forward only resolves from chrome.exe's own directory; load it explicitly. */
 wsprintfW(path,L"%s\\pwrp_k32_sm.dll",argv[1]);proxy=LoadLibraryW(path);
 if(!proxy){wsprintfA(text,"INHERIT load_error=%lu path=%S",GetLastError(),path);line(text);ExitProcess(2);}
 init_list=(INIT_LIST)(DWORD_PTR)GetProcAddress(proxy,"InitializeProcThreadAttributeList");
 update_list=(UPDATE_LIST)(DWORD_PTR)GetProcAddress(proxy,"UpdateProcThreadAttribute");
 delete_list=(DELETE_LIST)(DWORD_PTR)GetProcAddress(proxy,"DeleteProcThreadAttributeList");
 create_process=(CREATE_PROCESS)(DWORD_PTR)GetProcAddress(proxy,"CreateProcessW");
 if(!init_list || !update_list || !delete_list || !create_process || !query_object){line("INHERIT missing_exports");ExitProcess(3);}
 sa.nLength=sizeof(sa);sa.lpSecurityDescriptor=NULL;sa.bInheritHandle=TRUE;
 /* A real read-only shared-memory Section, like the field-trial allocation. */
 section=CreateFileMappingW(INVALID_HANDLE_VALUE,&sa,PAGE_READONLY,0,65536,NULL);
 event=CreateEventW(&sa,TRUE,FALSE,NULL);
 if(!section || !event){line("INHERIT object_create_failed");ExitProcess(4);}
 wsprintfA(text,"PARENT section_value=%ld event_value=%ld",(long)(DWORD)(UINT_PTR)section,(long)(DWORD)(UINT_PTR)event);line(text);
 /* Run each mode several times: handle-value collisions in the child are timing
  * and allocation dependent, so a single pass can miss the confusion. */
 for(i=0;i<6;i++)launch(section,event,1,"handle_list");
 for(i=0;i<3;i++)launch(section,event,0,"inherit_all");
 CloseHandle(section);CloseHandle(event);if(argv)LocalFree(argv);
 line("INHERIT_DONE");ExitProcess(0);
}
