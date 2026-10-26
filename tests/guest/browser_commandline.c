/* Isolated fixture diagnostic: read only command lines of test Supermium
 * processes, plus the HTTP/HTTPS association delegate values. No profile data.
 */
#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0501
#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
static HANDLE loghandle;
static void line(const char *s){DWORD n;WriteFile(loghandle,s,lstrlenA(s),&n,NULL);WriteFile(loghandle,"\r\n",2,&n,NULL);}
static void reg_value(LPCWSTR path,LPCWSTR value){HKEY k;DWORD size=2048,type;WCHAR data[1024];char out[4096];LONG e;
 e=RegOpenKeyExW(HKEY_CLASSES_ROOT,path,0,KEY_READ,&k);if(e)return;
 e=RegQueryValueExW(k,value,NULL,&type,(BYTE *)data,&size);
 if(!e && (type==REG_SZ || type==REG_EXPAND_SZ)){data[1023]=0;WideCharToMultiByte(CP_UTF8,0,data,-1,out,sizeof(out),NULL,NULL);line(out);}RegCloseKey(k);
}
void WINAPI FixtureMain(void){HANDLE snap;PROCESSENTRY32W p;typedef LONG (WINAPI *QUERY)(HANDLE,ULONG,PVOID,ULONG,PULONG);QUERY query;
 loghandle=CreateFileW(L"COM1",GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);if(loghandle==INVALID_HANDLE_VALUE)ExitProcess(3);
 query=(QUERY)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQueryInformationProcess");
 snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);p.dwSize=sizeof(p);
 if(snap!=INVALID_HANDLE_VALUE && query && Process32FirstW(snap,&p))do {
  if(!lstrcmpiW(p.szExeFile,L"chrome.exe")){
   HANDLE h=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,p.th32ProcessID);DWORD basic[6],peb[9],parameters[18];WCHAR command[4096];char out[8192];SIZE_T got;
   if(h){if(query(h,0,basic,sizeof(basic),NULL)==0 && ReadProcessMemory(h,(void *)(UINT_PTR)basic[1],peb,sizeof(peb),&got) && ReadProcessMemory(h,(void *)(UINT_PTR)peb[4],parameters,sizeof(parameters),&got)){
    DWORD length=parameters[16]&0xffff;char label[100];if(length>sizeof(command)-2)length=sizeof(command)-2;
    if(ReadProcessMemory(h,(void *)(UINT_PTR)parameters[17],command,length,&got)){command[length/2]=0;WideCharToMultiByte(CP_UTF8,0,command,-1,out,sizeof(out),NULL,NULL);wsprintfA(label,"FIXTURE_COMMAND pid=%lu",p.th32ProcessID);line(label);line(out);}
   }CloseHandle(h);}
  }
 }while(Process32NextW(snap,&p));
 if(snap!=INVALID_HANDLE_VALUE)CloseHandle(snap);
 line("HTTP command:");reg_value(L"http\\shell\\open\\command",NULL);line("HTTP DelegateExecute:");reg_value(L"http\\shell\\open\\command",L"DelegateExecute");
 line("HTTPS command:");reg_value(L"https\\shell\\open\\command",NULL);line("HTTPS DelegateExecute:");reg_value(L"https\\shell\\open\\command",L"DelegateExecute");
 CloseHandle(loghandle);ExitProcess(0);
}
