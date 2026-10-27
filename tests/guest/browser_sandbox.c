/* Private, unmonitored fixture only. Exercise effective tokens against newly
 * created administrator-only file/registry objects. No renderer injection,
 * privilege enabling, existing ACL changes or browser profile inspection.
 */
#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0501
#include <windows.h>
#include <aclapi.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <wchar.h>
static HANDLE output;static PSID admin_sid,system_sid,restricted_sid;static DWORD explorer_pid,system_pid;static WCHAR profile[MAX_PATH];
static WCHAR command[4096];static BYTE token_data[16384];
static void line(const char *s){DWORD n;WriteFile(output,s,lstrlenA(s),&n,NULL);WriteFile(output,"\r\n",2,&n,NULL);}
static int setup(void){
 SID_IDENTIFIER_AUTHORITY authority=SECURITY_NT_AUTHORITY;EXPLICIT_ACCESSW entries[2];PACL acl=NULL;SECURITY_DESCRIPTOR descriptor;SECURITY_ATTRIBUTES attributes;HKEY key;DWORD disposition,error;
 if(!AllocateAndInitializeSid(&authority,2,SECURITY_BUILTIN_DOMAIN_RID,DOMAIN_ALIAS_RID_ADMINS,0,0,0,0,0,0,&admin_sid) || !AllocateAndInitializeSid(&authority,1,SECURITY_LOCAL_SYSTEM_RID,0,0,0,0,0,0,0,&system_sid) || !AllocateAndInitializeSid(&authority,1,SECURITY_RESTRICTED_CODE_RID,0,0,0,0,0,0,0,&restricted_sid))return 1;
 ZeroMemory(entries,sizeof(entries));entries[0].grfAccessPermissions=GENERIC_ALL;entries[0].grfAccessMode=SET_ACCESS;entries[0].grfInheritance=SUB_CONTAINERS_AND_OBJECTS_INHERIT;entries[0].Trustee.TrusteeForm=TRUSTEE_IS_SID;entries[0].Trustee.ptstrName=(LPWSTR)admin_sid;entries[1]=entries[0];entries[1].Trustee.ptstrName=(LPWSTR)system_sid;
 error=SetEntriesInAclW(2,entries,NULL,&acl);if(error)return (int)error;
 InitializeSecurityDescriptor(&descriptor,SECURITY_DESCRIPTOR_REVISION);SetSecurityDescriptorOwner(&descriptor,admin_sid,FALSE);SetSecurityDescriptorDacl(&descriptor,TRUE,acl,FALSE);SetSecurityDescriptorControl(&descriptor,SE_DACL_PROTECTED,SE_DACL_PROTECTED);
 attributes.nLength=sizeof(attributes);attributes.lpSecurityDescriptor=&descriptor;attributes.bInheritHandle=FALSE;
 CreateDirectoryW(L"C:\\xp25",NULL);CreateDirectoryW(L"C:\\xp25\\browserdiag",NULL);
 if(!CreateDirectoryW(L"C:\\xp25\\browserdiag\\Boundary",&attributes)){error=GetLastError();LocalFree(acl);return (int)error;}
 error=RegCreateKeyExW(HKEY_LOCAL_MACHINE,L"Software\\XP25\\BrowserDiagBoundary26",0,NULL,0,KEY_ALL_ACCESS,&attributes,&key,&disposition);LocalFree(acl);
 if(error)return (int)error;
 RegCloseKey(key);if(disposition!=REG_CREATED_NEW_KEY)return ERROR_ALREADY_EXISTS;
 return 0;
}
static int boundary(HANDLE token,DWORD pid,const char *kind){
 WCHAR path[MAX_PATH],key_path[MAX_PATH];HANDLE file;HKEY key;DWORD file_error,reg_error,disposition;BOOL impersonated=FALSE;char text[512];
 wsprintfW(path,L"C:\\xp25\\browserdiag\\Boundary\\p%lu.tmp",pid);wsprintfW(key_path,L"Software\\XP25\\BrowserDiagBoundary26\\p%lu",pid);
 if(token){impersonated=ImpersonateLoggedOnUser(token);if(!impersonated){wsprintfA(text,"IMPERSONATION_FAILED pid=%lu kind=%s error=%lu",pid,kind,GetLastError());line(text);return -1;}}
 file=CreateFileW(path,GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_TEMPORARY|FILE_FLAG_DELETE_ON_CLOSE,NULL);file_error=file==INVALID_HANDLE_VALUE?GetLastError():0;if(file!=INVALID_HANDLE_VALUE)CloseHandle(file);
 reg_error=RegCreateKeyExW(HKEY_LOCAL_MACHINE,key_path,0,NULL,0,KEY_READ|KEY_WRITE,NULL,&key,&disposition);
 if(!reg_error){RegCloseKey(key);RegDeleteKeyW(HKEY_LOCAL_MACHINE,key_path);}
 /* Informational: what the token can still reach. The user's own profile is
  * expected to stay writable; opening the unrestricted shell for injection
  * rights is the NT 5.1 cross-process boundary (no UIPI or integrity levels). */
 {DWORD user_error=0,shell_error=0,sys_file_error=0,sys_inject_error=0;HANDLE shell,sysproc,sysfile;WCHAR sys[MAX_PATH];
  wsprintfW(path,L"%s\\xp25-boundary-p%lu.tmp",profile,pid);
  file=CreateFileW(path,GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_TEMPORARY|FILE_FLAG_DELETE_ON_CLOSE,NULL);user_error=file==INVALID_HANDLE_VALUE?GetLastError():0;if(file!=INVALID_HANDLE_VALUE)CloseHandle(file);
  shell=explorer_pid?OpenProcess(PROCESS_VM_WRITE|PROCESS_VM_OPERATION|PROCESS_CREATE_THREAD,FALSE,explorer_pid):NULL;shell_error=shell?0:(explorer_pid?GetLastError():ERROR_NOT_FOUND);if(shell)CloseHandle(shell);
  /* Protected system file: a renderer must not write under %WINDIR%\\system32. */
  GetSystemDirectoryW(sys,MAX_PATH);wsprintfW(path,L"%s\\xp25-sysboundary-p%lu.tmp",sys,pid);
  sysfile=CreateFileW(path,GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_TEMPORARY|FILE_FLAG_DELETE_ON_CLOSE,NULL);sys_file_error=sysfile==INVALID_HANDLE_VALUE?GetLastError():0;if(sysfile!=INVALID_HANDLE_VALUE)CloseHandle(sysfile);
  /* Privileged SYSTEM process: a renderer must not open it for code injection. */
  sysproc=system_pid?OpenProcess(PROCESS_VM_WRITE|PROCESS_VM_OPERATION|PROCESS_CREATE_THREAD,FALSE,system_pid):NULL;sys_inject_error=sysproc?0:(system_pid?GetLastError():ERROR_NOT_FOUND);if(sysproc)CloseHandle(sysproc);
  if(impersonated && !RevertToSelf())ExitProcess(70);
  wsprintfA(text,"REACHABLE pid=%lu kind=%s user_profile_write=%u user_profile_error=%lu shell_injection_rights=%u shell_error=%lu",pid,kind,user_error==0,user_error,shell_error==0,shell_error);line(text);
  wsprintfA(text,"PRIVBOUNDARY pid=%lu kind=%s system_file_write=%u system_file_error=%lu system_pid=%lu system_inject=%u system_inject_error=%lu",pid,kind,sys_file_error==0,sys_file_error,system_pid,sys_inject_error==0,sys_inject_error);line(text);}
 wsprintfA(text,"BOUNDARY pid=%lu kind=%s file_write=%u file_error=%lu registry_write=%u registry_error=%lu",pid,kind,file_error==0,file_error,reg_error==0,reg_error);line(text);
 if(!file_error && !reg_error)return 2;
 return file_error==ERROR_ACCESS_DENIED && reg_error==ERROR_ACCESS_DENIED?1:0;
}
static void inspect_token(HANDLE token,DWORD pid,DWORD tid,const char *kind){
 DWORD size,i;HANDLE duplicate;char text[512];BOOL restricted=IsTokenRestricted(token);wsprintfA(text,"TOKEN pid=%lu tid=%lu kind=%s restricted=%u",pid,tid,kind,restricted);line(text);
 if(GetTokenInformation(token,TokenGroups,token_data,sizeof(token_data),&size)){
  TOKEN_GROUPS *groups=(TOKEN_GROUPS *)token_data;
  for(i=0;i<groups->GroupCount;i++)if(EqualSid(groups->Groups[i].Sid,admin_sid)){wsprintfA(text,"ADMIN_SID pid=%lu tid=%lu attributes=%08lx",pid,tid,groups->Groups[i].Attributes);line(text);}
 }
 if(GetTokenInformation(token,TokenRestrictedSids,token_data,sizeof(token_data),&size)){wsprintfA(text,"RESTRICTED_SIDS pid=%lu tid=%lu count=%lu",pid,tid,((TOKEN_GROUPS *)token_data)->GroupCount);line(text);}
 if(GetTokenInformation(token,TokenPrivileges,token_data,sizeof(token_data),&size)){
  TOKEN_PRIVILEGES *privileges=(TOKEN_PRIVILEGES *)token_data;
  for(i=0;i<privileges->PrivilegeCount;i++)if(privileges->Privileges[i].Attributes&SE_PRIVILEGE_ENABLED){wsprintfA(text,"ENABLED_PRIVILEGE pid=%lu tid=%lu luid_low=%lu attributes=%lu",pid,tid,privileges->Privileges[i].Luid.LowPart,privileges->Privileges[i].Attributes);line(text);}
 }
 if(DuplicateTokenEx(token,TOKEN_QUERY|TOKEN_IMPERSONATE,NULL,SecurityImpersonation,TokenImpersonation,&duplicate)){boundary(duplicate,pid,kind);CloseHandle(duplicate);}
 else {wsprintfA(text,"DUPLICATE_TOKEN_FAILED pid=%lu tid=%lu error=%lu",pid,tid,GetLastError());line(text);}
}
static void process_command(HANDLE process){
 typedef LONG (WINAPI *QUERY)(HANDLE,ULONG,PVOID,ULONG,PULONG);QUERY query=(QUERY)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQueryInformationProcess");DWORD basic[6],peb[9],params[18],length;SIZE_T got;
 command[0]=0;if(!query || query(process,0,basic,sizeof(basic),NULL))return;
 if(!ReadProcessMemory(process,(void *)(UINT_PTR)basic[1],peb,sizeof(peb),&got) || !ReadProcessMemory(process,(void *)(UINT_PTR)peb[4],params,sizeof(params),&got))return;
 length=params[16]&0xffff;if(length>sizeof(command)-2)length=sizeof(command)-2;
 if(ReadProcessMemory(process,(void *)(UINT_PTR)params[17],command,length,&got))command[length/2]=0;
}
void WINAPI SandboxMain(void){
 HANDLE snapshot,own,restricted;PROCESSENTRY32W entry;SID_AND_ATTRIBUTES disabled,restriction;DWORD count=0;char text[1024];int error;output=GetStdHandle(STD_OUTPUT_HANDLE);
 if(!GetEnvironmentVariableW(L"USERPROFILE",profile,MAX_PATH))ExitProcess(8);
 snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);entry.dwSize=sizeof(entry);
 if(snapshot!=INVALID_HANDLE_VALUE && Process32FirstW(snapshot,&entry))do{if(!lstrcmpiW(entry.szExeFile,L"explorer.exe"))explorer_pid=entry.th32ProcessID;
  if(!system_pid && (!lstrcmpiW(entry.szExeFile,L"services.exe")||!lstrcmpiW(entry.szExeFile,L"winlogon.exe")||!lstrcmpiW(entry.szExeFile,L"lsass.exe")))system_pid=entry.th32ProcessID;}while(Process32NextW(snapshot,&entry));
 if(snapshot!=INVALID_HANDLE_VALUE)CloseHandle(snapshot);
 error=setup();wsprintfA(text,"BOUNDARY_SETUP=%d",error);line(text);if(error)ExitProcess(2);
 if(boundary(NULL,GetCurrentProcessId(),"baseline")!=2)ExitProcess(3);
 if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY|TOKEN_DUPLICATE,&own))ExitProcess(4);
 disabled.Sid=admin_sid;disabled.Attributes=0;restriction.Sid=restricted_sid;restriction.Attributes=0;
 if(!CreateRestrictedToken(own,DISABLE_MAX_PRIVILEGE,1,&disabled,0,NULL,1,&restriction,&restricted))ExitProcess(5);
 if(boundary(restricted,0,"known_restricted")!=1)ExitProcess(6);
 CloseHandle(restricted);CloseHandle(own);
 snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);entry.dwSize=sizeof(entry);
 if(snapshot!=INVALID_HANDLE_VALUE && Process32FirstW(snapshot,&entry))do{
  if(!lstrcmpiW(entry.szExeFile,L"chrome.exe")){
   HANDLE process=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,entry.th32ProcessID),token;const char *role="browser_or_utility";
   wsprintfA(text,"OBSERVED_BROWSER pid=%lu parent=%lu",entry.th32ProcessID,entry.th32ParentProcessID);line(text);
   if(!process){wsprintfA(text,"PROCESS_OPEN_FAILED pid=%lu error=%lu",entry.th32ProcessID,GetLastError());line(text);continue;}
   process_command(process);if(wcsstr(command,L"--type=renderer"))role="renderer";else if(wcsstr(command,L"--type=gpu-process"))role="gpu";
   wsprintfA(text,"SANDBOX_PROCESS pid=%lu parent=%lu role=%s",entry.th32ProcessID,entry.th32ParentProcessID,role);line(text);count++;
   if(OpenProcessToken(process,TOKEN_QUERY|TOKEN_DUPLICATE,&token)){inspect_token(token,entry.th32ProcessID,0,"primary");CloseHandle(token);}else {wsprintfA(text,"TOKEN_OPEN_FAILED pid=%lu error=%lu",entry.th32ProcessID,GetLastError());line(text);}
   {HANDLE threads=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);THREADENTRY32 t;t.dwSize=sizeof(t);
    if(threads!=INVALID_HANDLE_VALUE && Thread32First(threads,&t))do{if(t.th32OwnerProcessID==entry.th32ProcessID){HANDLE thread=OpenThread(THREAD_QUERY_INFORMATION,FALSE,t.th32ThreadID);if(thread){if(OpenThreadToken(thread,TOKEN_QUERY|TOKEN_DUPLICATE,FALSE,&token)){inspect_token(token,entry.th32ProcessID,t.th32ThreadID,"thread");CloseHandle(token);}else {DWORD e=GetLastError();wsprintfA(text,"THREAD_TOKEN pid=%lu tid=%lu error=%lu",entry.th32ProcessID,t.th32ThreadID,e);line(text);}CloseHandle(thread);}}}while(Thread32Next(threads,&t));
    if(threads!=INVALID_HANDLE_VALUE)CloseHandle(threads);
   }
   CloseHandle(process);
  }
 }while(Process32NextW(snapshot,&entry));
 if(snapshot!=INVALID_HANDLE_VALUE)CloseHandle(snapshot);
 wsprintfA(text,"SANDBOX_PROCESS_COUNT=%lu",count);line(text);
 RegDeleteKeyW(HKEY_LOCAL_MACHINE,L"Software\\XP25\\BrowserDiagBoundary26");RemoveDirectoryW(L"C:\\xp25\\browserdiag\\Boundary");
 FreeSid(admin_sid);FreeSid(system_sid);FreeSid(restricted_sid);ExitProcess(count?0:7);
}
