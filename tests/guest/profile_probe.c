/* A fresh local fixture account/profile; never changes the existing XP25 account. */
#define WINVER 0x0501
#define _WIN32_WINNT 0x0501
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <lm.h>
#include <sddl.h>
#include <userenv.h>
static HANDLE serial;static unsigned failures;
static void report(const char *name,BOOL ok,DWORD error){char row[220];DWORD n;if(!ok)++failures;wsprintfA(row,"{\"profile_case\":\"%s\",\"status\":\"%s\",\"error\":%lu}\r\n",name,ok?"pass":"fail",ok?0:error);WriteFile(serial,row,lstrlenA(row),&n,NULL);}
static BOOL privilege(HANDLE token,const WCHAR *name){TOKEN_PRIVILEGES p={0};p.PrivilegeCount=1;p.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;if(!LookupPrivilegeValueW(NULL,name,&p.Privileges[0].Luid))return FALSE;SetLastError(0);return AdjustTokenPrivileges(token,FALSE,&p,0,NULL,NULL)&&GetLastError()==0;}
void WINAPI ProbeMain(void){
 const WCHAR user[]=L"XP25ProfileFixture",password[]=L"XP25-Profile-Fixture-2026!x";USER_INFO_1 info={0};LPBYTE unused=NULL;NET_API_STATUS result;HANDLE token=NULL,self=NULL;PROFILEINFOW profile={0};BOOL account=FALSE,loaded=FALSE,ok;DWORD n,size=0,error=0,value=25,read=0,type;BYTE buffer[2048];LPWSTR sid=NULL;HKEY key=NULL,root=NULL;HMODULE module;WCHAR path[MAX_PATH];
 typedef BOOL(WINAPI *LOAD)(HANDLE,LPPROFILEINFOW);typedef BOOL(WINAPI *UNLOAD)(HANDLE,HANDLE);typedef BOOL(WINAPI *PATH)(HANDLE,LPWSTR,LPDWORD);typedef BOOL(WINAPI *PROFILEDELETE)(LPCWSTR,LPCWSTR,LPCWSTR);LOAD load;UNLOAD unload;PATH getpath;PROFILEDELETE remove;
 serial=CreateFileA("COM1",GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);if(serial==INVALID_HANDLE_VALUE)ExitProcess(90);WriteFile(serial,"PROFILE_PROBE_STARTED\r\n",23,&n,NULL);
 module=LoadLibraryA("userenv.dll");load=(LOAD)GetProcAddress(module,"LoadUserProfileW");unload=(UNLOAD)GetProcAddress(module,"UnloadUserProfile");getpath=(PATH)GetProcAddress(module,"GetUserProfileDirectoryW");remove=(PROFILEDELETE)GetProcAddress(module,"DeleteProfileW");
 report("profile_api_access",module&&load&&unload&&getpath&&remove,GetLastError());if(failures)goto done;
 ok=OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY|TOKEN_ADJUST_PRIVILEGES,&self)&&privilege(self,L"SeBackupPrivilege")&&privilege(self,L"SeRestorePrivilege");report("existing_profile_privileges_enabled",ok,GetLastError());if(self)CloseHandle(self);if(!ok)goto done;
 result=NetUserGetInfo(NULL,user,0,&unused);if(unused)NetApiBufferFree(unused);report("fixture_account_unused",result==NERR_UserNotFound,result);if(result!=NERR_UserNotFound)goto done;
 info.usri1_name=(LPWSTR)user;info.usri1_password=(LPWSTR)password;info.usri1_priv=USER_PRIV_USER;info.usri1_flags=UF_SCRIPT|UF_NORMAL_ACCOUNT|UF_DONT_EXPIRE_PASSWD;result=NetUserAdd(NULL,1,(LPBYTE)&info,&error);account=result==0;report("fixture_account_created",account,result);if(!account)goto done;
 ok=LogonUserW(user,L".",password,LOGON32_LOGON_INTERACTIVE,LOGON32_PROVIDER_DEFAULT,&token);report("fixture_authentication",ok,GetLastError());if(!ok)goto cleanup;
 ok=GetTokenInformation(token,TokenUser,buffer,sizeof(buffer),&size)&&ConvertSidToStringSidW(((TOKEN_USER*)buffer)->User.Sid,&sid);report("fixture_token_sid",ok,GetLastError());if(!ok)goto cleanup;
 profile.dwSize=sizeof(profile);profile.dwFlags=PI_NOUI;profile.lpUserName=(LPWSTR)user;loaded=load(token,&profile);report("new_profile_initialized",loaded&&profile.hProfile,GetLastError());if(!loaded)goto cleanup;
 size=MAX_PATH;ok=getpath(token,path,&size)&&lstrlenW(path)>0;report("new_profile_path",ok,GetLastError());
 ok=RegOpenKeyExW(HKEY_USERS,sid,0,KEY_READ,&root)==0;report("new_profile_hive_mounted",ok,GetLastError());if(root)RegCloseKey(root);
 ok=RegCreateKeyExW((HKEY)profile.hProfile,L"Software\\XP25ProfileFixture",0,NULL,0,KEY_READ|KEY_WRITE,NULL,&key,NULL)==0&&RegSetValueExW(key,L"Value",0,REG_DWORD,(BYTE*)&value,4)==0;size=4;ok=ok&&RegQueryValueExW(key,L"Value",NULL,&type,(BYTE*)&read,&size)==0&&read==25;report("new_profile_registry_roundtrip",ok,GetLastError());if(key)RegCloseKey(key);RegDeleteKeyW((HKEY)profile.hProfile,L"Software\\XP25ProfileFixture");
 ok=unload(token,profile.hProfile);report("new_profile_unloaded",ok,GetLastError());if(ok)loaded=FALSE;
 cleanup:if(loaded){ok=unload(token,profile.hProfile);if(ok)loaded=FALSE;}
 if(sid&&!loaded)report("new_profile_deleted",remove(sid,NULL,NULL),GetLastError());
 if(token){CloseHandle(token);}if(sid){LocalFree(sid);}if(account){result=NetUserDel(NULL,user);report("fixture_account_deleted",result==0,result);}
 done:if(module)FreeLibrary(module);report("profile_probe_complete",failures==0,failures);CloseHandle(serial);ExitProcess(failures?1:0);
}
