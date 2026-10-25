/* Ordinary-process tests. Never registers as Winlogon and never creates a
   logon, activation result, privileged token, or replacement shell. */
#define WINVER 0x0501
#define _WIN32_WINNT 0x0501
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <userenv.h>
#include <stdio.h>
#include <wchar.h>
int wl_session_tests(void);
static unsigned failures;
static void report(const char *name,BOOL ok)
{printf("{\"session_control\":\"%s\",\"passed\":%s,\"error\":%lu}\n",name,ok?"true":"false",ok?0:GetLastError());if(!ok)++failures;}
int __cdecl main(void)
{
    HANDLE own=NULL,process=NULL,shell=NULL,file=INVALID_HANDLE_VALUE;DWORD pid=0,bytes=0,session=~0u,shell_session=~0u;
    TOKEN_STATISTICS a,b;HWND window,tray;PVOID env=NULL;BOOL ok;WCHAR path[MAX_PATH],profile[MAX_PATH],current[MAX_PATH];
    DWORD chars=MAX_PATH,wrote,got;char payload[]="XP25 native session contract control",data[sizeof(payload)];HKEY key=NULL;
    DWORD disposition=0,value=0x2505,back=0,type=0,length=sizeof(back);LONG error;WCHAR regname[128];
    ZeroMemory(current,sizeof(current));
    ZeroMemory(&a,sizeof(a));ZeroMemory(&b,sizeof(b));
    if(wl_session_tests())++failures;
    ok=OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&own)&&
        GetTokenInformation(own,TokenStatistics,&a,sizeof(a),&bytes)&&
        GetTokenInformation(own,TokenSessionId,&session,sizeof(session),&bytes);
    report("current_authenticated_token",ok);
    window=GetShellWindow();if(window)GetWindowThreadProcessId(window,&pid);
    process=pid?OpenProcess(PROCESS_QUERY_INFORMATION,FALSE,pid):NULL;
    ok=ok&&process&&OpenProcessToken(process,TOKEN_QUERY,&shell)&&
        GetTokenInformation(shell,TokenStatistics,&b,sizeof(b),&bytes)&&
        GetTokenInformation(shell,TokenSessionId,&shell_session,sizeof(shell_session),&bytes)&&
        a.AuthenticationId.LowPart==b.AuthenticationId.LowPart&&a.AuthenticationId.HighPart==b.AuthenticationId.HighPart&&
        session==shell_session&&b.TokenType==TokenPrimary;
    report("existing_explorer_logon_identity",ok);printf("{\"explorer_pid\":%lu,\"session\":%lu}\n",pid,session);
    tray=FindWindowW(L"Shell_TrayWnd",NULL);report("existing_taskbar_visible",tray&&IsWindowVisible(tray));
    ok=own&&GetUserProfileDirectoryW(own,profile,&chars)&&GetEnvironmentVariableW(L"USERPROFILE",current,MAX_PATH)&&!lstrcmpiW(profile,current);
    report("existing_profile_directory",ok);
    ok=own&&CreateEnvironmentBlock(&env,own,FALSE);report("private_user_environment_created",ok);
    if(env){ok=DestroyEnvironmentBlock(env);report("private_user_environment_released",ok);}
    ok=GetEnvironmentVariableW(L"USERPROFILE",path,MAX_PATH)&&!lstrcmpW(path,current);report("caller_environment_unchanged",ok);
    ZeroMemory(path,sizeof(path));
    ok=GetTempPathW(MAX_PATH,profile)&&GetTempFileNameW(profile,L"W25",0,path);
    if(ok)file=CreateFileW(path,GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_TEMPORARY,NULL);
    ok=ok&&file!=INVALID_HANDLE_VALUE&&WriteFile(file,payload,sizeof(payload),&wrote,NULL)&&wrote==sizeof(payload)&&
        SetFilePointer(file,0,NULL,FILE_BEGIN)!=INVALID_SET_FILE_POINTER&&ReadFile(file,data,sizeof(data),&got,NULL)&&
        got==sizeof(payload)&&!memcmp(data,payload,sizeof(data));
    if(file!=INVALID_HANDLE_VALUE)CloseHandle(file);if(path[0])ok=DeleteFileW(path)&&ok;report("current_user_file_roundtrip",ok);
    wsprintfW(regname,L"Software\\XP25SessionContract%lu",GetCurrentProcessId());
    error=RegCreateKeyExW(HKEY_CURRENT_USER,regname,0,NULL,REG_OPTION_VOLATILE,KEY_QUERY_VALUE|KEY_SET_VALUE,NULL,&key,&disposition);
    if(!error&&disposition!=REG_CREATED_NEW_KEY)error=ERROR_ALREADY_EXISTS;
    if(!error)error=RegSetValueExW(key,L"Roundtrip",0,REG_DWORD,(BYTE*)&value,sizeof(value));
    if(!error)error=RegQueryValueExW(key,L"Roundtrip",NULL,&type,(BYTE*)&back,&length);
    if(key)RegCloseKey(key);
    ok=!error&&type==REG_DWORD&&length==sizeof(back)&&back==value;
    if(disposition==REG_CREATED_NEW_KEY)ok=RegDeleteKeyW(HKEY_CURRENT_USER,regname)==0&&ok;
    SetLastError(error);report("current_user_registry_roundtrip",ok);
    if(shell)CloseHandle(shell);if(process)CloseHandle(process);if(own)CloseHandle(own);
    printf("XP25_SESSION_NATIVE_CONTROL failures=%u\n",failures);return failures?1:0;
}
