/* XP25 original secure desktop and token validation implementation. */
#include "platform.h"

typedef BOOL (WINAPI *REGISTER_LOGON)(DWORD,BOOL);
typedef BOOL (WINAPI *SET_STATION_USER)(HWINSTA,PLUID,PSID,DWORD);

BOOL wl_privilege(LPCWSTR name)
{
    HANDLE token; TOKEN_PRIVILEGES p; BOOL ok;DWORD id=0;
    /* NT 5.1 ntseapi.h privilege LUIDs. LookupPrivilegeValue needs LSASS RPC,
       which does not exist yet when the boot logon process enables TCB. */
    if(lstrcmpW(name,SE_TCB_NAME)==0)id=7;
    else if(lstrcmpW(name,SE_ASSIGNPRIMARYTOKEN_NAME)==0)id=3;
    else if(lstrcmpW(name,SE_INCREASE_QUOTA_NAME)==0)id=5;
    else if(lstrcmpW(name,SE_BACKUP_NAME)==0)id=17;
    else if(lstrcmpW(name,SE_RESTORE_NAME)==0)id=18;
    else if(lstrcmpW(name,SE_SHUTDOWN_NAME)==0)id=19;
    else {SetLastError(ERROR_NO_SUCH_PRIVILEGE);return FALSE;}
    if (!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&token)) return FALSE;
    ZeroMemory(&p,sizeof(p));p.PrivilegeCount=1;p.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
    p.Privileges[0].Luid.LowPart=id;p.Privileges[0].Luid.HighPart=0;
    SetLastError(0);ok=AdjustTokenPrivileges(token,FALSE,&p,0,NULL,NULL)&&GetLastError()==0;
    CloseHandle(token);return ok;
}

static BOOL object_dacl(HANDLE object,LPCWSTR sddl)
{
    PSECURITY_DESCRIPTOR descriptor=NULL; SECURITY_INFORMATION info=DACL_SECURITY_INFORMATION; BOOL ok;
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,SDDL_REVISION_1,&descriptor,NULL))return FALSE;
    ok=SetUserObjectSecurity(object,&info,descriptor);LocalFree(descriptor);return ok;
}

BOOL wl_security_init(void)
{
    HMODULE user=GetModuleHandleW(L"user32.dll");REGISTER_LOGON reg;
    SECURITY_ATTRIBUTES attributes;PSECURITY_DESCRIPTOR descriptor=NULL;HANDLE self;TOKEN_USER *u;DWORD bytes=0;BOOL system;
    if(!wl_privilege(SE_TCB_NAME)||!wl_privilege(SE_ASSIGNPRIMARYTOKEN_NAME)||
       !wl_privilege(SE_INCREASE_QUOTA_NAME)||!wl_privilege(SE_BACKUP_NAME)||
       !wl_privilege(SE_RESTORE_NAME)||!wl_privilege(SE_SHUTDOWN_NAME))return FALSE;
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&self))return FALSE;
    GetTokenInformation(self,TokenUser,NULL,0,&bytes);u=LocalAlloc(LPTR,bytes);
    if(!u){CloseHandle(self);return FALSE;}
    system=GetTokenInformation(self,TokenUser,u,bytes,&bytes)&&IsWellKnownSid(u->User.Sid,WinLocalSystemSid);
    LocalFree(u);CloseHandle(self);
    if(!system){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
    reg=(REGISTER_LOGON)GetProcAddress(user,"RegisterLogonProcess");
    if(!reg){SetLastError(ERROR_PROC_NOT_FOUND);return FALSE;}
    if(!reg(GetCurrentProcessId(),TRUE))return FALSE;
    wl_log("user_logon_registered",0);
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)(A;;RC;;;BA)",1,&descriptor,NULL))return FALSE;
    attributes.nLength=sizeof(attributes);attributes.lpSecurityDescriptor=descriptor;attributes.bInheritHandle=FALSE;
    wl.station=CreateWindowStationW(L"WinSta0",0,WL_WINSTA_ACCESS,&attributes);
    if(!wl.station){LocalFree(descriptor);return FALSE;}
    if(!SetProcessWindowStation(wl.station)){LocalFree(descriptor);return FALSE;}
    wl.secure=CreateDesktopW(L"Winlogon",NULL,NULL,0,WL_DESKTOP_ACCESS,&attributes);
    wl.application=CreateDesktopW(L"Default",NULL,NULL,0,WL_DESKTOP_ACCESS,&attributes);
    LocalFree(descriptor);
    if(!wl.secure||!wl.application)return FALSE;
    if(!object_dacl(wl.secure,L"D:P(A;;GA;;;SY)(A;;RC;;;BA)")||
       !object_dacl(wl.application,L"D:P(A;;GA;;;SY)(A;;RC;;;BA)")||
       !object_dacl(wl.station,L"D:P(A;;GA;;;SY)(A;;RC;;;BA)"))return FALSE;
    if(!SetThreadDesktop(wl.secure)||!SwitchDesktop(wl.secure))return FALSE;
    wl_log("secure_desktop_created",0);return TRUE;
}

BOOL wl_switch_secure(void)
{
    UINT (WINAPI *lock)(HWINSTA);UINT result;
    lock=(UINT (WINAPI*)(HWINSTA))GetProcAddress(GetModuleHandleW(L"user32.dll"),"LockWindowStation");
    if(!lock){SetLastError(ERROR_PROC_NOT_FOUND);return FALSE;}
    if(!SwitchDesktop(wl.secure))return FALSE;
    result=(UINT)lock(wl.station);return result!=0;
}

BOOL wl_switch_user(void)
{
    BOOL (WINAPI *unlock)(HWINSTA);
    if(!wl.token||!wl.profile){SetLastError(ERROR_INVALID_FUNCTION);return FALSE;}
    unlock=(BOOL(WINAPI*)(HWINSTA))GetProcAddress(GetModuleHandleW(L"user32.dll"),"UnlockWindowStation");
    if(!unlock){SetLastError(ERROR_PROC_NOT_FOUND);return FALSE;}
    return unlock(wl.station)&&SwitchDesktop(wl.application);
}

BOOL wl_check_token(HANDLE token,const LUID *id,PSID sid)
{
    TOKEN_STATISTICS stats;DWORD bytes,session,i;TOKEN_GROUPS *groups;TOKEN_USER *user;BOOL found=FALSE,system;
    if(!token||!id||!IsValidSid(sid)){SetLastError(ERROR_INVALID_PARAMETER);return FALSE;}
    if(!GetTokenInformation(token,TokenStatistics,&stats,sizeof(stats),&bytes)||stats.TokenType!=TokenPrimary||
       stats.AuthenticationId.LowPart!=id->LowPart||stats.AuthenticationId.HighPart!=id->HighPart){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
    if(!GetTokenInformation(token,TokenSessionId,&session,sizeof(session),&bytes)||session!=wl.session_id){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
    GetTokenInformation(token,TokenUser,NULL,0,&bytes);user=LocalAlloc(LPTR,bytes);if(!user)return FALSE;
    if(!GetTokenInformation(token,TokenUser,user,bytes,&bytes)){LocalFree(user);return FALSE;}
    system=IsWellKnownSid(user->User.Sid,WinLocalSystemSid);LocalFree(user);
    if(system){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
    GetTokenInformation(token,TokenGroups,NULL,0,&bytes);groups=LocalAlloc(LPTR,bytes);if(!groups)return FALSE;
    if(GetTokenInformation(token,TokenGroups,groups,bytes,&bytes))for(i=0;i<groups->GroupCount;++i)
        if((groups->Groups[i].Attributes&SE_GROUP_LOGON_ID)==SE_GROUP_LOGON_ID&&EqualSid(groups->Groups[i].Sid,sid))found=TRUE;
    LocalFree(groups);if(!found)SetLastError(ERROR_INVALID_SID);return found;
}

BOOL wl_apply_user_security(HANDLE token)
{
    LPWSTR sid=NULL;WCHAR dacl[512];SET_STATION_USER assign;BOOL ok;DWORD bytes=0;TOKEN_USER *user;
    if(!wl_check_token(token,&wl.authentication_id,wl.logon_sid))return FALSE;
    if(!ConvertSidToStringSidW(wl.logon_sid,&sid))return FALSE;
    if(lstrlenW(sid)>184){LocalFree(sid);SetLastError(ERROR_BUFFER_OVERFLOW);return FALSE;}
    wsprintfW(dacl,L"D:P(A;;GA;;;SY)(A;;RC;;;BA)(A;;GA;;;%s)",sid);LocalFree(sid);
    if(!object_dacl(wl.application,dacl)||!object_dacl(wl.station,dacl))return FALSE;
    assign=(SET_STATION_USER)GetProcAddress(GetModuleHandleW(L"user32.dll"),"SetWindowStationUser");
    if(!assign){SetLastError(ERROR_PROC_NOT_FOUND);return FALSE;}
    GetTokenInformation(token,TokenUser,NULL,0,&bytes);user=LocalAlloc(LPTR,bytes);if(!user)return FALSE;
    ok=GetTokenInformation(token,TokenUser,user,bytes,&bytes)&&assign(wl.station,&wl.authentication_id,user->User.Sid,GetLengthSid(user->User.Sid));
    LocalFree(user);return ok;
}

BOOL wl_clear_user_security(void)
{
    SET_STATION_USER assign;LUID none;
    if(!object_dacl(wl.application,L"D:P(A;;GA;;;SY)(A;;RC;;;BA)")||
       !object_dacl(wl.station,L"D:P(A;;GA;;;SY)(A;;RC;;;BA)"))return FALSE;
    assign=(SET_STATION_USER)GetProcAddress(GetModuleHandleW(L"user32.dll"),"SetWindowStationUser");
    if(!assign){SetLastError(ERROR_PROC_NOT_FOUND);return FALSE;}
    ZeroMemory(&none,sizeof(none));
    /* Supplied NT 5.1 _SetWindowStationUser explicitly accepts a NULL SID
       and clears the previous station SID before assigning the zero LUID. */
    return assign(wl.station,&none,NULL,0);
}

BOOL wl_per_user_parameters(HANDLE token,BOOL logged_on)
{
    BOOL (WINAPI *update)(HANDLE,DWORD);
    update=(BOOL(WINAPI*)(HANDLE,DWORD))GetProcAddress(GetModuleHandleW(L"user32.dll"),"UpdatePerUserSystemParameters");
    if(!update){SetLastError(ERROR_PROC_NOT_FOUND);return FALSE;}
    return update(token,logged_on?1:0); /* UPUSP_USERLOGGEDON */
}

typedef struct {DWORD pid,error;} WL_SHELL_CHECK;

static DWORD WINAPI check_shell_desktop(PVOID parameter)
{
    WL_SHELL_CHECK *check=parameter;HWND window;HANDLE process,token,snapshot;
    MODULEENTRY32W module;DWORD pid,again,transient=0,started=GetTickCount();WCHAR expected[MAX_PATH];BOOL valid;
    if(!SetThreadDesktop(wl.application)){check->error=GetLastError();return 1;}
    if(!GetWindowsDirectoryW(expected,MAX_PATH)||lstrlenW(expected)+14>=MAX_PATH){
        check->error=ERROR_BUFFER_OVERFLOW;return 1;
    }
    lstrcatW(expected,L"\\explorer.exe");
    do{
        window=GetShellWindow();pid=0;
        if(window&&GetWindowThreadProcessId(window,&pid)&&pid){
            process=OpenProcess(PROCESS_QUERY_INFORMATION|SYNCHRONIZE,FALSE,pid);
            if(!process){check->error=GetLastError();return 1;}
            /* After a shell exit USER can still report the dead shell's window
               until CSR cleanup completes; that is not yet the new shell. */
            if(WaitForSingleObject(process,0)==WAIT_OBJECT_0){CloseHandle(process);Sleep(100);continue;}
            token=NULL;valid=OpenProcessToken(process,TOKEN_QUERY,&token)&&
                wl_check_token(token,&wl.authentication_id,wl.logon_sid);
            if(!valid){check->error=GetLastError();if(token)CloseHandle(token);CloseHandle(process);return 1;}
            CloseHandle(token);snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,pid);
            /* The module query runs a thread in the target; a starting shell can
               transiently refuse it. Identity failures above remain fatal. */
            if(snapshot==INVALID_HANDLE_VALUE){transient=GetLastError();CloseHandle(process);Sleep(250);continue;}
            ZeroMemory(&module,sizeof(module));module.dwSize=sizeof(module);
            valid=Module32FirstW(snapshot,&module);
            if(!valid)check->error=GetLastError();
            else if(lstrcmpiW(module.szExePath,expected)){valid=FALSE;check->error=ERROR_ACCESS_DENIED;}
            CloseHandle(snapshot);again=0;
            if(valid&&(GetShellWindow()!=window||!GetWindowThreadProcessId(window,&again)||again!=pid||
               WaitForSingleObject(process,0)!=WAIT_TIMEOUT)){valid=FALSE;check->error=ERROR_PROCESS_ABORTED;}
            CloseHandle(process);if(!valid)return 1;
            check->pid=pid;return 0;
        }
        Sleep(100);
    }while(GetTickCount()-started<120000);
    check->error=transient?transient:ERROR_TIMEOUT;return 1;
}

BOOL wl_wait_user_shell(DWORD *pid)
{
    WL_SHELL_CHECK *check;HANDLE thread;DWORD result,error;
    if(!pid||!wl.token||!wl.profile){SetLastError(ERROR_INVALID_PARAMETER);return FALSE;}
    *pid=0;check=LocalAlloc(LPTR,sizeof(*check));if(!check)return FALSE;
    thread=CreateThread(NULL,0,check_shell_desktop,check,0,NULL);
    if(!thread){error=GetLastError();LocalFree(check);SetLastError(error);return FALSE;}
    result=WaitForSingleObject(thread,150000);
    /* A hung worker still references the authenticated context. Retain it;
       never return to profile/token cleanup with that thread still running. */
    if(result!=WAIT_OBJECT_0)wl_fail("shell_identity_worker_wait_failed",result==WAIT_TIMEOUT?ERROR_TIMEOUT:GetLastError());
    error=check->error;*pid=check->pid;CloseHandle(thread);LocalFree(check);
    if(!*pid){SetLastError(error?error:ERROR_INVALID_DATA);return FALSE;}
    wl_log("explorer_token_identity_verified",*pid);return TRUE;
}
