/* Separate native harness: real private desktops/profile references/children,
   explicit GINA/policy/notification/power doubles. Never a Winlogon host. */
#ifndef XP25_SESSION_TEST
#error Private session harness cannot enter a production build
#endif
#define WINVER 0x0501
#define _WIN32_WINNT 0x0501
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <userenv.h>
#include <sddl.h>
#include <stdio.h>
#include <wchar.h>
#include <string.h>
#include "session_engine.h"
#include "session_native.h"
typedef struct {USHORT length,maximum;PWSTR text;} TEST_STRING;
typedef LONG (NTAPI *SET_ENV)(PVOID*,TEST_STRING*,TEST_STRING*);
typedef struct {
    WL_MACHINE machine;WL_SESSION_ENGINE engine;
    HANDLE reference,token,watch;PROFILEINFOW profile;PVOID environment;
    HDESK original,secure,user;WCHAR secure_name[80],user_name[80],desktop[96];
    WCHAR image[MAX_PATH],fixture_image[MAX_PATH],child_file[MAX_PATH];
    PROCESS_INFORMATION child;DWORD activation_fault,desktop_fault;
    unsigned copies,transfers,activations,ends,releases,notices[7];
    BOOL explorer;
} RUNTIME;
static unsigned checks,failures;
static void check(const char *name,BOOL ok)
{++checks;if(!ok)++failures;printf("{\"native_session\":\"%s\",\"passed\":%s,\"error\":%lu}\n",name,ok?"true":"false",ok?0:GetLastError());fflush(stdout);}
static DWORD error(BOOL ok){DWORD e;if(ok)return 0;e=GetLastError();return e?e:ERROR_GEN_FAILURE;}
static BOOL bound_is(LPCWSTR expected)
{
    HDESK input;WCHAR name[80];DWORD bytes;BOOL ok;
    input=GetThreadDesktop(GetCurrentThreadId());if(!input)return FALSE;
    ok=GetUserObjectInformationW(input,UOI_NAME,name,sizeof(name),&bytes)&&!lstrcmpW(name,expected);
    if(!ok)SetLastError(ERROR_INVALID_DATA);return ok;
}
static DWORD user(void *p)
{RUNTIME *r=p;return error(r->token&&wl_same_logon(r->reference,r->token));}
static DWORD profile(void *p)
{
    RUNTIME *r=p;WCHAR username[256];DWORD n=256;SET_ENV set;TEST_STRING key,value;
    if(!GetUserNameW(username,&n))return GetLastError();
    ZeroMemory(&r->profile,sizeof(r->profile));r->profile.dwSize=sizeof(r->profile);r->profile.dwFlags=PI_NOUI;r->profile.lpUserName=username;
    if(!LoadUserProfileW(r->token,&r->profile))return GetLastError();
    r->profile.lpUserName=NULL;
    if(!CreateEnvironmentBlock(&r->environment,r->token,FALSE))return GetLastError();
    set=(SET_ENV)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"RtlSetEnvironmentVariable");if(!set)return ERROR_PROC_NOT_FOUND;
    key.text=L"XP25_SESSION_CHILD_RESULT";key.length=(USHORT)(lstrlenW(key.text)*2);key.maximum=key.length+2;
    value.text=r->child_file;value.length=(USHORT)(lstrlenW(value.text)*2);value.maximum=value.length+2;
    if(set(&r->environment,&key,&value)<0)return ERROR_INVALID_DATA;
    return 0;
}
static void policy(void *p,WL_POLICY_RESULT *out)
{UNREFERENCED_PARAMETER(p);out->version=1;out->decision=WlPolicyAllowed;out->verified=WL_POLICY_REQUIRED;out->error=0;}
static DWORD copy(void *p,void **out)
{RUNTIME *r=p;*out=wl_copy_user_environment(r->environment);if(*out)++r->copies;return error(*out!=NULL);}
static DWORD discard(void *p,void *block)
{UNREFERENCED_PARAMETER(p);return error(VirtualFree(block,0,MEM_RELEASE));}
static DWORD secure(void *p)
{RUNTIME *r=p;return error(SetThreadDesktop(r->secure)&&bound_is(r->secure_name));}
static DWORD protect(void *p)
{
    RUNTIME *r=p;TOKEN_GROUPS *groups;DWORD bytes=0,i;LPWSTR sid=NULL;WCHAR sddl[256];PSECURITY_DESCRIPTOR sd=NULL;BOOL ok=FALSE;
    GetTokenInformation(r->token,TokenGroups,NULL,0,&bytes);groups=LocalAlloc(LPTR,bytes);if(!groups)return ERROR_NOT_ENOUGH_MEMORY;
    if(GetTokenInformation(r->token,TokenGroups,groups,bytes,&bytes))for(i=0;i<groups->GroupCount;++i)
        if((groups->Groups[i].Attributes&SE_GROUP_LOGON_ID)==SE_GROUP_LOGON_ID){ok=ConvertSidToStringSidW(groups->Groups[i].Sid,&sid);break;}
    if(ok){wsprintfW(sddl,L"D:P(A;;GA;;;SY)(A;;RC;;;BA)(A;;GA;;;%s)",sid);ok=ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,1,&sd,NULL);}
    if(ok){SECURITY_INFORMATION info=DACL_SECURITY_INFORMATION;ok=SetUserObjectSecurity(r->user,&info,sd);}
    if(sd)LocalFree(sd);if(sid)LocalFree(sid);LocalFree(groups);return error(ok);
}
static DWORD activate(void *p,void *block)
{
    RUNTIME *r=p;WCHAR command[2*MAX_PATH];DWORD e=0;BOOL ok=FALSE;++r->activations;++r->transfers;
    check("controlled_activation_on_bound_secure_desktop",bound_is(r->secure_name));
    if(r->activation_fault==1)e=ERROR_ACCESS_DENIED;
    else{
        DeleteFileW(r->child_file);wsprintfW(command,r->explorer?L"\"%s\"":L"\"%s\" --fixture",r->image);
        ok=wl_spawn_user_process(r->token,r->image,command,r->desktop,block,&r->child);if(!ok)e=GetLastError();
        if(ok&&r->activation_fault==2)e=ERROR_GEN_FAILURE;
    }
    if(!VirtualFree(block,0,MEM_RELEASE)&&!e)e=GetLastError();
    return e;
}
typedef struct {RUNTIME *r;DWORD error;} FIND;
static DWORD WINAPI find_shell(void *p)
{
    FIND *f=p;RUNTIME *r=f->r;DWORD start=GetTickCount(),pid=0;HWND window,tray;
    if(!SetThreadDesktop(r->user)){f->error=GetLastError();return 1;}
    do{
        window=r->explorer?GetShellWindow():FindWindowW(L"XP25SessionFixture",NULL);
        if(window){GetWindowThreadProcessId(window,&pid);tray=FindWindowW(L"Shell_TrayWnd",NULL);
            if(pid==r->child.dwProcessId&&(!r->explorer||(tray&&IsWindowVisible(tray))))return 0;}
        if(WaitForSingleObject(r->child.hProcess,0)==WAIT_OBJECT_0){f->error=ERROR_PROCESS_ABORTED;return 1;}
        Sleep(100);
    }while(GetTickCount()-start<30000);
    f->error=ERROR_TIMEOUT;return 1;
}
static DWORD identity(void *p)
{
    RUNTIME *r=p;FIND find;HANDLE thread,next=NULL;DWORD status,e=0;char data[300];HANDLE file;DWORD n;
    find.r=r;find.error=0;thread=CreateThread(NULL,0,find_shell,&find,0,NULL);if(!thread)return GetLastError();
    status=WaitForSingleObject(thread,35000);if(status!=WAIT_OBJECT_0){printf("FATAL private desktop worker did not finish\n");ExitProcess(99);}
    CloseHandle(thread);if(find.error)return find.error;
    if(!wl_watch_user_process(r->token,r->child.dwProcessId,r->image,&next))return GetLastError();
    if(r->watch){e=wl_user_process_exited(r->watch);if(!e){CloseHandle(r->watch);r->watch=NULL;}}
    if(e){CloseHandle(next);return e;}r->watch=next;
    if(!r->explorer){
        ZeroMemory(data,sizeof(data));file=CreateFileW(r->child_file,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
        if(file==INVALID_HANDLE_VALUE)return GetLastError();
        if(!ReadFile(file,data,sizeof(data)-1,&n,NULL))e=GetLastError();CloseHandle(file);
        if(!e&&(!strstr(data,"XP25_CHILD_ENVIRONMENT_OK")||!strstr(data,"desktop=XP25SessionUser")))e=ERROR_INVALID_DATA;
    }
    printf("{\"private_shell_pid\":%lu,\"explorer\":%s,\"generation\":%lu}\n",r->child.dwProcessId,r->explorer?"true":"false",r->machine.generation);fflush(stdout);
    return e;
}
static DWORD desktop(void *p)
{RUNTIME *r=p;if(r->desktop_fault)return r->desktop_fault;return error(SetThreadDesktop(r->user)&&bound_is(r->user_name));}
static DWORD notify(void *p,WL_SESSION_NOTICE event)
{RUNTIME *r=p;++r->notices[event];printf("{\"controlled_notification\":%u}\n",(unsigned)event);return 0;}
static DWORD end(void *p)
{
    RUNTIME *r=p;DWORD e;++r->ends;
    if(r->child.hProcess){
        if(WaitForSingleObject(r->child.hProcess,0)==WAIT_TIMEOUT){
            if(!PostThreadMessageW(r->child.dwThreadId,WM_QUIT,0,0))return GetLastError();
            if(WaitForSingleObject(r->child.hProcess,10000)!=WAIT_OBJECT_0)return ERROR_BUSY;
        }
        e=wl_user_process_exited(r->child.hProcess);if(e)return e;
        CloseHandle(r->child.hThread);CloseHandle(r->child.hProcess);ZeroMemory(&r->child,sizeof(r->child));
    }
    return 0;
}
static DWORD release(void *p)
{
    RUNTIME *r=p;++r->releases;
    if(r->watch){DWORD e=wl_user_process_exited(r->watch);if(e)return e;CloseHandle(r->watch);r->watch=NULL;}
    if(r->environment){if(!DestroyEnvironmentBlock(r->environment))return GetLastError();r->environment=NULL;}
    if(r->profile.hProfile){if(!UnloadUserProfile(r->token,r->profile.hProfile))return GetLastError();r->profile.hProfile=NULL;}
    if(r->token){CloseHandle(r->token);r->token=NULL;}DeleteFileW(r->child_file);return 0;
}
static DWORD power(void *p,unsigned mode)
{UNREFERENCED_PARAMETER(p);printf("{\"controlled_power_request\":%u,\"host_shutdown_requested\":false}\n",mode);return 0;}
static DWORD exited(void *p){RUNTIME *r=p;return wl_user_process_exited(r->watch);}
static DWORD restart(void *p,void *block)
{
    RUNTIME *r=p;
    if(r->child.hProcess){CloseHandle(r->child.hThread);CloseHandle(r->child.hProcess);ZeroMemory(&r->child,sizeof(r->child));}
    return activate(p,block);
}
static const WL_SESSION_DRIVER driver={user,profile,policy,copy,discard,secure,protect,activate,identity,desktop,notify,end,release,power,exited,restart};
static BOOL begin(RUNTIME *r)
{
    DWORD status;BOOL ok;
    /* Documented CreateProcessAsUser exemption: a restricted copy of our own
       authenticated primary token needs no SeAssignPrimaryToken privilege. */
    ok=CreateRestrictedToken(r->reference,DISABLE_MAX_PRIVILEGE,0,NULL,0,NULL,0,NULL,&r->token);
    check("restricted_existing_authenticated_token",ok);if(!ok)return FALSE;
    ok=wl_same_logon(r->reference,r->token);check("restricted_token_logon_identity",ok);if(!ok)return FALSE;
    status=secure(r);SetLastError(status);check("private_secure_thread_transition",status==0);if(status)return FALSE;
    ok=wl_state_step(&r->machine,WlAttention,WL_SECURE_ACTIVE);check("private_attention_transition",ok);if(!ok)return FALSE;
    ok=wl_state_step(&r->machine,WlAuthenticated,WL_TOKEN_CHECKED);check("existing_token_model_transition",ok);if(!ok)return FALSE;
    wl_engine_bind(&r->engine,&r->machine,&driver,r);return TRUE;
}
static BOOL crash(RUNTIME *r)
{return r->child.hProcess&&TerminateProcess(r->child.hProcess,0x2505)&&WaitForSingleObject(r->child.hProcess,10000)==WAIT_OBJECT_0;}
static BOOL denied_switch(LPCWSTR name,HANDLE restricted)
{
    HDESK d;DWORD e;if(!ImpersonateLoggedOnUser(restricted))return FALSE;
    d=OpenDesktopW(name,0,FALSE,DESKTOP_SWITCHDESKTOP);e=GetLastError();
    if(!RevertToSelf())ExitProcess(98);if(d)CloseDesktop(d);
    return !d&&e==ERROR_ACCESS_DENIED;
}
static BOOL privilege(HANDLE token,LPCWSTR name,TOKEN_PRIVILEGES *old)
{
    TOKEN_PRIVILEGES p;DWORD bytes=sizeof(*old);ZeroMemory(&p,sizeof(p));p.PrivilegeCount=1;p.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
    if(!LookupPrivilegeValueW(NULL,name,&p.Privileges[0].Luid))return FALSE;
    SetLastError(0);return AdjustTokenPrivileges(token,FALSE,&p,sizeof(*old),old,&bytes)&&GetLastError()==0;
}
int wl_session_runtime_tests(void)
{
    RUNTIME r;TOKEN_PRIVILEGES backup,restore;HANDLE restricted=NULL,unexpected=NULL;DWORD pid=GetCurrentProcessId();
    PSECURITY_DESCRIPTOR sd=NULL;BOOL backup_set=FALSE,restore_set=FALSE;unsigned i;
    ZeroMemory(&r,sizeof(r));ZeroMemory(&backup,sizeof(backup));ZeroMemory(&restore,sizeof(restore));checks=failures=0;
    r.original=OpenDesktopW(L"Default",0,FALSE,DESKTOP_SWITCHDESKTOP|DESKTOP_READOBJECTS|DESKTOP_WRITEOBJECTS);if(!r.original)goto fail;
    /* Restricted token handles inherit the original handle's access mask. */
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY|TOKEN_DUPLICATE|TOKEN_ASSIGN_PRIMARY|TOKEN_ADJUST_PRIVILEGES,&r.reference))goto fail;
    backup_set=privilege(r.reference,SE_BACKUP_NAME,&backup);restore_set=privilege(r.reference,SE_RESTORE_NAME,&restore);
    if(!backup_set||!restore_set)goto fail;
    wsprintfW(r.secure_name,L"XP25SessionSecure%lu",pid);wsprintfW(r.user_name,L"XP25SessionUser%lu",pid);wsprintfW(r.desktop,L"WinSta0\\%s",r.user_name);
    wsprintfW(r.child_file,L"C:\\xp25\\session-child-%lu.txt",pid);GetModuleFileNameW(NULL,r.fixture_image,MAX_PATH);lstrcpyW(r.image,r.fixture_image);
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)",1,&sd,NULL))goto fail;
    /* Retain the creator handle before restricting subsequent opens. This
       user-owned test object is not a substitute for SYSTEM-owned Winlogon. */
    r.secure=CreateDesktopW(r.secure_name,NULL,NULL,0,GENERIC_ALL,NULL);
    if(r.secure){SECURITY_INFORMATION info=DACL_SECURITY_INFORMATION;if(!SetUserObjectSecurity(r.secure,&info,sd))goto fail;}
    r.user=CreateDesktopW(r.user_name,NULL,NULL,0,GENERIC_ALL,NULL);LocalFree(sd);sd=NULL;
    if(!r.secure||!r.user)goto fail;
    check("restricted_token_created",CreateRestrictedToken(r.reference,DISABLE_MAX_PRIVILEGE,0,NULL,0,NULL,0,NULL,&restricted));
    if(restricted){check("private_secure_switch_denied",denied_switch(r.secure_name,restricted));check("original_winlogon_switch_denied",denied_switch(L"Winlogon",restricted));CloseHandle(restricted);restricted=NULL;}
    /* A direct input switch hit a checked win32k invariant in the retained
       experiment. Do not repeat it or disable the assertion. The callbacks
       below exercise real thread-desktop binding with explicit input doubles. */
    printf("{\"native_input_switch\":false,\"coverage\":\"controlled_callbacks_and_real_thread_binding\"}\n");
    wl_state_init(&r.machine);check("runtime_boot_model",wl_state_step(&r.machine,WlBootReady,WL_BOOT_FACTS));
    for(i=0;i<2;++i){
        if(!begin(&r))goto fail;
        if(!wl_engine_start(&r.engine)){SetLastError(r.engine.error);goto fail;}
        check("real_private_user_thread_desktop",bound_is(r.user_name));
        check("live_process_is_not_exit",!wl_engine_recover(&r.engine,r.machine.generation)&&r.engine.error==ERROR_BUSY);
        check("wrong_image_rejected",!wl_watch_user_process(r.token,r.child.dwProcessId,L"C:\\wrong-image.exe",&unexpected)&&!unexpected);
        check("lock_private_session",wl_engine_lock(&r.engine)&&bound_is(r.secure_name));
        check("sas_routes_to_unlock_model",wl_state_step(&r.machine,WlAttention,WL_SECURE_ACTIVE));
        check("unlock_without_gina_proof_denied",!wl_engine_unlock(&r.engine,0)&&bound_is(r.secure_name));
        r.desktop_fault=ERROR_ACCESS_DENIED;check("failed_unlock_preserves_secure_desktop",!wl_engine_unlock(&r.engine,1)&&r.machine.phase==WlLocked&&bound_is(r.secure_name));r.desktop_fault=0;
        check("unlock_retry_attention",wl_state_step(&r.machine,WlAttention,WL_SECURE_ACTIVE));
        check("controlled_authorized_unlock",wl_engine_unlock(&r.engine,1)&&bound_is(r.user_name));
        check("owned_fixture_crashed",crash(&r));
        check("stale_recovery_generation_denied",!wl_engine_recover(&r.engine,r.machine.generation+1));
        if(!wl_engine_recover(&r.engine,r.machine.generation)){SetLastError(r.engine.error);goto fail;}
        check("recovered_process_identity",r.watch&&wl_user_process_exited(r.watch)==ERROR_BUSY);
        check("lock_before_second_crash",wl_engine_lock(&r.engine));check("locked_owned_fixture_crashed",crash(&r));
        check("locked_recovery_stays_secure",wl_engine_recover(&r.engine,r.machine.generation)&&r.machine.phase==WlLocked&&bound_is(r.secure_name));
        check("private_logoff_and_profile_reference_release",wl_engine_logoff(&r.engine)&&!r.token&&!r.environment&&!r.profile.hProfile&&!r.watch);
        check("profile_generation_advances",r.machine.generation==i+1);
    }
    for(i=1;i<=2;++i){
        r.activation_fault=i;if(!begin(&r))goto fail;
        check("controlled_shell_failure",!wl_engine_start(&r.engine));
        check("shell_failure_real_resource_cleanup",wl_engine_abort(&r.engine)&&!r.token&&!r.profile.hProfile&&!r.environment);
    }
    r.activation_fault=0;r.explorer=TRUE;if(!GetWindowsDirectoryW(r.image,MAX_PATH))goto fail;lstrcatW(r.image,L"\\explorer.exe");
    if(!begin(&r))goto fail;
    if(!wl_engine_start(&r.engine)){SetLastError(r.engine.error);goto fail;}
    check("source_explorer_on_private_desktop",bound_is(r.user_name));printf("XP25_PRIVATE_EXPLORER_READY\n");fflush(stdout);Sleep(8000);
    check("owned_source_explorer_crash",crash(&r));
    if(!wl_engine_recover(&r.engine,r.machine.generation)){SetLastError(r.engine.error);goto fail;}
    check("source_explorer_recovered_by_coordinator",bound_is(r.user_name));Sleep(3000);
    check("private_explorer_logoff",wl_engine_logoff(&r.engine));
    check("environment_transfers_accounted_for",r.copies==r.transfers&&!r.environment&&!r.profile.hProfile&&!r.token);
    check("controlled_logged_off_power",wl_engine_power(&r.engine,1));goto done;
fail:
    check("native_runtime_operation",FALSE);printf("{\"runtime_failure_operation\":%u,\"engine_error\":%lu}\n",(unsigned)r.engine.operation,r.engine.error);fflush(stdout);
done:
    if(r.original){SwitchDesktop(r.original);SetThreadDesktop(r.original);}
    if(r.child.hProcess&&WaitForSingleObject(r.child.hProcess,0)==WAIT_TIMEOUT){printf("XP25_FIXTURE_FORCED_CLEANUP\n");TerminateProcess(r.child.hProcess,0x25ff);WaitForSingleObject(r.child.hProcess,10000);}
    if(r.child.hProcess){DWORD cleanup=end(&r);SetLastError(cleanup);check("fixture_process_cleanup",cleanup==0);}
    if(r.token){DWORD cleanup=release(&r);SetLastError(cleanup);check("fixture_profile_cleanup",cleanup==0);}
    if(r.watch)CloseHandle(r.watch);if(r.environment)DestroyEnvironmentBlock(r.environment);
    if(restore_set)AdjustTokenPrivileges(r.reference,FALSE,&restore,0,NULL,NULL);
    if(backup_set)AdjustTokenPrivileges(r.reference,FALSE,&backup,0,NULL,NULL);
    if(r.reference)CloseHandle(r.reference);if(sd)LocalFree(sd);if(restricted)CloseHandle(restricted);
    if(r.secure)check("private_secure_handle_closed",CloseDesktop(r.secure));
    if(r.user)check("private_user_handle_closed",CloseDesktop(r.user));if(r.original)CloseDesktop(r.original);
    printf("XP25_SESSION_RUNTIME cases_checked=%u failures=%u production_winlogon=false native_input_switch=0\n",checks,failures);fflush(stdout);return failures?1:0;
}
static LRESULT CALLBACK fixture_window(HWND window,UINT message,WPARAM wp,LPARAM lp)
{if(message==WM_CLOSE){DestroyWindow(window);return 0;}if(message==WM_DESTROY){PostQuitMessage(0);return 0;}return DefWindowProcW(window,message,wp,lp);}
int wl_session_fixture(void)
{
    WCHAR file[MAX_PATH],desktop[80],profile[MAX_PATH];DWORD bytes,n;HANDLE output;WNDCLASSW cls;MSG message;char row[300];HWND window;
    if(!GetEnvironmentVariableW(L"XP25_SESSION_CHILD_RESULT",file,MAX_PATH)||!GetEnvironmentVariableW(L"USERPROFILE",profile,MAX_PATH)||
       !GetUserObjectInformationW(GetThreadDesktop(GetCurrentThreadId()),UOI_NAME,desktop,sizeof(desktop),&bytes))return 91;
    wsprintfA(row,"XP25_CHILD_ENVIRONMENT_OK desktop=%S profile_chars=%u\r\n",desktop,(unsigned)lstrlenW(profile));
    output=CreateFileW(file,GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);if(output==INVALID_HANDLE_VALUE)return 92;
    WriteFile(output,row,lstrlenA(row),&n,NULL);CloseHandle(output);
    ZeroMemory(&cls,sizeof(cls));cls.lpfnWndProc=fixture_window;cls.hInstance=GetModuleHandleW(NULL);cls.lpszClassName=L"XP25SessionFixture";
    if(!RegisterClassW(&cls))return 93;
    window=CreateWindowW(cls.lpszClassName,L"XP25 owned session fixture",WS_OVERLAPPEDWINDOW|WS_VISIBLE,40,40,440,180,NULL,NULL,cls.hInstance,NULL);
    if(!window)return 94;
    while(GetMessageW(&message,NULL,0,0)>0){TranslateMessage(&message);DispatchMessageW(&message);}return 0;
}
