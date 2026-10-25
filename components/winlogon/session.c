/* Original XP25 profile preparation and guarded GINA shell handoff.
   The unresolved activation-policy dependency does not authorize a shell. */
#include "platform.h"
#include "environment.h"

typedef struct {USHORT length,maximum;PWSTR buffer;} WL_ENV_STRING;
typedef LONG (NTAPI *SET_ENVIRONMENT)(PVOID*,WL_ENV_STRING*,WL_ENV_STRING*);
typedef LONG (NTAPI *EXPAND_ENVIRONMENT)(PVOID,WL_ENV_STRING*,WL_ENV_STRING*,PULONG);
typedef LONG (NTAPI *QUERY_KEY)(HANDLE,ULONG,PVOID,ULONG,PULONG);

static BOOL user_identity(void)
{
    TOKEN_USER *user;DWORD bytes=0,users=256,domains=256,computer_chars=MAX_COMPUTERNAME_LENGTH+1;
    WCHAR computer[MAX_COMPUTERNAME_LENGTH+1];SID_NAME_USE use=SidTypeUnknown;BOOL ok;
    if(!wl_check_token(wl.token,&wl.authentication_id,wl.logon_sid))return FALSE;
    GetTokenInformation(wl.token,TokenUser,NULL,0,&bytes);
    if(!bytes){SetLastError(ERROR_INVALID_DATA);return FALSE;}
    user=LocalAlloc(LPTR,bytes);if(!user)return FALSE;
    ok=GetTokenInformation(wl.token,TokenUser,user,bytes,&bytes)&&
       LookupAccountSidW(NULL,user->User.Sid,wl.username,&users,wl.domain,&domains,&use);
    LocalFree(user);if(!ok)return FALSE;
    if(use!=SidTypeUser||!GetComputerNameW(computer,&computer_chars)||lstrcmpiW(wl.domain,computer)){
        SetLastError(ERROR_NOT_SUPPORTED);return FALSE; /* Domain/profile-policy orchestration is not implemented. */
    }
    if(!wl.mpr.pszUserName||lstrcmpiW(wl.mpr.pszUserName,wl.username)){
        SetLastError(ERROR_ACCESS_DENIED);return FALSE;
    }
    if(wl.mpr.pszDomain&&wl.mpr.pszDomain[0]&&lstrcmpW(wl.mpr.pszDomain,L".")&&lstrcmpiW(wl.mpr.pszDomain,wl.domain)){
        SetLastError(ERROR_ACCESS_DENIED);return FALSE;
    }
    wl_log("profile_token_account_matched",0);return TRUE;
}

static BOOL verify_hive(void)
{
    QUERY_KEY query;TOKEN_USER *user;DWORD bytes=0;LPWSTR sid=NULL;WCHAR expected[256];LONG status;
    struct {ULONG bytes;WCHAR text[256];} name;ULONG returned=0;BOOL ok=FALSE;
    query=(QUERY_KEY)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQueryKey");
    if(!query){SetLastError(ERROR_PROC_NOT_FOUND);return FALSE;}
    GetTokenInformation(wl.token,TokenUser,NULL,0,&bytes);if(!bytes)return FALSE;
    user=LocalAlloc(LPTR,bytes);if(!user)return FALSE;
    if(!GetTokenInformation(wl.token,TokenUser,user,bytes,&bytes)||!ConvertSidToStringSidW(user->User.Sid,&sid))goto done;
    if(lstrlenW(sid)+17>=256){SetLastError(ERROR_BUFFER_OVERFLOW);goto done;}
    wsprintfW(expected,L"\\REGISTRY\\USER\\%s",sid);ZeroMemory(&name,sizeof(name));
    status=query(wl.profile,3,&name,sizeof(name)-sizeof(WCHAR),&returned); /* NT5.1 KeyNameInformation */
    if(status<0){SetLastError(LsaNtStatusToWinError(status));goto done;}
    if(returned<sizeof(ULONG)||name.bytes%sizeof(WCHAR)||name.bytes>=sizeof(name.text)||
       name.bytes>returned-sizeof(ULONG)){SetLastError(ERROR_INVALID_DATA);goto done;}
    name.text[name.bytes/sizeof(WCHAR)]=0;
    if(lstrcmpiW(expected,name.text)){SetLastError(ERROR_ACCESS_DENIED);goto done;}
    ok=TRUE;wl_log("profile_hive_identity_verified",0);
done:
    if(sid)LocalFree(sid);LocalFree(user);return ok;
}

static BOOL environment_value(LPCWSTR name,LPCWSTR expected)
{
    MEMORY_BASIC_INFORMATION memory;SIZE_T available;const unsigned short *value;unsigned length;WCHAR copy[MAX_PATH];
    if(!VirtualQuery(wl.environment,&memory,sizeof(memory))||memory.State!=MEM_COMMIT){SetLastError(ERROR_INVALID_DATA);return FALSE;}
    available=memory.RegionSize-((BYTE*)wl.environment-(BYTE*)memory.BaseAddress);
    if(available>32767*sizeof(WCHAR))available=32767*sizeof(WCHAR);
    if(wl_environment_find(wl.environment,(unsigned)(available/sizeof(WCHAR)),name,&value,&length)!=1||length>=MAX_PATH){
        SetLastError(ERROR_INVALID_DATA);return FALSE;
    }
    CopyMemory(copy,value,length*sizeof(WCHAR));copy[length]=0;
    if(lstrcmpiW(copy,expected)){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}return TRUE;
}

static BOOL merge_gina_environment(SET_ENVIRONMENT set)
{
    PWLX_PROFILE_V2_0 source=wl.gina_profile;HLOCAL block;SIZE_T bytes;unsigned capacity,at=0,previous;
    const unsigned short *name,*value,*other,*ignored;unsigned names,values,others,unused;int status,comparison;
    EXPAND_ENVIRONMENT expand;WL_ENV_STRING key,input,output;WCHAR *expanded;ULONG required;LONG result;BOOL ok=FALSE;
    if(source->dwType!=WLX_PROFILE_TYPE_V2_0||!source->pszEnvironment)return TRUE;
    block=source->pszEnvironment;bytes=LocalSize(block);
    if(bytes<2*sizeof(WCHAR)||bytes>32767*sizeof(WCHAR)||bytes%sizeof(WCHAR)){
        SetLastError(ERROR_INVALID_DATA);return FALSE;
    }
    capacity=(unsigned)(bytes/sizeof(WCHAR));
    /* Validate the complete GINA allocation before changing our environment.
       CompareString provides NT's Unicode case-insensitive name comparison. */
    while((status=wl_environment_next(block,capacity,&at,&name,&names,&value,&values))==1){
        if(name[0]==L'='){SetLastError(ERROR_INVALID_DATA);return FALSE;}
        previous=0;
        while(wl_environment_next(block,capacity,&previous,&other,&others,&ignored,&unused)==1&&other<name){
            comparison=CompareStringW(LOCALE_INVARIANT,NORM_IGNORECASE,name,(int)names,other,(int)others);
            if(!comparison)return FALSE;
            if(comparison==CSTR_EQUAL){SetLastError(ERROR_INVALID_DATA);return FALSE;}
        }
    }
    if(status<0){SetLastError(ERROR_INVALID_DATA);return FALSE;}
    expand=(EXPAND_ENVIRONMENT)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"RtlExpandEnvironmentStrings_U");
    if(!expand){SetLastError(ERROR_PROC_NOT_FOUND);return FALSE;}
    expanded=LocalAlloc(LPTR,32767*sizeof(WCHAR));if(!expanded)return FALSE;
    at=0;
    while(wl_environment_next(block,capacity,&at,&name,&names,&value,&values)==1){
        key.buffer=(PWSTR)name;key.length=(USHORT)(names*sizeof(WCHAR));key.maximum=key.length;
        input.buffer=(PWSTR)value;input.length=(USHORT)(values*sizeof(WCHAR));input.maximum=input.length;
        output.buffer=expanded;output.length=0;output.maximum=32767*sizeof(WCHAR);required=0;
        result=expand(wl.environment,&input,&output,&required);
        if(result<0){SetLastError(LsaNtStatusToWinError(result));goto done;}
        if(output.length%sizeof(WCHAR)||output.length>=output.maximum||required>output.maximum){
            SetLastError(ERROR_INVALID_DATA);goto done;
        }
        result=set(&wl.environment,&key,&output);
        if(result<0){SetLastError(LsaNtStatusToWinError(result));goto done;}
    }
    ok=TRUE;wl_log("gina_environment_merged",0);
done:
    LocalFree(expanded);return ok;
}

static BOOL prepare_environment(void)
{
    SET_ENVIRONMENT set;WL_ENV_STRING name,value;LONG status;WCHAR path[MAX_PATH];DWORD chars=MAX_PATH,attributes;
    if(!GetUserProfileDirectoryW(wl.token,path,&chars))return FALSE;
    attributes=GetFileAttributesW(path);
    if(attributes==INVALID_FILE_ATTRIBUTES)return FALSE;
    if(!(attributes&FILE_ATTRIBUTE_DIRECTORY)){SetLastError(ERROR_DIRECTORY);return FALSE;}
    if(!CreateEnvironmentBlock(&wl.environment,wl.token,FALSE))return FALSE;
    set=(SET_ENVIRONMENT)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"RtlSetEnvironmentVariable");
    if(!set){SetLastError(ERROR_PROC_NOT_FOUND);return FALSE;}
    if(!merge_gina_environment(set))return FALSE;
    name.buffer=L"SESSIONNAME";name.length=(USHORT)(lstrlenW(name.buffer)*sizeof(WCHAR));name.maximum=name.length+sizeof(WCHAR);
    value.buffer=L"Console";value.length=(USHORT)(lstrlenW(value.buffer)*sizeof(WCHAR));value.maximum=value.length+sizeof(WCHAR);
    if(WTSGetActiveConsoleSessionId()!=wl.session_id){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
    status=set(&wl.environment,&name,&value);
    if(status<0){SetLastError(LsaNtStatusToWinError(status));return FALSE;}
    if(!environment_value(L"USERNAME",wl.username)||!environment_value(L"USERDOMAIN",wl.domain)||
       !environment_value(L"USERPROFILE",path)||!environment_value(L"SESSIONNAME",L"Console"))return FALSE;
    wl_log("profile_environment_verified",0);return TRUE;
}

static BOOL prepare_profile(void)
{
    PROFILEINFOW profile;PWLX_PROFILE_V2_0 source=wl.gina_profile;static BOOL initialized;
    VOID (WINAPI *initialize)(void);HMODULE userenv;
    if(wl.machine.phase!=WlLoadingProfile||!wl.token||wl.profile||wl.environment){SetLastError(ERROR_INVALID_STATE);return FALSE;}
    if(!user_identity())return FALSE;
    if(!source||(source->dwType!=WLX_PROFILE_TYPE_V1_0&&source->dwType!=WLX_PROFILE_TYPE_V2_0)){
        SetLastError(ERROR_NOT_SUPPORTED);return FALSE;
    }
    if(!initialized){
        userenv=GetModuleHandleW(L"userenv.dll");if(!userenv){SetLastError(ERROR_MOD_NOT_FOUND);return FALSE;}
        /* SP3 ABI: NONAME ordinal117, mapped to original SP1 ordinal118 by
           the verified UserEnv adapter. There is no named export to resolve. */
        initialize=(VOID(WINAPI*)(void))GetProcAddress(userenv,MAKEINTRESOURCEA(117));
        if(!initialize){SetLastError(ERROR_PROC_NOT_FOUND);return FALSE;}
        initialize();initialized=TRUE;wl_log("profile_manager_initialize_invoked",0);
    }
    ZeroMemory(&profile,sizeof(profile));profile.dwSize=sizeof(profile);profile.dwFlags=PI_NOUI;
    profile.lpUserName=wl.username;profile.lpProfilePath=source->pszProfile;
    if(source->dwType==WLX_PROFILE_TYPE_V2_0){
        profile.lpDefaultPath=source->pszNetworkDefaultUserProfile;profile.lpServerName=source->pszServerName;profile.lpPolicyPath=source->pszPolicy;
    }
    if(!LoadUserProfileW(wl.token,&profile))return FALSE;
    if(!profile.hProfile){SetLastError(ERROR_INVALID_DATA);return FALSE;}
    wl.profile=profile.hProfile;wl_log("profile_loaded",0);
    if(!verify_hive())return FALSE;
    if(!prepare_environment())return FALSE;
    return TRUE;
}

static BOOL record_token(void)
{
    TOKEN_STATISTICS stats;TOKEN_USER *user;DWORD bytes=0,session;LPWSTR sid=NULL;char row[256];BOOL ok=FALSE;
    if(!GetTokenInformation(wl.token,TokenStatistics,&stats,sizeof(stats),&bytes)||
       !GetTokenInformation(wl.token,TokenSessionId,&session,sizeof(session),&bytes))return FALSE;
    GetTokenInformation(wl.token,TokenUser,NULL,0,&bytes);if(!bytes)return FALSE;
    user=LocalAlloc(LPTR,bytes);if(!user)return FALSE;
    if(!GetTokenInformation(wl.token,TokenUser,user,bytes,&bytes)||!ConvertSidToStringSidW(user->User.Sid,&sid))goto done;
    if(!WideCharToMultiByte(CP_UTF8,0,sid,-1,row,sizeof(row),NULL,NULL))goto done;
    wl_log(row,0);
    wsprintfA(row,"authenticated_token_luid_%08lx_%08lx",stats.AuthenticationId.HighPart,stats.AuthenticationId.LowPart);
    wl_log(row,0);wl_log("authenticated_token_type",stats.TokenType);wl_log("authenticated_token_session",session);ok=TRUE;
done:
    if(sid)LocalFree(sid);LocalFree(user);return ok;
}

static PVOID copy_shell_environment(void)
{
    MEMORY_BASIC_INFORMATION memory;SIZE_T bytes;unsigned capacity,at=0,names,values;int status;
    const unsigned short *name,*value;PVOID copy;
    if(!VirtualQuery(wl.environment,&memory,sizeof(memory))||memory.State!=MEM_COMMIT){SetLastError(ERROR_INVALID_DATA);return NULL;}
    bytes=memory.RegionSize-((BYTE*)wl.environment-(BYTE*)memory.BaseAddress);
    if(bytes>32767*sizeof(WCHAR))bytes=32767*sizeof(WCHAR);
    capacity=(unsigned)(bytes/sizeof(WCHAR));
    while((status=wl_environment_next(wl.environment,capacity,&at,&name,&names,&value,&values))==1){}
    if(status<0){SetLastError(ERROR_INVALID_DATA);return NULL;}
    bytes=(at?at+1:2)*sizeof(WCHAR);
    copy=VirtualAlloc(NULL,bytes,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    if(copy)CopyMemory(copy,wl.environment,bytes);return copy;
}

static WL_SESSION_ENGINE session_engine;
static DWORD shell_pid;
static unsigned long native_error(BOOL ok)
{DWORD error;if(ok)return 0;error=GetLastError();return error?error:ERROR_GEN_FAILURE;}
static unsigned long native_user(void *context)
{UNREFERENCED_PARAMETER(context);return native_error(user_identity());}
static unsigned long native_profile(void *context)
{UNREFERENCED_PARAMETER(context);return native_error(prepare_profile()&&record_token());}
static void native_policy(void *context,WL_POLICY_RESULT *result)
{UNREFERENCED_PARAMETER(context);wl_session_policy(result);}
static unsigned long native_copy(void *context,void **copy)
{UNREFERENCED_PARAMETER(context);*copy=copy_shell_environment();return native_error(*copy!=NULL);}
static unsigned long native_discard(void *context,void *copy)
{UNREFERENCED_PARAMETER(context);return native_error(VirtualFree(copy,0,MEM_RELEASE));}
static unsigned long native_secure(void *context)
{UNREFERENCED_PARAMETER(context);return native_error(wl_switch_secure());}
static unsigned long native_protect(void *context)
{UNREFERENCED_PARAMETER(context);return native_error(wl_apply_user_security(wl.token));}
static unsigned long native_activate(void *context,void *copy)
{
    BOOL result;UNREFERENCED_PARAMETER(context);
    result=wl.gina.activate_shell(wl.gina_context,L"WinSta0\\Default",NULL,copy);
    if(result)wl_log("user_shell_activation_success",0);return native_error(result);
}
static unsigned long native_shell(void *context)
{UNREFERENCED_PARAMETER(context);return native_error(wl_wait_user_shell(&shell_pid));}
static unsigned long native_desktop(void *context)
{UNREFERENCED_PARAMETER(context);return native_error(wl_switch_user());}
static unsigned long native_notify(void *context,WL_SESSION_NOTICE event)
{
    static const WCHAR *names[]={L"Logon",L"StartShell",L"PostShell",L"Lock",L"Unlock",L"Logoff",L"Shutdown"};
    UNREFERENCED_PARAMETER(context);if((unsigned)event>=sizeof(names)/sizeof(names[0]))return ERROR_INVALID_PARAMETER;
    return native_error(wl_notify(names[event]));
}

static BOOL no_user_processes(void)
{
    HANDLE list,process,token;PROCESSENTRY32W row;TOKEN_STATISTICS stats;DWORD bytes,error=0;BOOL more;
    list=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);if(list==INVALID_HANDLE_VALUE)return FALSE;
    row.dwSize=sizeof(row);more=Process32FirstW(list,&row);
    if(!more){error=GetLastError();CloseHandle(list);SetLastError(error);return FALSE;}
    do{
        /* NT 5.1 Idle/System and our own SYSTEM host are not user processes. */
        if(!row.th32ProcessID||row.th32ProcessID==4||row.th32ProcessID==GetCurrentProcessId())continue;
        process=OpenProcess(PROCESS_QUERY_INFORMATION|SYNCHRONIZE,FALSE,row.th32ProcessID);
        if(!process){error=GetLastError();if(error==ERROR_INVALID_PARAMETER){error=0;continue;}break;}
        if(WaitForSingleObject(process,0)==WAIT_OBJECT_0){CloseHandle(process);continue;}
        token=NULL;
        if(!OpenProcessToken(process,TOKEN_QUERY,&token)||!GetTokenInformation(token,TokenStatistics,&stats,sizeof(stats),&bytes)){
            error=GetLastError();if(token)CloseHandle(token);CloseHandle(process);break;
        }
        CloseHandle(token);CloseHandle(process);
        if(stats.AuthenticationId.LowPart==wl.authentication_id.LowPart&&stats.AuthenticationId.HighPart==wl.authentication_id.HighPart){
            error=ERROR_BUSY;break;
        }
    }while(Process32NextW(list,&row));
    if(!error){error=GetLastError();if(error==ERROR_NO_MORE_FILES)error=0;}
    CloseHandle(list);SetLastError(error);return error==0;
}
static unsigned long native_end_processes(void *context)
{
    BOOL result;DWORD error;UNREFERENCED_PARAMETER(context);
    if(!ImpersonateLoggedOnUser(wl.token))return GetLastError();
    /* Supplied USER/Csr code uses this thread's impersonation LUID, recognizes
       the registered Winlogon PID, and performs normal end-session processing. */
    result=ExitWindowsEx(EWX_LOGOFF,0);error=result?0:GetLastError();
    if(!RevertToSelf())wl_fail("session_logoff_revert_failed",GetLastError());
    if(!result)return error?error:ERROR_CANCELLED;
    if(!no_user_processes())return GetLastError();
    return native_error(wl_clear_user_security());
}
static unsigned long native_release(void *context)
{
    UNREFERENCED_PARAMETER(context);
    if(!wl_notifications_wait_user())return GetLastError();
    wl.gina.logoff(wl.gina_context);wl_free_gina_result();
    if(!wl_session_end())return GetLastError();
    if(wl.token){if(!CloseHandle(wl.token))return GetLastError();wl.token=NULL;}
    ZeroMemory(&wl.authentication_id,sizeof(wl.authentication_id));SecureZeroMemory(wl.logon_sid,sizeof(wl.logon_sid));return 0;
}
static unsigned long native_power(void *context,unsigned mode)
{
    LONG (NTAPI *shutdown)(int);LONG status;UNREFERENCED_PARAMETER(context);
    shutdown=(LONG(NTAPI*)(int))GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtShutdownSystem");
    if(!shutdown)return ERROR_PROC_NOT_FOUND;
    wl.gina.shutdown(wl.gina_context,mode?WLX_SAS_ACTION_SHUTDOWN_REBOOT:WLX_SAS_ACTION_SHUTDOWN_POWER_OFF);
    /* First let USER/Csr/SCM finish system end-session processing. An API
       request alone is not recorded as successful hardware shutdown. */
    if(!ExitWindowsEx(EWX_SHUTDOWN,0))return GetLastError();
    wl_log("native_power_system_processes_released",mode);
    status=shutdown(mode?1:2); /* supplied NT SHUTDOWN_ACTION: reboot / poweroff */
    return status<0?LsaNtStatusToWinError(status):0;
}
static const WL_SESSION_DRIVER native_driver={native_user,native_profile,native_policy,native_copy,native_discard,
    native_secure,native_protect,native_activate,native_shell,native_desktop,native_notify,
    native_end_processes,native_release,native_power};

BOOL wl_session_start(void)
{
    BOOL result;wl_engine_bind(&session_engine,&wl.machine,&native_driver,&wl);
    wl.in_gina=TRUE;result=wl_engine_start(&session_engine);wl.in_gina=FALSE;
    if(!result){SetLastError(session_engine.error);wl_log("session_engine_start_operation",session_engine.operation);return FALSE;}
    wl_log("session_interactive",shell_pid);return TRUE;
}
BOOL wl_session_abort(void)
{
    BOOL result=wl_engine_abort(&session_engine);
    if(!result)SetLastError(session_engine.error);return result;
}
BOOL wl_session_lock(void)
{
    BOOL result;
    if(!wl.gina.lock_ok(wl.gina_context)){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
    result=wl_engine_lock(&session_engine);if(!result)SetLastError(session_engine.error);return result;
}
BOOL wl_session_unlock(void)
{BOOL result=wl_engine_unlock(&session_engine,1);if(!result)SetLastError(session_engine.error);return result;}
BOOL wl_session_logoff(void)
{
    BOOL result;
    if(!wl.gina.logoff_ok(wl.gina_context)){SetLastError(ERROR_CANCELLED);return FALSE;}
    wl.in_gina=TRUE;result=wl_engine_logoff(&session_engine);wl.in_gina=FALSE;
    if(!result)SetLastError(session_engine.error);return result;
}
BOOL wl_session_power(unsigned mode)
{
    BOOL result;
    if(!session_engine.driver)wl_engine_bind(&session_engine,&wl.machine,&native_driver,&wl);
    result=wl_engine_power(&session_engine,mode);if(!result)SetLastError(session_engine.error);return result;
}
BOOL wl_session_end(void)
{
    /* The caller first releases GINA's HKCU/environment references. Retain the
       token and profile handle on failure so ownership is never forgotten. */
    if(wl.environment){
        if(!DestroyEnvironmentBlock(wl.environment))return FALSE;
        wl.environment=NULL;wl_log("profile_environment_released",0);
    }
    if(wl.profile){
        if(!wl.token){SetLastError(ERROR_INVALID_HANDLE);return FALSE;}
        if(!UnloadUserProfile(wl.token,wl.profile))return FALSE;
        wl.profile=NULL;wl_log("profile_unloaded",0);
    }
    ZeroMemory(wl.username,sizeof(wl.username));ZeroMemory(wl.domain,sizeof(wl.domain));return TRUE;
}
