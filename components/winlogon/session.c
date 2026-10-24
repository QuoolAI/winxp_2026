/* Original XP25 profile preparation and ownership. This does not authorize a
   shell: the unresolved activation-policy boundary remains below. */
#include "platform.h"
#include "environment.h"

typedef struct {USHORT length,maximum;PWSTR buffer;} WL_ENV_STRING;
typedef LONG (NTAPI *SET_ENVIRONMENT)(PVOID*,WL_ENV_STRING*,WL_ENV_STRING*);
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
    if(!wl_state_step(&wl.machine,WlProfileReady,WL_PROFILE_LOADED)){SetLastError(ERROR_INVALID_DATA);return FALSE;}
    return prepare_environment();
}

BOOL wl_session_start(void)
{
    if(!prepare_profile()){wl_log("session_preparation_failed",GetLastError());return FALSE;}
    /* No activation-success stub, policy override or alternate shell path.
       Profile preparation is not permission to omit the original policy. */
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    wl_log("activation_policy_contract_unresolved",ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
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
