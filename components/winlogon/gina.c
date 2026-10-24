/* Original XP25 implementation of the versioned documented WLX host contract. */
#include "platform.h"

typedef struct { DLGPROC procedure; LPARAM parameter; HWND previous; } WL_DIALOG;
static const WCHAR dialog_property[]=L"XP25.WLX.Dialog";
static BOOL valid(HANDLE h){if(h==&wl)return TRUE;SetLastError(ERROR_INVALID_HANDLE);return FALSE;}
static BOOL unsupported(const char *name){wl_log(name,ERROR_CALL_NOT_IMPLEMENTED);SetLastError(ERROR_CALL_NOT_IMPLEMENTED);return FALSE;}
static VOID WINAPI use_cad(HANDLE h){if(valid(h))wl.cad=TRUE;}
static VOID WINAPI set_context(HANDLE h,PVOID value){if(valid(h))wl.gina_context=value;}
static VOID WINAPI sas_notify(HANDLE h,DWORD type){if(valid(h))PostMessageW(wl.window,WL_APP_SAS,type,0);}
static BOOL WINAPI timeout(HANDLE h,DWORD seconds){if(!valid(h)||seconds>86400){SetLastError(ERROR_INVALID_PARAMETER);return FALSE;}wl.timeout=seconds;return TRUE;}
static int WINAPI shell_protection(HANDLE h,HANDLE token,HANDLE process,HANDLE thread)
{UNREFERENCED_PARAMETER(token);UNREFERENCED_PARAMETER(process);UNREFERENCED_PARAMETER(thread);if(!valid(h))return ERROR_INVALID_HANDLE;unsupported("WlxAssignShellProtection");return ERROR_CALL_NOT_IMPLEMENTED;}
static int WINAPI message_box(HANDLE h,HWND owner,LPWSTR text,LPWSTR title,UINT flags)
{if(!valid(h))return 0;return MessageBoxW(owner,text,title,flags);}

static INT_PTR CALLBACK dialog_proc(HWND h,UINT message,WPARAM wp,LPARAM lp)
{
    WL_DIALOG *context=(WL_DIALOG*)GetPropW(h,dialog_property);INT_PTR result;
    if(message==WM_INITDIALOG){
        context=(WL_DIALOG*)lp;
        if(!SetPropW(h,dialog_property,context)){EndDialog(h,-1);return FALSE;}
        wl.dialog=h;
        if(wl.timeout&&!SetTimer(h,1,wl.timeout*1000,NULL)){EndDialog(h,-1);return FALSE;}
        return context->procedure(h,message,wp,context->parameter);
    }
    if(!context)return FALSE;
    if(message==WM_TIMER&&wp==1){EndDialog(h,WLX_DLG_INPUT_TIMEOUT);return TRUE;}
    if(message==WLX_WM_SAS){EndDialog(h,WLX_DLG_SAS);return TRUE;}
    result=context->procedure(h,message,wp,lp);
    if(message==WM_NCDESTROY){KillTimer(h,1);RemovePropW(h,dialog_property);wl.dialog=context->previous;}
    return result;
}
static int WINAPI dialog_param(HANDLE h,HANDLE instance,LPWSTR name,HWND owner,DLGPROC proc,LPARAM param)
{WL_DIALOG c;if(!valid(h))return -1;c.procedure=proc;c.parameter=param;c.previous=wl.dialog;return (int)DialogBoxParamW(instance,name,owner,dialog_proc,(LPARAM)&c);}
static int WINAPI dialog(HANDLE h,HANDLE i,LPWSTR name,HWND owner,DLGPROC proc){return dialog_param(h,i,name,owner,proc,0);}
static int WINAPI dialog_indirect_param(HANDLE h,HANDLE instance,LPCDLGTEMPLATE t,HWND owner,DLGPROC proc,LPARAM param)
{WL_DIALOG c;if(!valid(h))return -1;c.procedure=proc;c.parameter=param;c.previous=wl.dialog;return (int)DialogBoxIndirectParamW(instance,t,owner,dialog_proc,(LPARAM)&c);}
static int WINAPI dialog_indirect(HANDLE h,HANDLE i,LPCDLGTEMPLATE t,HWND owner,DLGPROC proc){return dialog_indirect_param(h,i,t,owner,proc,0);}
static int WINAPI switch_user(HANDLE h){return valid(h)&&wl_switch_user();}
static int WINAPI switch_secure(HANDLE h){return valid(h)&&wl_switch_secure();}
static int WINAPI password_notify(HANDLE h,PWLX_MPR_NOTIFY_INFO m,DWORD flags)
{UNREFERENCED_PARAMETER(m);UNREFERENCED_PARAMETER(flags);if(!valid(h))return ERROR_INVALID_HANDLE;unsupported("password_provider_notification");return ERROR_CALL_NOT_IMPLEMENTED;}
static BOOL WINAPI source_desktop(HANDLE h,PWLX_DESKTOP *result)
{
    PWLX_DESKTOP d;LPCWSTR name;
    if(!valid(h)||!result){SetLastError(ERROR_INVALID_PARAMETER);return FALSE;}
    name=wl.machine.phase==WlInteractive?L"Default":L"Winlogon";
    d=LocalAlloc(LPTR,sizeof(*d)+(lstrlenW(name)+1)*sizeof(WCHAR));if(!d)return FALSE;
    d->Size=sizeof(*d);d->Flags=WLX_DESKTOP_NAME|WLX_DESKTOP_HANDLE;d->pszDesktopName=(PWSTR)(d+1);lstrcpyW(d->pszDesktopName,name);
    d->hDesktop=OpenDesktopW(name,0,FALSE,DESKTOP_READOBJECTS|DESKTOP_WRITEOBJECTS|DESKTOP_SWITCHDESKTOP);
    if(!d->hDesktop){LocalFree(d);return FALSE;}*result=d;return TRUE;
}
static BOOL WINAPI return_desktop(HANDLE h,PWLX_DESKTOP d)
{if(!valid(h)||!d||d->Size!=sizeof(*d)){SetLastError(ERROR_INVALID_PARAMETER);return FALSE;}return unsupported("WlxSetReturnDesktop");}
static BOOL WINAPI create_desktop(HANDLE h,HANDLE token,DWORD flags,PWSTR name,PWLX_DESKTOP *d)
{UNREFERENCED_PARAMETER(token);UNREFERENCED_PARAMETER(flags);UNREFERENCED_PARAMETER(name);UNREFERENCED_PARAMETER(d);return valid(h)&&unsupported("WlxCreateUserDesktop");}
static int WINAPI password_notify_ex(HANDLE h,PWLX_MPR_NOTIFY_INFO m,DWORD flags,PWSTR provider,PVOID reserved)
{UNREFERENCED_PARAMETER(provider);UNREFERENCED_PARAMETER(reserved);return password_notify(h,m,flags);}
static BOOL WINAPI close_desktop(HANDLE h,PWLX_DESKTOP d,HANDLE token)
{UNREFERENCED_PARAMETER(token);if(!valid(h)||!d||d->Size!=sizeof(*d)){SetLastError(ERROR_INVALID_PARAMETER);return FALSE;}if((d->Flags&WLX_DESKTOP_HANDLE)&&!CloseDesktop(d->hDesktop))return FALSE;LocalFree(d);return TRUE;}
static ULONG_PTR *option(DWORD id)
{
    switch(id){case WLX_OPTION_IGNORE_AUTO_LOGON:return &wl.ignore_auto;case WLX_OPTION_USE_SMART_CARD:return &wl.smartcard;case WLX_OPTION_FORCE_LOGOFF_TIME:return &wl.force_logoff;default:return NULL;}
}
static BOOL WINAPI get_option(HANDLE h,DWORD id,ULONG_PTR *value)
{
    ULONG_PTR *p;if(!valid(h)||!value){SetLastError(ERROR_INVALID_PARAMETER);return FALSE;}*value=0;
    if(id==WLX_OPTION_DISPATCH_TABLE_SIZE){*value=sizeof(wl.dispatch);return TRUE;}
    if(id==WLX_OPTION_CONTEXT_POINTER){*value=(ULONG_PTR)wl.gina_context;return TRUE;}
    if(id==WLX_OPTION_USE_CTRL_ALT_DEL){*value=wl.cad;return TRUE;}
    if(id==WLX_OPTION_NO_SWITCH_ON_SAS){*value=wl.no_switch;return TRUE;}
    p=option(id);if(p){*value=*p;return TRUE;}
    wl_log("unsupported_WLX_get_option_id",id);return unsupported("unsupported_WLX_get_option");
}
static BOOL WINAPI set_option(HANDLE h,DWORD id,ULONG_PTR value,ULONG_PTR *old)
{
    ULONG_PTR prior,*p;if(!valid(h))return FALSE;
    if(!get_option(h,id,&prior))return FALSE;
    if(id==WLX_OPTION_CONTEXT_POINTER)wl.gina_context=(PVOID)value;
    else if(id==WLX_OPTION_USE_CTRL_ALT_DEL)wl.cad=(BOOL)value;
    else if(id==WLX_OPTION_NO_SWITCH_ON_SAS)wl.no_switch=(BOOL)value;
    else {p=option(id);if(!p){SetLastError(ERROR_INVALID_PARAMETER);return FALSE;}*p=value;}
    if(old)*old=prior;return TRUE;
}
static VOID WINAPI migrate(HANDLE h){if(valid(h))wl_fail("Win31_migration_unsupported",ERROR_CALL_NOT_IMPLEMENTED);}
static BOOL WINAPI client_cred(PWLX_CLIENT_CREDENTIALS_INFO_V1_0 c){UNREFERENCED_PARAMETER(c);return unsupported("remote_credentials_unsupported");}
static BOOL WINAPI ts_cred(PWLX_CLIENT_CREDENTIALS_INFO_V2_0 c){UNREFERENCED_PARAMETER(c);return unsupported("TS_credentials_unsupported");}
static BOOL WINAPI disconnect(void){return unsupported("session_disconnect_unsupported");}
static DWORD WINAPI ts_data(HANDLE h,PWLX_TERMINAL_SERVICES_DATA data,WCHAR *u,WCHAR *d)
{UNREFERENCED_PARAMETER(data);UNREFERENCED_PARAMETER(u);UNREFERENCED_PARAMETER(d);if(!valid(h))return ERROR_INVALID_HANDLE;unsupported("TS_data_unsupported");return ERROR_CALL_NOT_IMPLEMENTED;}
static DWORD WINAPI console_cred(PWLX_CONSOLESWITCH_CREDENTIALS_INFO_V1_0 c){UNREFERENCED_PARAMETER(c);unsupported("console_switch_unsupported");return ERROR_CALL_NOT_IMPLEMENTED;}

BOOL wl_gina_init(void)
{
    WCHAR path[MAX_PATH],name[MAX_PATH];HKEY key;DWORD bytes=sizeof(name),type;LONG error;
    ZeroMemory(&wl.dispatch,sizeof(wl.dispatch));
    wl.dispatch.WlxUseCtrlAltDel=use_cad;wl.dispatch.WlxSetContextPointer=set_context;wl.dispatch.WlxSasNotify=sas_notify;
    wl.dispatch.WlxSetTimeout=timeout;wl.dispatch.WlxAssignShellProtection=shell_protection;wl.dispatch.WlxMessageBox=message_box;
    wl.dispatch.WlxDialogBox=dialog;wl.dispatch.WlxDialogBoxParam=dialog_param;wl.dispatch.WlxDialogBoxIndirect=dialog_indirect;
    wl.dispatch.WlxDialogBoxIndirectParam=dialog_indirect_param;wl.dispatch.WlxSwitchDesktopToUser=switch_user;wl.dispatch.WlxSwitchDesktopToWinlogon=switch_secure;
    wl.dispatch.WlxChangePasswordNotify=password_notify;wl.dispatch.WlxGetSourceDesktop=source_desktop;wl.dispatch.WlxSetReturnDesktop=return_desktop;
    wl.dispatch.WlxCreateUserDesktop=create_desktop;wl.dispatch.WlxChangePasswordNotifyEx=password_notify_ex;wl.dispatch.WlxCloseUserDesktop=close_desktop;
    wl.dispatch.WlxSetOption=set_option;wl.dispatch.WlxGetOption=get_option;wl.dispatch.WlxWin31Migrate=migrate;
    wl.dispatch.WlxQueryClientCredentials=client_cred;wl.dispatch.WlxQueryInetConnectorCredentials=client_cred;
    wl.dispatch.WlxDisconnect=disconnect;wl.dispatch.WlxQueryTerminalServicesData=ts_data;
    wl.dispatch.WlxQueryConsoleSwitchCredentials=console_cred;wl.dispatch.WlxQueryTsLogonCredentials=ts_cred;
    lstrcpyW(name,L"msgina.dll");error=RegOpenKeyExW(HKEY_LOCAL_MACHINE,WL_WINLOGON_KEY,0,KEY_QUERY_VALUE,&key);
    if(error!=0){SetLastError(error);return FALSE;}
    error=RegQueryValueExW(key,L"GinaDLL",NULL,&type,(BYTE*)name,&bytes);RegCloseKey(key);
    if(error!=ERROR_FILE_NOT_FOUND&&(error||type!=REG_SZ||bytes<2||name[bytes/2-1])){SetLastError(ERROR_INVALID_DATA);return FALSE;}
    if(lstrcmpiW(name,L"msgina.dll")){SetLastError(ERROR_NOT_SUPPORTED);return FALSE;}
    if(!GetSystemDirectoryW(path,MAX_PATH)||lstrlenW(path)+12>=MAX_PATH)return FALSE;
    lstrcatW(path,L"\\msgina.dll");wl.gina_module=LoadLibraryW(path);if(!wl.gina_module)return FALSE;
#define LOAD(field,export_name) {*(FARPROC*)&wl.gina.field=GetProcAddress(wl.gina_module,export_name);if(!wl.gina.field){wl_log(export_name,ERROR_PROC_NOT_FOUND);return FALSE;}}
    LOAD(negotiate,"WlxNegotiate");LOAD(initialize,"WlxInitialize");LOAD(sas_notice,"WlxDisplaySASNotice");LOAD(logged_out,"WlxLoggedOutSAS");
    LOAD(activate_shell,"WlxActivateUserShell");LOAD(logged_on,"WlxLoggedOnSAS");LOAD(locked_notice,"WlxDisplayLockedNotice");LOAD(locked_sas,"WlxWkstaLockedSAS");
    LOAD(lock_ok,"WlxIsLockOk");LOAD(logoff_ok,"WlxIsLogoffOk");LOAD(logoff,"WlxLogoff");LOAD(shutdown,"WlxShutdown");LOAD(network,"WlxNetworkProviderLoad");
#undef LOAD
    if(!wl.gina.negotiate(WLX_VERSION_1_4,&wl.gina_version)||wl.gina_version<WLX_VERSION_1_3||wl.gina_version>WLX_VERSION_1_4){SetLastError(ERROR_REVISION_MISMATCH);return FALSE;}
    wl_log("gina_negotiated",wl.gina_version);
    if(!wl.gina.initialize(L"WinSta0",&wl,NULL,&wl.dispatch,&wl.gina_context))return FALSE;
    wl_log("gina_initialized",0);return TRUE;
}

static void free_string(PWSTR *s,BOOL secret)
{if(*s){if(secret)SecureZeroMemory(*s,lstrlenW(*s)*sizeof(WCHAR));LocalFree(*s);*s=NULL;}}
void wl_free_gina_result(void)
{
    PWLX_PROFILE_V2_0 p=(PWLX_PROFILE_V2_0)wl.gina_profile;
    free_string(&wl.mpr.pszPassword,TRUE);free_string(&wl.mpr.pszOldPassword,TRUE);free_string(&wl.mpr.pszUserName,FALSE);free_string(&wl.mpr.pszDomain,FALSE);
    if(p){free_string(&p->pszProfile,FALSE);if(p->dwType==WLX_PROFILE_TYPE_V2_0){free_string(&p->pszPolicy,FALSE);free_string(&p->pszNetworkDefaultUserProfile,FALSE);free_string(&p->pszServerName,FALSE);free_string(&p->pszEnvironment,FALSE);}LocalFree(p);wl.gina_profile=NULL;}
}

void wl_attention(DWORD type)
{
    int action;DWORD options=0,error;LUID unique;SID_IDENTIFIER_AUTHORITY authority=SECURITY_NT_AUTHORITY;
    if(wl.in_gina){wl_log("sas_reentry_rejected",ERROR_BUSY);return;}
    if(!wl_switch_secure())wl_fail("secure_switch_failed",GetLastError());
    if(!wl_state_step(&wl.machine,WlAttention,WL_SECURE_ACTIVE)){wl_log("sas_state_rejected",ERROR_BUSY);return;}
    wl.in_gina=TRUE;
    if(wl.machine.phase==WlAuthenticating){
        if(WTSGetActiveConsoleSessionId()!=wl.session_id)wl_fail("nonconsole_authentication_unsupported",ERROR_ACCESS_DENIED);
        if(!AllocateLocallyUniqueId(&unique)||!InitializeSid(wl.logon_sid,&authority,3))wl_fail("logon_sid_failed",GetLastError());
        *GetSidSubAuthority(wl.logon_sid,0)=SECURITY_LOGON_IDS_RID;*GetSidSubAuthority(wl.logon_sid,1)=unique.HighPart;*GetSidSubAuthority(wl.logon_sid,2)=unique.LowPart;
        action=wl.gina.logged_out(wl.gina_context,type,&wl.authentication_id,wl.logon_sid,&options,&wl.token,&wl.mpr,&wl.gina_profile);
        wl.in_gina=FALSE;wl_log("gina_logged_out_result",action);
        if(action==WLX_SAS_ACTION_LOGON){
            if(WTSGetActiveConsoleSessionId()!=wl.session_id)wl_fail("console_changed_during_authentication",ERROR_ACCESS_DENIED);
            if(!wl_check_token(wl.token,&wl.authentication_id,wl.logon_sid))wl_fail("gina_token_rejected",GetLastError());
            if(options){wl_fail("gina_profile_option_unsupported",ERROR_NOT_SUPPORTED);}
            if(!wl_state_step(&wl.machine,WlAuthenticated,WL_TOKEN_CHECKED))wl_fail("auth_state_rejected",ERROR_INVALID_DATA);
            if(!wl_session_start()){
                error=GetLastError();wl_free_gina_result();wl.gina.logoff(wl.gina_context);
                if(!wl_session_end())wl_fail("session_cleanup_failed",GetLastError());
                if(wl.token){CloseHandle(wl.token);wl.token=NULL;}
                if(!wl.profile&&!wl.environment)wl_state_step(&wl.machine,WlRollbackCompleted,WL_RESOURCES_GONE|WL_SECURE_ACTIVE);
                wl_fail("session_start_failed",error);
            }
        }else{
            if(wl.token){CloseHandle(wl.token);wl.token=NULL;}
            wl_free_gina_result();
            if(action!=0&&action!=WLX_SAS_ACTION_NONE)wl_fail("logged_out_action_unsupported",ERROR_NOT_SUPPORTED);
            if(!wl_state_step(&wl.machine,WlDenied,0))wl_fail("denial_state_rejected",ERROR_INVALID_DATA);
            PostMessageW(wl.window,WL_APP_NOTICE,100,0);
        }
    }else if(wl.machine.phase==WlUnlocking){
        action=wl.gina.locked_sas(wl.gina_context,type);wl.in_gina=FALSE;wl_log("gina_unlock_result",action);
        if(action==WLX_SAS_ACTION_UNLOCK_WKSTA){
            if(!wl_check_token(wl.token,&wl.authentication_id,wl.logon_sid)||!wl_switch_user())wl_fail("unlock_token_or_desktop_failed",GetLastError());
            if(!wl_state_step(&wl.machine,WlUnlockCompleted,WL_UNLOCK_CHECKED|WL_USER_ACTIVE))wl_fail("unlock_state_rejected",ERROR_INVALID_DATA);
        }else if(action==WLX_SAS_ACTION_NONE||action==0){wl_state_step(&wl.machine,WlDenied,0);wl.gina.locked_notice(wl.gina_context);}
        else wl_fail("locked_action_unsupported",ERROR_NOT_SUPPORTED);
    }else{
        action=wl.gina.logged_on(wl.gina_context,type,NULL);wl.in_gina=FALSE;wl_log("gina_security_action",action);
        if(action==WLX_SAS_ACTION_LOCK_WKSTA){if(!wl_state_step(&wl.machine,WlLockCompleted,WL_SECURE_ACTIVE))wl_fail("lock_state_rejected",ERROR_INVALID_DATA);wl.gina.locked_notice(wl.gina_context);}
        else if(action==WLX_SAS_ACTION_NONE||action==0){if(!wl_switch_user()||!wl_state_step(&wl.machine,WlCancelled,WL_USER_ACTIVE))wl_fail("security_cancel_failed",GetLastError());}
        else wl_fail("security_action_unsupported",ERROR_NOT_SUPPORTED);
    }
}
