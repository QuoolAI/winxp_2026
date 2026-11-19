/* XP25 original screen-saver host. USER asks the logon process to start the screen saver
   (LOGON_INPUT_TIMEOUT); win32k accepts a saver only from a STARTF_SCREENSAVER process whose
   parent is the registered logon process, and stops asking once it runs. The saver runs on
   WinSta0\Screen-saver with the station switch-locked; the logon desktop's saver comes from
   .DEFAULT and runs as SYSTEM, a session's from the user's hive and runs as the user. On NT
   the saver checks no password: a secure session saver ends in a Winlogon lock. */
#include "platform.h"

#define WL_STARTF_SCREENSAVER 0x80000000u /* winuserp.h */
#define WL_NOTICE_LOG_PERIOD 600000u

static struct {
    HANDLE process, wait;
    WL_SAVER_PLACE place;
    unsigned secure, wanted;
    DWORD pid, started, notices, last_notice, quiet_notices, quiet_logged;
    LONG generation;
    HWND interrupted;
} saver;

/* Notices that start nothing are counted: USER repeats them about twice a second for as
   long as the station stays idle without a saver. Record the first, then one per period. */
static void not_started(const char *reason)
{
    DWORD now=GetTickCount();
    ++saver.quiet_notices;
    if(!saver.quiet_logged||now-saver.quiet_logged>=WL_NOTICE_LOG_PERIOD){
        wl_log("screen_saver_not_started",saver.quiet_notices);wl_log(reason,0);
        saver.quiet_logged=now?now:1;saver.quiet_notices=0;
    }
}

static BOOL read_value(HKEY root,LPCWSTR path,LPCWSTR name,WCHAR *text,DWORD chars,DWORD *number,BOOL *is_number)
{
    HKEY key;DWORD type=0,bytes=chars*sizeof(WCHAR),value=0;LONG error;
    if(RegOpenKeyExW(root,path,0,KEY_QUERY_VALUE,&key))return FALSE;
    error=RegQueryValueExW(key,name,NULL,&type,(BYTE*)text,&bytes);
    if(!error&&type==REG_DWORD&&bytes==sizeof(DWORD)){CopyMemory(&value,text,sizeof(value));*number=value;*is_number=TRUE;}
    else if(!error&&(type==REG_SZ||type==REG_EXPAND_SZ)&&bytes>=sizeof(WCHAR)&&bytes%sizeof(WCHAR)==0&&bytes<=chars*sizeof(WCHAR)){
        if(text[bytes/sizeof(WCHAR)-1]){
            if(bytes/sizeof(WCHAR)>=chars)error=ERROR_INVALID_DATA;else text[bytes/sizeof(WCHAR)]=0;
        }
        *is_number=FALSE;
    }else if(!error)error=ERROR_INVALID_DATA;
    RegCloseKey(key);return error==0;
}

/* ScreenSaveActive/ScreenSaverIsSecure as USER and Desktop.cpl store them ("0"/"1"), or a
   policy DWORD. The policy key overrides the user's own value. */
static void read_flag(HKEY root,LPCWSTR name,unsigned *flag)
{
    static const WCHAR *keys[]={L"Control Panel\\Desktop",L"Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop"};
    WCHAR text[16];DWORD number;BOOL is_number;unsigned i;
    for(i=0;i<2;++i)if(read_value(root,keys[i],name,text,16,&number,&is_number))
        *flag=(is_number?number!=0:(text[0]!=L'0'&&text[0]!=0))?1u:0u;
}

static BOOL read_image(HKEY root,HANDLE token,WCHAR *path)
{
    static const WCHAR *keys[]={L"Control Panel\\Desktop",L"Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop"};
    WCHAR raw[MAX_PATH],value[MAX_PATH],expanded[MAX_PATH];DWORD number,attributes,chars;BOOL is_number,found=FALSE;unsigned i;
    for(i=0;i<2;++i)if(read_value(root,keys[i],L"SCRNSAVE.EXE",value,MAX_PATH,&number,&is_number)&&!is_number){
        lstrcpyW(raw,value);found=TRUE;
    }
    if(!found||!raw[0]){SetLastError(ERROR_FILE_NOT_FOUND);return FALSE;}
    /* Desktop.cpl stores a full or short path; the Default User hive "%SystemRoot%\System32\logon.scr",
       .DEFAULT a bare "logon.scr". Expand as that account, then resolve a bare name in System32. */
    if(token)chars=ExpandEnvironmentStringsForUserW(token,raw,expanded,MAX_PATH)?(DWORD)lstrlenW(expanded)+1:0;
    else chars=ExpandEnvironmentStringsW(raw,expanded,MAX_PATH);
    if(!chars||chars>MAX_PATH){SetLastError(ERROR_BUFFER_OVERFLOW);return FALSE;}
    if(!wcschr(expanded,L'\\')&&!wcschr(expanded,L'/')&&!wcschr(expanded,L':')){
        if(!GetSystemDirectoryW(path,MAX_PATH)||lstrlenW(path)+lstrlenW(expanded)+2>MAX_PATH){SetLastError(ERROR_BUFFER_OVERFLOW);return FALSE;}
        lstrcatW(path,L"\\");lstrcatW(path,expanded);
    }else lstrcpyW(path,expanded);
    /* A local drive path only: the logon desktop's saver runs as SYSTEM. */
    if(lstrlenW(path)<4||path[1]!=L':'||path[2]!=L'\\'){SetLastError(ERROR_BAD_PATHNAME);return FALSE;}
    attributes=GetFileAttributesW(path);
    if(attributes==INVALID_FILE_ATTRIBUTES)return FALSE;
    if(attributes&FILE_ATTRIBUTE_DIRECTORY){SetLastError(ERROR_DIRECTORY);return FALSE;}
    return TRUE;
}

static BOOL read_settings(WL_SAVER_PLACE place,WL_SAVER_SETTINGS *s,WCHAR *path)
{
    HKEY root=NULL;HANDLE token=NULL;BOOL ok;
    s->active=1;s->image=0;s->secure=0;
    if(place==WlSaverLogonDesktop){
        if(RegOpenKeyExW(HKEY_USERS,L".DEFAULT",0,KEY_READ,&root)){s->active=0;return FALSE;}
    }else{
        if(!wl.profile||!wl.token){s->active=0;SetLastError(ERROR_INVALID_STATE);return FALSE;}
        root=(HKEY)wl.profile;token=wl.token;
    }
    read_flag(root,L"ScreenSaveActive",&s->active);
    if(place!=WlSaverLogonDesktop)read_flag(root,L"ScreenSaverIsSecure",&s->secure);
    ok=read_image(root,token,path);s->image=ok?1u:0u;
    if(place==WlSaverLogonDesktop)RegCloseKey(root);
    return ok;
}

static VOID CALLBACK saver_exited(PVOID context,BOOLEAN timer)
{
    UNREFERENCED_PARAMETER(timer);
    PostMessageW(wl.window,WL_APP_NOTICE,WL_NOTICE_SAVER_ENDED,(LPARAM)context);
}

/* The saver's exit has been observed (or it was terminated): release the wait and handle. */
static DWORD release_saver(void)
{
    DWORD code=STILL_ACTIVE;
    if(saver.wait&&!UnregisterWaitEx(saver.wait,INVALID_HANDLE_VALUE))wl_fail("screen_saver_wait_release_failed",GetLastError());
    saver.wait=NULL;
    if(!GetExitCodeProcess(saver.process,&code))code=GetLastError();
    if(!CloseHandle(saver.process))wl_fail("screen_saver_handle_release_failed",GetLastError());
    saver.process=NULL;
    wl_log("screen_saver_notices_during_run",saver.notices);
    wl_log("screen_saver_last_notice_ms",saver.notices?saver.last_notice-saver.started:0);
    wl_log("screen_saver_run_ms",GetTickCount()-saver.started);
    return code;
}

static void lock_session(const char *event)
{
    if(!wl_session_lock())wl_fail("screen_saver_lock_failed",GetLastError());
    wl_log(event,0);wl.gina.locked_notice(wl.gina_context);
}

static BOOL launch(WL_SAVER_PLACE place,unsigned secure,const WCHAR *image)
{
    WCHAR command[MAX_PATH+8],desktop[]=L"WinSta0\\Screen-saver";STARTUPINFOW startup;PROCESS_INFORMATION child;
    PVOID copy;BOOL ok;DWORD error;const WCHAR *name;char row[96],file[49];
    wsprintfW(command,L"\"%s\" /s",image);
    if(!wl_switch_saver())return FALSE;
    ZeroMemory(&child,sizeof(child));
    if(place==WlSaverLogonDesktop){
        ZeroMemory(&startup,sizeof(startup));startup.cb=sizeof(startup);startup.lpDesktop=desktop;startup.dwFlags=WL_STARTF_SCREENSAVER;
        ok=CreateProcessW(image,command,NULL,NULL,FALSE,0,NULL,NULL,&startup,&child);error=GetLastError();
    }else{
        copy=wl_copy_user_environment(wl.environment);if(!copy)return FALSE;
        ok=wl_spawn_user_process_flags(wl.token,image,command,desktop,copy,WL_STARTF_SCREENSAVER,&child);error=GetLastError();
        if(!ok&&child.hProcess)wl_fail("screen_saver_cleanup_failed",error);
        VirtualFree(copy,0,MEM_RELEASE);
    }
    if(!ok){SetLastError(error);return FALSE;}
    CloseHandle(child.hThread);
    saver.process=child.hProcess;saver.pid=child.dwProcessId;saver.place=place;saver.secure=secure;
    saver.started=GetTickCount();saver.notices=0;saver.last_notice=0;saver.wanted=0;saver.interrupted=NULL;
    ++saver.generation;
    if(!RegisterWaitForSingleObject(&saver.wait,saver.process,saver_exited,(PVOID)(LONG_PTR)saver.generation,INFINITE,WT_EXECUTEONLYONCE)){
        error=GetLastError();saver.wait=NULL;
        if(!TerminateProcess(saver.process,ERROR_CANCELLED)||WaitForSingleObject(saver.process,10000)!=WAIT_OBJECT_0)
            wl_fail("screen_saver_unwatched",error);
        release_saver();SetLastError(error);return FALSE;
    }
    name=wcsrchr(image,L'\\');ZeroMemory(file,sizeof(file));
    if(!WideCharToMultiByte(CP_UTF8,0,name?name+1:image,-1,file,sizeof(file)-1,NULL,NULL))lstrcpyA(file,"unnamed");
    wsprintfA(row,"screen_saver_image_%s",file);wl_log(row,0);
    wl_log(place==WlSaverLogonDesktop?"screen_saver_started_logon_desktop":place==WlSaverLocked?
           "screen_saver_started_locked":"screen_saver_started_session",saver.pid);
    wl_log("screen_saver_secure",secure);
    return TRUE;
}

/* Back from a saver that could not start: never leave the saver desktop showing. A secure
   session saver that cannot run still protects the session: it locks. */
static void start_failed(WL_SAVER_PLACE place,unsigned secure,DWORD error)
{
    wl_log("screen_saver_start_failed",error);
    if(place==WlSaverSession&&secure){lock_session("screen_saver_secure_lock_without_saver");return;}
    if(place==WlSaverSession?!wl_switch_user():!wl_switch_secure())wl_fail("screen_saver_return_failed",GetLastError());
}

static BOOL attempt(WL_SAVER_PLACE place,unsigned request)
{
    WL_SAVER_SETTINGS settings;WCHAR image[MAX_PATH];unsigned secure;BOOL allowed,ginasecure;WL_SAVER_ACTION action;DWORD error;
    if(!read_settings(place,&settings,image)&&settings.active&&request!=WL_SAVER_REQUEST_MONITOR_OFF){
        not_started("screen_saver_image_unavailable");return FALSE;
    }
    if(!wl_saver_consult(place,request,&settings,&secure)){
        if(request!=WL_SAVER_REQUEST_SECURE_ONLY)not_started("screen_saver_not_configured");
        return FALSE;
    }
    /* WLX 1.1: the GINA may decline the saver and decides whether it is secure (MSGINA:
       a secure saver is a lock, so it is secure only when WlxIsLockOk). */
    ginasecure=secure?TRUE:FALSE;
    if(wl.gina.screen_saver)allowed=wl.gina.screen_saver(wl.gina_context,&ginasecure);
    else{allowed=TRUE;if(ginasecure)ginasecure=wl.gina.lock_ok(wl.gina_context);}
    action=wl_saver_decide(place,request,allowed,ginasecure?1u:0u);
    if(action==WlSaverIgnore){not_started(allowed?"screen_saver_secure_only":"screen_saver_gina_declined");return FALSE;}
    if(action==WlSaverLockNow){lock_session("screen_saver_monitor_off_lock");return TRUE;}
    secure=place==WlSaverSession&&ginasecure?1u:0u;
    if(launch(place,secure,image))return TRUE;
    error=GetLastError();start_failed(place,secure,error?error:ERROR_GEN_FAILURE);return FALSE;
}

BOOL wl_saver_active(void){return saver.process!=NULL;}

void wl_saver_notice(DWORD request)
{
    WL_SAVER_PLACE place;WL_SAVER_SETTINGS settings;WCHAR image[MAX_PATH];unsigned secure,wanted;
    if(saver.process){++saver.notices;saver.last_notice=GetTickCount();return;}
    place=wl_saver_place(wl.machine.phase);
    if(place==WlSaverNowhere){not_started("screen_saver_phase_busy");return;}
    if(wl.dialog){
        /* A GINA dialog is up (the logon dialog, the locked notice). WLX: the dialog sees the
           screen-saver notice first; one that does not handle it ends with
           WLX_DLG_SCREEN_SAVER_TIMEOUT. The saver starts once the GINA call has returned. */
        if(wl.dialog==saver.interrupted)return;
        read_settings(place,&settings,image);
        if(!wl_saver_consult(place,request,&settings,&secure)){not_started("screen_saver_not_configured");return;}
        saver.interrupted=wl.dialog;saver.wanted=1;
        wl_log("screen_saver_dialog_interrupted",request);
        SendMessageW(wl.dialog,WLX_WM_SAS,WLX_SAS_TYPE_SCRNSVR_TIMEOUT,0);
        return;
    }
    if(wl.in_gina){not_started("screen_saver_gina_busy");return;}
    wanted=saver.wanted;saver.wanted=0;saver.interrupted=NULL;
    /* A locked notice that ended for this saver (MSGINA ends it itself) comes back if the
       saver cannot run. At the logon desktop the GINA's caller shows its notice again. */
    if(!attempt(place,request)&&wanted&&place==WlSaverLocked)wl.gina.locked_notice(wl.gina_context);
}

/* The GINA call that showed an interrupted dialog has returned, and the SAS notice or the
   locked notice is about to be shown again (without Ctrl+Alt+Del either one at once brings
   back the dialog): show the saver instead. TRUE when a saver runs; its end shows the notice. */
BOOL wl_saver_resume(void)
{
    WL_SAVER_PLACE place;
    if(saver.process)return TRUE;
    if(!saver.wanted)return FALSE;
    saver.wanted=0;saver.interrupted=NULL;
    place=wl_saver_place(wl.machine.phase);
    return (place==WlSaverLogonDesktop||place==WlSaverLocked)&&attempt(place,WL_SAVER_REQUEST_START);
}

void wl_saver_ended(DWORD generation)
{
    DWORD code;WL_SAVER_PLACE place=saver.place;unsigned secure=saver.secure;
    if(!saver.process||(LONG)generation!=saver.generation)return;
    code=release_saver();wl_log("screen_saver_ended",code);
    switch(wl_saver_return(place,secure)){
    case WlSaverLockSession:
        if(wl.machine.phase!=WlInteractive)wl_fail("screen_saver_secure_phase_changed",ERROR_INVALID_STATE);
        lock_session("screen_saver_secure_lock");break;
    case WlSaverBackToDesktop:
        if(wl.machine.phase==WlInteractive&&wl_switch_user()){wl_log("screen_saver_returned_to_desktop",0);break;}
        wl_log("screen_saver_desktop_return_failed",GetLastError());lock_session("screen_saver_lock_after_failed_return");break;
    case WlSaverBackToLocked:
        if(!wl_switch_secure())wl_fail("screen_saver_return_failed",GetLastError());
        wl_log("screen_saver_returned_to_locked",0);wl.gina.locked_notice(wl.gina_context);break;
    default:
        if(!wl_switch_secure())wl_fail("screen_saver_return_failed",GetLastError());
        wl_log("screen_saver_returned_to_logon",0);
        if(!PostMessageW(wl.window,WL_APP_NOTICE,100,0))wl_fail("screen_saver_logon_notice_failed",GetLastError());
    }
    wl_session_poll_shell();
}

/* Before a SAS, a lock, a logoff or a power request: end a running saver. TRUE when it was
   a secure session saver, which the caller must lock before anything else happens. */
BOOL wl_saver_stop(const char *reason)
{
    BOOL secure=saver.process&&saver.place==WlSaverSession&&saver.secure;
    saver.wanted=0;saver.interrupted=NULL;
    if(!saver.process)return FALSE;
    if(WaitForSingleObject(saver.process,0)!=WAIT_OBJECT_0&&
       (!TerminateProcess(saver.process,ERROR_CANCELLED)||WaitForSingleObject(saver.process,10000)!=WAIT_OBJECT_0))
        wl_fail("screen_saver_stop_failed",GetLastError());
    wl_log(reason,saver.pid);release_saver();
    return secure;
}
