/* XP25 original implementation of documented registry notification packages. */
#include "platform.h"

typedef VOID (WINAPI *NOTIFY_HANDLER)(PWLX_NOTIFICATION_INFO);
typedef BOOL (WINAPI *GINA_STATUS)(PVOID,HDESK,DWORD,PWSTR,PWSTR);
typedef struct WL_NOTIFY_JOB {
    struct WL_NOTIFY_JOB *next;
    HANDLE thread;
    HMODULE module;
    NOTIFY_HANDLER callback;
    BOOL impersonate;
    DWORD result;
    WLX_NOTIFICATION_INFO info;
    WCHAR user[256],domain[256];
} WL_NOTIFY_JOB;
static WL_NOTIFY_JOB *jobs;
static volatile LONG status_shown;

static DWORD status_message(BOOL verbose,LPWSTR message)
{
    GINA_STATUS display;
    if(!wl.gina_module||!wl.gina_context)return ERROR_NOT_READY;
    display=(GINA_STATUS)GetProcAddress(wl.gina_module,"WlxDisplayStatusMessage");
    if(!display)return ERROR_PROC_NOT_FOUND;
    if(!display(wl.gina_context,wl.secure,verbose?0:STATUSMSG_OPTION_NOANIMATION,L"Windows XP 25th Anniversary Edition",message))return GetLastError();
    InterlockedExchange((LONG*)&status_shown,1);return ERROR_SUCCESS;
}

void wl_status_clear(void)
{
    BOOL (WINAPI *remove)(PVOID);
    /* MSGINA keeps a displayed status dialog until the host removes it. */
    if(!InterlockedExchange((LONG*)&status_shown,0)||!wl.gina_module)return;
    remove=(BOOL(WINAPI*)(PVOID))GetProcAddress(wl.gina_module,"WlxRemoveStatusMessage");
    wl_log("status_message_removed",remove&&remove(wl.gina_context)?0:GetLastError());
}

static DWORD WINAPI notify_worker(PVOID parameter)
{
    WL_NOTIFY_JOB *job=parameter;BOOL impersonated=FALSE;
    if(job->impersonate&&job->info.hToken){
        if(!ImpersonateLoggedOnUser(job->info.hToken)){job->result=GetLastError();return job->result;}
        impersonated=TRUE;
    }
    job->callback(&job->info);
    if(impersonated&&!RevertToSelf()){job->result=GetLastError();wl_fail("notification_revert_failed",job->result);}
    return job->result;
}

static void release_job(WL_NOTIFY_JOB *job)
{
    if(job->thread)CloseHandle(job->thread);
    if(job->info.hToken)CloseHandle(job->info.hToken);
    if(job->module)FreeLibrary(job->module);
    LocalFree(job);
}

static BOOL wait_jobs(BOOL user_only)
{
    WL_NOTIFY_JOB *job,**link=&jobs;DWORD result,started,elapsed;MSG message;
    while(*link){
        job=*link;
        /* Startup jobs own no user token or profile. Retain their worker and
           module until a machine-wide join; user rollback must not join them. */
        if(user_only&&!job->info.hToken){link=&job->next;continue;}
        started=GetTickCount();
        /* Notification packages can synchronously send to this GUI thread.
           Service sent messages while joining, without dispatching posted SAS
           or user input and reentering authentication/cleanup. */
        for(;;){
            elapsed=GetTickCount()-started;
            if(elapsed>=120000){result=WAIT_TIMEOUT;break;}
            result=MsgWaitForMultipleObjects(1,&job->thread,FALSE,120000-elapsed,QS_SENDMESSAGE);
            if(result!=WAIT_OBJECT_0+1)break;
            PeekMessageW(&message,NULL,0,0,PM_NOREMOVE);
        }
        if(result!=WAIT_OBJECT_0){SetLastError(result==WAIT_TIMEOUT?ERROR_TIMEOUT:GetLastError());return FALSE;}
        if(job->result){SetLastError(job->result);return FALSE;}
        *link=job->next;release_job(job);
    }
    return TRUE;
}

BOOL wl_notifications_wait(void){return wait_jobs(FALSE);}
BOOL wl_notifications_wait_user(void){return wait_jobs(TRUE);}

static LONG registry_string(HKEY key,LPCWSTR name,WCHAR *buffer,DWORD capacity)
{
    DWORD bytes=capacity*sizeof(WCHAR),type;LONG error;
    error=RegQueryValueExW(key,name,NULL,&type,(BYTE*)buffer,&bytes);
    if(error)return error;
    if((type!=REG_SZ&&type!=REG_EXPAND_SZ)||bytes<sizeof(WCHAR)||bytes>capacity*sizeof(WCHAR)||
       bytes%sizeof(WCHAR)||buffer[bytes/sizeof(WCHAR)-1])return ERROR_INVALID_DATA;
    if(type==REG_EXPAND_SZ){WCHAR expanded[MAX_PATH];DWORD count=ExpandEnvironmentStringsW(buffer,expanded,MAX_PATH);
        if(!count||count>MAX_PATH||count>capacity)return ERROR_BUFFER_OVERFLOW;lstrcpyW(buffer,expanded);}
    return ERROR_SUCCESS;
}

static LONG registry_boolean(HKEY key,LPCWSTR name,BOOL *value)
{
    DWORD bytes=sizeof(DWORD),type,data;LONG error;
    *value=FALSE;error=RegQueryValueExW(key,name,NULL,&type,(BYTE*)&data,&bytes);
    if(error==ERROR_FILE_NOT_FOUND)return ERROR_SUCCESS;
    if(error)return error;
    if(type!=REG_DWORD||bytes!=sizeof(DWORD)||data>1)return ERROR_INVALID_DATA;
    *value=data!=0;return ERROR_SUCCESS;
}

BOOL wl_notify(LPCWSTR event)
{
    HKEY root,key;WCHAR package[128],module[MAX_PATH],path[MAX_PATH],function[128];char entry[128];
    DWORD index=0,chars;LONG error;BOOL async=FALSE,impersonate=FALSE,used;WL_NOTIFY_JOB *job;
    error=RegOpenKeyExW(HKEY_LOCAL_MACHINE,WL_WINLOGON_KEY L"\\Notify",0,KEY_READ,&root);
    if(error==ERROR_FILE_NOT_FOUND)return TRUE;
    if(error){SetLastError(error);return FALSE;}
    if(lstrcmpW(event,L"Logoff")==0&&!wl_notifications_wait_user()){RegCloseKey(root);return FALSE;}
    for(;;){
        chars=128;error=RegEnumKeyExW(root,index++,package,&chars,NULL,NULL,NULL,NULL);
        if(error==ERROR_NO_MORE_ITEMS){RegCloseKey(root);return TRUE;}
        if(error)break;
        error=RegOpenKeyExW(root,package,0,KEY_READ,&key);if(error)break;
        error=registry_string(key,event,function,128);
        if(error==ERROR_FILE_NOT_FOUND){RegCloseKey(key);continue;}
        if(!error)error=registry_string(key,L"DLLName",module,MAX_PATH);
        if(!error)error=registry_boolean(key,L"Asynchronous",&async);
        if(!error)error=registry_boolean(key,L"Impersonate",&impersonate);
        RegCloseKey(key);if(error)break;
        used=FALSE;
        if(!WideCharToMultiByte(CP_ACP,WC_NO_BEST_FIT_CHARS,function,-1,entry,sizeof(entry),NULL,&used)||used){error=ERROR_NO_UNICODE_TRANSLATION;break;}
        if(wcschr(module,L'\\')||wcschr(module,L'/')||wcschr(module,L':')){
            if(lstrlenW(module)<3||module[1]!=L':'||module[2]!=L'\\'){error=ERROR_BAD_PATHNAME;break;}
            lstrcpyW(path,module);
        }else{
            if(!GetSystemDirectoryW(path,MAX_PATH)||lstrlenW(path)+lstrlenW(module)+2>=MAX_PATH){error=ERROR_BUFFER_OVERFLOW;break;}
            lstrcatW(path,L"\\");lstrcatW(path,module);
        }
        job=LocalAlloc(LPTR,sizeof(*job));if(!job){error=ERROR_NOT_ENOUGH_MEMORY;break;}
        job->module=LoadLibraryW(path);
        if(!job->module){error=GetLastError();release_job(job);break;}
        job->callback=(NOTIFY_HANDLER)GetProcAddress(job->module,entry);
        if(!job->callback){error=GetLastError();release_job(job);break;}
        job->impersonate=impersonate;job->info.Size=sizeof(job->info);
        if(wl.token){
            if(!DuplicateHandle(GetCurrentProcess(),wl.token,GetCurrentProcess(),&job->info.hToken,0,FALSE,DUPLICATE_SAME_ACCESS)){
                error=GetLastError();release_job(job);break;}
            lstrcpyW(job->user,wl.username);lstrcpyW(job->domain,wl.domain);job->info.UserName=job->user;job->info.Domain=job->domain;
        }
        job->info.WindowStation=L"WinSta0";job->info.hDesktop=wl.machine.phase==WlInteractive?wl.application:wl.secure;
        job->info.pStatusCallback=status_message;wl_log(entry,0);
        if(async&&lstrcmpW(event,L"Logoff")!=0&&lstrcmpW(event,L"Shutdown")!=0){
            job->thread=CreateThread(NULL,0,notify_worker,job,0,NULL);
            if(!job->thread){error=GetLastError();release_job(job);break;}
            job->next=jobs;jobs=job;
        }else{
            error=(LONG)notify_worker(job);release_job(job);if(error)break;
        }
    }
    RegCloseKey(root);SetLastError(error);wl_log("notification_failed",error);return FALSE;
}

void wl_notifications_probe(void)
{
    HKEY root,key;WCHAR name[128],dll[MAX_PATH];DWORD index=0,count;char row[256];LONG error;
    wl_log("probe_begin_no_registration",0);
    error=RegOpenKeyExW(HKEY_LOCAL_MACHINE,WL_WINLOGON_KEY L"\\Notify",0,KEY_READ,&root);
    if(error){wl_log("notify_inventory_open",error);return;}
    for(;;){
        count=128;error=RegEnumKeyExW(root,index++,name,&count,NULL,NULL,NULL,NULL);if(error==ERROR_NO_MORE_ITEMS)break;
        if(error){wl_log("notify_inventory_enumeration",error);break;}
        if(RegOpenKeyExW(root,name,0,KEY_READ,&key)==0){
            if(registry_string(key,L"DLLName",dll,MAX_PATH)==0){
                if(WideCharToMultiByte(CP_UTF8,0,dll,-1,row,sizeof(row),NULL,NULL)){row[127]=0;wl_log(row,0);}
            }
            RegCloseKey(key);
        }
    }
    RegCloseKey(root);
}
