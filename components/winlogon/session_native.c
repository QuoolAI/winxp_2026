#define WINVER 0x0501
#define _WIN32_WINNT 0x0501
#define UNICODE
#define _UNICODE
#include "session_native.h"
#include "environment.h"
#include <tlhelp32.h>

PVOID wl_copy_user_environment(PVOID environment)
{
    MEMORY_BASIC_INFORMATION memory;SIZE_T bytes;unsigned capacity,at=0,names,values;int status;
    const unsigned short *name,*value;PVOID copy;
    if(!environment||!VirtualQuery(environment,&memory,sizeof(memory))||memory.State!=MEM_COMMIT){SetLastError(ERROR_INVALID_DATA);return NULL;}
    bytes=memory.RegionSize-((BYTE*)environment-(BYTE*)memory.BaseAddress);
    if(bytes>32767*sizeof(WCHAR))bytes=32767*sizeof(WCHAR);
    capacity=(unsigned)(bytes/sizeof(WCHAR));
    while((status=wl_environment_next(environment,capacity,&at,&name,&names,&value,&values))==1){}
    if(status<0){SetLastError(ERROR_INVALID_DATA);return NULL;}
    bytes=(at?at+1:2)*sizeof(WCHAR);
    copy=VirtualAlloc(NULL,bytes,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    if(copy)CopyMemory(copy,environment,bytes);return copy;
}
static PVOID information(HANDLE token,TOKEN_INFORMATION_CLASS kind)
{
    DWORD bytes=0,error;PVOID p;
    GetTokenInformation(token,kind,NULL,0,&bytes);if(!bytes)return NULL;
    p=LocalAlloc(LPTR,bytes);if(!p)return NULL;
    if(!GetTokenInformation(token,kind,p,bytes,&bytes)){error=GetLastError();LocalFree(p);SetLastError(error);return NULL;}
    return p;
}
BOOL wl_same_logon(HANDLE reference,HANDLE candidate)
{
    TOKEN_STATISTICS a,b;DWORD bytes,sa,sb,i,j;TOKEN_USER *ua=NULL,*ub=NULL;
    TOKEN_GROUPS *ga=NULL,*gb=NULL;BOOL ok=FALSE,found=FALSE;
    if(!GetTokenInformation(reference,TokenStatistics,&a,sizeof(a),&bytes)||
       !GetTokenInformation(candidate,TokenStatistics,&b,sizeof(b),&bytes)||
       !GetTokenInformation(reference,TokenSessionId,&sa,sizeof(sa),&bytes)||
       !GetTokenInformation(candidate,TokenSessionId,&sb,sizeof(sb),&bytes))return FALSE;
    if(a.TokenType!=TokenPrimary||b.TokenType!=TokenPrimary||sa!=sb||
       a.AuthenticationId.LowPart!=b.AuthenticationId.LowPart||a.AuthenticationId.HighPart!=b.AuthenticationId.HighPart){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
    ua=information(reference,TokenUser);ub=information(candidate,TokenUser);
    ga=information(reference,TokenGroups);gb=information(candidate,TokenGroups);
    if(!ua||!ub||!ga||!gb)goto done;
    if(IsWellKnownSid(ua->User.Sid,WinLocalSystemSid)||!EqualSid(ua->User.Sid,ub->User.Sid))goto done;
    for(i=0;i<ga->GroupCount;++i)if((ga->Groups[i].Attributes&SE_GROUP_LOGON_ID)==SE_GROUP_LOGON_ID)
        for(j=0;j<gb->GroupCount;++j)if((gb->Groups[j].Attributes&SE_GROUP_LOGON_ID)==SE_GROUP_LOGON_ID&&
            EqualSid(ga->Groups[i].Sid,gb->Groups[j].Sid))found=TRUE;
    ok=found;
done:
    if(ua)LocalFree(ua);if(ub)LocalFree(ub);if(ga)LocalFree(ga);if(gb)LocalFree(gb);
    if(!ok)SetLastError(ERROR_ACCESS_DENIED);return ok;
}
DWORD wl_user_process_exited(HANDLE process)
{
    DWORD result;if(!process)return ERROR_INVALID_HANDLE;
    result=WaitForSingleObject(process,0);
    if(result==WAIT_OBJECT_0)return 0;
    if(result==WAIT_TIMEOUT)return ERROR_BUSY;
    return GetLastError();
}
BOOL wl_watch_user_process(HANDLE token,DWORD pid,LPCWSTR image,HANDLE *result)
{
    HANDLE process=NULL,primary=NULL,snapshot=INVALID_HANDLE_VALUE;MODULEENTRY32W module;DWORD error;BOOL ok=FALSE;
    if(!result||*result||!pid||!image){SetLastError(ERROR_INVALID_PARAMETER);return FALSE;}
    process=OpenProcess(PROCESS_QUERY_INFORMATION|SYNCHRONIZE,FALSE,pid);if(!process)return FALSE;
    if(WaitForSingleObject(process,0)!=WAIT_TIMEOUT){SetLastError(ERROR_PROCESS_ABORTED);goto done;}
    if(!OpenProcessToken(process,TOKEN_QUERY,&primary)||!wl_same_logon(token,primary))goto done;
    snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,pid);if(snapshot==INVALID_HANDLE_VALUE)goto done;
    ZeroMemory(&module,sizeof(module));module.dwSize=sizeof(module);
    if(!Module32FirstW(snapshot,&module))goto done;
    if(lstrcmpiW(module.szExePath,image)){SetLastError(ERROR_ACCESS_DENIED);goto done;}
    if(WaitForSingleObject(process,0)!=WAIT_TIMEOUT){SetLastError(ERROR_PROCESS_ABORTED);goto done;}
    *result=process;process=NULL;ok=TRUE;
done:
    error=GetLastError();if(snapshot!=INVALID_HANDLE_VALUE)CloseHandle(snapshot);
    if(primary)CloseHandle(primary);if(process)CloseHandle(process);SetLastError(error);return ok;
}
BOOL wl_spawn_user_process(HANDLE token,LPCWSTR image,LPWSTR command,LPWSTR desktop,PVOID environment,PROCESS_INFORMATION *result)
{
    STARTUPINFOW startup;HANDLE primary=NULL;DWORD error;BOOL ok=FALSE;
    if(!result){SetLastError(ERROR_INVALID_PARAMETER);return FALSE;}
    ZeroMemory(result,sizeof(*result));
    if(!image||lstrlenW(image)<4||image[1]!=L':'||image[2]!=L'\\'||!desktop||!environment){SetLastError(ERROR_INVALID_PARAMETER);return FALSE;}
    ZeroMemory(&startup,sizeof(startup));startup.cb=sizeof(startup);startup.lpDesktop=desktop;
    if(!CreateProcessAsUserW(token,image,command,NULL,NULL,FALSE,CREATE_UNICODE_ENVIRONMENT|CREATE_SUSPENDED,
        environment,NULL,&startup,result))return FALSE;
    if(!OpenProcessToken(result->hProcess,TOKEN_QUERY,&primary)||!wl_same_logon(token,primary))goto done;
    if(ResumeThread(result->hThread)==(DWORD)-1)goto done;
    ok=TRUE;
done:
    error=GetLastError();if(primary)CloseHandle(primary);
    if(!ok){
        /* This is our own newly-created suspended child, never another session. */
        if(!TerminateProcess(result->hProcess,ERROR_ACCESS_DENIED)||WaitForSingleObject(result->hProcess,10000)!=WAIT_OBJECT_0){
            SetLastError(ERROR_PROCESS_ABORTED);return FALSE; /* retain handles */
        }
        CloseHandle(result->hThread);CloseHandle(result->hProcess);ZeroMemory(result,sizeof(*result));
    }
    SetLastError(error);return ok;
}
