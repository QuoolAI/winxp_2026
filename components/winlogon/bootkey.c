/* Original XP25 LPC endpoint for the existing NT 5.1 LSASS startup-key client.
   Stored mode only. Keys never enter logs, files, window messages or test output. */
#include "platform.h"
#include "bootkey_codec.h"
#define STATUS_OK ((LONG)0)
#define STATUS_FAILED ((LONG)0xc0000001L)
#define STATUS_DENIED ((LONG)0xc0000022L)
#define STATUS_PARAMETER ((LONG)0xc000000dL)
#define STATUS_UNSUPPORTED ((LONG)0xc00000bbL)
typedef struct {USHORT length,maximum;PWSTR buffer;} WL_NT_STRING;
typedef struct {ULONG length;HANDLE root;WL_NT_STRING *name;ULONG flags;PVOID descriptor,qos;} WL_NT_OBJECT;
/* NT PORT_MESSAGE forces eight-byte alignment with a double union. The outer
   Wx record therefore has four trailing padding bytes: 64, not 60, bytes. */
typedef struct {USHORT data,total,type,offset;union {struct {HANDLE process,thread;} id;double alignment;} client;ULONG id,view;} WL_PORT_HEADER;
typedef struct {WL_PORT_HEADER header;LONG status;ULONG api;ULONG auth,capacity,used;BYTE key[16];} WL_KEY_MESSAGE;
typedef char WL_PORT_ABI[(sizeof(WL_PORT_HEADER)==24&&sizeof(WL_KEY_MESSAGE)==64)?1:-1];
typedef LONG (NTAPI *CREATE_PORT)(PHANDLE,WL_NT_OBJECT*,ULONG,ULONG,ULONG);
typedef LONG (NTAPI *RECEIVE_PORT)(HANDLE,PVOID*,WL_PORT_HEADER*,WL_PORT_HEADER*);
typedef LONG (NTAPI *ACCEPT_PORT)(PHANDLE,PVOID,WL_PORT_HEADER*,BYTE,PVOID,PVOID);
typedef LONG (NTAPI *COMPLETE_PORT)(HANDLE);
typedef LONG (NTAPI *REPLY_PORT)(HANDLE,WL_PORT_HEADER*);
typedef LONG (NTAPI *IMPERSONATE_PORT)(HANDLE,WL_PORT_HEADER*);
static HANDLE listener,ready;
static CREATE_PORT create_port;static RECEIVE_PORT receive_port;static ACCEPT_PORT accept_port;
static COMPLETE_PORT complete_port;static REPLY_PORT reply_port;static IMPERSONATE_PORT impersonate_port;

BOOL wl_wait_sam(void)
{
    LONG (NTAPI *open_event)(PHANDLE,ULONG,WL_NT_OBJECT*);WL_NT_STRING name;WL_NT_OBJECT object;
    HANDLE event=NULL;LONG status;DWORD started=GetTickCount(),elapsed,result;
    open_event=(LONG(NTAPI*)(PHANDLE,ULONG,WL_NT_OBJECT*))GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtOpenEvent");
    if(!open_event){SetLastError(ERROR_PROC_NOT_FOUND);return FALSE;}
    name.buffer=L"\\SAM_SERVICE_STARTED";name.length=(USHORT)(lstrlenW(name.buffer)*sizeof(WCHAR));name.maximum=name.length+sizeof(WCHAR);
    ZeroMemory(&object,sizeof(object));object.length=sizeof(object);object.name=&name;
    do{
        status=open_event(&event,SYNCHRONIZE,&object);
        if(status>=0)break;
        if(status!=(LONG)0xc0000034L){SetLastError(LsaNtStatusToWinError(status));return FALSE;}
        Sleep(100);
    }while(GetTickCount()-started<60000);
    if(!event){SetLastError(ERROR_TIMEOUT);return FALSE;}
    elapsed=GetTickCount()-started;result=WaitForSingleObject(event,elapsed<60000?60000-elapsed:0);CloseHandle(event);
    if(result!=WAIT_OBJECT_0){SetLastError(result==WAIT_TIMEOUT?ERROR_TIMEOUT:GetLastError());return FALSE;}
    wl_log("sam_ready",0);return TRUE;
}

static LONG read_stored_key(BYTE key[16])
{
    static const WCHAR *names[]={L"JD",L"Skew1",L"GBG",L"Data"};HKEY root,part;
    DWORD size,type,mode,bytes;LONG error;unsigned i;char text[4][9];const char *classes[4];
    ZeroMemory(text,sizeof(text));ZeroMemory(key,16);
    error=RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Control\\Lsa",0,KEY_READ,&root);
    if(error)return STATUS_DENIED;
    bytes=sizeof(mode);error=RegQueryValueExW(root,L"SecureBoot",NULL,&type,(BYTE*)&mode,&bytes);
    if(error||type!=REG_DWORD||bytes!=sizeof(mode)||mode!=1){RegCloseKey(root);return STATUS_UNSUPPORTED;}
    for(i=0;i<4;++i){
        error=RegOpenKeyExW(root,names[i],0,KEY_READ,&part);if(error)break;
        size=sizeof(text[i]);error=RegQueryInfoKeyA(part,text[i],&size,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL);RegCloseKey(part);
        if(error||size!=8){error=ERROR_INVALID_DATA;break;}classes[i]=text[i];
    }
    RegCloseKey(root);
    if(!error&&!wl_decode_boot_classes(classes,key))error=ERROR_INVALID_DATA;
    SecureZeroMemory(text,sizeof(text));
    if(error){SecureZeroMemory(key,16);return STATUS_FAILED;}
    return STATUS_OK;
}

static BOOL trusted_request(HANDLE client,WL_KEY_MESSAGE *message)
{
    HANDLE token;TOKEN_USER *user;DWORD bytes=0,session;BOOL ok=FALSE;
    if((DWORD)(ULONG_PTR)message->header.client.id.process!=wl.lsa_pid||!wl.lsa_pid)return FALSE;
    if(impersonate_port(client,&message->header)<0)return FALSE;
    if(OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,TRUE,&token)){
        GetTokenInformation(token,TokenUser,NULL,0,&bytes);user=LocalAlloc(LPTR,bytes);
        if(user){
            ok=GetTokenInformation(token,TokenUser,user,bytes,&bytes)&&IsWellKnownSid(user->User.Sid,WinLocalSystemSid);
            if(ok)ok=GetTokenInformation(token,TokenSessionId,&session,sizeof(session),&bytes)&&session==wl.session_id;
            LocalFree(user);
        }
        CloseHandle(token);
    }
    if(!RevertToSelf())wl_fail("startup_key_revert_failed",GetLastError());
    return ok;
}

static DWORD WINAPI key_worker(PVOID ignored)
{
    HANDLE client=NULL,rejected=NULL;PVOID context=NULL;WL_KEY_MESSAGE message;LONG status;BOOL done=FALSE;
    UNREFERENCED_PARAMETER(ignored);SetEvent(ready);
    for(;;){
        ZeroMemory(&message,sizeof(message));status=receive_port(listener,&context,NULL,&message.header);
        if(status<0){wl_fail("startup_key_receive_failed",(DWORD)status);}
        if((message.header.type&0xff)==10){
            if(client||(DWORD)(ULONG_PTR)message.header.client.id.process!=wl.lsa_pid||!wl.lsa_pid){
                accept_port(&rejected,NULL,&message.header,FALSE,NULL,NULL);if(rejected){CloseHandle(rejected);rejected=NULL;}continue;
            }
            status=accept_port(&client,&client,&message.header,TRUE,NULL,NULL);
            if(status<0||complete_port(client)<0)wl_fail("startup_key_connect_failed",(DWORD)status);
        }else if((message.header.type&0xff)==1){
            message.status=STATUS_PARAMETER;
            if(message.header.total==sizeof(message)&&message.header.data==sizeof(message)-sizeof(message.header)){
                if(!trusted_request(client,&message))message.status=STATUS_DENIED;
                else if(message.api==0){
                    if(message.auth==1&&message.capacity==16){message.status=read_stored_key(message.key);if(message.status>=0)message.used=16;}
                    else message.status=STATUS_UNSUPPORTED;
                }else if(message.api==1){
                    /* The client reports actual cipher authentication results. Never replace failure with success. */
                    message.status=(LONG)message.auth;
                    wl_log("lsa_startup_key_result",(DWORD)message.status);done=message.status>=0;
                }
            }
            status=reply_port(client,&message.header);SecureZeroMemory(&message,sizeof(message));
            if(status<0)wl_fail("startup_key_reply_failed",(DWORD)status);
        }else if((message.header.type&0xff)==5){
            if(client)CloseHandle(client);CloseHandle(listener);listener=NULL;
            if(!done)wl_fail("startup_key_client_left_unverified",ERROR_LOGON_FAILURE);
            wl_log("startup_key_channel_complete",0);return 0;
        }else{
            wl_fail("startup_key_message_unsupported",ERROR_NOT_SUPPORTED);
        }
    }
}

BOOL wl_bootkey_start(void)
{
    HMODULE nt=GetModuleHandleW(L"ntdll.dll");HANDLE thread;WL_NT_STRING name;WL_NT_OBJECT object;
    PSECURITY_DESCRIPTOR descriptor=NULL;LONG status;DWORD result;
#define NT_LOAD(field,type,name) {field=(type)GetProcAddress(nt,name);if(!field){SetLastError(ERROR_PROC_NOT_FOUND);return FALSE;}}
    NT_LOAD(create_port,CREATE_PORT,"NtCreatePort");NT_LOAD(receive_port,RECEIVE_PORT,"NtReplyWaitReceivePort");
    NT_LOAD(accept_port,ACCEPT_PORT,"NtAcceptConnectPort");NT_LOAD(complete_port,COMPLETE_PORT,"NtCompleteConnectPort");
    NT_LOAD(reply_port,REPLY_PORT,"NtReplyPort");NT_LOAD(impersonate_port,IMPERSONATE_PORT,"NtImpersonateClientOfPort");
#undef NT_LOAD
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)",1,&descriptor,NULL))return FALSE;
    name.buffer=L"\\Security\\WxApiPort";name.length=(USHORT)(lstrlenW(name.buffer)*sizeof(WCHAR));name.maximum=name.length+sizeof(WCHAR);
    ZeroMemory(&object,sizeof(object));object.length=sizeof(object);object.name=&name;object.descriptor=descriptor;
    status=create_port(&listener,&object,sizeof(ULONG),sizeof(WL_KEY_MESSAGE),sizeof(WL_KEY_MESSAGE));LocalFree(descriptor);
    if(status<0){wl_log("startup_key_port_create_failed",(DWORD)status);SetLastError(ERROR_GEN_FAILURE);return FALSE;}
    ready=CreateEventW(NULL,TRUE,FALSE,NULL);if(!ready)return FALSE;
    thread=CreateThread(NULL,0,key_worker,NULL,0,NULL);if(!thread)return FALSE;
    result=WaitForSingleObject(ready,10000);CloseHandle(thread);CloseHandle(ready);ready=NULL;
    if(result!=WAIT_OBJECT_0){SetLastError(ERROR_TIMEOUT);return FALSE;}
    wl_log("startup_key_port_ready",0);return TRUE;
}
