/* Remote Registry lifecycle and loopback RPC checks in a disposable XP guest. */
#define WINVER 0x0501
#define _WIN32_WINNT 0x0501
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>

static HANDLE serial;
static unsigned failures;
static void emit(const char *s) { DWORD n; WriteFile(serial,s,lstrlenA(s),&n,NULL); }
static void report(const char *name, BOOL ok, DWORD error)
{
    char s[220]; if(!ok)++failures;
    wsprintfA(s,"{\"regsvc_case\":\"%s\",\"status\":\"%s\",\"error\":%lu}\r\n",name,ok?"pass":"fail",ok?0:error);emit(s);
}
static BOOL wait_state(SC_HANDLE service, DWORD wanted, SERVICE_STATUS_PROCESS *status)
{
    DWORD size,start=GetTickCount();
    do {
        if(!QueryServiceStatusEx(service,SC_STATUS_PROCESS_INFO,(BYTE*)status,sizeof(*status),&size))return FALSE;
        if(status->dwCurrentState==wanted)return TRUE;
        Sleep(100);
    }while(GetTickCount()-start<15000);
    return FALSE;
}
static void module(DWORD pid)
{
    HANDLE snapshot,process=NULL,token=NULL;TOKEN_PRIVILEGES privileges={0};
    MODULEENTRY32 entry={0};BOOL found=FALSE,read=FALSE;DWORD offset=0,checksum=0;SIZE_T size;
    if(OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&token)){
        privileges.PrivilegeCount=1;privileges.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
        if(LookupPrivilegeValueA(NULL,SE_DEBUG_NAME,&privileges.Privileges[0].Luid))AdjustTokenPrivileges(token,FALSE,&privileges,0,NULL,NULL);
        CloseHandle(token);
    }
    snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,pid);
    entry.dwSize=sizeof(entry);
    if(snapshot!=INVALID_HANDLE_VALUE&&Module32First(snapshot,&entry))do {
        if(lstrcmpiA(entry.szModule,"regsvc.dll")==0){found=TRUE;break;}
    }while(Module32Next(snapshot,&entry));
    if(found)process=OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION,FALSE,pid);
    if(process){
        read=ReadProcessMemory(process,entry.modBaseAddr+60,&offset,4,&size)&&size==4&&
             ReadProcessMemory(process,entry.modBaseAddr+offset+24+64,&checksum,4,&size)&&size==4;
        CloseHandle(process);
    }
    {char s[200];wsprintfA(s,"{\"regsvc_image_identity\":true,\"pid\":%lu,\"found\":%u,\"read\":%u,\"pe_checksum\":%lu}\r\n",pid,found,read,checksum);emit(s);}
    report("service_module_mapped",found&&read,GetLastError());
    if(snapshot!=INVALID_HANDLE_VALUE)CloseHandle(snapshot);
}
static void rpc(BOOL stopped)
{
    HKEY remote=NULL,key=NULL,local=NULL;LONG error;DWORD type,size,value=0,expected=0x2551;
    WCHAR oldname[128]={0},newname[128]={0};BOOL unused=FALSE;unsigned before=failures;
    /* Dot selects the local named-pipe endpoint without requiring an SMB redirector. */
    error=RegConnectRegistryW(L"\\\\.",HKEY_LOCAL_MACHINE,&remote);
    if(stopped){
        if(!error)error=RegOpenKeyExW(remote,L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",0,KEY_QUERY_VALUE,&key);
        if(key)RegCloseKey(key);
        if(remote)RegCloseKey(remote);
        report("rpc_stopped_service_rejected",error!=ERROR_SUCCESS,(DWORD)error);return;
    }
    report("rpc_connect_loopback",error==ERROR_SUCCESS,(DWORD)error);if(error)return;
    error=RegOpenKeyExW(remote,L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",0,KEY_QUERY_VALUE,&key);
    size=sizeof(newname);if(!error)error=RegQueryValueExW(key,L"ProductName",NULL,&type,(BYTE*)newname,&size);
    if(key){RegCloseKey(key);key=NULL;}
    report("rpc_read_os_identity",error==ERROR_SUCCESS&&type==REG_SZ,(DWORD)error);
    error=RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",0,KEY_QUERY_VALUE,&local);
    size=sizeof(oldname);if(!error)error=RegQueryValueExW(local,L"ProductName",NULL,&type,(BYTE*)oldname,&size);
    if(local){RegCloseKey(local);local=NULL;}
    report("rpc_matches_local_registry",error==ERROR_SUCCESS&&lstrcmpW(oldname,newname)==0,(DWORD)error);
    error=RegOpenKeyExW(remote,L"SOFTWARE\\XP25RegsvcFixture",0,KEY_QUERY_VALUE,&key);
    unused=error==ERROR_FILE_NOT_FOUND;if(key){RegCloseKey(key);key=NULL;}
    report("rpc_fixture_name_unused",unused,(DWORD)error);
    if(unused){
        error=RegCreateKeyExW(remote,L"SOFTWARE\\XP25RegsvcFixture",0,NULL,0,KEY_QUERY_VALUE|KEY_SET_VALUE,NULL,&key,NULL);
        report("rpc_create_own_key",error==ERROR_SUCCESS,(DWORD)error);
        if(!error){
            error=RegSetValueExW(key,L"Roundtrip",0,REG_DWORD,(BYTE*)&expected,4);
            report("rpc_write_own_value",error==ERROR_SUCCESS,(DWORD)error);
            size=4;error=RegQueryValueExW(key,L"Roundtrip",NULL,&type,(BYTE*)&value,&size);
            report("rpc_read_own_value",error==ERROR_SUCCESS&&type==REG_DWORD&&size==4&&value==expected,(DWORD)error);
            error=RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\XP25RegsvcFixture",0,KEY_QUERY_VALUE,&local);
            size=4;value=0;if(!error)error=RegQueryValueExW(local,L"Roundtrip",NULL,&type,(BYTE*)&value,&size);
            report("rpc_write_visible_locally",error==ERROR_SUCCESS&&value==expected,(DWORD)error);
            if(local)RegCloseKey(local);
            error=RegDeleteValueW(key,L"Roundtrip");report("rpc_delete_own_value",error==ERROR_SUCCESS,(DWORD)error);
            RegCloseKey(key);key=NULL;
            error=RegDeleteKeyW(remote,L"SOFTWARE\\XP25RegsvcFixture");report("rpc_delete_own_key",error==ERROR_SUCCESS,(DWORD)error);
        }
    }
    RegCloseKey(remote);report("rpc_worker_complete",before==failures,failures);
}
static void worker(BOOL stopped)
{
    char path[MAX_PATH],command[MAX_PATH+32];STARTUPINFOA start={0};PROCESS_INFORMATION process={0};DWORD code=99;BOOL ok;
    GetModuleFileNameA(NULL,path,sizeof(path));wsprintfA(command,"\"%s\" %s",path,stopped?"--rpc-off":"--rpc");start.cb=sizeof(start);
    CloseHandle(serial);
    ok=CreateProcessA(NULL,command,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&start,&process);
    if(ok){
        if(WaitForSingleObject(process.hProcess,30000)!=WAIT_OBJECT_0){TerminateProcess(process.hProcess,91);WaitForSingleObject(process.hProcess,5000);}
        ok=GetExitCodeProcess(process.hProcess,&code)&&code==0;CloseHandle(process.hThread);CloseHandle(process.hProcess);
    }
    serial=CreateFileA("COM1",GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);
    if(serial==INVALID_HANDLE_VALUE)ExitProcess(90);
    report("bounded_rpc_worker_exit",ok,code);
}
void WINAPI ProbeMain(void)
{
    SC_HANDLE manager,service;SERVICE_STATUS_PROCESS status={0};SERVICE_STATUS stop={0};DWORD size;BOOL running=FALSE,ok;
    serial=CreateFileA("COM1",GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);
    if(serial==INVALID_HANDLE_VALUE)ExitProcess(90);
    if(lstrcmpA(GetCommandLineA()+lstrlenA(GetCommandLineA())-9,"--rpc-off")==0){rpc(TRUE);CloseHandle(serial);ExitProcess(failures?1:0);}
    if(lstrcmpA(GetCommandLineA()+lstrlenA(GetCommandLineA())-5,"--rpc")==0){rpc(FALSE);CloseHandle(serial);ExitProcess(failures?1:0);}
    emit("REGSVC_PROBE_STARTED\r\n");manager=OpenSCManagerA(NULL,NULL,SC_MANAGER_CONNECT);
    service=manager?OpenServiceA(manager,"RemoteRegistry",SERVICE_QUERY_STATUS|SERVICE_QUERY_CONFIG|SERVICE_START|SERVICE_STOP):NULL;
    report("remote_registry_service_access",service!=NULL,GetLastError());
    if(service){
        ok=QueryServiceStatusEx(service,SC_STATUS_PROCESS_INFO,(BYTE*)&status,sizeof(status),&size);
        running=ok&&status.dwCurrentState==SERVICE_RUNNING;
        if(ok&&status.dwCurrentState!=SERVICE_STOPPED){ControlService(service,SERVICE_CONTROL_STOP,&stop);ok=wait_state(service,SERVICE_STOPPED,&status);}
        report("service_initial_stop",ok&&status.dwCurrentState==SERVICE_STOPPED,GetLastError());
        if(ok)worker(TRUE);
        ok=StartServiceA(service,0,NULL)&&wait_state(service,SERVICE_RUNNING,&status);
        report("service_start",ok,GetLastError());
        if(ok){module(status.dwProcessId);worker(FALSE);}
        ok=ControlService(service,SERVICE_CONTROL_STOP,&stop)&&wait_state(service,SERVICE_STOPPED,&status);
        report("service_stop",ok,GetLastError());
        if(ok)worker(TRUE);
        ok=StartServiceA(service,0,NULL)&&wait_state(service,SERVICE_RUNNING,&status);
        report("service_restart",ok,GetLastError());
        if(ok)worker(FALSE);
        if(!running){ok=ControlService(service,SERVICE_CONTROL_STOP,&stop)&&wait_state(service,SERVICE_STOPPED,&status);}
        else ok=wait_state(service,SERVICE_RUNNING,&status);
        report("original_service_running_state_restored",ok,GetLastError());CloseServiceHandle(service);
    }
    if(manager)CloseServiceHandle(manager);
    report("regsvc_probe_complete",failures==0,failures);CloseHandle(serial);ExitProcess(failures?1:0);
}
