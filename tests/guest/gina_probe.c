/* Read-only evidence from the actual Winlogon process and secure desktop ACL. */
#define WINVER 0x0501
#define _WIN32_WINNT 0x0501
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>

static HANDLE serial;
static unsigned failures;
static void report(const char *name,BOOL ok,DWORD error)
{
    char s[200];DWORD n;if(!ok)++failures;
    wsprintfA(s,"{\"gina_case\":\"%s\",\"status\":\"%s\",\"error\":%lu}\r\n",name,ok?"pass":"fail",ok?0:error);
    WriteFile(serial,s,lstrlenA(s),&n,NULL);
}
void WINAPI ProbeMain(void)
{
    HANDLE token=NULL,snapshot,process=NULL;TOKEN_PRIVILEGES privileges={0};
    PROCESSENTRY32 entry={0};MODULEENTRY32 module={0};DWORD pid=0,offset=0,checksum=0,n,current_session=99,session;
    SIZE_T bytes;BOOL found=FALSE,read=FALSE;HDESK desktop;
    serial=CreateFileA("COM1",GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);
    if(serial==INVALID_HANDLE_VALUE)ExitProcess(90);
    WriteFile(serial,"GINA_PROBE_STARTED\r\n",20,&n,NULL);
    if(OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&token)){
        privileges.PrivilegeCount=1;privileges.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
        if(LookupPrivilegeValueA(NULL,SE_DEBUG_NAME,&privileges.Privileges[0].Luid))AdjustTokenPrivileges(token,FALSE,&privileges,0,NULL,NULL);
        CloseHandle(token);
    }
    ProcessIdToSessionId(GetCurrentProcessId(),&current_session);
    snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);entry.dwSize=sizeof(entry);
    if(snapshot!=INVALID_HANDLE_VALUE&&Process32First(snapshot,&entry))do{
        if(lstrcmpiA(entry.szExeFile,"winlogon.exe")==0&&ProcessIdToSessionId(entry.th32ProcessID,&session)&&session==current_session){pid=entry.th32ProcessID;break;}
    }while(Process32Next(snapshot,&entry));
    if(snapshot!=INVALID_HANDLE_VALUE)CloseHandle(snapshot);
    report("interactive_session_winlogon_found",pid!=0,GetLastError());
    snapshot=pid?CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,pid):INVALID_HANDLE_VALUE;module.dwSize=sizeof(module);
    if(snapshot!=INVALID_HANDLE_VALUE&&Module32First(snapshot,&module))do{
        if(lstrcmpiA(module.szModule,"msgina.dll")==0){found=TRUE;break;}
    }while(Module32Next(snapshot,&module));
    if(found)process=OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION,FALSE,pid);
    if(process){read=ReadProcessMemory(process,module.modBaseAddr+60,&offset,4,&bytes)&&bytes==4&&
        ReadProcessMemory(process,module.modBaseAddr+offset+24+64,&checksum,4,&bytes)&&bytes==4;CloseHandle(process);}
    if(snapshot!=INVALID_HANDLE_VALUE)CloseHandle(snapshot);
    {char s[200];wsprintfA(s,"{\"gina_image_identity\":true,\"pid\":%lu,\"session\":%lu,\"found\":%u,\"read\":%u,\"pe_checksum\":%lu}\r\n",pid,current_session,found,read,checksum);WriteFile(serial,s,lstrlenA(s),&n,NULL);}
    report("msgina_mapped_in_real_winlogon",found&&read,GetLastError());
    found=FALSE;read=FALSE;checksum=0;
    snapshot=pid?CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,pid):INVALID_HANDLE_VALUE;module.dwSize=sizeof(module);
    if(snapshot!=INVALID_HANDLE_VALUE&&Module32First(snapshot,&module))do{
        if(lstrcmpiA(module.szModule,"userenv.dll")==0){found=TRUE;break;}
    }while(Module32Next(snapshot,&module));
    if(found){process=OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION,FALSE,pid);
        if(process){read=ReadProcessMemory(process,module.modBaseAddr+60,&offset,4,&bytes)&&bytes==4&&
            ReadProcessMemory(process,module.modBaseAddr+offset+24+64,&checksum,4,&bytes)&&bytes==4;CloseHandle(process);}}
    if(snapshot!=INVALID_HANDLE_VALUE)CloseHandle(snapshot);
    {char row[180];wsprintfA(row,"{\"winlogon_userenv_identity\":true,\"pid\":%lu,\"read\":%u,\"pe_checksum\":%lu}\r\n",pid,read,checksum);WriteFile(serial,row,lstrlenA(row),&n,NULL);}
    report("userenv_mapped_in_real_winlogon",found&&read,GetLastError());
    SetLastError(ERROR_SUCCESS);desktop=OpenDesktopW(L"Winlogon",0,FALSE,DESKTOP_CREATEWINDOW|DESKTOP_WRITEOBJECTS|WRITE_DAC);
    report("user_cannot_write_secure_desktop",desktop==NULL&&GetLastError()==ERROR_ACCESS_DENIED,GetLastError());
    if(desktop)CloseDesktop(desktop);
    report("gina_probe_complete",failures==0,failures);CloseHandle(serial);ExitProcess(failures?1:0);
}
