/* XP25 original native NT 5.1 x86 Winlogon entry and bootstrap. */
#include "platform.h"
WL_HOST wl;
static CRITICAL_SECTION log_lock;

void wl_log(const char *event,DWORD status)
{
    HANDLE serial,file;DWORD wrote,saved_error=GetLastError();char row[1024],escaped[769];int n;unsigned i=0,j=0;unsigned char c;
    EnterCriticalSection(&log_lock);
    while(event[i]&&i<127){c=(unsigned char)event[i++];
        if(c=='\\'||c=='"'){escaped[j++]='\\';escaped[j++]=(char)c;}
        else if(c<32){wsprintfA(escaped+j,"\\u%04x",c);j+=6;}
        else escaped[j++]=(char)c;
    }
    escaped[j]=0;
    n=wsprintfA(row,"{\"xp25_winlogon\":\"%s\",\"status\":%lu,\"phase\":\"%s\",\"event_truncated\":%u}\r\n",escaped,status,wl_phase_name(wl.machine.phase),(unsigned)(event[i]!=0));
    OutputDebugStringA(row);
    serial=CreateFileW(L"COM1",GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);
    if(serial!=INVALID_HANDLE_VALUE){WriteFile(serial,row,n,&wrote,NULL);CloseHandle(serial);}
    file=CreateFileW(L"C:\\xp25\\native-winlogon.log",FILE_APPEND_DATA,FILE_SHARE_READ,NULL,OPEN_ALWAYS,0,NULL);
    if(file!=INVALID_HANDLE_VALUE){WriteFile(file,row,n,&wrote,NULL);CloseHandle(file);}
    LeaveCriticalSection(&log_lock);SetLastError(saved_error);
}

void wl_fail(const char *operation,DWORD error)
{
    wl_log(operation,error?error:ERROR_GEN_FAILURE);wl_state_step(&wl.machine,WlFatalError,0);
    if(wl.secure){SwitchDesktop(wl.secure);MessageBoxW(NULL,L"XP25 Winlogon initialization or session operation failed.\nThe secure session remains unavailable. See native-winlogon.log.",L"XP25 experimental Winlogon",MB_OK|MB_ICONERROR|MB_SYSTEMMODAL);}
    /* Never start an unauthenticated shell or fall through to a success path.
       Keep failure available to the debugger; this is not a successful boot. */
    for(;;)Sleep(INFINITE);
}

static BOOL start_system_process(LPCWSTR name)
{
    HANDLE snap;PROCESSENTRY32W row;BOOL exists=FALSE;WCHAR path[MAX_PATH],command[MAX_PATH+4];STARTUPINFOW si;PROCESS_INFORMATION pi;
    snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);row.dwSize=sizeof(row);
    if(snap==INVALID_HANDLE_VALUE)return FALSE;
    if(Process32FirstW(snap,&row))do{if(lstrcmpiW(row.szExeFile,name)==0){exists=TRUE;break;}}while(Process32NextW(snap,&row));
    CloseHandle(snap);if(exists){if(lstrcmpiW(name,L"lsass.exe")==0)InterlockedExchange((LONG*)&wl.lsa_pid,(LONG)row.th32ProcessID);return TRUE;}
    if(!GetSystemDirectoryW(path,MAX_PATH)||lstrlenW(path)+lstrlenW(name)+2>=MAX_PATH){SetLastError(ERROR_BUFFER_OVERFLOW);return FALSE;}
    lstrcatW(path,L"\\");lstrcatW(path,name);wsprintfW(command,L"\"%s\"",path);
    ZeroMemory(&si,sizeof(si));si.cb=sizeof(si);ZeroMemory(&pi,sizeof(pi));
    if(!CreateProcessW(path,command,NULL,NULL,FALSE,CREATE_SUSPENDED,NULL,NULL,&si,&pi))return FALSE;
    if(lstrcmpiW(name,L"lsass.exe")==0)InterlockedExchange((LONG*)&wl.lsa_pid,(LONG)pi.dwProcessId);
    if(ResumeThread(pi.hThread)==(DWORD)-1){CloseHandle(pi.hThread);CloseHandle(pi.hProcess);return FALSE;}
    CloseHandle(pi.hThread);CloseHandle(pi.hProcess);return TRUE;
}

BOOL wl_system_services(void)
{
    LSA_STRING name;LSA_OPERATIONAL_MODE mode;NTSTATUS status;DWORD started=GetTickCount();
    if(!start_system_process(L"lsass.exe"))return FALSE;
    if(!start_system_process(L"services.exe"))return FALSE;
    if(!wl_wait_sam())return FALSE;
    name.Buffer="XP25Winlogon";name.Length=12;name.MaximumLength=13;
    do{
        status=LsaRegisterLogonProcess(&name,&wl.lsa,&mode);
        if(status>=0){wl_log("trusted_lsa_registered",0);return TRUE;}
        Sleep(250);
    }while(GetTickCount()-started<60000);
    SetLastError(LsaNtStatusToWinError(status));return FALSE;
}

static BOOL connect_console(void)
{
    WCHAR path[MAX_PATH];HMODULE module;BOOLEAN (WINAPI *connect)(void);BOOL ok;DWORD error;
    DWORD active=WTSGetActiveConsoleSessionId();wl_log("console_session_before_connect",active);
    if(active==wl.session_id)return TRUE;
    if(!GetSystemDirectoryW(path,MAX_PATH)||lstrlenW(path)+12>=MAX_PATH){SetLastError(ERROR_BUFFER_OVERFLOW);return FALSE;}
    lstrcatW(path,L"\\winsta.dll");module=LoadLibraryW(path);if(!module)return FALSE;
    connect=(BOOLEAN(WINAPI*)(void))GetProcAddress(module,"_WinStationWaitForConnect");
    if(!connect){FreeLibrary(module);SetLastError(ERROR_PROC_NOT_FOUND);return FALSE;}
    ok=connect()!=0;error=GetLastError();FreeLibrary(module);
    if(!ok){SetLastError(error);return FALSE;}
    active=WTSGetActiveConsoleSessionId();wl_log("console_session_after_connect",active);
    /* Let the existing session manager establish console ownership. Never write
       shared kernel data or reinterpret a remote logon as a local one. */
    if(active!=wl.session_id){SetLastError(ERROR_CTX_WINSTATION_NOT_FOUND);return FALSE;}
    return TRUE;
}

static BOOL console_authentication_options(void)
{
    /* The original host issues MSV1_0 process-options mask3. Only the verified
       local-console blank-password option is needed here; do not request its
       separate administrator-lockout exception. No machine policy is changed.
       LSA still verifies the account, password, rights and returned token. */
    struct {ULONG message,options;BOOLEAN disable;BYTE padding[3];} request;
    LSA_STRING package;ULONG id,bytes=0;PVOID response=NULL;NTSTATUS status,protocol=(NTSTATUS)0xc0000001L;
    if(WTSGetActiveConsoleSessionId()!=wl.session_id){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
    package.Buffer=MSV1_0_PACKAGE_NAME;
    package.Length=(USHORT)strlen(package.Buffer);package.MaximumLength=package.Length+1;
    status=LsaLookupAuthenticationPackage(wl.lsa,&package,&id);
    if(status<0){SetLastError(LsaNtStatusToWinError(status));return FALSE;}
    ZeroMemory(&request,sizeof(request));request.message=MsV1_0SetProcessOption;request.options=1;
    status=LsaCallAuthenticationPackage(wl.lsa,id,&request,sizeof(request),&response,&bytes,&protocol);
    if(response)LsaFreeReturnBuffer(response);
    if(status<0||protocol<0){SetLastError(LsaNtStatusToWinError(status<0?status:protocol));return FALSE;}
    wl_log("console_authentication_options",request.options);return TRUE;
}

static LRESULT CALLBACK notify_window(HWND h,UINT message,WPARAM wp,LPARAM lp)
{
    if(message==WM_HOTKEY&&wp==WL_HOTKEY){PostMessageW(h,WL_APP_SAS,WLX_SAS_TYPE_CTRL_ALT_DEL,0);return 0;}
    if(message==WL_APP_SAS){
        if(wl.dialog&&(wl.machine.phase==WlSignedOut||wl.machine.phase==WlLocked)){
            EndDialog(wl.dialog,WLX_DLG_SAS);PostMessageW(h,WL_APP_SAS,wp,0);return 0;
        }
        if(wl.in_gina&&wl.dialog){PostMessageW(wl.dialog,WLX_WM_SAS,wp,0);return 0;}
        wl_attention((DWORD)wp);return 0;
    }
    if(message==WL_LOGON_NOTIFY){wl_log("user_logon_notify",(DWORD)wp);PostMessageW(h,WL_APP_NOTICE,wp,lp);return 0;}
    if(message==WL_APP_NOTICE){
        if(wp==100&&wl.machine.phase==WlSignedOut){wl.gina.sas_notice(wl.gina_context);return 0;}
        if(wp==5&&wl.machine.phase==WlInteractive){
            if(wl_session_lock())wl.gina.locked_notice(wl.gina_context);else wl_log("lock_request_failed",GetLastError());
        }else if(wp==0){
            /* USER adds EWX_WINLOGON_CALLER (0x200) to completion notices from
               our own registered-process ExitWindowsEx call; do not recurse. */
            if((DWORD)lp&0x200){wl_log("native_end_session_completion",(DWORD)lp);return 0;}
            wl.pending_power=(DWORD)lp;
            if(wl.token&&!wl_session_logoff())wl_fail("user_requested_logoff_failed",GetLastError());
            if((DWORD)lp&(EWX_SHUTDOWN|EWX_REBOOT|EWX_POWEROFF)){
                if(!wl_session_power(((DWORD)lp&EWX_REBOOT)!=0))wl_fail("user_requested_power_failed",GetLastError());
            }else PostMessageW(h,WL_APP_NOTICE,100,0);
        }
        else wl_log("unsupported_user_notification",(DWORD)wp);
        return 0;
    }
    return DefWindowProcW(h,message,wp,lp);
}

BOOL wl_boot(void)
{
    WNDCLASSW cls;BOOL (WINAPI *set_notify)(HWND);OSVERSIONINFOEXW version;
    wl_state_init(&wl.machine);wl_log("entry",0);
    ZeroMemory(&version,sizeof(version));version.dwOSVersionInfoSize=sizeof(version);
    if(!GetVersionExW((OSVERSIONINFOW*)&version))return FALSE;
    if(version.dwPlatformId!=VER_PLATFORM_WIN32_NT||version.dwMajorVersion!=5||version.dwMinorVersion!=1||version.dwBuildNumber!=2600){SetLastError(ERROR_OLD_WIN_VERSION);return FALSE;}
    if(!ProcessIdToSessionId(GetCurrentProcessId(),&wl.session_id)||wl.session_id!=0){SetLastError(ERROR_NOT_SUPPORTED);return FALSE;}
    if(!wl_security_init()){wl_log("security_init_failed",GetLastError());return FALSE;}
    ZeroMemory(&cls,sizeof(cls));cls.lpfnWndProc=notify_window;cls.hInstance=wl.instance;cls.lpszClassName=L"XP25WinlogonNotify";
    if(!RegisterClassW(&cls))return FALSE;
    wl.window=CreateWindowExW(0,cls.lpszClassName,L"XP25 Winlogon",0,0,0,0,0,NULL,NULL,wl.instance,NULL);
    if(!wl.window)return FALSE;
    set_notify=(BOOL(WINAPI*)(HWND))GetProcAddress(GetModuleHandleW(L"user32.dll"),"SetLogonNotifyWindow");
    if(!set_notify||!set_notify(wl.window))return FALSE;
    if(!RegisterHotKey(wl.window,WL_HOTKEY,WL_MOD_SAS|MOD_CONTROL|MOD_ALT,VK_DELETE))return FALSE;
    if(!wl_bootkey_start())return FALSE;
    if(!wl_system_services())return FALSE;
    if(!connect_console())return FALSE;
    if(!console_authentication_options())return FALSE;
    if(!wl_policy_initialize())return FALSE;
    if(!wl_gina_init())return FALSE;
    if(!wl_notify(L"Startup"))return FALSE;
    if(!wl_switch_secure())return FALSE;
    if(!wl_state_step(&wl.machine,WlBootReady,WL_BOOT_FACTS)){SetLastError(ERROR_INVALID_DATA);return FALSE;}
    wl_log("core_ready",0);return TRUE;
}

BOOL wl_model_test(void)
{
    WL_MACHINE m;wl_state_init(&m);
    if(wl_state_step(&m,WlBootReady,0))return FALSE;
    if(!wl_state_step(&m,WlBootReady,WL_BOOT_FACTS)||!wl_state_step(&m,WlAttention,WL_SECURE_ACTIVE))return FALSE;
    if(wl_state_step(&m,WlAuthenticated,0)||wl_state_step(&m,WlAttention,WL_SECURE_ACTIVE))return FALSE;
    if(!wl_state_step(&m,WlDenied,0)||m.phase!=WlSignedOut)return FALSE;
    if(!wl_state_step(&m,WlAttention,WL_SECURE_ACTIVE)||!wl_state_step(&m,WlAuthenticated,WL_TOKEN_CHECKED))return FALSE;
    if(wl_state_step(&m,WlShellReady,WL_SHELL_USER|WL_USER_ACTIVE))return FALSE;
    if(!wl_state_step(&m,WlRollbackCompleted,WL_RESOURCES_GONE|WL_SECURE_ACTIVE))return FALSE;
    return !m.token_owned&&!m.profile_owned&&!m.shell_owned;
}

int WINAPI WinMain(HINSTANCE instance,HINSTANCE previous,LPSTR command,int show)
{
    MSG msg;BOOL test;
    UNREFERENCED_PARAMETER(previous);UNREFERENCED_PARAMETER(show);InitializeCriticalSection(&log_lock);wl.instance=instance;wl_state_init(&wl.machine);
    if(lstrcmpA(command,"--self-test")==0){test=wl_model_test();wl_log("model_self_test",test?0:ERROR_INVALID_DATA);return test?0:1;}
    if(lstrcmpA(command,"--probe")==0){wl_notifications_probe();test=wl_model_test();wl_log("nonprivileged_probe_complete",test?0:ERROR_INVALID_DATA);return test?0:1;}
    if(command[0])return ERROR_INVALID_PARAMETER;
    if(!wl_boot())wl_fail("bootstrap_failed",GetLastError());
    wl.gina.sas_notice(wl.gina_context);
    while(GetMessageW(&msg,NULL,0,0)>0){TranslateMessage(&msg);DispatchMessageW(&msg);}
    wl_fail("message_loop_ended",GetLastError());return ERROR_GEN_FAILURE;
}
