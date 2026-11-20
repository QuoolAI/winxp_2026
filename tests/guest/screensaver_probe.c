/* R-0: screen savers and the idle lock under the XP25 Winlogon, seen from the user's session.
   Started at each logon of XP25 (an administrator) by a Startup script of
   vm/winlogon_screensaver_probe.py, which supplies the input that ends each saver, unlocks the
   station and logs on. Winlogon's own serial records decide the gates; this probe adds what a
   session program observes: whether USER reports a running saver (SPI_GETSCREENSAVERRUNNING,
   true only for a saver that win32k accepted from the logon process) and which input desktop
   it can open (Screen-saver while a saver shows, Default when back, none while locked).

   First session (no C:\xp25\saver-stage.txt): with an idle timeout of N seconds (argument,
   default 20) and ssstars.scr it waits through four savers:
     nonsecure   ScreenSaverIsSecure 0: running, then back on Default, never locked
     secure_key  ScreenSaverIsSecure 1, ended by a key: running, then locked, then Default
     secure_sas  the same, ended by Ctrl+Alt+Del
     locked      ScreenSaverIsSecure 0 on a station locked with Win+L: locked, running, locked,
                 then Default after the unlock
   It then sets the logon desktop's (.DEFAULT) timeout to N, restores its own timeout and logs off.
   Second session: restores .DEFAULT's timeout (600 s). One JSON record per case goes to COM1
   (retried: the port is exclusive) and to C:\xp25\saver-probe.log. Exit 0 when every case passed. */
#define WINVER 0x0501
#define _WIN32_WINNT 0x0501
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define STAGE L"C:\\xp25\\saver-stage.txt"
#define DESKTOP_KEY L"Control Panel\\Desktop"

static DWORD t0;

static void emit(const char *row)
{
    HANDLE h;DWORD n,start=GetTickCount();
    h=CreateFileW(L"C:\\xp25\\saver-probe.log",FILE_APPEND_DATA,FILE_SHARE_READ,NULL,OPEN_ALWAYS,0,NULL);
    if(h!=INVALID_HANDLE_VALUE){WriteFile(h,row,lstrlenA(row),&n,NULL);WriteFile(h,"\r\n",2,&n,NULL);CloseHandle(h);}
    do{
        h=CreateFileA("COM1",GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);
        if(h!=INVALID_HANDLE_VALUE){WriteFile(h,row,lstrlenA(row),&n,NULL);WriteFile(h,"\r\n",2,&n,NULL);CloseHandle(h);return;}
        Sleep(50);
    }while(GetTickCount()-start<20000);
}

static BOOL set_string(HKEY root,LPCWSTR name,LPCWSTR value)
{
    HKEY key;LONG error;
    if(RegCreateKeyExW(root,DESKTOP_KEY,0,NULL,0,KEY_SET_VALUE,NULL,&key,NULL))return FALSE;
    error=RegSetValueExW(key,name,0,REG_SZ,(const BYTE*)value,(DWORD)(lstrlenW(value)+1)*sizeof(WCHAR));
    RegCloseKey(key);return error==0;
}

static BOOL running(void)
{
    BOOL value=FALSE;
    return SystemParametersInfoW(SPI_GETSCREENSAVERRUNNING,0,&value,0)&&value;
}

/* 1 when the input desktop opens (its name in name), 0 when it does not (a locked station). */
static int input_desktop(WCHAR *name)
{
    HDESK desktop=OpenInputDesktop(0,FALSE,DESKTOP_READOBJECTS);DWORD bytes=0;
    lstrcpyW(name,L"none");
    if(!desktop)return 0;
    if(!GetUserObjectInformationW(desktop,UOI_NAME,name,64*sizeof(WCHAR),&bytes))lstrcpyW(name,L"unnamed");
    CloseDesktop(desktop);return 1;
}

/* Wait (polling every 200 ms) until the saver state or the input desktop matches. */
static BOOL wait_running(BOOL wanted,DWORD seconds)
{
    DWORD start=GetTickCount();
    do{if(running()==wanted)return TRUE;Sleep(200);}while(GetTickCount()-start<seconds*1000);
    return FALSE;
}
static BOOL wait_desktop(LPCWSTR wanted,DWORD seconds)
{
    WCHAR name[64];DWORD start=GetTickCount();int open;
    do{open=input_desktop(name);if(wanted?open&&!lstrcmpiW(name,wanted):!open)return TRUE;Sleep(200);}while(GetTickCount()-start<seconds*1000);
    return FALSE;
}

static void narrow(char *out,const WCHAR *in)
{
    int i;for(i=0;in[i]&&i<63;++i)out[i]=(char)(in[i]<128?in[i]:'?');out[i]=0;
}

/* One saver: it shows (USER reports it, the input desktop is Screen-saver), then ends; a
   secure one ends locked, then unlocked by the harness; a non-secure one ends on Default. */
static BOOL saver_case(const char *label,BOOL secure,BOOL start_locked,DWORD seconds)
{
    WCHAR name[64];char row[400],shown[64],after[64];BOOL started,ended,locked=FALSE,back,locked_before=TRUE;DWORD wait_ms;
    if(start_locked)locked_before=wait_desktop(NULL,seconds*10);
    wait_ms=GetTickCount();
    started=wait_running(TRUE,seconds*6);wait_ms=GetTickCount()-wait_ms;
    Sleep(500);input_desktop(name);narrow(shown,name);
    ended=started&&wait_running(FALSE,seconds*6);
    if(secure||start_locked)locked=ended&&wait_desktop(NULL,15);
    Sleep(1500);
    back=ended&&wait_desktop(L"Default",secure||start_locked?seconds*10:30);
    input_desktop(name);narrow(after,name);
    /* Winlogon records the same transition on COM1 and drops a line when the port is busy
       (roadmap R-0b): let its records go first. */
    Sleep(2000);
    wsprintfA(row,"{\"saver_case\":\"%s\",\"locked_before\":%d,\"saw_running\":%d,\"wait_ms\":%lu,\"desktop_while_running\":\"%s\","
                  "\"ended\":%d,\"locked_after\":%d,\"desktop_after\":\"%s\",\"t\":%lu,\"passed\":%d}",
              label,locked_before,started,wait_ms,shown,ended,locked,after,GetTickCount()-t0,
              locked_before&&started&&!lstrcmpA(shown,"Screen-saver")&&ended&&back&&(locked==(secure||start_locked)));
    emit(row);
    return locked_before&&started&&!lstrcmpA(shown,"Screen-saver")&&ended&&back&&locked==(secure||start_locked);
}

static DWORD argument(void)
{
    LPWSTR p=GetCommandLineW();DWORD value=0;BOOL quoted=FALSE;
    while(*p&&(quoted||*p!=L' ')){if(*p==L'"')quoted=!quoted;++p;}
    while(*p==L' ')++p;
    while(*p>=L'0'&&*p<=L'9'){value=value*10+(DWORD)(*p-L'0');++p;}
    return value>=5&&value<=600?value:20;
}

void WINAPI ProbeMain(void)
{
    WCHAR text[16];char row[160];HKEY defaults;HANDLE stage;DWORD seconds=argument(),n;BOOL ok=TRUE,second;
    t0=GetTickCount();
    second=GetFileAttributesW(STAGE)!=INVALID_FILE_ATTRIBUTES;
    wsprintfA(row,"{\"saver_probe\":\"started\",\"session\":%d,\"timeout_s\":%lu}",second?2:1,seconds);emit(row);
    if(RegOpenKeyExW(HKEY_USERS,L".DEFAULT",0,KEY_SET_VALUE|KEY_CREATE_SUB_KEY,&defaults)){emit("{\"saver_probe\":\"default_hive_unavailable\",\"passed\":0}");ExitProcess(1);}
    if(second){
        ok=set_string(defaults,L"ScreenSaveTimeOut",L"600");RegCloseKey(defaults);
        wsprintfA(row,"{\"saver_case\":\"restored\",\"passed\":%d}",ok);emit(row);
        ExitProcess(ok?0:1);
    }
    ok=set_string(HKEY_CURRENT_USER,L"SCRNSAVE.EXE",L"C:\\WINDOWS\\system32\\ssstars.scr")&&
       set_string(HKEY_CURRENT_USER,L"ScreenSaverIsSecure",L"0")&&
       SystemParametersInfoW(SPI_SETSCREENSAVEACTIVE,TRUE,NULL,SPIF_UPDATEINIFILE|SPIF_SENDCHANGE)&&
       SystemParametersInfoW(SPI_SETSCREENSAVETIMEOUT,seconds,NULL,SPIF_UPDATEINIFILE|SPIF_SENDCHANGE);
    wsprintfA(row,"{\"saver_probe\":\"configured\",\"passed\":%d}",ok);emit(row);
    ok=saver_case("nonsecure",FALSE,FALSE,seconds)&&ok;
    ok=set_string(HKEY_CURRENT_USER,L"ScreenSaverIsSecure",L"1")&&ok;
    ok=saver_case("secure_key",TRUE,FALSE,seconds)&&ok;
    ok=saver_case("secure_sas",TRUE,FALSE,seconds)&&ok;
    ok=set_string(HKEY_CURRENT_USER,L"ScreenSaverIsSecure",L"0")&&ok;
    emit("{\"saver_probe\":\"ready_locked\"}");
    ok=saver_case("locked",FALSE,TRUE,seconds)&&ok;
    /* The logon desktop's saver: .DEFAULT's timeout applies once the user has logged off. */
    wsprintfW(text,L"%lu",seconds);
    ok=set_string(defaults,L"ScreenSaveTimeOut",text)&&set_string(defaults,L"ScreenSaveActive",L"1")&&ok;
    RegCloseKey(defaults);
    ok=SystemParametersInfoW(SPI_SETSCREENSAVETIMEOUT,600,NULL,SPIF_UPDATEINIFILE|SPIF_SENDCHANGE)&&ok;
    stage=CreateFileW(STAGE,GENERIC_WRITE,0,NULL,CREATE_NEW,0,NULL);
    if(stage!=INVALID_HANDLE_VALUE){WriteFile(stage,"2",1,&n,NULL);CloseHandle(stage);}else ok=FALSE;
    wsprintfA(row,"{\"saver_probe\":\"first_session_done\",\"passed\":%d}",ok);emit(row);
    if(!ExitWindowsEx(EWX_LOGOFF,0)){emit("{\"saver_probe\":\"logoff_failed\",\"passed\":0}");ExitProcess(1);}
    ExitProcess(ok?0:1);
}
