/* UserEnv contract/profile checks. Unknown private ABIs are resolved, never guessed. */
#define WINVER 0x0501
#define _WIN32_WINNT 0x0501
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "userenv_contract.h"

static HANDLE serial;
static unsigned failures;
static void report(const char *name,BOOL ok,DWORD error)
{
    char s[220];DWORD n;if(!ok)++failures;
    wsprintfA(s,"{\"userenv_case\":\"%s\",\"status\":\"%s\",\"error\":%lu}\r\n",name,ok?"pass":"fail",ok?0:error);
    WriteFile(serial,s,lstrlenA(s),&n,NULL);
}
static HMODULE owner(FARPROC procedure)
{
    MEMORY_BASIC_INFORMATION info;
    return VirtualQuery((LPCVOID)procedure,&info,sizeof(info))==sizeof(info)?(HMODULE)info.AllocationBase:NULL;
}
static const WCHAR *environment_value(const WCHAR *block,const WCHAR *name)
{
    MEMORY_BASIC_INFORMATION info;const WCHAR *end,*s=block;unsigned i;
    if(!VirtualQuery(block,&info,sizeof(info)))return NULL;
    end=(const WCHAR*)((BYTE*)info.BaseAddress+info.RegionSize);if(end-block>65536)end=block+65536;
    while(s<end&&*s){
        for(i=0;name[i]&&s+i<end&&s[i]==name[i];++i){}
        if(!name[i]&&s+i<end&&s[i]=='=')return s+i+1;
        while(s<end&&*s)++s;
        ++s;
    }
    return NULL;
}
void WINAPI ProbeMain(void)
{
    HMODULE module,original=NULL;HANDLE token=NULL;DWORD n,size;unsigned i;BOOL ok=TRUE,compat=FALSE,candidate=FALSE;
    static WCHAR profile[512],current[512],expanded[512],expected[600];static char ansi[1024];
    typedef BOOL (WINAPI *PROFILEW)(HANDLE,LPWSTR,LPDWORD);
    typedef BOOL (WINAPI *PROFILEA)(HANDLE,LPSTR,LPDWORD);
    typedef BOOL (WINAPI *DIRECTORYW)(LPWSTR,LPDWORD);
    typedef BOOL (WINAPI *CREATEENV)(LPVOID*,HANDLE,BOOL);
    typedef BOOL (WINAPI *DESTROYENV)(LPVOID);
    typedef BOOL (WINAPI *EXPANDENV)(HANDLE,LPCWSTR,LPWSTR,DWORD);
    PROFILEW profile_w;PROFILEA profile_a;DIRECTORYW directory;
    CREATEENV create;DESTROYENV destroy;EXPANDENV expand;LPVOID environment=NULL;
    const char *line=GetCommandLineA();
    for(i=0;line[i];++i){
        if(line[i]=='-'&&lstrlenA(line+i)>=8&&CompareStringA(LOCALE_INVARIANT,0,line+i,8,"--compat",8)==CSTR_EQUAL)compat=TRUE;
        if(line[i]=='-'&&lstrlenA(line+i)>=11&&CompareStringA(LOCALE_INVARIANT,0,line+i,11,"--candidate",11)==CSTR_EQUAL)candidate=TRUE;
    }
    serial=CreateFileA("COM1",GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);
    if(serial==INVALID_HANDLE_VALUE)ExitProcess(90);
    WriteFile(serial,"USERENV_PROBE_STARTED\r\n",23,&n,NULL);
    if(candidate)original=LoadLibraryA("D:\\candidate\\ue51sp3.dll");
    module=LoadLibraryA(candidate?"D:\\candidate\\userenv.dll":"userenv.dll");report("load_userenv",module!=NULL,GetLastError());if(!module)goto finish;
    {
        char path[MAX_PATH],row[440];DWORD checksum=0;IMAGE_DOS_HEADER *dos=(IMAGE_DOS_HEADER*)module;
        if(dos->e_magic==IMAGE_DOS_SIGNATURE)checksum=((IMAGE_NT_HEADERS*)((BYTE*)module+dos->e_lfanew))->OptionalHeader.CheckSum;
        GetModuleFileNameA(module,path,MAX_PATH);
        wsprintfA(row,"{\"userenv_image_identity\":true,\"pe_checksum\":%lu,\"candidate_cd\":%u}\r\n",checksum,candidate);
        WriteFile(serial,row,lstrlenA(row),&n,NULL);
    }
    for(i=0;i<sizeof(userenv_exports)/sizeof(userenv_exports[0]);++i){
        FARPROC named=GetProcAddress(module,userenv_exports[i].name),ordinal=GetProcAddress(module,MAKEINTRESOURCEA(userenv_exports[i].ordinal));
        if(!named||named!=ordinal)ok=FALSE;
        if(compat&&userenv_exports[i].ordinal!=159&&owner(named)!=module)ok=FALSE;
    }
    report("all_49_named_sp3_ordinals_match",ok,GetLastError());ok=TRUE;
    for(i=100;i<=158;++i)if(!GetProcAddress(module,MAKEINTRESOURCEA(i)))ok=FALSE;
    report("original_59_private_exports_present",ok,GetLastError());
    if(compat){
        original=GetModuleHandleA("ue51sp3.dll");
        ok=original&&original!=module&&GetProcAddress(module,"CheckXForestLogon")==GetProcAddress(original,"CheckXForestLogon")&&
           GetProcAddress(module,MAKEINTRESOURCEA(200))==GetProcAddress(original,MAKEINTRESOURCEA(200))&&
           GetProcAddress(module,MAKEINTRESOURCEA(201))==GetProcAddress(original,MAKEINTRESOURCEA(201));
        report("three_exact_original_sp3_forward_targets",ok,GetLastError());
    }
    profile_w=(PROFILEW)GetProcAddress(module,"GetUserProfileDirectoryW");profile_a=(PROFILEA)GetProcAddress(module,"GetUserProfileDirectoryA");
    create=(CREATEENV)GetProcAddress(module,"CreateEnvironmentBlock");destroy=(DESTROYENV)GetProcAddress(module,"DestroyEnvironmentBlock");expand=(EXPANDENV)GetProcAddress(module,"ExpandEnvironmentStringsForUserW");
    ok=profile_w&&profile_a&&create&&destroy&&expand&&OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY|TOKEN_DUPLICATE,&token);
    report("profile_token_and_api_access",ok,GetLastError());if(!ok)goto done;
    size=0;SetLastError(0);ok=!profile_w(token,NULL,&size)&&size>0&&GetLastError()==ERROR_INSUFFICIENT_BUFFER;
    report("profile_unicode_buffer_contract",ok,GetLastError());size=512;
    ok=profile_w(token,profile,&size)&&GetEnvironmentVariableW(L"USERPROFILE",current,512)>0&&lstrcmpiW(profile,current)==0;
    report("profile_matches_logged_on_user",ok,GetLastError());size=sizeof(ansi);
    ok=profile_a(token,ansi,&size)&&MultiByteToWideChar(CP_ACP,0,ansi,-1,expanded,512)>0&&lstrcmpiW(profile,expanded)==0;
    report("profile_ansi_unicode_agree",ok,GetLastError());
    directory=(DIRECTORYW)GetProcAddress(module,"GetAllUsersProfileDirectoryW");size=512;
    report("all_users_profile_path",directory&&directory(expanded,&size)&&expanded[0]!=0,GetLastError());
    directory=(DIRECTORYW)GetProcAddress(module,"GetDefaultUserProfileDirectoryW");size=512;
    report("default_user_profile_path",directory&&directory(expanded,&size)&&expanded[0]!=0,GetLastError());
    ok=create(&environment,token,FALSE);report("create_user_environment",ok&&environment!=NULL,GetLastError());
    if(ok&&environment){
        const WCHAR *value=environment_value((WCHAR*)environment,L"USERPROFILE");
        report("environment_userprofile_matches",value&&lstrcmpiW(value,profile)==0,GetLastError());
        report("destroy_user_environment",destroy(environment),GetLastError());
    }
    lstrcpyW(expected,profile);lstrcatW(expected,L"\\xp25-native-env");
    report("expand_environment_for_user",expand(token,L"%USERPROFILE%\\xp25-native-env",expanded,512)&&lstrcmpiW(expanded,expected)==0,GetLastError());
done:
    if(token)CloseHandle(token);
    FreeLibrary(module);
    if(candidate&&original)FreeLibrary(original);
finish:
    report("userenv_probe_complete",failures==0,failures);CloseHandle(serial);ExitProcess(failures?1:0);
}
