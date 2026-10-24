/* XP-era APIs only. Read-only OS identity capture and disposable compatibility fixtures. */
#define WINVER 0x0501
#define _WIN32_WINNT 0x0501
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static HANDLE serial;
static unsigned failures;
static BOOL branded;
static BOOL system_brand;
static void emit(const char *text)
{
    DWORD written;
    WriteFile(serial, text, lstrlenA(text), &written, NULL);
}
static void report(const char *name, BOOL ok, DWORD error)
{
    char line[240];
    if (!ok) ++failures;
    wsprintfA(line, "{\"branding_case\":\"%s\",\"status\":\"%s\",\"error\":%lu}\r\n",
              name, ok ? "pass" : "fail", ok ? 0 : error);
    emit(line);
}
static BOOL has(const char *text, const char *part)
{
    unsigned i, j;
    for (i=0; text[i]; ++i) {
        for (j=0; part[j] && text[i+j] == part[j]; ++j) {}
        if (!part[j]) return TRUE;
    }
    return FALSE;
}
static BOOL product_name(char *value, DWORD capacity)
{
    HKEY key; DWORD type;
    LONG error = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_QUERY_VALUE, &key);
    if (error) return FALSE;
    error = RegQueryValueExA(key, "ProductName", NULL, &type, (BYTE *)value, &capacity);
    RegCloseKey(key);
    return error == ERROR_SUCCESS && type == REG_SZ;
}
static void identity(void)
{
    OSVERSIONINFOEXA a = {0}; OSVERSIONINFOEXW w = {0}, rtl = {0};
    SYSTEM_INFO system; char line[700], product[128] = {0};
    typedef LONG (WINAPI *RTL_VERSION)(OSVERSIONINFOEXW *);
    RTL_VERSION query = (RTL_VERSION)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlGetVersion");
    BOOL ok, wide;
    a.dwOSVersionInfoSize = sizeof(a); w.dwOSVersionInfoSize = sizeof(w);
    rtl.dwOSVersionInfoSize = sizeof(rtl);
    ok = GetVersionExA((OSVERSIONINFOA *)&a);
    wide = GetVersionExW((OSVERSIONINFOW *)&w);
    GetSystemInfo(&system);
    report("nt51_x86_build_identity", ok && wide && a.dwMajorVersion == 5 && a.dwMinorVersion == 1 &&
        a.dwBuildNumber == 2600 && a.dwPlatformId == VER_PLATFORM_WIN32_NT &&
        a.wProductType == VER_NT_WORKSTATION && system.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL && sizeof(void *) == 4, GetLastError());
    report("ansi_unicode_version_agree", ok && wide && a.dwMajorVersion == w.dwMajorVersion &&
        a.dwMinorVersion == w.dwMinorVersion && a.dwBuildNumber == w.dwBuildNumber &&
        a.wServicePackMajor == w.wServicePackMajor && a.wServicePackMinor == w.wServicePackMinor &&
        a.wSuiteMask == w.wSuiteMask && a.wProductType == w.wProductType, GetLastError());
    report("rtl_version_identity", query && query(&rtl) == 0 && rtl.dwMajorVersion == w.dwMajorVersion &&
        rtl.dwMinorVersion == w.dwMinorVersion && rtl.dwBuildNumber == w.dwBuildNumber &&
        rtl.wServicePackMajor == w.wServicePackMajor && rtl.wServicePackMinor == w.wServicePackMinor &&
        rtl.wProductType == w.wProductType, GetLastError());
    report("product_name_legacy_detection", product_name(product, sizeof(product)) && has(product, "Windows XP"), GetLastError());
    wsprintfA(line, "{\"branding_identity\":true,\"major\":%lu,\"minor\":%lu,\"build\":%lu,\"platform\":%lu,\"sp_major\":%u,\"sp_minor\":%u,\"suite\":%u,\"product_type\":%u,\"architecture\":%u,\"pointer_bytes\":%u,\"getversion\":%lu,\"csd\":\"%s\",\"product_name\":\"%s\"}\r\n",
        a.dwMajorVersion,a.dwMinorVersion,a.dwBuildNumber,a.dwPlatformId,a.wServicePackMajor,
        a.wServicePackMinor,a.wSuiteMask,a.wProductType,system.wProcessorArchitecture,
        (unsigned)sizeof(void *),GetVersion(),a.szCSDVersion,product);
    emit(line);
    {
        ULONGLONG mask=0;
        mask=VerSetConditionMask(mask,VER_MAJORVERSION,VER_EQUAL);
        mask=VerSetConditionMask(mask,VER_MINORVERSION,VER_EQUAL);
        mask=VerSetConditionMask(mask,VER_BUILDNUMBER,VER_EQUAL);
        mask=VerSetConditionMask(mask,VER_SERVICEPACKMAJOR,VER_EQUAL);
        mask=VerSetConditionMask(mask,VER_SERVICEPACKMINOR,VER_EQUAL);
        mask=VerSetConditionMask(mask,VER_PRODUCT_TYPE,VER_EQUAL);
        report("verify_version_info_legacy", VerifyVersionInfoA(&a,VER_MAJORVERSION|VER_MINORVERSION|
            VER_BUILDNUMBER|VER_SERVICEPACKMAJOR|VER_SERVICEPACKMINOR|VER_PRODUCT_TYPE,mask) &&
            VerifyVersionInfoW(&w,VER_MAJORVERSION|VER_MINORVERSION|VER_BUILDNUMBER|
            VER_SERVICEPACKMAJOR|VER_SERVICEPACKMINOR|VER_PRODUCT_TYPE,mask),GetLastError());
    }
}
static void raw_write(HANDLE file, const void *data, DWORD size)
{
    DWORD written;
    if (!WriteFile(file,data,size,&written,NULL) || written != size) ++failures;
}
static void identity_registry(void)
{
    static const char *keys[] = {
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        "SYSTEM\\CurrentControlSet\\Control\\ProductOptions",
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\WPAEvents"};
    static const char *values[] = {"ProductName","CurrentVersion","CurrentBuildNumber","CurrentBuild",
        "CSDVersion","BuildLab","ProductId","DigitalProductId",NULL,"ProductType","ProductSuite",NULL,"OOBETimer",NULL};
    static BYTE data[65536];
    HANDLE file = CreateFileA("C:\\xp25\\branding-identity.bin",GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    unsigned k, i=0, before=failures;
    if (file == INVALID_HANDLE_VALUE) { report("protected_identity_snapshot",FALSE,GetLastError()); return; }
    for (k=0;k<3;++k) {
        HKEY key=NULL; LONG opened=RegOpenKeyExA(HKEY_LOCAL_MACHINE,keys[k],0,KEY_QUERY_VALUE,&key);
        for (;values[i];++i) {
            DWORD header[4],size=sizeof(data),type=0;
            LONG error=opened ? opened : RegQueryValueExA(key,values[i],NULL,&type,data,&size);
            if (error) size=0;
            header[0]=k;header[1]=lstrlenA(values[i]);header[2]=(DWORD)error;header[3]=type;
            raw_write(file,header,sizeof(header));raw_write(file,values[i],header[1]);
            raw_write(file,&size,sizeof(size));if(size)raw_write(file,data,size);
        }
        ++i;if(key)RegCloseKey(key);
    }
    FlushFileBuffers(file);CloseHandle(file);
    report("protected_identity_snapshot", failures==before,GetLastError());
}
static DWORD fixture_app(void)
{
    OSVERSIONINFOA version={0};HKEY key;DWORD value=0,size=sizeof(value),type;char name[128]={0};
    version.dwOSVersionInfoSize=sizeof(version);
    if(!GetVersionExA(&version)||version.dwMajorVersion!=5||version.dwMinorVersion!=1||version.dwBuildNumber!=2600||!product_name(name,sizeof(name))||!has(name,"Windows XP"))return 80;
    if(RegOpenKeyExA(HKEY_CURRENT_USER,"Software\\XP25BrandingFixture",0,KEY_QUERY_VALUE,&key))return 81;
    if(RegQueryValueExA(key,"Installed",NULL,&type,(BYTE*)&value,&size))value=0;
    RegCloseKey(key);return value==1 ? 0 : 82;
}
static void installer(void)
{
    char self[MAX_PATH],command[MAX_PATH+64];HKEY key=NULL;DWORD value=1,exitcode=99;
    STARTUPINFOA startup={0};PROCESS_INFORMATION process={0};BOOL ok;
    GetModuleFileNameA(NULL,self,sizeof(self));
    /* Clear only this fixture's own leftovers from a previously failed test. */
    SetFileAttributesA("C:\\xp25\\LegacyBrandingFixture\\legacy-version.exe",FILE_ATTRIBUTE_NORMAL);
    DeleteFileA("C:\\xp25\\LegacyBrandingFixture\\legacy-version.exe");
    RemoveDirectoryA("C:\\xp25\\LegacyBrandingFixture");
    ok=CreateDirectoryA("C:\\xp25\\LegacyBrandingFixture",NULL);
    report("legacy_setup_directory",ok,GetLastError());if(!ok)return;
    ok=CopyFileA(self,"C:\\xp25\\LegacyBrandingFixture\\legacy-version.exe",TRUE);
    report("legacy_setup_file_copy",ok,GetLastError());
    ok=RegCreateKeyExA(HKEY_CURRENT_USER,"Software\\XP25BrandingFixture",0,NULL,0,KEY_SET_VALUE|KEY_QUERY_VALUE,NULL,&key,NULL)==ERROR_SUCCESS &&
       RegSetValueExA(key,"Installed",0,REG_DWORD,(BYTE*)&value,sizeof(value))==ERROR_SUCCESS;
    if(key)RegCloseKey(key);
    report("legacy_setup_registration",ok,GetLastError());
    lstrcpyA(command,"C:\\xp25\\LegacyBrandingFixture\\legacy-version.exe --fixture-app");
    startup.cb=sizeof(startup);
    ok=CreateProcessA(NULL,command,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&startup,&process);
    if(ok){ok=WaitForSingleObject(process.hProcess,10000)==WAIT_OBJECT_0 && GetExitCodeProcess(process.hProcess,&exitcode) && exitcode==0;CloseHandle(process.hThread);CloseHandle(process.hProcess);}
    report("legacy_installed_application_version_detection",ok,exitcode);
    {
        DWORD start=GetTickCount();
        SetFileAttributesA("C:\\xp25\\LegacyBrandingFixture\\legacy-version.exe",FILE_ATTRIBUTE_NORMAL);
        do {ok=DeleteFileA("C:\\xp25\\LegacyBrandingFixture\\legacy-version.exe");if(ok)break;Sleep(100);} while(GetTickCount()-start<5000);
        ok=ok && RemoveDirectoryA("C:\\xp25\\LegacyBrandingFixture");
    }
    report("legacy_setup_file_uninstall",ok,GetLastError());
    report("legacy_setup_registry_uninstall",RegDeleteKeyA(HKEY_CURRENT_USER,"Software\\XP25BrandingFixture")==ERROR_SUCCESS,GetLastError());
}
static void calculator(void)
{
    STARTUPINFOA startup={0};PROCESS_INFORMATION process={0};
    char command[]="calc.exe",text[64]={0};HWND window=NULL,button,edit;BOOL ok;unsigned i;
    const UINT identifiers[]={81,126,92,126,112};
    startup.cb=sizeof(startup);ok=CreateProcessA(NULL,command,NULL,NULL,FALSE,0,NULL,NULL,&startup,&process);
    if(ok){
        DWORD start=GetTickCount(),pid=0;
        WaitForInputIdle(process.hProcess,10000);
        do {window=FindWindowA("SciCalc","Calculator");if(window)GetWindowThreadProcessId(window,&pid);
            if(window&&pid==process.dwProcessId)break;
            window=NULL;Sleep(100);
        }while(GetTickCount()-start<10000);
    }
    for(i=0;ok&&window&&i<5;++i){button=GetDlgItem(window,identifiers[i]);if(!button)ok=FALSE;else SendMessageA(window,WM_COMMAND,MAKEWPARAM(identifiers[i],BN_CLICKED),(LPARAM)button);}
    edit=window ? GetDlgItem(window,403):NULL;
    if(edit)SendMessageA(edit,WM_GETTEXT,sizeof(text),(LPARAM)text);
    /* XP Calculator right-pads its display with spaces. */
    {unsigned length=lstrlenA(text);while(length&&text[length-1]==' ')text[--length]=0;}
    {char line[180];wsprintfA(line,"{\"calculator_observation\":true,\"window\":%u,\"edit\":%u,\"buttons\":%u,\"text\":\"%s\"}\r\n",window!=NULL,edit!=NULL,ok,text);emit(line);}
    report("legacy_calculator_arithmetic",ok&&edit&&(lstrcmpA(text,"4.")==0||lstrcmpA(text,"4")==0),GetLastError());
    if(window)SendMessageA(window,WM_CLOSE,0,0);
    if(process.hProcess){WaitForSingleObject(process.hProcess,10000);CloseHandle(process.hThread);CloseHandle(process.hProcess);}
}
static void resources(void)
{
    WCHAR value[128];HMODULE module;
    module=LoadLibraryExA("winver.exe",NULL,LOAD_LIBRARY_AS_DATAFILE);
    report("winver_scoped_resource",module&&LoadStringW(module,101,value,128)>0&&
        lstrcmpW(value,(branded||system_brand)?L"Windows XP25":L"Windows")==0,GetLastError());
    if(module)FreeLibrary(module);
    if(branded){
        module=LoadLibraryExA("logonui.exe",NULL,LOAD_LIBRARY_AS_DATAFILE);
        report("login_scoped_resource",module&&LoadStringW(module,4000,value,128)>0&&lstrcmpW(value,L"Windows XP 25th Anniversary Edition")==0,GetLastError());
        if(module)FreeLibrary(module);
    }
}
static void layout(void)
{
    static const WCHAR alphabet[]=L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    HDC dc=GetDC(NULL);unsigned dpi;BOOL ok=dc!=NULL;
    for(dpi=96;ok&&dpi<=144;dpi+=24){
        HFONT font=CreateFontW(-MulDiv(8,dpi,72),0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,DEFAULT_QUALITY,DEFAULT_PITCH,L"MS Shell Dlg");
        HGDIOBJ old=font?SelectObject(dc,font):NULL;SIZE abc,first,second,about;TEXTMETRICW metric;
        ok=font&&GetTextExtentPoint32W(dc,alphabet,52,&abc)&&GetTextMetricsW(dc,&metric)&&
           GetTextExtentPoint32W(dc,L"Windows XP",10,&first)&&
           GetTextExtentPoint32W(dc,L"25th Anniversary Edition",24,&second)&&
           GetTextExtentPoint32W(dc,L"Windows XP 25th Anniversary Edition",lstrlenW(L"Windows XP 25th Anniversary Edition"),&about);
        if(ok){int base=(abc.cx/26+1)/2;ok=first.cx<=MulDiv(120,base,4)&&second.cx<=MulDiv(120,base,4)&&
            metric.tmHeight*2<=MulDiv(20,metric.tmHeight,8)&&about.cx<=MulDiv(261,base,4)&&metric.tmHeight<=MulDiv(10,metric.tmHeight,8);}
        if(old)SelectObject(dc,old);
        if(font)DeleteObject(font);
    }
    if(dc)ReleaseDC(NULL,dc);
    report("branding_label_metrics_96_120_144dpi",ok,GetLastError());
}
static DWORD msi_state(BOOL installed)
{
    HKEY key;DWORD value=0,type=0,size=sizeof(value);LONG error;
    error=RegOpenKeyExA(HKEY_CURRENT_USER,"Software\\XP25MsiBrandingFixture",0,KEY_QUERY_VALUE,&key);
    if(error==ERROR_FILE_NOT_FOUND)return installed?1:0;
    if(error)return 2;
    error=RegQueryValueExA(key,"Installed",NULL,&type,(BYTE*)&value,&size);RegCloseKey(key);
    return installed ? (error==ERROR_SUCCESS&&value==1?0:3) : (error==ERROR_FILE_NOT_FOUND?0:4);
}
void WINAPI ProbeMain(void)
{
    if(has(GetCommandLineA(),"--fixture-app"))ExitProcess(fixture_app());
    if(has(GetCommandLineA(),"--msi-installed"))ExitProcess(msi_state(TRUE));
    if(has(GetCommandLineA(),"--msi-absent"))ExitProcess(msi_state(FALSE));
    branded=has(GetCommandLineA(),"--branded");
    system_brand=has(GetCommandLineA(),"--system");
    serial=CreateFileA("COM1",GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);
    if(serial==INVALID_HANDLE_VALUE)ExitProcess(90);
    emit("BRANDING_PROBE_STARTED\r\n");
    if(has(GetCommandLineA(),"--msi-log")){
        static char log[65536];DWORD count=0;HANDLE file=CreateFileA("C:\\xp25\\msi-install.log",GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
        if(file!=INVALID_HANDLE_VALUE){
            ReadFile(file,log,sizeof(log)-2,&count,NULL);log[count]=0;log[count+1]=0;
            if(count>=2&&(BYTE)log[0]==0xff&&(BYTE)log[1]==0xfe){
                static char ansi[65536];
                int size=WideCharToMultiByte(CP_UTF8,0,(WCHAR*)(log+2),(count-2)/2,ansi,sizeof(ansi)-1,NULL,NULL);
                if(size>0){ansi[size]=0;emit(ansi);}
            }else emit(log);
            CloseHandle(file);
        }
        CloseHandle(serial);ExitProcess(0);
    }
    identity();identity_registry();resources();layout();installer();calculator();
    report("branding_probe_complete",failures==0,failures);
    CloseHandle(serial);ExitProcess(failures?1:0);
}
