/* Test-only: start Supermium with the arguments that follow, at the same SAFER
 * Normal User level as XP25's launcher, then wait and return its exit code.
 * Lets DevTools-driven regressions exercise the shipping privilege level.
 * Never installed; XP25Browser.exe builds only fixed, validated arguments.
 */
#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0501
#include <windows.h>
#include <winsafer.h>
static WCHAR command[8192];
void WINAPI LaunchMain(void){
 LPCWSTR tail=GetCommandLineW();SAFER_LEVEL_HANDLE level=NULL;HANDLE token=NULL;STARTUPINFOW si;PROCESS_INFORMATION pi;DWORD code=1,quoted=0;
 static const WCHAR program[]=L"C:\\Program Files\\Supermium\\chrome.exe";
 for(;*tail && (quoted || (*tail!=L' ' && *tail!=L'\t'));tail++)if(*tail==L'"')quoted=!quoted;
 while(*tail==L' ' || *tail==L'\t')tail++;
 if(lstrlenW(tail)+lstrlenW(program)+4>=8192)ExitProcess(ERROR_BUFFER_OVERFLOW);
 wsprintfW(command,L"\"%s\" %s",program,tail);
 if(!SaferCreateLevel(SAFER_SCOPEID_USER,SAFER_LEVELID_NORMALUSER,SAFER_LEVEL_OPEN,&level,NULL))ExitProcess(GetLastError());
 if(!SaferComputeTokenFromLevel(level,NULL,&token,0,NULL)){code=GetLastError();SaferCloseLevel(level);ExitProcess(code);}
 SaferCloseLevel(level);ZeroMemory(&si,sizeof(si));si.cb=sizeof(si);
 if(!CreateProcessAsUserW(token,program,command,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi)){code=GetLastError();CloseHandle(token);ExitProcess(code);}
 CloseHandle(token);CloseHandle(pi.hThread);WaitForSingleObject(pi.hProcess,INFINITE);GetExitCodeProcess(pi.hProcess,&code);CloseHandle(pi.hProcess);ExitProcess(code);
}
