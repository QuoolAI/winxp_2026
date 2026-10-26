/* Private test guests only. Debug one fresh browser profile and its descendants.
 * Pass application exceptions to their real handlers; never skip a CHECK/AV.
 * Debugger presence is an observer effect, compared with unmonitored runs.
 * Usage: browser_debug.exe [debug|plain|snapshot] [cycles hold_seconds tag]
 * A tagged run keeps its own log, profile and small dumps for A/B phases.
 */
#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0501
#include <windows.h>
#include <shellapi.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <dbghelp.h>
static HANDLE log_file,console;
typedef struct {DWORD pid;HANDLE process;DWORD initial_break,dumps;} BROWSER_PROCESS;
static BROWSER_PROCESS processes[128];static DWORD used,active,total_dumps,cycle;
static WCHAR command[4096],tag[20],profile[MAX_PATH],chrome_log[MAX_PATH];static BYTE stack_data[16384];static DWORD cycles=3,hold_ms=30000;
static void write_line(HANDLE file,const char *s){DWORD n;WriteFile(file,s,lstrlenA(s),&n,NULL);WriteFile(file,"\r\n",2,&n,NULL);}
static void log_line(const char *s){write_line(log_file,s);}
static BROWSER_PROCESS *find(DWORD pid){DWORD i;for(i=0;i<used;i++)if(processes[i].pid==pid && processes[i].process)return &processes[i];return NULL;}
static int in_ntdll(BROWSER_PROCESS *p,LPVOID address){
 MEMORY_BASIC_INFORMATION info;WCHAR path[512];DWORD i,start=0;
 if(!VirtualQueryEx(p->process,address,&info,sizeof(info)))return 0;
 path[0]=0;if(!GetMappedFileNameW(p->process,info.AllocationBase,path,512))return 0;
 path[511]=0;for(i=0;path[i];i++)if(path[i]==L'\\')start=i+1;
 return !lstrcmpiW(path+start,L"ntdll.dll");
}
static void command_line(BROWSER_PROCESS *p){
 typedef LONG (WINAPI *QUERY)(HANDLE,ULONG,PVOID,ULONG,PULONG);QUERY query;
 DWORD basic[6],peb[9],params[18],length;SIZE_T got;static WCHAR value[4096];static char text[12000];
 query=(QUERY)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQueryInformationProcess");
 if(!query || query(p->process,0,basic,sizeof(basic),NULL))return;
 if(!ReadProcessMemory(p->process,(void *)(UINT_PTR)basic[1],peb,sizeof(peb),&got) || !ReadProcessMemory(p->process,(void *)(UINT_PTR)peb[4],params,sizeof(params),&got))return;
 length=params[16]&0xffff;if(length>sizeof(value)-2)length=sizeof(value)-2;
 if(!ReadProcessMemory(p->process,(void *)(UINT_PTR)params[17],value,length,&got))return;
 value[length/2]=0;WideCharToMultiByte(CP_UTF8,0,value,-1,text,sizeof(text),NULL,NULL);log_line(text);
}
static void module(BROWSER_PROCESS *p,LPVOID base){
 WCHAR path[512];char name[1536],text[2048];DWORD header[64],pe[48];SIZE_T got;path[0]=0;
 if(!GetModuleFileNameExW(p->process,(HMODULE)base,path,512))GetMappedFileNameW(p->process,base,path,512);
 path[511]=0;WideCharToMultiByte(CP_UTF8,0,path,-1,name,sizeof(name),NULL,NULL);
 ZeroMemory(header,sizeof(header));ZeroMemory(pe,sizeof(pe));
 if(ReadProcessMemory(p->process,base,header,sizeof(header),&got) && header[15]<0x10000)
  ReadProcessMemory(p->process,(BYTE *)base+header[15],pe,sizeof(pe),&got);
 wsprintfA(text,"MODULE cycle=%lu pid=%lu base=%08lx size=%08lx timestamp=%08lx checksum=%08lx path=%s",cycle,p->pid,(DWORD)(UINT_PTR)base,pe[20],pe[2],pe[22],name);log_line(text);
}
static void memory(BROWSER_PROCESS *p){
 PROCESS_MEMORY_COUNTERS m;MEMORYSTATUSEX g;HANDLE token;BOOL job=FALSE;char s[512];ZeroMemory(&m,sizeof(m));m.cb=sizeof(m);
 if(GetProcessMemoryInfo(p->process,&m,sizeof(m))){wsprintfA(s,"MEMORY cycle=%lu pid=%lu working_set=%lu peak=%lu commit=%lu peak_commit=%lu",cycle,p->pid,m.WorkingSetSize,m.PeakWorkingSetSize,m.PagefileUsage,m.PeakPagefileUsage);log_line(s);}
 if(OpenProcessToken(p->process,TOKEN_QUERY,&token)){wsprintfA(s,"TOKEN pid=%lu restricted=%u",p->pid,IsTokenRestricted(token));log_line(s);CloseHandle(token);}
 if(IsProcessInJob(p->process,NULL,&job)){wsprintfA(s,"JOB pid=%lu member=%u",p->pid,job);log_line(s);}
 ZeroMemory(&g,sizeof(g));g.dwLength=sizeof(g);
 if(GlobalMemoryStatusEx(&g)){wsprintfA(s,"SYSTEM_MEMORY load=%lu available_phys_low=%lu available_virtual_low=%lu available_commit_low=%lu",g.dwMemoryLoad,(DWORD)g.ullAvailPhys,(DWORD)g.ullAvailVirtual,(DWORD)g.ullAvailPageFile);log_line(s);}
}
static void exception(BROWSER_PROCESS *p,DEBUG_EVENT *event){
 CONTEXT context;HANDLE thread,file;EXCEPTION_POINTERS pointers;MINIDUMP_EXCEPTION_INFORMATION info;
 EXCEPTION_RECORD *r=&event->u.Exception.ExceptionRecord;DWORD frame,i,words[10];SIZE_T got;char s[2048];WCHAR path[MAX_PATH];
 ZeroMemory(&context,sizeof(context));context.ContextFlags=CONTEXT_FULL;
 thread=OpenThread(THREAD_GET_CONTEXT|THREAD_QUERY_INFORMATION,FALSE,event->dwThreadId);
 wsprintfA(s,"EXCEPTION cycle=%lu pid=%lu tid=%lu code=%08lx address=%08lx first=%lu flags=%08lx parameters=%lu p0=%08lx p1=%08lx",cycle,p->pid,event->dwThreadId,r->ExceptionCode,(DWORD)(UINT_PTR)r->ExceptionAddress,event->u.Exception.dwFirstChance,r->ExceptionFlags,r->NumberParameters,r->ExceptionInformation[0],r->ExceptionInformation[1]);log_line(s);write_line(console,s);
 if(!thread || !GetThreadContext(thread,&context)){if(thread)CloseHandle(thread);return;}CloseHandle(thread);
 wsprintfA(s,"REGISTERS eip=%08lx esp=%08lx ebp=%08lx eax=%08lx ebx=%08lx ecx=%08lx edx=%08lx esi=%08lx edi=%08lx",context.Eip,context.Esp,context.Ebp,context.Eax,context.Ebx,context.Ecx,context.Edx,context.Esi,context.Edi);log_line(s);
 frame=context.Ebp;
 for(i=0;i<48 && frame>0 && frame<0x7fff0000;i++){
  if(!ReadProcessMemory(p->process,(LPVOID)(UINT_PTR)frame,words,sizeof(words),&got) || got!=sizeof(words))break;
  wsprintfA(s,"FRAME index=%lu ebp=%08lx return=%08lx arg0=%08lx arg1=%08lx arg2=%08lx arg3=%08lx arg4=%08lx arg5=%08lx",i,frame,words[1],words[2],words[3],words[4],words[5],words[6],words[7]);log_line(s);
  if(words[0]<=frame || words[0]>frame+0x100000)break;
  frame=words[0];
 }
 memory(p);command_line(p);
 if(total_dumps>=8 || p->dumps>=2)return;
 total_dumps++;p->dumps++;
 wsprintfW(path,L"C:\\xp25\\browserdiag\\%sc%lu-p%lu-t%lu-e%08lx-f%lu.stack",tag,cycle,p->pid,event->dwThreadId,r->ExceptionCode,event->u.Exception.dwFirstChance);
 file=CreateFileW(path,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,0,NULL);
 if(file!=INVALID_HANDLE_VALUE){if(ReadProcessMemory(p->process,(LPVOID)(UINT_PTR)context.Esp,stack_data,sizeof(stack_data),&got)){DWORD n;WriteFile(file,stack_data,(DWORD)got,&n,NULL);}CloseHandle(file);}
 wsprintfW(path,L"C:\\xp25\\browserdiag\\%sc%lu-p%lu-t%lu-e%08lx-f%lu.dmp",tag,cycle,p->pid,event->dwThreadId,r->ExceptionCode,event->u.Exception.dwFirstChance);
 file=CreateFileW(path,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,0,NULL);
 if(file!=INVALID_HANDLE_VALUE){BOOL ok;DWORD error;pointers.ExceptionRecord=r;pointers.ContextRecord=&context;info.ThreadId=event->dwThreadId;info.ExceptionPointers=&pointers;info.ClientPointers=FALSE;
  ok=MiniDumpWriteDump(p->process,p->pid,file,tag[0]?(MINIDUMP_TYPE)(MiniDumpNormal|MiniDumpWithIndirectlyReferencedMemory):MiniDumpWithFullMemory,&info,NULL,NULL);error=ok?0:GetLastError();CloseHandle(file);
  wsprintfA(s,"DUMP cycle=%lu pid=%lu full_memory=%u written=%u error=%lu",cycle,p->pid,!tag[0],ok,error);log_line(s);write_line(console,s);
 }
 FlushFileBuffers(log_file);
}
static void browser_command(void){
 wsprintfW(command,L"\"C:\\Program Files\\Supermium\\chrome.exe\" --no-first-run --disable-gpu --classic-omnibox --classic-omnibox-border --compact-ui --enable-features=SupermiumCustomTabs,ForceXpTheme --user-data-dir=%s --enable-logging --log-file=%s http://xp25.test:8080/local.html?cycle=%lu%s%s",profile,chrome_log,cycle,tag[0]?L"&run=":L"",tag);
}
static BOOL CALLBACK close_window(HWND window,LPARAM value){DWORD pid;GetWindowThreadProcessId(window,&pid);if(pid==(DWORD)value)PostMessageW(window,WM_CLOSE,0,0);return TRUE;}
static int run_plain_cycle(void){
 STARTUPINFOW startup;PROCESS_INFORMATION child;DWORD started,root,root_exit=STILL_ACTIVE,close_sent=0;char text[512];
 ZeroMemory(&startup,sizeof(startup));startup.cb=sizeof(startup);ZeroMemory(&child,sizeof(child));
 browser_command();
 if(!CreateProcessW(L"C:\\Program Files\\Supermium\\chrome.exe",command,NULL,NULL,FALSE,0,NULL,NULL,&startup,&child))return 1;
 root=child.dwProcessId;CloseHandle(child.hThread);started=GetTickCount();active=1;used=1;ZeroMemory(processes,sizeof(processes));processes[0].pid=root;processes[0].process=child.hProcess;
 wsprintfA(text,"PLAIN_PROCESS_CREATE cycle=%lu pid=%lu",cycle,root);log_line(text);write_line(console,text);
 for(;;){
  HANDLE snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);PROCESSENTRY32W entry;DWORD i;
  entry.dwSize=sizeof(entry);
  if(snapshot!=INVALID_HANDLE_VALUE){
   if(Process32FirstW(snapshot,&entry))do{
    if(!lstrcmpiW(entry.szExeFile,L"chrome.exe") && find(entry.th32ParentProcessID) && !find(entry.th32ProcessID) && used<128){
     HANDLE process=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ|SYNCHRONIZE,FALSE,entry.th32ProcessID);
     if(process){BROWSER_PROCESS *p=&processes[used++];ZeroMemory(p,sizeof(*p));p->pid=entry.th32ProcessID;p->process=process;active++;wsprintfA(text,"PLAIN_PROCESS_CREATE cycle=%lu pid=%lu parent=%lu",cycle,p->pid,entry.th32ParentProcessID);log_line(text);command_line(p);memory(p);}
    }
   }while(Process32NextW(snapshot,&entry));CloseHandle(snapshot);
  }
  for(i=0;i<used;i++)if(processes[i].process && WaitForSingleObject(processes[i].process,0)==WAIT_OBJECT_0){
   DWORD code;GetExitCodeProcess(processes[i].process,&code);wsprintfA(text,"PLAIN_PROCESS_EXIT cycle=%lu pid=%lu code=%08lx root=%u",cycle,processes[i].pid,code,processes[i].pid==root);log_line(text);write_line(console,text);memory(&processes[i]);if(processes[i].pid==root)root_exit=code;CloseHandle(processes[i].process);processes[i].process=NULL;active--;
  }
  if(!active)break;
  if(GetTickCount()-started>hold_ms && !close_sent){EnumWindows(close_window,(LPARAM)root);close_sent=1;wsprintfA(text,"PLAIN_CLOSE_REQUEST cycle=%lu root=%lu",cycle,root);log_line(text);write_line(console,text);}
  if(GetTickCount()-started>hold_ms+60000){for(i=0;i<used;i++)if(processes[i].process){memory(&processes[i]);CloseHandle(processes[i].process);}log_line("PLAIN_DEADLINE processes_left_running");return 124;}
  Sleep(250);
 }
 wsprintfA(text,"PLAIN_CYCLE_EXIT cycle=%lu root_code=%08lx elapsed_ms=%lu",cycle,root_exit,GetTickCount()-started);log_line(text);write_line(console,text);return root_exit?1:0;
}
static int run_cycle(void){
 STARTUPINFOW startup;PROCESS_INFORMATION child;DEBUG_EVENT event;DWORD started,root,root_exit=STILL_ACTIVE,close_sent=0;char text[1024];
 ZeroMemory(&startup,sizeof(startup));startup.cb=sizeof(startup);ZeroMemory(&child,sizeof(child));
 browser_command();
 if(!CreateProcessW(L"C:\\Program Files\\Supermium\\chrome.exe",command,NULL,NULL,FALSE,DEBUG_PROCESS,NULL,NULL,&startup,&child)){wsprintfA(text,"CREATE_FAILED error=%lu",GetLastError());log_line(text);write_line(console,text);return 1;}
 root=child.dwProcessId;CloseHandle(child.hThread);CloseHandle(child.hProcess);started=GetTickCount();active=0;used=0;
 if(!DebugSetProcessKillOnExit(FALSE)){wsprintfA(text,"DEBUG_KILL_POLICY_ERROR error=%lu",GetLastError());log_line(text);}
 for(;;){
  DWORD status=DBG_CONTINUE;BROWSER_PROCESS *p;
  if(GetTickCount()-started>hold_ms && !close_sent){EnumWindows(close_window,(LPARAM)root);close_sent=1;wsprintfA(text,"CLOSE_REQUEST cycle=%lu root=%lu",cycle,root);log_line(text);write_line(console,text);}
  if(GetTickCount()-started>hold_ms+60000){DWORD i;for(i=0;i<used;i++)if(processes[i].process){memory(&processes[i]);DebugActiveProcessStop(processes[i].pid);}log_line("DEADLINE detach_without_termination");write_line(console,"XP25_DEBUG_DEADLINE");return 124;}
  if(!WaitForDebugEvent(&event,250)){if(GetLastError()==ERROR_SEM_TIMEOUT)continue;wsprintfA(text,"WAIT_ERROR error=%lu",GetLastError());log_line(text);return 2;}
  p=find(event.dwProcessId);
  if(event.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT){
   if(used>=128)return 3;
   p=&processes[used++];ZeroMemory(p,sizeof(*p));p->pid=event.dwProcessId;p->process=event.u.CreateProcessInfo.hProcess;active++;
   wsprintfA(text,"PROCESS_CREATE cycle=%lu pid=%lu root=%lu image=%08lx",cycle,p->pid,root,(DWORD)(UINT_PTR)event.u.CreateProcessInfo.lpBaseOfImage);log_line(text);module(p,event.u.CreateProcessInfo.lpBaseOfImage);if(event.u.CreateProcessInfo.hFile)CloseHandle(event.u.CreateProcessInfo.hFile);
  }else if(event.dwDebugEventCode==LOAD_DLL_DEBUG_EVENT){if(p)module(p,event.u.LoadDll.lpBaseOfDll);if(event.u.LoadDll.hFile)CloseHandle(event.u.LoadDll.hFile);
  }else if(event.dwDebugEventCode==EXCEPTION_DEBUG_EVENT && p){
   DWORD code=event.u.Exception.ExceptionRecord.ExceptionCode;DWORD address=(DWORD)(UINT_PTR)event.u.Exception.ExceptionRecord.ExceptionAddress;
   if(code==EXCEPTION_BREAKPOINT && !p->initial_break && in_ntdll(p,(LPVOID)(UINT_PTR)address)){p->initial_break=1;wsprintfA(text,"INITIAL_LOADER_BREAK pid=%lu address=%08lx",p->pid,address);log_line(text);command_line(p);memory(p);}
   else {status=DBG_EXCEPTION_NOT_HANDLED;
    if(code!=0x406d1388){if(code==EXCEPTION_ACCESS_VIOLATION || code==EXCEPTION_ILLEGAL_INSTRUCTION || code==EXCEPTION_BREAKPOINT || !event.u.Exception.dwFirstChance)exception(p,&event);
     else {wsprintfA(text,"FIRST_CHANCE cycle=%lu pid=%lu code=%08lx address=%08lx",cycle,p->pid,code,address);log_line(text);}}
   }
  }else if(event.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT){wsprintfA(text,"PROCESS_EXIT cycle=%lu pid=%lu code=%08lx root=%u",cycle,event.dwProcessId,event.u.ExitProcess.dwExitCode,event.dwProcessId==root);log_line(text);write_line(console,text);if(event.dwProcessId==root)root_exit=event.u.ExitProcess.dwExitCode;if(p){memory(p);p->process=NULL;active--;}
  }else if(event.dwDebugEventCode==OUTPUT_DEBUG_STRING_EVENT && p){
   static char debug[4096];SIZE_T got;DWORD n=event.u.DebugString.nDebugStringLength;
   if(!event.u.DebugString.fUnicode && n<sizeof(debug) && ReadProcessMemory(p->process,event.u.DebugString.lpDebugStringData,debug,n,&got)){debug[got]=0;log_line(debug);}
  }
  ContinueDebugEvent(event.dwProcessId,event.dwThreadId,status);
  if(!active)break;
 }
 wsprintfA(text,"CYCLE_EXIT cycle=%lu root_code=%08lx elapsed_ms=%lu",cycle,root_exit,GetTickCount()-started);log_line(text);write_line(console,text);return root_exit?1:0;
}
static int snapshot_processes(void){
 HANDLE snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);PROCESSENTRY32W entry;DWORD count=0;entry.dwSize=sizeof(entry);
 if(snapshot!=INVALID_HANDLE_VALUE && Process32FirstW(snapshot,&entry))do{
  if(!lstrcmpiW(entry.szExeFile,L"chrome.exe") && count<12){
   BROWSER_PROCESS p;WCHAR path[MAX_PATH];HANDLE file;char text[512];BOOL ok;DWORD error;ZeroMemory(&p,sizeof(p));p.pid=entry.th32ProcessID;p.process=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ|PROCESS_DUP_HANDLE,FALSE,p.pid);
   if(!p.process){wsprintfA(text,"SNAPSHOT_OPEN_ERROR pid=%lu error=%lu",p.pid,GetLastError());log_line(text);continue;}
   count++;wsprintfA(text,"SNAPSHOT_PROCESS pid=%lu parent=%lu",p.pid,entry.th32ParentProcessID);log_line(text);command_line(&p);memory(&p);
   wsprintfW(path,L"C:\\xp25\\browserdiag\\snapshot-p%lu.dmp",p.pid);file=CreateFileW(path,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,0,NULL);
   if(file!=INVALID_HANDLE_VALUE){ok=MiniDumpWriteDump(p.process,p.pid,file,MiniDumpNormal,NULL,NULL,NULL);error=ok?0:GetLastError();CloseHandle(file);wsprintfA(text,"SNAPSHOT_DUMP pid=%lu success=%u error=%lu",p.pid,ok,error);log_line(text);write_line(console,text);}
   CloseHandle(p.process);
  }
 }while(Process32NextW(snapshot,&entry));
 if(snapshot!=INVALID_HANDLE_VALUE)CloseHandle(snapshot);
 FlushFileBuffers(log_file);return count?0:7;
}
static int parse_number(LPCWSTR s,DWORD low,DWORD high,DWORD *value){
 DWORD n=0,i;for(i=0;s[i];i++){if(s[i]<L'0'||s[i]>L'9'||i>5)return 0;n=n*10+(s[i]-L'0');}
 if(!i||n<low||n>high)return 0;
 *value=n;return 1;
}
static int parse_tag(LPCWSTR s){
 DWORD i;for(i=0;s[i];i++)if(i>=16||!((s[i]>=L'a'&&s[i]<=L'z')||(s[i]>=L'A'&&s[i]<=L'Z')||(s[i]>=L'0'&&s[i]<=L'9')))return 0;
 if(!i)return 0;
 wsprintfW(tag,L"%s-",s);return 1;
}
void WINAPI DebugMain(void){DWORD errors=0;int argc=0,plain=0,snapshot=0;WCHAR **argv=CommandLineToArgvW(GetCommandLineW(),&argc),log_path[MAX_PATH];
 if(argc>=2 && !lstrcmpW(argv[1],L"plain"))plain=1;
 if(argc==2 && !lstrcmpW(argv[1],L"snapshot"))snapshot=1;
 if(argc==5 && (plain || !lstrcmpW(argv[1],L"debug"))){DWORD hold;if(!parse_number(argv[2],1,40,&cycles) || !parse_number(argv[3],10,300,&hold) || !parse_tag(argv[4]))ExitProcess(87);hold_ms=hold*1000;}
 else if(argc>2 || (argc==2 && !plain && !snapshot))ExitProcess(87);
 if(argv)LocalFree(argv);
 console=GetStdHandle(STD_OUTPUT_HANDLE);CreateDirectoryW(L"C:\\xp25",NULL);CreateDirectoryW(L"C:\\xp25\\browserdiag",NULL);
 wsprintfW(profile,L"C:\\xp25\\browserdiag\\%sProfile",tag);wsprintfW(chrome_log,L"C:\\xp25\\browserdiag\\%schrome.log",tag);
 wsprintfW(log_path,snapshot?L"C:\\xp25\\browserdiag\\snapshot.log":L"C:\\xp25\\browserdiag\\%sevents.log",tag);
 log_file=CreateFileW(log_path,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_ALWAYS,0,NULL);if(log_file==INVALID_HANDLE_VALUE)ExitProcess(4);
 if(snapshot){int result=snapshot_processes();CloseHandle(log_file);ExitProcess(result);}
 for(cycle=1;cycle<=cycles;cycle++){int code=plain?run_plain_cycle():run_cycle();if(code)errors++;FlushFileBuffers(log_file);if(code==124)break;Sleep(3000);}
 {char text[256];wsprintfA(text,"RUN_SUMMARY mode=%s cycles=%lu hold_ms=%lu failed_cycles=%lu",plain?"plain":"debug",cycles,hold_ms,errors);log_line(text);write_line(console,text);}
 CloseHandle(log_file);ExitProcess(errors?1:0);
}
