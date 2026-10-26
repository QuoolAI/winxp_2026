/* Verify the XP25 pwrp_k32 proxy against kernel32 and Supermium's original
 * wrapper, using Chromium's watcher pattern: arm on a worker that exits, then
 * change or close the directory. Results are reported, never translated.
 * Usage: browser_watch.exe <directory containing pwrp_k32.dll and pwrp_k32_sm.dll>
 */
#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0501
#include <windows.h>
#include <shellapi.h>
typedef BOOL (WINAPI *READ_CHANGES)(HANDLE,LPVOID,DWORD,BOOL,DWORD,LPDWORD,LPOVERLAPPED,LPOVERLAPPED_COMPLETION_ROUTINE);
typedef struct {READ_CHANGES read;HANDLE directory;OVERLAPPED request;DWORD issue_error;DWORD routine_thread;DWORD routine_error;DWORD routine_bytes;BYTE buffer[4096];} WATCH;
static HANDLE output;static DWORD failures;static WATCH watches[64];static OVERLAPPED requests[2];static READ_CHANGES kernel_read,original_read,proxy_read;
static const WCHAR root[]=L"C:\\xp25\\watch-proof";
static void line(const char *s){DWORD n;WriteFile(output,s,lstrlenA(s),&n,NULL);WriteFile(output,"\r\n",2,&n,NULL);}
static void check(int ok,const char *s){char t[640];wsprintfA(t,"WATCH %s %s",ok?"PASS":"FAIL",s);line(t);if(!ok)failures++;}
static HANDLE open_root(int overlapped){return CreateFileW(root,FILE_LIST_DIRECTORY,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|(overlapped?FILE_FLAG_OVERLAPPED:0),NULL);}
static DWORD arm(WATCH *w){return w->read(w->directory,w->buffer,sizeof(w->buffer),FALSE,FILE_NOTIFY_CHANGE_FILE_NAME,NULL,&w->request,NULL)?0:GetLastError();}
static DWORD WINAPI arm_and_exit(LPVOID argument){WATCH *w=(WATCH *)argument;w->issue_error=arm(w);return 0;}
static VOID CALLBACK routine(DWORD error,DWORD bytes,LPOVERLAPPED request){WATCH *w=(WATCH *)request->hEvent;w->routine_thread=GetCurrentThreadId();w->routine_error=error;w->routine_bytes=bytes;}
static DWORD WINAPI arm_with_routine(LPVOID argument){
 WATCH *w=(WATCH *)argument;DWORD i;w->request.hEvent=(HANDLE)w;
 w->issue_error=w->read(w->directory,w->buffer,sizeof(w->buffer),FALSE,FILE_NOTIFY_CHANGE_FILE_NAME,NULL,&w->request,routine)?0:GetLastError();
 for(i=0;i<50 && !w->routine_thread;i++)SleepEx(100,TRUE);
 return 0;
}
static int run_worker(LPTHREAD_START_ROUTINE start,WATCH *w,DWORD *thread_id){
 HANDLE thread=CreateThread(NULL,0,start,w,0,thread_id);DWORD wait;if(!thread)return 0;
 wait=WaitForSingleObject(thread,10000);CloseHandle(thread);return wait==WAIT_OBJECT_0;
}
static void touch(DWORD n){WCHAR path[MAX_PATH];HANDLE f;wsprintfW(path,L"%s\\w%lu.tmp",root,n);f=CreateFileW(path,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,0,NULL);if(f!=INVALID_HANDLE_VALUE)CloseHandle(f);DeleteFileW(path);}
static int names_file(WATCH *w,DWORD n,DWORD bytes){
 FILE_NOTIFY_INFORMATION *info=(FILE_NOTIFY_INFORMATION *)w->buffer;WCHAR name[32];DWORD length=(DWORD)wsprintfW(name,L"w%lu.tmp",n)*sizeof(WCHAR);
 DWORD i;if(bytes<sizeof(*info) || info->Action!=FILE_ACTION_ADDED || info->FileNameLength!=length)return 0;
 for(i=0;i<length/sizeof(WCHAR);i++)if(info->FileName[i]!=name[i])return 0;
 return 1;
}
static void dequeue(HANDLE port,DWORD timeout,BOOL *ok,DWORD *error,DWORD *bytes,ULONG_PTR *key,OVERLAPPED **completed){
 *completed=NULL;*bytes=0;*key=0;*ok=GetQueuedCompletionStatus(port,bytes,key,completed,timeout);*error=*ok?0:GetLastError();
}
/* Arm on a worker that exits; then either create a file or close the handle. */
static void exited_worker(const char *path,READ_CHANGES read,int change,DWORD iteration,int expect_cancel){
 WATCH *w=&watches[0];HANDLE port;BOOL ok;DWORD error,bytes,id;ULONG_PTR key;OVERLAPPED *completed;char t[512];int good;
 ZeroMemory(w,sizeof(*w));w->read=read;w->directory=open_root(1);if(w->directory==INVALID_HANDLE_VALUE){check(0,"open directory");return;}
 port=CreateIoCompletionPort(w->directory,NULL,0x2500+iteration,1);
 if(!port || !run_worker(arm_and_exit,w,&id) || w->issue_error){check(0,"arm on worker");CloseHandle(w->directory);if(port)CloseHandle(port);return;}
 Sleep(50);
 if(change)touch(iteration);else {CloseHandle(w->directory);w->directory=NULL;}
 dequeue(port,5000,&ok,&error,&bytes,&key,&completed);
 if(expect_cancel)good=!ok && error==ERROR_OPERATION_ABORTED && !bytes;
 else if(change)good=ok && names_file(w,iteration,bytes);
 else good=ok && !bytes;
 good=good && key==0x2500+iteration && completed==&w->request;
 wsprintfA(t,"%s %s iteration=%lu success=%u error=%lu bytes=%lu key_match=%u request_match=%u",path,change?"change_after_issuer_exit":"close_after_issuer_exit",iteration,ok,error,bytes,key==0x2500+iteration,completed==&w->request);check(good,t);
 if(w->directory)CloseHandle(w->directory);
 CloseHandle(port);
}
static void event_request(DWORD iteration){
 WATCH *w=&watches[0];HANDLE port,event;BOOL ok;DWORD error,bytes,id;ULONG_PTR key;OVERLAPPED *completed;char t[512];
 ZeroMemory(w,sizeof(*w));w->read=proxy_read;w->directory=open_root(1);event=CreateEventW(NULL,TRUE,FALSE,NULL);w->request.hEvent=event;
 port=CreateIoCompletionPort(w->directory,NULL,0x2600,1);
 if(!run_worker(arm_and_exit,w,&id) || w->issue_error){check(0,"event arm");}
 else {dequeue(port,5000,&ok,&error,&bytes,&key,&completed);
  wsprintfA(t,"proxy event_request_unchanged_nt51 iteration=%lu success=%u error=%lu bytes=%lu",iteration,ok,error,bytes);check(!ok && error==ERROR_OPERATION_ABORTED && completed==&w->request,t);}
 CloseHandle(w->directory);CloseHandle(port);CloseHandle(event);
}
static void routine_request(void){
 WATCH *w=&watches[0];HANDLE thread;DWORD id=0;char t[512];
 ZeroMemory(w,sizeof(*w));w->read=proxy_read;w->directory=open_root(1);
 thread=CreateThread(NULL,0,arm_with_routine,w,0,&id);Sleep(300);touch(77);
 if(thread){WaitForSingleObject(thread,10000);CloseHandle(thread);}
 wsprintfA(t,"proxy completion_routine_on_issuing_thread issue_error=%lu routine_on_caller=%u error=%lu bytes=%lu",w->issue_error,w->routine_thread==id,w->routine_error,w->routine_bytes);
 check(!w->issue_error && w->routine_thread==id && !w->routine_error && names_file(w,77,w->routine_bytes),t);CloseHandle(w->directory);
}
/* Requests here complete after closing, so their OVERLAPPED storage is static. */
static void errors_match(void){
 HANDLE directory;BYTE buffer[512];BOOL rk,rp;DWORD ek,ep;char t[512];
 ZeroMemory(requests,sizeof(requests));
 SetLastError(12345);rk=kernel_read(NULL,buffer,sizeof(buffer),FALSE,FILE_NOTIFY_CHANGE_FILE_NAME,NULL,&requests[0],NULL);ek=GetLastError();
 SetLastError(12345);rp=proxy_read(NULL,buffer,sizeof(buffer),FALSE,FILE_NOTIFY_CHANGE_FILE_NAME,NULL,&requests[1],NULL);ep=GetLastError();
 wsprintfA(t,"invalid_handle kernel32=%u/%lu proxy=%u/%lu",rk,ek,rp,ep);check(!rk && rk==rp && ek==ep && ek!=12345,t);
 directory=open_root(1);ZeroMemory(requests,sizeof(requests));
 SetLastError(12345);rp=proxy_read(directory,watches[1].buffer,sizeof(watches[1].buffer),FALSE,FILE_NOTIFY_CHANGE_FILE_NAME,NULL,&requests[1],NULL);ep=GetLastError();
 CloseHandle(directory);Sleep(100);directory=open_root(1);
 SetLastError(12345);rk=kernel_read(directory,watches[2].buffer,sizeof(watches[2].buffer),FALSE,FILE_NOTIFY_CHANGE_FILE_NAME,NULL,&requests[0],NULL);ek=GetLastError();
 wsprintfA(t,"pending_success_last_error kernel32=%u/%lu proxy=%u/%lu",rk,ek,rp,ep);check(rk && rp && ek==ep,t);CloseHandle(directory);Sleep(100);
}
static void concurrent(void){
 HANDLE port=NULL,threads[32];DWORD i,ok_count=0,id;char t[256];BOOL ok;DWORD error,bytes;ULONG_PTR key;OVERLAPPED *completed;
 for(i=0;i<32;i++){WATCH *w=&watches[i];ZeroMemory(w,sizeof(*w));w->read=proxy_read;w->directory=open_root(1);port=CreateIoCompletionPort(w->directory,port,0x2700+i,1);threads[i]=CreateThread(NULL,0,arm_and_exit,w,0,&id);}
 for(i=0;i<32;i++)if(threads[i]){WaitForSingleObject(threads[i],10000);CloseHandle(threads[i]);}
 Sleep(100);touch(500);
 for(i=0;i<32;i++){dequeue(port,5000,&ok,&error,&bytes,&key,&completed);if(ok && key>=0x2700 && key<0x2720 && completed==&watches[key-0x2700].request && names_file(&watches[key-0x2700],500,bytes))ok_count++;}
 wsprintfA(t,"proxy concurrent_exited_issuers completed=%lu of 32",ok_count);check(ok_count==32,t);
 for(i=0;i<32;i++)CloseHandle(watches[i].directory);
 CloseHandle(port);
}
void WINAPI WatchMain(void){
 int argc=0;WCHAR **argv=CommandLineToArgvW(GetCommandLineW(),&argc),path[MAX_PATH];HMODULE original,proxy,owner=NULL;DWORD i;char t[512];
 output=GetStdHandle(STD_OUTPUT_HANDLE);
 if(argc!=2 || lstrlenW(argv[1])>200)ExitProcess(87);
 SetCurrentDirectoryW(argv[1]);
 wsprintfW(path,L"%s\\pwrp_k32_sm.dll",argv[1]);original=LoadLibraryW(path);
 wsprintfW(path,L"%s\\pwrp_k32.dll",argv[1]);proxy=LoadLibraryW(path);
 kernel_read=(READ_CHANGES)GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"ReadDirectoryChangesW");
 if(!original || !proxy || !kernel_read){wsprintfA(t,"WATCH_LOAD_FAILED original=%u proxy=%u error=%lu",original!=NULL,proxy!=NULL,GetLastError());line(t);ExitProcess(2);}
 original_read=(READ_CHANGES)GetProcAddress(original,"ReadDirectoryChangesW");proxy_read=(READ_CHANGES)GetProcAddress(proxy,"ReadDirectoryChangesW");
 GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,(LPCWSTR)(ULONG_PTR)proxy_read,&owner);
 check(original_read && proxy_read && owner==proxy,"proxy implements ReadDirectoryChangesW");
 check(GetProcAddress(proxy,"CreateIoCompletionPort")==GetProcAddress(original,"CreateIoCompletionPort") && GetProcAddress(proxy,"ReadDirectoryChangesExW")==GetProcAddress(original,"ReadDirectoryChangesExW"),"other exports forward to the original wrapper");
 CreateDirectoryW(L"C:\\xp25",NULL);if(!CreateDirectoryW(root,NULL)){line("WATCH_ROOT_EXISTS");ExitProcess(3);}
 for(i=0;i<4;i++){exited_worker("kernel32",kernel_read,1,i,1);exited_worker("original_wrapper",original_read,1,i,1);}
 for(i=0;i<8;i++){exited_worker("proxy",proxy_read,1,i,0);exited_worker("proxy",proxy_read,0,i,0);}
 for(i=0;i<2;i++)event_request(i);
 routine_request();errors_match();concurrent();
 RemoveDirectoryW(root);wsprintfA(t,"WATCH_SUMMARY failures=%lu",failures);line(t);LocalFree(argv);ExitProcess(failures?1:0);
}
