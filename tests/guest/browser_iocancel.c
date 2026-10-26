/* Reproduce a real directory-watch completion on close, without translating
 * NT/Win32 error codes. Only a newly created test directory is touched. */
#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0501
#include <windows.h>
static BYTE buffer[8192];static HANDLE output;
static void line(const char *s){DWORD n;WriteFile(output,s,lstrlenA(s),&n,NULL);WriteFile(output,"\r\n",2,&n,NULL);}
typedef struct {HANDLE directory;OVERLAPPED request;} WATCH;
static DWORD WINAPI issue_and_exit(LPVOID argument){WATCH *watch=(WATCH *)argument;return ReadDirectoryChangesW(watch->directory,buffer,sizeof(buffer),FALSE,FILE_NOTIFY_CHANGE_FILE_NAME,NULL,&watch->request,NULL)?0:GetLastError();}
void WINAPI IoCancelMain(void){DWORD i,failures=0;output=GetStdHandle(STD_OUTPUT_HANDLE);CreateDirectoryW(L"C:\\xp25",NULL);CreateDirectoryW(L"C:\\xp25\\watcher-proof",NULL);
 for(i=0;i<8;i++){
  HANDLE directory,port,file;OVERLAPPED request,*completed;DWORD bytes,error;ULONG_PTR key;BOOL ok;WCHAR path[MAX_PATH];char text[512];
  directory=CreateFileW(L"C:\\xp25\\watcher-proof",FILE_LIST_DIRECTORY,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OVERLAPPED,NULL);
  if(directory==INVALID_HANDLE_VALUE)ExitProcess(2);
  port=CreateIoCompletionPort(directory,NULL,1,1);if(!port)ExitProcess(3);ZeroMemory(&request,sizeof(request));
  ok=ReadDirectoryChangesW(directory,buffer,sizeof(buffer),FALSE,FILE_NOTIFY_CHANGE_FILE_NAME,NULL,&request,NULL);if(!ok)ExitProcess(4);
  wsprintfW(path,L"C:\\xp25\\watcher-proof\\p%lu.tmp",i);file=CreateFileW(path,GENERIC_WRITE,0,NULL,CREATE_NEW,0,NULL);if(file==INVALID_HANDLE_VALUE)ExitProcess(5);CloseHandle(file);
  completed=NULL;bytes=0;key=0;ok=GetQueuedCompletionStatus(port,&bytes,&key,&completed,5000);error=ok?0:GetLastError();
  wsprintfA(text,"IOCANCEL positive iteration=%lu success=%u error=%lu bytes=%lu key=%lu matching_request=%u",i,ok,error,bytes,(DWORD)key,completed==&request);line(text);if(!ok || key!=1 || completed!=&request || !bytes)failures++;
  ZeroMemory(&request,sizeof(request));ok=ReadDirectoryChangesW(directory,buffer,sizeof(buffer),FALSE,FILE_NOTIFY_CHANGE_FILE_NAME,NULL,&request,NULL);if(!ok)ExitProcess(6);
  CloseHandle(directory);completed=NULL;bytes=0;key=0;ok=GetQueuedCompletionStatus(port,&bytes,&key,&completed,5000);error=ok?0:GetLastError();
  wsprintfA(text,"IOCANCEL closed iteration=%lu success=%u error=%lu bytes=%lu key=%lu matching_request=%u",i,ok,error,bytes,(DWORD)key,completed==&request);line(text);
  if(bytes || key!=1 || completed!=&request || (!ok && error!=ERROR_OPERATION_ABORTED && error!=ERROR_ACCESS_DENIED))failures++;
  CloseHandle(port);DeleteFileW(path);
 }
 /* NT cancels I/O owned by an exiting issuing thread. The watch handle stays
  * open until after this completion; do not translate cancellation to success. */
 for(i=0;i<8;i++){
  WATCH watch;HANDLE port,thread;DWORD code,bytes,error;ULONG_PTR key;OVERLAPPED *completed;BOOL ok;char text[512];
  ZeroMemory(&watch,sizeof(watch));watch.directory=CreateFileW(L"C:\\xp25\\watcher-proof",FILE_LIST_DIRECTORY,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OVERLAPPED,NULL);if(watch.directory==INVALID_HANDLE_VALUE)ExitProcess(7);
  port=CreateIoCompletionPort(watch.directory,NULL,2,1);if(!port)ExitProcess(8);
  thread=CreateThread(NULL,0,issue_and_exit,&watch,0,NULL);if(!thread)ExitProcess(9);
  if(WaitForSingleObject(thread,5000)!=WAIT_OBJECT_0)ExitProcess(10);
  if(!GetExitCodeThread(thread,&code)||code)ExitProcess(11);
  CloseHandle(thread);
  completed=NULL;bytes=0;key=0;ok=GetQueuedCompletionStatus(port,&bytes,&key,&completed,5000);error=ok?0:GetLastError();
  wsprintfA(text,"IOCANCEL issuing_thread_exit iteration=%lu success=%u error=%lu bytes=%lu key=%lu matching_request=%u",i,ok,error,bytes,(DWORD)key,completed==&watch.request);line(text);
  if(ok || error!=ERROR_OPERATION_ABORTED || bytes || key!=2 || completed!=&watch.request)failures++;
  CloseHandle(watch.directory);CloseHandle(port);
 }
 RemoveDirectoryW(L"C:\\xp25\\watcher-proof");ExitProcess(failures?1:0);
}
