/* XP25 compatibility proxy for Supermium's pwrp_k32.dll (NT 5.1 x86 only).
 *
 * Installed as pwrp_k32.dll beside the unmodified original, which is renamed
 * pwrp_k32_sm.dll. pwrp_k32.def forwards every original export unchanged
 * except ReadDirectoryChangesW.
 *
 * NT 5.1 cancels a pending IRP when the thread that issued it exits
 * (IoCancelThreadIo). Vista and later keep I/O on completion-port handles
 * alive instead, and Chromium's directory watcher depends on that: it arms a
 * watch on a thread-pool worker which may later be reclaimed, then CHECKs that
 * the port never reports ERROR_OPERATION_ABORTED (file_path_watcher_win.cc).
 *
 * An overlapped watch with no event and no completion routine can only be
 * observed through a completion port or the file handle itself. On an
 * asynchronous handle such a request is issued from one persistent thread, so
 * the issuing worker's exit no longer cancels it. The real call's result and
 * last error are returned unchanged, and completion still reaches the caller's
 * port with its own key and OVERLAPPED. Every other request, and any request
 * the persistent thread cannot take, calls the original export directly with
 * NT 5.1 semantics. Nothing is translated: errors from the real call,
 * including cancellation by handle close, reach the caller as before.
 *
 * Limit: CancelIo cancels only the calling thread's I/O on NT 5.1, so a watch
 * issued here is ended by closing its handle (as Chromium does), not CancelIo.
 */
#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0501
#include <windows.h>

typedef BOOL (WINAPI *READ_CHANGES)(HANDLE,LPVOID,DWORD,BOOL,DWORD,LPDWORD,LPOVERLAPPED,LPOVERLAPPED_COMPLETION_ROUTINE);
typedef struct {LONG Status;ULONG_PTR Information;} XP25_IO_STATUS;
typedef LONG (WINAPI *QUERY_FILE)(HANDLE,XP25_IO_STATUS *,PVOID,ULONG,ULONG);

#define XP25_FILE_MODE_INFORMATION 16
#define XP25_FILE_SYNCHRONOUS_IO (0x10|0x20)
/* Application-defined (bit 29) code no system API sets: last error untouched. */
#define XP25_LAST_ERROR_UNCHANGED 0x20255001UL
#define ISSUER_IDLE 0
#define ISSUER_STARTING 1
#define ISSUER_READY 2
#define ISSUER_UNAVAILABLE 3

typedef struct {
    HANDLE directory;LPVOID buffer;DWORD length;BOOL subtree;DWORD filter;LPDWORD returned;LPOVERLAPPED overlapped;
    BOOL result;DWORD error;HANDLE done;
} WATCH_REQUEST;

static READ_CHANGES real_read;
static QUERY_FILE query_file;
static HANDLE issuer;
static DWORD issuer_id;
static volatile LONG issuer_state=ISSUER_IDLE;

static READ_CHANGES resolve_read(void) {
    HMODULE original=GetModuleHandleW(L"pwrp_k32_sm.dll");FARPROC f=NULL;
    if(!original)original=LoadLibraryW(L"pwrp_k32_sm.dll");
    if(original)f=GetProcAddress(original,"ReadDirectoryChangesW");
    if(!f)f=GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"ReadDirectoryChangesW");
    return (READ_CHANGES)f;
}

static DWORD WINAPI issuer_main(LPVOID ready) {
    SetEvent((HANDLE)ready);
    /* An infinite alertable wait returns only after running queued APCs. */
    while(SleepEx(INFINITE,TRUE)==WAIT_IO_COMPLETION){}
    return 0;
}

static VOID CALLBACK issue(ULONG_PTR argument) {
    WATCH_REQUEST *r=(WATCH_REQUEST *)argument;
    SetLastError(XP25_LAST_ERROR_UNCHANGED);
    r->result=real_read(r->directory,r->buffer,r->length,r->subtree,r->filter,r->returned,r->overlapped,NULL);
    r->error=GetLastError();
    SetEvent(r->done);
}

/* The first caller starts the thread; others wait for that bounded attempt. */
static int start_issuer(void) {
    if(InterlockedCompareExchange((LONG *)&issuer_state,ISSUER_STARTING,ISSUER_IDLE)==ISSUER_IDLE) {
        HANDLE ready,thread=NULL;DWORD id=0;LONG next=ISSUER_UNAVAILABLE;
        query_file=(QUERY_FILE)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQueryInformationFile");
        ready=CreateEventW(NULL,TRUE,FALSE,NULL);
        if(ready && query_file)thread=CreateThread(NULL,65536,issuer_main,ready,STACK_SIZE_PARAM_IS_A_RESERVATION,&id);
        /* A thread that never started may still signal later, so only close the
         * event once it has been observed signalled. */
        if(thread && WaitForSingleObject(ready,2000)==WAIT_OBJECT_0) {
            issuer=thread;issuer_id=id;next=ISSUER_READY;CloseHandle(ready);
        }
        InterlockedExchange((LONG *)&issuer_state,next);
    }
    while(issuer_state==ISSUER_STARTING)Sleep(1);
    return issuer_state==ISSUER_READY;
}

static int thread_agnostic(HANDLE directory,LPOVERLAPPED overlapped,LPOVERLAPPED_COMPLETION_ROUTINE routine) {
    XP25_IO_STATUS status;ULONG mode=0;
    if(!overlapped || routine || overlapped->hEvent)return 0;
    if(!start_issuer() || GetCurrentThreadId()==issuer_id)return 0;
    if(query_file(directory,&status,&mode,sizeof(mode),XP25_FILE_MODE_INFORMATION)<0)return 0;
    return !(mode&XP25_FILE_SYNCHRONOUS_IO);
}

BOOL WINAPI Xp25ReadDirectoryChangesW(HANDLE directory,LPVOID buffer,DWORD length,BOOL subtree,DWORD filter,
                                      LPDWORD returned,LPOVERLAPPED overlapped,LPOVERLAPPED_COMPLETION_ROUTINE routine) {
    WATCH_REQUEST r;DWORD saved=GetLastError();
    if(!real_read)real_read=resolve_read();
    if(!real_read){SetLastError(ERROR_PROC_NOT_FOUND);return FALSE;}
    if(thread_agnostic(directory,overlapped,routine)) {
        r.directory=directory;r.buffer=buffer;r.length=length;r.subtree=subtree;r.filter=filter;r.returned=returned;
        r.overlapped=overlapped;r.result=FALSE;r.error=XP25_LAST_ERROR_UNCHANGED;r.done=CreateEventW(NULL,FALSE,FALSE,NULL);
        if(r.done && QueueUserAPC(issue,issuer,(ULONG_PTR)&r)) {
            WaitForSingleObject(r.done,INFINITE);CloseHandle(r.done);
            SetLastError(r.error==XP25_LAST_ERROR_UNCHANGED?saved:r.error);
            return r.result;
        }
        if(r.done)CloseHandle(r.done);
    }
    SetLastError(saved);
    return real_read(directory,buffer,length,subtree,filter,returned,overlapped,routine);
}

BOOL WINAPI Xp25PwrpEntry(HINSTANCE module,DWORD reason,LPVOID reserved) {
    (void)reserved;
    if(reason==DLL_PROCESS_ATTACH)DisableThreadLibraryCalls(module);
    return TRUE;
}
