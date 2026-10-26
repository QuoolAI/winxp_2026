/* Test guest only: Application Error metadata, no profile/browser data. */
#define _WIN32_WINNT 0x0501
#include <windows.h>
static DWORD buffer[16384];
static void line(const char *s) {
    DWORD n;HANDLE h=GetStdHandle(STD_OUTPUT_HANDLE);
    WriteFile(h,s,lstrlenA(s),&n,NULL);WriteFile(h,"\r\n",2,&n,NULL);
}
void WINAPI CrashMain(void) {
    HANDLE log=OpenEventLogA(NULL,"Application");DWORD bytes,needed,count=0;
    if(!log)ExitProcess(GetLastError());
    while(count<256 && ReadEventLogA(log,EVENTLOG_BACKWARDS_READ|EVENTLOG_SEQUENTIAL_READ,0,
                                  buffer,sizeof(buffer),&bytes,&needed)) {
        DWORD pos=0;
        while(pos+sizeof(EVENTLOGRECORD)<=bytes && count++<256) {
            EVENTLOGRECORD *r=(EVENTLOGRECORD *)((BYTE *)buffer+pos);char text[256];DWORD off,i;
            if(r->Length<sizeof(*r) || r->Length>bytes-pos)break;
            if(r->EventType==EVENTLOG_ERROR_TYPE) {
                wsprintfA(text,"APPLICATION_ERROR event=%lu record=%lu time=%lu",r->EventID,r->RecordNumber,r->TimeGenerated);line(text);
                off=r->StringOffset;
                for(i=0;i<r->NumStrings && off<r->Length;i++) {
                    char *s=(char *)r+off;DWORD remain=r->Length-off,n=0;
                    while(n<remain && s[n])n++;
                    if(n==remain)break;
                    line(s);off+=n+1;
                }
            }
            pos+=r->Length;
        }
    }
    CloseEventLog(log);ExitProcess(0);
}
