/* Isolated browser test fixture only. A bounded bridge from the fixture gateway
 * (10.25.0.1) to Chromium's loopback-only DevTools port in an empty test profile.
 * Never installed or enabled in a packaged browser configuration.
 */
#define _WIN32_WINNT 0x0501
#include <winsock2.h>
#include <windows.h>
static DWORD WINAPI forward(LPVOID arg) {
    SOCKET client=(SOCKET)(UINT_PTR)arg,upstream;struct sockaddr_in addr;char buf[16384];
    upstream=socket(AF_INET,SOCK_STREAM,0);
    ZeroMemory(&addr,sizeof(addr));addr.sin_family=AF_INET;addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);addr.sin_port=htons(9222);
    if(upstream==INVALID_SOCKET || connect(upstream,(struct sockaddr *)&addr,sizeof(addr)))goto done;
    for(;;){fd_set r;struct timeval tv;int n,k;SOCKET from,to;
        r.fd_count=2;r.fd_array[0]=client;r.fd_array[1]=upstream;tv.tv_sec=30;tv.tv_usec=0;
        n=select(0,&r,NULL,NULL,&tv);if(n<=0)break;
        from=FD_ISSET(client,&r)?client:upstream;to=from==client?upstream:client;
        n=recv(from,buf,sizeof(buf),0);if(n<=0)break;
        for(k=0;k<n;){int w=send(to,buf+k,n-k,0);if(w<=0)goto done;k+=w;}
    }
 done:if(upstream!=INVALID_SOCKET)closesocket(upstream);closesocket(client);return 0;
}
void WINAPI BridgeMain(void) {
    WSADATA w;SOCKET listener;struct sockaddr_in addr;DWORD started=GetTickCount();
    if(WSAStartup(MAKEWORD(2,2),&w))ExitProcess(1);
    listener=socket(AF_INET,SOCK_STREAM,0);ZeroMemory(&addr,sizeof(addr));addr.sin_family=AF_INET;
    addr.sin_addr.s_addr=inet_addr("10.25.0.10");addr.sin_port=htons(9223);
    if(listener==INVALID_SOCKET || bind(listener,(struct sockaddr *)&addr,sizeof(addr)) || listen(listener,8))ExitProcess(2);
    while(GetTickCount()-started<1800000){fd_set r;struct timeval tv;int size=sizeof(addr);SOCKET client;HANDLE t;
        r.fd_count=1;r.fd_array[0]=listener;tv.tv_sec=1;tv.tv_usec=0;
        if(select(0,&r,NULL,NULL,&tv)<=0)continue;
        client=accept(listener,(struct sockaddr *)&addr,&size);
        if(client==INVALID_SOCKET)continue;
        if(addr.sin_addr.s_addr!=inet_addr("10.25.0.1")){closesocket(client);continue;}
        t=CreateThread(NULL,0,forward,(LPVOID)(UINT_PTR)client,0,NULL);if(t)CloseHandle(t);else closesocket(client);
    }
    closesocket(listener);WSACleanup();ExitProcess(0);
}
