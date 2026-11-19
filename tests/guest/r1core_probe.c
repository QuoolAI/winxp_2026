/* R-1: the rebuilt win32k.sys, user32.dll and gdi32.dll in a running guest. Observations
   and ordinary API use only: nothing is mapped writable, no malformed file is used.

   gdi_section  Counts this process's own handles to the GDI shared handle table section
                (a Section with SEC_NO_CHANGE whose size matches the read-only view at
                PEB->GdiSharedHandleTable) and reports their granted access. The 1106
                win32k leaves one SECTION_ALL_ACCESS handle in every GUI process; the R-1
                build leaves none.
   cursors      Loads every .ani and .cur file in %windir%\Cursors with LoadCursorFromFileW
                and draws each animated cursor through its steps (DrawIconEx), which uses
                the kernel's frame and sequence tables.
   metafile     Records a WMF (rectangle and line), plays it into a memory bitmap, converts
                it to an EMF and plays that too; both must draw.

   One JSON record per check on COM1 (retried) and in C:\xp25-r1core.json.
   Exit 0 when the cursors and metafiles all work and no GDI section handle is held. */
#define WINVER 0x0501
#define _WIN32_WINNT 0x0501
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

typedef LONG (WINAPI *QSI)(ULONG, PVOID, ULONG, PULONG);
typedef LONG (WINAPI *QS)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef LONG (WINAPI *QIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef struct { USHORT pid, backtrace; UCHAR type, attributes; USHORT handle; PVOID object; ULONG access; } HANDLE_ENTRY;
typedef struct { PVOID base; ULONG attributes; LARGE_INTEGER size; } SECTION_BASIC;
typedef struct { LONG status; PVOID peb; ULONG_PTR affinity; LONG priority; ULONG_PTR pid, parent; } PROCESS_BASIC;

static char out[2048];
static DWORD used;

static void emit(const char *row)
{
    HANDLE h;DWORD n,start=GetTickCount();
    lstrcpyA(out+used,row);used+=lstrlenA(row);lstrcpyA(out+used,"\r\n");used+=2;
    do{
        h=CreateFileA("COM1",GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);
        if(h!=INVALID_HANDLE_VALUE){WriteFile(h,row,lstrlenA(row),&n,NULL);WriteFile(h,"\r\n",2,&n,NULL);CloseHandle(h);return;}
        Sleep(50);
    }while(GetTickCount()-start<20000);
}

/* The GDI shared handle table view and its size, from this process's PEB (offset 0x94 on NT 5.1 x86). */
static SIZE_T gdi_view(QIP query, PVOID *base)
{
    PROCESS_BASIC info;MEMORY_BASIC_INFORMATION m;PVOID table;
    *base=NULL;
    if(query(GetCurrentProcess(),0,&info,sizeof(info),NULL)<0)return 0;
    table=*(PVOID*)((BYTE*)info.peb+0x94);
    if(!table||!VirtualQuery(table,&m,sizeof(m)))return 0;
    *base=table;return m.RegionSize;
}

static BOOL gdi_section(void)
{
    HMODULE ntdll=GetModuleHandleW(L"ntdll.dll");
    QSI qsi=(QSI)GetProcAddress(ntdll,"NtQuerySystemInformation");
    QS qs=(QS)GetProcAddress(ntdll,"NtQuerySection");
    QIP qip=(QIP)GetProcAddress(ntdll,"NtQueryInformationProcess");
    ULONG size=1<<20,count,i,matches=0,sections=0,access=0;LONG status;BYTE *buffer;HANDLE_ENTRY *entry;
    SECTION_BASIC sb;PVOID view;SIZE_T region;char row[300];HDC dc;
    dc=CreateCompatibleDC(NULL);if(dc)DeleteDC(dc);     /* a GDI call: the table is mapped */
    if(!qsi||!qs||!qip){emit("{\"r1_probe\":\"gdi_section\",\"error\":\"ntdll\",\"passed\":0}");return FALSE;}
    region=gdi_view(qip,&view);
    for(;;){
        buffer=VirtualAlloc(NULL,size,MEM_COMMIT,PAGE_READWRITE);if(!buffer)return FALSE;
        status=qsi(16,buffer,size,NULL);                /* SystemHandleInformation */
        if(status!=(LONG)0xC0000004)break;              /* STATUS_INFO_LENGTH_MISMATCH */
        VirtualFree(buffer,0,MEM_RELEASE);size*=2;
    }
    if(status<0){VirtualFree(buffer,0,MEM_RELEASE);emit("{\"r1_probe\":\"gdi_section\",\"error\":\"handles\",\"passed\":0}");return FALSE;}
    count=*(ULONG*)buffer;entry=(HANDLE_ENTRY*)(buffer+sizeof(ULONG));
    for(i=0;i<count;i++){
        if(entry[i].pid!=(USHORT)GetCurrentProcessId())continue;
        if(qs((HANDLE)(ULONG_PTR)entry[i].handle,0,&sb,sizeof(sb),NULL)<0)continue;   /* SectionBasicInformation */
        ++sections;
        /* NtQuerySection does not report SEC_NO_CHANGE (querysec.c): the GDI section is the
           committed, pagefile-backed one (SEC_COMMIT, not SEC_IMAGE or SEC_FILE) whose size is
           that of the read-only view at PEB->GdiSharedHandleTable. */
        wsprintfA(row,"{\"r1_probe\":\"section_handle\",\"handle\":\"0x%x\",\"access\":\"0x%lx\",\"attributes\":\"0x%lx\",\"bytes\":%lu}",
                  entry[i].handle,entry[i].access,sb.attributes,sb.size.LowPart);
        emit(row);
        if((sb.attributes&0x08000000)&&!(sb.attributes&(0x01000000|0x00800000))&&region&&
           (SIZE_T)((sb.size.LowPart+0xFFF)&~0xFFFu)==region){++matches;access=entry[i].access;}
    }
    VirtualFree(buffer,0,MEM_RELEASE);
    wsprintfA(row,"{\"r1_probe\":\"gdi_section\",\"view\":\"%p\",\"view_bytes\":%lu,\"section_handles\":%lu,\"gdi_section_handles\":%lu,"
                  "\"granted_access\":\"0x%lx\",\"passed\":%d}",view,(ULONG)region,sections,matches,access,region!=0&&matches==0);
    emit(row);
    return region!=0&&matches==0;
}

static BOOL cursors(void)
{
    WCHAR dir[MAX_PATH],pattern[MAX_PATH],path[MAX_PATH];WIN32_FIND_DATAW f;HANDLE find;HCURSOR h;HDC dc;HBITMAP bm,old;
    DWORD ani=0,ani_ok=0,cur=0,cur_ok=0,steps=0;int pass,s;char row[300];
    if(!GetWindowsDirectoryW(dir,MAX_PATH))return FALSE;
    lstrcatW(dir,L"\\Cursors\\");
    dc=CreateCompatibleDC(NULL);bm=CreateCompatibleBitmap(GetDC(NULL),64,64);old=SelectObject(dc,bm);
    for(pass=0;pass<2;pass++){
        lstrcpyW(pattern,dir);lstrcatW(pattern,pass?L"*.cur":L"*.ani");
        find=FindFirstFileW(pattern,&f);
        if(find==INVALID_HANDLE_VALUE)continue;
        do{
            lstrcpyW(path,dir);lstrcatW(path,f.cFileName);
            h=LoadCursorFromFileW(path);
            if(pass)++cur;else ++ani;
            if(!h)continue;
            if(pass)++cur_ok;else ++ani_ok;
            for(s=0;s<(pass?1:8);s++)if(DrawIconEx(dc,0,0,h,32,32,(UINT)s,NULL,DI_NORMAL))++steps;
            DestroyCursor(h);
        }while(FindNextFileW(find,&f));
        FindClose(find);
    }
    SelectObject(dc,old);DeleteObject(bm);DeleteDC(dc);
    wsprintfA(row,"{\"r1_probe\":\"cursors\",\"ani_loaded\":%lu,\"ani_files\":%lu,\"cur_loaded\":%lu,\"cur_files\":%lu,\"steps_drawn\":%lu,\"passed\":%d}",
              ani_ok,ani,cur_ok,cur,steps,ani>0&&ani_ok==ani&&cur_ok==cur);
    emit(row);
    return ani>0&&ani_ok==ani&&cur_ok==cur;
}

static BOOL drawn(HDC dc){return GetPixel(dc,10,10)!=RGB(255,255,255)||GetPixel(dc,30,30)!=RGB(255,255,255);}

static BOOL metafile(void)
{
    HDC rec,dc;HMETAFILE wmf;HENHMETAFILE emf=NULL;HBITMAP bm,old;UINT bytes;BYTE *bits;RECT r={0,0,64,64};
    BOOL wmf_ok=FALSE,emf_ok=FALSE;char row[200];
    rec=CreateMetaFileW(NULL);if(!rec)return FALSE;
    Rectangle(rec,10,10,50,50);MoveToEx(rec,0,30,NULL);LineTo(rec,64,30);
    wmf=CloseMetaFile(rec);if(!wmf)return FALSE;
    dc=CreateCompatibleDC(NULL);bm=CreateCompatibleBitmap(GetDC(NULL),64,64);old=SelectObject(dc,bm);
    PatBlt(dc,0,0,64,64,WHITENESS);
    wmf_ok=PlayMetaFile(dc,wmf)&&drawn(dc);
    bytes=GetMetaFileBitsEx(wmf,0,NULL);bits=bytes?LocalAlloc(LPTR,bytes):NULL;
    if(bits&&GetMetaFileBitsEx(wmf,bytes,bits)==bytes)emf=SetWinMetaFileBits(bytes,bits,NULL,NULL);
    if(emf){PatBlt(dc,0,0,64,64,WHITENESS);emf_ok=PlayEnhMetaFile(dc,emf,&r)&&drawn(dc);DeleteEnhMetaFile(emf);}
    if(bits)LocalFree(bits);
    SelectObject(dc,old);DeleteObject(bm);DeleteDC(dc);DeleteMetaFile(wmf);
    wsprintfA(row,"{\"r1_probe\":\"metafile\",\"wmf_drawn\":%d,\"emf_drawn\":%d,\"passed\":%d}",wmf_ok,emf_ok,wmf_ok&&emf_ok);
    emit(row);
    return wmf_ok&&emf_ok;
}

void WINAPI ProbeMain(void)
{
    HANDLE file;DWORD n;BOOL ok;
    emit("{\"r1_probe\":\"started\"}");
    ok=gdi_section();
    ok=cursors()&&ok;
    ok=metafile()&&ok;
    emit(ok?"{\"r1_probe\":\"done\",\"passed\":1}":"{\"r1_probe\":\"done\",\"passed\":0}");
    file=CreateFileW(L"C:\\xp25-r1core.json",GENERIC_WRITE,0,NULL,CREATE_ALWAYS,0,NULL);
    if(file!=INVALID_HANDLE_VALUE){WriteFile(file,out,used,&n,NULL);CloseHandle(file);}
    ExitProcess(ok?0:1);
}
