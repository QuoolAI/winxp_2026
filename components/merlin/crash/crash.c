/* MerlinCrash.exe: the XP25 post-mortem crash handler.

   Registered as the AeDebug debugger ("MerlinCrash.exe" -p %ld -e %ld,
   Auto=1). The source-built kernel32 (base/win32/client/thread.c,
   UnhandledExceptionFilter) then starts it in the crashing process's own
   security context instead of calling faultrep.dll (Microsoft's "Send Error
   Report" dialog, dwwin.exe). This is the integration point Dr. Watson uses;
   nothing is hooked and no other dialog is touched.

   It attaches as a debugger, releases the faulting thread, takes the
   second-chance exception, records the exception, faulting module, stack and
   module list, optionally writes a minidump, writes the stock "Application
   Error" event 1000 with the same five strings faultrep writes (so existing
   event collection keeps working), ends the crashed process, and only then
   shows the MerlinAI error dialog: Send to MerlinAI / Don't Send. The dialog
   never holds the crashed program (Dr. Watson, which XP25 used before, ended
   it silently; a browser restarting a crashed process must not wait for the
   user).

   Crashes outside the interactive user's context (services, LocalSystem,
   LocalService, NetworkService) never get a dialog, because a SYSTEM process
   must not put UI on the user's desktop. They are queued silently and show
   up as locally discovered problems. Sending never starts an update build. */
#include <windows.h>
#include <shellapi.h>
#include <psapi.h>
#include <dbghelp.h>
#include <string.h>
#include "../client/merlin_client.h"
#include "resource.h"

#define FRAMES 20
#define MAX_MODULES 256
#define MAX_THREADS 512
#define GUARD L"XP25_MERLIN_CRASH_HANDLER"

typedef BOOL(WINAPI *STACKWALK64_FN)(DWORD, HANDLE, HANDLE, LPSTACKFRAME64, PVOID, PREAD_PROCESS_MEMORY_ROUTINE64,
                                     PFUNCTION_TABLE_ACCESS_ROUTINE64, PGET_MODULE_BASE_ROUTINE64, PTRANSLATE_ADDRESS_ROUTINE64);
typedef BOOL(WINAPI *SYMINITIALIZE_FN)(HANDLE, PCSTR, BOOL);
typedef BOOL(WINAPI *SYMCLEANUP_FN)(HANDLE);
typedef DWORD64(WINAPI *SYMLOADMODULE64_FN)(HANDLE, HANDLE, PCSTR, PCSTR, DWORD64, DWORD);
typedef BOOL(WINAPI *MINIDUMPWRITEDUMP_FN)(HANDLE, DWORD, HANDLE, MINIDUMP_TYPE, PMINIDUMP_EXCEPTION_INFORMATION,
                                           PMINIDUMP_USER_STREAM_INFORMATION, PMINIDUMP_CALLBACK_INFORMATION);

typedef struct {
    DWORD base, size;
    WCHAR path[MAX_PATH];
} MODULE;

typedef struct {
    DWORD tid;
    HANDLE thread;
} THREAD;

static struct {
    DWORD pid, tid;
    HANDLE process, event;
    MODULE modules[MAX_MODULES];
    int module_count;
    THREAD threads[MAX_THREADS];
    int thread_count;
    EXCEPTION_RECORD exception;
    CONTEXT context;
    BOOL have_exception, have_context, interactive;
    DWORD frames[FRAMES];
    int frame_count;
    MERLIN_PROBLEM report;
    WCHAR dump_path[MAX_PATH];
    MERLIN_CONFIG config;
    char details[12000];
    char status[512];
} c;

static void u32hex(char *out, int size, DWORD v)
{
    unsigned char b[4];
    b[0] = (unsigned char)(v >> 24);
    b[1] = (unsigned char)(v >> 16);
    b[2] = (unsigned char)(v >> 8);
    b[3] = (unsigned char)v;
    merlin_append_hex(out, size, b, 4);
}

static unsigned long now_seconds(void)
{
    FILETIME ft;
    ULARGE_INTEGER v;
    GetSystemTimeAsFileTime(&ft);
    v.LowPart = ft.dwLowDateTime;
    v.HighPart = ft.dwHighDateTime;
    /* 100 ns units since 1601 -> seconds since 1970 (11644473600 s apart) */
    return (unsigned long)(v.QuadPart / 10000000 - (ULONGLONG)116444736 * 100);
}

static LONG WINAPI own_filter(EXCEPTION_POINTERS *e)
{
    (void)e;
    ExitProcess(3);                                   /* never debug ourselves */
}

static const WCHAR *base_name(const WCHAR *path)
{
    const WCHAR *b = path, *p;
    for (p = path; *p; ++p)
        if (*p == L'\\' || *p == L'/') b = p + 1;
    return b;
}

static void file_version(const WCHAR *path, char *out, int size)
{
    DWORD handle = 0, len = GetFileVersionInfoSizeW((LPWSTR)path, &handle);
    BYTE *data;
    VS_FIXEDFILEINFO *fixed;
    UINT fixed_len;
    out[0] = 0;
    if (!len || len > 1024 * 1024) return;
    data = (BYTE *)HeapAlloc(GetProcessHeap(), 0, len);
    if (!data) return;
    if (GetFileVersionInfoW((LPWSTR)path, 0, len, data) && VerQueryValueW(data, L"\\", (void **)&fixed, &fixed_len) &&
        fixed_len >= sizeof(*fixed)) {
        merlin_append_ulong(out, size, HIWORD(fixed->dwFileVersionMS));
        merlin_append(out, size, ".");
        merlin_append_ulong(out, size, LOWORD(fixed->dwFileVersionMS));
        merlin_append(out, size, ".");
        merlin_append_ulong(out, size, HIWORD(fixed->dwFileVersionLS));
        merlin_append(out, size, ".");
        merlin_append_ulong(out, size, LOWORD(fixed->dwFileVersionLS));
    }
    HeapFree(GetProcessHeap(), 0, data);
}

static void add_module(DWORD base)
{
    MODULE *m;
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS nt;
    SIZE_T got;
    int i;
    for (i = 0; i < c.module_count; ++i)
        if (c.modules[i].base == base) return;
    if (c.module_count >= MAX_MODULES) return;
    m = &c.modules[c.module_count++];
    m->base = base;
    m->size = 0;
    m->path[0] = 0;
    if (ReadProcessMemory(c.process, (LPCVOID)(DWORD_PTR)base, &dos, sizeof(dos), &got) && dos.e_magic == IMAGE_DOS_SIGNATURE &&
        dos.e_lfanew > 0 && dos.e_lfanew < 4096 &&
        ReadProcessMemory(c.process, (LPCVOID)(DWORD_PTR)(base + (DWORD)dos.e_lfanew), &nt, sizeof(nt), &got) &&
        nt.Signature == IMAGE_NT_SIGNATURE)
        m->size = nt.OptionalHeader.SizeOfImage;
}

static MODULE *module_at(DWORD address)
{
    int i;
    for (i = 0; i < c.module_count; ++i)
        if (address >= c.modules[i].base && address - c.modules[i].base < c.modules[i].size) return &c.modules[i];
    return NULL;
}

static HANDLE thread_handle(DWORD tid)
{
    int i;
    for (i = 0; i < c.thread_count; ++i)
        if (c.threads[i].tid == tid) return c.threads[i].thread;
    return NULL;
}

static void add_thread(DWORD tid, HANDLE thread)
{
    if (c.thread_count < MAX_THREADS) {
        c.threads[c.thread_count].tid = tid;
        c.threads[c.thread_count].thread = thread;
        ++c.thread_count;
    }
}

/* Is the crashed process the interactive user's? INTERACTIVE (S-1-5-4) must
   be an enabled group of its token and its user must not be a service account. */
static BOOL interactive_target(void)
{
    HANDLE token;
    static BYTE buffer[8192];
    DWORD len, i;
    TOKEN_GROUPS *groups = (TOKEN_GROUPS *)buffer;
    TOKEN_USER *user = (TOKEN_USER *)buffer;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    PSID interactive = NULL, system = NULL, local = NULL, network = NULL;
    BOOL found = FALSE, service = TRUE;
    if (!OpenProcessToken(c.process, TOKEN_QUERY, &token)) return FALSE;
    AllocateAndInitializeSid(&nt, 1, SECURITY_INTERACTIVE_RID, 0, 0, 0, 0, 0, 0, 0, &interactive);
    AllocateAndInitializeSid(&nt, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &system);
    AllocateAndInitializeSid(&nt, 1, SECURITY_LOCAL_SERVICE_RID, 0, 0, 0, 0, 0, 0, 0, &local);
    AllocateAndInitializeSid(&nt, 1, SECURITY_NETWORK_SERVICE_RID, 0, 0, 0, 0, 0, 0, 0, &network);
    if (system && local && network && GetTokenInformation(token, TokenUser, buffer, sizeof(buffer), &len))
        service = EqualSid(user->User.Sid, system) || EqualSid(user->User.Sid, local) || EqualSid(user->User.Sid, network);
    if (!service && interactive && GetTokenInformation(token, TokenGroups, buffer, sizeof(buffer), &len))
        for (i = 0; i < groups->GroupCount; ++i)
            if ((groups->Groups[i].Attributes & SE_GROUP_ENABLED) && EqualSid(groups->Groups[i].Sid, interactive)) found = TRUE;
    CloseHandle(token);
    if (interactive) FreeSid(interactive);
    if (system) FreeSid(system);
    if (local) FreeSid(local);
    if (network) FreeSid(network);
    return found && !service;
}

static void walk_stack(void)
{
    HMODULE dbghelp = LoadLibraryW(L"dbghelp.dll");
    STACKWALK64_FN walk = NULL;
    SYMINITIALIZE_FN init = NULL;
    SYMCLEANUP_FN cleanup = NULL;
    SYMLOADMODULE64_FN load = NULL;
    PFUNCTION_TABLE_ACCESS_ROUTINE64 table = NULL;
    PGET_MODULE_BASE_ROUTINE64 modbase = NULL;
    HANDLE thread = thread_handle(c.tid);
    c.frame_count = 0;
    if (!c.have_context) return;
    if (dbghelp) {
        walk = (STACKWALK64_FN)GetProcAddress(dbghelp, "StackWalk64");
        init = (SYMINITIALIZE_FN)GetProcAddress(dbghelp, "SymInitialize");
        cleanup = (SYMCLEANUP_FN)GetProcAddress(dbghelp, "SymCleanup");
        load = (SYMLOADMODULE64_FN)GetProcAddress(dbghelp, "SymLoadModule64");
        table = (PFUNCTION_TABLE_ACCESS_ROUTINE64)GetProcAddress(dbghelp, "SymFunctionTableAccess64");
        modbase = (PGET_MODULE_BASE_ROUTINE64)GetProcAddress(dbghelp, "SymGetModuleBase64");
    }
    if (walk && init && load && table && modbase && thread && init(c.process, NULL, FALSE)) {
        STACKFRAME64 frame;
        CONTEXT ctx = c.context;
        int i;
        for (i = 0; i < c.module_count; ++i) {
            char path[MAX_PATH * 3];
            MerlinWideToUtf8(c.modules[i].path, path, sizeof(path));
            load(c.process, NULL, path, NULL, c.modules[i].base, c.modules[i].size);
        }
        ZeroMemory(&frame, sizeof(frame));
        frame.AddrPC.Offset = ctx.Eip;
        frame.AddrPC.Mode = AddrModeFlat;
        frame.AddrFrame.Offset = ctx.Ebp;
        frame.AddrFrame.Mode = AddrModeFlat;
        frame.AddrStack.Offset = ctx.Esp;
        frame.AddrStack.Mode = AddrModeFlat;
        while (c.frame_count < FRAMES &&
               walk(IMAGE_FILE_MACHINE_I386, c.process, thread, &frame, &ctx, NULL, table, modbase, NULL) && frame.AddrPC.Offset)
            c.frames[c.frame_count++] = (DWORD)frame.AddrPC.Offset;
        if (cleanup) cleanup(c.process);
    }
    if (!c.frame_count) {
        /* Frame-pointer chain when dbghelp is unavailable. */
        DWORD ebp = c.context.Ebp, next[2];
        SIZE_T got;
        c.frames[c.frame_count++] = c.context.Eip;
        while (c.frame_count < FRAMES && ebp && ReadProcessMemory(c.process, (LPCVOID)(DWORD_PTR)ebp, next, sizeof(next), &got) &&
               next[0] > ebp && next[1]) {
            c.frames[c.frame_count++] = next[1];
            ebp = next[0];
        }
    }
    if (dbghelp) FreeLibrary(dbghelp);
}

static void write_dump(void)
{
    HMODULE dbghelp;
    MINIDUMPWRITEDUMP_FN write;
    MINIDUMP_EXCEPTION_INFORMATION info;
    EXCEPTION_POINTERS pointers;
    HANDLE f;
    char name[MERLIN_ID_SIZE + 8];
    WCHAR wname[40];
    if (!c.config.collect_dumps || !c.have_exception) return;
    merlin_copy(name, sizeof(name), c.report.id);
    merlin_append(name, sizeof(name), ".dmp");
    if (!MerlinQueueDirectory(c.dump_path, MAX_PATH)) return;
    MerlinUtf8ToWide(name, wname, 40);
    lstrcatW(c.dump_path, L"\\");
    lstrcatW(c.dump_path, wname);
    dbghelp = LoadLibraryW(L"dbghelp.dll");
    write = dbghelp ? (MINIDUMPWRITEDUMP_FN)GetProcAddress(dbghelp, "MiniDumpWriteDump") : NULL;
    if (write) {
        f = CreateFileW(c.dump_path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        if (f != INVALID_HANDLE_VALUE) {
            BOOL ok;
            pointers.ExceptionRecord = &c.exception;
            pointers.ContextRecord = &c.context;
            info.ThreadId = c.tid;
            info.ExceptionPointers = &pointers;
            info.ClientPointers = FALSE;
            ok = write(c.process, c.pid, f, MiniDumpNormal, c.have_context ? &info : NULL, NULL, NULL);
            CloseHandle(f);
            if (ok) merlin_copy(c.report.dump, sizeof(c.report.dump), name);
            else DeleteFileW(c.dump_path);
        }
    }
    if (dbghelp) FreeLibrary(dbghelp);
}

static void build_report(void)
{
    MERLIN_PROBLEM *r = &c.report;
    MODULE *app = c.module_count ? &c.modules[0] : NULL, *fault;
    DWORD address = (DWORD)(DWORD_PTR)c.exception.ExceptionAddress;
    char line[MERLIN_TEXT], time[MERLIN_TIME_SIZE], ref[MERLIN_SHORT];
    WCHAR who[128];
    DWORD n = 128;
    int i;
    merlin_problem_init(r);
    MerlinNewReportId(r->id);
    merlin_copy(r->kind, sizeof(r->kind), "crash");
    merlin_copy(r->severity, sizeof(r->severity), "error");
    if (app && app->path[0]) {
        MerlinWideToUtf8(base_name(app->path), r->app, sizeof(r->app));
        file_version(app->path, r->app_version, sizeof(r->app_version));
    } else merlin_copy(r->app, sizeof(r->app), "unknown");
    fault = module_at(address);
    r->offset[0] = 0;
    if (fault && fault->path[0]) {
        MerlinWideToUtf8(base_name(fault->path), r->module, sizeof(r->module));
        file_version(fault->path, r->module_version, sizeof(r->module_version));
        u32hex(r->offset, sizeof(r->offset), address - fault->base);
    } else {
        merlin_copy(r->module, sizeof(r->module), "unknown");
        u32hex(r->offset, sizeof(r->offset), address);
    }
    r->code[0] = 0;
    u32hex(r->code, sizeof(r->code), c.exception.ExceptionCode);
    merlin_crash_signature("crash", r->app, r->app_version, r->module, r->module_version, r->offset, r->signature);
    merlin_copy(r->component, sizeof(r->component), r->app);
    merlin_copy(r->title, sizeof(r->title), r->app);
    merlin_append(r->title, sizeof(r->title), " crashed in ");
    merlin_append(r->title, sizeof(r->title), r->module);
    merlin_copy(r->impact, sizeof(r->impact), "The program closed unexpectedly; unsaved work in it was lost.");
    if (GetUserNameW(who, &n)) MerlinWideToUtf8(who, r->owner, sizeof(r->owner));
    merlin_copy(line, sizeof(line), merlin_exception_name(c.exception.ExceptionCode));
    merlin_append(line, sizeof(line), " (0x");
    merlin_append(line, sizeof(line), r->code);
    merlin_append(line, sizeof(line), ") at ");
    merlin_append(line, sizeof(line), r->module);
    merlin_append(line, sizeof(line), "+0x");
    merlin_append(line, sizeof(line), r->offset);
    if (c.exception.ExceptionCode == EXCEPTION_ACCESS_VIOLATION && c.exception.NumberParameters >= 2) {
        merlin_append(line, sizeof(line), c.exception.ExceptionInformation[0] == 1   ? ", writing address 0x"
                                          : c.exception.ExceptionInformation[0] == 8 ? ", executing address 0x"
                                                                                     : ", reading address 0x");
        u32hex(line, sizeof(line), (DWORD)c.exception.ExceptionInformation[1]);
    }
    merlin_problem_add_evidence(r, line);
    for (i = 0; i < c.frame_count && r->evidence_count < MERLIN_MAX_EVIDENCE - 4; ++i) {
        MODULE *m = module_at(c.frames[i]);
        merlin_copy(line, sizeof(line), "frame ");
        merlin_append_ulong(line, sizeof(line), (unsigned long)i);
        merlin_append(line, sizeof(line), ": ");
        if (m && m->path[0]) {
            char name[MAX_PATH];
            MerlinWideToUtf8(base_name(m->path), name, sizeof(name));
            merlin_append(line, sizeof(line), name);
            merlin_append(line, sizeof(line), "+0x");
            u32hex(line, sizeof(line), c.frames[i] - m->base);
        } else {
            merlin_append(line, sizeof(line), "0x");
            u32hex(line, sizeof(line), c.frames[i]);
        }
        merlin_problem_add_evidence(r, line);
    }
    merlin_copy(line, sizeof(line), "modules:");
    for (i = 0; i < c.module_count; ++i) {
        char name[MAX_PATH];
        MerlinWideToUtf8(base_name(c.modules[i].path), name, sizeof(name));
        if (!name[0]) continue;
        if (lstrlenA(line) + lstrlenA(name) + 2 >= (int)sizeof(line)) {
            merlin_problem_add_evidence(r, line);
            merlin_copy(line, sizeof(line), "modules:");
            if (r->evidence_count >= MERLIN_MAX_EVIDENCE - 1) break;
        }
        merlin_append(line, sizeof(line), " ");
        merlin_append(line, sizeof(line), name);
    }
    merlin_problem_add_evidence(r, line);
    merlin_format_time(now_seconds(), time);
    merlin_copy(ref, sizeof(ref), "crash:");
    merlin_append(ref, sizeof(ref), r->id);
    merlin_problem_add_occurrence(r, time, ref);
}

/* "Application Error" event 1000, exactly the strings faultrep.dll writes. */
static void write_application_event(void)
{
    HANDLE log = RegisterEventSourceW(NULL, L"Application Error");
    WCHAR s[5][MERLIN_NAME];
    const WCHAR *strings[5];
    int i;
    if (!log) return;
    MerlinUtf8ToWide(c.report.app, s[0], MERLIN_NAME);
    MerlinUtf8ToWide(c.report.app_version, s[1], MERLIN_NAME);
    MerlinUtf8ToWide(c.report.module, s[2], MERLIN_NAME);
    MerlinUtf8ToWide(c.report.module_version, s[3], MERLIN_NAME);
    MerlinUtf8ToWide(c.report.offset, s[4], MERLIN_NAME);
    for (i = 0; i < 5; ++i) strings[i] = s[i];
    ReportEventW(log, EVENTLOG_ERROR_TYPE, 100, 1000, NULL, 5, 0, strings, NULL);
    DeregisterEventSource(log);
}

static DWORD save_report(BOOL submitted, BOOL transfer, BOOL dump_consent)
{
    c.report.submitted = submitted;
    c.report.transfer_consent = submitted && transfer;
    c.report.dump_consent = submitted && transfer && dump_consent && c.report.dump[0];
    return MerlinQueueSave(&c.report);
}

/* ---- dialog ---- */
static void set_text_utf8(HWND dlg, int id, const char *text)
{
    static WCHAR w[12000];
    MerlinUtf8ToWide(text, w, 12000);
    SetDlgItemTextW(dlg, id, w);
}

static INT_PTR CALLBACK details_proc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
    (void)lp;
    if (msg == WM_INITDIALOG) {
        set_text_utf8(dlg, IDC_DETAILS_TEXT, c.details);
        return TRUE;
    }
    if (msg == WM_COMMAND && (LOWORD(wp) == IDOK || LOWORD(wp) == IDCANCEL)) {
        EndDialog(dlg, IDOK);
        return TRUE;
    }
    return FALSE;
}

static void serial(const char *line);

static INT_PTR CALLBACK report_proc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
    (void)lp;
    switch (msg) {
    case WM_INITDIALOG: {
        char text[MERLIN_TEXT * 2];
        unsigned long code = c.exception.ExceptionCode;
        merlin_copy(text, sizeof(text), c.report.app);
        merlin_append(text, sizeof(text), " has encountered a problem and needs to close.");
        set_text_utf8(dlg, IDC_HEADLINE, text);
        merlin_copy(text, sizeof(text), "Application: ");
        merlin_append(text, sizeof(text), c.report.app);
        if (c.report.app_version[0]) {
            merlin_append(text, sizeof(text), " (version ");
            merlin_append(text, sizeof(text), c.report.app_version);
            merlin_append(text, sizeof(text), ")");
        }
        merlin_append(text, sizeof(text), "\r\nError type: ");
        merlin_append(text, sizeof(text), merlin_exception_name(code));
        merlin_append(text, sizeof(text), " (0x");
        merlin_append(text, sizeof(text), c.report.code);
        merlin_append(text, sizeof(text), ")\r\nSummary: ");
        merlin_append(text, sizeof(text), c.report.evidence_count ? c.report.evidence[0] : c.report.title);
        MerlinRedact(text, sizeof(text));
        set_text_utf8(dlg, IDC_SUMMARY, text);
        CheckDlgButton(dlg, IDC_TRANSFER, BST_UNCHECKED);
        CheckDlgButton(dlg, IDC_DUMP, BST_UNCHECKED);
        EnableWindow(GetDlgItem(dlg, IDC_DUMP), FALSE);
        if (!c.report.dump[0]) SetDlgItemTextW(dlg, IDC_DUMP, L"Include the memory dump (none was written)");
        SetForegroundWindow(dlg);
        serial("XP25_MERLIN_CRASH_DIALOG_READY");
        return TRUE;
    }
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDC_TRANSFER:
            EnableWindow(GetDlgItem(dlg, IDC_DUMP), IsDlgButtonChecked(dlg, IDC_TRANSFER) == BST_CHECKED && c.report.dump[0]);
            if (IsDlgButtonChecked(dlg, IDC_TRANSFER) != BST_CHECKED) CheckDlgButton(dlg, IDC_DUMP, BST_UNCHECKED);
            return TRUE;
        case IDC_VIEW_DETAILS:
            MerlinReportText(&c.report, c.details, sizeof(c.details));
            DialogBoxParamW(GetModuleHandleW(NULL), MAKEINTRESOURCEW(IDD_DETAILS), dlg, details_proc, 0);
            return TRUE;
        case IDC_SEND:
            EndDialog(dlg, IsDlgButtonChecked(dlg, IDC_TRANSFER) == BST_CHECKED
                               ? (IsDlgButtonChecked(dlg, IDC_DUMP) == BST_CHECKED ? 3 : 2)
                               : 1);
            return TRUE;
        case IDC_DONT_SEND:
        case IDCANCEL:
            EndDialog(dlg, 0);
            return TRUE;
        }
        break;
    }
    return FALSE;
}

static void serial(const char *line)
{
    /* Lab marker; ignored on machines without COM1. */
    HANDLE port = CreateFileW(L"COM1", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    DWORD wrote;
    int tries;
    /* COM1 is exclusive: Winlogon and other writers hold it briefly. */
    for (tries = 0; port == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED && tries < 40; ++tries) {
        Sleep(50);
        port = CreateFileW(L"COM1", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    }
    if (port == INVALID_HANDLE_VALUE) return;
    WriteFile(port, line, (DWORD)lstrlenA(line), &wrote, NULL);
    WriteFile(port, "\r\n", 2, &wrote, NULL);
    CloseHandle(port);
}

static void interact(void)
{
    INT_PTR choice;
    char marker[160];
    DWORD error;
    choice = DialogBoxParamW(GetModuleHandleW(NULL), MAKEINTRESOURCEW(IDD_REPORT), NULL, report_proc, 0);
    if (choice <= 0) {
        if (c.report.dump[0]) DeleteFileW(c.dump_path);
        merlin_copy(marker, sizeof(marker), "XP25_MERLIN_CRASH_CHOICE=dont_send id=");
        merlin_append(marker, sizeof(marker), c.report.id);
        serial(marker);
        return;
    }
    error = save_report(TRUE, choice >= 2, choice == 3);
    merlin_copy(marker, sizeof(marker), "XP25_MERLIN_CRASH_CHOICE=send id=");
    merlin_append(marker, sizeof(marker), c.report.id);
    merlin_append(marker, sizeof(marker), " queued=");
    merlin_append_ulong(marker, sizeof(marker), error);
    merlin_append(marker, sizeof(marker), " transfer=");
    merlin_append(marker, sizeof(marker), choice >= 2 ? "1" : "0");
    serial(marker);
    if (!error && choice >= 2) {
        char message[256];
        const char *ids[1];
        WCHAR w[256];
        ids[0] = c.report.id;
        error = MerlinTransfer(ids, 1, message, sizeof(message));
        merlin_copy(marker, sizeof(marker), "XP25_MERLIN_CRASH_TRANSFER=");
        merlin_append_ulong(marker, sizeof(marker), error);
        serial(marker);
        MerlinUtf8ToWide(message, w, 256);
        if (message[0])
            MessageBoxW(NULL, w, L"MerlinAI", MB_OK | MB_ICONINFORMATION | MB_SETFOREGROUND);
    }
}

static BOOL parse_args(void)
{
    int argc, i;
    LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) return FALSE;
    for (i = 1; i + 1 < argc; ++i) {
        DWORD v = 0;
        WCHAR *d;
        for (d = argv[i + 1]; *d >= L'0' && *d <= L'9'; ++d) v = v * 10 + (DWORD)(*d - L'0');
        if (!lstrcmpW(argv[i], L"-p")) c.pid = v;
        else if (!lstrcmpW(argv[i], L"-e")) c.event = (HANDLE)(DWORD_PTR)v;
    }
    LocalFree(argv);
    return c.pid != 0;
}

/* Attach, release the faulting thread, and wait for the second-chance exception. */
static void debug_target(void)
{
    DEBUG_EVENT de;
    BOOL released = FALSE, done = FALSE;
    DWORD deadline = GetTickCount() + 60000;
    if (!DebugActiveProcess(c.pid)) {
        if (c.event) SetEvent(c.event);
        return;
    }
    DebugSetProcessKillOnExit(TRUE);
    while (!done && GetTickCount() < deadline) {
        DWORD status = DBG_CONTINUE;
        if (!WaitForDebugEvent(&de, 5000)) continue;
        switch (de.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT:
            c.process = de.u.CreateProcessInfo.hProcess;
            add_module((DWORD)(DWORD_PTR)de.u.CreateProcessInfo.lpBaseOfImage);
            add_thread(de.dwThreadId, de.u.CreateProcessInfo.hThread);
            if (de.u.CreateProcessInfo.hFile) CloseHandle(de.u.CreateProcessInfo.hFile);
            break;
        case CREATE_THREAD_DEBUG_EVENT:
            add_thread(de.dwThreadId, de.u.CreateThread.hThread);
            break;
        case LOAD_DLL_DEBUG_EVENT:
            add_module((DWORD)(DWORD_PTR)de.u.LoadDll.lpBaseOfDll);
            if (de.u.LoadDll.hFile) CloseHandle(de.u.LoadDll.hFile);
            break;
        case EXIT_PROCESS_DEBUG_EVENT:
            done = TRUE;
            break;
        case EXCEPTION_DEBUG_EVENT:
            if (!released && de.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {
                /* The attach breakpoint: let kernel32 continue into the second chance. */
                released = TRUE;
                if (c.event) SetEvent(c.event);
                break;
            }
            if (!de.u.Exception.dwFirstChance) {
                /* The faulting thread's exception, now unhandled for the second time. */
                HANDLE thread = thread_handle(de.dwThreadId);
                c.exception = de.u.Exception.ExceptionRecord;
                c.have_exception = TRUE;
                c.tid = de.dwThreadId;
                c.context.ContextFlags = CONTEXT_FULL;
                c.have_context = thread && GetThreadContext(thread, &c.context);
                done = TRUE;
                continue;                             /* keep the target stopped for the dump */
            }
            status = DBG_EXCEPTION_NOT_HANDLED;
            break;
        }
        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, status);
    }
    if (!released && c.event) SetEvent(c.event);
}

/* Terminate the target, release its pending second-chance event and wait (bounded) for it to exit. */
static void end_target(void)
{
    DEBUG_EVENT de;
    DWORD deadline = GetTickCount() + 10000;
    TerminateProcess(c.process, c.exception.ExceptionCode);
    ContinueDebugEvent(c.pid, c.tid, DBG_EXCEPTION_NOT_HANDLED);
    while (GetTickCount() < deadline) {
        if (!WaitForDebugEvent(&de, 1000)) continue;
        if (de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
            break;
        }
        if (de.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT && de.u.LoadDll.hFile) CloseHandle(de.u.LoadDll.hFile);
        if (de.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT && de.u.CreateProcessInfo.hFile) CloseHandle(de.u.CreateProcessInfo.hFile);
        ContinueDebugEvent(de.dwProcessId, de.dwThreadId,
                           de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT ? DBG_EXCEPTION_NOT_HANDLED : DBG_CONTINUE);
    }
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE previous, LPWSTR command_line, int show)
{
    WCHAR guard[4];
    int i;
    (void)instance;
    (void)previous;
    (void)command_line;
    (void)show;
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    SetUnhandledExceptionFilter(own_filter);
    /* Started for a crash of MerlinCrash itself: do nothing, so it cannot loop. */
    if (GetEnvironmentVariableW(GUARD, guard, 4)) return 4;
    SetEnvironmentVariableW(GUARD, L"1");
    if (!parse_args()) return 2;
    MerlinGetConfig(&c.config);
    debug_target();
    if (!c.process) return 5;
    for (i = 0; i < c.module_count; ++i)
        GetModuleFileNameExW(c.process, (HMODULE)(DWORD_PTR)c.modules[i].base, c.modules[i].path, MAX_PATH);
    if (!c.have_exception) {
        /* The process ended or never reached its second chance; nothing to report. */
        DebugActiveProcessStop(c.pid);
        return 6;
    }
    c.interactive = interactive_target();
    walk_stack();
    build_report();
    write_dump();
    write_application_event();
    {
        char marker[200];
        merlin_copy(marker, sizeof(marker), "XP25_MERLIN_CRASH_CAPTURED id=");
        merlin_append(marker, sizeof(marker), c.report.id);
        merlin_append(marker, sizeof(marker), " app=");
        merlin_append(marker, sizeof(marker), c.report.app);
        merlin_append(marker, sizeof(marker), " module=");
        merlin_append(marker, sizeof(marker), c.report.module);
        merlin_append(marker, sizeof(marker), " offset=");
        merlin_append(marker, sizeof(marker), c.report.offset);
        merlin_append(marker, sizeof(marker), " code=");
        merlin_append(marker, sizeof(marker), c.report.code);
        merlin_append(marker, sizeof(marker), c.interactive ? " interactive=1" : " interactive=0");
        serial(marker);
    }
    /* Everything the report needs is captured: end the crashed program before asking anything, so the
       dialog never holds it (a browser restarting a crashed process must not wait for the user). */
    end_target();
    if (c.interactive) interact();
    else save_report(FALSE, FALSE, FALSE);          /* queued silently, discovered locally */
    return 0;
}
