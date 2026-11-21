/* MerlinAI.exe entry point.

   MerlinAI.exe                 the Control Panel window
   MerlinAI.exe /install        register MerlinAI (administrators; see install.c)
   MerlinAI.exe /uninstall      restore the saved settings
   MerlinAI.exe /logon          at logon: collect (administrators, if enabled)
   MerlinAI.exe /collect        collect now and report the counts on COM1
   MerlinAI.exe /configure <builder-url> <deploy-url> <installation> <builder-key> <deploy-key>
                                set endpoints and identity without the dialog
   MerlinAI.exe /status         queue and identity summary on COM1 (lab use)
   All modes except the window print an XP25_MERLIN_* line to COM1 for the
   lab harness and return a Win32 error code. */
#include <windows.h>
#include <shellapi.h>
#include "app.h"

HINSTANCE merlin_instance;

static void directory_of_exe(WCHAR *out)
{
    WCHAR *slash = NULL, *p;
    GetModuleFileNameW(NULL, out, MAX_PATH);
    for (p = out; *p; ++p)
        if (*p == L'\\') slash = p;
    if (slash) *slash = 0;
}

static void result(const char *what, DWORD error)
{
    char line[200];
    merlin_copy(line, sizeof(line), what);
    merlin_append(line, sizeof(line), "=");
    merlin_append_ulong(line, sizeof(line), error);
    merlin_serial(line);
}

static DWORD collect(BOOL quiet)
{
    MERLIN_COLLECT_STATS s;
    char line[300];
    DWORD e = MerlinCollect(&s);
    merlin_copy(line, sizeof(line), "XP25_MERLIN_COLLECT=");
    merlin_append_ulong(line, sizeof(line), e);
    merlin_append(line, sizeof(line), " new_problems=");
    merlin_append_ulong(line, sizeof(line), s.new_problems);
    merlin_append(line, sizeof(line), " new_occurrences=");
    merlin_append_ulong(line, sizeof(line), s.new_occurrences);
    merlin_append(line, sizeof(line), " events_read=");
    merlin_append_ulong(line, sizeof(line), s.events_read);
    merlin_append(line, sizeof(line), " crash_reports=");
    merlin_append_ulong(line, sizeof(line), s.crash_reports);
    merlin_append(line, sizeof(line), " winlogon_lines=");
    merlin_append_ulong(line, sizeof(line), s.winlogon_lines);
    merlin_append(line, sizeof(line), " removed=");
    merlin_append_ulong(line, sizeof(line), s.removed);
    merlin_append(line, sizeof(line), " errors=");
    merlin_append_ulong(line, sizeof(line), s.errors);
    if (!quiet) merlin_serial(line);
    return e;
}

static DWORD status_report(void)
{
    MERLIN_LIST list;
    MERLIN_IDENTITY id;
    char line[600];
    int i;
    DWORD e = MerlinQueueList(&list);
    result("XP25_MERLIN_STATUS_QUEUE", e);
    if (e) return e;
    for (i = 0; i < list.count; ++i) {
        MERLIN_PROBLEM *p = &list.items[i];
        merlin_copy(line, sizeof(line), "XP25_MERLIN_PROBLEM id=");
        merlin_append(line, sizeof(line), p->id);
        merlin_append(line, sizeof(line), " kind=");
        merlin_append(line, sizeof(line), p->kind);
        merlin_append(line, sizeof(line), " severity=");
        merlin_append(line, sizeof(line), p->severity);
        merlin_append(line, sizeof(line), " count=");
        merlin_append_ulong(line, sizeof(line), p->count);
        merlin_append(line, sizeof(line), " submitted=");
        merlin_append(line, sizeof(line), p->submitted ? "1" : "0");
        merlin_append(line, sizeof(line), " status=");
        merlin_append(line, sizeof(line), p->status);
        merlin_append(line, sizeof(line), " job=");
        merlin_append(line, sizeof(line), p->job[0] ? p->job : "-");
        merlin_append(line, sizeof(line), " title=");
        merlin_append(line, sizeof(line), p->title);
        merlin_sanitize_line(line);
        merlin_serial(line);
    }
    merlin_copy(line, sizeof(line), "XP25_MERLIN_STATUS_COUNT=");
    merlin_append_ulong(line, sizeof(line), (unsigned long)list.count);
    merlin_serial(line);
    MerlinFreeList(&list);
    e = MerlinGetIdentity(&id);
    merlin_copy(line, sizeof(line), "XP25_MERLIN_STATUS_IDENTITY=");
    merlin_append_ulong(line, sizeof(line), e);
    merlin_append(line, sizeof(line), id.has_builder_key ? " builder_key=1" : " builder_key=0");
    merlin_append(line, sizeof(line), id.has_deploy_key ? " deploy_key=1" : " deploy_key=0");
    SecureZeroMemory(&id, sizeof(id));
    merlin_serial(line);
    return 0;
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE previous, LPWSTR command_line, int show)
{
    int argc;
    LPWSTR *argv;
    DWORD e = 0;
    (void)previous;
    (void)command_line;
    merlin_instance = instance;
    argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv || argc < 2) {
        if (argv) LocalFree(argv);
        return merlin_run_ui(show);
    }
    if (!lstrcmpiW(argv[1], L"/install")) {
        WCHAR dir[MAX_PATH];
        char log[2048];
        directory_of_exe(dir);
        e = merlin_install(dir, log, sizeof(log));
        result("XP25_MERLIN_INSTALL", e);
    } else if (!lstrcmpiW(argv[1], L"/uninstall")) {
        char log[2048];
        e = merlin_uninstall(log, sizeof(log));
        result("XP25_MERLIN_UNINSTALL", e);
    } else if (!lstrcmpiW(argv[1], L"/logon")) {
        MERLIN_CONFIG c;
        MerlinGetConfig(&c);
        if (c.auto_collect && MerlinIsAdmin()) e = collect(FALSE);
    } else if (!lstrcmpiW(argv[1], L"/collect")) {
        e = collect(FALSE);
    } else if (!lstrcmpiW(argv[1], L"/status")) {
        e = status_report();
    } else if (!lstrcmpiW(argv[1], L"/configure") && argc == 7) {
        MERLIN_CONFIG c;
        char inst[80], bkey[80], dkey[80];
        MerlinGetConfig(&c);
        lstrcpynW(c.builder, argv[2], 256);
        lstrcpynW(c.deploy, argv[3], 256);
        MerlinWideToUtf8(argv[4], inst, sizeof(inst));
        MerlinWideToUtf8(argv[5], bkey, sizeof(bkey));
        MerlinWideToUtf8(argv[6], dkey, sizeof(dkey));
        e = MerlinSetConfig(&c);
        if (!e) e = MerlinSetIdentity(inst, bkey, dkey);
        SecureZeroMemory(bkey, sizeof(bkey));
        SecureZeroMemory(dkey, sizeof(dkey));
        result("XP25_MERLIN_CONFIGURE", e);
    } else {
        MessageBoxW(NULL, L"Usage: MerlinAI.exe [/install | /uninstall | /collect | /status | /configure ...]", L"MerlinAI", MB_OK | MB_ICONINFORMATION);
        e = ERROR_INVALID_PARAMETER;
    }
    LocalFree(argv);
    return (int)e;
}
