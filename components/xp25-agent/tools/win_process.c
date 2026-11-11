/* XP25 AI runtime: process_list, process_details and process_control
   (Toolhelp snapshots, PSAPI memory counters, sampled CPU times). */
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdlib.h>
#include <string.h>
#include "win_tools.h"

typedef struct {
    DWORD pid, parent, threads;
    LONG base_priority;
    char name[MAX_PATH * 3];
    xp25_u64 cpu_start, cpu_end;
    xp25_u64 working_set, private_bytes;
    int sampled;
} PROC_ROW;

static xp25_u64 ft64(const FILETIME *ft) { return ((xp25_u64)ft->dwHighDateTime << 32) | ft->dwLowDateTime; }

static int cpu_time(DWORD pid, xp25_u64 *total)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    FILETIME c, e, k, u;
    int ok;
    if (!h) return 0;
    ok = GetProcessTimes(h, &c, &e, &k, &u) != 0;
    if (ok) *total = ft64(&k) + ft64(&u);
    CloseHandle(h);
    return ok;
}

static size_t snapshot(PROC_ROW **out)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe;
    size_t n = 0, cap = 128;
    PROC_ROW *list;
    *out = NULL;
    if (snap == INVALID_HANDLE_VALUE) return 0;
    list = (PROC_ROW *)xp25_alloc(cap * sizeof(PROC_ROW));
    pe.dwSize = sizeof(pe);
    if (list && Process32FirstW(snap, &pe)) {
        do {
            if (!pe.th32ProcessID) continue;    /* System Idle Process */
            if (n == cap) {
                PROC_ROW *bigger = (PROC_ROW *)xp25_realloc(list, cap * 2 * sizeof(PROC_ROW));
                if (!bigger) break;
                list = bigger;
                cap *= 2;
            }
            memset(&list[n], 0, sizeof(PROC_ROW));
            list[n].pid = pe.th32ProcessID;
            list[n].parent = pe.th32ParentProcessID;
            list[n].threads = pe.cntThreads;
            list[n].base_priority = pe.pcPriClassBase;
            xp25w_copy_utf8(list[n].name, sizeof(list[n].name), pe.szExeFile);
            list[n].sampled = cpu_time(pe.th32ProcessID, &list[n].cpu_start);
            ++n;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    *out = list;
    return n;
}

static void memory(PROC_ROW *p)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, p->pid);
    PROCESS_MEMORY_COUNTERS pmc;
    if (!h) return;
    pmc.cb = sizeof(pmc);
    if (GetProcessMemoryInfo(h, &pmc, sizeof(pmc))) {
        p->working_set = pmc.WorkingSetSize;
        p->private_bytes = pmc.PagefileUsage;
    }
    CloseHandle(h);
}

static int sort_key;
static xp25_u64 sort_scale;

static long percent(const PROC_ROW *p)
{
    if (!p->sampled || !sort_scale || p->cpu_end < p->cpu_start) return 0;
    return (long)(((p->cpu_end - p->cpu_start) * 100 + sort_scale / 2) / sort_scale);
}

static int XP25_CDECL compare(const void *a, const void *b)
{
    const PROC_ROW *x = (const PROC_ROW *)a, *y = (const PROC_ROW *)b;
    if (sort_key == 1 && x->working_set != y->working_set) return x->working_set < y->working_set ? 1 : -1;
    if (sort_key == 2) return lstrcmpiA(x->name, y->name);
    if (sort_key == 3) return x->pid < y->pid ? -1 : x->pid > y->pid;
    if (sort_key == 0) {
        xp25_u64 dx = x->sampled ? x->cpu_end - x->cpu_start : 0, dy = y->sampled ? y->cpu_end - y->cpu_start : 0;
        if (dx != dy) return dx < dy ? 1 : -1;
        if (x->working_set != y->working_set) return x->working_set < y->working_set ? 1 : -1;
    }
    return x->pid < y->pid ? -1 : x->pid > y->pid;
}

int tool_process_list(const XP25_TOOL *tool, const XP25_JNODE *args, XP25_BUF *out, XP25_EGRESS *egress)
{
    const char *sort = tool_arg(args, "sort", "cpu"), *filter = tool_arg(args, "filter", NULL);
    long limit = tool_int(args, "limit", 15, 1, 100), sample = tool_int(args, "sample_ms", 1000, 0, 5000);
    PROC_ROW *list;
    size_t n, i;
    long shown = 0;
    SYSTEM_INFO si;
    FILETIME i1, k1, u1, i2, k2, u2;
    DWORD t1, t2;
    XP25_JW w;
    (void)tool; (void)egress;
    GetSystemInfo(&si);
    GetSystemTimes(&i1, &k1, &u1);
    t1 = GetTickCount();
    n = snapshot(&list);
    if (!list) return tool_win32_error(out, "snapshot_failed", "Could not list processes", GetLastError());
    if (sample > 0) Sleep((DWORD)sample);
    t2 = GetTickCount();
    GetSystemTimes(&i2, &k2, &u2);
    for (i = 0; i < n; ++i) {
        list[i].sampled = list[i].sampled && cpu_time(list[i].pid, &list[i].cpu_end);
        memory(&list[i]);
    }
    /* Percent of the capacity of all processors over the sampled wall time. */
    sort_scale = (xp25_u64)(t2 - t1 ? t2 - t1 : 1) * 10000 * si.dwNumberOfProcessors;
    sort_key = !strcmp(sort, "memory") ? 1 : !strcmp(sort, "name") ? 2 : !strcmp(sort, "pid") ? 3 : 0;
    qsort(list, n, sizeof(PROC_ROW), compare);
    tool_ok_begin(&w, out);
    xp25_jw_key(&w, "cpu_count"); xp25_jw_u64(&w, si.dwNumberOfProcessors);
    xp25_jw_key(&w, "sample_ms"); xp25_jw_u64(&w, t2 - t1);
    {
        xp25_u64 idle = ft64(&i2) - ft64(&i1), total = ft64(&k2) - ft64(&k1) + ft64(&u2) - ft64(&u1);
        xp25_jw_key(&w, "cpu_busy_percent");
        xp25_jw_i64(&w, total ? (xp25_i64)(100 - (idle * 100 + total / 2) / total) : 0);
    }
    xp25_jw_key(&w, "total"); xp25_jw_u64(&w, (xp25_u64)n);
    xp25_jw_key(&w, "processes");
    xp25_jw_arr(&w);
    for (i = 0; i < n && shown < limit; ++i) {
        if (filter && *filter && !xp25_stristr(list[i].name, filter)) continue;
        xp25_jw_obj(&w);
        xp25_jw_key(&w, "pid"); xp25_jw_u64(&w, list[i].pid);
        xp25_jw_key(&w, "name"); xp25_jw_str(&w, list[i].name);
        xp25_jw_key(&w, "cpu_percent"); xp25_jw_i64(&w, percent(&list[i]));
        xp25_jw_key(&w, "cpu_sampled"); xp25_jw_bool(&w, list[i].sampled);
        xp25_jw_key(&w, "working_set_bytes"); xp25_jw_u64(&w, list[i].working_set);
        xp25_jw_key(&w, "private_bytes"); xp25_jw_u64(&w, list[i].private_bytes);
        xp25_jw_key(&w, "threads"); xp25_jw_u64(&w, list[i].threads);
        xp25_jw_key(&w, "parent_pid"); xp25_jw_u64(&w, list[i].parent);
        xp25_jw_end(&w);
        ++shown;
    }
    xp25_jw_end(&w);
    xp25_free(list);
    return tool_finish(&w, out);
}

/* Image name of a live process, from a fresh snapshot (not from arguments). */
static int image_of(DWORD pid, char *out, size_t size, DWORD *parent, DWORD *threads)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe;
    int found = 0;
    out[0] = 0;
    if (snap == INVALID_HANDLE_VALUE) return 0;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe))
        do {
            if (pe.th32ProcessID == pid) {
                xp25w_copy_utf8(out, size, pe.szExeFile);
                if (parent) *parent = pe.th32ParentProcessID;
                if (threads) *threads = pe.cntThreads;
                found = 1;
                break;
            }
        } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    return found;
}

int tool_process_details(const XP25_TOOL *tool, const XP25_JNODE *args, XP25_BUF *out, XP25_EGRESS *egress)
{
    long pid = tool_int(args, "pid", 0, 0, 0x7fffffff);
    char name[MAX_PATH * 3], text[MAX_PATH * 3];
    DWORD parent = 0, threads = 0, handles = 0;
    HANDLE h;
    XP25_JW w;
    (void)tool; (void)egress;
    if (!pid || !image_of((DWORD)pid, name, sizeof(name), &parent, &threads)) {
        xp25_result_error(out, "not_found", "No running process has this PID.");
        return 0;
    }
    tool_ok_begin(&w, out);
    xp25_jw_key(&w, "process");
    xp25_jw_obj(&w);
    xp25_jw_key(&w, "pid"); xp25_jw_i64(&w, pid);
    xp25_jw_key(&w, "name"); xp25_jw_str(&w, name);
    xp25_jw_key(&w, "parent_pid"); xp25_jw_u64(&w, parent);
    xp25_jw_key(&w, "threads"); xp25_jw_u64(&w, threads);
    h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, (DWORD)pid);
    xp25_jw_key(&w, "access"); xp25_jw_str(&w, h ? "full" : "limited");
    if (h) {
        WCHAR path[MAX_PATH];
        FILETIME c, e, k, u;
        PROCESS_MEMORY_COUNTERS pmc;
        IO_COUNTERS io;
        HMODULE modules[256];
        DWORD needed = 0, i, count;
        if (GetModuleFileNameExW(h, NULL, path, MAX_PATH)) {
            xp25w_copy_utf8(text, sizeof(text), path);
            xp25_jw_key(&w, "path"); xp25_jw_str(&w, text);
        }
        xp25_jw_key(&w, "priority_class"); xp25_jw_u64(&w, GetPriorityClass(h));
        if (GetProcessHandleCount(h, &handles)) { xp25_jw_key(&w, "handles"); xp25_jw_u64(&w, handles); }
        if (GetProcessTimes(h, &c, &e, &k, &u)) {
            xp25w_format_filetime(&c, text);
            xp25_jw_key(&w, "started"); xp25_jw_str(&w, text);
            xp25_jw_key(&w, "cpu_kernel_ms"); xp25_jw_u64(&w, ft64(&k) / 10000);
            xp25_jw_key(&w, "cpu_user_ms"); xp25_jw_u64(&w, ft64(&u) / 10000);
        }
        pmc.cb = sizeof(pmc);
        if (GetProcessMemoryInfo(h, &pmc, sizeof(pmc))) {
            xp25_jw_key(&w, "working_set_bytes"); xp25_jw_u64(&w, pmc.WorkingSetSize);
            xp25_jw_key(&w, "peak_working_set_bytes"); xp25_jw_u64(&w, pmc.PeakWorkingSetSize);
            xp25_jw_key(&w, "private_bytes"); xp25_jw_u64(&w, pmc.PagefileUsage);
            xp25_jw_key(&w, "page_faults"); xp25_jw_u64(&w, pmc.PageFaultCount);
        }
        if (GetProcessIoCounters(h, &io)) {
            xp25_jw_key(&w, "io_read_bytes"); xp25_jw_u64(&w, io.ReadTransferCount);
            xp25_jw_key(&w, "io_write_bytes"); xp25_jw_u64(&w, io.WriteTransferCount);
        }
        if (EnumProcessModules(h, modules, sizeof(modules), &needed)) {
            count = needed / sizeof(HMODULE);
            if (count > 256) count = 256;
            xp25_jw_key(&w, "module_count"); xp25_jw_u64(&w, count);
            xp25_jw_key(&w, "modules");
            xp25_jw_arr(&w);
            for (i = 0; i < count && i < 40; ++i)
                if (GetModuleFileNameExW(h, modules[i], path, MAX_PATH)) {
                    xp25w_copy_utf8(text, sizeof(text), path);
                    xp25_jw_str(&w, text);
                }
            xp25_jw_end(&w);
        }
        CloseHandle(h);
    }
    xp25_jw_end(&w);
    return tool_finish(&w, out);
}

int classify_process_control(const XP25_TOOL *tool, const XP25_JNODE *args, XP25_PROPOSAL *p)
{
    long pid = tool_int(args, "pid", 0, 0, 0x7fffffff);
    const char *expected = tool_arg(args, "image", ""), *action = tool_arg(args, "action", "");
    char actual[MAX_PATH * 3], reason[200];
    XP25_BUF command, effects;
    XP25W_TOOLS *ctx = TOOL_CONTEXT(tool);
    if (!pid || !image_of((DWORD)pid, actual, sizeof(actual), NULL, NULL)) {
        xp25_proposal_deny(p, "No running process has this PID.");
        return 1;
    }
    if (!xp25_strieq(actual, expected)) {
        /* Refuse rather than act on a reused PID or a misidentified process. */
        xp25_proposal_deny(p, "The PID now belongs to a different program than the one named.");
        return 1;
    }
    if ((unsigned long)pid == ctx->self_pid) { xp25_proposal_deny(p, "The assistant does not end itself."); return 1; }
    p->perm = xp25_policy_process((unsigned long)pid, actual, action, reason, sizeof(reason));
    if (p->perm == XP25_PERM_DENIED) { xp25_proposal_deny(p, reason); return 1; }
    xp25_buf_init(&command);
    xp25_buf_init(&effects);
    xp25_buf_puts(&command, !strcmp(action, "terminate") ? "End process " : "Set below-normal priority for ");
    xp25_buf_puts(&command, actual);
    xp25_buf_puts(&command, " (PID ");
    xp25_buf_i64(&command, pid);
    xp25_buf_puts(&command, ")");
    xp25_buf_puts(&effects, reason);
    if (*tool_arg(args, "reason", "")) {
        xp25_buf_puts(&effects, " Assistant's reason: ");
        xp25_buf_puts(&effects, tool_arg(args, "reason", ""));
    }
    tool_proposal(p, !strcmp(action, "terminate") ? "End a process" : "Lower process priority",
                  xp25_buf_cstr(&command), actual, xp25_buf_cstr(&effects));
    xp25_buf_free(&command);
    xp25_buf_free(&effects);
    return 1;
}

int tool_process_control(const XP25_TOOL *tool, const XP25_JNODE *args, XP25_BUF *out, XP25_EGRESS *egress)
{
    long pid = tool_int(args, "pid", 0, 0, 0x7fffffff);
    const char *expected = tool_arg(args, "image", ""), *action = tool_arg(args, "action", "");
    char actual[MAX_PATH * 3];
    HANDLE h;
    XP25_JW w;
    int exited = 0;
    (void)tool; (void)egress;
    h = OpenProcess(PROCESS_TERMINATE | PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION | SYNCHRONIZE, FALSE, (DWORD)pid);
    if (!h) return tool_win32_error(out, "open_failed", "Could not open the process", GetLastError());
    /* Re-check identity while holding the handle: the PID cannot be reused now. */
    if (!image_of((DWORD)pid, actual, sizeof(actual), NULL, NULL) || !xp25_strieq(actual, expected)) {
        CloseHandle(h);
        xp25_result_error(out, "process_changed", "The process exited or the PID changed owner; nothing was done.");
        return 0;
    }
    if (!strcmp(action, "terminate")) {
        if (!TerminateProcess(h, 1)) {
            DWORD error = GetLastError();
            CloseHandle(h);
            return tool_win32_error(out, "terminate_failed", "Could not end the process", error);
        }
        exited = WaitForSingleObject(h, 5000) == WAIT_OBJECT_0;
    } else if (!SetPriorityClass(h, BELOW_NORMAL_PRIORITY_CLASS)) {
        DWORD error = GetLastError();
        CloseHandle(h);
        return tool_win32_error(out, "priority_failed", "Could not change the priority", error);
    }
    CloseHandle(h);
    tool_ok_begin(&w, out);
    xp25_jw_key(&w, "pid"); xp25_jw_i64(&w, pid);
    xp25_jw_key(&w, "image"); xp25_jw_str(&w, actual);
    xp25_jw_key(&w, "action"); xp25_jw_str(&w, action);
    if (!strcmp(action, "terminate")) { xp25_jw_key(&w, "exited"); xp25_jw_bool(&w, exited); }
    return tool_finish(&w, out);
}
