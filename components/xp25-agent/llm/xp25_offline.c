/* XP25 AI runtime: offline assistant (local planner). Portable C89.
   It reads only the user's request and the JSON results of tools it called
   in this turn. Every action it proposes goes through the agent's permission
   policy and the host's approval dialog, exactly like a model's request. */
#include <string.h>
#include "xp25_offline.h"
#include "../permissions/xp25_policy.h"

enum {
    I_UNKNOWN, I_HELP, I_SLOW, I_EVENTS, I_CMD, I_PROCESSES, I_PROCESS_DETAIL, I_SERVICES,
    I_SERVICE_CONTROL, I_NETWORK, I_DISK, I_SYSINFO, I_REGISTRY, I_FIND_EXPLAIN, I_FIND, I_EXPLAIN_FILE
};

static const char *intent_names[] = {
    "unknown", "help", "slow_computer", "event_log", "command", "processes", "process_details",
    "services", "service_control", "network", "disk", "system_info", "registry", "find_and_explain",
    "find_files", "explain_file"
};

const char *xp25_offline_intent_name(int intent)
{
    return intent >= 0 && intent <= I_EXPLAIN_FILE ? intent_names[intent] : "unknown";
}

static int has(const char *text, const char *word) { return xp25_stristr(text, word) != NULL; }

static int any(const char *text, const char *const *words)
{
    for (; *words; ++words) if (has(text, *words)) return 1;
    return 0;
}

static const char *drive_path(const char *text)
{
    const char *p;
    for (p = text; *p; ++p)
        if (xp25_is_alpha((unsigned char)p[0]) && p[1] == ':' && p[2] == '\\' &&
            (p == text || !xp25_is_alpha((unsigned char)p[-1]))) return p;
    return NULL;
}

static int starts(const char *text, const char *prefix)
{
    while (xp25_is_space((unsigned char)*text)) ++text;
    return xp25_starts_with_i(text, prefix);
}

int xp25_offline_intent(const char *t)
{
    static const char *const explain[] = { "explain", "wrong", "problem", "check", "fix", "analy", "what is in", "what's in", NULL };
    static const char *const finding[] = { "find ", "locate", "where is", "where are", "where's", "search for", "look for", NULL };
    static const char *const slow[] = { "slow", "sluggish", "performance", "lag", "freez", "hang", "high cpu",
                                        "speed up", "unresponsive", "takes forever", NULL };
    static const char *const events[] = { "event", " log", "logs", "crash", "error", NULL };
    static const char *const processes[] = { "process", "running program", "task manager", "cpu usage",
                                             "memory usage", "what's running", "what is running", "programs running", NULL };
    static const char *const network[] = { "network", "internet", "connect", "ip address", "dns", "ping",
                                           "wifi", "wi-fi", "adapter", "gateway", "online", NULL };
    static const char *const disk[] = { "disk", "drive", "space", "storage", "chkdsk", "hard", NULL };
    static const char *const sysinfo[] = { "system info", "specs", "about this computer", "ram", "version",
                                           "hardware", "my computer", "system", "cpu", "memory", NULL };
    static const char *const help[] = { "help", "hello", "hi ", "what can you", "who are you", NULL };
    if (!t || !*t) return I_HELP;
    if (drive_path(t) && (any(t, explain) || starts(t, "open") || starts(t, "read") || starts(t, "show")))
        return I_EXPLAIN_FILE;
    if (starts(t, "run ") || starts(t, "run:") || starts(t, "execute ") || starts(t, "cmd ") ||
        starts(t, "command:") || starts(t, "run command")) return I_CMD;
    if (has(t, "hklm\\") || has(t, "hkcu\\") || has(t, "hkey_") || has(t, "registry")) return I_REGISTRY;
    if (any(t, finding) && any(t, explain)) return I_FIND_EXPLAIN;
    if (any(t, finding)) return I_FIND;
    if ((has(t, "restart") || has(t, "start") || has(t, "stop")) && (has(t, "service") || has(t, "spooler")))
        return I_SERVICE_CONTROL;
    if (any(t, slow)) return I_SLOW;
    if (any(t, events)) return I_EVENTS;
    if (has(t, "service")) return I_SERVICES;
    if (has(t, "process") && (has(t, ".exe") || has(t, "pid"))) return I_PROCESS_DETAIL;
    if (any(t, processes)) return I_PROCESSES;
    if (any(t, network)) return I_NETWORK;
    if (any(t, disk)) return I_DISK;
    if (any(t, sysinfo)) return I_SYSINFO;
    if (any(t, help) || starts(t, "hi")) return I_HELP;
    return I_UNKNOWN;
}

typedef struct {
    const XP25_CONVERSATION *c;
    size_t start;
    const char *text;
    XP25_OFFLINE *settings;
    XP25_REPLY *reply;
} PLAN;

static int plan_help(PLAN *p, int unknown);

static const XP25_ITEM *result_of(const PLAN *p, const char *tool, int nth)
{
    size_t i;
    for (i = p->start + 1; i < p->c->count; ++i) {
        const XP25_ITEM *item = &p->c->items[i];
        if (item->kind == XP25_ITEM_RESULT && item->name && !strcmp(item->name, tool) && nth-- == 0) return item;
    }
    return NULL;
}

static int call(PLAN *p, const char *tool, const char *arguments)
{
    XP25_CALL *c = &p->reply->calls[0];
    c->call_id = NULL;
    c->name = xp25_strdup(tool);
    c->arguments = xp25_strdup(arguments);
    p->reply->call_count = c->name && c->arguments ? 1 : 0;
    return p->reply->call_count == 1;
}

static int answer(PLAN *p, XP25_BUF *text)
{
    p->reply->text = xp25_buf_detach(text);
    return p->reply->text != NULL;
}

/* Parse a result item; returns the root object or NULL. */
static const XP25_JNODE *parse(const XP25_ITEM *item, XP25_JDOC *doc)
{
    memset(doc, 0, sizeof(*doc));
    if (!item || !item->text || !xp25_json_parse(doc, item->text, strlen(item->text))) return NULL;
    return doc->root;
}

static xp25_i64 num(const XP25_JNODE *o, const char *key)
{
    xp25_i64 v = 0;
    xp25_json_i64(o, key, &v);
    return v;
}

static const char *str(const XP25_JNODE *o, const char *key)
{
    const char *s = xp25_json_string(o, key);
    return s ? s : "";
}

static void error_text(XP25_BUF *out, const XP25_JNODE *root, const char *what)
{
    const XP25_JNODE *error = xp25_json_get(root, "error");
    const char *code = xp25_json_string(error, "code");
    xp25_buf_puts(out, what);
    if (code && !strcmp(code, "user_declined")) xp25_buf_puts(out, ": you declined it, so nothing was changed.");
    else if (code && !strcmp(code, "permission_denied")) {
        xp25_buf_puts(out, ": not allowed by XP25 policy (");
        xp25_buf_puts(out, str(error, "message"));
        xp25_buf_puts(out, ").");
    } else {
        xp25_buf_puts(out, " failed: ");
        xp25_buf_puts(out, xp25_json_string(error, "message") ? str(error, "message") : "unknown error");
        if (code) { xp25_buf_puts(out, " ["); xp25_buf_puts(out, code); xp25_buf_puts(out, "]"); }
    }
}

static void say_system(XP25_BUF *out, const XP25_JNODE *r)
{
    const XP25_JNODE *os = xp25_json_get(r, "os"), *cpu = xp25_json_get(r, "cpu"), *mem = xp25_json_get(r, "memory");
    const XP25_JNODE *drives = xp25_json_get(r, "drives"), *d;
    xp25_i64 up = num(r, "uptime_seconds");
    xp25_buf_puts(out, "- System: ");
    xp25_buf_puts(out, str(os, "name"));
    xp25_buf_puts(out, " ");
    xp25_buf_puts(out, str(os, "version"));
    if (*str(os, "service_pack")) { xp25_buf_puts(out, " ("); xp25_buf_puts(out, str(os, "service_pack")); xp25_buf_puts(out, ")"); }
    xp25_buf_puts(out, " on ");
    xp25_buf_puts(out, str(r, "computer"));
    xp25_buf_puts(out, ", up ");
    xp25_buf_i64(out, up / 3600);
    xp25_buf_puts(out, " h ");
    xp25_buf_i64(out, (up / 60) % 60);
    xp25_buf_puts(out, " min.\n- Processor: ");
    xp25_buf_puts(out, str(cpu, "name"));
    xp25_buf_puts(out, " (");
    xp25_buf_i64(out, num(cpu, "count"));
    xp25_buf_puts(out, num(cpu, "count") == 1 ? " CPU), " : " CPUs), ");
    xp25_buf_i64(out, num(cpu, "usage_percent"));
    xp25_buf_puts(out, "% busy.\n- Memory: ");
    xp25_buf_size(out, (xp25_u64)num(mem, "available_bytes"));
    xp25_buf_puts(out, " free of ");
    xp25_buf_size(out, (xp25_u64)num(mem, "total_bytes"));
    xp25_buf_puts(out, " (");
    xp25_buf_i64(out, num(mem, "load_percent"));
    xp25_buf_puts(out, "% in use).\n");
    for (d = drives ? drives->child : NULL; d; d = d->next) {
        xp25_buf_puts(out, "- Drive ");
        xp25_buf_puts(out, str(d, "root"));
        xp25_buf_puts(out, " ");
        xp25_buf_size(out, (xp25_u64)num(d, "free_bytes"));
        xp25_buf_puts(out, " free of ");
        xp25_buf_size(out, (xp25_u64)num(d, "total_bytes"));
        xp25_buf_puts(out, " (");
        xp25_buf_i64(out, num(d, "free_percent"));
        xp25_buf_puts(out, "% free).\n");
    }
}

static void say_processes(XP25_BUF *out, const XP25_JNODE *r, int limit)
{
    const XP25_JNODE *p;
    int n = 0;
    xp25_buf_puts(out, "- CPU is ");
    xp25_buf_i64(out, num(r, "cpu_busy_percent"));
    xp25_buf_puts(out, "% busy across ");
    xp25_buf_i64(out, num(r, "cpu_count"));
    xp25_buf_puts(out, num(r, "cpu_count") == 1 ? " processor; " : " processors; ");
    xp25_buf_i64(out, num(r, "total"));
    xp25_buf_puts(out, " processes are running. Busiest:\n");
    for (p = xp25_json_get(r, "processes") ? xp25_json_get(r, "processes")->child : NULL; p && n < limit; p = p->next, ++n) {
        xp25_buf_puts(out, "    ");
        xp25_buf_puts(out, str(p, "name"));
        xp25_buf_puts(out, " (PID ");
        xp25_buf_i64(out, num(p, "pid"));
        xp25_buf_puts(out, "): ");
        xp25_buf_i64(out, num(p, "cpu_percent"));
        xp25_buf_puts(out, "% CPU, ");
        xp25_buf_size(out, (xp25_u64)num(p, "working_set_bytes"));
        xp25_buf_puts(out, " memory\n");
    }
}

static void say_events(XP25_BUF *out, const XP25_JNODE *r, int limit)
{
    const XP25_JNODE *counts = xp25_json_get(r, "counts"), *e;
    int n = 0;
    xp25_buf_puts(out, "- ");
    xp25_buf_puts(out, str(r, "log"));
    xp25_buf_puts(out, " log: ");
    xp25_buf_i64(out, num(counts, "error"));
    xp25_buf_puts(out, " errors, ");
    xp25_buf_i64(out, num(counts, "warning"));
    xp25_buf_puts(out, " warnings in the period checked (");
    xp25_buf_i64(out, num(r, "scanned"));
    xp25_buf_puts(out, " records read).\n");
    for (e = xp25_json_get(r, "records") ? xp25_json_get(r, "records")->child : NULL; e && n < limit; e = e->next, ++n) {
        const char *message = str(e, "message");
        xp25_buf_puts(out, "    ");
        xp25_buf_puts(out, str(e, "time"));
        xp25_buf_puts(out, " ");
        xp25_buf_puts(out, str(e, "type"));
        xp25_buf_puts(out, " from ");
        xp25_buf_puts(out, str(e, "source"));
        xp25_buf_puts(out, " (event ");
        xp25_buf_i64(out, num(e, "event_id"));
        xp25_buf_puts(out, "): ");
        xp25_buf_append(out, message, xp25_utf8_clip(message, 160));
        xp25_buf_puts(out, "\n");
    }
}

static int protected_process(const PLAN *p, const XP25_JNODE *proc)
{
    char reason[128];
    xp25_i64 pid = num(proc, "pid");
    if ((unsigned long)pid == p->settings->self_pid) return 1;
    return xp25_policy_process((unsigned long)pid, str(proc, "name"), "terminate", reason, sizeof(reason)) == XP25_PERM_DENIED;
}

static const XP25_JNODE *busiest(const PLAN *p, const XP25_JNODE *list)
{
    const XP25_JNODE *proc;
    for (proc = xp25_json_get(list, "processes") ? xp25_json_get(list, "processes")->child : NULL; proc; proc = proc->next)
        if (num(proc, "cpu_percent") >= p->settings->cpu_threshold && !protected_process(p, proc)) return proc;
    return NULL;
}

static const XP25_JNODE *system_volume(const XP25_JNODE *disk)
{
    const XP25_JNODE *v, *vols = xp25_json_get(disk, "volumes");
    const char *sys = str(disk, "system_drive");
    for (v = vols ? vols->child : NULL; v; v = v->next)
        if (xp25_strieq(str(v, "root"), sys)) return v;
    return vols ? vols->child : NULL;
}

static int plan_slow(PLAN *p)
{
    XP25_JDOC d_sys, d_proc, d_sevt, d_aevt, d_disk, d_act, d_ver;
    const XP25_JNODE *sys, *proc, *sevt, *aevt, *disk, *act, *ver, *cand = NULL, *vol;
    const XP25_ITEM *action = result_of(p, "process_control", 0);
    const XP25_ITEM *clean = result_of(p, "file_operations", 0);
    XP25_BUF out;
    int done;
    if (!result_of(p, "system_info", 0)) return call(p, "system_info", "{}");
    if (!result_of(p, "process_list", 0))
        return call(p, "process_list", "{\"sort\":\"cpu\",\"limit\":8,\"sample_ms\":1500}");
    if (!result_of(p, "eventlog_read", 0))
        return call(p, "eventlog_read", "{\"log\":\"System\",\"types\":[\"error\",\"warning\"],\"max_records\":6,\"since_hours\":72}");
    if (!result_of(p, "eventlog_read", 1))
        return call(p, "eventlog_read", "{\"log\":\"Application\",\"types\":[\"error\"],\"max_records\":4,\"since_hours\":72}");
    if (!result_of(p, "disk_diagnostics", 0)) return call(p, "disk_diagnostics", "{}");
    sys = parse(result_of(p, "system_info", 0), &d_sys);
    proc = parse(result_of(p, "process_list", 0), &d_proc);
    sevt = parse(result_of(p, "eventlog_read", 0), &d_sevt);
    aevt = parse(result_of(p, "eventlog_read", 1), &d_aevt);
    disk = parse(result_of(p, "disk_diagnostics", 0), &d_disk);
    act = parse(action ? action : clean, &d_act);
    ver = parse(result_of(p, "process_list", 1), &d_ver);
    cand = proc ? busiest(p, proc) : NULL;
    vol = disk ? system_volume(disk) : NULL;
    done = 0;
    if (cand && !action) {
        XP25_BUF args;
        XP25_JW w;
        xp25_buf_init(&args);
        xp25_jw_init(&w, &args);
        xp25_jw_obj(&w);
        xp25_jw_key(&w, "pid"); xp25_jw_i64(&w, num(cand, "pid"));
        xp25_jw_key(&w, "image"); xp25_jw_str(&w, str(cand, "name"));
        xp25_jw_key(&w, "action"); xp25_jw_str(&w, "terminate");
        xp25_jw_key(&w, "reason"); xp25_jw_str(&w, "Uses most of the processor time.");
        xp25_jw_end(&w);
        done = call(p, "process_control", xp25_buf_cstr(&args));
        xp25_buf_free(&args);
    } else if (!cand && !clean && vol && num(vol, "free_percent") < p->settings->disk_free_threshold &&
               *str(xp25_json_get(disk, "temp"), "path")) {
        XP25_BUF args;
        XP25_JW w;
        xp25_buf_init(&args);
        xp25_jw_init(&w, &args);
        xp25_jw_obj(&w);
        xp25_jw_key(&w, "action"); xp25_jw_str(&w, "clean_temp");
        xp25_jw_key(&w, "path"); xp25_jw_str(&w, str(xp25_json_get(disk, "temp"), "path"));
        xp25_jw_end(&w);
        done = call(p, "file_operations", xp25_buf_cstr(&args));
        xp25_buf_free(&args);
    } else if (action && act && xp25_json_flag(act, "ok", 0) && !ver) {
        done = call(p, "process_list", "{\"sort\":\"cpu\",\"limit\":5,\"sample_ms\":1500}");
    }
    if (!done) {
        xp25_buf_init(&out);
        xp25_buf_puts(&out, "I checked this computer's processor, memory, Event Viewer and disk. Findings:\n");
        if (sys) say_system(&out, sys);
        if (proc) say_processes(&out, proc, 4);
        if (sevt) say_events(&out, sevt, 3);
        if (aevt) say_events(&out, aevt, 2);
        if (vol) {
            xp25_buf_puts(&out, "- System drive ");
            xp25_buf_puts(&out, str(vol, "root"));
            xp25_buf_puts(&out, ": ");
            xp25_buf_i64(&out, num(vol, "free_percent"));
            xp25_buf_puts(&out, "% free");
            if (xp25_json_get(vol, "dirty") && xp25_json_flag(vol, "dirty", 0)) xp25_buf_puts(&out, ", marked for a disk check");
            xp25_buf_puts(&out, ".\n");
        }
        xp25_buf_puts(&out, "\nLikely cause: ");
        if (cand) {
            xp25_buf_puts(&out, str(cand, "name"));
            xp25_buf_puts(&out, " (PID ");
            xp25_buf_i64(&out, num(cand, "pid"));
            xp25_buf_puts(&out, ") is using ");
            xp25_buf_i64(&out, num(cand, "cpu_percent"));
            xp25_buf_puts(&out, "% of the processor.\n");
        } else if (sys && num(xp25_json_get(sys, "memory"), "load_percent") >= p->settings->memory_threshold) {
            xp25_buf_puts(&out, "memory is almost full; close programs you are not using.\n");
        } else if (vol && num(vol, "free_percent") < p->settings->disk_free_threshold) {
            xp25_buf_puts(&out, "the system drive is nearly full.\n");
        } else {
            xp25_buf_puts(&out, "no single program or resource is overloaded right now. If the slowdown "
                                "comes and goes, ask me again while it is happening.\n");
        }
        if (action) {
            xp25_buf_puts(&out, "\nAction: ");
            if (act && xp25_json_flag(act, "ok", 0)) {
                xp25_buf_puts(&out, "ended ");
                xp25_buf_puts(&out, str(act, "image"));
                xp25_buf_puts(&out, " (PID ");
                xp25_buf_i64(&out, num(act, "pid"));
                xp25_buf_puts(&out, ") with your approval.\n");
            } else if (act) {
                error_text(&out, act, "Ending the process");
                xp25_buf_puts(&out, "\n");
            }
        } else if (clean) {
            xp25_buf_puts(&out, "\nAction: ");
            if (act && xp25_json_flag(act, "ok", 0)) {
                xp25_buf_puts(&out, "removed ");
                xp25_buf_i64(&out, num(act, "deleted_files"));
                xp25_buf_puts(&out, " old temporary files (");
                xp25_buf_size(&out, (xp25_u64)num(act, "deleted_bytes"));
                xp25_buf_puts(&out, ") with your approval.\n");
            } else if (act) {
                error_text(&out, act, "Cleaning temporary files");
                xp25_buf_puts(&out, "\n");
            }
        }
        if (ver) {
            const XP25_JNODE *q;
            int still = 0;
            for (q = xp25_json_get(ver, "processes") ? xp25_json_get(ver, "processes")->child : NULL; q; q = q->next)
                if (act && num(q, "pid") == num(act, "pid")) still = 1;
            xp25_buf_puts(&out, "Verification: the processor is now ");
            xp25_buf_i64(&out, num(ver, "cpu_busy_percent"));
            xp25_buf_puts(&out, "% busy (was ");
            xp25_buf_i64(&out, num(proc, "cpu_busy_percent"));
            xp25_buf_puts(&out, "%), and ");
            xp25_buf_puts(&out, str(act, "image"));
            xp25_buf_puts(&out, still ? " is still listed. The problem is not resolved yet." :
                                        " is no longer running. The problem is resolved.");
        } else if (!action && !clean) {
            xp25_buf_puts(&out, "No changes were needed or made.");
        }
        done = answer(p, &out);
    }
    xp25_json_free(&d_sys); xp25_json_free(&d_proc); xp25_json_free(&d_sevt); xp25_json_free(&d_aevt);
    xp25_json_free(&d_disk); xp25_json_free(&d_act); xp25_json_free(&d_ver);
    return done;
}

static int finish_with(PLAN *p, const char *tool, int nth, void (*say)(XP25_BUF *, const XP25_JNODE *, int),
                       const char *intro, int limit)
{
    XP25_JDOC doc;
    const XP25_JNODE *r = parse(result_of(p, tool, nth), &doc);
    XP25_BUF out;
    int ok;
    xp25_buf_init(&out);
    if (!r) xp25_buf_puts(&out, "The tool returned no readable result.");
    else if (!xp25_json_flag(r, "ok", 0)) error_text(&out, r, intro);
    else {
        xp25_buf_puts(&out, intro);
        xp25_buf_puts(&out, ":\n");
        say(&out, r, limit);
    }
    ok = answer(p, &out);
    xp25_json_free(&doc);
    return ok;
}

static void say_system_wrapped(XP25_BUF *out, const XP25_JNODE *r, int limit) { (void)limit; say_system(out, r); }

static void say_services(XP25_BUF *out, const XP25_JNODE *r, int limit)
{
    const XP25_JNODE *s;
    int n = 0;
    xp25_buf_puts(out, "- ");
    xp25_buf_i64(out, num(r, "running"));
    xp25_buf_puts(out, " of ");
    xp25_buf_i64(out, num(r, "total"));
    xp25_buf_puts(out, " services are running.\n");
    for (s = xp25_json_get(r, "services") ? xp25_json_get(r, "services")->child : NULL; s && n < limit; s = s->next, ++n) {
        xp25_buf_puts(out, "    ");
        xp25_buf_puts(out, str(s, "display_name"));
        xp25_buf_puts(out, " (");
        xp25_buf_puts(out, str(s, "name"));
        xp25_buf_puts(out, "): ");
        xp25_buf_puts(out, str(s, "state"));
        xp25_buf_puts(out, ", start ");
        xp25_buf_puts(out, str(s, "start_type"));
        xp25_buf_puts(out, "\n");
    }
}

static void say_network(XP25_BUF *out, const XP25_JNODE *r, int limit)
{
    const XP25_JNODE *a, *v, *c;
    (void)limit;
    for (a = xp25_json_get(r, "adapters") ? xp25_json_get(r, "adapters")->child : NULL; a; a = a->next) {
        xp25_buf_puts(out, "- Adapter ");
        xp25_buf_puts(out, str(a, "description"));
        xp25_buf_puts(out, xp25_json_flag(a, "dhcp", 0) ? " (DHCP): " : " (static): ");
        for (v = xp25_json_get(a, "ip") ? xp25_json_get(a, "ip")->child : NULL; v; v = v->next) {
            xp25_buf_puts(out, v->str ? v->str : "");
            xp25_buf_puts(out, " ");
        }
        xp25_buf_puts(out, "gateway ");
        v = xp25_json_at(xp25_json_get(a, "gateway"), 0);
        xp25_buf_puts(out, v && v->type == XP25_JSTR ? v->str : "none");
        xp25_buf_puts(out, "\n");
    }
    xp25_buf_puts(out, "- DNS servers: ");
    for (v = xp25_json_get(r, "dns_servers") ? xp25_json_get(r, "dns_servers")->child : NULL; v; v = v->next) {
        xp25_buf_puts(out, v->str ? v->str : "");
        xp25_buf_puts(out, " ");
    }
    xp25_buf_puts(out, "\n");
    for (c = xp25_json_get(r, "checks") ? xp25_json_get(r, "checks")->child : NULL; c; c = c->next) {
        xp25_buf_puts(out, xp25_json_flag(c, "ok", 0) ? "- OK: " : "- FAILED: ");
        xp25_buf_puts(out, str(c, "check"));
        xp25_buf_puts(out, " ");
        xp25_buf_puts(out, str(c, "target"));
        if (*str(c, "detail")) { xp25_buf_puts(out, " - "); xp25_buf_puts(out, str(c, "detail")); }
        xp25_buf_puts(out, "\n");
    }
}

static void say_disk(XP25_BUF *out, const XP25_JNODE *r, int limit)
{
    const XP25_JNODE *v, *temp = xp25_json_get(r, "temp");
    (void)limit;
    for (v = xp25_json_get(r, "volumes") ? xp25_json_get(r, "volumes")->child : NULL; v; v = v->next) {
        xp25_buf_puts(out, "- ");
        xp25_buf_puts(out, str(v, "root"));
        xp25_buf_puts(out, " ");
        xp25_buf_puts(out, str(v, "fs"));
        xp25_buf_puts(out, ": ");
        xp25_buf_size(out, (xp25_u64)num(v, "free_bytes"));
        xp25_buf_puts(out, " free of ");
        xp25_buf_size(out, (xp25_u64)num(v, "total_bytes"));
        xp25_buf_puts(out, " (");
        xp25_buf_i64(out, num(v, "free_percent"));
        xp25_buf_puts(out, "% free)");
        if (xp25_json_get(v, "dirty") && xp25_json_get(v, "dirty")->type == XP25_JBOOL)
            xp25_buf_puts(out, xp25_json_flag(v, "dirty", 0) ? ", needs a disk check" : ", file system clean");
        xp25_buf_puts(out, "\n");
    }
    if (temp) {
        xp25_buf_puts(out, "- Your TEMP folder holds ");
        xp25_buf_i64(out, num(temp, "files"));
        xp25_buf_puts(out, " files (");
        xp25_buf_size(out, (xp25_u64)num(temp, "bytes"));
        xp25_buf_puts(out, ").\n");
    }
}

static void say_cmd(XP25_BUF *out, const XP25_JNODE *r, int limit)
{
    const char *text = str(r, "output");
    (void)limit;
    xp25_buf_puts(out, "Exit code ");
    xp25_buf_i64(out, num(r, "exit_code"));
    if (xp25_json_flag(r, "timed_out", 0)) xp25_buf_puts(out, " (stopped after the time limit)");
    xp25_buf_puts(out, ". Output:\n");
    xp25_buf_append(out, text, xp25_utf8_clip(text, 3000));
    if (xp25_json_flag(r, "truncated", 0) || strlen(text) > 3000) xp25_buf_puts(out, "\n[output shortened]");
}

static void say_registry(XP25_BUF *out, const XP25_JNODE *r, int limit)
{
    const XP25_JNODE *v;
    int n = 0;
    xp25_buf_puts(out, str(r, "path"));
    xp25_buf_puts(out, "\n");
    for (v = xp25_json_get(r, "values") ? xp25_json_get(r, "values")->child : NULL; v && n < limit; v = v->next, ++n) {
        const char *data = str(v, "data");
        xp25_buf_puts(out, "    ");
        xp25_buf_puts(out, *str(v, "name") ? str(v, "name") : "(Default)");
        xp25_buf_puts(out, " [");
        xp25_buf_puts(out, str(v, "type"));
        xp25_buf_puts(out, "] = ");
        xp25_buf_append(out, data, xp25_utf8_clip(data, 200));
        xp25_buf_puts(out, "\n");
    }
    for (v = xp25_json_get(r, "subkeys") ? xp25_json_get(r, "subkeys")->child : NULL; v && n < limit; v = v->next, ++n) {
        xp25_buf_puts(out, "    [");
        xp25_buf_puts(out, v->str ? v->str : "");
        xp25_buf_puts(out, "]\n");
    }
}

static void say_search(XP25_BUF *out, const XP25_JNODE *r, int limit)
{
    const XP25_JNODE *f;
    int n = 0;
    xp25_buf_puts(out, "RoverAI looked for: ");
    xp25_buf_puts(out, str(r, "description"));
    xp25_buf_puts(out, ". ");
    xp25_buf_i64(out, num(r, "total"));
    xp25_buf_puts(out, num(r, "total") == 1 ? " match" : " matches");
    if (xp25_json_flag(r, "relaxed", 0)) xp25_buf_puts(out, " (no file mentions every word, so the other criteria were used)");
    xp25_buf_puts(out, ".\n");
    for (f = xp25_json_get(r, "results") ? xp25_json_get(r, "results")->child : NULL; f && n < limit; f = f->next, ++n) {
        xp25_buf_puts(out, "- ");
        xp25_buf_puts(out, str(f, "path"));
        xp25_buf_puts(out, " (");
        if (!xp25_json_flag(f, "directory", 0)) { xp25_buf_size(out, (xp25_u64)num(f, "size")); xp25_buf_puts(out, ", "); }
        xp25_buf_puts(out, "modified ");
        xp25_buf_puts(out, str(f, "modified"));
        xp25_buf_puts(out, ")\n");
    }
}

static const char *command_of(const char *t)
{
    static const char *prefixes[] = { "run command:", "run command", "command:", "run:", "execute:", "execute ", "run ", "cmd ", NULL };
    size_t i;
    while (xp25_is_space((unsigned char)*t)) ++t;
    for (i = 0; prefixes[i]; ++i)
        if (xp25_starts_with_i(t, prefixes[i])) { t += strlen(prefixes[i]); break; }
    while (xp25_is_space((unsigned char)*t)) ++t;
    return t;
}

static int plan_cmd(PLAN *p)
{
    const XP25_ITEM *done = result_of(p, "cmd_execute", 0);
    XP25_BUF args, out;
    XP25_JW w;
    if (!done) {
        const char *command = command_of(p->text);
        size_t n = strlen(command);
        int ok;
        if (n >= 2 && (command[0] == '`' || command[0] == '"') && command[n - 1] == command[0]) { ++command; n -= 2; }
        xp25_buf_init(&args);
        xp25_jw_init(&w, &args);
        xp25_jw_obj(&w);
        xp25_jw_key(&w, "command"); xp25_jw_strn(&w, command, n);
        xp25_jw_key(&w, "timeout_seconds"); xp25_jw_i64(&w, 30);
        xp25_jw_end(&w);
        ok = call(p, "cmd_execute", xp25_buf_cstr(&args));
        xp25_buf_free(&args);
        return ok;
    }
    {
        XP25_JDOC doc;
        const XP25_JNODE *r = parse(done, &doc);
        const XP25_JNODE *error = xp25_json_get(r, "error");
        const char *code = xp25_json_string(error, "code");
        int ok;
        xp25_buf_init(&out);
        if (!r) xp25_buf_puts(&out, "The command produced no readable result.");
        else if (xp25_json_get(r, "exit_code")) {
            xp25_buf_puts(&out, xp25_json_flag(r, "ok", 0) ? "The command `" : "The command failed: `");
            xp25_buf_puts(&out, str(r, "command"));
            xp25_buf_puts(&out, "`. ");
            say_cmd(&out, r, 0);
        } else if (code) error_text(&out, r, "Running the command");
        ok = answer(p, &out);
        xp25_json_free(&doc);
        return ok;
    }
}

static const char *service_name(const char *t)
{
    static const struct { const char *phrase, *name; } map[] = {
        { "spooler", "Spooler" }, { "print", "Spooler" }, { "theme", "Themes" }, { "time", "W32Time" },
        { "update", "wuauserv" }, { "bits", "BITS" }, { "dhcp", "Dhcp" }, { "dns", "Dnscache" },
        { "firewall", "SharedAccess" }, { "wireless", "WZCSVC" }, { "audio", "AudioSrv" }, { "sound", "AudioSrv" },
        { "schedul", "Schedule" }, { "workstation", "LanmanWorkstation" }, { "server", "LanmanServer" },
        { "messenger", "Messenger" }, { "help", "helpsvc" }, { NULL, NULL } };
    size_t i;
    for (i = 0; map[i].phrase; ++i) if (has(t, map[i].phrase)) return map[i].name;
    return NULL;
}

static int plan_service_control(PLAN *p)
{
    const XP25_ITEM *done = result_of(p, "service_control", 0);
    const char *name = service_name(p->text);
    const char *action = has(p->text, "restart") ? "restart" : has(p->text, "stop") ? "stop" : "start";
    XP25_BUF args, out;
    XP25_JW w;
    if (!name) {
        xp25_buf_init(&out);
        xp25_buf_puts(&out, "Which service should I change? Name it, for example: \"restart the Print Spooler service\". "
                            "Ask me to \"list services\" to see them.");
        return answer(p, &out);
    }
    if (!done) {
        int ok;
        xp25_buf_init(&args);
        xp25_jw_init(&w, &args);
        xp25_jw_obj(&w);
        xp25_jw_key(&w, "name"); xp25_jw_str(&w, name);
        xp25_jw_key(&w, "action"); xp25_jw_str(&w, action);
        xp25_jw_end(&w);
        ok = call(p, "service_control", xp25_buf_cstr(&args));
        xp25_buf_free(&args);
        return ok;
    }
    {
        XP25_JDOC doc;
        const XP25_JNODE *r = parse(done, &doc);
        int ok;
        xp25_buf_init(&out);
        if (r && xp25_json_flag(r, "ok", 0)) {
            xp25_buf_puts(&out, "Done: ");
            xp25_buf_puts(&out, str(r, "action"));
            xp25_buf_puts(&out, " of service ");
            xp25_buf_puts(&out, str(r, "name"));
            xp25_buf_puts(&out, " completed; it is now ");
            xp25_buf_puts(&out, str(r, "state"));
            xp25_buf_puts(&out, ".");
        } else if (r) error_text(&out, r, "Changing the service");
        ok = answer(p, &out);
        xp25_json_free(&doc);
        return ok;
    }
}

/* Strip conversational tails so RoverAI gets the description of the file. */
static void search_part(const char *t, char *out, size_t size)
{
    static const char *cuts[] = { " and explain", " and tell", " and check", " and fix", " and show", " then ",
                                  " and what", ", and", ". ", NULL };
    size_t n = strlen(t), i;
    for (i = 0; cuts[i]; ++i) {
        const char *hit = xp25_stristr(t, cuts[i]);
        if (hit && (size_t)(hit - t) < n) n = (size_t)(hit - t);
    }
    if (n >= size) n = size - 1;
    memcpy(out, t, n);
    out[n] = 0;
}

static int read_call(PLAN *p, const char *path)
{
    XP25_BUF args;
    XP25_JW w;
    int ok;
    xp25_buf_init(&args);
    xp25_jw_init(&w, &args);
    xp25_jw_obj(&w);
    xp25_jw_key(&w, "action"); xp25_jw_str(&w, "read_text");
    xp25_jw_key(&w, "path"); xp25_jw_str(&w, path);
    xp25_jw_key(&w, "max_bytes"); xp25_jw_i64(&w, 16384);
    xp25_jw_end(&w);
    ok = call(p, "file_operations", xp25_buf_cstr(&args));
    xp25_buf_free(&args);
    return ok;
}

static int explain_content(PLAN *p, const char *path, int searched)
{
    const XP25_ITEM *read = result_of(p, "file_operations", 0), *edit = result_of(p, "file_operations", 1);
    XP25_JDOC rdoc, sdoc, edoc;
    const XP25_JNODE *r = parse(read, &rdoc), *s = searched ? parse(result_of(p, "file_search", 0), &sdoc) : NULL;
    const XP25_JNODE *e = parse(edit, &edoc);
    XP25_BUF out, findings;
    long fix_line = 0;
    char fix_old[256], fix_new[256];
    int problems = 0, ok;
    xp25_buf_init(&out);
    xp25_buf_init(&findings);
    if (!searched) memset(&sdoc, 0, sizeof(sdoc));
    if (s) say_search(&out, s, 3);
    if (!r || !xp25_json_flag(r, "ok", 0)) {
        if (r) error_text(&out, r, "Reading the file");
        else xp25_buf_puts(&out, "The file could not be read.");
        goto finish;
    }
    problems = xp25_analyze_network_text(str(r, "text"), &findings, &fix_line, fix_old, fix_new, sizeof(fix_old));
    if (!edit && fix_line > 0) {
        XP25_BUF args;
        XP25_JW w;
        xp25_buf_init(&args);
        xp25_jw_init(&w, &args);
        xp25_jw_obj(&w);
        xp25_jw_key(&w, "action"); xp25_jw_str(&w, "edit_line");
        xp25_jw_key(&w, "path"); xp25_jw_str(&w, path);
        xp25_jw_key(&w, "line"); xp25_jw_i64(&w, fix_line);
        xp25_jw_key(&w, "old_text"); xp25_jw_str(&w, fix_old);
        xp25_jw_key(&w, "new_text"); xp25_jw_str(&w, fix_new);
        xp25_jw_end(&w);
        ok = call(p, "file_operations", xp25_buf_cstr(&args));
        xp25_buf_free(&args);
        xp25_buf_free(&out);
        xp25_buf_free(&findings);
        xp25_json_free(&rdoc); xp25_json_free(&sdoc); xp25_json_free(&edoc);
        return ok;
    }
    xp25_buf_puts(&out, "\nI read ");
    xp25_buf_puts(&out, path);
    xp25_buf_puts(&out, " (");
    xp25_buf_size(&out, (xp25_u64)num(r, "bytes"));
    xp25_buf_puts(&out, ").\n");
    if (findings.len) xp25_buf_append(&out, findings.data, findings.len);
    if (!problems) xp25_buf_puts(&out, "I did not find problems in the network settings it contains.\n");
    if (edit) {
        if (e && xp25_json_flag(e, "ok", 0)) {
            xp25_buf_puts(&out, "Fix applied with your approval: line ");
            xp25_buf_i64(&out, num(e, "line"));
            xp25_buf_puts(&out, " now reads \"");
            xp25_buf_puts(&out, str(e, "new_text"));
            xp25_buf_puts(&out, "\". A backup was saved as ");
            xp25_buf_puts(&out, str(e, "backup"));
            xp25_buf_puts(&out, xp25_json_flag(e, "verified", 0) ? ". I re-read the file to confirm the change." : ".");
        } else if (e) error_text(&out, e, "Changing the file");
    }
finish:
    ok = answer(p, &out);
    xp25_buf_free(&findings);
    xp25_json_free(&rdoc); xp25_json_free(&sdoc); xp25_json_free(&edoc);
    return ok;
}

static int plan_find(PLAN *p, int explain)
{
    const XP25_ITEM *search = result_of(p, "file_search", 0);
    XP25_JDOC doc;
    const XP25_JNODE *r, *pick = NULL, *f;
    char query[400], path[300];
    int ok;
    if (!search) {
        XP25_BUF args;
        XP25_JW w;
        search_part(p->text, query, sizeof(query));
        xp25_buf_init(&args);
        xp25_jw_init(&w, &args);
        xp25_jw_obj(&w);
        xp25_jw_key(&w, "query"); xp25_jw_str(&w, query);
        xp25_jw_key(&w, "limit"); xp25_jw_i64(&w, explain ? 5 : 10);
        xp25_jw_end(&w);
        ok = call(p, "file_search", xp25_buf_cstr(&args));
        xp25_buf_free(&args);
        return ok;
    }
    r = parse(search, &doc);
    if (!explain || !r || !xp25_json_flag(r, "ok", 0) || !num(r, "total")) {
        XP25_BUF out;
        xp25_buf_init(&out);
        if (!r || !xp25_json_flag(r, "ok", 0)) error_text(&out, r, "Searching");
        else if (!num(r, "total")) {
            xp25_buf_puts(&out, "RoverAI found no files matching: ");
            xp25_buf_puts(&out, str(r, "description"));
            xp25_buf_puts(&out, ". Try other words, or check that the folder is included in RoverAI's indexed locations.");
        } else say_search(&out, r, 10);
        ok = answer(p, &out);
        xp25_json_free(&doc);
        return ok;
    }
    for (f = xp25_json_get(r, "results")->child; f && !pick; f = f->next)
        if (!xp25_json_flag(f, "directory", 0)) pick = f;
    if (!pick) {
        XP25_BUF out;
        xp25_buf_init(&out);
        say_search(&out, r, 5);
        xp25_buf_puts(&out, "Only folders matched, so there is no file content to explain.");
        ok = answer(p, &out);
        xp25_json_free(&doc);
        return ok;
    }
    strncpy(path, str(pick, "path"), sizeof(path) - 1);
    path[sizeof(path) - 1] = 0;
    xp25_json_free(&doc);
    if (!result_of(p, "file_operations", 0)) return read_call(p, path);
    return explain_content(p, path, 1);
}

/* Path named in a request: "quoted" exactly, otherwise up to the first
   " and ..." / " then ..." that follows a file extension, so folder names
   such as "Documents and Settings" stay intact. */
int xp25_offline_path(const char *text, char *path, size_t size)
{
    const char *start = drive_path(text), *end, *p;
    size_t n;
    if (!start || !size) return 0;
    if (start > text && start[-1] == '"' && (end = strchr(start, '"')) != NULL) n = (size_t)(end - start);
    else {
        n = strcspn(start, "\"\r\n");
        for (p = start; p < start + n; ++p) {
            if (*p == ' ' && (xp25_starts_with_i(p, " and ") || xp25_starts_with_i(p, " then ") ||
                              xp25_starts_with_i(p, " for ") || xp25_starts_with_i(p, " to "))) {
                const char *dot = p;
                while (dot > start && *dot != '.' && *dot != '\\') --dot;
                if (*dot == '.' && p - dot >= 2 && p - dot <= 6) { n = (size_t)(p - start); break; }
            }
        }
        while (n && (start[n - 1] == '.' || start[n - 1] == '?' || start[n - 1] == ' ' || start[n - 1] == ',' ||
                     start[n - 1] == '!')) --n;
    }
    if (!n || n >= size) return 0;
    memcpy(path, start, n);
    path[n] = 0;
    return 1;
}

static int plan_explain_file(PLAN *p)
{
    char path[300];
    if (!xp25_offline_path(p->text, path, sizeof(path))) return plan_help(p, 1);
    if (!result_of(p, "file_operations", 0)) return read_call(p, path);
    return explain_content(p, path, 0);
}

static int plan_registry(PLAN *p)
{
    const char *t = p->text;
    const char *start = xp25_stristr(t, "hklm\\");
    char path[400];
    size_t n = 0;
    XP25_BUF args;
    XP25_JW w;
    if (!start) start = xp25_stristr(t, "hkcu\\");
    if (!start) start = xp25_stristr(t, "hkey_");
    if (result_of(p, "registry_read", 0)) return finish_with(p, "registry_read", 0, say_registry, "Registry values", 40);
    if (!start) {
        start = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
        if (has(t, "startup") || has(t, "run")) start = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
    }
    while (start[n] && start[n] != '"' && start[n] != '\n' && n < sizeof(path) - 1) { path[n] = start[n]; ++n; }
    while (n && (path[n - 1] == '.' || path[n - 1] == '?' || path[n - 1] == ' ')) --n;
    path[n] = 0;
    xp25_buf_init(&args);
    xp25_jw_init(&w, &args);
    xp25_jw_obj(&w);
    xp25_jw_key(&w, "path"); xp25_jw_str(&w, path);
    xp25_jw_end(&w);
    n = (size_t)call(p, "registry_read", xp25_buf_cstr(&args));
    xp25_buf_free(&args);
    return (int)n;
}

static int plan_help(PLAN *p, int unknown)
{
    XP25_BUF out;
    xp25_buf_init(&out);
    if (unknown)
        xp25_buf_puts(&out, "I'm working offline, so I understand a fixed set of requests. ");
    xp25_buf_puts(&out, "I can help with:\n"
        "- \"My computer is running slowly\" - full check of CPU, memory, Event Viewer and disk, with fixes you approve\n"
        "- \"Show recent errors in Event Viewer\"\n"
        "- \"Run ipconfig /all\" (any command is shown to you for approval first)\n"
        "- \"List running processes\", \"List services\", \"Restart the Print Spooler service\"\n"
        "- \"Check my network connection\", \"How much disk space is free?\", \"System information\"\n"
        "- \"Find the PDF I edited yesterday\" or \"Find my network configuration file and explain what's wrong\"\n"
        "Configure an AI provider in Settings for open-ended questions.");
    return answer(p, &out);
}

static int plan(PLAN *p)
{
    int intent = xp25_offline_intent(p->text);
    switch (intent) {
    case I_SLOW: return plan_slow(p);
    case I_CMD: return plan_cmd(p);
    case I_EVENTS:
        if (!result_of(p, "eventlog_read", 0))
            return call(p, "eventlog_read", "{\"log\":\"System\",\"types\":[\"error\",\"warning\"],\"max_records\":8,\"since_hours\":168}");
        if (!result_of(p, "eventlog_read", 1))
            return call(p, "eventlog_read", "{\"log\":\"Application\",\"types\":[\"error\",\"warning\"],\"max_records\":5,\"since_hours\":168}");
        {
            XP25_JDOC a, b;
            const XP25_JNODE *s = parse(result_of(p, "eventlog_read", 0), &a), *ap = parse(result_of(p, "eventlog_read", 1), &b);
            XP25_BUF out;
            int ok;
            xp25_buf_init(&out);
            xp25_buf_puts(&out, "Event Viewer, last 7 days:\n");
            if (s && xp25_json_flag(s, "ok", 0)) say_events(&out, s, 8); else error_text(&out, s, "Reading the System log");
            if (ap && xp25_json_flag(ap, "ok", 0)) say_events(&out, ap, 5); else error_text(&out, ap, "\nReading the Application log");
            ok = answer(p, &out);
            xp25_json_free(&a);
            xp25_json_free(&b);
            return ok;
        }
    case I_PROCESSES:
        if (!result_of(p, "process_list", 0))
            return call(p, "process_list", has(p->text, "memory") ? "{\"sort\":\"memory\",\"limit\":15,\"sample_ms\":1000}"
                                                                  : "{\"sort\":\"cpu\",\"limit\":15,\"sample_ms\":1000}");
        return finish_with(p, "process_list", 0, say_processes, "Running processes", 15);
    case I_PROCESS_DETAIL:
        if (!result_of(p, "process_list", 0)) return call(p, "process_list", "{\"sort\":\"cpu\",\"limit\":40,\"sample_ms\":500}");
        return finish_with(p, "process_list", 0, say_processes, "Running processes (ask about one by PID for details)", 15);
    case I_SERVICES:
        if (!result_of(p, "service_list", 0)) return call(p, "service_list", "{\"state\":\"all\",\"limit\":60}");
        return finish_with(p, "service_list", 0, say_services, "Windows services", 60);
    case I_SERVICE_CONTROL: return plan_service_control(p);
    case I_NETWORK:
        if (!result_of(p, "network_diagnostics", 0)) return call(p, "network_diagnostics", "{}");
        return finish_with(p, "network_diagnostics", 0, say_network, "Network diagnostics", 0);
    case I_DISK:
        if (!result_of(p, "disk_diagnostics", 0)) return call(p, "disk_diagnostics", "{}");
        return finish_with(p, "disk_diagnostics", 0, say_disk, "Disk diagnostics", 0);
    case I_SYSINFO:
        if (!result_of(p, "system_info", 0)) return call(p, "system_info", "{}");
        return finish_with(p, "system_info", 0, say_system_wrapped, "System information", 0);
    case I_REGISTRY: return plan_registry(p);
    case I_FIND_EXPLAIN: return plan_find(p, 1);
    case I_FIND: return plan_find(p, 0);
    case I_EXPLAIN_FILE: return plan_explain_file(p);
    case I_HELP: return plan_help(p, 0);
    default: return plan_help(p, 1);
    }
}

static int offline_complete(XP25_PROVIDER *self, const XP25_CONVERSATION *c, const XP25_REGISTRY *registry,
                            const char *instructions, XP25_REPLY *reply)
{
    PLAN p;
    (void)registry;
    (void)instructions;
    p.c = c;
    p.start = xp25_conversation_last_user(c);
    p.settings = (XP25_OFFLINE *)self->context;
    p.reply = reply;
    if (p.start >= c->count) { xp25_reply_error(reply, "no_request", "There is no request to answer.", 0); return 0; }
    p.text = c->items[p.start].text;
    if (!plan(&p)) {
        if (!reply->error_code[0]) xp25_reply_error(reply, "offline_planner_failed", "The offline assistant could not continue.", 0);
        return 0;
    }
    return 1;
}

void xp25_offline_init(XP25_PROVIDER *provider, XP25_OFFLINE *settings)
{
    if (!settings->cpu_threshold) settings->cpu_threshold = 40;
    if (!settings->memory_threshold) settings->memory_threshold = 90;
    if (!settings->disk_free_threshold) settings->disk_free_threshold = 10;
    provider->name = "offline";
    provider->remote = 0;
    provider->complete = offline_complete;
    provider->context = settings;
}

/* ---- network settings analysis ---- */

static int parse_ipv4(const char *s, size_t n, unsigned long *out)
{
    unsigned long value = 0, part = 0;
    int parts = 0, digits = 0;
    size_t i;
    for (i = 0; i <= n; ++i) {
        char c = i < n ? s[i] : '.';
        if (xp25_is_digit((unsigned char)c)) {
            part = part * 10 + (unsigned long)(c - '0');
            if (++digits > 3) return 0;
        } else if (c == '.') {
            if (!digits || part > 255 || ++parts > 4) return 0;
            value = (value << 8) | part;
            part = 0;
            digits = 0;
        } else return 0;
    }
    if (parts != 4) return 0;
    *out = value & 0xFFFFFFFFUL;
    return 1;
}

static void ip_text(XP25_BUF *b, unsigned long ip)
{
    xp25_buf_u64(b, (ip >> 24) & 255); xp25_buf_putc(b, '.');
    xp25_buf_u64(b, (ip >> 16) & 255); xp25_buf_putc(b, '.');
    xp25_buf_u64(b, (ip >> 8) & 255); xp25_buf_putc(b, '.');
    xp25_buf_u64(b, ip & 255);
}

typedef struct { long line; char key[64]; char value[128]; char raw[256]; size_t value_at; } KV;

static int key_in(const char *key, const char *const *names)
{
    for (; *names; ++names) if (xp25_strieq(key, *names)) return 1;
    return 0;
}

int xp25_analyze_network_text(const char *text, XP25_BUF *findings, long *fix_line,
                              char *fix_old, char *fix_new, size_t fix_size)
{
    static const char *const ip_keys[] = { "ipaddress", "ip", "address", "ip_address", "staticip", "ipaddr", NULL };
    static const char *const mask_keys[] = { "subnetmask", "subnet", "netmask", "mask", NULL };
    static const char *const gw_keys[] = { "defaultgateway", "gateway", "router", "gw", NULL };
    static const char *const dns_keys[] = { "dns", "dns1", "dns2", "dnsserver", "nameserver", "primarydns",
                                            "secondarydns", "dnsservers", NULL };
    static const char *const dhcp_keys[] = { "dhcp", "usedhcp", "enabledhcp", "dhcpenabled", NULL };
    static const char *const watched[] = { "microsoft.com", "windowsupdate", "google.", "openai.com", "bank", NULL };
    KV ip, mask, gw, dhcp;
    KV dns[4];
    int dns_count = 0, problems = 0, hosts_lines = 0, ini_lines = 0;
    long line_no = 0;
    const char *p = text ? text : "";
    memset(&ip, 0, sizeof(ip)); memset(&mask, 0, sizeof(mask)); memset(&gw, 0, sizeof(gw)); memset(&dhcp, 0, sizeof(dhcp));
    *fix_line = 0;
    fix_old[0] = fix_new[0] = 0;
    while (*p) {
        const char *end = p, *eq, *s, *e;
        size_t len;
        char line[256];
        while (*end && *end != '\n') ++end;
        len = (size_t)(end - p);
        if (len && p[len - 1] == '\r') --len;
        if (len >= sizeof(line)) len = sizeof(line) - 1;
        memcpy(line, p, len);
        line[len] = 0;
        ++line_no;
        p = *end ? end + 1 : end;
        s = line;
        while (xp25_is_space((unsigned char)*s)) ++s;
        if (!*s || *s == '#' || *s == ';' || *s == '[') continue;
        eq = strchr(s, '=');
        if (eq) {
            KV kv;
            size_t kn;
            memset(&kv, 0, sizeof(kv));
            e = eq;
            while (e > s && xp25_is_space((unsigned char)e[-1])) --e;
            kn = (size_t)(e - s);
            if (!kn || kn >= sizeof(kv.key)) continue;
            memcpy(kv.key, s, kn);
            s = eq + 1;
            while (xp25_is_space((unsigned char)*s)) ++s;
            e = s + strlen(s);
            while (e > s && xp25_is_space((unsigned char)e[-1])) --e;
            if ((size_t)(e - s) >= sizeof(kv.value)) continue;
            memcpy(kv.value, s, (size_t)(e - s));
            kv.value_at = (size_t)(s - line);
            kv.line = line_no;
            strcpy(kv.raw, line);
            ++ini_lines;
            if (key_in(kv.key, ip_keys)) ip = kv;
            else if (key_in(kv.key, mask_keys)) mask = kv;
            else if (key_in(kv.key, gw_keys)) gw = kv;
            else if (key_in(kv.key, dhcp_keys)) dhcp = kv;
            else if (key_in(kv.key, dns_keys) && dns_count < 4) dns[dns_count++] = kv;
        } else {
            /* hosts format: address followed by names */
            unsigned long addr;
            size_t i, an = 0;
            const char *names;
            while (s[an] && !xp25_is_space((unsigned char)s[an])) ++an;
            names = s + an;
            while (xp25_is_space((unsigned char)*names)) ++names;
            if (!*names) continue;
            ++hosts_lines;
            if (!parse_ipv4(s, an, &addr)) {
                xp25_buf_puts(findings, "- Problem: line ");
                xp25_buf_i64(findings, line_no);
                xp25_buf_puts(findings, " maps names to \"");
                xp25_buf_append(findings, s, an);
                xp25_buf_puts(findings, "\", which is not a valid IPv4 address.\n");
                ++problems;
                continue;
            }
            for (i = 0; watched[i]; ++i)
                if (xp25_stristr(names, watched[i]) && (addr >> 24) != 127) {
                    xp25_buf_puts(findings, "- Problem: line ");
                    xp25_buf_i64(findings, line_no);
                    xp25_buf_puts(findings, " redirects ");
                    xp25_buf_puts(findings, names);
                    xp25_buf_puts(findings, " to another address; this can hijack or block that site.\n");
                    ++problems;
                    break;
                }
        }
    }
    if (ini_lines && (ip.line || gw.line || dns_count || mask.line)) {
        unsigned long a = 0, m = 0, g = 0, d;
        int have_a = ip.line && parse_ipv4(ip.value, strlen(ip.value), &a);
        int have_m = mask.line && parse_ipv4(mask.value, strlen(mask.value), &m);
        int have_g = gw.line && parse_ipv4(gw.value, strlen(gw.value), &g);
        int uses_dhcp = dhcp.line && (xp25_strieq(dhcp.value, "yes") || xp25_strieq(dhcp.value, "true") || !strcmp(dhcp.value, "1"));
        int i;
        xp25_buf_puts(findings, "The file holds network settings");
        if (ip.line) { xp25_buf_puts(findings, ": address "); xp25_buf_puts(findings, ip.value); }
        if (mask.line) { xp25_buf_puts(findings, ", mask "); xp25_buf_puts(findings, mask.value); }
        if (gw.line) { xp25_buf_puts(findings, ", gateway "); xp25_buf_puts(findings, gw.value); }
        for (i = 0; i < dns_count; ++i) { xp25_buf_puts(findings, i ? ", " : ", DNS "); xp25_buf_puts(findings, dns[i].value); }
        if (dhcp.line) { xp25_buf_puts(findings, ", DHCP "); xp25_buf_puts(findings, dhcp.value); }
        xp25_buf_puts(findings, ".\n");
        if (ip.line && !have_a) {
            xp25_buf_puts(findings, "- Problem: line "); xp25_buf_i64(findings, ip.line);
            xp25_buf_puts(findings, " has an invalid IP address \""); xp25_buf_puts(findings, ip.value); xp25_buf_puts(findings, "\".\n");
            ++problems;
        }
        if (mask.line && (!have_m || ((~m & 0xFFFFFFFFUL) & ((~m & 0xFFFFFFFFUL) + 1)) != 0)) {
            xp25_buf_puts(findings, "- Problem: line "); xp25_buf_i64(findings, mask.line);
            xp25_buf_puts(findings, " has an invalid subnet mask \""); xp25_buf_puts(findings, mask.value); xp25_buf_puts(findings, "\".\n");
            ++problems;
            have_m = 0;
        }
        if (gw.line && !have_g) {
            xp25_buf_puts(findings, "- Problem: line "); xp25_buf_i64(findings, gw.line);
            xp25_buf_puts(findings, " has an invalid gateway \""); xp25_buf_puts(findings, gw.value); xp25_buf_puts(findings, "\".\n");
            ++problems;
        }
        if (have_a && have_m && have_g && (a & m) != (g & m)) {
            unsigned long suggestion = (a & m) + 1;
            XP25_BUF fixed;
            xp25_buf_puts(findings, "- Problem: line "); xp25_buf_i64(findings, gw.line);
            xp25_buf_puts(findings, ": the gateway "); xp25_buf_puts(findings, gw.value);
            xp25_buf_puts(findings, " is outside this computer's subnet (");
            ip_text(findings, a & m); xp25_buf_puts(findings, " with mask "); xp25_buf_puts(findings, mask.value);
            xp25_buf_puts(findings, "), so traffic cannot leave the local network.\n  Suggested fix: use a gateway inside the subnet, usually ");
            ip_text(findings, suggestion);
            xp25_buf_puts(findings, ".\n");
            ++problems;
            if (suggestion == a) ++suggestion;
            xp25_buf_init(&fixed);
            xp25_buf_append(&fixed, gw.raw, gw.value_at);
            ip_text(&fixed, suggestion);
            xp25_buf_puts(&fixed, gw.raw + gw.value_at + strlen(gw.value));
            if (fixed.len < fix_size && strlen(gw.raw) < fix_size && !*fix_line) {
                *fix_line = gw.line;
                strcpy(fix_old, gw.raw);
                strcpy(fix_new, xp25_buf_cstr(&fixed));
            }
            xp25_buf_free(&fixed);
        }
        if (have_a && have_g && a == g) {
            xp25_buf_puts(findings, "- Problem: the gateway is the same as this computer's own address.\n");
            ++problems;
        }
        for (i = 0; i < dns_count; ++i)
            if (*dns[i].value && !parse_ipv4(dns[i].value, strlen(dns[i].value), &d)) {
                xp25_buf_puts(findings, "- Problem: line "); xp25_buf_i64(findings, dns[i].line);
                xp25_buf_puts(findings, " has an invalid DNS server \""); xp25_buf_puts(findings, dns[i].value); xp25_buf_puts(findings, "\".\n");
                ++problems;
            }
        if (!dns_count && !uses_dhcp && ip.line) {
            xp25_buf_puts(findings, "- Problem: no DNS server is configured for this static address, so names will not resolve.\n");
            ++problems;
        }
    } else if (!hosts_lines && !ini_lines) {
        xp25_buf_puts(findings, "The file does not contain recognizable network settings (no key=value pairs or address entries).\n");
    } else if (hosts_lines && !problems) {
        xp25_buf_puts(findings, "The file is in hosts format with ");
        xp25_buf_i64(findings, hosts_lines);
        xp25_buf_puts(findings, " name mapping(s); all addresses are valid.\n");
    }
    return problems;
}
