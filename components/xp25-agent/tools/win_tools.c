/* XP25 AI runtime: native tool registry and shared helpers. */
#include <windows.h>
#include <string.h>
#include "win_tools.h"

void tool_proposal(XP25_PROPOSAL *p, const char *action, const char *command, const char *target, const char *effects)
{
    lstrcpynA(p->action, action, sizeof(p->action));
    xp25_proposal_text(&p->command, command);
    xp25_proposal_text(&p->target, target);
    xp25_proposal_text(&p->effects, effects);
}

int tool_ok_begin(XP25_JW *w, XP25_BUF *out)
{
    xp25_buf_reset(out);
    xp25_jw_init(w, out);
    xp25_jw_obj(w);
    xp25_jw_key(w, "ok");
    xp25_jw_bool(w, 1);
    return 1;
}

int tool_finish(XP25_JW *w, XP25_BUF *out)
{
    xp25_jw_end(w);
    if (!xp25_jw_ok(w)) {
        xp25_result_error(out, "result_too_large", "The result could not be encoded.");
        return 0;
    }
    return 1;
}

int tool_win32_error(XP25_BUF *out, const char *code, const char *what, DWORD error)
{
    WCHAR *text = NULL;
    XP25_BUF message;
    xp25_buf_init(&message);
    xp25_buf_puts(&message, what);
    xp25_buf_puts(&message, " (Windows error ");
    xp25_buf_u64(&message, error);
    xp25_buf_puts(&message, ")");
    if (FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                       NULL, error, 0, (WCHAR *)&text, 0, NULL) && text) {
        size_t n = lstrlenW(text);
        while (n && (text[n - 1] == L'\r' || text[n - 1] == L'\n' || text[n - 1] == L' ' || text[n - 1] == L'.')) text[--n] = 0;
        xp25_buf_puts(&message, ": ");
        xp25w_buf_wide(&message, text);
        LocalFree(text);
    }
    xp25_result_error(out, code, xp25_buf_cstr(&message));
    xp25_buf_free(&message);
    return 0;
}

const char *tool_arg(const XP25_JNODE *args, const char *key, const char *fallback)
{
    const char *value = xp25_json_string(args, key);
    return value ? value : fallback;
}

long tool_int(const XP25_JNODE *args, const char *key, long fallback, long low, long high)
{
    xp25_i64 v;
    if (!xp25_json_i64(args, key, &v)) return fallback;
    if (v < low) return low;
    if (v > high) return high;
    return (long)v;
}

static const char empty_schema[] = "{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}";

int xp25w_register_tools(XP25_REGISTRY *r, XP25W_TOOLS *context)
{
    static const struct {
        const char *name, *description, *parameters;
        XP25_PERM base;
        XP25_EGRESS egress;
        XP25_CLASSIFY classify;
        XP25_EXECUTE execute;
    } tools[] = {
        { "system_info", "Windows version, computer name, processor, memory use, uptime and drive capacity.",
          empty_schema, XP25_PERM_READ, XP25_EGRESS_METADATA, NULL, tool_system_info },
        { "process_list", "List running processes with CPU use (sampled), memory and threads, busiest first.",
          "{\"type\":\"object\",\"properties\":{\"sort\":{\"type\":\"string\",\"enum\":[\"cpu\",\"memory\",\"name\",\"pid\"]},"
          "\"limit\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":100},\"sample_ms\":{\"type\":\"integer\",\"minimum\":0,"
          "\"maximum\":5000},\"filter\":{\"type\":\"string\"}},\"additionalProperties\":false}",
          XP25_PERM_READ, XP25_EGRESS_METADATA, NULL, tool_process_list },
        { "process_details", "Inspect one process: path, parent, priority, memory, CPU time, handles and loaded modules.",
          "{\"type\":\"object\",\"properties\":{\"pid\":{\"type\":\"integer\"}},\"required\":[\"pid\"],\"additionalProperties\":false}",
          XP25_PERM_READ, XP25_EGRESS_METADATA, NULL, tool_process_details },
        { "process_control", "End a process or lower its priority. Requires the user's approval; Windows and XP25 processes are refused.",
          "{\"type\":\"object\",\"properties\":{\"pid\":{\"type\":\"integer\"},\"image\":{\"type\":\"string\",\"description\":"
          "\"Expected image name such as app.exe\"},\"action\":{\"type\":\"string\",\"enum\":[\"terminate\",\"lower_priority\"]},"
          "\"reason\":{\"type\":\"string\"}},\"required\":[\"pid\",\"image\",\"action\"],\"additionalProperties\":false}",
          XP25_PERM_APPROVAL, XP25_EGRESS_METADATA, classify_process_control, tool_process_control },
        { "service_list", "List Windows services with state, start type and process ID.",
          "{\"type\":\"object\",\"properties\":{\"state\":{\"type\":\"string\",\"enum\":[\"all\",\"running\",\"stopped\"]},"
          "\"filter\":{\"type\":\"string\"},\"limit\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":300}},\"additionalProperties\":false}",
          XP25_PERM_READ, XP25_EGRESS_METADATA, NULL, tool_service_list },
        { "service_control", "Start, stop or restart an authorized Windows service. Requires approval; administrative changes use the XP25 broker.",
          "{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\",\"description\":\"Service key name, e.g. Spooler\"},"
          "\"action\":{\"type\":\"string\",\"enum\":[\"start\",\"stop\",\"restart\"]}},\"required\":[\"name\",\"action\"],"
          "\"additionalProperties\":false}",
          XP25_PERM_APPROVAL, XP25_EGRESS_METADATA, classify_service_control, tool_service_control },
        { "cmd_execute", "Run one command with cmd.exe and capture its output and exit code. Read-only diagnostics such as "
          "ipconfig run directly; any other command is shown to the user for approval first.",
          "{\"type\":\"object\",\"properties\":{\"command\":{\"type\":\"string\"},\"timeout_seconds\":{\"type\":\"integer\","
          "\"minimum\":1,\"maximum\":300},\"working_directory\":{\"type\":\"string\"}},\"required\":[\"command\"],"
          "\"additionalProperties\":false}",
          XP25_PERM_APPROVAL, XP25_EGRESS_SENSITIVE, classify_cmd, tool_cmd },
        { "eventlog_read", "Read Event Viewer records (System, Application or Security) newest first, with formatted messages.",
          "{\"type\":\"object\",\"properties\":{\"log\":{\"type\":\"string\",\"enum\":[\"System\",\"Application\",\"Security\"]},"
          "\"types\":{\"type\":\"array\",\"items\":{\"type\":\"string\",\"enum\":[\"error\",\"warning\",\"information\","
          "\"audit_success\",\"audit_failure\"]}},\"max_records\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":100},"
          "\"since_hours\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":8760},\"source\":{\"type\":\"string\"}},"
          "\"additionalProperties\":false}",
          XP25_PERM_READ, XP25_EGRESS_SENSITIVE, NULL, tool_eventlog },
        { "network_diagnostics", "Network adapters, IP configuration, DNS servers, and gateway, DNS and TCP reachability checks.",
          "{\"type\":\"object\",\"properties\":{\"host\":{\"type\":\"string\"},\"port\":{\"type\":\"integer\",\"minimum\":1,"
          "\"maximum\":65535}},\"additionalProperties\":false}",
          XP25_PERM_READ, XP25_EGRESS_METADATA, NULL, tool_network },
        { "disk_diagnostics", "Fixed volume capacity, file system, dirty-bit status and the size of the user's TEMP folder.",
          empty_schema, XP25_PERM_READ, XP25_EGRESS_METADATA, NULL, tool_disk },
        { "registry_read", "Read values and subkeys of an approved diagnostic registry key (HKLM or HKCU). Credential and "
          "security locations are refused.",
          "{\"type\":\"object\",\"properties\":{\"path\":{\"type\":\"string\"},\"value\":{\"type\":\"string\"}},"
          "\"required\":[\"path\"],\"additionalProperties\":false}",
          XP25_PERM_READ, XP25_EGRESS_SENSITIVE, classify_registry, tool_registry },
        { "file_operations", "Inspect files (stat, list, read_text) and, with the user's approval, change them (write_text, "
          "edit_line, copy, move, rename, delete to Recycle Bin, mkdir, clean_temp).",
          "{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\",\"enum\":[\"stat\",\"list\",\"read_text\","
          "\"write_text\",\"edit_line\",\"copy\",\"move\",\"rename\",\"delete\",\"mkdir\",\"clean_temp\"]},\"path\":{\"type\":"
          "\"string\"},\"destination\":{\"type\":\"string\"},\"new_name\":{\"type\":\"string\"},\"content\":{\"type\":\"string\"},"
          "\"line\":{\"type\":\"integer\"},\"old_text\":{\"type\":\"string\"},\"new_text\":{\"type\":\"string\"},\"max_bytes\":"
          "{\"type\":\"integer\",\"minimum\":1,\"maximum\":262144}},\"required\":[\"action\",\"path\"],\"additionalProperties\":false}",
          XP25_PERM_APPROVAL, XP25_EGRESS_SENSITIVE, classify_files, tool_files },
        { "file_search", "RoverAI local file search. Describe the files in natural language; results are real files from the "
          "local index (never invented). Searches the whole computer or one folder.",
          "{\"type\":\"object\",\"properties\":{\"query\":{\"type\":\"string\"},\"scope\":{\"type\":\"string\",\"description\":"
          "\"computer, or a folder path\"},\"limit\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":200}},\"required\":[\"query\"],"
          "\"additionalProperties\":false}",
          XP25_PERM_READ, XP25_EGRESS_METADATA, NULL, tool_file_search },
        { NULL, NULL, NULL, XP25_PERM_DENIED, XP25_EGRESS_NEVER, NULL, NULL }
    };
    size_t i;
    for (i = 0; tools[i].name; ++i) {
        XP25_TOOL t;
        memset(&t, 0, sizeof(t));
        t.name = tools[i].name;
        t.description = tools[i].description;
        t.parameters = tools[i].parameters;
        t.base = tools[i].base;
        t.egress = tools[i].egress;
        t.classify = tools[i].classify;
        t.execute = tools[i].execute;
        t.context = context;
        if (!xp25_registry_add(r, &t)) return 0;
    }
    return 1;
}
