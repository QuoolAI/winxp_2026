/* XP25 AI runtime: internal declarations shared by the native tools. */
#ifndef XP25_WIN_TOOLS_H
#define XP25_WIN_TOOLS_H
#include "../runtime/xp25_win.h"

#define TOOL_CONTEXT(tool) ((XP25W_TOOLS *)(tool)->context)

int tool_system_info(const XP25_TOOL *, const XP25_JNODE *, XP25_BUF *, XP25_EGRESS *);
int tool_disk(const XP25_TOOL *, const XP25_JNODE *, XP25_BUF *, XP25_EGRESS *);
int tool_process_list(const XP25_TOOL *, const XP25_JNODE *, XP25_BUF *, XP25_EGRESS *);
int tool_process_details(const XP25_TOOL *, const XP25_JNODE *, XP25_BUF *, XP25_EGRESS *);
int classify_process_control(const XP25_TOOL *, const XP25_JNODE *, XP25_PROPOSAL *);
int tool_process_control(const XP25_TOOL *, const XP25_JNODE *, XP25_BUF *, XP25_EGRESS *);
int tool_service_list(const XP25_TOOL *, const XP25_JNODE *, XP25_BUF *, XP25_EGRESS *);
int classify_service_control(const XP25_TOOL *, const XP25_JNODE *, XP25_PROPOSAL *);
int tool_service_control(const XP25_TOOL *, const XP25_JNODE *, XP25_BUF *, XP25_EGRESS *);
int classify_cmd(const XP25_TOOL *, const XP25_JNODE *, XP25_PROPOSAL *);
int tool_cmd(const XP25_TOOL *, const XP25_JNODE *, XP25_BUF *, XP25_EGRESS *);
int tool_eventlog(const XP25_TOOL *, const XP25_JNODE *, XP25_BUF *, XP25_EGRESS *);
int tool_network(const XP25_TOOL *, const XP25_JNODE *, XP25_BUF *, XP25_EGRESS *);
int classify_registry(const XP25_TOOL *, const XP25_JNODE *, XP25_PROPOSAL *);
int tool_registry(const XP25_TOOL *, const XP25_JNODE *, XP25_BUF *, XP25_EGRESS *);
int classify_files(const XP25_TOOL *, const XP25_JNODE *, XP25_PROPOSAL *);
int tool_files(const XP25_TOOL *, const XP25_JNODE *, XP25_BUF *, XP25_EGRESS *);
int tool_file_search(const XP25_TOOL *, const XP25_JNODE *, XP25_BUF *, XP25_EGRESS *);

/* Broker client: one JSON request, one JSON reply over the broker pipe. */
#define XP25_BROKER_PIPE L"\\\\.\\pipe\\XP25AgentBroker"
int xp25w_broker_call(const char *request_json, XP25_BUF *reply);
/* Start/stop/restart through the SCM; shared by the tool and XP25Broker.exe. */
int xp25w_service_change(const char *name, const char *action, XP25_BUF *out);

void tool_proposal(XP25_PROPOSAL *p, const char *action, const char *command, const char *target, const char *effects);
int tool_ok_begin(XP25_JW *w, XP25_BUF *out);
int tool_finish(XP25_JW *w, XP25_BUF *out);
int tool_win32_error(XP25_BUF *out, const char *code, const char *what, DWORD error);
const char *tool_arg(const XP25_JNODE *args, const char *key, const char *fallback);
long tool_int(const XP25_JNODE *args, const char *key, long fallback, long low, long high);
#endif
