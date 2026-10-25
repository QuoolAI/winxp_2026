/* XP25 AI runtime: shared agent contract for ClippyAI, RoverAI and later agents.

   Ownership and trust rules:
   - Permission is decided by the tool's classifier and the host's approval
     callback only. Model output, tool results, file names and log text are
     data; nothing in them can authorize a tool call.
   - An approval covers exactly one parsed call (tool + canonical arguments,
     recorded as a digest) and is consumed by that call.
   - Results classified XP25_EGRESS_SENSITIVE are sent to a remote provider
     only after the host's share callback allows it; otherwise the provider
     receives a withheld placeholder. XP25_EGRESS_NEVER is never sent. */
#ifndef XP25_AGENT_H
#define XP25_AGENT_H
#include "xp25_base.h"

typedef enum {
    XP25_PERM_READ,        /* collect information and report */
    XP25_PERM_APPROVAL,    /* change something: explicit user approval */
    XP25_PERM_PRIVILEGED,  /* administrative: approval plus privileged broker */
    XP25_PERM_DENIED       /* outside policy: never executed */
} XP25_PERM;

typedef enum {
    XP25_EGRESS_METADATA,  /* system facts the user expects the assistant to discuss */
    XP25_EGRESS_SENSITIVE, /* logs, file content, command output, registry data */
    XP25_EGRESS_NEVER      /* must not leave the machine */
} XP25_EGRESS;

typedef struct {
    XP25_PERM perm;
    char action[96];     /* short title, e.g. "Restart service" */
    char *command;       /* exact operation shown to the user */
    char *target;        /* object affected */
    char *effects;       /* expected effects */
    char *denial;        /* reason when perm == XP25_PERM_DENIED */
    char digest[65];     /* SHA-256 of tool name and canonical arguments */
} XP25_PROPOSAL;

typedef struct XP25_TOOL XP25_TOOL;
/* Fill the proposal (perm, action, command, target, effects). Return 0 on
   malformed arguments after writing a denial reason. */
typedef int (*XP25_CLASSIFY)(const XP25_TOOL *tool, const XP25_JNODE *args, XP25_PROPOSAL *proposal);
/* Write a JSON object to result: {"ok":true,...} or {"ok":false,"error":{...}}.
   Return 1 on success, 0 on failure. May raise *egress. */
typedef int (*XP25_EXECUTE)(const XP25_TOOL *tool, const XP25_JNODE *args, XP25_BUF *result,
                            XP25_EGRESS *egress);

struct XP25_TOOL {
    const char *name;
    const char *description;
    const char *parameters;   /* JSON Schema object text */
    XP25_PERM base;
    XP25_EGRESS egress;
    XP25_CLASSIFY classify;   /* NULL: use base permission */
    XP25_EXECUTE execute;
    void *context;
};

typedef struct {
    XP25_TOOL *items;
    size_t count;
    size_t cap;
} XP25_REGISTRY;

int xp25_registry_add(XP25_REGISTRY *registry, const XP25_TOOL *tool);
const XP25_TOOL *xp25_registry_find(const XP25_REGISTRY *registry, const char *name);
void xp25_registry_free(XP25_REGISTRY *registry);
void xp25_proposal_free(XP25_PROPOSAL *proposal);
void xp25_proposal_text(char **field, const char *text);
void xp25_proposal_deny(XP25_PROPOSAL *proposal, const char *reason);
void xp25_result_error(XP25_BUF *result, const char *code, const char *message);
const char *xp25_perm_name(XP25_PERM perm);
/* Digest of a call: SHA-256("xp25-call\n" name "\n" canonical-args) as hex. */
void xp25_call_digest(const char *name, const XP25_JNODE *args, char digest[65]);

typedef enum { XP25_ITEM_USER, XP25_ITEM_ASSISTANT, XP25_ITEM_CALL, XP25_ITEM_RESULT } XP25_ITEM_KIND;

typedef struct {
    XP25_ITEM_KIND kind;
    int turn;
    char *text;          /* user/assistant text or tool result JSON */
    char *call_id;
    char *name;          /* tool name for calls and results */
    char *arguments;     /* call arguments JSON text */
    XP25_EGRESS egress;
    int shared;          /* results: 1 may leave the machine, -1 withheld, 0 undecided */
    int ok;              /* results: tool reported success */
} XP25_ITEM;

typedef struct {
    XP25_ITEM *items;
    size_t count;
    size_t cap;
    int turn;
} XP25_CONVERSATION;

void xp25_conversation_init(XP25_CONVERSATION *c);
void xp25_conversation_free(XP25_CONVERSATION *c);
XP25_ITEM *xp25_conversation_add(XP25_CONVERSATION *c, XP25_ITEM_KIND kind, const char *text);
/* Index of the newest user item, or c->count when there is none. */
size_t xp25_conversation_last_user(const XP25_CONVERSATION *c);
/* Text sent to a remote provider for this result (placeholder when withheld). */
const char *xp25_item_output_for(const XP25_ITEM *item, int remote);

#define XP25_MAX_CALLS 8
typedef struct {
    char *call_id;
    char *name;
    char *arguments;
} XP25_CALL;

typedef struct {
    char *text;
    XP25_CALL calls[XP25_MAX_CALLS];
    size_t call_count;
    char error_code[40];   /* empty on success */
    char *error_message;
    int retryable;
    int http_status;
} XP25_REPLY;

void xp25_reply_free(XP25_REPLY *reply);
void xp25_reply_error(XP25_REPLY *reply, const char *code, const char *message, int retryable);

typedef struct XP25_PROVIDER XP25_PROVIDER;
struct XP25_PROVIDER {
    const char *name;
    int remote;   /* request content leaves this computer */
    int (*complete)(XP25_PROVIDER *self, const XP25_CONVERSATION *conversation,
                    const XP25_REGISTRY *registry, const char *instructions, XP25_REPLY *reply);
    void *context;
};

typedef enum {
    XP25_EV_THINKING, XP25_EV_TOOL_START, XP25_EV_TOOL_DONE, XP25_EV_TOOL_DENIED,
    XP25_EV_ASSISTANT, XP25_EV_ERROR, XP25_EV_NOTICE
} XP25_EVENT_KIND;

typedef struct {
    XP25_EVENT_KIND kind;
    const char *tool;
    const char *text;     /* user-facing summary */
    const char *detail;   /* result JSON or proposal command */
    int ok;
} XP25_EVENT;

#define XP25_SHARE_DENY 0
#define XP25_SHARE_ONCE 1
#define XP25_SHARE_CONVERSATION 2

typedef struct {
    int (*approve)(void *ctx, const char *tool, const XP25_PROPOSAL *proposal); /* 1 approve */
    int (*share)(void *ctx, const char *tool, const char *provider, const char *preview);
    void (*event)(void *ctx, const XP25_EVENT *event);
    int (*cancelled)(void *ctx);
    void (*audit)(void *ctx, const char *json_line);
    void *ctx;
} XP25_HOST;

typedef struct {
    XP25_CONVERSATION conversation;
    XP25_REGISTRY *registry;
    XP25_PROVIDER *provider;
    XP25_PROVIDER *fallback;     /* local planner used when the configured provider fails */
    XP25_HOST host;
    const char *instructions;
    int max_steps;
    unsigned long call_counter;
    int share_remembered;
    size_t result_limit;         /* bytes of one tool result kept in the conversation */
} XP25_AGENT;

void xp25_agent_init(XP25_AGENT *agent, XP25_REGISTRY *registry, XP25_PROVIDER *provider);
void xp25_agent_free(XP25_AGENT *agent);
/* Run one user turn to completion. Returns 1 when an assistant answer was
   produced, 0 on failure or cancellation (reported through host events). */
int xp25_agent_turn(XP25_AGENT *agent, const char *user_text);
/* Execute one call through classification, approval, execution and audit.
   Used by the loop and by hosts that run a tool directly (e.g. RoverAI). */
int xp25_agent_call(XP25_AGENT *agent, const char *name, const char *arguments, XP25_BUF *result);
extern const char xp25_default_instructions[];
#endif
