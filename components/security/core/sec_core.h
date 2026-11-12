/* XP25 security baseline and audit: portable C89 core (no Windows headers).
   It holds the reviewed policy tables and the deterministic classification
   rules. Native adapters supply facts and perform every system operation;
   nothing here reports success for an operation it did not observe. */
#ifndef XP25_SEC_CORE_H
#define XP25_SEC_CORE_H
#include <stddef.h>

#define SEC_BASELINE_VERSION 1UL

/* Service start types as stored by the Service Control Manager. */
#define SEC_START_AUTO 2UL
#define SEC_START_MANUAL 3UL
#define SEC_START_DISABLED 4UL

/* Why a service is in the baseline. */
#define SEC_SVC_NETWORK_LISTENER 0x01u  /* accepts connections or datagrams */
#define SEC_SVC_REMOTE_ADMIN 0x02u      /* remote administration or remote control */
#define SEC_SVC_LEGACY_DISCOVERY 0x04u  /* NetBIOS browsing, SSDP, UPnP */
#define SEC_SVC_LEGACY_PROTOCOL 0x08u   /* SMBv1 server, NetDDE, Telnet, WebDAV redirector */
#define SEC_SVC_RETIRED_ENDPOINT 0x10u  /* talks to a vendor service that no longer exists */

typedef struct {
    const char *name;        /* service key name */
    unsigned long start;     /* enforced start type */
    unsigned flags;
    const char *reason;
    const char *compatibility;
} SEC_SERVICE_RULE;

unsigned sec_service_rule_count(void);
const SEC_SERVICE_RULE *sec_service_rule_at(unsigned index);
const SEC_SERVICE_RULE *sec_service_rule(const char *name);
/* Services the baseline must never stop or disable (RPC, COM, logon, shell,
   networking and installer dependencies). */
int sec_service_is_critical(const char *name);

/* Registry value kinds. Targets are HKEY_LOCAL_MACHINE only. */
#define SEC_REG_DWORD 1u        /* set exactly */
#define SEC_REG_DWORD_MIN 2u    /* raise to the target, never lower an existing stricter value */
#define SEC_REG_SZ 3u
#define SEC_REG_MULTI_EMPTY 4u  /* REG_MULTI_SZ with no strings */

/* Whether the running system honours the value at once or after a restart. */
#define SEC_EFFECT_IMMEDIATE 0u
#define SEC_EFFECT_RESTART 1u

typedef struct {
    const char *id;          /* stable identifier used by backup records */
    const char *key;         /* below HKEY_LOCAL_MACHINE */
    const char *value;       /* "" is the key's default value */
    unsigned kind;
    unsigned long number;
    const char *text;
    unsigned effect;
    const char *area;        /* lsa, smb, tcpip, remote, autorun, firewall, ie, wsh, help, process, rpc, audit */
    const char *reason;
    const char *compatibility;
} SEC_REGISTRY_RULE;

unsigned sec_registry_rule_count(void);
const SEC_REGISTRY_RULE *sec_registry_rule_at(unsigned index);
const SEC_REGISTRY_RULE *sec_registry_rule(const char *id);
/* Whether an observed DWORD satisfies the rule (present is 0 for a missing value). */
int sec_registry_dword_ok(const SEC_REGISTRY_RULE *rule, int present, unsigned long current);

/* Access-control baseline. A REPAIR rule looks at each file directly in a
   system directory and resets only those an unprivileged or individual
   account can modify; a TREE rule gives an XP25-owned directory or registry
   tree one protected descriptor. %W% is the Windows directory, %P% Program
   Files and %D% the system drive ("C:"). */
#define SEC_ACL_REPAIR_FILES 1u     /* files directly in a directory */
#define SEC_ACL_TREE_FILES 2u
#define SEC_ACL_TREE_REGISTRY 3u
#define SEC_ACL_REPAIR_KEYS 4u      /* every key below a registry key */

typedef struct {
    const char *id;
    unsigned kind;
    const char *root;        /* registry roots are below HKEY_LOCAL_MACHINE */
    const char *sddl;        /* TREE rules: owner and protected DACL of the root */
    const char *reason;
    const char *compatibility;
} SEC_ACL_RULE;

unsigned sec_acl_rule_count(void);
const SEC_ACL_RULE *sec_acl_rule_at(unsigned index);
const SEC_ACL_RULE *sec_acl_rule(const char *id);
/* Expands the rule root. Returns 0 when it does not fit. */
int sec_acl_root(const SEC_ACL_RULE *rule, const char *windows, const char *programs, char *out, size_t size);
/* 1 when path is the rule root or below it and has no "." or ".." component:
   a backup record can only name objects its rule covers. REPAIR rules cover
   files directly in the root only, REPAIR_KEYS rules any key below the root. */
int sec_acl_in_scope(const SEC_ACL_RULE *rule, const char *path, const char *windows, const char *programs);

/* NT 5.1 audit categories (POLICY_AUDIT_EVENT_TYPE order) and the baseline
   options: bit 0 success, bit 1 failure. */
#define SEC_AUDIT_CATEGORIES 9u
#define SEC_AUDIT_SUCCESS 1UL
#define SEC_AUDIT_FAILURE 2UL
const char *sec_audit_category_name(unsigned category);
unsigned long sec_audit_baseline(unsigned category);

/* ---- Backup records: one text line per item, strictly parsed ---------- */
#define SEC_BACKUP_MAGIC "XP25SEC-BACKUP 1"
#define SEC_BACKUP_DATA_MAX 2048u

#define SEC_ITEM_SERVICE 1u
#define SEC_ITEM_REGISTRY 2u
#define SEC_ITEM_AUDIT 3u
#define SEC_ITEM_ACL 4u         /* data holds "path\0SDDL": the object's original owner and DACL */

typedef struct {
    unsigned item;
    char id[64];                /* service name, registry or ACL rule id, audit category name or "mode" */
    unsigned long start;        /* service: original start type */
    unsigned running;           /* service: was running when recorded */
    unsigned present;           /* registry: the value existed */
    unsigned long type;         /* registry: original value type */
    unsigned long size;         /* registry: original data bytes */
    unsigned char data[SEC_BACKUP_DATA_MAX];
    unsigned long options;      /* audit: original options */
} SEC_BACKUP_RECORD;

/* Writes one line including the newline. Returns the length, 0 when the
   record is invalid or does not fit. */
size_t sec_backup_format(const SEC_BACKUP_RECORD *record, char *line, size_t size);
/* Parses one line without its newline. Returns 1 on success, 0 on any
   deviation from the exact format; unknown ids are a parse failure, so a
   backup can only name items this baseline manages. */
int sec_backup_parse(const char *line, SEC_BACKUP_RECORD *record);

/* ---- Bounded JSON line writer ----------------------------------------- */
typedef struct {
    char *data;
    size_t size, length;
    int overflow, first;
} SEC_JSON;

void sec_json_begin(SEC_JSON *json, char *buffer, size_t size);
void sec_json_string(SEC_JSON *json, const char *key, const char *value);
void sec_json_uint(SEC_JSON *json, const char *key, unsigned long value);
void sec_json_bool(SEC_JSON *json, const char *key, int value);
/* Closes the object and appends CR LF. Returns the length, 0 on overflow. */
size_t sec_json_end(SEC_JSON *json);

/* ---- Deterministic classification rules ------------------------------- */
#define SEC_SEVERITY_INFO 0
#define SEC_SEVERITY_LOW 1
#define SEC_SEVERITY_MEDIUM 2
#define SEC_SEVERITY_HIGH 3
const char *sec_severity_name(int severity);

/* Path facts. Paths are compared case-insensitively; both separators are accepted. */
#define SEC_PATH_UNQUOTED_SPACE 0x01u   /* unquoted command line whose program path contains a space */
#define SEC_PATH_USER_WRITABLE 0x02u    /* under a profile, a temp or a recycler directory */
#define SEC_PATH_OUTSIDE_SYSTEM 0x04u   /* not under the Windows or Program Files directories */
#define SEC_PATH_RELATIVE 0x08u         /* no drive or UNC root: resolved through a search path */
#define SEC_PATH_NETWORK 0x10u          /* UNC path */
/* command is an ImagePath or Run command line; windows and programs are the
   expanded directories (e.g. C:\WINDOWS, C:\Program Files). */
unsigned sec_path_facts(const char *command, const char *windows, const char *programs);

typedef struct {
    unsigned short port;
    int udp;
    int severity;               /* when reachable from the network */
    const char *name;
    const char *owner;          /* usual owning service */
} SEC_PORT;
/* Known legacy listener, or NULL for a port this table does not describe. */
const SEC_PORT *sec_port_lookup(unsigned short port, int udp);

typedef struct {
    const char *log;            /* Security or System */
    const char *source;         /* event source, NULL for any */
    unsigned long id;
    int severity;
    const char *rule;           /* finding rule identifier */
    const char *title;
} SEC_EVENT;
/* Event Log records the audit reports, or NULL when the record is not relevant. */
const SEC_EVENT *sec_event_lookup(const char *log, const char *source, unsigned long id);

/* Registry locations that start code automatically or load it into other
   processes. Keys are below HKEY_LOCAL_MACHINE; per-user locations are also
   read below HKEY_CURRENT_USER. */
#define SEC_AS_VALUES 0         /* every value of the key is one entry */
#define SEC_AS_SINGLE 1         /* one named value */
#define SEC_AS_SUBKEYS 2        /* one entry per subkey, read from its named value */
#define SEC_AS_MULTI 3          /* REG_MULTI_SZ: one entry per string */
#define SEC_AS_ANY_IS_FINDING 0x100 /* the location is empty on an unmodified system */

typedef struct {
    const char *id;
    int per_user;
    const char *key;
    int kind;                   /* SEC_AS_* with optional SEC_AS_ANY_IS_FINDING */
    const char *value;
    const char *expected;       /* SINGLE: installed default; MULTI: defaults joined by '|';
                                   %W% stands for the Windows directory; NULL: no default known */
    int severity;               /* of a deviation from the default */
} SEC_AUTOSTART;
unsigned sec_autostart_count(void);
const SEC_AUTOSTART *sec_autostart_at(unsigned index);
/* 1 when an entry of the location equals (SINGLE) or belongs to (MULTI) the
   installed default; 0 when it deviates or the location has no default. */
int sec_autostart_default(const SEC_AUTOSTART *location, const char *current, const char *windows);

int sec_equal_nocase(const char *a, const char *b);
#endif
