/* XP25 AI runtime: native NT 5.1 adapters shared through xp25agent.dll. */
#ifndef XP25_WIN_H
#define XP25_WIN_H
#include <windows.h>
#include "xp25_agent.h"
#include "../permissions/xp25_policy.h"

#define XP25_REG_ROOT L"Software\\XP25\\Agent"
#define XP25_REG_SECRETS L"Software\\XP25\\Agent\\Protected"

/* Conversions return xp25_alloc'd strings (free with xp25_free). */
WCHAR *xp25w_wide(const char *utf8);
char *xp25w_utf8(const WCHAR *wide);
int xp25w_buf_wide(XP25_BUF *b, const WCHAR *wide);
void xp25w_copy_utf8(char *out, size_t size, const WCHAR *wide);
void xp25w_copy_wide(WCHAR *out, size_t count, const char *utf8);

unsigned long xp25w_unix_time(const FILETIME *utc);
unsigned long xp25w_now(void);
long xp25w_bias_minutes(void);
void xp25w_format_filetime(const FILETIME *utc, char out[20]);   /* local "YYYY-MM-DD HH:MM" */

typedef struct {
    WCHAR windows[MAX_PATH];
    WCHAR profile[MAX_PATH];
    WCHAR profiles_root[MAX_PATH];
    WCHAR temp[MAX_PATH];
    WCHAR program_files[MAX_PATH];
    WCHAR app_data[MAX_PATH];        /* %APPDATA%\XP25 */
    WCHAR local_data[MAX_PATH];      /* %LOCALAPPDATA%\XP25 */
    WCHAR documents[MAX_PATH];
    WCHAR desktop[MAX_PATH];
    char u_windows[MAX_PATH * 3], u_profile[MAX_PATH * 3], u_profiles_root[MAX_PATH * 3];
    char u_temp[MAX_PATH * 3], u_program_files[MAX_PATH * 3], u_secret[MAX_PATH * 3];
    XP25_PATHS policy;               /* points into the u_* fields */
} XP25W_PATHS;

int xp25w_paths(XP25W_PATHS *paths);
/* Long, canonical, absolute form of a user-supplied path (no wildcards). */
int xp25w_full_path(const char *utf8, WCHAR *out, size_t count, char *u_out, size_t u_size);

typedef enum { XP25_PROVIDER_OFFLINE, XP25_PROVIDER_GATEWAY, XP25_PROVIDER_LOCAL, XP25_PROVIDER_OPENAI } XP25_PROVIDER_KIND;

typedef struct {
    XP25_PROVIDER_KIND provider;
    int api;                         /* 0 Responses, 1 Chat Completions */
    char endpoint[260];              /* http://host:port base, e.g. http://10.25.0.1:8443 */
    char model[96];
    char gateway_client[64];
    long timeout_seconds;
    long retries;
    long max_output_tokens;
    char service_allowlist[600];
    char mascot[MAX_PATH * 3];       /* "builtin" or path to an Agent .acs character */
    int ai_query_interpretation;     /* RoverAI may send the query text (never file content) to the provider */
    int content_index;
    char index_roots[1200];          /* ';'-separated; empty = fixed drives */
    char index_excludes[1200];
} XP25_CONFIG;

void xp25w_config_defaults(XP25_CONFIG *config);
int xp25w_config_load(XP25_CONFIG *config);
int xp25w_config_save(const XP25_CONFIG *config);
const char *xp25w_provider_name(XP25_PROVIDER_KIND kind);

/* Per-user protected secrets: user-scope DPAPI (CryptProtectData), or the
   Windows Credential Manager where user DPAPI is unavailable. */
int xp25w_secret_set(const WCHAR *name, const unsigned char *data, DWORD size);
int xp25w_secret_get(const WCHAR *name, unsigned char **data, DWORD *size); /* free with xp25w_secret_free */
void xp25w_secret_free(unsigned char *data, DWORD size);
void xp25w_wipe(void *data, size_t size);
int xp25w_secret_delete(const WCHAR *name);
int xp25w_secret_delete_dpapi(const WCHAR *name);

void xp25w_audit(const char *application, const char *json_line);
int xp25w_is_admin(void);
DWORD xp25w_read_file(const WCHAR *path, char **data, DWORD max_bytes, int *truncated);
int xp25w_write_file_atomic(const WCHAR *path, const void *data, DWORD size);

/* Tool registration: every tool of the shared runtime. */
typedef struct {
    XP25W_PATHS *paths;
    XP25_CONFIG *config;
    XP25_PROVIDER *provider;          /* optional: RoverAI query interpretation */
    unsigned long self_pid;
} XP25W_TOOLS;

int xp25w_register_tools(XP25_REGISTRY *registry, XP25W_TOOLS *context);

/* Network providers. Returns NULL for offline or on configuration error (reason set). */
XP25_PROVIDER *xp25w_provider_create(const XP25_CONFIG *config, char *reason, size_t reason_size);
void xp25w_provider_destroy(XP25_PROVIDER *provider);
/* One-shot request without tools (RoverAI query interpretation). */
int xp25w_provider_ask(XP25_PROVIDER *provider, const char *instructions, const char *question, XP25_REPLY *reply);
#endif
