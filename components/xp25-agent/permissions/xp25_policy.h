/* XP25 AI runtime: fail-closed permission classification. Portable C89.
   Inputs are already-canonical absolute paths/names from native adapters;
   classification never consults model text or tool output. */
#ifndef XP25_POLICY_H
#define XP25_POLICY_H
#include "../runtime/xp25_agent.h"

typedef struct {
    const char *windows;      /* e.g. C:\WINDOWS */
    const char *profile;      /* current user's profile */
    const char *other_profiles_root; /* e.g. C:\Documents and Settings */
    const char *temp;         /* user temp directory */
    const char *program_files;
    const char *secret_store; /* XP25 protected configuration file */
} XP25_PATHS;

/* cmd_execute: READ only for an exact read-only allowlist without shell
   metacharacters, APPROVAL for anything else, DENIED for malformed input. */
XP25_PERM xp25_policy_command(const char *command, char *reason, size_t reason_size);
/* registry_read: READ inside approved locations, DENIED elsewhere. The
   canonical path (HKLM\..., HKCU\...) is written to canonical. */
XP25_PERM xp25_policy_registry(const char *path, char *canonical, size_t canonical_size,
                               char *reason, size_t reason_size);
/* file_operations: op is stat, list, read_text, write_text, copy, move,
   rename, delete, mkdir or clean_temp. */
XP25_PERM xp25_policy_file(const char *op, const char *path, const XP25_PATHS *paths,
                           char *reason, size_t reason_size);
/* Whether a path is sensitive for indexing/reading (credentials, hives,
   other users' profiles, browser caches). */
int xp25_policy_sensitive_path(const char *path, const XP25_PATHS *paths);
/* service_control: allowlisted services only; administrative changes from a
   non-administrator are PRIVILEGED (broker), critical services DENIED. */
XP25_PERM xp25_policy_service(const char *name, const char *action, const char *allowlist,
                              int is_admin, char *reason, size_t reason_size);
/* process_control: never critical system processes or the assistant itself. */
XP25_PERM xp25_policy_process(unsigned long pid, const char *image, const char *action,
                              char *reason, size_t reason_size);
extern const char xp25_default_service_allowlist[];
#endif
