/* XP25 security baseline and audit: native NT 5.1 helpers shared by
   XP25Sec.exe and XP25Audit.exe. Strings cross this boundary as UTF-8. */
#ifndef XP25_SEC_WIN_H
#define XP25_SEC_WIN_H
#ifndef WINVER
#define WINVER 0x0501
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <lm.h>
#include <ntsecapi.h>
#include <tlhelp32.h>
#include "sec_core.h"

#define SECW_STORE_KEY L"SOFTWARE\\XP25\\Security"
#define SECW_BASELINE_KEY L"SOFTWARE\\XP25\\Security\\Baseline"
#define SECW_LINE 6144

/* Where records go: an optional file, COM1 when requested, and standard output. */
typedef struct {
    HANDLE file, serial, console;
    unsigned long lines, dropped;
} SECW_SINK;

/* Common command-line options: --out <file>, --serial, --quiet. Returns
   FALSE (after writing the error to standard error) for a bad option. */
BOOL secw_sink_open(SECW_SINK *sink, int argc, WCHAR **argv, int first);
void secw_sink_close(SECW_SINK *sink);
/* Finishes the JSON object and writes it as one line; a record that does
   not fit is counted in dropped, never written truncated. */
void secw_emit(SECW_SINK *sink, SEC_JSON *json);

/* Splits the process command line (CommandLineToArgvW rules). Caller owns nothing. */
WCHAR **secw_arguments(int *count);
void secw_utf8(const WCHAR *wide, char *out, int size);
void secw_wide(const char *utf8, WCHAR *out, int count);
void secw_error_text(const char *what, DWORD error);

BOOL secw_is_admin(void);
BOOL secw_enable_privilege(const WCHAR *name);
/* DOMAIN\name, or the SID string when the account cannot be resolved. */
void secw_account(PSID sid, char *out, int size);
void secw_sid_string(PSID sid, char *out, int size);
void secw_utc_now(char *out, int size);                 /* 2026-11-11T12:00:00Z */
void secw_filetime_text(const FILETIME *time, char *out, int size);

/* The protected XP25 security store: %SystemRoot%\XP25\Security and
   HKLM\SOFTWARE\XP25\Security, owned by Administrators, writable by
   Administrators and SYSTEM only, readable by Users. */
BOOL secw_store_path(const WCHAR *name, WCHAR *out, int count);
/* Creates the directory and key if needed and (re)applies owner and
   protected access control. Administrators only. */
DWORD secw_store_prepare(void);

/* Access-control inspection: which unprivileged principals hold write-like
   access in an object's DACL. */
#define SECW_WHO_EVERYONE 0x01u
#define SECW_WHO_USERS 0x02u
#define SECW_WHO_AUTHENTICATED 0x04u
#define SECW_WHO_INTERACTIVE 0x08u
#define SECW_WHO_GUESTS 0x10u
#define SECW_WHO_ANONYMOUS 0x20u
#define SECW_WHO_POWER_USERS 0x40u
#define SECW_WHO_NULL_DACL 0x80u
#define SECW_WHO_UNPRIVILEGED 0xbfu     /* everything except Power Users */
#define SECW_WHO_INDIVIDUAL 0x100u      /* a named account: a restricted token of that account keeps the access */
#define SECW_OWNER_NOT_SYSTEM 0x200u    /* owner is neither SYSTEM nor Administrators and may rewrite the DACL */
#define SECW_EXPOSED (SECW_WHO_UNPRIVILEGED | SECW_WHO_INDIVIDUAL | SECW_OWNER_NOT_SYSTEM)
/* write_mask is the object-specific set of rights that count as modification. */
unsigned secw_dacl_writers(PACL dacl, BOOL present, DWORD write_mask);
DWORD secw_object_writers(const WCHAR *name, SE_OBJECT_TYPE type, DWORD write_mask, unsigned *who);
void secw_who_text(unsigned who, char *out, int size);
/* Like secw_object_writers, and also reports individual-account access and ownership. */
DWORD secw_object_exposure(const WCHAR *name, SE_OBJECT_TYPE type, DWORD write_mask, unsigned *exposure);
/* Owner and DACL as SDDL text. */
DWORD secw_sddl_get(const WCHAR *name, SE_OBJECT_TYPE type, char *sddl, int size);
/* Applies the owner and DACL of an SDDL string; the DACL is protected exactly when the string says so. */
DWORD secw_sddl_set(const WCHAR *name, SE_OBJECT_TYPE type, const char *sddl);
/* Makes Administrators the owner and replaces the DACL by inheritance from the parent alone. */
DWORD secw_inherit_only(const WCHAR *name, SE_OBJECT_TYPE type);
/* Calls visit for every file and directory below a directory (not the directory
   itself), depth first, never through a reparse point. Returns the first error. */
typedef DWORD (*SECW_VISIT)(const WCHAR *path, BOOL directory, void *context);
DWORD secw_walk_files(const WCHAR *directory, BOOL recursive, SECW_VISIT visit, void *context);
/* Calls visit with "MACHINE\<key>" for every subkey below a key of HKEY_LOCAL_MACHINE. */
DWORD secw_walk_keys(const WCHAR *key, SECW_VISIT visit, void *context);

#define SECW_FILE_WRITE (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | \
                         DELETE | WRITE_DAC | WRITE_OWNER | FILE_DELETE_CHILD)
#define SECW_KEY_WRITE (KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK | DELETE | WRITE_DAC | WRITE_OWNER)
#define SECW_SERVICE_WRITE (SERVICE_CHANGE_CONFIG | DELETE | WRITE_DAC | WRITE_OWNER)

/* Registry helpers below HKEY_LOCAL_MACHINE (or the given root). */
DWORD secw_reg_read(HKEY root, const char *key, const char *value, DWORD *type, BYTE *data, DWORD *size);
BOOL secw_reg_string(HKEY root, const char *key, const char *value, char *out, int size);
BOOL secw_reg_dword(HKEY root, const char *key, const char *value, DWORD *out);

/* Opens a key below HKEY_LOCAL_MACHINE for writing, creating missing levels owned
   by the Administrators group: a key created under the caller's default owner
   could be re-secured by a restricted process of the same account. */
DWORD secw_reg_create(const WCHAR *key, HKEY *handle);

/* Whether an observed value satisfies a baseline rule, and its text form. */
BOOL secw_registry_matches(const SEC_REGISTRY_RULE *rule, unsigned present, DWORD type, const BYTE *data, DWORD size);
void secw_registry_describe(char *text, int text_size, unsigned present, DWORD type, const BYTE *data, DWORD size);
/* Reads the rule's value and reports compliance; FALSE with *error set when it cannot be read. */
BOOL secw_registry_rule_state(const SEC_REGISTRY_RULE *rule, char *current, int current_size, DWORD *error);

/* Expanded C:\WINDOWS and C:\Program Files as UTF-8. */
void secw_directories(char *windows, int windows_size, char *programs, int programs_size);
#endif
