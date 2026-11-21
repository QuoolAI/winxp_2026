/* MerlinClient.dll: the MerlinAI client library for NT 5.1.

   It owns the local problem queue, configuration and credentials, event
   collection and the authenticated connections to the MerlinAI Builder and
   the host deployment agent. It does not use xp25agent.dll, ClippyAI or
   RoverAI. Exports are __stdcall (MERLINAPI). Strings are UTF-16 at this
   boundary unless a parameter says UTF-8. */
#ifndef MERLIN_CLIENT_H
#define MERLIN_CLIENT_H
#include <windows.h>
#include "../core/merlin_core.h"

#define MERLINAPI WINAPI
#define MERLIN_REG_ROOT L"SOFTWARE\\XP25\\MerlinAI"
#define MERLIN_REG_CREDENTIALS L"SOFTWARE\\XP25\\MerlinAI\\Credentials"
#define MERLIN_REG_SAVED L"SOFTWARE\\XP25\\MerlinAI\\Saved"
#define MERLIN_REG_COLLECTOR L"SOFTWARE\\XP25\\MerlinAI\\Collector"
#define MERLIN_EVENT_SOURCE L"MerlinAI"
#define MERLIN_KEY_BYTES 32

typedef struct {
    WCHAR builder[256];              /* MerlinAI Builder API, e.g. http://10.25.0.1:8740 */
    WCHAR deploy[256];               /* host deployment agent, e.g. http://10.25.0.1:8746 */
    DWORD auto_collect;              /* collect events at logon and while MerlinAI runs */
    DWORD collect_minutes;           /* periodic collection while MerlinAI runs; 0 = off */
    DWORD retention_days;            /* local reports older than this are removed (1..3650) */
    DWORD notify_jobs;               /* show build-job status changes */
    DWORD collect_dumps;             /* write minidumps for crashes (kept locally) */
} MERLIN_CONFIG;

typedef struct {
    char installation[65];
    unsigned char builder_key[MERLIN_KEY_BYTES];
    unsigned char deploy_key[MERLIN_KEY_BYTES];
    int has_builder_key, has_deploy_key;
} MERLIN_IDENTITY;

typedef struct {
    MERLIN_PROBLEM *items;
    int count;
} MERLIN_LIST;

typedef struct {
    unsigned long new_problems, new_occurrences, events_read, crash_reports, winlogon_lines, removed, errors;
} MERLIN_COLLECT_STATS;

typedef struct {
    int status;                      /* HTTP status, 0 when no reply */
    char *body;                      /* NUL-terminated UTF-8, free with MerlinFree */
    DWORD body_len;
    char error[160];                 /* machine code + detail when status is 0 or verification failed */
} MERLIN_REPLY;

/* ---- configuration and identity ---- */
BOOL MERLINAPI MerlinGetConfig(MERLIN_CONFIG *config);
DWORD MERLINAPI MerlinSetConfig(const MERLIN_CONFIG *config);              /* administrators only */
/* Reads the credentials key (readable by SYSTEM and Administrators only). */
DWORD MERLINAPI MerlinGetIdentity(MERLIN_IDENTITY *identity);
/* installation: token; keys: 64 lowercase hex characters, or NULL/empty to keep. */
DWORD MERLINAPI MerlinSetIdentity(const char *installation, const char *builder_key_hex, const char *deploy_key_hex);
BOOL MERLINAPI MerlinIsAdmin(void);

/* ---- queue ---- */
/* C:\Documents and Settings\All Users\Application Data\XP25\MerlinAI\Queue */
BOOL MERLINAPI MerlinQueueDirectory(WCHAR *path, DWORD chars);
/* Problems visible to the caller: every P- record (administrators) and the
   caller's own crash reports not yet merged. Free with MerlinFreeList. */
DWORD MERLINAPI MerlinQueueList(MERLIN_LIST *list);
void MERLINAPI MerlinFreeList(MERLIN_LIST *list);
DWORD MERLINAPI MerlinQueueLoad(const char *id, MERLIN_PROBLEM *problem);
/* Write a problem atomically (temp file + rename). P- records need administrators. */
DWORD MERLINAPI MerlinQueueSave(const MERLIN_PROBLEM *problem);
/* Remove a problem and the crash reports and dumps it references. */
DWORD MERLINAPI MerlinQueueRemove(const char *id);
/* Collect: event logs, the XP25 Winlogon log and crash reports -> P- records.
   Administrators only; returns ERROR_ACCESS_DENIED otherwise. Never transmits. */
DWORD MERLINAPI MerlinCollect(MERLIN_COLLECT_STATS *stats);
/* A fresh crash-report id "C-<16 hex>" (time + random). */
void MERLINAPI MerlinNewReportId(char id[MERLIN_ID_SIZE]);
/* Redact text for preview/transfer with the current account and computer names. */
void MERLINAPI MerlinRedact(char *utf8, DWORD size);
/* Human-readable report text (the preview shown before transmission). */
DWORD MERLINAPI MerlinReportText(const MERLIN_PROBLEM *problem, char *utf8, DWORD size);

/* ---- builder and deployment agent ---- */
/* Authenticated call to the builder (path below /merlin/v1). body may be NULL. */
DWORD MERLINAPI MerlinBuilderCall(const char *method, const char *path, const char *body, DWORD body_len,
                                  const char *content_type, MERLIN_REPLY *reply);
/* Authenticated call to the deployment agent (path below /deploy/v1). */
DWORD MERLINAPI MerlinDeployCall(const char *method, const char *path, const char *body, DWORD body_len, MERLIN_REPLY *reply);
void MERLINAPI MerlinFreeReply(MERLIN_REPLY *reply);
/* Transfer the given problems (with consent recorded in each) to the builder;
   dumps only for problems with dump_consent. Marks them transferred. */
DWORD MERLINAPI MerlinTransfer(const char *const *ids, int count, char *message, DWORD message_size);
/* The installation manifest: image revision and hashes of XP25 components (JSON, UTF-8). */
DWORD MERLINAPI MerlinManifestJson(char *utf8, DWORD size);

/* ---- Control Panel policy (mc_policy.c) ---- */
typedef struct {
    DWORD loaded;          /* hives already loaded (users logged on) */
    DWORD offline;         /* other profiles, loaded with RegLoadKey */
    DWORD default_user;    /* 1 when Default User was done */
    DWORD failed;
    DWORD last_error;
} MERLIN_POLICY_STATS;
/* Hide (apply) or restore the Security Center and Automatic Updates applets in one user hive. */
DWORD MERLINAPI MerlinUserPolicy(HKEY root, BOOL apply);
/* The same for every user hive and Default User (administrators: needs the backup and restore privileges). */
DWORD MERLINAPI MerlinUserPolicyAll(BOOL apply, MERLIN_POLICY_STATS *stats);

/* ---- utilities ---- */
void MERLINAPI MerlinFree(void *p);
void MERLINAPI MerlinLogEvent(WORD type, const WCHAR *text);
BOOL MERLINAPI MerlinUtf8ToWide(const char *in, WCHAR *out, int chars);
BOOL MERLINAPI MerlinWideToUtf8(const WCHAR *in, char *out, int size);
#endif
