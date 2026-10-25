/* RoverAI native index store, scanner, change watcher and query execution. */
#ifndef ROVER_WIN_H
#define ROVER_WIN_H
#include "../../xp25-agent/runtime/xp25_win.h"
#include "rover_index.h"
#include "../search/rover_query.h"

#define ROVER_MAX_ROOTS 26
#define ROVER_MAX_EXCLUDES 64

typedef struct {
    char *roots[ROVER_MAX_ROOTS];
    size_t root_count;
    char *excludes[ROVER_MAX_EXCLUDES];
    size_t exclude_count;
    ROVER_SCAN_CONFIG scan;
    XP25W_PATHS *paths;
} ROVER_SETTINGS;

int rover_settings_init(ROVER_SETTINGS *s, const XP25_CONFIG *config, XP25W_PATHS *paths);
void rover_settings_free(ROVER_SETTINGS *s);
void rover_win_fs(ROVER_FS *fs, ROVER_SETTINGS *s);
int rover_store_file(const XP25W_PATHS *paths, WCHAR *out);
int rover_store_load(ROVER_INDEX *index, const XP25W_PATHS *paths, char *error, size_t size);
int rover_store_save(const ROVER_INDEX *index, const XP25W_PATHS *paths);
/* Load the saved index, rescan incrementally when it is older than
   max_age_seconds (0 forces a rescan), save, and return 1 on success. */
int rover_store_refresh(ROVER_INDEX *index, ROVER_SETTINGS *s, unsigned long max_age_seconds, ROVER_SCAN_STATS *stats);

typedef struct ROVER_WATCH ROVER_WATCH;
/* Watch every root with ReadDirectoryChangesW and apply renames, moves,
   deletions and changes to index under lock; saves after quiet periods. */
ROVER_WATCH *rover_watch_start(ROVER_SETTINGS *s, ROVER_INDEX *index, CRITICAL_SECTION *lock);
void rover_watch_stop(ROVER_WATCH *watch);
unsigned long rover_watch_applied(const ROVER_WATCH *watch);

typedef struct {
    char *path;
    size_t name;
    xp25_u64 size;
    unsigned long mtime, attrs;
    long score;
    int content_match;
} ROVER_RESULT;

typedef struct {
    ROVER_CRITERIA criteria;
    ROVER_RESULT *items;
    size_t count;
    size_t total;
    int relaxed;
    int by_ai;
    int live_scan;
    char description[400];
    char note[200];
    unsigned long index_updated;
    size_t index_entries;
} ROVER_RESULTS;

#define ROVER_AI_NEVER 0
#define ROVER_AI_AUTO 1
#define ROVER_AI_ALWAYS 2
int rover_query_run(const char *query, const char *scope, int limit, int ai_mode, XP25_PROVIDER *provider,
                    ROVER_SETTINGS *s, ROVER_RESULTS *results);
void rover_results_free(ROVER_RESULTS *results);
void rover_results_json(const ROVER_RESULTS *results, const char *query, XP25_BUF *out);
#endif
