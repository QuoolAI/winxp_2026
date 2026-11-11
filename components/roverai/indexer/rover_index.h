/* RoverAI local file index. Portable C89; the native scanner supplies a
   filesystem table, so incremental, rename and permission behavior is
   exercised on the host as well. Paths are UTF-8 with backslashes. */
#ifndef ROVER_INDEX_H
#define ROVER_INDEX_H
#include "../../xp25-agent/runtime/xp25_base.h"

#define ROVER_ATTR_DIRECTORY 0x10UL
#define ROVER_ATTR_HIDDEN    0x02UL
#define ROVER_ATTR_SYSTEM    0x04UL
#define ROVER_ATTR_REPARSE   0x400UL
#define ROVER_MAX_WORDS 512
#define ROVER_CONTENT_BYTES 32768

typedef struct {
    char *path;
    size_t name;               /* offset of the final component */
    xp25_u64 size;
    unsigned long mtime;       /* seconds since 1970-01-01 UTC */
    unsigned long ctime;
    unsigned long attrs;
    unsigned long *words;      /* sorted distinct content word hashes (text files only) */
    unsigned short word_count;
} ROVER_ENTRY;

typedef struct {
    ROVER_ENTRY *entries;
    size_t count;
    size_t cap;
    int sorted;
    unsigned long built;       /* first full scan */
    unsigned long updated;     /* last change applied */
    unsigned long generation;
} ROVER_INDEX;

typedef struct {
    char *name;
    xp25_u64 size;
    unsigned long mtime, ctime, attrs;
} ROVER_DIRENT;

#define ROVER_FS_OK 0
#define ROVER_FS_DENIED 5
#define ROVER_FS_MISSING 2

typedef struct {
    int (*list)(void *ctx, const char *dir, ROVER_DIRENT **entries, size_t *count);
    int (*stat)(void *ctx, const char *path, ROVER_DIRENT *entry);   /* name not filled */
    /* Optional: up to max bytes of a text file's beginning; returns bytes read. */
    size_t (*read_head)(void *ctx, const char *path, char *buffer, size_t max);
    void (*free_list)(void *ctx, ROVER_DIRENT *entries, size_t count);
    void *ctx;
} ROVER_FS;

typedef struct {
    const char **roots;
    size_t root_count;
    const char **excludes;      /* path prefixes never indexed */
    size_t exclude_count;
    int (*sensitive)(void *ctx, const char *path);   /* built-in privacy rules */
    void *sensitive_ctx;
    size_t max_entries;
    int content;                /* build word filters for small text files */
    int (*cancelled)(void *ctx);
    void *cancel_ctx;
} ROVER_SCAN_CONFIG;

typedef struct {
    unsigned long directories, files, added, updated, removed, denied, excluded, content;
    int truncated;
    int cancelled;
} ROVER_SCAN_STATS;

void rover_index_init(ROVER_INDEX *index);
void rover_index_free(ROVER_INDEX *index);
int rover_path_compare(const char *a, const char *b);
ROVER_ENTRY *rover_index_find(ROVER_INDEX *index, const char *path);
/* Insert or update one entry. Returns 1 added, 2 updated, 3 unchanged, 0 failure. */
int rover_index_upsert(ROVER_INDEX *index, const char *path, const ROVER_DIRENT *meta);
/* Remove a path and, for directories, everything below it. Returns entries removed. */
size_t rover_index_remove(ROVER_INDEX *index, const char *path);
/* Move a path and everything below it to a new location (rename or move). */
size_t rover_index_rename(ROVER_INDEX *index, const char *old_path, const char *new_path);
/* Full or incremental walk: lists every reachable directory, reconciles
   direct children (added/changed/removed) and purges denied or excluded trees. */
int rover_index_scan(ROVER_INDEX *index, const ROVER_FS *fs, const ROVER_SCAN_CONFIG *config,
                     ROVER_SCAN_STATS *stats, unsigned long now);
/* Apply one change notification. action: 1 added, 2 removed, 3 modified,
   4 renamed (old_path -> path). */
int rover_index_apply(ROVER_INDEX *index, const ROVER_FS *fs, const ROVER_SCAN_CONFIG *config,
                      int action, const char *path, const char *old_path, unsigned long now);
int rover_index_excluded(const ROVER_SCAN_CONFIG *config, const char *path);

/* Persistence with a trailing SHA-256 over the content. */
int rover_index_serialize(const ROVER_INDEX *index, XP25_BUF *out);
int rover_index_deserialize(ROVER_INDEX *index, const unsigned char *data, size_t len, char *error, size_t error_size);

/* Content words: lowercase runs of 3-24 letters/digits, hashed with FNV-1a. */
unsigned long rover_word_hash(const char *word, size_t len);
size_t rover_words_from_text(const char *text, size_t len, unsigned long *words, size_t max);
int rover_entry_has_word(const ROVER_ENTRY *entry, const char *word);
int rover_text_extension(const char *name);
#endif
