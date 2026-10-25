/* RoverAI native index store, scanner, change watcher and query execution. */
#include <windows.h>
#include <string.h>
#include "rover_win.h"

/* ---- settings: roots and privacy exclusions ---- */

static void add_list(char **items, size_t *count, size_t max, const char *value)
{
    char *copy;
    size_t n;
    if (*count >= max || !value || !*value) return;
    copy = xp25_strdup(value);
    if (!copy) return;
    n = strlen(copy);
    while (n > 3 && copy[n - 1] == '\\') copy[--n] = 0;
    items[(*count)++] = copy;
}

static void add_wide(char **items, size_t *count, size_t max, const WCHAR *value, const WCHAR *suffix)
{
    WCHAR path[MAX_PATH * 2];
    char *u;
    if (!value || !value[0] || lstrlenW(value) + (suffix ? lstrlenW(suffix) : 0) >= MAX_PATH * 2) return;
    lstrcpyW(path, value);
    if (suffix) lstrcatW(path, suffix);
    u = xp25w_utf8(path);
    add_list(items, count, max, u);
    xp25_free(u);
}

static void split(char **items, size_t *count, size_t max, const char *list)
{
    char one[MAX_PATH * 3];
    while (list && *list) {
        const char *semi = strchr(list, ';');
        size_t n = semi ? (size_t)(semi - list) : strlen(list);
        if (n && n < sizeof(one)) {
            memcpy(one, list, n);
            one[n] = 0;
            add_list(items, count, max, one);
        }
        list = semi ? semi + 1 : NULL;
    }
}

static int sensitive(void *ctx, const char *path)
{
    ROVER_SETTINGS *s = (ROVER_SETTINGS *)ctx;
    return xp25_policy_sensitive_path(path, &s->paths->policy);
}

int rover_settings_init(ROVER_SETTINGS *s, const XP25_CONFIG *config, XP25W_PATHS *paths)
{
    memset(s, 0, sizeof(*s));
    s->paths = paths;
    split(s->roots, &s->root_count, ROVER_MAX_ROOTS, config->index_roots);
    if (!s->root_count) {
        WCHAR drives[256], *d;
        DWORD n = GetLogicalDriveStringsW(255, drives);
        for (d = drives; n && n < 256 && *d; d += lstrlenW(d) + 1)
            if (GetDriveTypeW(d) == DRIVE_FIXED) add_wide(s->roots, &s->root_count, ROVER_MAX_ROOTS, d, NULL);
    }
    split(s->excludes, &s->exclude_count, ROVER_MAX_EXCLUDES, config->index_excludes);
    add_wide(s->excludes, &s->exclude_count, ROVER_MAX_EXCLUDES, paths->local_data, NULL);
    add_wide(s->excludes, &s->exclude_count, ROVER_MAX_EXCLUDES, paths->app_data, NULL);
    add_wide(s->excludes, &s->exclude_count, ROVER_MAX_EXCLUDES, paths->windows, L"\\Temp");
    add_wide(s->excludes, &s->exclude_count, ROVER_MAX_EXCLUDES, paths->windows, L"\\Prefetch");
    add_wide(s->excludes, &s->exclude_count, ROVER_MAX_EXCLUDES, paths->windows, L"\\system32\\config");
    add_wide(s->excludes, &s->exclude_count, ROVER_MAX_EXCLUDES, paths->windows, L"\\repair");
    s->scan.roots = (const char **)s->roots;
    s->scan.root_count = s->root_count;
    s->scan.excludes = (const char **)s->excludes;
    s->scan.exclude_count = s->exclude_count;
    s->scan.sensitive = sensitive;
    s->scan.sensitive_ctx = s;
    s->scan.max_entries = 400000;
    s->scan.content = config->content_index;
    return s->root_count > 0;
}

void rover_settings_free(ROVER_SETTINGS *s)
{
    size_t i;
    for (i = 0; i < s->root_count; ++i) xp25_free(s->roots[i]);
    for (i = 0; i < s->exclude_count; ++i) xp25_free(s->excludes[i]);
    memset(s, 0, sizeof(*s));
}

/* ---- Win32 filesystem table ---- */

static void fill(ROVER_DIRENT *e, const WIN32_FIND_DATAW *fd)
{
    e->size = ((xp25_u64)fd->nFileSizeHigh << 32) | fd->nFileSizeLow;
    e->mtime = xp25w_unix_time(&fd->ftLastWriteTime);
    e->ctime = xp25w_unix_time(&fd->ftCreationTime);
    e->attrs = fd->dwFileAttributes;
}

static int fs_list(void *ctx, const char *dir, ROVER_DIRENT **entries, size_t *count)
{
    WCHAR *wide = xp25w_wide(dir), *pattern;
    WIN32_FIND_DATAW fd;
    HANDLE find;
    size_t cap = 64, n = 0, len;
    ROVER_DIRENT *list;
    (void)ctx;
    *entries = NULL;
    *count = 0;
    if (!wide) return ROVER_FS_MISSING;
    len = lstrlenW(wide);
    pattern = (WCHAR *)xp25_alloc((len + 3) * sizeof(WCHAR));
    if (!pattern) { xp25_free(wide); return ROVER_FS_MISSING; }
    lstrcpyW(pattern, wide);
    lstrcatW(pattern, len && wide[len - 1] == L'\\' ? L"*" : L"\\*");
    find = FindFirstFileW(pattern, &fd);
    xp25_free(pattern);
    if (find == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError(), attrs = GetFileAttributesW(wide);
        xp25_free(wide);
        if (error == ERROR_ACCESS_DENIED) return ROVER_FS_DENIED;
        if (error == ERROR_FILE_NOT_FOUND && attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) return ROVER_FS_OK;
        return ROVER_FS_MISSING;
    }
    xp25_free(wide);
    list = (ROVER_DIRENT *)xp25_alloc(cap * sizeof(ROVER_DIRENT));
    do {
        if (!list) break;
        if (!lstrcmpW(fd.cFileName, L".") || !lstrcmpW(fd.cFileName, L"..")) continue;
        if (n == cap) {
            ROVER_DIRENT *bigger = (ROVER_DIRENT *)xp25_realloc(list, cap * 2 * sizeof(ROVER_DIRENT));
            if (!bigger) break;
            list = bigger;
            cap *= 2;
        }
        memset(&list[n], 0, sizeof(ROVER_DIRENT));
        list[n].name = xp25w_utf8(fd.cFileName);
        if (!list[n].name) continue;
        fill(&list[n], &fd);
        ++n;
    } while (FindNextFileW(find, &fd));
    FindClose(find);
    *entries = list;
    *count = n;
    return ROVER_FS_OK;
}

static int fs_stat(void *ctx, const char *path, ROVER_DIRENT *e)
{
    WCHAR *wide = xp25w_wide(path);
    WIN32_FILE_ATTRIBUTE_DATA a;
    int ok;
    (void)ctx;
    memset(&a, 0, sizeof(a));
    ok = wide && GetFileAttributesExW(wide, GetFileExInfoStandard, &a);
    xp25_free(wide);
    if (!ok) return GetLastError() == ERROR_ACCESS_DENIED ? ROVER_FS_DENIED : ROVER_FS_MISSING;
    e->size = ((xp25_u64)a.nFileSizeHigh << 32) | a.nFileSizeLow;
    e->mtime = xp25w_unix_time(&a.ftLastWriteTime);
    e->ctime = xp25w_unix_time(&a.ftCreationTime);
    e->attrs = a.dwFileAttributes;
    return ROVER_FS_OK;
}

static size_t fs_head(void *ctx, const char *path, char *buffer, size_t max)
{
    ROVER_SETTINGS *s = (ROVER_SETTINGS *)ctx;
    WCHAR *wide;
    HANDLE h;
    DWORD got = 0;
    char all_users[MAX_PATH * 3];
    /* Content words are collected only from the user's own and shared documents. */
    lstrcpynA(all_users, s->paths->u_profiles_root, sizeof(all_users) - 12);
    lstrcatA(all_users, "\\All Users\\");
    if (!xp25_starts_with_i(path, s->paths->u_profile) && !xp25_starts_with_i(path, all_users)) return 0;
    wide = xp25w_wide(path);
    if (!wide) return 0;
    h = CreateFileW(wide, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                    FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    xp25_free(wide);
    if (h == INVALID_HANDLE_VALUE) return 0;
    if (!ReadFile(h, buffer, (DWORD)max, &got, NULL)) got = 0;
    CloseHandle(h);
    return got;
}

static void fs_free(void *ctx, ROVER_DIRENT *entries, size_t count)
{
    size_t i;
    (void)ctx;
    for (i = 0; i < count; ++i) xp25_free(entries[i].name);
    xp25_free(entries);
}

void rover_win_fs(ROVER_FS *fs, ROVER_SETTINGS *s)
{
    fs->list = fs_list;
    fs->stat = fs_stat;
    fs->read_head = fs_head;
    fs->free_list = fs_free;
    fs->ctx = s;
}

/* ---- persistence ---- */

int rover_store_file(const XP25W_PATHS *paths, WCHAR *out)
{
    if (!paths->local_data[0] || lstrlenW(paths->local_data) > MAX_PATH - 24) return 0;
    lstrcpyW(out, paths->local_data);
    lstrcatW(out, L"\\RoverAI");
    CreateDirectoryW(out, NULL);
    lstrcatW(out, L"\\index.dat");
    return 1;
}

int rover_store_load(ROVER_INDEX *index, const XP25W_PATHS *paths, char *error, size_t size)
{
    WCHAR file[MAX_PATH];
    char *data;
    DWORD n;
    int truncated, ok;
    if (error && size) error[0] = 0;
    if (!rover_store_file(paths, file)) return 0;
    n = xp25w_read_file(file, &data, 256 * 1024 * 1024, &truncated);
    if (n == (DWORD)-1) { if (error) lstrcpynA(error, "no saved index", (int)size); return 0; }
    ok = !truncated && rover_index_deserialize(index, (const unsigned char *)data, n, error, size);
    xp25_free(data);
    return ok;
}

int rover_store_save(const ROVER_INDEX *index, const XP25W_PATHS *paths)
{
    WCHAR file[MAX_PATH];
    XP25_BUF data;
    int ok;
    if (!rover_store_file(paths, file)) return 0;
    xp25_buf_init(&data);
    ok = rover_index_serialize(index, &data) && xp25w_write_file_atomic(file, data.data, (DWORD)data.len);
    xp25_buf_free(&data);
    return ok;
}

/* Exists while a background indexer has a change notification open on every
   root (see rover_watch_start). */
#define WATCHING_EVENT L"Local\\XP25RoverAIWatching"
#define STORE_MUTEX L"Local\\XP25RoverAIIndex"
#define STORE_WAIT_LONG 600000

/* A watched index is kept current by change notifications, so its age alone
   is no reason for a full rescan. */
static int index_watched(void)
{
    HANDLE h = OpenEventW(SYNCHRONIZE, FALSE, WATCHING_EVENT);
    if (!h) return 0;
    CloseHandle(h);
    return 1;
}

static int saved_index_exists(const XP25W_PATHS *paths)
{
    WCHAR file[MAX_PATH];
    return rover_store_file(paths, file) && GetFileAttributesW(file) != INVALID_FILE_ATTRIBUTES;
}

/* Load the saved index; rescan and save when it is missing, forced
   (max_age_seconds 0) or older than max_age_seconds (unless trust_watch and a
   background indexer watches every root). Scanning and saving happen only
   while holding the store mutex: without it, a scan could save a listing
   older than the owner's save. lock, when given, guards index against
   watcher threads and is always taken after the store mutex. */
static int refresh(ROVER_INDEX *index, ROVER_SETTINGS *s, unsigned long max_age_seconds, DWORD wait_ms,
                   int trust_watch, CRITICAL_SECTION *lock, ROVER_SCAN_STATS *stats)
{
    HANDLE mutex = CreateMutexW(NULL, FALSE, STORE_MUTEX);
    DWORD wait = mutex ? WaitForSingleObject(mutex, wait_ms) : WAIT_FAILED;
    int owned, ok = 1;
    ROVER_FS fs;
    char error[96];
    unsigned long now = xp25w_now();
    if (wait == WAIT_TIMEOUT && wait_ms < STORE_WAIT_LONG && !saved_index_exists(s->paths))
        wait = WaitForSingleObject(mutex, STORE_WAIT_LONG);   /* the first index is being built elsewhere */
    owned = wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED;
    memset(stats, 0, sizeof(*stats));
    if (lock) EnterCriticalSection(lock);
    rover_index_free(index);
    rover_store_load(index, s->paths, error, sizeof(error));
    if (!owned) {
        ok = index->count > 0;    /* the last saved index; the store's owner is updating it */
    } else if (!max_age_seconds || !index->count ||
               ((now - index->updated >= max_age_seconds || now < index->updated) && !(trust_watch && index_watched()))) {
        rover_win_fs(&fs, s);
        ok = rover_index_scan(index, &fs, &s->scan, stats, now);
        if (ok && !stats->cancelled) ok = rover_store_save(index, s->paths);
    }
    if (lock) LeaveCriticalSection(lock);
    if (owned) ReleaseMutex(mutex);
    if (mutex) CloseHandle(mutex);
    return ok;
}

int rover_store_refresh(ROVER_INDEX *index, ROVER_SETTINGS *s, unsigned long max_age_seconds, ROVER_SCAN_STATS *stats)
{
    /* A search waits briefly for a busy store; a forced rebuild waits for it. */
    return refresh(index, s, max_age_seconds, max_age_seconds ? 2000 : STORE_WAIT_LONG, 1, NULL, stats);
}

int rover_store_reconcile(ROVER_INDEX *index, ROVER_SETTINGS *s, CRITICAL_SECTION *lock, unsigned long max_age_seconds,
                          ROVER_SCAN_STATS *stats)
{
    return refresh(index, s, max_age_seconds, STORE_WAIT_LONG, 0, lock, stats);
}

/* ---- change watcher ---- */

typedef struct {
    struct ROVER_WATCH *owner;
    char root[MAX_PATH * 3];
    HANDLE thread;
} WATCH_ROOT;

struct ROVER_WATCH {
    ROVER_SETTINGS *settings;
    ROVER_INDEX *index;
    CRITICAL_SECTION *lock;
    HANDLE stop;
    WATCH_ROOT roots[ROVER_MAX_ROOTS];
    size_t count;
    volatile LONG applied;
    volatile LONG dirty;
    volatile DWORD dirty_since;
    volatile LONG watching;   /* roots with an open change notification (interlocked) */
    HANDLE live;              /* WATCHING_EVENT while every root is watched (under lock) */
};

/* A root is no longer watched: searches judge the saved index by its age again. */
static void unadvertise(struct ROVER_WATCH *w)
{
    HANDLE h;
    EnterCriticalSection(w->lock);
    h = w->live;
    w->live = NULL;
    LeaveCriticalSection(w->lock);
    if (h) CloseHandle(h);
}

/* Saves under the store mutex shared with rover_store_refresh; the index
   stays dirty (and is retried) until a save actually succeeds. */
static void save_now(struct ROVER_WATCH *w)
{
    XP25_BUF data;
    WCHAR file[MAX_PATH];
    HANDLE mutex = CreateMutexW(NULL, FALSE, STORE_MUTEX);
    DWORD wait = mutex ? WaitForSingleObject(mutex, 30000) : WAIT_FAILED;
    int saved = 0;
    if (wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED) {
        xp25_buf_init(&data);
        EnterCriticalSection(w->lock);
        rover_index_serialize(w->index, &data);
        InterlockedExchange(&w->dirty, 0);
        LeaveCriticalSection(w->lock);
        saved = xp25_buf_ok(&data) && rover_store_file(w->settings->paths, file) &&
                xp25w_write_file_atomic(file, data.data, (DWORD)data.len);
        xp25_buf_free(&data);
        ReleaseMutex(mutex);
    }
    if (mutex) CloseHandle(mutex);
    if (!saved && !InterlockedExchange(&w->dirty, 1)) w->dirty_since = GetTickCount();
}

static void apply_one(struct ROVER_WATCH *w, const char *root, const WCHAR *name, DWORD bytes, int action, char *old_path)
{
    WCHAR rel[MAX_PATH];
    char path[MAX_PATH * 4], *u;
    ROVER_FS fs;
    size_t n = bytes / sizeof(WCHAR);
    if (n >= MAX_PATH) return;
    memcpy(rel, name, n * sizeof(WCHAR));
    rel[n] = 0;
    u = xp25w_utf8(rel);
    if (!u) return;
    lstrcpynA(path, root, MAX_PATH * 3);
    if (path[0] && path[lstrlenA(path) - 1] != '\\') lstrcatA(path, "\\");
    if (lstrlenA(path) + lstrlenA(u) < (int)sizeof(path)) lstrcatA(path, u);
    xp25_free(u);
    if (action == FILE_ACTION_RENAMED_OLD_NAME) { lstrcpynA(old_path, path, MAX_PATH * 4); return; }
    if (rover_index_excluded(&w->settings->scan, path) && !(action == FILE_ACTION_RENAMED_NEW_NAME && old_path[0])) return;
    rover_win_fs(&fs, w->settings);
    EnterCriticalSection(w->lock);
    if (action == FILE_ACTION_RENAMED_NEW_NAME && old_path[0])
        rover_index_apply(w->index, &fs, &w->settings->scan, 4, path, old_path, xp25w_now());
    else
        rover_index_apply(w->index, &fs, &w->settings->scan, action == FILE_ACTION_ADDED ? 1 :
                          action == FILE_ACTION_REMOVED ? 2 : 3, path, NULL, xp25w_now());
    LeaveCriticalSection(w->lock);
    old_path[0] = 0;
    InterlockedIncrement(&w->applied);
    if (!InterlockedExchange(&w->dirty, 1)) w->dirty_since = GetTickCount();
}

static DWORD WINAPI watch_thread(void *param)
{
    WATCH_ROOT *r = (WATCH_ROOT *)param;
    struct ROVER_WATCH *w = r->owner;
    WCHAR *wide = xp25w_wide(r->root);
    HANDLE dir, events[2];
    OVERLAPPED ov;
    DWORD *buffer = (DWORD *)xp25_alloc(64 * 1024);
    char *old_path = (char *)xp25_alloc(MAX_PATH * 4);
    DWORD last_change = 0;
    int pending = 0;
    if (!wide || !buffer || !old_path) goto done;
    dir = CreateFileW(wide, FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
    if (dir == INVALID_HANDLE_VALUE) goto done;
    InterlockedIncrement(&w->watching);
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    events[0] = w->stop;
    events[1] = ov.hEvent;
    for (;;) {
        DWORD wait, got = 0;
        if (!pending) {
            ResetEvent(ov.hEvent);
            if (!ReadDirectoryChangesW(dir, buffer, 64 * 1024, TRUE,
                                       FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_SIZE |
                                       FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_CREATION, NULL, &ov, NULL)) break;
            pending = 1;
        }
        wait = WaitForMultipleObjects(2, events, FALSE, 2000);
        if (wait == WAIT_OBJECT_0) { CancelIo(dir); break; }
        if (w->dirty && (GetTickCount() - last_change > 3000 || GetTickCount() - w->dirty_since > 10000)) save_now(w);
        if (wait == WAIT_TIMEOUT) continue;
        pending = 0;
        if (!GetOverlappedResult(dir, &ov, &got, FALSE)) continue;
        last_change = GetTickCount();
        if (!got) {
            /* The change buffer overflowed: reconcile this root fully. */
            ROVER_FS fs;
            ROVER_SCAN_CONFIG one = w->settings->scan;
            ROVER_SCAN_STATS stats;
            const char *root = r->root;
            one.roots = &root;
            one.root_count = 1;
            rover_win_fs(&fs, w->settings);
            EnterCriticalSection(w->lock);
            rover_index_scan(w->index, &fs, &one, &stats, xp25w_now());
            LeaveCriticalSection(w->lock);
            InterlockedExchange(&w->dirty, 1);
            continue;
        }
        {
            BYTE *p = (BYTE *)buffer;
            for (;;) {
                FILE_NOTIFY_INFORMATION *info = (FILE_NOTIFY_INFORMATION *)p;
                apply_one(w, r->root, info->FileName, info->FileNameLength, (int)info->Action, old_path);
                if (!info->NextEntryOffset) break;
                p += info->NextEntryOffset;
            }
        }
    }
    CloseHandle(ov.hEvent);
    CloseHandle(dir);
    InterlockedDecrement(&w->watching);
    unadvertise(w);
done:
    xp25_free(wide);
    xp25_free(buffer);
    xp25_free(old_path);
    return 0;
}

ROVER_WATCH *rover_watch_start(ROVER_SETTINGS *s, ROVER_INDEX *index, CRITICAL_SECTION *lock)
{
    struct ROVER_WATCH *w = (struct ROVER_WATCH *)xp25_alloc(sizeof(*w));
    size_t i;
    DWORD id;
    if (!w) return NULL;
    w->settings = s;
    w->index = index;
    w->lock = lock;
    w->stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    for (i = 0; i < s->root_count; ++i) {
        WATCH_ROOT *r = &w->roots[w->count];
        r->owner = w;
        lstrcpynA(r->root, s->roots[i], sizeof(r->root));
        r->thread = CreateThread(NULL, 0, watch_thread, r, 0, &id);
        if (r->thread) ++w->count;
    }
    /* Advertise only once every root has an open change notification. */
    for (i = 0; i < 50 && w->count == s->root_count && w->watching < (LONG)s->root_count; ++i) Sleep(100);
    EnterCriticalSection(lock);
    if (w->count == s->root_count && w->watching == (LONG)s->root_count)
        w->live = CreateEventW(NULL, TRUE, FALSE, WATCHING_EVENT);
    LeaveCriticalSection(lock);
    return w;
}

void rover_watch_stop(ROVER_WATCH *w)
{
    size_t i;
    if (!w) return;
    SetEvent(w->stop);
    for (i = 0; i < w->count; ++i) {
        WaitForSingleObject(w->roots[i].thread, 10000);
        CloseHandle(w->roots[i].thread);
    }
    unadvertise(w);
    if (w->dirty) save_now(w);
    CloseHandle(w->stop);
    xp25_free(w);
}

unsigned long rover_watch_applied(const ROVER_WATCH *w) { return w ? (unsigned long)w->applied : 0; }

/* ---- query execution ---- */

static int interpret(XP25_PROVIDER *provider, const char *query, unsigned long now, long bias, ROVER_CRITERIA *c,
                     char *note, size_t note_size)
{
    XP25_REPLY reply;
    XP25_JDOC doc;
    const char *text, *start, *end;
    char error[96];
    int ok = 0;
    memset(&reply, 0, sizeof(reply));
    if (!xp25w_provider_ask(provider, rover_criteria_instructions, query, &reply) || !reply.text) {
        lstrcpynA(note, "AI interpretation unavailable; used the local interpreter.", (int)note_size);
        xp25_reply_free(&reply);
        return 0;
    }
    text = reply.text;
    start = strchr(text, '{');
    end = strrchr(text, '}');
    if (start && end && end > start && xp25_json_parse(&doc, start, (size_t)(end - start + 1))) {
        ok = rover_criteria_from_json(doc.root, now, bias, c, error, sizeof(error));
        xp25_json_free(&doc);
    } else xp25_json_free(&doc);
    if (!ok) lstrcpynA(note, "The AI interpretation was not valid criteria; used the local interpreter.", (int)note_size);
    xp25_reply_free(&reply);
    return ok;
}

static int under_roots(ROVER_SETTINGS *s, const char *path)
{
    size_t i;
    for (i = 0; i < s->root_count; ++i) {
        size_t n = strlen(s->roots[i]);
        if (xp25_strnieq(path, s->roots[i], n) && (path[n] == '\\' || path[n] == 0 || s->roots[i][n - 1] == '\\')) return 1;
    }
    return 0;
}

int rover_query_run(const char *query, const char *scope, int limit, int ai_mode, XP25_PROVIDER *provider,
                    ROVER_SETTINGS *s, ROVER_RESULTS *r)
{
    unsigned long now = xp25w_now();
    long bias = xp25w_bias_minutes();
    ROVER_INDEX index;
    ROVER_SCAN_STATS stats;
    ROVER_HIT *hits;
    char scope_u[MAX_PATH * 3];
    WCHAR scope_w[MAX_PATH];
    const char *prefix = NULL;
    size_t i, n;
    XP25_BUF desc;
    int ok;
    memset(r, 0, sizeof(*r));
    rover_query_parse(query, now, bias, &r->criteria);
    if (provider && (ai_mode == ROVER_AI_ALWAYS ||
                     (ai_mode == ROVER_AI_AUTO && !r->criteria.recognized && r->criteria.term_count >= 3))) {
        ROVER_CRITERIA ai;
        if (interpret(provider, query, now, bias, &ai, r->note, sizeof(r->note))) { r->criteria = ai; r->by_ai = 1; }
    }
    if (limit > 0) r->criteria.limit = limit;
    lstrcpynA(r->criteria.home, s->paths->u_profile, sizeof(r->criteria.home));
    rover_index_init(&index);
    if (scope && *scope && !xp25_strieq(scope, "computer")) {
        if (!xp25w_full_path(scope, scope_w, MAX_PATH, scope_u, sizeof(scope_u))) {
            lstrcpynA(r->note, "The search folder is not a valid local path.", sizeof(r->note));
            return 0;
        }
        prefix = scope_u;
    }
    if (prefix && !under_roots(s, prefix)) {
        /* Folder outside the indexed locations: scan just that folder now. */
        ROVER_FS fs;
        ROVER_SCAN_CONFIG one = s->scan;
        one.roots = &prefix;
        one.root_count = 1;
        one.max_entries = 50000;
        rover_win_fs(&fs, s);
        ok = rover_index_scan(&index, &fs, &one, &stats, now);
        r->live_scan = 1;
    } else ok = rover_store_refresh(&index, s, 600, &stats);
    if (!ok) { rover_index_free(&index); lstrcpynA(r->note, "The file index could not be read or built.", sizeof(r->note)); return 0; }
    r->index_updated = index.updated;
    r->index_entries = index.count;
    hits = (ROVER_HIT *)xp25_alloc(500 * sizeof(ROVER_HIT));
    if (!hits) { rover_index_free(&index); return 0; }
    n = rover_search(&index, &r->criteria, prefix, hits, 500, &r->total, &r->relaxed);
    r->items = (ROVER_RESULT *)xp25_alloc((n ? n : 1) * sizeof(ROVER_RESULT));
    for (i = 0; r->items && i < n; ++i) {
        ROVER_RESULT *item = &r->items[r->count];
        item->path = xp25_strdup(hits[i].entry->path);
        if (!item->path) continue;
        item->name = hits[i].entry->name;
        item->size = hits[i].entry->size;
        item->mtime = hits[i].entry->mtime;
        item->attrs = hits[i].entry->attrs;
        item->score = hits[i].score;
        item->content_match = hits[i].content_match;
        ++r->count;
    }
    xp25_free(hits);
    rover_index_free(&index);
    xp25_buf_init(&desc);
    rover_criteria_describe(&r->criteria, bias, &desc);
    lstrcpynA(r->description, xp25_buf_cstr(&desc), sizeof(r->description));
    xp25_buf_free(&desc);
    return 1;
}

void rover_results_free(ROVER_RESULTS *r)
{
    size_t i;
    for (i = 0; i < r->count; ++i) xp25_free(r->items[i].path);
    xp25_free(r->items);
    memset(r, 0, sizeof(*r));
}

void rover_results_json(const ROVER_RESULTS *r, const char *query, XP25_BUF *out)
{
    XP25_JW w;
    size_t i;
    long bias = xp25w_bias_minutes();
    char stamp[20];
    xp25_buf_reset(out);
    xp25_jw_init(&w, out);
    xp25_jw_obj(&w);
    xp25_jw_key(&w, "ok"); xp25_jw_bool(&w, 1);
    xp25_jw_key(&w, "query"); xp25_jw_str(&w, query);
    xp25_jw_key(&w, "description"); xp25_jw_str(&w, r->description);
    xp25_jw_key(&w, "interpretation"); xp25_jw_str(&w, r->by_ai ? "ai" : "local");
    xp25_jw_key(&w, "criteria"); rover_criteria_json(&r->criteria, bias, &w);
    xp25_jw_key(&w, "total"); xp25_jw_u64(&w, (xp25_u64)r->total);
    xp25_jw_key(&w, "relaxed"); xp25_jw_bool(&w, r->relaxed);
    xp25_jw_key(&w, "live_scan"); xp25_jw_bool(&w, r->live_scan);
    if (r->note[0]) { xp25_jw_key(&w, "note"); xp25_jw_str(&w, r->note); }
    xp25_jw_key(&w, "results");
    xp25_jw_arr(&w);
    for (i = 0; i < r->count; ++i) {
        const ROVER_RESULT *item = &r->items[i];
        int directory = (item->attrs & ROVER_ATTR_DIRECTORY) != 0;
        rover_format_local(item->mtime, bias, stamp);
        xp25_jw_obj(&w);
        xp25_jw_key(&w, "path"); xp25_jw_str(&w, item->path);
        xp25_jw_key(&w, "name"); xp25_jw_str(&w, item->path + item->name);
        xp25_jw_key(&w, "directory"); xp25_jw_bool(&w, directory);
        xp25_jw_key(&w, "size"); xp25_jw_u64(&w, item->size);
        xp25_jw_key(&w, "modified"); xp25_jw_str(&w, stamp);
        xp25_jw_key(&w, "type"); xp25_jw_str(&w, rover_type_name(item->path + item->name, directory));
        if (item->content_match) { xp25_jw_key(&w, "content_match"); xp25_jw_bool(&w, 1); }
        xp25_jw_end(&w);
    }
    xp25_jw_end(&w);
    rover_format_local(r->index_updated, bias, stamp);
    xp25_jw_key(&w, "index");
    xp25_jw_obj(&w);
    xp25_jw_key(&w, "entries"); xp25_jw_u64(&w, (xp25_u64)r->index_entries);
    xp25_jw_key(&w, "updated"); xp25_jw_str(&w, stamp);
    xp25_jw_end(&w);
    xp25_jw_end(&w);
}
