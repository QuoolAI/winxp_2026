/* RoverAI local file index: sorted entries, incremental reconciliation and
   checked persistence. Portable C89. */
#include <stdlib.h>
#include <string.h>
#include "rover_index.h"
#include "../../xp25-agent/llm/xp25_sha256.h"

#define DEAD 0x80000000UL

void rover_index_init(ROVER_INDEX *index) { memset(index, 0, sizeof(*index)); index->sorted = 1; }

static void entry_free(ROVER_ENTRY *e)
{
    xp25_free(e->path);
    xp25_free(e->words);
    e->path = NULL;
    e->words = NULL;
    e->word_count = 0;
}

void rover_index_free(ROVER_INDEX *index)
{
    size_t i;
    for (i = 0; i < index->count; ++i) entry_free(&index->entries[i]);
    xp25_free(index->entries);
    rover_index_init(index);
}

int rover_path_compare(const char *a, const char *b)
{
    for (;; ++a, ++b) {
        int x = xp25_lower((unsigned char)*a), y = xp25_lower((unsigned char)*b);
        if (x != y || !x) return x - y;
    }
}

static int XP25_CDECL entry_compare(const void *a, const void *b)
{
    return rover_path_compare(((const ROVER_ENTRY *)a)->path, ((const ROVER_ENTRY *)b)->path);
}

static size_t lower_bound(const ROVER_INDEX *index, const char *path)
{
    size_t lo = 0, hi = index->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (rover_path_compare(index->entries[mid].path, path) < 0) lo = mid + 1;
        else hi = mid;
    }
    return lo;
}

static size_t name_offset(const char *path)
{
    const char *slash = strrchr(path, '\\');
    return slash && slash[1] ? (size_t)(slash - path + 1) : 0;
}

ROVER_ENTRY *rover_index_find(ROVER_INDEX *index, const char *path)
{
    size_t at = lower_bound(index, path);
    if (at < index->count && !rover_path_compare(index->entries[at].path, path) &&
        !(index->entries[at].attrs & DEAD)) return &index->entries[at];
    return NULL;
}

static int grow(ROVER_ENTRY **entries, size_t *cap, size_t need)
{
    size_t next;
    ROVER_ENTRY *bigger;
    if (need <= *cap) return 1;
    next = *cap ? *cap * 2 : 256;
    while (next < need) next *= 2;
    bigger = (ROVER_ENTRY *)xp25_realloc(*entries, next * sizeof(ROVER_ENTRY));
    if (!bigger) return 0;
    *entries = bigger;
    *cap = next;
    return 1;
}

static int same_meta(const ROVER_ENTRY *e, const ROVER_DIRENT *m)
{
    return e->size == m->size && e->mtime == m->mtime && e->ctime == m->ctime && e->attrs == m->attrs;
}

static void set_meta(ROVER_ENTRY *e, const ROVER_DIRENT *m)
{
    e->size = m->size;
    e->mtime = m->mtime;
    e->ctime = m->ctime;
    e->attrs = m->attrs & ~DEAD;
}

int rover_index_upsert(ROVER_INDEX *index, const char *path, const ROVER_DIRENT *meta)
{
    size_t at = lower_bound(index, path);
    ROVER_ENTRY *e;
    if (at < index->count && !rover_path_compare(index->entries[at].path, path)) {
        e = &index->entries[at];
        if (!(e->attrs & DEAD) && same_meta(e, meta)) return 3;
        set_meta(e, meta);
        xp25_free(e->words);
        e->words = NULL;
        e->word_count = 0;
        return 2;
    }
    if (!grow(&index->entries, &index->cap, index->count + 1)) return 0;
    memmove(&index->entries[at + 1], &index->entries[at], (index->count - at) * sizeof(ROVER_ENTRY));
    e = &index->entries[at];
    memset(e, 0, sizeof(*e));
    e->path = xp25_strdup(path);
    if (!e->path) {
        memmove(&index->entries[at], &index->entries[at + 1], (index->count - at) * sizeof(ROVER_ENTRY));
        return 0;
    }
    e->name = name_offset(e->path);
    set_meta(e, meta);
    ++index->count;
    return 1;
}

static char *child_prefix(const char *dir)
{
    size_t n = strlen(dir);
    char *p = (char *)xp25_alloc(n + 2);
    if (!p) return NULL;
    memcpy(p, dir, n);
    if (!n || dir[n - 1] != '\\') p[n++] = '\\';
    p[n] = 0;
    return p;
}

static char *join(const char *dir, const char *name)
{
    char *prefix = child_prefix(dir), *full;
    size_t a, b;
    if (!prefix) return NULL;
    a = strlen(prefix);
    b = strlen(name);
    full = (char *)xp25_alloc(a + b + 1);
    if (full) { memcpy(full, prefix, a); memcpy(full + a, name, b); }
    xp25_free(prefix);
    return full;
}

/* [first, last) of entries strictly below dir. */
static void subtree(const ROVER_INDEX *index, const char *dir, size_t *first, size_t *last)
{
    char *prefix = child_prefix(dir);
    size_t n, i;
    *first = *last = index->count;
    if (!prefix) return;
    n = strlen(prefix);
    i = lower_bound(index, prefix);
    *first = i;
    while (i < index->count && xp25_strnieq(index->entries[i].path, prefix, n)) ++i;
    *last = i;
    xp25_free(prefix);
}

static size_t compact(ROVER_INDEX *index)
{
    size_t i, out = 0, removed = 0;
    for (i = 0; i < index->count; ++i) {
        if (index->entries[i].attrs & DEAD) { entry_free(&index->entries[i]); ++removed; continue; }
        index->entries[out++] = index->entries[i];
    }
    index->count = out;
    return removed;
}

static size_t mark_tree(ROVER_INDEX *index, const char *path, int include_self)
{
    size_t first, last, i, marked = 0;
    ROVER_ENTRY *self = include_self ? rover_index_find(index, path) : NULL;
    if (self) { self->attrs |= DEAD; ++marked; }
    subtree(index, path, &first, &last);
    for (i = first; i < last; ++i)
        if (!(index->entries[i].attrs & DEAD)) { index->entries[i].attrs |= DEAD; ++marked; }
    return marked;
}

size_t rover_index_remove(ROVER_INDEX *index, const char *path)
{
    size_t marked = mark_tree(index, path, 1);
    if (marked) compact(index);
    return marked;
}

static char *moved_path(const char *path, size_t old_len, const char *new_path, size_t new_len)
{
    const char *suffix = path + old_len;
    char *result = (char *)xp25_alloc(new_len + strlen(suffix) + 1);
    if (!result) return NULL;
    memcpy(result, new_path, new_len);
    strcpy(result + new_len, suffix);
    return result;
}

size_t rover_index_rename(ROVER_INDEX *index, const char *old_path, const char *new_path)
{
    size_t first, last, at, i, base, moved = 0, old_len = strlen(old_path), new_len = strlen(new_path);
    int has_self;
    if (!rover_path_compare(old_path, new_path)) {
        /* Case-only rename: rewrite spelling in place; the order is unchanged. */
        ROVER_ENTRY *self = rover_index_find(index, old_path);
        if (self && strlen(self->path) == new_len) { memcpy(self->path, new_path, new_len); return 1; }
        return 0;
    }
    rover_index_remove(index, new_path);
    at = lower_bound(index, old_path);
    has_self = at < index->count && !rover_path_compare(index->entries[at].path, old_path) &&
               !(index->entries[at].attrs & DEAD);
    subtree(index, old_path, &first, &last);
    if (!has_self && first == last) return 0;
    if (!grow(&index->entries, &index->cap, index->count + (has_self ? 1 : 0) + (last - first))) return 0;
    base = index->count;
    for (i = has_self ? at : first; i < last; i = (has_self && i == at) ? first : i + 1) {
        ROVER_ENTRY *src = &index->entries[i], *dst;
        char *path;
        if (src->attrs & DEAD) continue;
        path = moved_path(src->path, old_len, new_path, new_len);
        if (!path) continue;
        dst = &index->entries[base + moved++];
        *dst = *src;
        dst->path = path;
        dst->name = name_offset(path);
        src->words = NULL;       /* ownership moves to the new entry */
        src->word_count = 0;
        src->attrs |= DEAD;
        if (has_self && i == at && first == last) break;
    }
    index->count = base + moved;
    compact(index);
    qsort(index->entries, index->count, sizeof(ROVER_ENTRY), entry_compare);
    return moved;
}

int rover_index_excluded(const ROVER_SCAN_CONFIG *config, const char *path)
{
    size_t i;
    for (i = 0; i < config->exclude_count; ++i) {
        size_t n = strlen(config->excludes[i]);
        if (xp25_strnieq(path, config->excludes[i], n) && (path[n] == 0 || path[n] == '\\' ||
            (n && config->excludes[i][n - 1] == '\\'))) return 1;
    }
    return config->sensitive && config->sensitive(config->sensitive_ctx, path);
}

unsigned long rover_word_hash(const char *word, size_t len)
{
    unsigned long h = 2166136261UL;
    size_t i;
    for (i = 0; i < len; ++i) {
        h ^= (unsigned long)xp25_lower((unsigned char)word[i]);
        h = (h * 16777619UL) & 0xFFFFFFFFUL;
    }
    return h;
}

static int XP25_CDECL ulong_compare(const void *a, const void *b)
{
    unsigned long x = *(const unsigned long *)a, y = *(const unsigned long *)b;
    return x < y ? -1 : x > y;
}

static int word_char(unsigned char c) { return xp25_is_alpha(c) || xp25_is_digit(c) || c >= 0x80; }

size_t rover_words_from_text(const char *text, size_t len, unsigned long *words, size_t max)
{
    size_t i = 0, n = 0, out, k;
    while (i < len && n < max * 4) {
        size_t start;
        while (i < len && !word_char((unsigned char)text[i])) ++i;
        start = i;
        while (i < len && word_char((unsigned char)text[i])) ++i;
        if (i - start >= 3 && i - start <= 24) {
            unsigned long h = rover_word_hash(text + start, i - start);
            /* Keep the first distinct words; duplicates are removed after sorting. */
            for (k = 0; k < n && words[k] != h; ++k) {}
            if (k == n && n < max) words[n++] = h;
            if (n == max) break;
        }
    }
    qsort(words, n, sizeof(unsigned long), ulong_compare);
    for (i = 0, out = 0; i < n; ++i)
        if (!out || words[out - 1] != words[i]) words[out++] = words[i];
    return out;
}

int rover_entry_has_word(const ROVER_ENTRY *entry, const char *word)
{
    unsigned long h;
    size_t lo = 0, hi;
    if (!entry->words || !entry->word_count || !word) return 0;
    h = rover_word_hash(word, strlen(word));
    hi = entry->word_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (entry->words[mid] < h) lo = mid + 1;
        else hi = mid;
    }
    return lo < entry->word_count && entry->words[lo] == h;
}

int rover_text_extension(const char *name)
{
    static const char *ext[] = { ".txt", ".log", ".ini", ".inf", ".csv", ".xml", ".htm", ".html", ".rtf",
                                 ".md", ".cfg", ".conf", ".bat", ".cmd", ".c", ".h", ".cpp", ".py", ".js",
                                 ".json", ".eml", ".nfo", NULL };
    size_t i;
    for (i = 0; ext[i]; ++i)
        if (xp25_ends_with_i(name, ext[i])) return 1;
    return 0;
}

static void index_content(ROVER_ENTRY *e, const ROVER_FS *fs, const ROVER_SCAN_CONFIG *config, ROVER_SCAN_STATS *stats)
{
    char *text;
    unsigned long words[ROVER_MAX_WORDS];
    size_t got, n;
    if (!config->content || !fs->read_head || (e->attrs & ROVER_ATTR_DIRECTORY) || e->word_count ||
        e->size > 4 * 1024 * 1024 || !rover_text_extension(e->path + e->name)) return;
    text = (char *)xp25_alloc(ROVER_CONTENT_BYTES);
    if (!text) return;
    got = fs->read_head(fs->ctx, e->path, text, ROVER_CONTENT_BYTES);
    n = rover_words_from_text(text, got, words, ROVER_MAX_WORDS);
    xp25_free(text);
    if (!n) return;
    e->words = (unsigned long *)xp25_alloc(n * sizeof(unsigned long));
    if (!e->words) return;
    memcpy(e->words, words, n * sizeof(unsigned long));
    e->word_count = (unsigned short)n;
    if (stats) ++stats->content;
}

typedef struct {
    char **items;
    size_t count, cap;
} STACK;

static int push(STACK *s, char *dir)
{
    if (!dir) return 0;
    if (s->count == s->cap) {
        size_t cap = s->cap ? s->cap * 2 : 64;
        char **items = (char **)xp25_realloc(s->items, cap * sizeof(char *));
        if (!items) { xp25_free(dir); return 0; }
        s->items = items;
        s->cap = cap;
    }
    s->items[s->count++] = dir;
    return 1;
}

static int XP25_CDECL dirent_compare(const void *a, const void *b)
{
    return rover_path_compare(((const ROVER_DIRENT *)a)->name, ((const ROVER_DIRENT *)b)->name);
}

static int listed(const ROVER_DIRENT *list, size_t n, const char *name)
{
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = rover_path_compare(list[mid].name, name);
        if (!c) return 1;
        if (c < 0) lo = mid + 1; else hi = mid;
    }
    return 0;
}

typedef struct {
    ROVER_ENTRY *items;
    size_t count, cap;
} PENDING;

static void reconcile(ROVER_INDEX *index, PENDING *pending, STACK *stack, const ROVER_FS *fs,
                      const ROVER_SCAN_CONFIG *config, ROVER_SCAN_STATS *stats, const char *dir)
{
    ROVER_DIRENT *list = NULL;
    size_t n = 0, i, first, last;
    char *prefix;
    size_t prefix_len;
    int status = fs->list(fs->ctx, dir, &list, &n);
    if (status != ROVER_FS_OK) {
        /* Respect permissions: an unreadable directory contributes nothing. */
        if (status == ROVER_FS_DENIED) ++stats->denied;
        stats->removed += (unsigned long)mark_tree(index, dir, status == ROVER_FS_MISSING);
        return;
    }
    ++stats->directories;
    qsort(list, n, sizeof(ROVER_DIRENT), dirent_compare);
    prefix = child_prefix(dir);
    prefix_len = prefix ? strlen(prefix) : 0;
    subtree(index, dir, &first, &last);
    for (i = first; prefix && i < last; ++i) {
        ROVER_ENTRY *e = &index->entries[i];
        const char *rest = e->path + prefix_len;
        if ((e->attrs & DEAD) || strchr(rest, '\\')) continue;
        if (!listed(list, n, rest)) stats->removed += (unsigned long)mark_tree(index, e->path, 1);
    }
    for (i = 0; i < n; ++i) {
        char *full = join(dir, list[i].name);
        ROVER_ENTRY *e;
        if (!full) continue;
        if (rover_index_excluded(config, full)) {
            ++stats->excluded;
            stats->removed += (unsigned long)mark_tree(index, full, 1);
            xp25_free(full);
            continue;
        }
        if (!(list[i].attrs & ROVER_ATTR_DIRECTORY)) ++stats->files;
        e = rover_index_find(index, full);
        if (e) {
            if (!same_meta(e, &list[i])) {
                set_meta(e, &list[i]);
                xp25_free(e->words);
                e->words = NULL;
                e->word_count = 0;
                ++stats->updated;
            }
            index_content(e, fs, config, stats);
        } else if (index->count + pending->count >= config->max_entries) {
            stats->truncated = 1;
        } else if (grow(&pending->items, &pending->cap, pending->count + 1)) {
            ROVER_ENTRY *p = &pending->items[pending->count++];
            memset(p, 0, sizeof(*p));
            p->path = full;
            p->name = name_offset(full);
            set_meta(p, &list[i]);
            index_content(p, fs, config, stats);
            full = NULL;
            ++stats->added;
        }
        if ((list[i].attrs & ROVER_ATTR_DIRECTORY) && !(list[i].attrs & ROVER_ATTR_REPARSE))
            push(stack, join(dir, list[i].name));
        xp25_free(full);
    }
    xp25_free(prefix);
    if (fs->free_list) fs->free_list(fs->ctx, list, n);
}

static int merge(ROVER_INDEX *index, PENDING *pending)
{
    size_t i, a, b, out, capacity;
    ROVER_ENTRY *merged;
    compact(index);
    if (!pending->count) return 1;
    qsort(pending->items, pending->count, sizeof(ROVER_ENTRY), entry_compare);
    capacity = index->count + pending->count;
    merged = (ROVER_ENTRY *)xp25_alloc(capacity * sizeof(ROVER_ENTRY));
    if (!merged) {
        for (i = 0; i < pending->count; ++i) entry_free(&pending->items[i]);
        return 0;
    }
    for (a = b = out = 0; a < index->count || b < pending->count;) {
        int take_pending = a == index->count ||
            (b < pending->count && rover_path_compare(pending->items[b].path, index->entries[a].path) < 0);
        if (take_pending) {
            if (out && !rover_path_compare(merged[out - 1].path, pending->items[b].path)) {
                entry_free(&pending->items[b++]);
                continue;
            }
            merged[out++] = pending->items[b++];
        } else merged[out++] = index->entries[a++];
    }
    xp25_free(index->entries);
    index->entries = merged;
    index->count = out;
    index->cap = capacity;
    return 1;
}

static int under_root(const ROVER_SCAN_CONFIG *config, const char *path)
{
    size_t i;
    for (i = 0; i < config->root_count; ++i) {
        char *prefix = child_prefix(config->roots[i]);
        int inside = prefix && xp25_strnieq(path, prefix, strlen(prefix));
        xp25_free(prefix);
        if (inside) return 1;
    }
    return 0;
}

static int walk(ROVER_INDEX *index, const ROVER_FS *fs, const ROVER_SCAN_CONFIG *config,
                ROVER_SCAN_STATS *stats, const char **starts, size_t start_count)
{
    STACK stack;
    PENDING pending;
    size_t i;
    int ok;
    memset(&stack, 0, sizeof(stack));
    memset(&pending, 0, sizeof(pending));
    for (i = 0; i < start_count; ++i) push(&stack, xp25_strdup(starts[i]));
    while (stack.count) {
        char *dir = stack.items[--stack.count];
        if (config->cancelled && config->cancelled(config->cancel_ctx)) {
            stats->cancelled = 1;
            xp25_free(dir);
            break;
        }
        if (rover_index_excluded(config, dir)) {
            ++stats->excluded;
            stats->removed += (unsigned long)mark_tree(index, dir, 0);
        } else reconcile(index, &pending, &stack, fs, config, stats, dir);
        xp25_free(dir);
    }
    while (stack.count) xp25_free(stack.items[--stack.count]);
    xp25_free(stack.items);
    ok = merge(index, &pending);
    xp25_free(pending.items);
    return ok;
}

int rover_index_scan(ROVER_INDEX *index, const ROVER_FS *fs, const ROVER_SCAN_CONFIG *config,
                     ROVER_SCAN_STATS *stats, unsigned long now)
{
    size_t i;
    int ok;
    memset(stats, 0, sizeof(*stats));
    if (!index->sorted) {
        qsort(index->entries, index->count, sizeof(ROVER_ENTRY), entry_compare);
        index->sorted = 1;
    }
    for (i = 0; i < index->count; ++i)
        if (!under_root(config, index->entries[i].path)) { index->entries[i].attrs |= DEAD; ++stats->removed; }
    ok = walk(index, fs, config, stats, config->roots, config->root_count);
    if (!stats->cancelled) {
        if (!index->built) index->built = now;
    }
    index->updated = now;
    ++index->generation;
    return ok;
}

int rover_index_apply(ROVER_INDEX *index, const ROVER_FS *fs, const ROVER_SCAN_CONFIG *config,
                      int action, const char *path, const char *old_path, unsigned long now)
{
    ROVER_DIRENT meta;
    ROVER_SCAN_STATS stats;
    int status, had;
    memset(&stats, 0, sizeof(stats));
    if (action == 4 && old_path) {
        if (!under_root(config, path) || rover_index_excluded(config, path)) {
            rover_index_remove(index, old_path);
            index->updated = now;
            return 1;
        }
        had = rover_index_find(index, old_path) != NULL;
        rover_index_rename(index, old_path, path);
        action = had ? 3 : 1;
    }
    if (!under_root(config, path)) return 0;
    if (action == 2 || rover_index_excluded(config, path)) {
        rover_index_remove(index, path);
        index->updated = now;
        return 1;
    }
    memset(&meta, 0, sizeof(meta));
    status = fs->stat(fs->ctx, path, &meta);
    if (status != ROVER_FS_OK) {
        rover_index_remove(index, path);
        index->updated = now;
        return 1;
    }
    had = rover_index_find(index, path) != NULL;
    if (!rover_index_upsert(index, path, &meta)) return 0;
    {
        ROVER_ENTRY *e = rover_index_find(index, path);
        if (e) index_content(e, fs, config, &stats);
    }
    if ((meta.attrs & ROVER_ATTR_DIRECTORY) && !(meta.attrs & ROVER_ATTR_REPARSE) && (action == 1 || !had)) {
        const char *start = path;
        walk(index, fs, config, &stats, &start, 1);
    }
    index->updated = now;
    return 1;
}

static void put32(XP25_BUF *b, unsigned long v)
{
    unsigned char x[4];
    x[0] = (unsigned char)v; x[1] = (unsigned char)(v >> 8); x[2] = (unsigned char)(v >> 16); x[3] = (unsigned char)(v >> 24);
    xp25_buf_append(b, (const char *)x, 4);
}

static unsigned long get32(const unsigned char *p)
{
    return (unsigned long)p[0] | ((unsigned long)p[1] << 8) | ((unsigned long)p[2] << 16) | ((unsigned long)p[3] << 24);
}

int rover_index_serialize(const ROVER_INDEX *index, XP25_BUF *out)
{
    unsigned char digest[32];
    size_t i, live = 0;
    xp25_buf_reset(out);
    for (i = 0; i < index->count; ++i) if (!(index->entries[i].attrs & DEAD)) ++live;
    xp25_buf_append(out, "XP25RIX1", 8);
    put32(out, 1);
    put32(out, (unsigned long)live);
    put32(out, index->built);
    put32(out, index->updated);
    put32(out, index->generation);
    for (i = 0; i < index->count; ++i) {
        const ROVER_ENTRY *e = &index->entries[i];
        size_t n = strlen(e->path), k;
        unsigned char len[2];
        if (e->attrs & DEAD) continue;
        if (n > 0xFFFF) return 0;
        len[0] = (unsigned char)n;
        len[1] = (unsigned char)(n >> 8);
        xp25_buf_append(out, (const char *)len, 2);
        xp25_buf_append(out, e->path, n);
        put32(out, (unsigned long)(e->size & 0xFFFFFFFFUL));
        put32(out, (unsigned long)(e->size >> 32));
        put32(out, e->mtime);
        put32(out, e->ctime);
        put32(out, e->attrs);
        put32(out, (unsigned long)e->word_count);
        for (k = 0; k < e->word_count; ++k) put32(out, e->words[k]);
    }
    if (!xp25_buf_ok(out)) return 0;
    xp25_sha256(out->data, out->len, digest);
    return xp25_buf_append(out, (const char *)digest, 32);
}

static int bad(char *error, size_t size, const char *text)
{
    size_t n = strlen(text);
    if (error && size) {
        if (n >= size) n = size - 1;
        memcpy(error, text, n);
        error[n] = 0;
    }
    return 0;
}

int rover_index_deserialize(ROVER_INDEX *index, const unsigned char *data, size_t len, char *error, size_t error_size)
{
    unsigned char digest[32];
    size_t pos = 28, i, count;
    ROVER_INDEX loaded;
    rover_index_init(&loaded);
    if (len < 60 || memcmp(data, "XP25RIX1", 8)) return bad(error, error_size, "not an XP25 RoverAI index");
    xp25_sha256(data, len - 32, digest);
    if (memcmp(digest, data + len - 32, 32)) return bad(error, error_size, "index checksum mismatch");
    if (get32(data + 8) != 1) return bad(error, error_size, "unsupported index version");
    count = get32(data + 12);
    if (count > (len - 60) / 26 + 1) return bad(error, error_size, "entry count exceeds file size");
    loaded.built = get32(data + 16);
    loaded.updated = get32(data + 20);
    loaded.generation = get32(data + 24);
    loaded.entries = (ROVER_ENTRY *)xp25_alloc((count ? count : 1) * sizeof(ROVER_ENTRY));
    if (!loaded.entries) return bad(error, error_size, "out of memory");
    loaded.cap = count;
    len -= 32;
    for (i = 0; i < count; ++i) {
        ROVER_ENTRY *e = &loaded.entries[i];
        size_t n, words;
        if (len - pos < 2) goto truncated;
        n = (size_t)data[pos] | ((size_t)data[pos + 1] << 8);
        pos += 2;
        if (!n || len - pos < n + 24 || memchr(data + pos, 0, n)) goto truncated;
        e->path = xp25_strndup((const char *)data + pos, n);
        if (!e->path) goto truncated;
        ++loaded.count;
        pos += n;
        e->name = name_offset(e->path);
        e->size = (xp25_u64)get32(data + pos) | ((xp25_u64)get32(data + pos + 4) << 32);
        e->mtime = get32(data + pos + 8);
        e->ctime = get32(data + pos + 12);
        e->attrs = get32(data + pos + 16) & ~DEAD;
        words = get32(data + pos + 20);
        pos += 24;
        if (words > ROVER_MAX_WORDS || (len - pos) / 4 < words) goto truncated;
        if (words) {
            size_t k;
            e->words = (unsigned long *)xp25_alloc(words * sizeof(unsigned long));
            if (!e->words) goto truncated;
            for (k = 0; k < words; ++k) e->words[k] = get32(data + pos + 4 * k);
            e->word_count = (unsigned short)words;
            pos += 4 * words;
        }
        if (i && rover_path_compare(loaded.entries[i - 1].path, e->path) >= 0) {
            rover_index_free(&loaded);
            return bad(error, error_size, "entries are not strictly ordered");
        }
    }
    if (pos != len) { rover_index_free(&loaded); return bad(error, error_size, "trailing data"); }
    rover_index_free(index);
    *index = loaded;
    return 1;
truncated:
    rover_index_free(&loaded);
    return bad(error, error_size, "truncated or malformed entry");
}
