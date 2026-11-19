/* Milestone 8.4: differential test of the RoverAI index against a reference implementation.
   The reference is an earlier rover_index.c compiled with every exported name prefixed old_
   (tests/test_modernization.py takes it from git). Both implementations index the same randomly
   changing synthetic file system, by full and incremental scans and by change notifications, and
   must produce byte-identical saved indexes and identical scan statistics. Names use characters
   whose order changes under case folding ('[', '_', '`', 'A'..'Z'), characters on either side of
   the backslash, high bytes, case-only renames and duplicate spellings; directories can be denied,
   missing, reparse points or excluded.
   usage: rover_index_diff <rounds> [seed]   prints rounds=N and failures=N */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rover_index.h"

void old_rover_index_init(ROVER_INDEX *index);
void old_rover_index_free(ROVER_INDEX *index);
int old_rover_index_scan(ROVER_INDEX *index, const ROVER_FS *fs, const ROVER_SCAN_CONFIG *config,
                         ROVER_SCAN_STATS *stats, unsigned long now);
int old_rover_index_apply(ROVER_INDEX *index, const ROVER_FS *fs, const ROVER_SCAN_CONFIG *config,
                          int action, const char *path, const char *old_path, unsigned long now);
int old_rover_index_serialize(const ROVER_INDEX *index, XP25_BUF *out);

#define MAX_NODES 900
typedef struct {
    char name[24];
    int parent;          /* -1: the root "C:" */
    int dir, alive;
    unsigned long attrs, mtime;
    xp25_u64 size;
} NODE;

static NODE nodes[MAX_NODES];
static int node_count, failures;
static unsigned long seed = 0x9E3779B9UL;
static int denied_dir = -1, missing_dir = -1;

static unsigned long rnd(void)
{
    seed ^= (seed << 13) & 0xFFFFFFFFUL;
    seed ^= seed >> 17;
    seed ^= (seed << 5) & 0xFFFFFFFFUL;
    return seed & 0xFFFFFFFFUL;
}

static void random_name(char *out)
{
    static const char alphabet[] = "abcXYZ[]_`^ -.!~0189\x80\xc3\xa9";
    int n = 1 + (int)(rnd() % 6), i;
    for (i = 0; i < n; ++i) out[i] = alphabet[rnd() % (sizeof(alphabet) - 1)];
    out[n] = 0;
    if (rnd() % 4 == 0) strcpy(out + n, rnd() % 2 ? ".txt" : ".LOG");
}

static void node_path(int k, char *out, size_t size)
{
    if (k < 0) { strcpy(out, "C:"); return; }
    node_path(nodes[k].parent, out, size);
    if (strlen(out) + strlen(nodes[k].name) + 2 < size) { strcat(out, "\\"); strcat(out, nodes[k].name); }
}

static int dir_of_path(const char *path)
{
    char buf[1024];
    int k;
    if (!rover_path_compare(path, "C:")) return -1;
    for (k = 0; k < node_count; ++k) {
        if (!nodes[k].alive || !nodes[k].dir) continue;
        node_path(k, buf, sizeof(buf));
        if (!rover_path_compare(buf, path)) return k;
    }
    return -2;
}

static int alive_path(int k)
{
    for (; k >= 0; k = nodes[k].parent) if (!nodes[k].alive) return 0;
    return 1;
}

static int fs_list(void *ctx, const char *dir, ROVER_DIRENT **entries, size_t *count)
{
    int d = dir_of_path(dir), k, n = 0;
    ROVER_DIRENT *list;
    (void)ctx;
    if (d == -2 || (d >= 0 && (d == missing_dir || !alive_path(d)))) return ROVER_FS_MISSING;
    if (d >= 0 && d == denied_dir) return ROVER_FS_DENIED;
    list = (ROVER_DIRENT *)xp25_alloc(sizeof(ROVER_DIRENT) * MAX_NODES);
    for (k = 0; k < node_count; ++k) {
        if (!nodes[k].alive || nodes[k].parent != d) continue;
        list[n].name = xp25_strdup(nodes[k].name);
        list[n].size = nodes[k].size;
        list[n].mtime = list[n].ctime = nodes[k].mtime;
        list[n].attrs = nodes[k].attrs;
        ++n;
    }
    *entries = list;
    *count = (size_t)n;
    return ROVER_FS_OK;
}

static int fs_stat(void *ctx, const char *path, ROVER_DIRENT *entry)
{
    char buf[1024];
    int k;
    (void)ctx;
    for (k = 0; k < node_count; ++k) {
        if (!nodes[k].alive || !alive_path(k)) continue;
        node_path(k, buf, sizeof(buf));
        if (!rover_path_compare(buf, path)) {
            entry->size = nodes[k].size;
            entry->mtime = entry->ctime = nodes[k].mtime;
            entry->attrs = nodes[k].attrs;
            return ROVER_FS_OK;
        }
    }
    return ROVER_FS_MISSING;
}

static size_t fs_head(void *ctx, const char *path, char *buffer, size_t max)
{
    size_t n = strlen(path) < max ? strlen(path) : max;
    (void)ctx;
    memcpy(buffer, path, n);
    return n;
}

static void fs_free(void *ctx, ROVER_DIRENT *entries, size_t count)
{
    size_t i;
    (void)ctx;
    for (i = 0; i < count; ++i) xp25_free(entries[i].name);
    xp25_free(entries);
}

static int sensitive(void *ctx, const char *path) { (void)ctx; return xp25_stristr(path, "\\~") != NULL; }

static int add_node(int parent, int dir)
{
    NODE *n;
    if (node_count == MAX_NODES) return -1;
    n = &nodes[node_count];
    memset(n, 0, sizeof(*n));
    random_name(n->name);
    n->parent = parent;
    n->dir = dir;
    n->alive = 1;
    n->attrs = dir ? (ROVER_ATTR_DIRECTORY | (rnd() % 17 == 0 ? ROVER_ATTR_REPARSE : 0)) : 0x20;
    n->size = dir ? 0 : rnd() % 100000;
    n->mtime = 1700000000UL + rnd() % 1000;
    return node_count++;
}

static int random_dir(void)
{
    int tries;
    for (tries = 0; tries < 20; ++tries) {
        int k = (int)(rnd() % (unsigned long)(node_count + 1)) - 1;
        if (k < 0 || (nodes[k].alive && nodes[k].dir)) return k;
    }
    return -1;
}

static void mutate(void)
{
    int k = node_count ? (int)(rnd() % (unsigned long)node_count) : 0;
    switch (rnd() % 8) {
    case 0: case 1: add_node(random_dir(), (int)(rnd() % 3 == 0)); break;
    case 2: if (node_count) nodes[k].alive = 0; break;
    case 3: if (node_count) { nodes[k].mtime += 1 + rnd() % 50; nodes[k].size += rnd() % 7; } break;
    case 4: if (node_count) { char *c = nodes[k].name; for (; *c; ++c) if (*c >= 'a' && *c <= 'z') { *c = (char)(*c - 32); break; } else if (*c >= 'A' && *c <= 'Z') { *c = (char)(*c + 32); break; } } break;
    case 5: if (node_count) random_name(nodes[k].name); break;
    case 6:   /* move a folder (never below itself) */
        if (node_count && nodes[k].dir) {
            int to = random_dir(), up = to;
            while (up >= 0 && up != k) up = nodes[up].parent;
            if (up != k) nodes[k].parent = to;
        }
        break;
    default: denied_dir = rnd() % 3 ? -1 : random_dir(); missing_dir = rnd() % 4 ? -1 : random_dir(); break;
    }
}

static void compare(const char *what, int round, const ROVER_INDEX *a, const ROVER_INDEX *b,
                    const ROVER_SCAN_STATS *sa, const ROVER_SCAN_STATS *sb, int ra, int rb)
{
    XP25_BUF x, y;
    xp25_buf_init(&x);
    xp25_buf_init(&y);
    old_rover_index_serialize(a, &x);
    rover_index_serialize(b, &y);
    if (ra != rb || x.len != y.len || memcmp(x.data, y.data, x.len) || (sa && memcmp(sa, sb, sizeof(*sa)))) {
        ++failures;
        if (failures < 10) printf("FAIL round %d %s: results %d/%d, index bytes %lu/%lu, entries %lu/%lu\n", round, what, ra, rb,
                                  (unsigned long)x.len, (unsigned long)y.len, (unsigned long)a->count, (unsigned long)b->count);
    }
    xp25_buf_free(&x);
    xp25_buf_free(&y);
}

int main(int argc, char **argv)
{
    long rounds = argc > 1 ? atol(argv[1]) : 200, r;
    ROVER_FS fs;
    ROVER_SCAN_CONFIG config;
    const char *roots[2] = { "C:", "C:\\xyz" };
    const char *excludes[2] = { "C:\\[", "C:\\a\\b" };
    if (argc > 2) seed = strtoul(argv[2], NULL, 0) | 1UL;
    fs.list = fs_list; fs.stat = fs_stat; fs.read_head = fs_head; fs.free_list = fs_free; fs.ctx = NULL;
    for (r = 0; r < rounds; ++r) {
        ROVER_INDEX a, b;
        ROVER_SCAN_STATS sa, sb;
        int step, k;
        node_count = 0;
        denied_dir = missing_dir = -1;
        for (k = 0; k < 40 + (int)(rnd() % 200); ++k) add_node(random_dir(), (int)(rnd() % 3 == 0));
        memset(&config, 0, sizeof(config));
        config.roots = roots;
        config.root_count = 1 + (size_t)(rnd() % 2);
        config.excludes = excludes;
        config.exclude_count = (size_t)(rnd() % 3);
        config.sensitive = rnd() % 2 ? sensitive : NULL;
        config.max_entries = rnd() % 5 ? 100000 : 20 + rnd() % 60;
        config.content = (int)(rnd() % 2);
        old_rover_index_init(&a);
        rover_index_init(&b);
        compare("full scan", (int)r, &a, &b, &sa, &sb, old_rover_index_scan(&a, &fs, &config, &sa, 1700000000UL),
                rover_index_scan(&b, &fs, &config, &sb, 1700000000UL));
        for (step = 0; step < 6; ++step) {
            int m, changes = 1 + (int)(rnd() % 12);
            for (m = 0; m < changes; ++m) mutate();
            if (rnd() % 2) {
                compare("rescan", (int)r, &a, &b, &sa, &sb, old_rover_index_scan(&a, &fs, &config, &sa, 1700001000UL + (unsigned long)step),
                        rover_index_scan(&b, &fs, &config, &sb, 1700001000UL + (unsigned long)step));
            } else {
                char path[1024], old_path[1024];
                int action = 1 + (int)(rnd() % 4);
                k = node_count ? (int)(rnd() % (unsigned long)node_count) : 0;
                node_path(k, path, sizeof(path));
                node_path(node_count ? (int)(rnd() % (unsigned long)node_count) : 0, old_path, sizeof(old_path));
                compare("notification", (int)r, &a, &b, NULL, NULL,
                        old_rover_index_apply(&a, &fs, &config, action, path, action == 4 ? old_path : NULL, 1700002000UL),
                        rover_index_apply(&b, &fs, &config, action, path, action == 4 ? old_path : NULL, 1700002000UL));
            }
        }
        old_rover_index_free(&a);
        rover_index_free(&b);
    }
    printf("rounds=%ld\nfailures=%d\n", rounds, failures);
    return failures != 0;
}
