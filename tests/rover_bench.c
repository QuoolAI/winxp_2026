/* Milestone 8.4: host benchmark of the RoverAI portable index and search core. A deterministic
   synthetic file system shaped like the engineering image's C: drive (about 315,000 entries,
   documented in docs/xp25-ai-clippyai-roverai.md) is served through the same ROVER_FS callbacks
   the native scanner provides, with the native privacy rule (xp25_policy_sensitive_path) as the
   sensitive callback. It measures the portable CPU work only: the native file system, disk and
   the guest's CPU are not modelled, so absolute times say nothing about the guest.
   usage: rover_bench [directories] [files per directory] [repeats]   prints one JSON line per phase */
#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "xp25_base.h"
#include "xp25_policy.h"
#include "rover_index.h"
#include "rover_query.h"

typedef struct {
    long dirs, files_per_dir;
    long *parent;            /* parent directory of each directory (-1 for the root) */
    long *child_start;       /* children of directory d: child_list[child_start[d] .. child_start[d + 1]) */
    long *child_list;
    char **name;             /* directory names */
    char **path;             /* full directory paths */
    unsigned long listed;
} SYNTH;

static const char *const exts[] = { ".dll", ".exe", ".txt", ".ini", ".log", ".jpg", ".doc", ".htm", ".sys", ".inf", ".xml", ".mp3" };
static const char *const top[] = { "WINDOWS", "Program Files", "Documents and Settings", "System Volume Information", "RECYCLER" };

static double now_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1000.0 + (double)t.tv_nsec / 1e6;
}

static char *copy(const char *a)
{
    char *s = (char *)malloc(strlen(a) + 1);
    strcpy(s, a);
    return s;
}

static char *dup2(const char *a, const char *b)
{
    size_t x = strlen(a), y = strlen(b);
    char *s = (char *)malloc(x + y + 2);
    memcpy(s, a, x);
    s[x] = '\\';
    memcpy(s + x + 1, b, y + 1);
    return s;
}

/* A fixed tree: five top-level folders, then each new directory is placed under a pseudo-random
   earlier one, which gives a realistic mix of wide and deep folders. */
static void synth_build(SYNTH *s, long dirs, long files)
{
    long i;
    unsigned long r = 12345;
    s->dirs = dirs;
    s->files_per_dir = files;
    s->parent = (long *)calloc((size_t)dirs, sizeof(long));
    s->name = (char **)calloc((size_t)dirs, sizeof(char *));
    s->path = (char **)calloc((size_t)dirs, sizeof(char *));
    s->parent[0] = -1;
    s->name[0] = copy("C:");
    s->path[0] = copy("C:");
    for (i = 1; i < dirs; ++i) {
        char name[48];
        long p;
        r = r * 1103515245UL + 12345UL;
        if (i <= 5) { p = 0; strcpy(name, top[i - 1]); }
        else {
            p = 1 + (long)((r >> 8) % (unsigned long)(i - 1));
            sprintf(name, "Folder %05ld", i);
        }
        s->parent[i] = p;
        s->name[i] = copy(name);
        s->path[i] = dup2(s->path[p], name);
    }
    s->child_start = (long *)calloc((size_t)dirs + 1, sizeof(long));
    s->child_list = (long *)calloc((size_t)dirs, sizeof(long));
    for (i = 1; i < dirs; ++i) ++s->child_start[s->parent[i] + 1];
    for (i = 0; i < dirs; ++i) s->child_start[i + 1] += s->child_start[i];
    {
        long *fill = (long *)calloc((size_t)dirs, sizeof(long));
        for (i = 1; i < dirs; ++i) s->child_list[s->child_start[s->parent[i]] + fill[s->parent[i]]++] = i;
        free(fill);
    }
}

static long find_dir(const SYNTH *s, const char *path)
{
    long i;
    /* The benchmark keeps a sorted lookup out of the measured code: a linear search would dominate. */
    static long *order;
    static const SYNTH *built;
    if (built != s) {
        long k;
        free(order);
        order = (long *)malloc((size_t)s->dirs * sizeof(long));
        for (k = 0; k < s->dirs; ++k) order[k] = k;
        {
            /* insertion-free sort by path */
            long gap, a, b;
            for (gap = s->dirs / 2; gap > 0; gap /= 2)
                for (a = gap; a < s->dirs; ++a)
                    for (b = a; b >= gap && rover_path_compare(s->path[order[b - gap]], s->path[order[b]]) > 0; b -= gap) {
                        long t = order[b]; order[b] = order[b - gap]; order[b - gap] = t;
                    }
        }
        built = s;
    }
    {
        long lo = 0, hi = s->dirs;
        while (lo < hi) {
            long mid = lo + (hi - lo) / 2;
            int c = rover_path_compare(s->path[order[mid]], path);
            if (!c) return order[mid];
            if (c < 0) lo = mid + 1; else hi = mid;
        }
    }
    (void)i;
    return -1;
}

static int synth_list(void *ctx, const char *dir, ROVER_DIRENT **entries, size_t *count)
{
    SYNTH *s = (SYNTH *)ctx;
    long d = find_dir(s, dir), i, n = 0, cap;
    ROVER_DIRENT *list;
    if (d < 0) return ROVER_FS_MISSING;
    cap = s->files_per_dir + 64;
    list = (ROVER_DIRENT *)xp25_alloc((size_t)cap * sizeof(ROVER_DIRENT));
    for (i = 0; i < s->files_per_dir; ++i) {
        char name[48];
        sprintf(name, "file%04ld%s", i, exts[(i + d) % 12]);
        list[n].name = xp25_strdup(name);
        list[n].size = (xp25_u64)(i * 977 + d);
        list[n].mtime = 1600000000UL + (unsigned long)(i * 3600 + d);
        list[n].ctime = list[n].mtime;
        list[n].attrs = 0x20;
        ++n;
    }
    for (i = s->child_start[d]; i < s->child_start[d + 1]; ++i) {
        long c = s->child_list[i];
        if (n == cap) { cap *= 2; list = (ROVER_DIRENT *)xp25_realloc(list, (size_t)cap * sizeof(ROVER_DIRENT)); }
        list[n].name = xp25_strdup(s->name[c]);
        list[n].size = 0;
        list[n].mtime = list[n].ctime = 1600000000UL + (unsigned long)c;
        list[n].attrs = ROVER_ATTR_DIRECTORY;
        ++n;
    }
    ++s->listed;
    *entries = list;
    *count = (size_t)n;
    return ROVER_FS_OK;
}

static int synth_stat(void *ctx, const char *path, ROVER_DIRENT *entry)
{
    (void)ctx; (void)path;
    entry->size = 1; entry->mtime = entry->ctime = 1700000000UL; entry->attrs = 0x20;
    return ROVER_FS_OK;
}

static size_t synth_head(void *ctx, const char *path, char *buffer, size_t max)
{
    static const char text[] = "network adapter configuration proxy server address gateway dns suffix "
                               "windows update service printer spooler report invoice summer holiday ";
    size_t n = sizeof(text) - 1, k;
    (void)ctx;
    if (max < n) n = max;
    memcpy(buffer, text, n);
    for (k = 0; k < n && path[k]; ++k) buffer[k] = (char)(buffer[k] ^ (path[k] & 1));  /* vary the words a little */
    return n;
}

static void synth_free(void *ctx, ROVER_DIRENT *entries, size_t count)
{
    size_t i;
    (void)ctx;
    for (i = 0; i < count; ++i) xp25_free(entries[i].name);
    xp25_free(entries);
}

static XP25_PATHS paths;
static int sensitive(void *ctx, const char *path) { (void)ctx; return xp25_policy_sensitive_path(path, &paths); }

static int cmp_double(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

static void report(const char *phase, double *samples, int n, const char *extra)
{
    qsort(samples, (size_t)n, sizeof(double), cmp_double);
    printf("{\"phase\":\"%s\",\"median_ms\":%.1f,\"min_ms\":%.1f,\"max_ms\":%.1f,\"repeats\":%d%s}\n",
           phase, samples[n / 2], samples[0], samples[n - 1], n, extra ? extra : "");
    fflush(stdout);
}

int main(int argc, char **argv)
{
    long dirs = argc > 1 ? atol(argv[1]) : 21000, files = argc > 2 ? atol(argv[2]) : 14;
    int repeats = argc > 3 ? atoi(argv[3]) : 3, r, q;
    SYNTH s;
    ROVER_FS fs;
    ROVER_SCAN_CONFIG config;
    ROVER_SCAN_STATS stats;
    const char *roots[1] = { "C:" };
    const char *excludes[3] = { "C:\\WINDOWS\\Temp", "C:\\WINDOWS\\Prefetch", "C:\\Documents and Settings\\XP25\\Local Settings\\Application Data\\XP25" };
    double t[16];
    char extra[160];
    ROVER_INDEX index;
    XP25_BUF image;
    static const char *const queries[] = { "text files containing network", "photos from 2020 larger than 1 MB",
                                           "newest log files in WINDOWS", "Folder 01234", "files modified last week" };
    memset(&paths, 0, sizeof(paths));
    paths.windows = "C:\\WINDOWS";
    paths.profile = "C:\\Documents and Settings\\XP25";
    paths.other_profiles_root = "C:\\Documents and Settings";
    paths.temp = "C:\\Documents and Settings\\XP25\\Local Settings\\Temp";
    paths.program_files = "C:\\Program Files";
    synth_build(&s, dirs, files);
    find_dir(&s, "C:");
    fs.list = synth_list; fs.stat = synth_stat; fs.read_head = synth_head; fs.free_list = synth_free; fs.ctx = &s;
    memset(&config, 0, sizeof(config));
    config.roots = roots; config.root_count = 1;
    config.excludes = excludes; config.exclude_count = 3;
    config.sensitive = sensitive; config.sensitive_ctx = NULL;
    config.max_entries = 400000;
    config.content = argc > 4 ? atoi(argv[4]) : 0;
    if (repeats > 16) repeats = 16;
    for (r = 0; r < repeats; ++r) {
        double start;
        rover_index_init(&index);
        start = now_ms();
        rover_index_scan(&index, &fs, &config, &stats, 1700000000UL);
        t[r] = now_ms() - start;
        if (r + 1 < repeats) rover_index_free(&index);
    }
    sprintf(extra, ",\"entries\":%lu,\"directories\":%lu,\"files\":%lu,\"excluded\":%lu,\"content\":%lu",
            (unsigned long)index.count, stats.directories, stats.files, stats.excluded, stats.content);
    report("full_scan", t, repeats, extra);
    for (r = 0; r < repeats; ++r) {
        double start = now_ms();
        rover_index_scan(&index, &fs, &config, &stats, 1700000100UL);
        t[r] = now_ms() - start;
    }
    sprintf(extra, ",\"updated\":%lu,\"added\":%lu,\"removed\":%lu", stats.updated, stats.added, stats.removed);
    report("unchanged_rescan", t, repeats, extra);
    xp25_buf_init(&image);
    for (r = 0; r < repeats; ++r) {
        double start = now_ms();
        rover_index_serialize(&index, &image);
        t[r] = now_ms() - start;
    }
    sprintf(extra, ",\"bytes\":%lu", (unsigned long)image.len);
    report("serialize", t, repeats, extra);
    for (r = 0; r < repeats; ++r) {
        ROVER_INDEX loaded;
        char error[96];
        double start;
        rover_index_init(&loaded);
        start = now_ms();
        if (!rover_index_deserialize(&loaded, (const unsigned char *)image.data, image.len, error, sizeof(error))) printf("deserialize failed: %s\n", error);
        t[r] = now_ms() - start;
        rover_index_free(&loaded);
    }
    report("deserialize", t, repeats, NULL);
    for (q = 0; q < (int)(sizeof(queries) / sizeof(queries[0])); ++q) {
        static ROVER_HIT hits[300];
        size_t total = 0, found = 0;
        int relaxed = 0;
        for (r = 0; r < repeats; ++r) {
            ROVER_CRITERIA c;
            double start = now_ms();
            rover_query_parse(queries[q], 1700000000UL, 0, &c);
            found = rover_search(&index, &c, NULL, hits, 300, &total, &relaxed);
            t[r] = now_ms() - start;
        }
        sprintf(extra, ",\"query\":\"%s\",\"hits\":%lu,\"total\":%lu", queries[q], (unsigned long)found, (unsigned long)total);
        report("search", t, repeats, extra);
    }
    for (r = 0; r < repeats; ++r) {
        double start = now_ms();
        long k;
        for (k = 0; k < 2000; ++k) {
            char path[96];
            sprintf(path, "C:\\Program Files\\new%ld.txt", (k * 7919L + r * 13L) % 100000L);
            rover_index_apply(&index, &fs, &config, k % 3 == 2 ? 2 : 1, path, NULL, 1700000200UL);
        }
        t[r] = now_ms() - start;
    }
    report("apply_2000_notifications", t, repeats, NULL);
    xp25_buf_free(&image);
    rover_index_free(&index);
    return 0;
}
