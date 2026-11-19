/* Milestone 8.4: phase timing of the RoverAI index inside the guest, on the real file system.
   Loads the xp25agent.dll given on the command line and, for each repeat, times loading the saved
   index (rover_store_load), an incremental rescan of every configured root through the native file
   system (rover_index_scan) and serialization (rover_index_serialize). Nothing is saved, so the
   store is not changed and disk writes do not enter the times. Running it once per DLL build
   compares the builds on the same disk. Times come from GetTickCount (10-16 ms resolution).
   The NT build compiles XP25 C code with /Gz, so the DLL's exported C functions are __stdcall.
   usage: roverbench_probe.exe <xp25agent.dll> <label> <repeats>   JSON lines to COM1 */
#define WINVER 0x0501
#define _WIN32_WINNT 0x0501
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include "../../components/roverai/indexer/rover_win.h"

typedef void (WINAPI *PATHS_FN)(XP25W_PATHS *);
typedef void (WINAPI *CONFIG_FN)(XP25_CONFIG *);
typedef int (WINAPI *SETTINGS_FN)(ROVER_SETTINGS *, const XP25_CONFIG *, XP25W_PATHS *);
typedef void (WINAPI *FS_FN)(ROVER_FS *, ROVER_SETTINGS *);
typedef void (WINAPI *INDEX_FN)(ROVER_INDEX *);
typedef int (WINAPI *LOAD_FN)(ROVER_INDEX *, const XP25W_PATHS *, char *, size_t);
typedef int (WINAPI *SCAN_FN)(ROVER_INDEX *, const ROVER_FS *, const ROVER_SCAN_CONFIG *, ROVER_SCAN_STATS *, unsigned long);
typedef int (WINAPI *SERIALIZE_FN)(const ROVER_INDEX *, XP25_BUF *);
typedef void (WINAPI *BUF_FN)(XP25_BUF *);

/* Through void (*)(void): the generic function pointer type a FARPROC may be converted to. */
#define PROC(type, name) ((type)(void (*)(void))GetProcAddress(dll, name))

static HANDLE serial;
static XP25W_PATHS paths;
static XP25_CONFIG config;
static ROVER_SETTINGS settings;

static void put(const char *s)
{
    DWORD n;
    WriteFile(serial, s, lstrlenA(s), &n, NULL);
}

void WINAPI ProbeMain(void)
{
    int argc = 0, repeats, r;
    WCHAR **argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    HMODULE dll;
    char label[32], s[400];
    PATHS_FN get_paths;
    CONFIG_FN load_config;
    SETTINGS_FN settings_init;
    FS_FN win_fs;
    INDEX_FN index_init, index_free;
    LOAD_FN store_load;
    SCAN_FN scan;
    SERIALIZE_FN serialize;
    BUF_FN buf_init, buf_free;
    ROVER_FS fs;
    serial = CreateFileA("COM1", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (serial == INVALID_HANDLE_VALUE) ExitProcess(90);
    if (!argv || argc < 4) { put("ROVERBENCH_USAGE\r\n"); ExitProcess(2); }
    WideCharToMultiByte(CP_ACP, 0, argv[2], -1, label, sizeof(label), NULL, NULL);
    repeats = 0;
    for (r = 0; argv[3][r] >= L'0' && argv[3][r] <= L'9'; ++r) repeats = repeats * 10 + (argv[3][r] - L'0');
    dll = LoadLibraryW(argv[1]);
    get_paths = PROC(PATHS_FN, "xp25w_paths");
    load_config = PROC(CONFIG_FN, "xp25w_config_load");
    settings_init = PROC(SETTINGS_FN, "rover_settings_init");
    win_fs = PROC(FS_FN, "rover_win_fs");
    index_init = PROC(INDEX_FN, "rover_index_init");
    index_free = PROC(INDEX_FN, "rover_index_free");
    store_load = PROC(LOAD_FN, "rover_store_load");
    scan = PROC(SCAN_FN, "rover_index_scan");
    serialize = PROC(SERIALIZE_FN, "rover_index_serialize");
    buf_init = PROC(BUF_FN, "xp25_buf_init");
    buf_free = PROC(BUF_FN, "xp25_buf_free");
    if (!dll || !get_paths || !load_config || !settings_init || !win_fs || !index_init || !index_free || !store_load ||
        !scan || !serialize || !buf_init || !buf_free) { put("ROVERBENCH_DLL_UNUSABLE\r\n"); ExitProcess(3); }
    get_paths(&paths);
    load_config(&config);
    /* The structures are shared with the DLL; a layout mismatch would show here. */
    if (!settings_init(&settings, &config, &paths) || !settings.root_count || settings.root_count > ROVER_MAX_ROOTS ||
        settings.scan.roots != (const char **)settings.roots || settings.scan.root_count != settings.root_count) {
        put("ROVERBENCH_SETTINGS_UNUSABLE\r\n");
        ExitProcess(4);
    }
    win_fs(&fs, &settings);
    for (r = 1; r <= repeats; ++r) {
        ROVER_INDEX index;
        ROVER_SCAN_STATS stats;
        XP25_BUF out;
        char error[96];
        DWORD t0, t1, t2, t3;
        int loaded, scanned, serialized;
        index_init(&index);
        t0 = GetTickCount();
        loaded = store_load(&index, &paths, error, sizeof(error));
        t1 = GetTickCount();
        scanned = scan(&index, &fs, &settings.scan, &stats, 1795000000UL);
        t2 = GetTickCount();
        buf_init(&out);
        serialized = serialize(&index, &out);
        t3 = GetTickCount();
        wsprintfA(s, "{\"roverbench\":\"%s\",\"run\":%d,\"loaded\":%d,\"scanned\":%d,\"serialized\":%d,\"load_ms\":%lu,"
                     "\"scan_ms\":%lu,\"serialize_ms\":%lu,\"entries\":%lu,\"directories\":%lu,\"files\":%lu,\"added\":%lu,"
                     "\"updated\":%lu,\"removed\":%lu,\"bytes\":%lu}\r\n", label, r, loaded, scanned, serialized, t1 - t0, t2 - t1,
                  t3 - t2, (unsigned long)index.count, stats.directories, stats.files, stats.added, stats.updated, stats.removed,
                  (unsigned long)out.len);
        put(s);
        buf_free(&out);
        index_free(&index);
    }
    CloseHandle(serial);
    ExitProcess(0);
}
