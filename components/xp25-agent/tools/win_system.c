/* XP25 AI runtime: system_info and disk_diagnostics (kernel32/advapi32 only). */
#include <windows.h>
#include <winioctl.h>
#include <string.h>
#include "win_tools.h"

#ifndef FSCTL_IS_VOLUME_DIRTY
#define FSCTL_IS_VOLUME_DIRTY CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 30, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif
#ifndef VOLUME_IS_DIRTY
#define VOLUME_IS_DIRTY 0x00000001
#endif

static xp25_u64 ft64(const FILETIME *ft)
{
    return ((xp25_u64)ft->dwHighDateTime << 32) | ft->dwLowDateTime;
}

/* Whole-system busy percentage over interval_ms using GetSystemTimes. */
static long cpu_busy(DWORD interval_ms)
{
    FILETIME i1, k1, u1, i2, k2, u2;
    xp25_u64 idle, total;
    if (!GetSystemTimes(&i1, &k1, &u1)) return -1;
    Sleep(interval_ms);
    if (!GetSystemTimes(&i2, &k2, &u2)) return -1;
    idle = ft64(&i2) - ft64(&i1);
    total = (ft64(&k2) - ft64(&k1)) + (ft64(&u2) - ft64(&u1));   /* kernel time includes idle */
    if (!total) return 0;
    return (long)(100 - (idle * 100 + total / 2) / total);
}

static void registry_text(HKEY root, const WCHAR *key, const WCHAR *value, char *out, size_t size)
{
    HKEY h;
    WCHAR data[256];
    DWORD type, bytes = sizeof(data) - sizeof(WCHAR);
    out[0] = 0;
    if (RegOpenKeyExW(root, key, 0, KEY_READ, &h) != ERROR_SUCCESS) return;
    if (RegQueryValueExW(h, value, NULL, &type, (BYTE *)data, &bytes) == ERROR_SUCCESS && type == REG_SZ) {
        WCHAR *p = data;
        data[bytes / sizeof(WCHAR)] = 0;
        while (*p == L' ') ++p;
        xp25w_copy_utf8(out, size, p);
    }
    RegCloseKey(h);
}

static void drives(XP25_JW *w, int details)
{
    WCHAR roots[256], *root;
    DWORD n = GetLogicalDriveStringsW(255, roots);
    if (!n || n > 255) return;
    for (root = roots; *root; root += lstrlenW(root) + 1) {
        ULARGE_INTEGER avail, total, free_bytes;
        WCHAR fs[32], label[64];
        DWORD serial = 0, maxlen, flags = 0;
        char text[64];
        UINT type = GetDriveTypeW(root);
        if (type != DRIVE_FIXED) continue;
        if (!GetDiskFreeSpaceExW(root, &avail, &total, &free_bytes)) continue;
        xp25_jw_obj(w);
        xp25w_copy_utf8(text, sizeof(text), root);
        xp25_jw_key(w, "root"); xp25_jw_str(w, text);
        xp25_jw_key(w, "type"); xp25_jw_str(w, "fixed");
        xp25_jw_key(w, "total_bytes"); xp25_jw_u64(w, total.QuadPart);
        xp25_jw_key(w, "free_bytes"); xp25_jw_u64(w, free_bytes.QuadPart);
        xp25_jw_key(w, "free_percent");
        xp25_jw_u64(w, total.QuadPart ? (free_bytes.QuadPart * 100 + total.QuadPart / 2) / total.QuadPart : 0);
        if (details && GetVolumeInformationW(root, label, 64, &serial, &maxlen, &flags, fs, 32)) {
            WCHAR device[8];
            HANDLE h;
            DWORD dirty = 0, got = 0;
            xp25w_copy_utf8(text, sizeof(text), fs);
            xp25_jw_key(w, "fs"); xp25_jw_str(w, text);
            xp25w_copy_utf8(text, sizeof(text), label);
            xp25_jw_key(w, "label"); xp25_jw_str(w, text);
            xp25_jw_key(w, "compressed"); xp25_jw_bool(w, (flags & FS_VOL_IS_COMPRESSED) != 0);
            /* Dirty bit query needs volume access; report null when Windows refuses it. */
            device[0] = L'\\'; device[1] = L'\\'; device[2] = L'.'; device[3] = L'\\';
            device[4] = root[0]; device[5] = L':'; device[6] = 0;
            h = CreateFileW(device, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
            xp25_jw_key(w, "dirty");
            if (h != INVALID_HANDLE_VALUE &&
                DeviceIoControl(h, FSCTL_IS_VOLUME_DIRTY, NULL, 0, &dirty, sizeof(dirty), &got, NULL))
                xp25_jw_bool(w, (dirty & VOLUME_IS_DIRTY) != 0);
            else xp25_jw_null(w);
            if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
        }
        xp25_jw_end(w);
    }
}

int tool_system_info(const XP25_TOOL *tool, const XP25_JNODE *args, XP25_BUF *out, XP25_EGRESS *egress)
{
    XP25_JW w;
    OSVERSIONINFOEXW os;
    SYSTEM_INFO si;
    MEMORYSTATUSEX mem;
    WCHAR name[MAX_COMPUTERNAME_LENGTH + 1], user[257];
    DWORD n;
    char text[300];
    (void)tool; (void)args; (void)egress;
    memset(&os, 0, sizeof(os));
    os.dwOSVersionInfoSize = sizeof(os);
    GetVersionExW((OSVERSIONINFOW *)&os);
    GetSystemInfo(&si);
    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);
    tool_ok_begin(&w, out);
    xp25_jw_key(&w, "os");
    xp25_jw_obj(&w);
    registry_text(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ProductName", text, sizeof(text));
    xp25_jw_key(&w, "name"); xp25_jw_str(&w, text[0] ? text : "Windows");
    {
        XP25_BUF version;
        xp25_buf_init(&version);
        xp25_buf_u64(&version, os.dwMajorVersion); xp25_buf_putc(&version, '.');
        xp25_buf_u64(&version, os.dwMinorVersion); xp25_buf_putc(&version, '.');
        xp25_buf_u64(&version, os.dwBuildNumber);
        xp25_jw_key(&w, "version"); xp25_jw_str(&w, xp25_buf_cstr(&version));
        xp25_buf_free(&version);
    }
    xp25w_copy_utf8(text, sizeof(text), os.szCSDVersion);
    xp25_jw_key(&w, "service_pack"); xp25_jw_str(&w, text);
    xp25_jw_key(&w, "build"); xp25_jw_u64(&w, os.dwBuildNumber);
    xp25_jw_key(&w, "product_type"); xp25_jw_str(&w, os.wProductType == VER_NT_WORKSTATION ? "workstation" : "server");
    xp25_jw_end(&w);
    n = MAX_COMPUTERNAME_LENGTH + 1;
    if (!GetComputerNameW(name, &n)) name[0] = 0;
    xp25w_copy_utf8(text, sizeof(text), name);
    xp25_jw_key(&w, "computer"); xp25_jw_str(&w, text);
    n = 257;
    if (!GetUserNameW(user, &n)) user[0] = 0;
    xp25w_copy_utf8(text, sizeof(text), user);
    xp25_jw_key(&w, "user"); xp25_jw_str(&w, text);
    xp25_jw_key(&w, "administrator"); xp25_jw_bool(&w, xp25w_is_admin());
    xp25_jw_key(&w, "cpu");
    xp25_jw_obj(&w);
    registry_text(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", L"ProcessorNameString", text, sizeof(text));
    if (!text[0]) registry_text(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", L"Identifier", text, sizeof(text));
    xp25_jw_key(&w, "name"); xp25_jw_str(&w, text);
    xp25_jw_key(&w, "count"); xp25_jw_u64(&w, si.dwNumberOfProcessors);
    xp25_jw_key(&w, "usage_percent"); xp25_jw_i64(&w, cpu_busy(500));
    xp25_jw_end(&w);
    xp25_jw_key(&w, "memory");
    xp25_jw_obj(&w);
    xp25_jw_key(&w, "total_bytes"); xp25_jw_u64(&w, mem.ullTotalPhys);
    xp25_jw_key(&w, "available_bytes"); xp25_jw_u64(&w, mem.ullAvailPhys);
    xp25_jw_key(&w, "load_percent"); xp25_jw_u64(&w, mem.dwMemoryLoad);
    xp25_jw_key(&w, "commit_limit_bytes"); xp25_jw_u64(&w, mem.ullTotalPageFile);
    xp25_jw_key(&w, "commit_available_bytes"); xp25_jw_u64(&w, mem.ullAvailPageFile);
    xp25_jw_end(&w);
    xp25_jw_key(&w, "uptime_seconds"); xp25_jw_u64(&w, GetTickCount() / 1000);
    xp25_jw_key(&w, "drives");
    xp25_jw_arr(&w);
    drives(&w, 0);
    xp25_jw_end(&w);
    return tool_finish(&w, out);
}

int tool_disk(const XP25_TOOL *tool, const XP25_JNODE *args, XP25_BUF *out, XP25_EGRESS *egress)
{
    XP25W_TOOLS *ctx = TOOL_CONTEXT(tool);
    XP25_JW w;
    WCHAR system[MAX_PATH], pattern[MAX_PATH + 4];
    char text[MAX_PATH * 3];
    WIN32_FIND_DATAW fd;
    HANDLE find;
    xp25_u64 bytes = 0;
    unsigned long files = 0;
    (void)args; (void)egress;
    tool_ok_begin(&w, out);
    if (GetWindowsDirectoryW(system, MAX_PATH)) {
        system[3] = 0;
        xp25w_copy_utf8(text, sizeof(text), system);
        xp25_jw_key(&w, "system_drive"); xp25_jw_str(&w, text);
    }
    xp25_jw_key(&w, "volumes");
    xp25_jw_arr(&w);
    drives(&w, 1);
    xp25_jw_end(&w);
    if (ctx->paths->temp[0] && lstrlenW(ctx->paths->temp) < MAX_PATH - 3) {
        lstrcpyW(pattern, ctx->paths->temp);
        lstrcatW(pattern, L"\\*");
        find = FindFirstFileW(pattern, &fd);
        if (find != INVALID_HANDLE_VALUE) {
            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    ++files;
                    bytes += ((xp25_u64)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
                }
            } while (files < 100000 && FindNextFileW(find, &fd));
            FindClose(find);
        }
        xp25_jw_key(&w, "temp");
        xp25_jw_obj(&w);
        xp25_jw_key(&w, "path"); xp25_jw_str(&w, ctx->paths->u_temp);
        xp25_jw_key(&w, "files"); xp25_jw_u64(&w, files);
        xp25_jw_key(&w, "bytes"); xp25_jw_u64(&w, bytes);
        xp25_jw_end(&w);
    }
    return tool_finish(&w, out);
}
