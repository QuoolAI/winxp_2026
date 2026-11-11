/* XP25 AI runtime: file_operations. Paths are canonicalized before the
   policy check; changes require approval and deletions go to the Recycle Bin. */
#include <windows.h>
#include <shellapi.h>
#include <string.h>
#include "win_tools.h"

#define READ_LIMIT (256 * 1024)

typedef struct {
    WCHAR path[MAX_PATH], dest[MAX_PATH];
    char u_path[MAX_PATH * 3], u_dest[MAX_PATH * 3];
    int has_dest;
} TARGETS;

static const char *policy_op(const char *action)
{
    return !strcmp(action, "edit_line") ? "write_text" : action;
}

static int resolve(const XP25_JNODE *args, TARGETS *t, char *reason, size_t size)
{
    const char *action = tool_arg(args, "action", ""), *dest = tool_arg(args, "destination", NULL);
    const char *new_name = tool_arg(args, "new_name", NULL);
    memset(t, 0, sizeof(*t));
    if (!xp25w_full_path(tool_arg(args, "path", ""), t->path, MAX_PATH, t->u_path, sizeof(t->u_path))) {
        lstrcpynA(reason, "The path is not a valid local path.", (int)size);
        return 0;
    }
    if (!strcmp(action, "rename")) {
        WCHAR *slash;
        if (!new_name || !*new_name || strpbrk(new_name, "\\/:*?\"<>|")) {
            lstrcpynA(reason, "rename needs a plain new_name without folders.", (int)size);
            return 0;
        }
        lstrcpyW(t->dest, t->path);
        slash = wcsrchr(t->dest, L'\\');
        if (!slash) return 0;
        slash[1] = 0;
        xp25w_copy_wide(slash + 1, (size_t)(MAX_PATH - (slash + 1 - t->dest)), new_name);
        xp25w_copy_utf8(t->u_dest, sizeof(t->u_dest), t->dest);
        t->has_dest = 1;
    } else if (!strcmp(action, "copy") || !strcmp(action, "move")) {
        if (!dest || !xp25w_full_path(dest, t->dest, MAX_PATH, t->u_dest, sizeof(t->u_dest))) {
            lstrcpynA(reason, "copy and move need a valid destination path.", (int)size);
            return 0;
        }
        t->has_dest = 1;
    }
    return 1;
}

int classify_files(const XP25_TOOL *tool, const XP25_JNODE *args, XP25_PROPOSAL *p)
{
    XP25W_TOOLS *ctx = TOOL_CONTEXT(tool);
    const char *action = tool_arg(args, "action", "");
    char reason[200], reason2[200];
    TARGETS t;
    XP25_BUF command, effects;
    if (!resolve(args, &t, reason, sizeof(reason))) { xp25_proposal_deny(p, reason); return 1; }
    p->perm = xp25_policy_file(policy_op(action), t.u_path, &ctx->paths->policy, reason, sizeof(reason));
    if (p->perm != XP25_PERM_DENIED && t.has_dest) {
        XP25_PERM second = xp25_policy_file("write_text", t.u_dest, &ctx->paths->policy, reason2, sizeof(reason2));
        if (!strcmp(action, "copy") && p->perm == XP25_PERM_READ) p->perm = XP25_PERM_APPROVAL;
        if (second > p->perm) { p->perm = second; lstrcpynA(reason, reason2, sizeof(reason)); }
    }
    if (p->perm == XP25_PERM_DENIED) { xp25_proposal_deny(p, reason); return 1; }
    xp25_buf_init(&command);
    xp25_buf_init(&effects);
    xp25_buf_puts(&effects, reason);
    if (!strcmp(action, "read_text")) {
        xp25_buf_puts(&command, "Read the text of ");
        xp25_buf_puts(&command, t.u_path);
        xp25_buf_puts(&effects, " Its content is shown to the assistant; nothing is changed.");
    } else if (!strcmp(action, "edit_line")) {
        xp25_buf_puts(&command, "Edit line ");
        xp25_buf_i64(&command, tool_int(args, "line", 0, 0, 1000000));
        xp25_buf_puts(&command, " of ");
        xp25_buf_puts(&command, t.u_path);
        xp25_buf_puts(&effects, " Replace \"");
        xp25_buf_puts(&effects, tool_arg(args, "old_text", ""));
        xp25_buf_puts(&effects, "\" with \"");
        xp25_buf_puts(&effects, tool_arg(args, "new_text", ""));
        xp25_buf_puts(&effects, "\". The original is kept as a .bak copy.");
    } else if (!strcmp(action, "write_text")) {
        xp25_buf_puts(&command, "Write ");
        xp25_buf_u64(&command, (xp25_u64)strlen(tool_arg(args, "content", "")));
        xp25_buf_puts(&command, " bytes of text to ");
        xp25_buf_puts(&command, t.u_path);
        xp25_buf_puts(&effects, " Any existing file is replaced; the original is kept as a .bak copy.");
    } else if (!strcmp(action, "delete")) {
        xp25_buf_puts(&command, "Delete ");
        xp25_buf_puts(&command, t.u_path);
        xp25_buf_puts(&effects, " It is moved to the Recycle Bin and can be restored.");
    } else if (t.has_dest) {
        xp25_buf_puts(&command, !strcmp(action, "copy") ? "Copy " : !strcmp(action, "move") ? "Move " : "Rename ");
        xp25_buf_puts(&command, t.u_path);
        xp25_buf_puts(&command, " to ");
        xp25_buf_puts(&command, t.u_dest);
        xp25_buf_puts(&effects, " Existing files are never overwritten.");
    } else if (!strcmp(action, "clean_temp")) {
        xp25_buf_puts(&command, "Delete files older than one day from ");
        xp25_buf_puts(&command, t.u_path);
        xp25_buf_puts(&effects, " Files that are in use are skipped.");
    } else {
        xp25_buf_puts(&command, action);
        xp25_buf_putc(&command, ' ');
        xp25_buf_puts(&command, t.u_path);
    }
    tool_proposal(p, p->perm == XP25_PERM_READ ? "Read a file" : "Change files", xp25_buf_cstr(&command),
                  t.u_path, xp25_buf_cstr(&effects));
    xp25_buf_free(&command);
    xp25_buf_free(&effects);
    return 1;
}

/* Length of the valid UTF-8 text, ignoring an incomplete final character
   (the read may stop mid-character); (size_t)-1 when the bytes are not UTF-8. */
static size_t utf8_length(const unsigned char *s, size_t n)
{
    size_t i = 0;
    while (i < n) {
        unsigned char c = s[i];
        size_t extra = c < 0x80 ? 0 : (c & 0xE0) == 0xC0 ? 1 : (c & 0xF0) == 0xE0 ? 2 : (c & 0xF8) == 0xF0 ? 3 : 9;
        size_t k;
        if (extra == 9) return (size_t)-1;
        if (i + extra >= n) return extra ? i : n;
        for (k = 1; k <= extra; ++k) if ((s[i + k] & 0xC0) != 0x80) return (size_t)-1;
        i += extra + 1;
    }
    return n;
}

/* Text of a file as UTF-8; returns 0 for binary content. */
static int decode(const char *raw, DWORD n, XP25_BUF *out, const char **encoding)
{
    DWORD i, probe = n < 8192 ? n : 8192;
    if (n >= 2 && (unsigned char)raw[0] == 0xFF && (unsigned char)raw[1] == 0xFE) {
        WCHAR *wide = (WCHAR *)xp25_alloc(n + 2);
        if (!wide) return 0;
        memcpy(wide, raw + 2, n - 2);
        *encoding = "utf-16le";
        xp25w_buf_wide(out, wide);
        xp25_free(wide);
        return 1;
    }
    if (n >= 3 && (unsigned char)raw[0] == 0xEF && (unsigned char)raw[1] == 0xBB && (unsigned char)raw[2] == 0xBF) {
        *encoding = "utf-8";
        return xp25_buf_append(out, raw + 3, n - 3);
    }
    for (i = 0; i < probe; ++i) if (!raw[i]) return 0;
    {
        size_t valid = utf8_length((const unsigned char *)raw, n);
        if (valid != (size_t)-1) { *encoding = "utf-8"; return xp25_buf_append(out, raw, valid); }
    }
    {
        int count = MultiByteToWideChar(CP_ACP, 0, raw, (int)n, NULL, 0);
        WCHAR *wide = count > 0 ? (WCHAR *)xp25_alloc(((size_t)count + 1) * sizeof(WCHAR)) : NULL;
        if (!wide) return 0;
        MultiByteToWideChar(CP_ACP, 0, raw, (int)n, wide, count);
        *encoding = "ansi";
        xp25w_buf_wide(out, wide);
        xp25_free(wide);
        return 1;
    }
}

static void times(XP25_JW *w, const WIN32_FILE_ATTRIBUTE_DATA *a)
{
    char stamp[20];
    xp25w_format_filetime(&a->ftLastWriteTime, stamp);
    xp25_jw_key(w, "modified"); xp25_jw_str(w, stamp);
    xp25w_format_filetime(&a->ftCreationTime, stamp);
    xp25_jw_key(w, "created"); xp25_jw_str(w, stamp);
}

static int do_stat(const TARGETS *t, XP25_BUF *out)
{
    WIN32_FILE_ATTRIBUTE_DATA a;
    XP25_JW w;
    if (!GetFileAttributesExW(t->path, GetFileExInfoStandard, &a))
        return tool_win32_error(out, "not_found", "Could not read the file attributes", GetLastError());
    tool_ok_begin(&w, out);
    xp25_jw_key(&w, "path"); xp25_jw_str(&w, t->u_path);
    xp25_jw_key(&w, "directory"); xp25_jw_bool(&w, (a.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0);
    xp25_jw_key(&w, "size"); xp25_jw_u64(&w, ((xp25_u64)a.nFileSizeHigh << 32) | a.nFileSizeLow);
    xp25_jw_key(&w, "read_only"); xp25_jw_bool(&w, (a.dwFileAttributes & FILE_ATTRIBUTE_READONLY) != 0);
    xp25_jw_key(&w, "hidden"); xp25_jw_bool(&w, (a.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) != 0);
    times(&w, &a);
    return tool_finish(&w, out);
}

static int do_list(const TARGETS *t, XP25_BUF *out)
{
    WCHAR pattern[MAX_PATH + 4];
    WIN32_FIND_DATAW fd;
    HANDLE find;
    XP25_JW w;
    int n = 0;
    if (lstrlenW(t->path) > MAX_PATH - 3) return 0;
    lstrcpyW(pattern, t->path);
    lstrcatW(pattern, t->path[lstrlenW(t->path) - 1] == L'\\' ? L"*" : L"\\*");
    find = FindFirstFileW(pattern, &fd);
    if (find == INVALID_HANDLE_VALUE) return tool_win32_error(out, "list_failed", "Could not list the folder", GetLastError());
    tool_ok_begin(&w, out);
    xp25_jw_key(&w, "path"); xp25_jw_str(&w, t->u_path);
    xp25_jw_key(&w, "entries");
    xp25_jw_arr(&w);
    do {
        char name[MAX_PATH * 3], stamp[20];
        if (!lstrcmpW(fd.cFileName, L".") || !lstrcmpW(fd.cFileName, L"..")) continue;
        if (++n > 300) break;
        xp25w_copy_utf8(name, sizeof(name), fd.cFileName);
        xp25w_format_filetime(&fd.ftLastWriteTime, stamp);
        xp25_jw_obj(&w);
        xp25_jw_key(&w, "name"); xp25_jw_str(&w, name);
        xp25_jw_key(&w, "directory"); xp25_jw_bool(&w, (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0);
        xp25_jw_key(&w, "size"); xp25_jw_u64(&w, ((xp25_u64)fd.nFileSizeHigh << 32) | fd.nFileSizeLow);
        xp25_jw_key(&w, "modified"); xp25_jw_str(&w, stamp);
        xp25_jw_end(&w);
    } while (FindNextFileW(find, &fd));
    FindClose(find);
    xp25_jw_end(&w);
    xp25_jw_key(&w, "truncated"); xp25_jw_bool(&w, n > 300);
    return tool_finish(&w, out);
}

static int do_read(const TARGETS *t, long max_bytes, XP25_BUF *out)
{
    char *raw;
    int truncated;
    DWORD n = xp25w_read_file(t->path, &raw, (DWORD)max_bytes, &truncated);
    XP25_BUF text;
    const char *encoding = "utf-8";
    XP25_JW w;
    if (n == (DWORD)-1) return tool_win32_error(out, "read_failed", "Could not read the file", GetLastError());
    xp25_buf_init(&text);
    if (!decode(raw, n, &text, &encoding)) {
        xp25_free(raw);
        xp25_buf_free(&text);
        xp25_result_error(out, "binary_file", "The file is not a text file.");
        return 0;
    }
    xp25_free(raw);
    tool_ok_begin(&w, out);
    xp25_jw_key(&w, "path"); xp25_jw_str(&w, t->u_path);
    xp25_jw_key(&w, "bytes"); xp25_jw_u64(&w, n);
    xp25_jw_key(&w, "truncated"); xp25_jw_bool(&w, truncated);
    xp25_jw_key(&w, "encoding"); xp25_jw_str(&w, encoding);
    xp25_jw_key(&w, "text"); xp25_jw_str(&w, xp25_buf_cstr(&text));
    xp25_buf_free(&text);
    return tool_finish(&w, out);
}

static void backup_name(const WCHAR *path, WCHAR *out)
{
    lstrcpynW(out, path, MAX_PATH - 5);
    lstrcatW(out, L".bak");
}

static int do_edit_line(const TARGETS *t, const XP25_JNODE *args, XP25_BUF *out)
{
    long line = tool_int(args, "line", 0, 0, 1000000);
    const char *old_text = tool_arg(args, "old_text", NULL), *new_text = tool_arg(args, "new_text", NULL);
    char *raw, *start, *end, *again = NULL;
    int truncated, verified = 0;
    long current = 1;
    DWORD n;
    WCHAR backup[MAX_PATH];
    XP25_BUF updated;
    XP25_JW w;
    char u_backup[MAX_PATH * 3];
    if (line < 1 || !old_text || !new_text || strchr(new_text, '\n') || strchr(new_text, '\r')) {
        xp25_result_error(out, "bad_arguments", "edit_line needs line, old_text and a single-line new_text.");
        return 0;
    }
    n = xp25w_read_file(t->path, &raw, READ_LIMIT, &truncated);
    if (n == (DWORD)-1) return tool_win32_error(out, "read_failed", "Could not read the file", GetLastError());
    if (truncated || memchr(raw, 0, n)) {
        xp25_free(raw);
        xp25_result_error(out, "unsupported_file", "Only text files up to 256 KB without NUL bytes can be edited.");
        return 0;
    }
    for (start = raw; current < line && start; ++current) {
        start = strchr(start, '\n');
        if (start) ++start;
    }
    if (!start || !*start) { xp25_free(raw); xp25_result_error(out, "no_such_line", "The file has fewer lines."); return 0; }
    for (end = start; *end && *end != '\n' && *end != '\r'; ++end) {}
    if ((size_t)(end - start) != strlen(old_text) || memcmp(start, old_text, (size_t)(end - start))) {
        xp25_free(raw);
        xp25_result_error(out, "line_changed", "The line no longer contains the expected text; nothing was changed.");
        return 0;
    }
    xp25_buf_init(&updated);
    xp25_buf_append(&updated, raw, (size_t)(start - raw));
    xp25_buf_puts(&updated, new_text);
    xp25_buf_puts(&updated, end);
    backup_name(t->path, backup);
    if (!CopyFileW(t->path, backup, FALSE)) {
        DWORD error = GetLastError();
        xp25_free(raw);
        xp25_buf_free(&updated);
        return tool_win32_error(out, "backup_failed", "Could not save the backup copy", error);
    }
    if (!xp25_buf_ok(&updated) || !xp25w_write_file_atomic(t->path, updated.data, (DWORD)updated.len)) {
        DWORD error = GetLastError();
        xp25_free(raw);
        xp25_buf_free(&updated);
        return tool_win32_error(out, "write_failed", "Could not write the file", error);
    }
    if (xp25w_read_file(t->path, &again, READ_LIMIT, &truncated) == updated.len && !memcmp(again, updated.data, updated.len))
        verified = 1;
    xp25_free(again);
    xp25_free(raw);
    xp25_buf_free(&updated);
    xp25w_copy_utf8(u_backup, sizeof(u_backup), backup);
    tool_ok_begin(&w, out);
    xp25_jw_key(&w, "path"); xp25_jw_str(&w, t->u_path);
    xp25_jw_key(&w, "line"); xp25_jw_i64(&w, line);
    xp25_jw_key(&w, "old_text"); xp25_jw_str(&w, old_text);
    xp25_jw_key(&w, "new_text"); xp25_jw_str(&w, new_text);
    xp25_jw_key(&w, "backup"); xp25_jw_str(&w, u_backup);
    xp25_jw_key(&w, "verified"); xp25_jw_bool(&w, verified);
    return tool_finish(&w, out);
}

static int do_write(const TARGETS *t, const XP25_JNODE *args, XP25_BUF *out)
{
    const char *content = tool_arg(args, "content", NULL);
    WCHAR backup[MAX_PATH];
    XP25_JW w;
    int backed_up = 0;
    if (!content) { xp25_result_error(out, "bad_arguments", "write_text needs content."); return 0; }
    if (GetFileAttributesW(t->path) != INVALID_FILE_ATTRIBUTES) {
        backup_name(t->path, backup);
        if (!CopyFileW(t->path, backup, FALSE)) return tool_win32_error(out, "backup_failed", "Could not save the backup copy", GetLastError());
        backed_up = 1;
    }
    if (!xp25w_write_file_atomic(t->path, content, (DWORD)strlen(content)))
        return tool_win32_error(out, "write_failed", "Could not write the file", GetLastError());
    tool_ok_begin(&w, out);
    xp25_jw_key(&w, "path"); xp25_jw_str(&w, t->u_path);
    xp25_jw_key(&w, "bytes"); xp25_jw_u64(&w, (xp25_u64)strlen(content));
    xp25_jw_key(&w, "backup_saved"); xp25_jw_bool(&w, backed_up);
    return tool_finish(&w, out);
}

static int do_delete(const TARGETS *t, XP25_BUF *out)
{
    WCHAR from[MAX_PATH + 2];
    SHFILEOPSTRUCTW op;
    XP25_JW w;
    int status;
    memset(from, 0, sizeof(from));
    lstrcpyW(from, t->path);
    memset(&op, 0, sizeof(op));
    op.wFunc = FO_DELETE;
    op.pFrom = from;
    op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI;
    if (GetFileAttributesW(t->path) == INVALID_FILE_ATTRIBUTES)
        return tool_win32_error(out, "not_found", "The file does not exist", GetLastError());
    status = SHFileOperationW(&op);
    if (status || op.fAnyOperationsAborted || GetFileAttributesW(t->path) != INVALID_FILE_ATTRIBUTES) {
        xp25_result_error(out, "delete_failed", "Windows did not move the item to the Recycle Bin.");
        return 0;
    }
    tool_ok_begin(&w, out);
    xp25_jw_key(&w, "path"); xp25_jw_str(&w, t->u_path);
    xp25_jw_key(&w, "recycled"); xp25_jw_bool(&w, 1);
    return tool_finish(&w, out);
}

static int do_clean_temp(const TARGETS *t, XP25_BUF *out)
{
    WCHAR pattern[MAX_PATH + 4], file[MAX_PATH * 2];
    WIN32_FIND_DATAW fd;
    HANDLE find;
    FILETIME now_ft;
    ULARGE_INTEGER now, when;
    unsigned long deleted = 0, skipped = 0;
    xp25_u64 bytes = 0;
    XP25_JW w;
    lstrcpyW(pattern, t->path);
    lstrcatW(pattern, L"\\*");
    GetSystemTimeAsFileTime(&now_ft);
    now.LowPart = now_ft.dwLowDateTime;
    now.HighPart = now_ft.dwHighDateTime;
    find = FindFirstFileW(pattern, &fd);
    if (find != INVALID_HANDLE_VALUE) {
        do {
            if (fd.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) continue;
            when.LowPart = fd.ftLastWriteTime.dwLowDateTime;
            when.HighPart = fd.ftLastWriteTime.dwHighDateTime;
            if (now.QuadPart - when.QuadPart < (ULONGLONG)86400 * 10000000UL) continue;
            lstrcpyW(file, t->path);
            lstrcatW(file, L"\\");
            lstrcatW(file, fd.cFileName);
            if (DeleteFileW(file)) {
                ++deleted;
                bytes += ((xp25_u64)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            } else ++skipped;
        } while (deleted + skipped < 20000 && FindNextFileW(find, &fd));
        FindClose(find);
    }
    tool_ok_begin(&w, out);
    xp25_jw_key(&w, "path"); xp25_jw_str(&w, t->u_path);
    xp25_jw_key(&w, "deleted_files"); xp25_jw_u64(&w, deleted);
    xp25_jw_key(&w, "deleted_bytes"); xp25_jw_u64(&w, bytes);
    xp25_jw_key(&w, "skipped_in_use"); xp25_jw_u64(&w, skipped);
    return tool_finish(&w, out);
}

int tool_files(const XP25_TOOL *tool, const XP25_JNODE *args, XP25_BUF *out, XP25_EGRESS *egress)
{
    XP25W_TOOLS *ctx = TOOL_CONTEXT(tool);
    const char *action = tool_arg(args, "action", "");
    char reason[200];
    TARGETS t;
    XP25_JW w;
    if (!resolve(args, &t, reason, sizeof(reason))) { xp25_result_error(out, "bad_path", reason); return 0; }
    /* Re-check at execution time with the same canonical paths. */
    if (xp25_policy_file(policy_op(action), t.u_path, &ctx->paths->policy, reason, sizeof(reason)) == XP25_PERM_DENIED ||
        (t.has_dest && xp25_policy_file("write_text", t.u_dest, &ctx->paths->policy, reason, sizeof(reason)) == XP25_PERM_DENIED)) {
        xp25_result_error(out, "permission_denied", reason);
        return 0;
    }
    if (xp25_policy_file(policy_op(action), t.u_path, &ctx->paths->policy, reason, sizeof(reason)) == XP25_PERM_PRIVILEGED) {
        xp25_result_error(out, "broker_unsupported",
                          "This change needs administrator rights; the XP25 broker only performs service changes.");
        return 0;
    }
    if (!strcmp(action, "stat")) return do_stat(&t, out);
    if (!strcmp(action, "list")) return do_list(&t, out);
    *egress = XP25_EGRESS_SENSITIVE;
    if (!strcmp(action, "read_text")) return do_read(&t, tool_int(args, "max_bytes", 16384, 1, READ_LIMIT), out);
    if (!strcmp(action, "edit_line")) return do_edit_line(&t, args, out);
    if (!strcmp(action, "write_text")) return do_write(&t, args, out);
    if (!strcmp(action, "delete")) return do_delete(&t, out);
    if (!strcmp(action, "clean_temp")) return do_clean_temp(&t, out);
    if (!strcmp(action, "mkdir")) {
        if (!CreateDirectoryW(t.path, NULL)) return tool_win32_error(out, "mkdir_failed", "Could not create the folder", GetLastError());
    } else if (!strcmp(action, "copy")) {
        if (!CopyFileW(t.path, t.dest, TRUE)) return tool_win32_error(out, "copy_failed", "Could not copy", GetLastError());
    } else if (!strcmp(action, "move") || !strcmp(action, "rename")) {
        if (!MoveFileExW(t.path, t.dest, MOVEFILE_COPY_ALLOWED)) return tool_win32_error(out, "move_failed", "Could not move", GetLastError());
    } else {
        xp25_result_error(out, "bad_action", "Unknown file action.");
        return 0;
    }
    tool_ok_begin(&w, out);
    xp25_jw_key(&w, "action"); xp25_jw_str(&w, action);
    xp25_jw_key(&w, "path"); xp25_jw_str(&w, t.u_path);
    if (t.has_dest) { xp25_jw_key(&w, "destination"); xp25_jw_str(&w, t.u_dest); }
    return tool_finish(&w, out);
}
