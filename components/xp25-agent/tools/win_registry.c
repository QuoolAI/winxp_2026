/* XP25 AI runtime: registry_read for approved diagnostic locations only. */
#include <windows.h>
#include <string.h>
#include "win_tools.h"

int classify_registry(const XP25_TOOL *tool, const XP25_JNODE *args, XP25_PROPOSAL *p)
{
    char canonical[520], reason[200];
    (void)tool;
    p->perm = xp25_policy_registry(tool_arg(args, "path", ""), canonical, sizeof(canonical), reason, sizeof(reason));
    if (p->perm == XP25_PERM_DENIED) { xp25_proposal_deny(p, reason); return 1; }
    tool_proposal(p, "Read registry", canonical, canonical, "Reads values; nothing is changed.");
    return 1;
}

static int secret_name(const char *name)
{
    static const char *words[] = { "password", "pwd", "secret", "token", "credential", "apikey", "api_key", "protected", NULL };
    size_t i;
    for (i = 0; words[i]; ++i) if (xp25_stristr(name, words[i])) return 1;
    return 0;
}

static void value_json(XP25_JW *w, const char *name, DWORD type, const BYTE *data, DWORD size)
{
    XP25_BUF text;
    xp25_buf_init(&text);
    xp25_jw_obj(w);
    xp25_jw_key(w, "name"); xp25_jw_str(w, name);
    xp25_jw_key(w, "type");
    switch (type) {
    case REG_SZ: case REG_EXPAND_SZ: case REG_MULTI_SZ: {
        const WCHAR *s = (const WCHAR *)data;
        DWORD chars = size / sizeof(WCHAR), i = 0;
        xp25_jw_str(w, type == REG_SZ ? "REG_SZ" : type == REG_EXPAND_SZ ? "REG_EXPAND_SZ" : "REG_MULTI_SZ");
        while (i < chars && s[i]) {
            WCHAR item[1024];
            DWORD n = 0;
            while (i < chars && s[i] && n < 1023) item[n++] = s[i++];
            item[n] = 0;
            if (text.len) xp25_buf_puts(&text, " | ");
            xp25w_buf_wide(&text, item);
            while (i < chars && s[i]) ++i;
            ++i;
            if (type != REG_MULTI_SZ) break;
        }
        break;
    }
    case REG_DWORD:
        xp25_jw_str(w, "REG_DWORD");
        if (size >= 4) {
            DWORD v = *(const DWORD *)data;
            xp25_buf_u64(&text, v);
            xp25_buf_puts(&text, " (0x");
            {
                unsigned char be[4];
                be[0] = (unsigned char)(v >> 24); be[1] = (unsigned char)(v >> 16); be[2] = (unsigned char)(v >> 8); be[3] = (unsigned char)v;
                xp25_buf_hex(&text, be, 4);
            }
            xp25_buf_puts(&text, ")");
        }
        break;
    default:
        xp25_jw_str(w, type == REG_BINARY ? "REG_BINARY" : "REG_OTHER");
        xp25_buf_hex(&text, data, size > 64 ? 64 : size);
        if (size > 64) xp25_buf_puts(&text, "...");
        break;
    }
    xp25_jw_key(w, "data"); xp25_jw_strn(w, xp25_buf_cstr(&text), xp25_utf8_clip(xp25_buf_cstr(&text), 2000));
    xp25_jw_end(w);
    xp25_buf_free(&text);
}

int tool_registry(const XP25_TOOL *tool, const XP25_JNODE *args, XP25_BUF *out, XP25_EGRESS *egress)
{
    char canonical[520], reason[200], name_u[1024];
    const char *only = tool_arg(args, "value", NULL);
    WCHAR *subkey;
    HKEY root, key;
    DWORD i;
    BYTE *data;
    XP25_JW w;
    LONG status;
    (void)tool;
    *egress = XP25_EGRESS_SENSITIVE;
    if (xp25_policy_registry(tool_arg(args, "path", ""), canonical, sizeof(canonical), reason, sizeof(reason)) != XP25_PERM_READ) {
        xp25_result_error(out, "permission_denied", reason);
        return 0;
    }
    root = !strncmp(canonical, "HKLM", 4) ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER;
    subkey = xp25w_wide(canonical[4] == '\\' ? canonical + 5 : "");
    if (!subkey) { xp25_result_error(out, "out_of_memory", "Out of memory."); return 0; }
    status = RegOpenKeyExW(root, subkey, 0, KEY_READ, &key);
    xp25_free(subkey);
    if (status != ERROR_SUCCESS) return tool_win32_error(out, "open_failed", "Could not open the registry key", (DWORD)status);
    data = (BYTE *)xp25_alloc(65536 + 4);
    tool_ok_begin(&w, out);
    xp25_jw_key(&w, "path"); xp25_jw_str(&w, canonical);
    xp25_jw_key(&w, "values");
    xp25_jw_arr(&w);
    for (i = 0; data && i < 200; ++i) {
        WCHAR name[512];
        DWORD name_len = 512, type, size = 65536;
        status = RegEnumValueW(key, i, name, &name_len, NULL, &type, data, &size);
        if (status == ERROR_NO_MORE_ITEMS) break;
        if (status != ERROR_SUCCESS) continue;
        data[size] = data[size + 1] = 0;
        xp25w_copy_utf8(name_u, sizeof(name_u), name);
        if (only && !xp25_strieq(only, name_u)) continue;
        if (secret_name(name_u)) {
            xp25_jw_obj(&w);
            xp25_jw_key(&w, "name"); xp25_jw_str(&w, name_u);
            xp25_jw_key(&w, "type"); xp25_jw_str(&w, "redacted");
            xp25_jw_key(&w, "data"); xp25_jw_str(&w, "[withheld by XP25 policy]");
            xp25_jw_end(&w);
            continue;
        }
        value_json(&w, name_u, type, data, size);
    }
    xp25_jw_end(&w);
    xp25_jw_key(&w, "subkeys");
    xp25_jw_arr(&w);
    for (i = 0; !only && i < 200; ++i) {
        WCHAR name[256];
        DWORD n = 256;
        if (RegEnumKeyExW(key, i, name, &n, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        xp25w_copy_utf8(name_u, sizeof(name_u), name);
        xp25_jw_str(&w, name_u);
    }
    xp25_jw_end(&w);
    xp25_free(data);
    RegCloseKey(key);
    return tool_finish(&w, out);
}
