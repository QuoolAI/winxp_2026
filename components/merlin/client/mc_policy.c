/* MerlinClient.dll: the per-user Control Panel policy that retires the Security
   Center and Automatic Updates pages.

   The image's shell32 (an SP3 binary) shows "Security Center" as a direct link
   to wscui.cpl, whatever else is registered in that category; HKLM's
   "don't load" list only hides the applets' icons. The documented policy
   "Hide specified Control Panel items" removes the link: DisallowCPL = 1 and
   the file names under ...\Policies\Explorer\DisallowCpl. shell32 reads that
   list from HKEY_CURRENT_USER only, so it is written into every user hive:
   the loaded ones, the profiles in ProfileList (loaded with RegLoadKey) and
   Default User (new accounts). Each hive keeps its previous DisallowCPL under
   Software\XP25\MerlinAI so removal restores it; only MerlinAI's own list
   entries are deleted. Evidence: .work/merlin-20261121/experiments/seccenter-01. */
#include <windows.h>
#include "mc_internal.h"

#define POLICY_EXPLORER L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"
#define POLICY_LIST L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowCpl"
#define USER_SAVED L"Software\\XP25\\MerlinAI"
#define PROFILE_LIST L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"
#define SAVED_ABSENT 0xFFFFFFFFUL
#define TEMP_HIVE L"XP25MerlinPolicyHive"

static const WCHAR *const hidden[2][2] = {
    { L"XP25 MerlinAI: Security Center", L"wscui.cpl" },
    { L"XP25 MerlinAI: Automatic Updates", L"wuaucpl.cpl" },
};

static DWORD query_dword(HKEY key, const WCHAR *name, DWORD *value)
{
    DWORD type, size = sizeof(*value), e = (DWORD)RegQueryValueExW(key, name, NULL, &type, (BYTE *)value, &size);
    return !e && type != REG_DWORD ? ERROR_INVALID_DATA : e;
}

DWORD MERLINAPI MerlinUserPolicy(HKEY root, BOOL apply)
{
    HKEY explorer, list = NULL, saved;
    DWORD e, value, previous;
    int i;
    if (!apply) {
        if (!RegOpenKeyExW(root, POLICY_LIST, 0, KEY_SET_VALUE, &list)) {
            for (i = 0; i < 2; ++i) RegDeleteValueW(list, hidden[i][0]);
            RegCloseKey(list);
        }
        if (RegOpenKeyExW(root, USER_SAVED, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &saved)) return 0;
        e = 0;
        if (!query_dword(saved, L"Saved.DisallowCPL", &previous)) {
            e = (DWORD)RegOpenKeyExW(root, POLICY_EXPLORER, 0, KEY_SET_VALUE, &explorer);
            if (!e) {
                e = previous == SAVED_ABSENT ? (DWORD)RegDeleteValueW(explorer, L"DisallowCPL")
                                             : (DWORD)RegSetValueExW(explorer, L"DisallowCPL", 0, REG_DWORD, (const BYTE *)&previous,
                                                                     sizeof(previous));
                RegCloseKey(explorer);
            }
            if (e == ERROR_FILE_NOT_FOUND) e = 0;
            if (!e) RegDeleteValueW(saved, L"Saved.DisallowCPL");
        }
        RegCloseKey(saved);
        return e;
    }
    e = (DWORD)RegCreateKeyExW(root, POLICY_EXPLORER, 0, NULL, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, NULL, &explorer, NULL);
    if (e) return e;
    e = (DWORD)RegCreateKeyExW(root, USER_SAVED, 0, NULL, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, NULL, &saved, NULL);
    if (e) {
        RegCloseKey(explorer);
        return e;
    }
    /* Saved once: applying again (a reinstall) keeps the user's original setting. */
    if (query_dword(saved, L"Saved.DisallowCPL", &previous)) {
        previous = query_dword(explorer, L"DisallowCPL", &value) ? SAVED_ABSENT : value;
        e = (DWORD)RegSetValueExW(saved, L"Saved.DisallowCPL", 0, REG_DWORD, (const BYTE *)&previous, sizeof(previous));
    }
    value = 1;
    if (!e) e = (DWORD)RegSetValueExW(explorer, L"DisallowCPL", 0, REG_DWORD, (const BYTE *)&value, sizeof(value));
    if (!e) e = (DWORD)RegCreateKeyExW(root, POLICY_LIST, 0, NULL, 0, KEY_SET_VALUE, NULL, &list, NULL);
    if (!e) {
        for (i = 0; i < 2 && !e; ++i)
            e = (DWORD)RegSetValueExW(list, hidden[i][0], 0, REG_SZ, (const BYTE *)hidden[i][1],
                                      (DWORD)(lstrlenW(hidden[i][1]) + 1) * sizeof(WCHAR));
        RegCloseKey(list);
    }
    RegCloseKey(saved);
    RegCloseKey(explorer);
    return e;
}

/* A local or domain account's hive (S-1-5-21-...), not its _Classes hive and not SYSTEM or the service accounts. */
static BOOL user_sid(const WCHAR *name)
{
    int n = lstrlenW(name);
    if (n < 10 || CompareStringW(LOCALE_INVARIANT, NORM_IGNORECASE, name, 9, L"S-1-5-21-", 9) != CSTR_EQUAL) return FALSE;
    return CompareStringW(LOCALE_INVARIANT, NORM_IGNORECASE, name + n - 8, 8, L"_Classes", 8) != CSTR_EQUAL;
}

static void enable_privilege(const WCHAR *name)
{
    HANDLE token;
    TOKEN_PRIVILEGES tp;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) return;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (LookupPrivilegeValueW(NULL, name, &tp.Privileges[0].Luid)) AdjustTokenPrivileges(token, FALSE, &tp, 0, NULL, NULL);
    CloseHandle(token);
}

/* Load <profile>\NTUSER.DAT under HKEY_USERS\TEMP_HIVE, apply or remove, unload. */
static DWORD offline_hive(const WCHAR *profile, BOOL apply)
{
    WCHAR path[MAX_PATH];
    HKEY root;
    DWORD e;
    if (lstrlenW(profile) > MAX_PATH - 14) return ERROR_FILENAME_EXCED_RANGE;
    lstrcpyW(path, profile);
    lstrcatW(path, L"\\NTUSER.DAT");
    if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) return 0;
    e = (DWORD)RegLoadKeyW(HKEY_USERS, TEMP_HIVE, path);
    if (e) return e;
    e = (DWORD)RegOpenKeyExW(HKEY_USERS, TEMP_HIVE, 0, KEY_ALL_ACCESS, &root);
    if (!e) {
        e = MerlinUserPolicy(root, apply);
        RegCloseKey(root);
    }
    RegUnLoadKeyW(HKEY_USERS, TEMP_HIVE);
    return e;
}

static DWORD profile_value(const WCHAR *key, const WCHAR *name, WCHAR *out, DWORD chars)
{
    WCHAR raw[MAX_PATH];
    DWORD e = mc_reg_read_string(HKEY_LOCAL_MACHINE, key, name, raw, MAX_PATH);
    if (e) return e;
    return ExpandEnvironmentStringsW(raw, out, chars) && lstrlenW(out) < (int)chars ? 0 : ERROR_INSUFFICIENT_BUFFER;
}

DWORD MERLINAPI MerlinUserPolicyAll(BOOL apply, MERLIN_POLICY_STATS *stats)
{
    WCHAR name[128], key[200], profile[MAX_PATH], base[MAX_PATH], user[64];
    DWORD i, chars, e;
    HKEY root, list;
    ZeroMemory(stats, sizeof(*stats));
    enable_privilege(SE_RESTORE_NAME);
    enable_privilege(SE_BACKUP_NAME);
    /* Users whose hives are loaded (logged on, or held by a service). */
    for (i = 0; chars = 128, !RegEnumKeyExW(HKEY_USERS, i, name, &chars, NULL, NULL, NULL, NULL); ++i) {
        if (!user_sid(name)) continue;
        e = (DWORD)RegOpenKeyExW(HKEY_USERS, name, 0, KEY_ALL_ACCESS, &root);
        if (!e) {
            e = MerlinUserPolicy(root, apply);
            RegCloseKey(root);
        }
        if (e) {
            ++stats->failed;
            stats->last_error = e;
        } else ++stats->loaded;
    }
    /* Every other local profile. */
    if (!RegOpenKeyExW(HKEY_LOCAL_MACHINE, PROFILE_LIST, 0, KEY_ENUMERATE_SUB_KEYS, &list)) {
        for (i = 0; chars = 128, !RegEnumKeyExW(list, i, name, &chars, NULL, NULL, NULL, NULL); ++i) {
            if (!user_sid(name)) continue;
            if (!RegOpenKeyExW(HKEY_USERS, name, 0, KEY_QUERY_VALUE, &root)) {   /* loaded: done above */
                RegCloseKey(root);
                continue;
            }
            lstrcpyW(key, PROFILE_LIST L"\\");
            lstrcatW(key, name);
            e = profile_value(key, L"ProfileImagePath", profile, MAX_PATH);
            if (!e) e = offline_hive(profile, apply);
            if (e) {
                ++stats->failed;
                stats->last_error = e;
            } else ++stats->offline;
        }
        RegCloseKey(list);
    }
    /* Default User: accounts created later start with the policy. */
    e = profile_value(PROFILE_LIST, L"ProfilesDirectory", base, MAX_PATH);
    if (!e) e = mc_reg_read_string(HKEY_LOCAL_MACHINE, PROFILE_LIST, L"DefaultUserProfile", user, 64);
    if (!e && lstrlenW(base) + lstrlenW(user) + 2 < MAX_PATH) {
        lstrcpyW(profile, base);
        lstrcatW(profile, L"\\");
        lstrcatW(profile, user);
        e = offline_hive(profile, apply);
    } else if (!e) e = ERROR_FILENAME_EXCED_RANGE;
    if (e) {
        ++stats->failed;
        stats->last_error = e;
    } else stats->default_user = 1;
    return stats->failed ? stats->last_error : 0;
}
