/* XP25 AI runtime: fail-closed permission classification. Portable C89. */
#include <string.h>
#include "xp25_policy.h"

const char xp25_default_service_allowlist[] =
    "Alerter,AudioSrv,BITS,Browser,Dhcp,Dnscache,ERSvc,helpsvc,LanmanServer,LanmanWorkstation,"
    "Messenger,Netman,Nla,Schedule,SharedAccess,Spooler,SSDPSRV,stisvc,Themes,upnphost,"
    "W32Time,WebClient,wuauserv,WZCSVC";

static void say(char *reason, size_t size, const char *text)
{
    size_t n;
    if (!reason || !size) return;
    n = strlen(text);
    if (n >= size) n = size - 1;
    memcpy(reason, text, n);
    reason[n] = 0;
}

/* Collapse runs of whitespace and trim; returns 0 if the result would not fit. */
static int normalize(const char *in, char *out, size_t size)
{
    size_t n = 0;
    int space = 0;
    while (xp25_is_space((unsigned char)*in)) ++in;
    for (; *in; ++in) {
        if (xp25_is_space((unsigned char)*in)) { space = 1; continue; }
        if (space && n) { if (n + 1 >= size) return 0; out[n++] = ' '; }
        space = 0;
        if (n + 1 >= size) return 0;
        out[n++] = (char)xp25_lower((unsigned char)*in);
    }
    out[n] = 0;
    return 1;
}

static int plain_word(const char *s, size_t n, const char *extra)
{
    size_t i;
    if (!n) return 0;
    for (i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)s[i];
        if (!xp25_is_alpha(c) && !xp25_is_digit(c) && !strchr(extra, c)) return 0;
    }
    return 1;
}

static int matches_readonly(const char *cmd)
{
    static const char *exact[] = {
        "ver", "hostname", "ipconfig", "ipconfig /all", "systeminfo", "tasklist", "tasklist /v",
        "tasklist /svc", "netstat -an", "netstat -ano", "netstat -r", "netstat -s", "route print",
        "arp -a", "date /t", "time /t", "vol", "net start", "net config workstation",
        "net statistics workstation", "sc query", "sc query state= all", "driverquery", NULL };
    const char *rest;
    size_t i;
    for (i = 0; exact[i]; ++i)
        if (!strcmp(cmd, exact[i])) return 1;
    if (!strncmp(cmd, "sc query ", 9) && plain_word(cmd + 9, strlen(cmd + 9), "_-")) return 1;
    if (!strncmp(cmd, "sc qc ", 6) && plain_word(cmd + 6, strlen(cmd + 6), "_-")) return 1;
    if (!strncmp(cmd, "nslookup ", 9) && plain_word(cmd + 9, strlen(cmd + 9), ".-")) return 1;
    if (!strncmp(cmd, "ping ", 5)) {
        rest = cmd + 5;
        if (!strncmp(rest, "-n ", 3) && rest[3] >= '1' && rest[3] <= '9' && rest[4] == ' ') rest += 5;
        return plain_word(rest, strlen(rest), ".-");
    }
    if (!strncmp(cmd, "dir", 3) && (!cmd[3] || cmd[3] == ' ')) {
        /* Listing only: no redirection or chaining (checked by the caller) and no /s recursion bombs. */
        return !strstr(cmd, "/s");
    }
    return 0;
}

XP25_PERM xp25_policy_command(const char *command, char *reason, size_t reason_size)
{
    char norm[600];
    const char *p;
    if (!command || !*command) { say(reason, reason_size, "Empty command."); return XP25_PERM_DENIED; }
    if (strlen(command) > 512) { say(reason, reason_size, "Command is longer than 512 characters."); return XP25_PERM_DENIED; }
    for (p = command; *p; ++p)
        if (*p == '\r' || *p == '\n' || ((unsigned char)*p < 0x20 && *p != '\t')) {
            say(reason, reason_size, "Command contains line breaks or control characters.");
            return XP25_PERM_DENIED;
        }
    if (!normalize(command, norm, sizeof(norm)) || !*norm) {
        say(reason, reason_size, "Empty command.");
        return XP25_PERM_DENIED;
    }
    if (strpbrk(norm, "&|<>^%!()`\"") == NULL && matches_readonly(norm)) {
        say(reason, reason_size, "Read-only diagnostic command.");
        return XP25_PERM_READ;
    }
    say(reason, reason_size, "This command may change the system or reveal private data.");
    return XP25_PERM_APPROVAL;
}

static int prefix_component(const char *path, const char *prefix)
{
    size_t n = strlen(prefix);
    return xp25_strnieq(path, prefix, n) && strlen(path) >= n && (path[n] == 0 || path[n] == '\\');
}

XP25_PERM xp25_policy_registry(const char *path, char *canonical, size_t canonical_size,
                               char *reason, size_t reason_size)
{
    static const struct { const char *alias, *root; } roots[] = {
        { "HKEY_LOCAL_MACHINE", "HKLM" }, { "HKLM", "HKLM" },
        { "HKEY_CURRENT_USER", "HKCU" }, { "HKCU", "HKCU" }, { NULL, NULL } };
    static const char *allowed[] = {
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths",
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer",
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies",
        "HKLM\\SOFTWARE\\Policies",
        "HKLM\\SOFTWARE\\XP25",
        "HKLM\\SYSTEM\\CurrentControlSet\\Services",
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\ComputerName",
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management",
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation",
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Windows",
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\ProductOptions",
        "HKLM\\HARDWARE\\DESCRIPTION",
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer",
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies",
        "HKCU\\Software\\Policies",
        "HKCU\\Software\\XP25",
        "HKCU\\Control Panel\\Desktop",
        "HKCU\\Control Panel\\International",
        "HKCU\\Environment",
        NULL };
    static const char *blocked_words[] = { "password", "secret", "credential", "protect", "\\sam",
                                           "\\security", "winlogon", "lsa", "apikey", "token", NULL };
    char buf[520];
    const char *rest = NULL;
    size_t i, n;
    if (!path || !*path || strlen(path) > 500) {
        say(reason, reason_size, "Registry path is empty or too long.");
        return XP25_PERM_DENIED;
    }
    for (i = 0; roots[i].alias; ++i)
        if (prefix_component(path, roots[i].alias)) { rest = path + strlen(roots[i].alias); break; }
    if (!rest) { say(reason, reason_size, "Only HKLM and HKCU locations can be read."); return XP25_PERM_DENIED; }
    strcpy(buf, roots[i].root);
    n = strlen(buf);
    for (; *rest; ++rest) {
        char c = *rest == '/' ? '\\' : *rest;
        if (c == '\\' && n && buf[n - 1] == '\\') continue;
        if (n + 1 >= sizeof(buf)) { say(reason, reason_size, "Registry path is too long."); return XP25_PERM_DENIED; }
        buf[n++] = c;
    }
    while (n > 4 && buf[n - 1] == '\\') --n;
    buf[n] = 0;
    if (canonical && canonical_size) say(canonical, canonical_size, buf);
    for (i = 0; blocked_words[i]; ++i)
        if (xp25_stristr(buf, blocked_words[i])) {
            say(reason, reason_size, "This registry location can hold credentials or security data.");
            return XP25_PERM_DENIED;
        }
    for (i = 0; allowed[i]; ++i)
        if (prefix_component(buf, allowed[i])) {
            say(reason, reason_size, "Approved diagnostic registry location.");
            return XP25_PERM_READ;
        }
    say(reason, reason_size, "This registry location is outside the approved diagnostic locations.");
    return XP25_PERM_DENIED;
}

static int under(const char *path, const char *dir)
{
    return dir && *dir && prefix_component(path, dir);
}

static const char *after(const char *path, const char *dir)
{
    size_t n = strlen(dir);
    return path[n] == '\\' ? path + n + 1 : path + n;
}

int xp25_policy_sensitive_path(const char *path, const XP25_PATHS *paths)
{
    static const char *profile_private[] = {
        "Application Data\\Microsoft\\Protect", "Application Data\\Microsoft\\Credentials",
        "Application Data\\Microsoft\\Crypto", "Application Data\\Microsoft\\SystemCertificates",
        "Local Settings\\Application Data\\Microsoft\\Credentials", "Cookies",
        "Local Settings\\Temporary Internet Files", "Local Settings\\History", "Local Settings\\Temp",
        "NTUSER.DAT", "ntuser.dat.LOG", "ntuser.ini", "PrivacIE", "IETldCache",
        "Local Settings\\Application Data\\Microsoft\\Windows\\UsrClass.dat", "Application Data\\XP25", NULL };
    static const char *anywhere[] = { "System Volume Information", "RECYCLER", "$Recycle.Bin", NULL };
    const char *p;
    size_t i;
    if (!path) return 1;
    for (p = path; *p; ++p) {
        if (p == path || p[-1] == '\\') {
            for (i = 0; anywhere[i]; ++i)
                if (prefix_component(p, anywhere[i])) return 1;
        }
    }
    if (xp25_ends_with_i(path, "\\pagefile.sys") || xp25_ends_with_i(path, "\\hiberfil.sys")) return 1;
    if (paths->windows && *paths->windows) {
        char config[300];
        if (strlen(paths->windows) < 260) {
            strcpy(config, paths->windows);
            strcat(config, "\\system32\\config");
            if (under(path, config)) return 1;
            strcpy(config, paths->windows);
            strcat(config, "\\repair");
            if (under(path, config)) return 1;
        }
    }
    if (paths->secret_store && *paths->secret_store && xp25_strieq(path, paths->secret_store)) return 1;
    if (under(path, paths->profile)) {
        const char *rel = after(path, paths->profile);
        for (i = 0; profile_private[i]; ++i)
            if (prefix_component(rel, profile_private[i]) ||
                (xp25_starts_with_i(rel, "NTUSER.DAT") && !strchr(rel, '\\'))) return 1;
        return 0;
    }
    if (under(path, paths->other_profiles_root)) {
        const char *rel = after(path, paths->other_profiles_root);
        if (!*rel || prefix_component(rel, "All Users")) return 0;
        return 1;   /* other users' profiles, Default User, service profiles */
    }
    return 0;
}

static int nonsensitive_system_text(const char *path, const XP25_PATHS *paths)
{
    static const char *etc[] = { "hosts", "lmhosts.sam", "networks", "protocol", "services", NULL };
    char dir[300];
    size_t i;
    if (!paths->windows || strlen(paths->windows) > 250) return 0;
    strcpy(dir, paths->windows);
    strcat(dir, "\\system32\\drivers\\etc");
    if (under(path, dir)) {
        const char *rel = after(path, dir);
        for (i = 0; etc[i]; ++i)
            if (xp25_strieq(rel, etc[i])) return 1;
    }
    if (under(path, paths->windows)) {
        const char *rel = after(path, paths->windows);
        if (!strchr(rel, '\\') && xp25_ends_with_i(rel, ".log")) return 1;
    }
    if (xp25_strieq(path + (path[0] && path[1] == ':' ? 2 : 0), "\\boot.ini")) return 1;
    return 0;
}

XP25_PERM xp25_policy_file(const char *op, const char *path, const XP25_PATHS *paths,
                           char *reason, size_t reason_size)
{
    int read_op, modify;
    const char *p;
    if (!op || !path || strlen(path) < 3 || strlen(path) > 259) {
        say(reason, reason_size, "A full path shorter than 260 characters is required.");
        return XP25_PERM_DENIED;
    }
    if (!xp25_is_alpha((unsigned char)path[0]) || path[1] != ':' || path[2] != '\\') {
        say(reason, reason_size, "Only local drive paths such as C:\\folder\\file are accepted.");
        return XP25_PERM_DENIED;
    }
    for (p = path + 2; *p; ++p)
        if (*p == ':' || *p == '*' || *p == '?' || *p == '"' || *p == '<' || *p == '>' || *p == '|' ||
            (unsigned char)*p < 0x20 || (*p == '.' && p[1] == '.' && (p[2] == '\\' || !p[2]) && p[-1] == '\\')) {
            say(reason, reason_size, "The path contains reserved characters or traversal.");
            return XP25_PERM_DENIED;
        }
    read_op = !strcmp(op, "stat") || !strcmp(op, "list") || !strcmp(op, "read_text");
    modify = !strcmp(op, "write_text") || !strcmp(op, "copy") || !strcmp(op, "move") ||
             !strcmp(op, "rename") || !strcmp(op, "delete") || !strcmp(op, "mkdir") || !strcmp(op, "clean_temp");
    if (!read_op && !modify) { say(reason, reason_size, "Unknown file operation."); return XP25_PERM_DENIED; }
    if (xp25_policy_sensitive_path(path, paths)) {
        if (!(paths->temp && !strcmp(op, "clean_temp") && xp25_strieq(path, paths->temp))) {
            say(reason, reason_size, "This location holds credentials, registry hives or another user's data.");
            return XP25_PERM_DENIED;
        }
    }
    if (read_op) {
        if (strcmp(op, "read_text")) { say(reason, reason_size, "File metadata only."); return XP25_PERM_READ; }
        if (nonsensitive_system_text(path, paths)) {
            say(reason, reason_size, "Standard Windows configuration text file.");
            return XP25_PERM_READ;
        }
        say(reason, reason_size, "Reading this file's content may expose personal data.");
        return XP25_PERM_APPROVAL;
    }
    if (!strcmp(op, "clean_temp")) {
        if (!paths->temp || !xp25_strieq(path, paths->temp)) {
            say(reason, reason_size, "Temporary-file cleanup is limited to your own TEMP folder.");
            return XP25_PERM_DENIED;
        }
        say(reason, reason_size, "Deletes old files from your TEMP folder.");
        return XP25_PERM_APPROVAL;
    }
    if (under(path, paths->windows) || under(path, paths->program_files)) {
        char hosts[300];
        if (paths->windows && strlen(paths->windows) < 250) {
            strcpy(hosts, paths->windows);
            strcat(hosts, "\\system32\\drivers\\etc\\hosts");
            if (xp25_strieq(path, hosts) && !strcmp(op, "write_text")) {
                say(reason, reason_size, "Changes the system hosts file (administrator rights required).");
                return XP25_PERM_PRIVILEGED;
            }
        }
        say(reason, reason_size, "Windows and Program Files content is not modified by the assistant.");
        return XP25_PERM_DENIED;
    }
    if (strlen(path) <= 3) { say(reason, reason_size, "A drive root cannot be modified."); return XP25_PERM_DENIED; }
    say(reason, reason_size, "Changes files on this computer.");
    return XP25_PERM_APPROVAL;
}

static int in_list(const char *list, const char *name)
{
    size_t n = strlen(name);
    const char *p = list;
    while (p && *p) {
        const char *comma = strchr(p, ',');
        size_t len = comma ? (size_t)(comma - p) : strlen(p);
        while (len && xp25_is_space((unsigned char)*p)) { ++p; --len; }
        while (len && xp25_is_space((unsigned char)p[len - 1])) --len;
        if (len == n && xp25_strnieq(p, name, n)) return 1;
        p = comma ? comma + 1 : NULL;
    }
    return 0;
}

XP25_PERM xp25_policy_service(const char *name, const char *action, const char *allowlist,
                              int is_admin, char *reason, size_t reason_size)
{
    static const char critical[] =
        "RpcSs,DcomLaunch,PlugPlay,Eventlog,SamSs,ProtectedStorage,PolicyAgent,Winmgmt,"
        "TermService,Netlogon,seclogon,XP25Broker,lanmanserver_kernel";
    if (!name || !*name || strlen(name) > 256 || !plain_word(name, strlen(name), "_-. ")) {
        say(reason, reason_size, "A valid service name is required.");
        return XP25_PERM_DENIED;
    }
    if (!action || (strcmp(action, "start") && strcmp(action, "stop") && strcmp(action, "restart"))) {
        say(reason, reason_size, "Only start, stop and restart are supported.");
        return XP25_PERM_DENIED;
    }
    if (in_list(critical, name)) {
        say(reason, reason_size, "This service is critical to Windows security or stability.");
        return XP25_PERM_DENIED;
    }
    if (!in_list(allowlist ? allowlist : xp25_default_service_allowlist, name)) {
        say(reason, reason_size, "This service is not on the authorized service list.");
        return XP25_PERM_DENIED;
    }
    if (!is_admin) {
        say(reason, reason_size, "Service control needs administrator rights; the XP25 broker performs it.");
        return XP25_PERM_PRIVILEGED;
    }
    say(reason, reason_size, "Changes the state of an authorized Windows service.");
    return XP25_PERM_APPROVAL;
}

XP25_PERM xp25_policy_process(unsigned long pid, const char *image, const char *action,
                              char *reason, size_t reason_size)
{
    static const char protected_images[] =
        "system,smss.exe,csrss.exe,winlogon.exe,services.exe,lsass.exe,svchost.exe,explorer.exe,"
        "spoolsv.exe,clippyai.exe,roverai.exe,xp25broker.exe,agentsvr.exe,alg.exe,wdfmgr.exe";
    if (!action || (strcmp(action, "terminate") && strcmp(action, "lower_priority"))) {
        say(reason, reason_size, "Only terminate and lower_priority are supported.");
        return XP25_PERM_DENIED;
    }
    if (pid <= 4 || !image || !*image) {
        say(reason, reason_size, "System processes cannot be changed.");
        return XP25_PERM_DENIED;
    }
    if (in_list(protected_images, image)) {
        say(reason, reason_size, "This process is part of Windows or XP25 and cannot be changed by the assistant.");
        return XP25_PERM_DENIED;
    }
    say(reason, reason_size, !strcmp(action, "terminate") ? "Ends the process; unsaved work in it is lost."
                                                          : "Lowers the process priority so other programs respond faster.");
    return XP25_PERM_APPROVAL;
}
