/* Host tests of the portable XP25 security core (components/security/core).
   Strict C89; prints XP25_SECURITY_CORE failures=N. */
#include <stdio.h>
#include <string.h>
#include "sec_core.h"

static int failures;
#define CHECK(condition) do { if (!(condition)) { ++failures; printf("FAIL line %d: %s\n", __LINE__, #condition); } } while (0)

static void services(void)
{
    unsigned i, j;
    CHECK(sec_service_rule_count() >= 10);
    CHECK(sec_service_rule_at(sec_service_rule_count()) == NULL);
    for (i = 0; i < sec_service_rule_count(); ++i) {
        const SEC_SERVICE_RULE *rule = sec_service_rule_at(i);
        CHECK(rule->name[0] && strlen(rule->name) < 60);
        CHECK(rule->start == SEC_START_DISABLED || rule->start == SEC_START_MANUAL);
        CHECK(rule->flags != 0);
        CHECK(strlen(rule->reason) > 20 && strlen(rule->compatibility) > 3);
        /* The baseline must never name a dependency of logon, RPC, the shell or networking. */
        CHECK(!sec_service_is_critical(rule->name));
        CHECK(sec_service_rule(rule->name) == rule);
        for (j = 0; j < i; ++j) CHECK(!sec_equal_nocase(rule->name, sec_service_rule_at(j)->name));
    }
    CHECK(sec_service_rule("remoteregistry") != NULL);
    CHECK(sec_service_rule("REMOTEREGISTRY") == sec_service_rule("RemoteRegistry"));
    CHECK(sec_service_rule("RpcSs") == NULL && sec_service_rule("") == NULL && sec_service_rule(NULL) == NULL);
    CHECK(sec_service_rule("RemoteRegistryX") == NULL && sec_service_rule("RemoteRegistr") == NULL);
    CHECK(sec_service_is_critical("rpcss") && sec_service_is_critical("DcomLaunch") && sec_service_is_critical("SamSs"));
    CHECK(sec_service_is_critical("SharedAccess") && sec_service_is_critical("seclogon") && sec_service_is_critical("XP25Broker"));
    CHECK(!sec_service_is_critical("RemoteRegistry") && !sec_service_is_critical(NULL));
}

static void registry(void)
{
    unsigned i, j;
    const SEC_REGISTRY_RULE *minimum = sec_registry_rule("lsa.lmcompatibilitylevel"), *exact = sec_registry_rule("lsa.nolmhash");
    CHECK(sec_registry_rule_count() >= 40);
    for (i = 0; i < sec_registry_rule_count(); ++i) {
        const SEC_REGISTRY_RULE *rule = sec_registry_rule_at(i);
        CHECK(rule->id[0] && strlen(rule->id) < 60 && !strchr(rule->id, ' '));
        CHECK(rule->key[0] && rule->key[0] != '\\' && strncmp(rule->key, "HKEY", 4) != 0);
        CHECK(rule->kind >= SEC_REG_DWORD && rule->kind <= SEC_REG_MULTI_EMPTY);
        CHECK((rule->kind == SEC_REG_SZ) == (rule->text != NULL));
        CHECK(rule->effect == SEC_EFFECT_IMMEDIATE || rule->effect == SEC_EFFECT_RESTART);
        CHECK(strlen(rule->reason) > 10 && rule->area[0] && rule->compatibility[0]);
        CHECK(sec_registry_rule(rule->id) == rule);
        for (j = 0; j < i; ++j) {
            const SEC_REGISTRY_RULE *other = sec_registry_rule_at(j);
            CHECK(strcmp(rule->id, other->id) != 0);
            CHECK(!(sec_equal_nocase(rule->key, other->key) && sec_equal_nocase(rule->value, other->value)));
        }
    }
    CHECK(minimum && exact && sec_registry_rule("nothing") == NULL && sec_registry_rule(NULL) == NULL);
    /* A minimum never accepts a weaker value and never forces a stricter one down. */
    CHECK(!sec_registry_dword_ok(minimum, 0, 0) && !sec_registry_dword_ok(minimum, 1, 2));
    CHECK(sec_registry_dword_ok(minimum, 1, 3) && sec_registry_dword_ok(minimum, 1, 5));
    CHECK(sec_registry_dword_ok(exact, 1, 1) && !sec_registry_dword_ok(exact, 1, 0) && !sec_registry_dword_ok(exact, 1, 2));
    CHECK(!sec_registry_dword_ok(exact, 0, 1) && !sec_registry_dword_ok(NULL, 1, 1));
    CHECK(!sec_registry_dword_ok(sec_registry_rule("wsh.vbsfile"), 1, 0));
    /* Auditing: logon, account and policy changes in both directions; no object or process noise. */
    CHECK(sec_audit_baseline(1) == 3 && sec_audit_baseline(6) == 3 && sec_audit_baseline(5) == 3);
    CHECK(sec_audit_baseline(2) == 0 && sec_audit_baseline(4) == 0 && sec_audit_baseline(99) == 0);
    CHECK(sec_audit_category_name(0) && !strcmp(sec_audit_category_name(8), "account_logon") && !sec_audit_category_name(9));
}

static void access_control(void)
{
    const SEC_ACL_RULE *system32 = sec_acl_rule("acl.system32"), *programs = sec_acl_rule("acl.xp25_programs");
    const SEC_ACL_RULE *lab = sec_acl_rule("acl.xp25_lab"), *keys = sec_acl_rule("acl.service_keys"), *tree = sec_acl_rule("acl.xp25_registry");
    const char *w = "C:\\WINDOWS", *p = "C:\\Program Files";
    char root[64], tiny[8];
    unsigned i;
    CHECK(system32 && programs && lab && keys && tree && !sec_acl_rule("acl.none") && !sec_acl_rule(NULL));
    for (i = 0; i < sec_acl_rule_count(); ++i) {
        const SEC_ACL_RULE *rule = sec_acl_rule_at(i);
        CHECK(rule->kind >= SEC_ACL_REPAIR_FILES && rule->kind <= SEC_ACL_SERVICE);
        CHECK((rule->sddl != NULL) == (rule->kind == SEC_ACL_TREE_FILES || rule->kind == SEC_ACL_TREE_REGISTRY || rule->kind == SEC_ACL_SERVICE));
        /* Tree descriptors are protected and grant write access to SYSTEM and Administrators only. */
        if (rule->sddl && rule->kind != SEC_ACL_SERVICE)
            CHECK(!strncmp(rule->sddl, "O:BAD:P(", 8) && !strstr(rule->sddl, ";WD)") && !strstr(rule->sddl, ";AU)") && !strstr(rule->sddl, ";IU)"));
        /* Service descriptors: a DACL only, three entries; stop (WP), pause (DT), reconfigure (DC), delete (SD),
           re-secure (WD, WO) for SYSTEM and Administrators alone, and no entry for Power Users or everyone. */
        if (rule->kind == SEC_ACL_SERVICE) {
            const char *users = strstr(rule->sddl, "(A;;CCLCSWLOCRRC;;;AU)");
            CHECK(!strncmp(rule->sddl, "D:(A;;", 6) && users && users[22] == 0 && strstr(rule->sddl, ";;;SY)") && strstr(rule->sddl, ";;;BA)"));
            CHECK(!strstr(rule->sddl, ";PU)") && !strstr(rule->sddl, ";WD)") && !strstr(rule->sddl, ";BU)") && !strstr(rule->sddl, ";IU)"));
            CHECK(!strchr(rule->root, '\\') && !strchr(rule->root, '%'));
        }
        CHECK(sec_acl_rule(rule->id) == rule && strlen(rule->reason) > 20);
    }
    {
        /* A service rule covers exactly its own service; a backup record cannot name another one. */
        const SEC_ACL_RULE *firewall = sec_acl_rule("acl.firewall_service"), *tasks = sec_acl_rule("acl.tasks");
        CHECK(firewall && firewall->kind == SEC_ACL_SERVICE && !strcmp(firewall->root, "SharedAccess"));
        CHECK(sec_acl_in_scope(firewall, "SharedAccess", "", "") && sec_acl_in_scope(firewall, "sharedaccess", w, p));
        CHECK(!sec_acl_in_scope(firewall, "Eventlog", "", "") && !sec_acl_in_scope(firewall, "SharedAccess\\Parameters", "", ""));
        CHECK(!sec_acl_in_scope(firewall, "", "", "") && !sec_acl_in_scope(firewall, NULL, "", ""));
        CHECK(sec_acl_rule("acl.security_center_service") && sec_acl_rule("acl.xp25_broker_service"));
        CHECK(tasks && tasks->kind == SEC_ACL_TREE_FILES && sec_acl_root(tasks, w, p, root, sizeof(root)) && !strcmp(root, "C:\\WINDOWS\\Tasks"));
        CHECK(sec_acl_in_scope(tasks, "C:\\WINDOWS\\Tasks", w, p) && sec_acl_in_scope(tasks, "C:\\WINDOWS\\Tasks\\a.job", w, p));
        CHECK(!sec_acl_in_scope(tasks, "C:\\WINDOWS\\Tasks\\..\\system32\\a.dll", w, p));
    }
    CHECK(sec_acl_root(system32, w, p, root, sizeof(root)) && !strcmp(root, "C:\\WINDOWS\\system32"));
    CHECK(sec_acl_root(programs, w, p, root, sizeof(root)) && !strcmp(root, "C:\\Program Files\\XP25"));
    CHECK(sec_acl_root(lab, "D:\\WINNT", p, root, sizeof(root)) && !strcmp(root, "D:\\xp25"));
    CHECK(!sec_acl_root(system32, w, p, tiny, sizeof(tiny)) && !sec_acl_root(system32, "", p, root, sizeof(root)));
    CHECK(!sec_acl_root(lab, "WINDOWS", p, root, sizeof(root)));
    /* Files directly in a system directory, nothing else. */
    CHECK(sec_acl_in_scope(system32, "C:\\WINDOWS\\system32\\xp25krnl.exe", w, p));
    CHECK(sec_acl_in_scope(system32, "c:/windows/SYSTEM32/ntdll.dll", w, p));
    CHECK(!sec_acl_in_scope(system32, "C:\\WINDOWS\\system32", w, p));
    CHECK(!sec_acl_in_scope(system32, "C:\\WINDOWS\\system32\\", w, p));
    CHECK(!sec_acl_in_scope(system32, "C:\\WINDOWS\\system32\\drivers\\x.sys", w, p));
    CHECK(!sec_acl_in_scope(system32, "C:\\WINDOWS\\system32\\..\\explorer.exe", w, p));
    CHECK(!sec_acl_in_scope(system32, "C:\\WINDOWS\\system32x\\a.dll", w, p));
    CHECK(!sec_acl_in_scope(system32, "C:\\WINDOWS\\system3", w, p) && !sec_acl_in_scope(system32, NULL, w, p));
    CHECK(!sec_acl_in_scope(system32, "D:\\WINDOWS\\system32\\a.dll", w, p));
    /* A tree: its root and anything below, never a path that climbs out. */
    CHECK(sec_acl_in_scope(programs, "C:\\Program Files\\XP25", w, p));
    CHECK(sec_acl_in_scope(programs, "C:\\Program Files\\XP25\\Security\\XP25Sec.exe", w, p));
    CHECK(!sec_acl_in_scope(programs, "C:\\Program Files\\XP25\\..\\Internet Explorer", w, p));
    CHECK(!sec_acl_in_scope(programs, "C:\\Program Files\\XP25\\.\\a", w, p));
    CHECK(!sec_acl_in_scope(programs, "C:\\Program Files\\XP25\\a\\\\b", w, p));
    CHECK(!sec_acl_in_scope(programs, "C:\\Program Files\\XP25Other", w, p));
    CHECK(!sec_acl_in_scope(programs, "C:\\Program Files", w, p));
    CHECK(sec_acl_in_scope(programs, "C:\\Program Files\\XP25\\..name", w, p));
    /* Registry rules. */
    CHECK(sec_acl_in_scope(tree, "SOFTWARE\\XP25", "", "") && sec_acl_in_scope(tree, "software\\xp25\\Agent\\Policy", "", ""));
    CHECK(!sec_acl_in_scope(tree, "SOFTWARE\\XP25x", "", "") && !sec_acl_in_scope(tree, "SOFTWARE", "", ""));
    CHECK(sec_acl_in_scope(keys, "SYSTEM\\CurrentControlSet\\Services\\XP25Broker\\Parameters", "", ""));
    CHECK(!sec_acl_in_scope(keys, "SYSTEM\\CurrentControlSet\\Services", "", ""));
    CHECK(!sec_acl_in_scope(keys, "SYSTEM\\CurrentControlSet\\Control\\Lsa", "", ""));
}

static void backup_round_trip(const SEC_BACKUP_RECORD *record)
{
    SEC_BACKUP_RECORD parsed;
    char line[5000];
    size_t n = sec_backup_format(record, line, sizeof(line));
    CHECK(n > 0 && line[n - 1] == '\n');
    if (!n) return;
    line[n - 1] = 0;
    CHECK(sec_backup_parse(line, &parsed));
    CHECK(parsed.item == record->item && !strcmp(parsed.id, record->id));
    CHECK(parsed.start == record->start && parsed.running == record->running && parsed.present == record->present);
    CHECK(parsed.type == record->type && parsed.size == record->size && parsed.options == record->options);
    CHECK(!memcmp(parsed.data, record->data, record->size));
}

static void backup(void)
{
    static const char *const rejected[] = {
        "", "service", "service RemoteRegistry", "service RemoteRegistry start=2", "service RemoteRegistry start=2 running=1 ",
        "service RemoteRegistry start=5 running=0", "service RemoteRegistry start=2 running=2", "service remoteregistry start=2 running=1",
        "service RpcSs start=2 running=1", "service NoSuchService start=2 running=1", "service RemoteRegistry  start=2 running=1",
        "service RemoteRegistry start=02x running=1", "service RemoteRegistry start=99999999999 running=1",
        "registry lsa.nolmhash present=1 type=4 data=", "registry lsa.nolmhash present=1 type=4 data=0", "registry lsa.nolmhash present=1 type=4 data=0G000000",
        "registry lsa.nolmhash present=1 type=4 data=0A000000", "registry no.such.rule present=1 type=4 data=00000000",
        "registry lsa.nolmhash present=0 type=4 data=-", "registry lsa.nolmhash present=0 type=0 data=00", "registry lsa.nolmhash present=2 type=4 data=00000000",
        "registry lsa.nolmhash present=1 type=12 data=00000000", "registry lsa.nolmhash present=1 type=4 data=00000000 x",
        "registry SYSTEM\\CurrentControlSet\\Control\\Lsa present=1 type=4 data=00000000",
        "audit logon options=4", "audit nothing options=1", "audit logon options=1 ", "audit mode options=2", "audit logon",
        "acl acl.system32 data=", "acl acl.system32 data=41", "acl acl.system32 data=4100", "acl acl.system32 data=0041",
        "acl acl.system32 data=410042004300", "acl acl.none data=410042", "acl acl.system32 data=41004", "unknown x", " service RemoteRegistry start=2 running=1"
    };
    SEC_BACKUP_RECORD record, parsed;
    char line[5000];
    unsigned i;
    memset(&record, 0, sizeof(record));
    record.item = SEC_ITEM_SERVICE; strcpy(record.id, "RemoteRegistry"); record.start = SEC_START_AUTO; record.running = 1;
    backup_round_trip(&record);
    CHECK(sec_backup_format(&record, line, 10) == 0);
    strcpy(record.id, "RpcSs");
    CHECK(sec_backup_format(&record, line, sizeof(line)) == 0);      /* never a service outside the table */
    memset(&record, 0, sizeof(record));
    record.item = SEC_ITEM_REGISTRY; strcpy(record.id, "lsa.nolmhash");
    backup_round_trip(&record);                                        /* absent value */
    record.present = 1; record.type = 4; record.size = 4; record.data[0] = 0xdf; record.data[3] = 0x80;
    backup_round_trip(&record);
    record.type = 7; record.size = 0;
    backup_round_trip(&record);                                        /* present and empty */
    record.type = 1; record.size = SEC_BACKUP_DATA_MAX;
    for (i = 0; i < SEC_BACKUP_DATA_MAX; ++i) record.data[i] = (unsigned char)(i * 7 + 1);
    backup_round_trip(&record);
    record.size = SEC_BACKUP_DATA_MAX + 1;
    CHECK(sec_backup_format(&record, line, sizeof(line)) == 0);
    record.size = 4; record.present = 0;
    CHECK(sec_backup_format(&record, line, sizeof(line)) == 0);      /* data without a value */
    memset(&record, 0, sizeof(record));
    record.item = SEC_ITEM_AUDIT; strcpy(record.id, "logon"); record.options = 3;
    backup_round_trip(&record);
    strcpy(record.id, "mode"); record.options = 1;
    backup_round_trip(&record);
    record.options = 2;
    CHECK(sec_backup_format(&record, line, sizeof(line)) == 0);
    memset(&record, 0, sizeof(record));
    record.item = SEC_ITEM_ACL; strcpy(record.id, "acl.system32"); record.present = 1;
    memcpy(record.data, "C:\\WINDOWS\\system32\\a.dll\0O:BAD:(A;;FA;;;BA)", 44); record.size = 44;
    {
        SEC_BACKUP_RECORD copy = record;
        copy.present = 0;                                              /* the codec carries path and SDDL only */
        backup_round_trip(&copy);
    }
    record.data[43] = 0;
    CHECK(sec_backup_format(&record, line, sizeof(line)) == 0);      /* a second separator */
    record.item = 9;
    CHECK(sec_backup_format(&record, line, sizeof(line)) == 0);
    for (i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        if (sec_backup_parse(rejected[i], &parsed)) { ++failures; printf("FAIL accepted: %s\n", rejected[i]); }
    }
    CHECK(!sec_backup_parse(NULL, &parsed) && !sec_backup_parse("service RemoteRegistry start=2 running=1", NULL));
    CHECK(sec_backup_parse("registry lsa.nolmhash present=0 type=0 data=-", &parsed) && !parsed.present);
    CHECK(sec_backup_parse("audit mode options=0", &parsed) && sec_backup_parse("audit account_logon options=3", &parsed));
}

static void json(void)
{
    SEC_JSON j;
    char buffer[256], small[24];
    size_t n;
    sec_json_begin(&j, buffer, sizeof(buffer));
    sec_json_string(&j, "kind", "a\"b\\c\n\x01");
    sec_json_uint(&j, "n", 4294967295UL);
    sec_json_bool(&j, "t", 1);
    sec_json_bool(&j, "f", 0);
    sec_json_string(&j, "null", NULL);
    n = sec_json_end(&j);
    CHECK(n && !strcmp(buffer, "{\"kind\":\"a\\\"b\\\\c\\u000a\\u0001\",\"n\":4294967295,\"t\":true,\"f\":false,\"null\":\"\"}\r\n"));
    sec_json_begin(&j, small, sizeof(small));
    sec_json_string(&j, "key", "a value that cannot fit in the buffer");
    CHECK(sec_json_end(&j) == 0);                                      /* dropped, never truncated */
    sec_json_begin(&j, small, 4);
    CHECK(sec_json_end(&j) == 0);
    CHECK(!strcmp(sec_severity_name(3), "high") && !strcmp(sec_severity_name(-1), "info") && !strcmp(sec_severity_name(9), "info"));
}

static void rules(void)
{
    const char *w = "C:\\WINDOWS", *p = "C:\\Program Files";
    const SEC_AUTOSTART *userinit = NULL, *shell = NULL, *packages = NULL, *ifeo = NULL;
    unsigned i;
    CHECK(sec_path_facts("C:\\Program Files\\XP25\\XP25Broker.exe", w, p) == SEC_PATH_UNQUOTED_SPACE);
    CHECK(sec_path_facts("C:\\Program Files\\XP25\\XP25Broker.exe /service", w, p) == SEC_PATH_UNQUOTED_SPACE);
    CHECK(sec_path_facts("\"C:\\Program Files\\XP25\\XP25Broker.exe\" /service", w, p) == 0);
    CHECK(sec_path_facts("%SystemRoot%\\system32\\svchost.exe -k netsvcs", w, p) == 0);
    CHECK(sec_path_facts("C:\\WINDOWS\\system32\\spoolsv.exe", w, p) == 0);
    CHECK(sec_path_facts("System32\\DRIVERS\\tcpip.sys", w, p) == 0 && sec_path_facts("\\SystemRoot\\System32\\drivers\\a.sys", w, p) == 0);
    CHECK(sec_path_facts("\\??\\C:\\WINDOWS\\system32\\drivers\\a.sys", w, p) == 0);
    CHECK(sec_path_facts("C:\\Documents and Settings\\XP25\\Local Settings\\Temp\\a.exe", w, p) ==
          (SEC_PATH_UNQUOTED_SPACE | SEC_PATH_USER_WRITABLE | SEC_PATH_OUTSIDE_SYSTEM));
    CHECK(sec_path_facts("\"C:\\Documents and Settings\\XP25\\a.exe\"", w, p) == (SEC_PATH_USER_WRITABLE | SEC_PATH_OUTSIDE_SYSTEM));
    CHECK(sec_path_facts("C:\\Tools\\agent.exe -x", w, p) == SEC_PATH_OUTSIDE_SYSTEM);
    CHECK(sec_path_facts("C:\\WINDOWSX\\a.exe", w, p) == SEC_PATH_OUTSIDE_SYSTEM);
    CHECK(sec_path_facts("\\\\server\\share\\a.exe", w, p) == SEC_PATH_NETWORK);
    CHECK(sec_path_facts("rundll32 shell32,Control_RunDLL", w, p) == SEC_PATH_RELATIVE && sec_path_facts("ctfmon.exe", w, p) == SEC_PATH_RELATIVE);
    CHECK(sec_path_facts("%TEMP%\\x.exe", w, p) == SEC_PATH_USER_WRITABLE && sec_path_facts("", w, p) == 0 && sec_path_facts(NULL, w, p) == 0);
    CHECK(sec_port_lookup(135, 0) && sec_port_lookup(445, 0)->severity == SEC_SEVERITY_HIGH && sec_port_lookup(3389, 0));
    CHECK(sec_port_lookup(500, 1) && !sec_port_lookup(500, 0) && !sec_port_lookup(135, 1) && !sec_port_lookup(8080, 0));
    CHECK(sec_event_lookup("Security", "Security", 517)->severity == SEC_SEVERITY_HIGH && sec_event_lookup("security", NULL, 624));
    CHECK(sec_event_lookup("System", "Service Control Manager", 7040) && !sec_event_lookup("System", "W32Time", 7040));
    CHECK(!sec_event_lookup("Application", "x", 517) && !sec_event_lookup("Security", "Security", 1));
    CHECK(!strcmp(sec_event_lookup("Security", "x", 529)->rule, sec_event_lookup("Security", "x", 539)->rule));
    for (i = 0; i < sec_autostart_count(); ++i) {
        const SEC_AUTOSTART *location = sec_autostart_at(i);
        if (!strcmp(location->id, "winlogon_userinit")) userinit = location;
        if (!strcmp(location->id, "winlogon_shell")) shell = location;
        if (!strcmp(location->id, "lsa_security_packages")) packages = location;
        if (!strcmp(location->id, "image_file_execution_options")) ifeo = location;
        CHECK(location->key[0] && location->severity >= SEC_SEVERITY_LOW);
    }
    CHECK(userinit && shell && packages && ifeo && (ifeo->kind & SEC_AS_ANY_IS_FINDING));
    CHECK(sec_autostart_default(userinit, "C:\\WINDOWS\\system32\\userinit.exe,", w));
    CHECK(sec_autostart_default(userinit, "c:\\windows\\SYSTEM32\\USERINIT.EXE,", w));
    CHECK(!sec_autostart_default(userinit, "C:\\WINDOWS\\system32\\userinit.exe,C:\\evil.exe", w));
    CHECK(!sec_autostart_default(userinit, "C:\\WINDOWS\\system32\\userinit.exe", w) && !sec_autostart_default(userinit, "", w));
    CHECK(sec_autostart_default(shell, "explorer.exe", w) && !sec_autostart_default(shell, "explorer.exe evil.exe", w));
    CHECK(sec_autostart_default(packages, "kerberos", w) && sec_autostart_default(packages, "tspkg", w) && sec_autostart_default(packages, "MSV1_0", w));
    CHECK(!sec_autostart_default(packages, "evilssp", w) && !sec_autostart_default(packages, "kerberos|msv1_0", w) && !sec_autostart_default(packages, "", w));
    CHECK(!sec_autostart_default(ifeo, "ntsd -d", w) && !sec_autostart_default(NULL, "x", w) && !sec_autostart_default(shell, NULL, w));
}

int main(void)
{
    services();
    registry();
    access_control();
    backup();
    json();
    rules();
    printf("XP25_SECURITY_CORE failures=%d\n", failures);
    return failures != 0;
}
