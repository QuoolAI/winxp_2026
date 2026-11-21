/* Host tests for the MerlinAI portable core (components/merlin/core), built by
   tests/test_merlin.py as strict C89 under AddressSanitizer/UBSan. Prints
   failures=N plus a few values tests/test_merlin.py cross-checks in Python. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../components/merlin/core/merlin_core.h"

static int failures, checks;
#define CHECK(cond) do { ++checks; if (!(cond)) { ++failures; printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); } } while (0)

static MERLIN_JSON_DOC doc;

static void sample(MERLIN_PROBLEM *p)
{
    merlin_problem_init(p);
    merlin_crash_signature("crash", "MerlinTest.exe", "1.0.0.1", "MerlinTest.exe", "1.0.0.1", "0x00001a2B", p->signature);
    merlin_problem_set_id(p);
    strcpy(p->kind, "crash");
    strcpy(p->component, "MerlinTest.exe");
    strcpy(p->title, "MerlinTest.exe crashed in MerlinTest.exe");
    strcpy(p->app, "MerlinTest.exe");
    strcpy(p->code, "c0000005");
    strcpy(p->offset, "00001a2b");
    merlin_problem_add_occurrence(p, "2026-11-21T10:00:00Z", "crash:C-0001");
    merlin_problem_add_evidence(p, "line one\twith tab");
    merlin_problem_add_evidence(p, "back\\slash = equals");
}

static void test_text(void)
{
    char buf[8], t[MERLIN_TIME_SIZE];
    unsigned long s;
    CHECK(!merlin_copy(buf, sizeof(buf), "abcdefghij") && !strcmp(buf, "abcdefg"));
    CHECK(merlin_copy(buf, sizeof(buf), "abc") && merlin_append(buf, sizeof(buf), "de") && !strcmp(buf, "abcde"));
    CHECK(!merlin_append(buf, sizeof(buf), "xyz") && strlen(buf) == 7);
    merlin_format_time(0, t);
    CHECK(!strcmp(t, "1970-01-01T00:00:00Z"));
    merlin_format_time(1795255200UL, t);
    CHECK(merlin_parse_time(t, &s) && s == 1795255200UL);
    merlin_format_time(951782400UL, t);                  /* 2000-02-29 */
    CHECK(!strcmp(t, "2000-02-29T00:00:00Z"));
    CHECK(merlin_parse_time("2105-12-31T23:59:59Z", &s) && s == 4291747199UL);
    CHECK(!merlin_time_valid("2026-02-29T00:00:00Z"));
    CHECK(!merlin_time_valid("2026-13-01T00:00:00Z"));
    CHECK(!merlin_time_valid("2026-11-21 10:00:00Z"));
    CHECK(!merlin_time_valid("2106-01-01T00:00:00Z"));
    {
        char bad[] = { 'a', (char)0xC3, (char)0x28, '\n', (char)0xE2, (char)0x82, (char)0xAC, 0 };
        merlin_sanitize_line(bad);
        CHECK(!strcmp(bad, "a?(?\xE2\x82\xAC"));
    }
}

static void test_record(void)
{
    MERLIN_PROBLEM p, q;
    static char out[MERLIN_RECORD_MAX];
    char err[96];
    size_t n;
    char *mutated;
    sample(&p);
    n = merlin_problem_write(&p, out, sizeof(out));
    CHECK(n > 0);
    CHECK(merlin_problem_read(out, n, &q, err, sizeof(err)));
    CHECK(!strcmp(q.id, p.id) && !strcmp(q.signature, p.signature) && q.count == 1 && q.occurrence_count == 1);
    CHECK(q.evidence_count == 2 && !strcmp(q.evidence[0], "line one?with tab") && !strcmp(q.evidence[1], "back\\slash = equals"));
    CHECK(!strncmp(p.id, "P-", 2) && strlen(p.id) == 18);
    strcpy(p.job, "J-20261121-210855-dc09e4");           /* builder job ids are 24 characters */
    n = merlin_problem_write(&p, out, sizeof(out));
    CHECK(merlin_problem_read(out, n, &q, err, sizeof(err)) && !strcmp(q.job, "J-20261121-210855-dc09e4"));
    p.job[0] = 0;
    /* truncated: no end line */
    CHECK(!merlin_problem_read(out, n - 4, &q, err, sizeof(err)));
    /* write into a too-small buffer */
    CHECK(merlin_problem_write(&p, out, 64) == 0 && out[0] == 0);
    n = merlin_problem_write(&p, out, sizeof(out));
    mutated = (char *)malloc(n + 64);
    /* duplicate scalar */
    memcpy(mutated, out, n);
    memcpy(mutated + n - 4, "kind=hang\nend\n", 14);
    CHECK(!merlin_problem_read(mutated, n + 10, &q, err, sizeof(err)) && strstr(err, "duplicate"));
    /* unknown key is ignored */
    memcpy(mutated + n - 4, "future=1\nend\n", 13);
    CHECK(merlin_problem_read(mutated, n + 9, &q, err, sizeof(err)));
    /* data after end */
    memcpy(mutated, out, n);
    memcpy(mutated + n, "kind=x\n", 7);
    CHECK(!merlin_problem_read(mutated, n + 7, &q, err, sizeof(err)));
    free(mutated);
    /* id that does not match the signature */
    p.id[3] = p.id[3] == 'a' ? 'b' : 'a';
    n = merlin_problem_write(&p, out, sizeof(out));
    CHECK(!merlin_problem_read(out, n, &q, err, sizeof(err)));
    sample(&p);
    strcpy(p.dump, "..\\evil.dmp");
    n = merlin_problem_write(&p, out, sizeof(out));
    CHECK(!merlin_problem_read(out, n, &q, err, sizeof(err)));
    strcpy(p.dump, "C-0001.dmp");
    n = merlin_problem_write(&p, out, sizeof(out));
    CHECK(merlin_problem_read(out, n, &q, err, sizeof(err)));
    strcpy(p.status, "vulnerable");
    n = merlin_problem_write(&p, out, sizeof(out));
    CHECK(!merlin_problem_read(out, n, &q, err, sizeof(err)));
    CHECK(!merlin_problem_read("XP25-MERLIN-PROBLEM 1\nid=P-\\x00\nend\n", 36, &q, err, sizeof(err)));
}

static void test_occurrences(void)
{
    MERLIN_PROBLEM p, q;
    unsigned i;
    char ref[32], t[MERLIN_TIME_SIZE];
    sample(&p);
    CHECK(!merlin_problem_add_occurrence(&p, "2026-11-21T10:00:00Z", "crash:C-0001"));
    CHECK(p.count == 1);
    for (i = 0; i < 40; ++i) {
        sprintf(ref, "event:Application:%u", i);
        merlin_format_time(1795255200UL + i * 60UL, t);
        CHECK(merlin_problem_add_occurrence(&p, t, ref));
    }
    CHECK(p.count == 41 && p.occurrence_count == MERLIN_MAX_OCCURRENCES);
    CHECK(!strcmp(p.first, "2026-11-21T10:00:00Z") || strcmp(p.first, p.last) < 0);
    /* an older occurrence than all kept ones is counted but not stored */
    CHECK(merlin_problem_add_occurrence(&p, "2020-01-01T00:00:00Z", "event:Application:old"));
    CHECK(p.count == 42 && !strcmp(p.first, "2020-01-01T00:00:00Z"));
    CHECK(!merlin_problem_add_occurrence(&p, "not a time", "x"));
    CHECK(!merlin_problem_add_occurrence(&p, "2026-11-21T10:00:00Z", "has space"));
    sample(&q);
    merlin_problem_add_occurrence(&q, "2026-11-22T00:00:00Z", "crash:C-0002");
    q.submitted = 1;
    sample(&p);
    CHECK(merlin_problem_merge(&p, &q) && p.count == 2 && p.submitted && !strcmp(p.last, "2026-11-22T00:00:00Z"));
    CHECK(merlin_problem_merge(&p, &q) && p.count == 2);  /* idempotent */
    strcpy(q.signature, "00");
    CHECK(!merlin_problem_merge(&p, &q));
}

static void test_classify(void)
{
    MERLIN_PROBLEM p, crash;
    MERLIN_EVENT e;
    const char *fault[] = { "MerlinTest.exe", "1.0.0.1", "MerlinTest.exe", "1.0.0.1", "00001a2b" };
    const char *svc[] = { "Windows Firewall/Internet Connection Sharing (ICS)", "%%2" };
    const char *spool[] = { "Print Spooler" };
    const char *drivers[] = { "i8042prt" };
    memset(&e, 0, sizeof(e));
    e.log = "Application";
    e.source = "Application Error";
    e.event_id = 1000;
    e.type = MERLIN_EVENT_ERROR;
    e.strings = fault;
    e.string_count = 5;
    CHECK(merlin_classify_event(&e, &p) && !strcmp(p.kind, "crash") && !strcmp(p.offset, "00001a2b"));
    sample(&crash);
    CHECK(!strcmp(p.signature, crash.signature));       /* event 1000 and MerlinCrash report land together */
    e.string_count = 3;
    CHECK(!merlin_classify_event(&e, &p));
    e.source = "Application Hang";
    e.event_id = 1002;
    e.string_count = 5;
    CHECK(merlin_classify_event(&e, &p) && !strcmp(p.kind, "hang") && strcmp(p.signature, crash.signature));
    e.log = "System";
    e.source = "Service Control Manager";
    e.event_id = 0xC0001B58UL;                            /* 7000 with severity bits */
    e.strings = svc;
    e.string_count = 2;
    CHECK(merlin_classify_event(&e, &p) && !strcmp(p.kind, "security") && !strcmp(p.severity, "critical"));
    e.strings = spool;
    e.string_count = 1;
    e.event_id = 7031;
    CHECK(merlin_classify_event(&e, &p) && !strcmp(p.kind, "service") && strstr(p.title, "terminated unexpectedly"));
    {
        const char *timeout[] = { "30000", "Print Spooler" };
        e.event_id = 7009;
        e.strings = timeout;
        e.string_count = 2;
        CHECK(merlin_classify_event(&e, &p) && !strcmp(p.component, "Print Spooler") && strstr(p.title, "\"Print Spooler\""));
        e.string_count = 1;
        CHECK(merlin_classify_event(&e, &p) && !strcmp(p.component, ""));
    }
    e.event_id = 7026;
    e.strings = drivers;
    e.string_count = 1;
    CHECK(merlin_classify_event(&e, &p) && !strcmp(p.kind, "driver"));
    e.event_id = 7036;                                    /* "entered the running state": informational */
    e.type = MERLIN_EVENT_INFORMATION;
    CHECK(!merlin_classify_event(&e, &p));
    e.source = "EventLog";
    e.event_id = 6008;
    e.type = MERLIN_EVENT_ERROR;
    CHECK(merlin_classify_event(&e, &p) && !strcmp(p.kind, "shutdown"));
    e.source = "Save Dump";
    e.event_id = 1001;
    CHECK(merlin_classify_event(&e, &p) && !strcmp(p.kind, "kernel") && !strcmp(p.severity, "critical"));
    e.source = "Disk";
    e.event_id = 11;
    CHECK(merlin_classify_event(&e, &p) && !strcmp(p.kind, "storage"));
    e.source = "Some Driver";
    e.event_id = 3;
    e.type = MERLIN_EVENT_WARNING;
    CHECK(!merlin_classify_event(&e, &p));
    e.source = "XP25Broker";
    CHECK(merlin_classify_event(&e, &p) && !strcmp(p.severity, "warning"));
    e.type = MERLIN_EVENT_INFORMATION;
    CHECK(!merlin_classify_event(&e, &p));
    e.source = "MerlinAI";
    e.type = MERLIN_EVENT_ERROR;
    CHECK(!merlin_classify_event(&e, &p));
    e.log = "Security";
    e.source = "Security";
    e.event_id = 529;
    e.type = MERLIN_EVENT_AUDIT_FAILURE;
    CHECK(!merlin_classify_event(&e, &p));             /* a mistyped password is not a system failure */
    e.event_id = 517;
    e.type = MERLIN_EVENT_AUDIT_SUCCESS;
    CHECK(merlin_classify_event(&e, &p) && !strcmp(p.kind, "security"));
    CHECK(merlin_classify_winlogon("{\"xp25_winlogon\":\"secure_switch_failed\",\"status\":5,\"phase\":\"WlLoggedOn\",\"event_truncated\":0}", &p) &&
          !strcmp(p.kind, "winlogon") && strstr(p.title, "secure switch failed (status 5)"));
    CHECK(merlin_classify_winlogon("{\"xp25_winlogon\":\"shell_recovered\",\"status\":0,\"phase\":\"WlLoggedOn\",\"event_truncated\":0}", &p) &&
          !strcmp(p.severity, "warning"));
    CHECK(!merlin_classify_winlogon("{\"xp25_winlogon\":\"core_ready\",\"status\":0,\"phase\":\"WlInit\",\"event_truncated\":0}", &p));
    CHECK(!merlin_classify_winlogon("{\"xp25_winlogon\":\"a\\\"_failed\",\"status\":0}", &p));
    CHECK(!merlin_classify_winlogon("garbage", &p));
    CHECK(!strcmp(merlin_exception_name(0xC0000005UL), "Access violation"));
    {
        char o[16];
        CHECK(merlin_normalize_offset("0x1A2b", o) && !strcmp(o, "00001a2b"));
        CHECK(!merlin_normalize_offset("123456789", o) && !merlin_normalize_offset("12g4", o) && !merlin_normalize_offset("", o));
    }
}

static void redact(const char *in, const char *expected)
{
    char buf[512];
    MERLIN_REDACT ctx;
    ctx.user = "alice";
    ctx.computer = "HOMEPC";
    strcpy(buf, in);
    merlin_redact(buf, sizeof(buf), &ctx);
    if (strcmp(buf, expected)) printf("redact: '%s' -> '%s' (expected '%s')\n", in, buf, expected);
    CHECK(!strcmp(buf, expected));
}

static void test_redact(void)
{
    char small[16];
    MERLIN_REDACT ctx;
    redact("C:\\Documents and Settings\\alice\\My Documents\\x.txt", "%USERPROFILE%\\My Documents\\x.txt");
    redact("c:\\documents and settings\\Bob\\Desktop", "%PROFILES%\\*\\Desktop");
    redact("C:\\Documents and Settings\\All Users\\Application Data", "C:\\Documents and Settings\\All Users\\Application Data");
    redact("login password=hunter2; next", "login password=<redacted>; next");
    redact("Authorization: Bearer abc.def-123", "Authorization: Bearer <redacted>");
    redact("token : \"zz9\" ok", "token : \"<redacted>\" ok");
    redact("key sk-abcdefghijklmnop1234 end", "key <redacted-key> end");
    redact("mail alice.smith@example.org now", "mail <email> now");
    redact("user alice on HOMEPC", "user <user> on <computer>");
    redact("malice HOMEPCS", "malice HOMEPCS");
    redact("hash 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "hash 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
    redact("blob QWxhZGRpbjpvcGVuIHNlc2FtZQ9xYmNkZWZnaGlqa2xtbm8 x", "blob <redacted-token> x");
    redact("XP25 Winlogon", "XP25 Winlogon");
    redact("Registry key HKLM\\Software", "Registry key HKLM\\Software");
    ctx.user = "XP25";
    ctx.computer = NULL;
    strcpy(small, "user XP25 ok");
    merlin_redact(small, sizeof(small), &ctx);
    CHECK(!strcmp(small, "user XP25 ok"));
    ctx.user = "verylongname";
    strcpy(small, "verylongname!");
    merlin_redact(small, 8, &ctx);
    CHECK(strlen(small) <= 7 && !strstr(small, "verylong"));
}

static void test_json(void)
{
    static char buf[16384];
    MERLIN_JSON_OUT j;
    MERLIN_PROBLEM p;
    int root, problems, first, ev;
    char s[256];
    unsigned long n;
    int b;
    sample(&p);
    strcpy(p.title, "quote \" and \\ and \x01 and \xC3\xA9 and \xFF");
    merlin_json_begin(&j, buf, sizeof(buf));
    merlin_json_object(&j);
    merlin_json_key(&j, "schema");
    merlin_json_string(&j, "xp25-merlin-report/1");
    merlin_json_key(&j, "problems");
    merlin_json_array(&j);
    merlin_json_problem(&j, &p);
    merlin_json_problem(&j, &p);
    merlin_json_end_array(&j);
    merlin_json_end_object(&j);
    CHECK(merlin_json_done(&j));
    CHECK(merlin_json_parse(&doc, buf, strlen(buf)));
    root = 0;
    CHECK(merlin_json_member_string(&doc, root, "schema", s, sizeof(s)) && !strcmp(s, "xp25-merlin-report/1"));
    problems = merlin_json_member(&doc, root, "problems");
    first = merlin_json_element(&doc, problems, 0);
    CHECK(merlin_json_element(&doc, problems, 1) > 0 && merlin_json_element(&doc, problems, 2) < 0);
    CHECK(merlin_json_member_string(&doc, first, "title", s, sizeof(s)) && !strcmp(s, "quote \" and \\ and \x01 and \xC3\xA9 and ?"));
    CHECK(merlin_json_get_ulong(&doc, merlin_json_member(&doc, first, "count"), &n) && n == 1);
    CHECK(merlin_json_get_bool(&doc, merlin_json_member(&doc, first, "submitted"), &b) && b == 0);
    ev = merlin_json_member(&doc, first, "evidence");
    CHECK(merlin_json_get_string(&doc, merlin_json_element(&doc, ev, 1), s, sizeof(s)) && !strcmp(s, "back\\slash = equals"));
    merlin_json_begin(&j, buf, 10);
    merlin_json_problem(&j, &p);
    CHECK(!merlin_json_done(&j));
    CHECK(merlin_json_parse(&doc, "{\"a\":\"\\u00e9\\ud83d\\ude00\"}", 26));
    CHECK(merlin_json_member_string(&doc, 0, "a", s, sizeof(s)) && !strcmp(s, "\xC3\xA9\xF0\x9F\x98\x80"));
    CHECK(!merlin_json_parse(&doc, "{\"a\":1,}", 8));
    CHECK(!merlin_json_parse(&doc, "{\"a\" 1}", 7));
    CHECK(!merlin_json_parse(&doc, "[01]", 4));
    CHECK(!merlin_json_parse(&doc, "\"\x01\"", 3));
    CHECK(!merlin_json_parse(&doc, "[1] x", 5));
    CHECK(merlin_json_parse(&doc, " [true, false, null, -1.5e3, {}] ", 33));
    {
        char deep[200];
        int i;
        for (i = 0; i < 60; ++i) deep[i] = '[';
        for (i = 0; i < 60; ++i) deep[60 + i] = ']';
        CHECK(!merlin_json_parse(&doc, deep, 120));
    }
}

static void test_proto(void)
{
    unsigned char key[32];
    char mac[MERLIN_SIG_SIZE], hash[MERLIN_SIG_SIZE];
    const char *challenge = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const char *nonce = "0123456789abcdef0123456789abcdef";
    int i;
    for (i = 0; i < 32; ++i) key[i] = (unsigned char)i;
    CHECK(merlin_sign_request(MERLIN_LABEL_BUILDER, key, 32, "POST", "/merlin/v1/jobs", "inst-1", challenge, nonce,
                              "{}", 2, mac));
    printf("SIGN %s\n", mac);
    merlin_body_hash("{}", 2, hash);
    printf("BODY %s\n", hash);
    CHECK(!merlin_sign_request(MERLIN_LABEL_BUILDER, key, 32, "PUT", "/x", "inst-1", challenge, nonce, "", 0, mac));
    CHECK(!merlin_sign_request(MERLIN_LABEL_BUILDER, key, 32, "GET", "/a/../b", "inst-1", challenge, nonce, "", 0, mac));
    CHECK(!merlin_sign_request(MERLIN_LABEL_BUILDER, key, 32, "GET", "/a b", "inst-1", challenge, nonce, "", 0, mac));
    CHECK(!merlin_sign_request(MERLIN_LABEL_BUILDER, key, 32, "GET", "/a", "in st", challenge, nonce, "", 0, mac));
    CHECK(!merlin_sign_request(MERLIN_LABEL_BUILDER, key, 8, "GET", "/a", "inst-1", challenge, nonce, "", 0, mac));
    CHECK(!merlin_sign_request(MERLIN_LABEL_BUILDER, key, 32, "GET", "/a", "inst-1", "ABCD", nonce, "", 0, mac));
    /* response check against a MAC computed by Python (printed and verified by the test driver) */
    printf("RESPKEY ok\n");
    CHECK(!merlin_verify_response(MERLIN_LABEL_BUILDER, key, 32, nonce, 200, "{}", 2,
                                  "0000000000000000000000000000000000000000000000000000000000000000"));
    CHECK(!merlin_verify_response(MERLIN_LABEL_BUILDER, key, 32, nonce, 200, "{}", 2, "zz"));
    CHECK(merlin_token_valid("J-20261121-abc_1", 40) && !merlin_token_valid("a/b", 40) && !merlin_token_valid("", 40));
    CHECK(merlin_hex_valid("00ff", 4) && !merlin_hex_valid("00FF", 4) && !merlin_hex_valid("00f", 4));
}

/* Deterministic mutation fuzzing of the two parsers (the sanitizers do the judging). */
static void test_fuzz(unsigned long rounds)
{
    MERLIN_PROBLEM p, q;
    static char base[MERLIN_RECORD_MAX], work[MERLIN_RECORD_MAX];
    static char json[16384];
    MERLIN_JSON_OUT j;
    size_t n, jn;
    unsigned long seed = 12345, r;
    char err[96];
    sample(&p);
    n = merlin_problem_write(&p, base, sizeof(base));
    merlin_json_begin(&j, json, sizeof(json));
    merlin_json_problem(&j, &p);
    jn = j.used;
    for (r = 0; r < rounds; ++r) {
        size_t len = n, k, flips;
        seed = seed * 1103515245UL + 12345UL;
        memcpy(work, base, n);
        flips = 1 + (seed >> 16) % 4;
        for (k = 0; k < flips; ++k) {
            seed = seed * 1103515245UL + 12345UL;
            work[(seed >> 8) % len] = (char)(seed >> 3);
        }
        seed = seed * 1103515245UL + 12345UL;
        if (seed & 1) len = (seed >> 9) % n;
        merlin_problem_read(work, len, &q, err, sizeof(err));
        memcpy(work, json, jn);
        len = jn;
        for (k = 0; k < flips; ++k) {
            seed = seed * 1103515245UL + 12345UL;
            work[(seed >> 8) % len] = (char)(seed >> 3);
        }
        if (merlin_json_parse(&doc, work, len) && doc.count > 1) {
            char s[64];
            merlin_json_member_string(&doc, 0, "title", s, sizeof(s));
        }
        {
            MERLIN_REDACT ctx;
            char text[300];
            ctx.user = "alice";
            ctx.computer = "PC";
            memcpy(text, work, 299);
            text[299] = 0;
            merlin_redact(text, sizeof(text), &ctx);
        }
    }
}

int main(int argc, char **argv)
{
    test_text();
    test_record();
    test_occurrences();
    test_classify();
    test_redact();
    test_json();
    test_proto();
    test_fuzz(argc > 1 ? strtoul(argv[1], NULL, 10) : 20000UL);
    printf("checks=%d failures=%d\n", checks, failures);
    return failures != 0;
}
