/* Milestone 8.4: deterministic mutation fuzzing of the XP25 portable parsers under
   AddressSanitizer/UndefinedBehaviorSanitizer. Every input that crosses a trust boundary in the
   portable cores is driven from a seed corpus with a fixed-seed mutator (no external fuzzing
   engine), and the parsers' own round-trip properties are checked. A sanitizer report aborts
   the run. Synthetic inputs only: this says nothing about the native Windows adapters.
   usage: fuzz_parsers <iterations per target> [seed]   prints target=... runs=N and failures=N */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "xp25_base.h"
#include "xp25_agent.h"
#include "xp25_llm.h"
#include "xp25_offline.h"
#include "xp25_policy.h"
#include "xp25_sha256.h"
#include "rover_index.h"
#include "rover_query.h"
#include "sec_core.h"
#include "environment.h"
#include "bootkey_codec.h"

#define MAX_INPUT 4096
static unsigned long rng_state = 0x2545F491UL;
static int failures;

static unsigned long rnd(void)
{
    rng_state ^= (rng_state << 13) & 0xFFFFFFFFUL;
    rng_state ^= rng_state >> 17;
    rng_state ^= (rng_state << 5) & 0xFFFFFFFFUL;
    return rng_state & 0xFFFFFFFFUL;
}

static const char *const tokens[] = {
    "{", "}", "[", "]", "\"", "\\", "\\u", "\\uD800", "\\uDC00", "\\u0000", ":", ",", "0", "-", "1e9", "1.0",
    "true", "false", "null", "\n", "\r\n", " ", "\t", "\x00", "\xff", "\xc3\xa9", "\xef\xbb\xbf", "%", "=",
    "[Network]", "127.0.0.1", "localhost", "C:\\", "\\..\\", "..", "*", "?", "|", ">", "&", "^", "\"\"",
    "18446744073709551615", "-9223372036854775808", "99999999999999999999", "2026-13-45", "last week",
    "files from", "larger than", "MB", "GB", "KB", "before", "after", "newest", "type", "photos", "my",
    "XP25SEC-BACKUP 1", "service", "registry", "audit", "acl", "\x01", "%%", "=::=", "Path=", "A=B" };

static size_t mutate(unsigned char *buf, size_t n, size_t cap)
{
    int k, rounds = 1 + (int)(rnd() % 6);
    for (k = 0; k < rounds; ++k) {
        size_t at = n ? rnd() % (n + 1) : 0;
        switch (rnd() % 8) {
        case 0: if (n) buf[rnd() % n] ^= (unsigned char)(1u << (rnd() % 8)); break;
        case 1: if (n) buf[rnd() % n] = (unsigned char)rnd(); break;
        case 2: if (n < cap) { memmove(buf + at + 1, buf + at, n - at); buf[at] = (unsigned char)rnd(); ++n; } break;
        case 3: if (n && at < n) { memmove(buf + at, buf + at + 1, n - at - 1); --n; } break;
        case 4: {
            const char *t = tokens[rnd() % (sizeof(tokens) / sizeof(tokens[0]))];
            size_t len = strlen(t) ? strlen(t) : 1;
            if (n + len <= cap) { memmove(buf + at + len, buf + at, n - at); memcpy(buf + at, t, len); n += len; }
            break;
        }
        case 5: if (n) { size_t from = rnd() % n, len = 1 + rnd() % 32; if (from + len > n) len = n - from;
                    if (n + len <= cap) { memmove(buf + at + len, buf + at, n - at); memmove(buf + at, buf + from + (from >= at ? len : 0), len); n += len; } }
                break;
        case 6: if (n) n = rnd() % n; break;
        default: if (n > 1) { size_t a = rnd() % n, b = rnd() % n; unsigned char t = buf[a]; buf[a] = buf[b]; buf[b] = t; } break;
        }
    }
    return n;
}

/* A mutated copy of a random seed; the result is NUL terminated (n bytes plus NUL). */
static size_t next_input(const char *const *seeds, size_t seed_count, unsigned char *buf)
{
    const char *s = seeds[rnd() % seed_count];
    size_t n = strlen(s);
    if (n > MAX_INPUT) n = MAX_INPUT;
    memcpy(buf, s, n);
    n = mutate(buf, n, MAX_INPUT);
    buf[n] = 0;
    return n;
}

#define FAIL(what) do { ++failures; printf("FAIL %s: %s\n", target, what); } while (0)

static void fuzz_json(long iterations)
{
    static const char *const seeds[] = {
        "{\"v\":1,\"op\":\"service_control\",\"name\":\"Spooler\",\"action\":\"restart\"}",
        "[1,2.5,-3e2,true,false,null,\"x\\u00e9\\uD83D\\uDE00\\n\",{\"a\":[[]]}]",
        "{\"output\":[{\"type\":\"function_call\",\"name\":\"file_operations\",\"arguments\":\"{\\\"path\\\":\\\"C:\\\\\\\\x\\\"}\"}]}",
        "\xef\xbb\xbf{\"k\":\"v\"}", "0", "\"\"", "[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[1]]]]" };
    static unsigned char buf[MAX_INPUT + 1];
    const char *target = "json";
    long i;
    for (i = 0; i < iterations; ++i) {
        XP25_JDOC doc, again;
        size_t n = next_input(seeds, sizeof(seeds) / sizeof(seeds[0]), buf);
        if (xp25_json_parse(&doc, (const char *)buf, n)) {
            XP25_BUF a, b;
            xp25_buf_init(&a);
            xp25_buf_init(&b);
            xp25_json_write(&a, doc.root);
            if (!xp25_json_parse(&again, a.data, a.len)) FAIL("written JSON does not parse");
            else {
                xp25_json_write(&b, again.root);
                if (a.len != b.len || memcmp(a.data, b.data, a.len)) FAIL("JSON round trip is not stable");
            }
            {
                xp25_i64 v;
                const XP25_JNODE *node;
                size_t k;
                (void)xp25_json_i64(doc.root, "v", &v);
                (void)xp25_json_string(doc.root, "name");
                (void)xp25_json_flag(doc.root, "approved", 0);
                for (k = 0; (node = xp25_json_at(doc.root, k)) != NULL && k < 64; ++k) (void)xp25_json_node_i64(node, &v);
            }
            xp25_json_free(&again);
            xp25_buf_free(&a);
            xp25_buf_free(&b);
        }
        xp25_json_free(&doc);
    }
    printf("target=json runs=%ld\n", iterations);
}

static void fuzz_llm(long iterations)
{
    static const char *const seeds[] = {
        "{\"id\":\"r\",\"status\":\"completed\",\"output\":[{\"type\":\"message\",\"content\":[{\"type\":\"output_text\",\"text\":\"hi\"}]}]}",
        "{\"output\":[{\"type\":\"function_call\",\"call_id\":\"c1\",\"name\":\"system_info\",\"arguments\":\"{}\"}],\"status\":\"completed\"}",
        "{\"choices\":[{\"message\":{\"role\":\"assistant\",\"content\":\"x\",\"tool_calls\":[{\"id\":\"t\",\"type\":\"function\",\"function\":{\"name\":\"n\",\"arguments\":\"{}\"}}]}}]}",
        "{\"error\":{\"message\":\"bad\",\"type\":\"invalid_request_error\",\"code\":\"x\"}}",
        "{\"status\":\"incomplete\",\"incomplete_details\":{\"reason\":\"max_output_tokens\"}}" };
    static unsigned char buf[MAX_INPUT + 1];
    long i;
    for (i = 0; i < iterations; ++i) {
        XP25_REPLY reply;
        size_t n = next_input(seeds, sizeof(seeds) / sizeof(seeds[0]), buf);
        static const int statuses[] = { 200, 400, 429, 500, 0 };
        memset(&reply, 0, sizeof(reply));
        (void)xp25_llm_parse_response((XP25_API)(rnd() % 2), (const char *)buf, n, statuses[rnd() % 5], &reply);
        xp25_reply_free(&reply);
    }
    printf("target=llm_response runs=%ld\n", iterations);
}

static void fuzz_rover_query(long iterations)
{
    static const char *const seeds[] = {
        "photos from last summer larger than 2 MB", "my documents modified before 2025-03-01 sorted by size",
        "newest 20 text files in C:\\Windows containing network", "folders named 2024", "hosts",
        "files between 10KB and 1GB created in March 2023", "pdf or doc from yesterday" };
    static const char *const json_seeds[] = {
        "{\"terms\":[\"report\"],\"extensions\":[\"pdf\",\"doc\"],\"after\":\"2024-01-01\",\"before\":\"2025-01-01\",\"sort\":\"date_desc\",\"limit\":20}",
        "{\"kind\":\"folders\",\"location\":\"My Documents\",\"min_size\":1024,\"max_size\":1048576,\"year\":2024}",
        "{\"terms\":[],\"created\":true,\"sort\":\"size_asc\"}" };
    static unsigned char buf[MAX_INPUT + 1];
    long i;
    for (i = 0; i < iterations; ++i) {
        ROVER_CRITERIA c;
        XP25_JDOC doc;
        XP25_BUF out;
        XP25_JW w;
        char error[128];
        long bias = (long)(rnd() % 1441) - 720;
        unsigned long now = 1700000000UL + rnd() % 400000000UL;
        size_t n = next_input(seeds, sizeof(seeds) / sizeof(seeds[0]), buf);
        rover_query_parse((const char *)buf, now, bias, &c);
        xp25_buf_init(&out);
        rover_criteria_describe(&c, bias, &out);
        xp25_jw_init(&w, &out);
        rover_criteria_json(&c, bias, &w);
        xp25_buf_free(&out);
        n = next_input(json_seeds, sizeof(json_seeds) / sizeof(json_seeds[0]), buf);
        if (xp25_json_parse(&doc, (const char *)buf, n))
            (void)rover_criteria_from_json(doc.root, now, bias, &c, error, sizeof(error));
        xp25_json_free(&doc);
    }
    printf("target=rover_query runs=%ld\n", iterations);
}

static void fuzz_rover_index(long iterations)
{
    const char *target = "rover_index";
    ROVER_INDEX index;
    ROVER_DIRENT meta;
    XP25_BUF image;
    unsigned char *data;
    long i;
    rover_index_init(&index);
    memset(&meta, 0, sizeof(meta));
    for (i = 0; i < 40; ++i) {
        char path[64];
        sprintf(path, "C:\\Docs\\%c%ld\\file%ld.txt", (char)('a' + i % 7), i % 5, i);
        meta.size = (xp25_u64)i * 1000;
        meta.mtime = 1700000000UL + (unsigned long)i;
        if (!rover_index_upsert(&index, path, &meta)) FAIL("upsert");
        if (i % 3 == 0) {
            unsigned long *words = (unsigned long *)xp25_alloc(3 * sizeof(unsigned long));
            ROVER_ENTRY *e = rover_index_find(&index, path);
            words[0] = 1; words[1] = 7; words[2] = 99;
            e->words = words;
            e->word_count = 3;
        }
    }
    xp25_buf_init(&image);
    if (!rover_index_serialize(&index, &image)) FAIL("serialize");
    data = (unsigned char *)malloc(image.len + MAX_INPUT + 64);
    for (i = 0; i < iterations; ++i) {
        ROVER_INDEX loaded;
        char error[96];
        size_t n = image.len;
        memcpy(data, image.data, n);
        if (rnd() % 8) {
            /* Mutate the body and re-seal it: the checksum detects corruption, it is not an authenticity check. */
            size_t body = n - 32;
            body = mutate(data, body, image.len + MAX_INPUT);
            xp25_sha256(data, body, data + body);
            n = body + 32;
        } else n = mutate(data, n, image.len + MAX_INPUT);
        rover_index_init(&loaded);
        if (rover_index_deserialize(&loaded, data, n, error, sizeof(error))) {
            XP25_BUF again;
            ROVER_INDEX second;
            xp25_buf_init(&again);
            rover_index_init(&second);
            if (!rover_index_serialize(&loaded, &again) || !rover_index_deserialize(&second, (const unsigned char *)again.data, again.len, error, sizeof(error)))
                FAIL("a loaded index does not reserialize");
            rover_index_free(&second);
            xp25_buf_free(&again);
        }
        rover_index_free(&loaded);
    }
    free(data);
    xp25_buf_free(&image);
    rover_index_free(&index);
    printf("target=rover_index runs=%ld\n", iterations);
}

static void fuzz_offline(long iterations)
{
    static const char *const seeds[] = {
        "[Network]\nProxy=127.0.0.1:8080\nDNS=8.8.8.8\n", "127.0.0.1 localhost\n::1 localhost\n0.0.0.0 example.com\n",
        "explain \"C:\\Documents and Settings\\XP25\\notes.txt\" please", "why is my internet slow",
        "restart the print spooler", "show the event log errors from today" };
    static unsigned char buf[MAX_INPUT + 1];
    long i;
    for (i = 0; i < iterations; ++i) {
        XP25_BUF findings;
        long fix_line;
        char fix_old[128], fix_new[128], path[260];
        size_t n = next_input(seeds, sizeof(seeds) / sizeof(seeds[0]), buf);
        (void)n;
        xp25_buf_init(&findings);
        (void)xp25_analyze_network_text((const char *)buf, &findings, &fix_line, fix_old, fix_new, sizeof(fix_old));
        (void)xp25_offline_intent((const char *)buf);
        (void)xp25_offline_path((const char *)buf, path, sizeof(path));
        xp25_buf_free(&findings);
    }
    printf("target=offline_text runs=%ld\n", iterations);
}

static void fuzz_policy(long iterations)
{
    static const char *const seeds[] = {
        "C:\\Documents and Settings\\XP25\\My Documents\\a.txt", "C:\\WINDOWS\\system32\\drivers\\etc\\hosts",
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ipconfig /all", "ping -n 4 xp25.test",
        "sc query Spooler", "Spooler", "dir C:\\" };
    static unsigned char buf[MAX_INPUT + 1];
    static const char *const ops[] = { "stat", "list", "read_text", "write_text", "copy", "move", "rename", "delete", "mkdir", "clean_temp", "x" };
    XP25_PATHS paths;
    long i;
    memset(&paths, 0, sizeof(paths));
    paths.windows = "C:\\WINDOWS";
    paths.profile = "C:\\Documents and Settings\\XP25";
    paths.other_profiles_root = "C:\\Documents and Settings";
    paths.temp = "C:\\Documents and Settings\\XP25\\Local Settings\\Temp";
    paths.program_files = "C:\\Program Files";
    paths.secret_store = "C:\\Documents and Settings\\XP25\\Application Data\\XP25\\secret.dat";
    for (i = 0; i < iterations; ++i) {
        char reason[160], canonical[520];
        size_t n = next_input(seeds, sizeof(seeds) / sizeof(seeds[0]), buf);
        (void)n;
        (void)xp25_policy_command((const char *)buf, reason, sizeof(reason));
        (void)xp25_policy_registry((const char *)buf, canonical, sizeof(canonical), reason, sizeof(reason));
        (void)xp25_policy_file(ops[rnd() % 11], (const char *)buf, &paths, reason, sizeof(reason));
        (void)xp25_policy_service((const char *)buf, rnd() % 2 ? "restart" : "stop", rnd() % 2 ? NULL : "Spooler, W32Time",
                                  (int)(rnd() % 2), reason, sizeof(reason));
        (void)xp25_policy_process(rnd() % 9000, (const char *)buf, "terminate", reason, sizeof(reason));
        (void)xp25_utf8_clip((const char *)buf, rnd() % 300);
    }
    printf("target=agent_policy runs=%ld\n", iterations);
}

static void fuzz_sec_backup(long iterations)
{
    const char *target = "sec_backup";
    static char seeds_store[4][SEC_BACKUP_DATA_MAX * 3];
    const char *seeds[4];
    static unsigned char buf[MAX_INPUT + 1];
    SEC_BACKUP_RECORD r;
    unsigned s, count = 0;
    long i;
    /* Seeds are produced by the formatter itself from valid records of each kind. */
    for (s = 0; s < 4 && count < 4; ++s) {
        memset(&r, 0, sizeof(r));
        r.item = s + 1;
        if (r.item == SEC_ITEM_SERVICE) { strcpy(r.id, sec_service_rule_at(0)->name); r.start = 4; r.running = 1; }
        else if (r.item == SEC_ITEM_REGISTRY) { strcpy(r.id, sec_registry_rule_at(0)->id); r.present = 1; r.type = 4; r.size = 4; r.data[0] = 1; }
        else if (r.item == SEC_ITEM_AUDIT) { strcpy(r.id, sec_audit_category_name(0)); r.options = 3; }
        else { strcpy(r.id, sec_acl_rule_at(0)->id); r.size = 11; memcpy(r.data, "C:\\x\0D:P(A;", 11); }
        if (sec_backup_format(&r, seeds_store[count], sizeof(seeds_store[count]))) {
            size_t len = strlen(seeds_store[count]);
            if (len && seeds_store[count][len - 1] == '\n') seeds_store[count][len - 1] = 0;
            seeds[count] = seeds_store[count];
            ++count;
        }
    }
    if (!count) { FAIL("no seed record could be formatted"); return; }
    for (i = 0; i < iterations; ++i) {
        size_t n = next_input(seeds, count, buf);
        (void)n;
        memset(&r, 0, sizeof(r));
        if (sec_backup_parse((const char *)buf, &r)) {
            static char line[SEC_BACKUP_DATA_MAX * 3];
            SEC_BACKUP_RECORD again;
            size_t len = sec_backup_format(&r, line, sizeof(line));
            if (!len) FAIL("a parsed record does not format");
            else {
                if (line[len - 1] == '\n') line[len - 1] = 0;
                memset(&again, 0, sizeof(again));
                if (!sec_backup_parse(line, &again) || memcmp(&again, &r, sizeof(r))) FAIL("backup record round trip");
            }
        }
    }
    printf("target=sec_backup runs=%ld seeds=%u\n", iterations, count);
}

static void fuzz_winlogon(long iterations)
{
    static const char *const seeds[] = { "PATH=C:\\WINDOWS\nUSERPROFILE=C:\\x\n=C:=C:\\\n\n", "A=1\nB=2\n\n" };
    static const char *const class_seeds[] = { "0123456789abcdef0123456789abcdef", "deadbeef" };
    static unsigned char buf[MAX_INPUT + 1];
    unsigned short block[MAX_INPUT + 2];
    long i;
    for (i = 0; i < iterations; ++i) {
        size_t n = next_input(seeds, 2, buf), k;
        unsigned cursor = 0, name_len, value_len, length;
        const unsigned short *name, *value;
        static const unsigned short path_name[] = { 'P', 'A', 'T', 'H', 0 };
        for (k = 0; k < n; ++k) block[k] = buf[k] == '\n' ? 0 : (rnd() % 64 ? buf[k] : (unsigned short)rnd());
        /* The capacity may cut the block anywhere, including inside an entry. */
        while (wl_environment_next(block, (unsigned)n, &cursor, &name, &name_len, &value, &value_len) == 1) {}
        (void)wl_environment_find(block, (unsigned)n, path_name, &value, &length);
        {
            const char *classes[4];
            char parts[4][MAX_INPUT / 4 + 1];
            unsigned char key[16];
            int j;
            for (j = 0; j < 4; ++j) {
                size_t m = next_input(class_seeds, 2, buf);
                if (m > MAX_INPUT / 4) m = MAX_INPUT / 4;
                memcpy(parts[j], buf, m);
                parts[j][m] = 0;
                classes[j] = parts[j];
            }
            (void)wl_decode_boot_classes(classes, key);
        }
    }
    printf("target=winlogon_env_bootkey runs=%ld\n", iterations);
}

int main(int argc, char **argv)
{
    long iterations = argc > 1 ? atol(argv[1]) : 20000;
    if (argc > 2) rng_state = strtoul(argv[2], NULL, 0) | 1UL;
    fuzz_json(iterations);
    fuzz_llm(iterations);
    fuzz_rover_query(iterations);
    fuzz_rover_index(iterations / 4);
    fuzz_offline(iterations);
    fuzz_policy(iterations);
    fuzz_sec_backup(iterations);
    fuzz_winlogon(iterations);
    printf("failures=%d\n", failures);
    return failures != 0;
}
