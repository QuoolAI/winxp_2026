/* MerlinClient.dll: authenticated HTTP/1.1 to the MerlinAI Builder and to the
   host deployment agent, report transfer and the installation manifest.

   NT 5.1 SChannel cannot negotiate the TLS versions a modern builder needs,
   so the guest speaks plain HTTP to a relay on its own host (by default the
   isolated libvirt bridge, 10.25.0.1). Every request is authenticated with
   XP25-MERLIN1 (challenge, nonce, HMAC-SHA256 over method, path,
   installation and body hash) and every reply must carry a valid HMAC, so a
   relay or anything on the path can neither forge requests nor alter replies
   unnoticed. The link is not encrypted: diagnostics are redacted before they
   leave, and the relay forwards to a remote builder over TLS. */
#include <winsock2.h>
#include <windows.h>
#include <string.h>
#include "mc_internal.h"
#include "../../xp25-agent/llm/xp25_sha256.h"

#ifdef _MSC_VER
#pragma warning(disable : 4127) /* WinSock FD_SET expands to do { } while (0) */
#endif

#define MAX_REPLY (4UL * 1024UL * 1024UL)
#define MAX_DUMP (8UL * 1024UL * 1024UL)

static BOOL parse_base(const WCHAR *url, char *host, int host_size, unsigned short *port, char *prefix, int prefix_size)
{
    char u[260];
    char *h, *slash, *colon;
    unsigned long p = 80;
    if (!MerlinWideToUtf8(url, u, sizeof(u)) || u[0] == 0 || lstrlenA(u) < 8) return FALSE;
    if (CompareStringA(LOCALE_SYSTEM_DEFAULT, NORM_IGNORECASE, u, 7, "http://", 7) != CSTR_EQUAL) return FALSE;
    h = u + 7;
    slash = h;
    while (*slash && *slash != '/') ++slash;
    if (*slash) {
        merlin_copy(prefix, prefix_size, slash);
        *slash = 0;
    } else prefix[0] = 0;
    if (prefix[0] && prefix[lstrlenA(prefix) - 1] == '/') prefix[lstrlenA(prefix) - 1] = 0;
    colon = h;
    while (*colon && *colon != ':') ++colon;
    if (*colon) {
        char *d;
        *colon++ = 0;
        p = 0;
        for (d = colon; *d; ++d) {
            if (*d < '0' || *d > '9' || p > 65535) return FALSE;
            p = p * 10 + (unsigned long)(*d - '0');
        }
        if (!p || p > 65535) return FALSE;
    }
    if (!h[0] || lstrlenA(h) >= host_size) return FALSE;
    merlin_copy(host, host_size, h);
    *port = (unsigned short)p;
    return TRUE;
}

static void reply_error(MERLIN_REPLY *r, const char *code, DWORD detail)
{
    r->status = 0;
    merlin_copy(r->error, sizeof(r->error), code);
    if (detail) {
        merlin_append(r->error, sizeof(r->error), " ");
        merlin_append_ulong(r->error, sizeof(r->error), detail);
    }
}

/* Value of a response header (case-insensitive name) into out. */
static BOOL header_value(const char *headers, const char *name, char *out, int size)
{
    const char *line = headers;
    int n = lstrlenA(name);
    while (line && *line) {
        const char *end = line;
        while (*end && *end != '\r' && *end != '\n') ++end;
        if (end - line > n && line[n] == ':' && CompareStringA(LOCALE_SYSTEM_DEFAULT, NORM_IGNORECASE, line, n, name, n) == CSTR_EQUAL) {
            const char *v = line + n + 1;
            int len;
            while (*v == ' ') ++v;
            len = (int)(end - v);
            if (len >= size) return FALSE;
            CopyMemory(out, v, len);
            out[len] = 0;
            return TRUE;
        }
        line = end;
        while (*line == '\r' || *line == '\n') ++line;
    }
    return FALSE;
}

static DWORD http(const WCHAR *base, const char *method, const char *path, const char *extra_headers, const char *body,
                  DWORD body_len, MERLIN_REPLY *r, char *headers_out, int headers_size)
{
    WSADATA wsa;
    char host[128], prefix[128], head[2048], *buffer = NULL, *sep;
    unsigned short port;
    struct hostent *he;
    struct sockaddr_in addr;
    SOCKET s = INVALID_SOCKET;
    DWORD used = 0, capacity = 64 * 1024, timeout = 120000;
    fd_set wset;
    struct timeval tv;
    u_long nonblocking = 1;
    int n, status = 0;
    ZeroMemory(r, sizeof(*r));
    if (headers_out && headers_size) headers_out[0] = 0;
    if (!parse_base(base, host, sizeof(host), &port, prefix, sizeof(prefix))) {
        reply_error(r, "endpoint_invalid", 0);
        return ERROR_INVALID_PARAMETER;
    }
    if (WSAStartup(MAKEWORD(2, 2), &wsa)) {
        reply_error(r, "winsock_failed", 0);
        return ERROR_NETWORK_UNREACHABLE;
    }
    he = gethostbyname(host);
    if (!he || he->h_addrtype != AF_INET) {
        reply_error(r, "dns_failed", (DWORD)WSAGetLastError());
        WSACleanup();
        return ERROR_HOST_UNREACHABLE;
    }
    ZeroMemory(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    CopyMemory(&addr.sin_addr, he->h_addr_list[0], 4);
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        reply_error(r, "socket_failed", (DWORD)WSAGetLastError());
        WSACleanup();
        return ERROR_NETWORK_UNREACHABLE;
    }
    ioctlsocket(s, FIONBIO, &nonblocking);
    connect(s, (struct sockaddr *)&addr, sizeof(addr));
    FD_ZERO(&wset);
    FD_SET(s, &wset);
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    if (select(0, NULL, &wset, NULL, &tv) != 1) {
        reply_error(r, "connect_failed", 0);
        closesocket(s);
        WSACleanup();
        return ERROR_CONNECTION_REFUSED;
    }
    nonblocking = 0;
    ioctlsocket(s, FIONBIO, &nonblocking);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));
    head[0] = 0;
    merlin_append(head, sizeof(head), method);
    merlin_append(head, sizeof(head), " ");
    merlin_append(head, sizeof(head), prefix);
    merlin_append(head, sizeof(head), path);
    merlin_append(head, sizeof(head), " HTTP/1.1\r\nHost: ");
    merlin_append(head, sizeof(head), host);
    merlin_append(head, sizeof(head), "\r\nUser-Agent: XP25-MerlinAI/1.0\r\nConnection: close\r\nContent-Length: ");
    merlin_append_ulong(head, sizeof(head), body ? body_len : 0);
    merlin_append(head, sizeof(head), "\r\n");
    if (extra_headers) merlin_append(head, sizeof(head), extra_headers);
    if (!merlin_append(head, sizeof(head), "\r\n")) {
        reply_error(r, "request_too_large", 0);
        closesocket(s);
        WSACleanup();
        return ERROR_INSUFFICIENT_BUFFER;
    }
    if (send(s, head, lstrlenA(head), 0) != lstrlenA(head)) goto send_failed;
    while (body && body_len) {
        int chunk = body_len > 65536 ? 65536 : (int)body_len;
        n = send(s, body, chunk, 0);
        if (n <= 0) goto send_failed;
        body += n;
        body_len -= (DWORD)n;
    }
    buffer = (char *)mc_alloc(capacity + 1);
    while (buffer) {
        if (used == capacity) {
            char *bigger;
            if (capacity >= MAX_REPLY + 8192) break;
            bigger = (char *)mc_alloc(capacity * 2 + 1);
            if (!bigger) break;
            CopyMemory(bigger, buffer, used);
            mc_free(buffer);
            buffer = bigger;
            capacity *= 2;
        }
        n = recv(s, buffer + used, (int)(capacity - used), 0);
        if (n <= 0) break;
        used += (DWORD)n;
    }
    closesocket(s);
    WSACleanup();
    if (!buffer) {
        reply_error(r, "out_of_memory", 0);
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    buffer[used] = 0;
    sep = used > 12 ? strstr(buffer, "\r\n\r\n") : NULL;
    if (!sep || memcmp(buffer, "HTTP/1.", 7) || buffer[8] != ' ') {
        reply_error(r, used ? "malformed_reply" : "no_reply", used);
        mc_free(buffer);
        return ERROR_INVALID_DATA;
    }
    for (n = 9; n < 12; ++n) {
        if (buffer[n] < '0' || buffer[n] > '9') {
            reply_error(r, "malformed_status", 0);
            mc_free(buffer);
            return ERROR_INVALID_DATA;
        }
        status = status * 10 + buffer[n] - '0';
    }
    *sep = 0;
    {
        char length[24];
        DWORD body_used = used - (DWORD)(sep + 4 - buffer), declared = 0;
        int i;
        if (header_value(buffer, "Content-Length", length, sizeof(length))) {
            for (i = 0; length[i] >= '0' && length[i] <= '9' && i < 9; ++i) declared = declared * 10 + (DWORD)(length[i] - '0');
            if (declared != body_used) {
                reply_error(r, "truncated_reply", body_used);
                mc_free(buffer);
                return ERROR_INVALID_DATA;
            }
        }
        if (headers_out) merlin_copy(headers_out, headers_size, buffer);
        r->body = (char *)mc_alloc(body_used + 1);
        if (!r->body) {
            reply_error(r, "out_of_memory", 0);
            mc_free(buffer);
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        CopyMemory(r->body, sep + 4, body_used);
        r->body[body_used] = 0;
        r->body_len = body_used;
    }
    r->status = status;
    mc_free(buffer);
    return 0;
send_failed:
    reply_error(r, "send_failed", (DWORD)WSAGetLastError());
    closesocket(s);
    WSACleanup();
    return ERROR_NETWORK_UNREACHABLE;
}

void MERLINAPI MerlinFreeReply(MERLIN_REPLY *r)
{
    mc_free(r->body);
    r->body = NULL;
    r->body_len = 0;
}

static DWORD signed_call(int deploy, const char *method, const char *path, const char *body, DWORD body_len,
                         const char *content_type, MERLIN_REPLY *r)
{
    MERLIN_CONFIG config;
    MERLIN_IDENTITY id;
    MERLIN_REPLY challenge_reply;
    MERLIN_JSON_DOC *doc;
    char challenge[80], nonce[40], mac[MERLIN_SIG_SIZE], full[256], headers[1024], reply_headers[4096], reply_mac[80];
    const char *prefix = deploy ? "/deploy/v1" : "/merlin/v1";
    const char *label = deploy ? MERLIN_LABEL_DEPLOY : MERLIN_LABEL_BUILDER;
    const unsigned char *key;
    const WCHAR *base;
    DWORD error;
    ZeroMemory(r, sizeof(*r));
    MerlinGetConfig(&config);
    base = deploy ? config.deploy : config.builder;
    if (!base[0]) {
        reply_error(r, deploy ? "deployment_agent_not_configured" : "builder_not_configured", 0);
        return ERROR_NOT_FOUND;
    }
    error = MerlinGetIdentity(&id);
    if (error || !(deploy ? id.has_deploy_key : id.has_builder_key)) {
        reply_error(r, error == ERROR_ACCESS_DENIED ? "credentials_need_administrator" : "credentials_not_configured", error);
        SecureZeroMemory(&id, sizeof(id));
        return error ? error : ERROR_NOT_FOUND;
    }
    key = deploy ? id.deploy_key : id.builder_key;
    full[0] = 0;
    merlin_append(full, sizeof(full), prefix);
    merlin_append(full, sizeof(full), "/challenge");
    error = http(base, "GET", full, NULL, NULL, 0, &challenge_reply, NULL, 0);
    doc = (MERLIN_JSON_DOC *)mc_alloc(sizeof(MERLIN_JSON_DOC));
    if (!doc && !error) error = ERROR_NOT_ENOUGH_MEMORY;
    if (error || challenge_reply.status != 200 || !merlin_json_parse(doc, challenge_reply.body, challenge_reply.body_len) ||
        !merlin_json_member_string(doc, 0, "challenge", challenge, sizeof(challenge)) || !merlin_hex_valid(challenge, 64)) {
        mc_free(doc);
        if (!error) reply_error(r, "challenge_failed", (DWORD)challenge_reply.status);
        else CopyMemory(r->error, challenge_reply.error, sizeof(r->error));
        MerlinFreeReply(&challenge_reply);
        SecureZeroMemory(&id, sizeof(id));
        return error ? error : ERROR_INVALID_DATA;
    }
    MerlinFreeReply(&challenge_reply);
    mc_free(doc);
    mc_random_hex(nonce, 16);
    full[0] = 0;
    merlin_append(full, sizeof(full), prefix);
    if (!merlin_append(full, sizeof(full), path) || !nonce[0] ||
        !merlin_sign_request(label, key, MERLIN_KEY_BYTES, method, full, id.installation, challenge, nonce, body,
                             body ? body_len : 0, mac)) {
        reply_error(r, "request_not_signable", 0);
        SecureZeroMemory(&id, sizeof(id));
        return ERROR_INVALID_PARAMETER;
    }
    headers[0] = 0;
    merlin_append(headers, sizeof(headers), "X-Merlin-Installation: ");
    merlin_append(headers, sizeof(headers), id.installation);
    merlin_append(headers, sizeof(headers), "\r\nX-Merlin-Challenge: ");
    merlin_append(headers, sizeof(headers), challenge);
    merlin_append(headers, sizeof(headers), "\r\nX-Merlin-Nonce: ");
    merlin_append(headers, sizeof(headers), nonce);
    merlin_append(headers, sizeof(headers), "\r\nX-Merlin-Signature: ");
    merlin_append(headers, sizeof(headers), mac);
    merlin_append(headers, sizeof(headers), "\r\nContent-Type: ");
    merlin_append(headers, sizeof(headers), content_type ? content_type : "application/json");
    merlin_append(headers, sizeof(headers), "\r\n");
    error = http(base, method, full, headers, body, body_len, r, reply_headers, sizeof(reply_headers));
    if (!error && (!header_value(reply_headers, "X-Merlin-Signature", reply_mac, sizeof(reply_mac)) ||
                   !merlin_verify_response(label, key, MERLIN_KEY_BYTES, nonce, (unsigned)r->status, r->body, r->body_len, reply_mac))) {
        /* An unauthenticated reply is discarded entirely. */
        MerlinFreeReply(r);
        reply_error(r, "reply_not_authenticated", (DWORD)r->status);
        error = ERROR_ACCESS_DENIED;
    }
    SecureZeroMemory(&id, sizeof(id));
    return error;
}

DWORD MERLINAPI MerlinBuilderCall(const char *method, const char *path, const char *body, DWORD body_len,
                                  const char *content_type, MERLIN_REPLY *reply)
{
    return signed_call(0, method, path, body, body_len, content_type, reply);
}

DWORD MERLINAPI MerlinDeployCall(const char *method, const char *path, const char *body, DWORD body_len, MERLIN_REPLY *reply)
{
    return signed_call(1, method, path, body, body_len, "application/json", reply);
}

/* ---- installation manifest ---- */
static const WCHAR *const components[] = {
    L"system32\\winlogon.exe", L"system32\\xp25krnl.exe", L"system32\\xp25hal.dll", L"system32\\win32k.sys",
    L"system32\\ntdll.dll", L"system32\\kernel32.dll", L"system32\\user32.dll", L"system32\\gdi32.dll",
    L"system32\\lsasrv.dll", L"system32\\msgina.dll", L"system32\\userenv.dll", L"system32\\services.exe",
    L"explorer.exe",
    L"%ProgramFiles%\\XP25\\xp25agent.dll", L"%ProgramFiles%\\XP25\\ClippyAI.exe", L"%ProgramFiles%\\XP25\\RoverAI.exe",
    L"%ProgramFiles%\\XP25\\RoverAIBand.dll", L"%ProgramFiles%\\XP25\\XP25Broker.exe",
    L"%ProgramFiles%\\XP25\\MerlinAI\\MerlinAI.exe", L"%ProgramFiles%\\XP25\\MerlinAI\\MerlinClient.dll",
    L"%ProgramFiles%\\XP25\\MerlinAI\\MerlinCrash.exe", L"%ProgramFiles%\\XP25\\MerlinAI\\MerlinAI.cpl",
    L"%ProgramFiles%\\XP25\\MerlinAI\\MerlinSvc.exe", L"%ProgramFiles%\\XP25\\MerlinAI\\MerlinTest.exe",
};

static BOOL file_sha256(const WCHAR *path, char out[MERLIN_SIG_SIZE])
{
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    XP25_SHA256 ctx;
    BYTE *buf;
    DWORD got;
    unsigned char digest[32];
    if (f == INVALID_HANDLE_VALUE) return FALSE;
    buf = (BYTE *)mc_alloc(65536);
    if (!buf) {
        CloseHandle(f);
        return FALSE;
    }
    xp25_sha256_init(&ctx);
    while (ReadFile(f, buf, 65536, &got, NULL) && got) xp25_sha256_update(&ctx, buf, got);
    xp25_sha256_final(&ctx, digest);
    CloseHandle(f);
    mc_free(buf);
    out[0] = 0;
    merlin_append_hex(out, MERLIN_SIG_SIZE, digest, 32);
    return TRUE;
}

DWORD MERLINAPI MerlinManifestJson(char *out, DWORD size)
{
    MERLIN_JSON_OUT j;
    WCHAR windir[MAX_PATH], path[MAX_PATH * 2];
    char path8[MAX_PATH * 3], hash[MERLIN_SIG_SIZE], revision[128];
    DWORD len, error;
    char *text;
    unsigned i;
    GetWindowsDirectoryW(windir, MAX_PATH);
    revision[0] = 0;
    text = mc_read_file(L"C:\\xp25\\image-revision.txt", 4096, &len, &error);
    if (text) {
        for (i = 0; text[i] && text[i] != '\r' && text[i] != '\n' && i < sizeof(revision) - 1; ++i) revision[i] = text[i];
        revision[i] = 0;
        merlin_sanitize_line(revision);
        mc_free(text);
    }
    merlin_json_begin(&j, out, size);
    merlin_json_object(&j);
    merlin_json_key(&j, "image_revision");
    merlin_json_string(&j, revision);
    merlin_json_key(&j, "os");
    merlin_json_string(&j, "NT 5.1 x86 (XP25)");
    merlin_json_key(&j, "components");
    merlin_json_array(&j);
    for (i = 0; i < sizeof(components) / sizeof(components[0]); ++i) {
        if (components[i][0] == L'%') {
            if (!ExpandEnvironmentStringsW(components[i], path, MAX_PATH * 2)) continue;
        } else {
            lstrcpyW(path, windir);
            lstrcatW(path, L"\\");
            lstrcatW(path, components[i]);
        }
        MerlinWideToUtf8(path, path8, sizeof(path8));
        merlin_json_object(&j);
        merlin_json_key(&j, "path");
        merlin_json_string(&j, path8);
        if (file_sha256(path, hash)) {
            merlin_json_key(&j, "sha256");
            merlin_json_string(&j, hash);
        } else {
            merlin_json_key(&j, "missing");
            merlin_json_bool(&j, 1);
        }
        merlin_json_end_object(&j);
    }
    merlin_json_end_array(&j);
    merlin_json_end_object(&j);
    return merlin_json_done(&j) ? 0 : ERROR_INSUFFICIENT_BUFFER;
}

/* ---- report transfer ---- */
static void redact_problem(MERLIN_PROBLEM *p)
{
    unsigned i;
    MerlinRedact(p->title, sizeof(p->title));
    MerlinRedact(p->component, sizeof(p->component));
    MerlinRedact(p->impact, sizeof(p->impact));
    MerlinRedact(p->app, sizeof(p->app));
    MerlinRedact(p->module, sizeof(p->module));
    for (i = 0; i < p->evidence_count; ++i) MerlinRedact(p->evidence[i], MERLIN_TEXT);
}

DWORD MERLINAPI MerlinTransfer(const char *const *ids, int count, char *message, DWORD message_size)
{
    MERLIN_JSON_OUT j;
    MERLIN_IDENTITY id;
    MERLIN_REPLY reply;
    MERLIN_PROBLEM *p;
    MERLIN_JSON_DOC *doc;
    char *body;
    DWORD body_size = 1024 * 1024, error;
    int i, sent = 0, dumps = 0;
    message[0] = 0;
    if (!MerlinIsAdmin()) {
        merlin_copy(message, message_size, "Transferring reports needs an administrator; the consent is recorded and the reports stay queued.");
        return ERROR_ACCESS_DENIED;
    }
    error = MerlinGetIdentity(&id);
    SecureZeroMemory(id.builder_key, sizeof(id.builder_key));
    SecureZeroMemory(id.deploy_key, sizeof(id.deploy_key));
    if (error) {
        merlin_copy(message, message_size, "MerlinAI has no builder credentials yet (Settings).");
        return error;
    }
    body = (char *)mc_alloc(body_size);
    p = (MERLIN_PROBLEM *)mc_alloc(sizeof(MERLIN_PROBLEM));
    doc = (MERLIN_JSON_DOC *)mc_alloc(sizeof(MERLIN_JSON_DOC));
    if (!body || !p || !doc) {
        mc_free(body);
        mc_free(p);
        mc_free(doc);
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    merlin_json_begin(&j, body, body_size);
    merlin_json_object(&j);
    merlin_json_key(&j, "schema");
    merlin_json_string(&j, "xp25-merlin-report/1");
    merlin_json_key(&j, "installation");
    merlin_json_string(&j, id.installation);
    merlin_json_key(&j, "problems");
    merlin_json_array(&j);
    for (i = 0; i < count; ++i) {
        if (MerlinQueueLoad(ids[i], p) || !p->transfer_consent) continue;
        redact_problem(p);
        merlin_json_problem(&j, p);
        ++sent;
    }
    merlin_json_end_array(&j);
    merlin_json_end_object(&j);
    if (!sent) {
        merlin_copy(message, message_size, "None of the selected reports has transfer consent.");
        error = ERROR_NOT_FOUND;
    } else if (!merlin_json_done(&j)) error = ERROR_INSUFFICIENT_BUFFER;
    else {
        error = MerlinBuilderCall("POST", "/reports", body, (DWORD)j.used, "application/json", &reply);
        if (!error && reply.status == 200 && merlin_json_parse(doc, reply.body, reply.body_len)) {
            int accepted = merlin_json_member(doc, 0, "accepted"), k;
            char pid[MERLIN_ID_SIZE];
            for (k = 0; merlin_json_get_string(doc, merlin_json_element(doc, accepted, k), pid, sizeof(pid)); ++k) {
                if (MerlinQueueLoad(pid, p)) continue;
                p->transferred = 1;
                MerlinQueueSave(p);
                if (p->dump_consent && p->dump[0]) {
                    WCHAR path[MAX_PATH];
                    char *dump, dump_path[96];
                    DWORD len, e;
                    MERLIN_REPLY dr;
                    if (mc_queue_path(p->dump, path, MAX_PATH) && (dump = mc_read_file(path, MAX_DUMP, &len, &e)) != NULL) {
                        dump_path[0] = 0;
                        merlin_append(dump_path, sizeof(dump_path), "/reports/");
                        merlin_append(dump_path, sizeof(dump_path), pid);
                        merlin_append(dump_path, sizeof(dump_path), "/dump");
                        if (!MerlinBuilderCall("POST", dump_path, dump, len, "application/octet-stream", &dr) && dr.status == 200) ++dumps;
                        MerlinFreeReply(&dr);
                        mc_free(dump);
                    }
                }
            }
            merlin_copy(message, message_size, "Transferred ");
            merlin_append_ulong(message, message_size, (unsigned long)k);
            merlin_append(message, message_size, " report(s) to the MerlinAI Builder");
            if (dumps) {
                merlin_append(message, message_size, " with ");
                merlin_append_ulong(message, message_size, (unsigned long)dumps);
                merlin_append(message, message_size, " memory dump(s)");
            }
            merlin_append(message, message_size, ". No build was started.");
        } else {
            merlin_copy(message, message_size, "The builder did not accept the reports: ");
            merlin_append(message, message_size, error ? reply.error : "unexpected reply");
            if (!error) error = ERROR_INVALID_DATA;
        }
        MerlinFreeReply(&reply);
    }
    mc_free(body);
    mc_free(p);
    mc_free(doc);
    return error;
}
