/* XP25 AI runtime: minimal HTTP/1.1 client over Winsock 2 (NT 5.1).
   Plain HTTP only: it is used for the authenticated XP25 gateway and for
   explicitly configured local providers. It never handles https:// URLs. */
#include <winsock2.h>
#include <windows.h>
#include <string.h>
#include "xp25_http.h"

#define MAX_RESPONSE (8 * 1024 * 1024)

static void say(char *error, size_t size, const char *text) { if (error && size) lstrcpynA(error, text, (int)size); }

int xp25w_parse_url(const char *url, char *host, size_t host_size, unsigned short *port, char *path, size_t path_size)
{
    const char *p, *end;
    size_t n;
    if (!xp25_starts_with_i(url, "http://")) return 0;
    p = url + 7;
    for (end = p; *end && *end != ':' && *end != '/'; ++end) {}
    n = (size_t)(end - p);
    if (!n || n >= host_size) return 0;
    memcpy(host, p, n);
    host[n] = 0;
    *port = 80;
    if (*end == ':') {
        xp25_u64 v;
        const char *digits = ++end;
        while (xp25_is_digit((unsigned char)*end)) ++end;
        if (!xp25_parse_u64(digits, (size_t)(end - digits), &v) || !v || v > 65535) return 0;
        *port = (unsigned short)v;
    }
    if (!*end) end = "/";
    if (*end != '/' || strlen(end) >= path_size) return 0;
    lstrcpynA(path, end, (int)path_size);
    n = strlen(path);
    while (n > 1 && path[n - 1] == '/') path[--n] = 0;
    return 1;
}

static SOCKET connect_to(const char *host, unsigned short port, long timeout_ms, char *error, size_t size)
{
    struct sockaddr_in sa;
    unsigned long addr = inet_addr(host);
    SOCKET s;
    u_long mode = 1;
    fd_set writable, failed;
    struct timeval tv;
    int sel;
    if (addr == INADDR_NONE) {
        struct hostent *he = gethostbyname(host);
        if (!he || he->h_addrtype != AF_INET || !he->h_addr_list[0]) { say(error, size, "dns_failed"); return INVALID_SOCKET; }
        memcpy(&addr, he->h_addr_list[0], 4);
    }
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) { say(error, size, "socket_failed"); return s; }
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = addr;
    ioctlsocket(s, FIONBIO, &mode);
    connect(s, (struct sockaddr *)&sa, sizeof(sa));
    writable.fd_count = failed.fd_count = 1;
    writable.fd_array[0] = failed.fd_array[0] = s;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    sel = select(0, NULL, &writable, &failed, &tv);
    if (sel <= 0 || !FD_ISSET(s, &writable)) {
        closesocket(s);
        say(error, size, sel == 0 ? "connect_timeout" : "connect_failed");
        return INVALID_SOCKET;
    }
    mode = 0;
    ioctlsocket(s, FIONBIO, &mode);
    {
        int ms = (int)timeout_ms;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&ms, sizeof(ms));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&ms, sizeof(ms));
    }
    return s;
}

static int send_all(SOCKET s, const char *data, size_t n)
{
    while (n) {
        int sent = send(s, data, n > 65536 ? 65536 : (int)n, 0);
        if (sent <= 0) return 0;
        data += sent;
        n -= (size_t)sent;
    }
    return 1;
}

int xp25w_http_header(const XP25_HTTP_RESPONSE *r, const char *name, char *out, size_t size)
{
    const char *p = r->headers.data, *line;
    size_t n = strlen(name);
    out[0] = 0;
    if (!p) return 0;
    for (line = p; line && *line; line = strstr(line, "\r\n") ? strstr(line, "\r\n") + 2 : NULL) {
        if (xp25_strnieq(line, name, n) && line[n] == ':') {
            const char *v = line + n + 1, *end;
            size_t len;
            while (*v == ' ' || *v == '\t') ++v;
            end = strstr(v, "\r\n");
            len = end ? (size_t)(end - v) : strlen(v);
            if (len >= size) len = size - 1;
            memcpy(out, v, len);
            out[len] = 0;
            return 1;
        }
    }
    return 0;
}

static int dechunk(const char *data, size_t n, XP25_BUF *body)
{
    size_t pos = 0;
    for (;;) {
        xp25_u64 chunk = 0;
        size_t digits = 0;
        while (pos + digits < n) {
            char c = data[pos + digits];
            int v = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
            if (v < 0) break;
            chunk = chunk * 16 + (xp25_u64)v;
            if (++digits > 8) return 0;
        }
        if (!digits) return 0;
        pos += digits;
        while (pos < n && data[pos] != '\n') ++pos;
        ++pos;
        if (!chunk) return 1;
        if (pos + chunk > n) return 0;
        xp25_buf_append(body, data + pos, (size_t)chunk);
        pos += (size_t)chunk + 2;
    }
}

int xp25w_http(const char *url, const char *method, const char *headers, const char *body, size_t body_len,
               long timeout_seconds, XP25_HTTP_RESPONSE *r, char *error, size_t error_size)
{
    char host[256], path[1024], *head_end, length[32], encoding[64];
    unsigned short port;
    WSADATA wsa;
    SOCKET s;
    XP25_BUF request, raw;
    char chunk[16384];
    int got;
    memset(r, 0, sizeof(*r));
    xp25_buf_init(&r->headers);
    xp25_buf_init(&r->body);
    if (!xp25w_parse_url(url, host, sizeof(host), &port, path, sizeof(path))) {
        say(error, error_size, "bad_url");
        return 0;
    }
    if (WSAStartup(MAKEWORD(2, 2), &wsa)) { say(error, error_size, "winsock_unavailable"); return 0; }
    s = connect_to(host, port, timeout_seconds * 1000 > 30000 ? 30000 : timeout_seconds * 1000, error, error_size);
    if (s == INVALID_SOCKET) { WSACleanup(); return 0; }
    xp25_buf_init(&request);
    xp25_buf_puts(&request, method);
    xp25_buf_putc(&request, ' ');
    xp25_buf_puts(&request, path);
    xp25_buf_puts(&request, " HTTP/1.1\r\nHost: ");
    xp25_buf_puts(&request, host);
    if (port != 80) { xp25_buf_putc(&request, ':'); xp25_buf_u64(&request, port); }
    xp25_buf_puts(&request, "\r\nUser-Agent: XP25-Agent/1.0 (Windows NT 5.1)\r\nAccept: application/json\r\nConnection: close\r\n");
    if (body) {
        xp25_buf_puts(&request, "Content-Type: application/json\r\nContent-Length: ");
        xp25_buf_u64(&request, (xp25_u64)body_len);
        xp25_buf_puts(&request, "\r\n");
    }
    if (headers) xp25_buf_puts(&request, headers);
    xp25_buf_puts(&request, "\r\n");
    if (!xp25_buf_ok(&request) || !send_all(s, request.data, request.len) || (body && !send_all(s, body, body_len))) {
        xp25_buf_free(&request);
        closesocket(s);
        WSACleanup();
        say(error, error_size, "send_failed");
        return 0;
    }
    xp25_buf_free(&request);
    xp25_buf_init(&raw);
    while ((got = recv(s, chunk, sizeof(chunk), 0)) > 0) {
        if (raw.len + (size_t)got > MAX_RESPONSE) { xp25_buf_free(&raw); closesocket(s); WSACleanup(); say(error, error_size, "response_too_large"); return 0; }
        xp25_buf_append(&raw, chunk, (size_t)got);
    }
    if (got < 0) {
        int wsa_error = WSAGetLastError();
        xp25_buf_free(&raw);
        closesocket(s);
        WSACleanup();
        say(error, error_size, wsa_error == WSAETIMEDOUT ? "timeout" : "receive_failed");
        return 0;
    }
    closesocket(s);
    WSACleanup();
    head_end = raw.data ? strstr(raw.data, "\r\n\r\n") : NULL;
    if (!head_end || raw.len < 12 || strncmp(raw.data, "HTTP/1.", 7)) {
        xp25_buf_free(&raw);
        say(error, error_size, "malformed_http_response");
        return 0;
    }
    r->status = (raw.data[9] - '0') * 100 + (raw.data[10] - '0') * 10 + (raw.data[11] - '0');
    xp25_buf_append(&r->headers, raw.data, (size_t)(head_end - raw.data) + 2);
    head_end += 4;
    if (xp25w_http_header(r, "Transfer-Encoding", encoding, sizeof(encoding)) && xp25_stristr(encoding, "chunked")) {
        if (!dechunk(head_end, raw.len - (size_t)(head_end - raw.data), &r->body)) {
            xp25_buf_free(&raw);
            say(error, error_size, "malformed_chunked_body");
            return 0;
        }
    } else {
        size_t n = raw.len - (size_t)(head_end - raw.data);
        xp25_u64 declared;
        if (xp25w_http_header(r, "Content-Length", length, sizeof(length)) &&
            xp25_parse_u64(length, strlen(length), &declared) && declared < n) n = (size_t)declared;
        xp25_buf_append(&r->body, head_end, n);
    }
    xp25_buf_free(&raw);
    if (!r->body.data) xp25_buf_append(&r->body, "", 0);
    return xp25_buf_ok(&r->body);
}

void xp25w_http_free(XP25_HTTP_RESPONSE *r)
{
    xp25_buf_free(&r->headers);
    xp25_buf_free(&r->body);
}
