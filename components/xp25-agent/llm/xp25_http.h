/* XP25 AI runtime: plain HTTP/1.1 client used by the gateway and local providers. */
#ifndef XP25_HTTP_H
#define XP25_HTTP_H
#include "../runtime/xp25_win.h"

typedef struct {
    int status;
    XP25_BUF headers;
    XP25_BUF body;
} XP25_HTTP_RESPONSE;

int xp25w_parse_url(const char *url, char *host, size_t host_size, unsigned short *port, char *path, size_t path_size);
/* error receives a short machine code (timeout, connect_failed, dns_failed, ...). */
int xp25w_http(const char *url, const char *method, const char *headers, const char *body, size_t body_len,
               long timeout_seconds, XP25_HTTP_RESPONSE *response, char *error, size_t error_size);
int xp25w_http_header(const XP25_HTTP_RESPONSE *response, const char *name, char *out, size_t size);
void xp25w_http_free(XP25_HTTP_RESPONSE *response);
#endif
