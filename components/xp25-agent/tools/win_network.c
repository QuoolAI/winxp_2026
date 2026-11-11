/* XP25 AI runtime: network_diagnostics (IP Helper, Winsock, ICMP echo). */
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <string.h>
#include "win_tools.h"

typedef HANDLE (WINAPI *ICMP_CREATE)(void);
typedef BOOL (WINAPI *ICMP_CLOSE)(HANDLE);
typedef DWORD (WINAPI *ICMP_ECHO)(HANDLE, unsigned long, LPVOID, WORD, LPVOID, LPVOID, DWORD, DWORD);

static void check(XP25_JW *w, const char *name, const char *target, int ok, const char *detail)
{
    xp25_jw_obj(w);
    xp25_jw_key(w, "check"); xp25_jw_str(w, name);
    xp25_jw_key(w, "target"); xp25_jw_str(w, target);
    xp25_jw_key(w, "ok"); xp25_jw_bool(w, ok);
    xp25_jw_key(w, "detail"); xp25_jw_str(w, detail);
    xp25_jw_end(w);
}

static void ping(XP25_JW *w, const char *address)
{
    HMODULE lib = LoadLibraryW(L"iphlpapi.dll");
    ICMP_CREATE create = lib ? (ICMP_CREATE)GetProcAddress(lib, "IcmpCreateFile") : NULL;
    ICMP_CLOSE close_icmp = lib ? (ICMP_CLOSE)GetProcAddress(lib, "IcmpCloseHandle") : NULL;
    ICMP_ECHO echo = lib ? (ICMP_ECHO)GetProcAddress(lib, "IcmpSendEcho") : NULL;
    unsigned long ip = inet_addr(address);
    char data[8] = "XP25AI!", reply[sizeof(ICMP_ECHO_REPLY) + 64];
    HANDLE h;
    XP25_BUF detail;
    xp25_buf_init(&detail);
    if (!create || !close_icmp || !echo || ip == INADDR_NONE || (h = create()) == INVALID_HANDLE_VALUE) {
        check(w, "gateway_ping", address, 0, "ICMP echo is unavailable");
    } else {
        DWORD n = echo(h, ip, data, sizeof(data), NULL, reply, sizeof(reply), 1500);
        if (n && ((ICMP_ECHO_REPLY *)reply)->Status == 0) {
            xp25_buf_puts(&detail, "reply in ");
            xp25_buf_u64(&detail, ((ICMP_ECHO_REPLY *)reply)->RoundTripTime);
            xp25_buf_puts(&detail, " ms");
            check(w, "gateway_ping", address, 1, xp25_buf_cstr(&detail));
        } else check(w, "gateway_ping", address, 0, "no reply within 1.5 seconds");
        close_icmp(h);
    }
    xp25_buf_free(&detail);
    if (lib) FreeLibrary(lib);
}

static void tcp(XP25_JW *w, const char *host, unsigned short port)
{
    struct hostent *he;
    struct sockaddr_in sa;
    SOCKET s;
    u_long nonblocking = 1;
    fd_set writable, failed;
    struct timeval tv;
    XP25_BUF target, detail;
    unsigned long addr = inet_addr(host);
    int ok = 0;
    xp25_buf_init(&target);
    xp25_buf_init(&detail);
    xp25_buf_puts(&target, host);
    xp25_buf_putc(&target, ':');
    xp25_buf_u64(&target, port);
    if (addr == INADDR_NONE) {
        DWORD start = GetTickCount();
        he = gethostbyname(host);
        if (!he || he->h_addrtype != AF_INET || !he->h_addr_list[0]) {
            xp25_buf_puts(&detail, "name did not resolve (WSA error ");
            xp25_buf_u64(&detail, (xp25_u64)WSAGetLastError());
            xp25_buf_puts(&detail, ")");
            check(w, "dns", host, 0, xp25_buf_cstr(&detail));
            xp25_buf_free(&target);
            xp25_buf_free(&detail);
            return;
        }
        memcpy(&addr, he->h_addr_list[0], 4);
        xp25_buf_puts(&detail, "resolved to ");
        xp25_buf_puts(&detail, inet_ntoa(*(struct in_addr *)&addr));
        xp25_buf_puts(&detail, " in ");
        xp25_buf_u64(&detail, GetTickCount() - start);
        xp25_buf_puts(&detail, " ms");
        check(w, "dns", host, 1, xp25_buf_cstr(&detail));
        xp25_buf_reset(&detail);
    }
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s != INVALID_SOCKET) {
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons(port);
        sa.sin_addr.s_addr = addr;
        ioctlsocket(s, FIONBIO, &nonblocking);
        connect(s, (struct sockaddr *)&sa, sizeof(sa));
        writable.fd_count = failed.fd_count = 1;
        writable.fd_array[0] = failed.fd_array[0] = s;
        tv.tv_sec = 3;
        tv.tv_usec = 0;
        ok = select(0, NULL, &writable, &failed, &tv) > 0 && FD_ISSET(s, &writable);
        closesocket(s);
    }
    check(w, "tcp_connect", xp25_buf_cstr(&target), ok, ok ? "connection accepted" : "no connection within 3 seconds");
    xp25_buf_free(&target);
    xp25_buf_free(&detail);
}

/* Host and port of the configured AI endpoint, if any. */
static int endpoint_target(const XP25_CONFIG *config, char *host, size_t size, unsigned short *port)
{
    const char *p = config->endpoint, *end;
    size_t n;
    if (!xp25_starts_with_i(p, "http://") && !xp25_starts_with_i(p, "https://")) return 0;
    *port = (unsigned short)(xp25_starts_with_i(p, "https://") ? 443 : 80);
    p = strstr(p, "//") + 2;
    for (end = p; *end && *end != ':' && *end != '/'; ++end) {}
    n = (size_t)(end - p);
    if (!n || n >= size) return 0;
    memcpy(host, p, n);
    host[n] = 0;
    if (*end == ':') {
        xp25_u64 v = 0;
        const char *q = end + 1;
        size_t digits = 0;
        while (xp25_is_digit((unsigned char)q[digits])) ++digits;
        if (xp25_parse_u64(q, digits, &v) && v > 0 && v < 65536) *port = (unsigned short)v;
    }
    return 1;
}

int tool_network(const XP25_TOOL *tool, const XP25_JNODE *args, XP25_BUF *out, XP25_EGRESS *egress)
{
    XP25W_TOOLS *ctx = TOOL_CONTEXT(tool);
    WSADATA wsa;
    IP_ADAPTER_INFO *adapters = NULL, *a;
    FIXED_INFO *fixed = NULL;
    ULONG size = 0;
    char first_gateway[20] = "", host[256];
    unsigned short port = (unsigned short)tool_int(args, "port", 80, 1, 65535);
    XP25_JW w;
    (void)egress;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    tool_ok_begin(&w, out);
    if (GetNetworkParams(NULL, &size) == ERROR_BUFFER_OVERFLOW && (fixed = (FIXED_INFO *)xp25_alloc(size)) != NULL &&
        GetNetworkParams(fixed, &size) == NO_ERROR) {
        IP_ADDR_STRING *dns;
        xp25_jw_key(&w, "host_name"); xp25_jw_str(&w, fixed->HostName);
        xp25_jw_key(&w, "domain"); xp25_jw_str(&w, fixed->DomainName);
        xp25_jw_key(&w, "dns_servers");
        xp25_jw_arr(&w);
        for (dns = &fixed->DnsServerList; dns; dns = dns->Next)
            if (dns->IpAddress.String[0]) xp25_jw_str(&w, dns->IpAddress.String);
        xp25_jw_end(&w);
    }
    size = 0;
    xp25_jw_key(&w, "adapters");
    xp25_jw_arr(&w);
    if (GetAdaptersInfo(NULL, &size) == ERROR_BUFFER_OVERFLOW && (adapters = (IP_ADAPTER_INFO *)xp25_alloc(size)) != NULL &&
        GetAdaptersInfo(adapters, &size) == NO_ERROR) {
        for (a = adapters; a; a = a->Next) {
            IP_ADDR_STRING *ip;
            XP25_BUF mac;
            UINT i;
            xp25_jw_obj(&w);
            xp25_jw_key(&w, "name"); xp25_jw_str(&w, a->AdapterName);
            xp25_jw_key(&w, "description"); xp25_jw_str(&w, a->Description);
            xp25_buf_init(&mac);
            for (i = 0; i < a->AddressLength && i < 8; ++i) {
                if (i) xp25_buf_putc(&mac, '-');
                xp25_buf_hex(&mac, &a->Address[i], 1);
            }
            xp25_jw_key(&w, "mac"); xp25_jw_str(&w, xp25_buf_cstr(&mac));
            xp25_buf_free(&mac);
            xp25_jw_key(&w, "dhcp"); xp25_jw_bool(&w, a->DhcpEnabled != 0);
            if (a->DhcpEnabled) { xp25_jw_key(&w, "dhcp_server"); xp25_jw_str(&w, a->DhcpServer.IpAddress.String); }
            xp25_jw_key(&w, "ip"); xp25_jw_arr(&w);
            for (ip = &a->IpAddressList; ip; ip = ip->Next) xp25_jw_str(&w, ip->IpAddress.String);
            xp25_jw_end(&w);
            xp25_jw_key(&w, "mask"); xp25_jw_arr(&w);
            for (ip = &a->IpAddressList; ip; ip = ip->Next) xp25_jw_str(&w, ip->IpMask.String);
            xp25_jw_end(&w);
            xp25_jw_key(&w, "gateway"); xp25_jw_arr(&w);
            for (ip = &a->GatewayList; ip; ip = ip->Next)
                if (ip->IpAddress.String[0] && strcmp(ip->IpAddress.String, "0.0.0.0")) {
                    xp25_jw_str(&w, ip->IpAddress.String);
                    if (!first_gateway[0]) lstrcpynA(first_gateway, ip->IpAddress.String, sizeof(first_gateway));
                }
            xp25_jw_end(&w);
            xp25_jw_end(&w);
        }
    }
    xp25_jw_end(&w);
    xp25_jw_key(&w, "checks");
    xp25_jw_arr(&w);
    if (first_gateway[0]) ping(&w, first_gateway);
    else check(&w, "gateway_ping", "", 0, "no default gateway is configured");
    if (xp25_json_string(args, "host")) {
        lstrcpynA(host, xp25_json_string(args, "host"), sizeof(host));
        tcp(&w, host, port);
    } else if (endpoint_target(ctx->config, host, sizeof(host), &port)) {
        tcp(&w, host, port);
    } else if (first_gateway[0]) {
        lstrcpynA(host, "www.microsoft.com", sizeof(host));
        tcp(&w, host, 80);
    }
    xp25_jw_end(&w);
    xp25_free(adapters);
    xp25_free(fixed);
    WSACleanup();
    return tool_finish(&w, out);
}
