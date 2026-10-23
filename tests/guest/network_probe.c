/* Bounded XP networking tests. External traffic is confined by the VM harness. */
#define WINVER 0x0501
#define _WIN32_WINNT 0x0501
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>

static HANDLE serial;
static unsigned failures;
static void emit(const char *line)
{
    DWORD written;
    WriteFile(serial, line, lstrlenA(line), &written, NULL);
}
static void report(const char *name, BOOL pass, DWORD error)
{
    char line[256];
    if (!pass) ++failures;
    wsprintfA(line, "{\"case\":\"%s\",\"status\":\"%s\",\"error\":%lu}\r\n",
              name, pass ? "pass" : "fail", pass ? 0 : error);
    emit(line);
}
static BOOL readable(SOCKET s)
{
    fd_set set;
    struct timeval wait;
    FD_ZERO(&set); FD_SET(s, &set);
    wait.tv_sec = 5; wait.tv_usec = 0;
    return select(0, &set, NULL, NULL, &wait) == 1;
}
static void loopback(BOOL tcp)
{
    SOCKET a = INVALID_SOCKET, b = INVALID_SOCKET, c = INVALID_SOCKET;
    struct sockaddr_in addr = {0};
    int size = sizeof(addr), got = 0;
    char buffer[32];
    const char payload[] = "XP25-native-loopback";
    BOOL ok;
    a = socket(AF_INET, tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
    b = socket(AF_INET, tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ok = a != INVALID_SOCKET && b != INVALID_SOCKET &&
         bind(a, (struct sockaddr *)&addr, sizeof(addr)) == 0 &&
         getsockname(a, (struct sockaddr *)&addr, &size) == 0;
    if (ok && tcp) {
        ok = listen(a, 1) == 0 && connect(b, (struct sockaddr *)&addr, size) == 0 && readable(a);
        if (ok) c = accept(a, NULL, NULL);
        ok = ok && c != INVALID_SOCKET && send(b, payload, sizeof(payload), 0) == sizeof(payload) && readable(c);
        while (ok && got < (int)sizeof(payload)) {
            int n = recv(c, buffer + got, sizeof(payload) - got, 0);
            if (n <= 0) ok = FALSE;
            else got += n;
            if (ok && got < (int)sizeof(payload)) ok = readable(c);
        }
    } else if (ok) {
        ok = sendto(b, payload, sizeof(payload), 0, (struct sockaddr *)&addr, size) == sizeof(payload) && readable(a);
        if (ok) got = recv(a, buffer, sizeof(buffer), 0);
    }
    report(tcp ? "tcp_loopback" : "udp_loopback", ok && got == sizeof(payload) &&
           lstrcmpA(buffer, payload) == 0, WSAGetLastError());
    if (c != INVALID_SOCKET) closesocket(c);
    if (b != INVALID_SOCKET) closesocket(b);
    if (a != INVALID_SOCKET) closesocket(a);
}
static void parsing(void)
{
    struct sockaddr_in addr = {0};
    int size = sizeof(addr);
    WCHAR input[] = L"127.0.0.1:8080", invalid[] = L"256.0.0.1";
    BOOL ok = WSAStringToAddressW(input, AF_INET, NULL, (struct sockaddr *)&addr, &size) == 0 &&
              addr.sin_family == AF_INET && addr.sin_addr.s_addr == htonl(INADDR_LOOPBACK) &&
              addr.sin_port == htons(8080);
    report("ipv4_address_port_parsing", ok, WSAGetLastError());
    size = sizeof(addr);
    report("ipv4_invalid_octet_rejected", WSAStringToAddressW(invalid, AF_INET, NULL,
           (struct sockaddr *)&addr, &size) == SOCKET_ERROR, WSAGetLastError());
}
static void services(void)
{
    static const char *names[] = {"Afd", "Tcpip", "Dhcp", "Dnscache", "PlugPlay", "RpcSs"};
    SC_HANDLE manager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    unsigned i;
    for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        SC_HANDLE svc = manager ? OpenServiceA(manager, names[i], SERVICE_QUERY_STATUS) : NULL;
        SERVICE_STATUS status = {0};
        char label[80];
        BOOL ok = svc && QueryServiceStatus(svc, &status);
        wsprintfA(label, "service_%s_running", names[i]);
        report(label, ok && status.dwCurrentState == SERVICE_RUNNING, ok ? status.dwCurrentState : GetLastError());
        if (svc) CloseServiceHandle(svc);
    }
    if (manager) CloseServiceHandle(manager);
}
static void adapter(void)
{
    static BYTE storage[16384];
    ULONG size = sizeof(storage);
    IP_ADAPTER_INFO *a = (IP_ADAPTER_INFO *)storage;
    DWORD error = GetAdaptersInfo(a, &size);
    BOOL address = FALSE, dhcp = FALSE;
    if (error == NO_ERROR) for (; a; a = a->Next) {
        char line[512];
        wsprintfA(line, "{\"event\":\"adapter\",\"name\":\"%s\",\"description\":\"%s\",\"ip\":\"%s\",\"dhcp\":%lu,\"server\":\"%s\"}\r\n",
                  a->AdapterName, a->Description, a->IpAddressList.IpAddress.String,
                  a->DhcpEnabled, a->DhcpServer.IpAddress.String);
        emit(line);
        if (lstrcmpA(a->IpAddressList.IpAddress.String, "10.25.0.10") == 0) {
            address = TRUE;
            dhcp = a->DhcpEnabled && lstrcmpA(a->DhcpServer.IpAddress.String, "10.25.0.1") == 0;
        }
    }
    report("virtual_nic_controlled_ipv4", address, error);
    report("controlled_dhcp_lease", dhcp, error);
}
static BOOL contains(const char *text, const char *needle)
{
    unsigned i, j;
    for (i = 0; text[i]; ++i) {
        for (j = 0; needle[j] && text[i+j] && needle[j] == text[i+j]; ++j) {}
        if (!needle[j]) return TRUE;
    }
    return FALSE;
}
static void external(void)
{
    struct hostent *host = gethostbyname("xp25.test");
    struct sockaddr_in addr = {0};
    const char request[] = "GET /xp25-network-proof HTTP/1.0\r\nHost: xp25.test\r\n\r\n";
    char buffer[2048];
    int count = 0;
    SOCKET s;
    BOOL ok = host && host->h_addrtype == AF_INET && host->h_length == 4 &&
              (unsigned char)host->h_addr_list[0][0] == 10 &&
              (unsigned char)host->h_addr_list[0][1] == 25 &&
              (unsigned char)host->h_addr_list[0][2] == 0 &&
              (unsigned char)host->h_addr_list[0][3] == 1;
    report("controlled_dns_resolution", ok, WSAGetLastError());
    addr.sin_family = AF_INET; addr.sin_port = htons(8080);
    addr.sin_addr.s_addr = inet_addr("10.25.0.1");
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s != INVALID_SOCKET) {
        u_long nonblocking = 1;
        fd_set write_set, error_set;
        struct timeval wait = {5, 0};
        int error = 0, length = sizeof(error);
        ioctlsocket(s, FIONBIO, &nonblocking);
        ok = connect(s, (struct sockaddr *)&addr, sizeof(addr)) == 0;
        if (!ok && WSAGetLastError() == WSAEWOULDBLOCK) {
            FD_ZERO(&write_set); FD_SET(s, &write_set);
            FD_ZERO(&error_set); FD_SET(s, &error_set);
            ok = select(0, NULL, &write_set, &error_set, &wait) > 0 &&
                 FD_ISSET(s, &write_set) && !FD_ISSET(s, &error_set) &&
                 getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&error, &length) == 0 && error == 0;
        }
        report("isolated_server_tcp_connection", ok, WSAGetLastError());
        nonblocking = 0; ioctlsocket(s, FIONBIO, &nonblocking);
        if (ok) ok = send(s, request, sizeof(request)-1, 0) == sizeof(request)-1;
        while (ok && count < (int)sizeof(buffer)-1 && readable(s)) {
            int n = recv(s, buffer+count, sizeof(buffer)-1-count, 0);
            if (n <= 0) break;
            count += n;
        }
        buffer[count] = 0;
        report("isolated_http_response", ok && contains(buffer, "200 OK") &&
               contains(buffer, "XP25-ISOLATED-HTTP-PASS"), WSAGetLastError());
        closesocket(s);
    } else {
        report("isolated_server_tcp_connection", FALSE, WSAGetLastError());
        report("isolated_http_response", FALSE, WSAGetLastError());
    }
}
void WINAPI ProbeMain(void)
{
    WSADATA data;
    int error;
    serial = CreateFileA("COM1", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (serial == INVALID_HANDLE_VALUE) ExitProcess(90);
    emit("{\"event\":\"network_probe_started\"}\r\n");
    error = WSAStartup(MAKEWORD(2,2), &data);
    report("winsock_startup", error == 0, error);
    if (!error) {
        parsing(); loopback(TRUE); loopback(FALSE); services(); adapter(); external();
        WSACleanup();
    }
    report("network_probe_complete", failures == 0, failures);
    CloseHandle(serial);
    ExitProcess(failures ? 1 : 0);
}
