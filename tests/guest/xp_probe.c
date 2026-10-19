/* XP25 native guest diagnostic probe. Uses XP-era Win32 APIs and no C runtime.
 * Run after interactive logon: xp_probe.exe [--serial]
 * Passes observe this execution only; they do not establish a login transition,
 * device hardware functionality, Internet connectivity or security hardening.
 */
#define WINVER 0x0501
#define _WIN32_WINNT 0x0501
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>
#include <winsvc.h>

static HANDLE serial = INVALID_HANDLE_VALUE;
static unsigned failures;
static unsigned output_failed;

static void zero(void *memory, unsigned bytes)
{
    volatile unsigned char *p = memory;
    while (bytes--) *p++ = 0;
}

static BOOL same_bytes(const char *a, const char *b, DWORD count)
{
    DWORD i;
    for (i = 0; i < count; ++i) if (a[i] != b[i]) return FALSE;
    return TRUE;
}

static void emit(const char *text)
{
    DWORD size = (DWORD)lstrlenA(text), written;
    BOOL delivered = FALSE;
    HANDLE standard = GetStdHandle(STD_OUTPUT_HANDLE);
    if (standard != INVALID_HANDLE_VALUE && standard != NULL)
        delivered = WriteFile(standard, text, size, &written, NULL) && written == size;
    if (serial != INVALID_HANDLE_VALUE &&
        WriteFile(serial, text, size, &written, NULL) && written == size) delivered = TRUE;
    if (!delivered) output_failed = 1;
}

static void report(const char *name, BOOL passed, DWORD error)
{
    char line[256];
    if (!passed) ++failures;
    wsprintfA(line, "{\"event\":\"case\",\"name\":\"%s\",\"status\":\"%s\",\"error\":%lu}\r\n",
              name, passed ? "pass" : "fail", passed ? 0 : error);
    emit(line);
}

static void registry_probe(void)
{
    HKEY key;
    DWORD disposition, value = 0x58503235, returned = 0, size = sizeof(returned), type = 0;
    char path[128];
    LONG error;
    wsprintfA(path, "Software\\XP25\\Probe-%lu-%lu", GetCurrentProcessId(), GetTickCount());
    error = RegCreateKeyExA(HKEY_CURRENT_USER, path, 0, NULL, REG_OPTION_VOLATILE,
                            KEY_QUERY_VALUE | KEY_SET_VALUE, NULL, &key, &disposition);
    if (error != ERROR_SUCCESS) { report("registry", FALSE, error); return; }
    if (disposition != REG_CREATED_NEW_KEY) {
        RegCloseKey(key);
        report("registry", FALSE, ERROR_ALREADY_EXISTS);
        return;
    }
    error = RegSetValueExA(key, "RoundTrip", 0, REG_DWORD, (const BYTE *)&value, sizeof(value));
    if (error == ERROR_SUCCESS)
        error = RegQueryValueExA(key, "RoundTrip", NULL, &type, (BYTE *)&returned, &size);
    if (error == ERROR_SUCCESS && (type != REG_DWORD || size != sizeof(value) || returned != value))
        error = ERROR_INVALID_DATA;
    RegCloseKey(key);
    {
        LONG cleanup = RegDeleteKeyA(HKEY_CURRENT_USER, path);
        if (error == ERROR_SUCCESS) error = cleanup;
    }
    report("registry", error == ERROR_SUCCESS, error);
}

static void filesystem_probe(void)
{
    char directory[MAX_PATH], path[MAX_PATH], readback[32];
    const char payload[] = "XP25 filesystem roundtrip";
    DWORD count, error = ERROR_SUCCESS;
    HANDLE file;
    count = GetTempPathA(MAX_PATH, directory);
    if (!count || count >= MAX_PATH) { report("filesystem", FALSE, ERROR_BAD_PATHNAME); return; }
    if (!GetTempFileNameA(directory, "x25", 0, path)) { report("filesystem", FALSE, GetLastError()); return; }
    file = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (file == INVALID_HANDLE_VALUE) error = GetLastError();
    else {
        if (!WriteFile(file, payload, sizeof(payload), &count, NULL)) error = GetLastError();
        else if (count != sizeof(payload)) error = ERROR_WRITE_FAULT;
        if (error == ERROR_SUCCESS && SetFilePointer(file, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
            error = GetLastError();
        if (error == ERROR_SUCCESS) {
            if (!ReadFile(file, readback, sizeof(payload), &count, NULL)) error = GetLastError();
            else if (count != sizeof(payload) || !same_bytes(readback, payload, sizeof(payload)))
                error = ERROR_INVALID_DATA;
        }
        CloseHandle(file);
    }
    if (!DeleteFileA(path) && error == ERROR_SUCCESS) error = GetLastError();
    report("filesystem", error == ERROR_SUCCESS, error);
}

static void network_probe(void)
{
    WSADATA data;
    SOCKET sock;
    struct sockaddr_in address, sender;
    int length = sizeof(address), sender_length = sizeof(sender), error;
    DWORD timeout = 2000;
    char buffer[16];
    const char payload[] = "xp25-loopback";
    error = WSAStartup(MAKEWORD(2, 2), &data);
    if (error) { report("winsock_loopback", FALSE, error); return; }
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) { error = WSAGetLastError(); goto finished; }
    zero(&address, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout)) ||
        bind(sock, (const struct sockaddr *)&address, sizeof(address)) ||
        getsockname(sock, (struct sockaddr *)&address, &length)) {
        error = WSAGetLastError(); goto closed;
    }
    if (sendto(sock, payload, sizeof(payload), 0, (struct sockaddr *)&address, sizeof(address)) != sizeof(payload)) {
        error = WSAGetLastError(); if (!error) error = WSAEFAULT; goto closed;
    }
    if (recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&sender, &sender_length) != sizeof(payload)) {
        error = WSAGetLastError(); if (!error) error = WSAEFAULT; goto closed;
    }
    error = same_bytes(buffer, payload, sizeof(payload)) && sender.sin_addr.s_addr == address.sin_addr.s_addr &&
            sender.sin_port == address.sin_port ? 0 : WSAEFAULT;
closed:
    closesocket(sock);
finished:
    WSACleanup();
    report("winsock_loopback", error == 0, error);
}

static void explorer_probe(void)
{
    HWND shell = GetShellWindow();
    DWORD shell_pid = 0;
    PROCESSENTRY32 entry;
    HANDLE snapshot;
    BOOL found = FALSE;
    if (!shell || !GetWindowThreadProcessId(shell, &shell_pid)) {
        report("explorer_presence", FALSE, ERROR_NOT_FOUND); return;
    }
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) { report("explorer_presence", FALSE, GetLastError()); return; }
    zero(&entry, sizeof(entry));
    entry.dwSize = sizeof(entry);
    if (Process32First(snapshot, &entry)) do {
        if (entry.th32ProcessID == shell_pid && lstrcmpiA(entry.szExeFile, "explorer.exe") == 0)
            found = TRUE;
    } while (Process32Next(snapshot, &entry));
    CloseHandle(snapshot);
    report("explorer_presence", found, ERROR_NOT_FOUND);
}

static void driver_probe(void)
{
    SC_HANDLE manager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    ENUM_SERVICE_STATUSA *entries;
    const DWORD capacity = 4096;
    DWORD bytes, count, resume = 0, error = ERROR_MORE_DATA, i, previous;
    DWORD pages = 0, active = 0;
    char line[128];
    if (!manager) { report("driver_enumeration", FALSE, GetLastError()); return; }
    entries = HeapAlloc(GetProcessHeap(), 0, capacity);
    if (!entries) { CloseServiceHandle(manager); report("driver_enumeration", FALSE, ERROR_NOT_ENOUGH_MEMORY); return; }
    /* ERROR_MORE_DATA may include valid entries. Consume each page and resume;
     * a sizing query followed by one exact allocation is not sufficient on XP.
     * Bound both memory and continuation, including a non-progressing server.
     */
    while (pages < 256) {
        BOOL complete;
        previous = resume; bytes = 0; count = 0;
        complete = EnumServicesStatusA(manager, SERVICE_DRIVER, SERVICE_ACTIVE,
                                       entries, capacity, &bytes, &count, &resume);
        error = complete ? ERROR_SUCCESS : GetLastError();
        ++pages;
        if (error != ERROR_SUCCESS && error != ERROR_MORE_DATA) break;
        for (i = 0; i < count; ++i)
            if (entries[i].ServiceStatus.dwCurrentState == SERVICE_RUNNING) ++active;
        if (complete) break;
        if (!count || resume == previous) { error = ERROR_INVALID_DATA; break; }
    }
    if (error == ERROR_SUCCESS && !active) error = ERROR_NOT_FOUND;
    wsprintfA(line, "{\"event\":\"driver_services\",\"active\":%lu,\"pages\":%lu}\r\n", active, pages);
    emit(line);
    HeapFree(GetProcessHeap(), 0, entries);
    CloseServiceHandle(manager);
    report("driver_enumeration", error == ERROR_SUCCESS, error);
}

void WINAPI ProbeMain(void)
{
    OSVERSIONINFOA version;
    char line[256];
    const char *command = GetCommandLineA();
    for (; *command; ++command) {
        if (command[0] == '-' && command[1] == '-' &&
            command[2] == 's' && command[3] == 'e' && command[4] == 'r' &&
            command[5] == 'i' && command[6] == 'a' && command[7] == 'l') {
            serial = CreateFileA("\\\\.\\COM1", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
            if (serial != INVALID_HANDLE_VALUE) {
                DCB dcb;
                COMMTIMEOUTS timeouts;
                zero(&dcb, sizeof(dcb)); dcb.DCBlength = sizeof(dcb);
                zero(&timeouts, sizeof(timeouts)); timeouts.WriteTotalTimeoutConstant = 2000;
                if (!GetCommState(serial, &dcb)) { CloseHandle(serial); serial = INVALID_HANDLE_VALUE; }
                else {
                    dcb.BaudRate = CBR_115200; dcb.ByteSize = 8; dcb.Parity = NOPARITY; dcb.StopBits = ONESTOPBIT;
                    dcb.fBinary = TRUE; dcb.fOutxCtsFlow = FALSE; dcb.fOutxDsrFlow = FALSE;
                    dcb.fOutX = FALSE; dcb.fInX = FALSE;
                    dcb.fDtrControl = DTR_CONTROL_DISABLE; dcb.fRtsControl = RTS_CONTROL_DISABLE;
                    if (!SetCommState(serial, &dcb) || !SetCommTimeouts(serial, &timeouts)) {
                        CloseHandle(serial); serial = INVALID_HANDLE_VALUE;
                    }
                }
            }
            break;
        }
    }
    zero(&version, sizeof(version)); version.dwOSVersionInfoSize = sizeof(version);
    if (!GetVersionExA(&version)) { report("guest_identity", FALSE, GetLastError()); }
    else {
        wsprintfA(line, "{\"event\":\"identity\",\"protocol\":\"xp25-probe-v1\",\"major\":%lu,\"minor\":%lu,\"build\":%lu}\r\n",
                  version.dwMajorVersion, version.dwMinorVersion, version.dwBuildNumber);
        emit(line);
        report("guest_identity", version.dwPlatformId == VER_PLATFORM_WIN32_NT && version.dwMajorVersion == 5 &&
               (version.dwMinorVersion == 1 || version.dwMinorVersion == 2), ERROR_OLD_WIN_VERSION);
    }
    explorer_probe(); registry_probe(); filesystem_probe(); network_probe(); driver_probe();
    emit("{\"event\":\"case\",\"name\":\"login_transition\",\"status\":\"not_tested\"}\r\n");
    emit("{\"event\":\"case\",\"name\":\"legacy_games\",\"status\":\"not_tested\"}\r\n");
    emit("{\"event\":\"case\",\"name\":\"security_mitigations\",\"status\":\"not_tested\"}\r\n");
    emit("{\"event\":\"case\",\"name\":\"shutdown\",\"status\":\"not_tested\"}\r\n");
    wsprintfA(line, "{\"event\":\"summary\",\"failures\":%u,\"incomplete\":4}\r\n", failures);
    emit(line);
    if (serial != INVALID_HANDLE_VALUE) CloseHandle(serial);
    ExitProcess(output_failed ? 3 : failures ? 1 : 0);
}
