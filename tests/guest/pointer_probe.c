/* XP x86 pointer compatibility regression. No C runtime or secret-value logs. */
#define WINVER 0x0501
#define _WIN32_WINNT 0x0501
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

typedef PVOID (WINAPI *POINTER_API)(PVOID);
typedef LONG (WINAPI *QUERY_PROCESS)(HANDLE, ULONG, PVOID, ULONG, PULONG);
static POINTER_API encode_pointer, decode_pointer, rtl_encode, rtl_decode;
static QUERY_PROCESS query_process;
static volatile LONG thread_failure;
static HANDLE serial;
static unsigned failures;

static void report(const char *name, BOOL pass)
{
    char line[180];
    DWORD bytes;
    wsprintfA(line, "{\"case\":\"%s\",\"status\":\"%s\"}\r\n", name, pass ? "pass" : "fail");
    if (!pass) ++failures;
    WriteFile(serial, line, lstrlenA(line), &bytes, NULL);
}

static BOOL resolve(void)
{
    HMODULE k = GetModuleHandleA("kernel32.dll"), n = GetModuleHandleA("ntdll.dll");
    union { FARPROC raw; POINTER_API pointer; QUERY_PROCESS query; } api;
    api.raw = GetProcAddress(k, "EncodePointer"); encode_pointer = api.pointer;
    api.raw = GetProcAddress(k, "DecodePointer"); decode_pointer = api.pointer;
    api.raw = GetProcAddress(n, "RtlEncodePointer"); rtl_encode = api.pointer;
    api.raw = GetProcAddress(n, "RtlDecodePointer"); rtl_decode = api.pointer;
    api.raw = GetProcAddress(n, "NtQueryInformationProcess"); query_process = api.query;
    return encode_pointer && decode_pointer && rtl_encode && rtl_decode && query_process;
}

static DWORD WINAPI thread_test(PVOID argument)
{
    ULONG i, value, encoded;
    for (i = 0; i < 65536; ++i) {
        value = i * 0x9e3779b9UL + (ULONG)(ULONG_PTR)argument;
        encoded = (ULONG)(ULONG_PTR)encode_pointer((PVOID)(ULONG_PTR)value);
        if (decode_pointer((PVOID)(ULONG_PTR)encoded) != (PVOID)(ULONG_PTR)value ||
            rtl_decode(rtl_encode((PVOID)(ULONG_PTR)value)) != (PVOID)(ULONG_PTR)value ||
            encoded != (ULONG)(ULONG_PTR)rtl_encode((PVOID)(ULONG_PTR)value)) {
            InterlockedExchange(&thread_failure, 1);
            return 1;
        }
    }
    return 0;
}

void WINAPI ProbeMain(void)
{
    char name[80], module[MAX_PATH], command[MAX_PATH + 100];
    char *tail = GetCommandLineA();
    HANDLE mapping, threads[4], real_self;
    ULONG *shared, value, length, cookie;
    unsigned i;
    BOOL ok;
    STARTUPINFOA startup = {0};
    PROCESS_INFORMATION child = {0};
    DWORD code;

    if (!resolve()) ExitProcess(90);
    startup.cb = sizeof(startup);
    while (*tail && !(*tail == '-' && tail[1] == '-' && tail[2] == 'c')) ++tail;
    if (*tail) {
        while (*tail && *tail != ' ') ++tail;
        if (*tail) ++tail;
        mapping = OpenFileMappingA(FILE_MAP_READ, FALSE, tail);
        if (!mapping) ExitProcess(91);
        shared = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, sizeof(ULONG));
        if (!shared) ExitProcess(92);
        ok = (ULONG)(ULONG_PTR)encode_pointer(NULL) != *shared;
        UnmapViewOfFile(shared);
        CloseHandle(mapping);
        ExitProcess(ok ? 0 : 93);
    }
    serial = CreateFileA("COM1", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (serial == INVALID_HANDLE_VALUE) ExitProcess(94);
    report("exports_resolved", TRUE);
    ok = decode_pointer(encode_pointer(NULL)) == NULL &&
         decode_pointer(encode_pointer((PVOID)(ULONG_PTR)0xffffffffUL)) == (PVOID)(ULONG_PTR)0xffffffffUL &&
         decode_pointer(encode_pointer((PVOID)ProbeMain)) == (PVOID)ProbeMain &&
         encode_pointer(NULL) != NULL;
    report("null_allones_function_roundtrip_nonidentity", ok);
    ok = TRUE;
    for (i = 0; i < 4; ++i) {
        threads[i] = CreateThread(NULL, 0, thread_test, (PVOID)(ULONG_PTR)(i * 17), 0, NULL);
        if (!threads[i]) ok = FALSE;
    }
    if (ok) ok = WaitForMultipleObjects(4, threads, TRUE, 60000) == WAIT_OBJECT_0;
    report("concurrent_262144_roundtrips_stable_cookie", ok && !thread_failure);
    for (i = 0; i < 4; ++i) if (threads[i]) CloseHandle(threads[i]);
    length = 0;
    ok = query_process((HANDLE)-1, 36, &cookie, sizeof(cookie), &length) == 0 && length == 4;
    report("self_cookie_query_length", ok);
    real_self = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
    ok = real_self && (ULONG)query_process(real_self, 36, &value, 4, NULL) == 0xc000000dUL;
    if (real_self) CloseHandle(real_self);
    report("real_handle_query_rejected", ok);
    report("bad_length_rejected", (ULONG)query_process((HANDLE)-1, 36, &value, 0, NULL) == 0xc0000004UL &&
           (ULONG)query_process((HANDLE)-1, 36, &value, 8, NULL) == 0xc0000004UL);
    report("bad_output_buffer_rejected", query_process((HANDLE)-1, 36, (PVOID)1, 4, NULL) < 0);
    report("bad_return_length_buffer_rejected", query_process((HANDLE)-1, 36, &value, 4, (PULONG)1) < 0);
    wsprintfA(name, "XP25PointerProbe-%lu", GetCurrentProcessId());
    mapping = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(ULONG), name);
    ok = mapping != NULL && GetLastError() != ERROR_ALREADY_EXISTS;
    shared = mapping ? MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, sizeof(ULONG)) : NULL;
    ok = ok && shared != NULL;
    if (ok) {
        *shared = (ULONG)(ULONG_PTR)encode_pointer(NULL);
        GetModuleFileNameA(NULL, module, sizeof(module));
        wsprintfA(command, "\"%s\" --child %s", module, name);
        ok = CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &child);
        if (ok) {
            report("other_process_cookie_query_rejected",
                   (ULONG)query_process(child.hProcess, 36, &value, 4, NULL) == 0xc000000dUL);
            ok = WaitForSingleObject(child.hProcess, 10000) == WAIT_OBJECT_0 &&
                 GetExitCodeProcess(child.hProcess, &code) && code == 0;
            CloseHandle(child.hThread);
            CloseHandle(child.hProcess);
        }
    }
    report("distinct_process_encoding", ok);
    if (shared) UnmapViewOfFile(shared);
    if (mapping) CloseHandle(mapping);
    report("pointer_probe_complete", failures == 0);
    CloseHandle(serial);
    ExitProcess(failures ? 1 : 0);
}
