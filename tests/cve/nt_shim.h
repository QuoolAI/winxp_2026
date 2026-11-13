/* The NT types and the few calls that functions extracted from Source/XPSP1/NT need for a
   host build. Compiled with gcc -fshort-wchar so wide literals are 16 bits, as on NT.
   Nothing here decides a test: the shims only provide the environment the original code
   expects, and each harness documents which behaviour it models. */
#ifndef XP25_NT_SHIM_H
#define XP25_NT_SHIM_H

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void VOID;
typedef char CHAR;
typedef unsigned char UCHAR, BYTE, BOOLEAN, *PUCHAR, *LPBYTE, *PBOOLEAN;
typedef unsigned short WCHAR, USHORT, WORD, *PWCHAR, *PWSTR, *LPWSTR, *PUSHORT;
typedef const unsigned short *LPCWSTR, *PCWSTR;
typedef char *PCHAR, *PSTR, *LPSTR;
typedef const char *LPCSTR, *PCSTR;
typedef short SHORT, *PSHORT;
typedef uint32_t ULONG, DWORD, UINT, CLONG, *PULONG, *LPDWORD, *PUINT;
typedef int32_t LONG, *PLONG, NTSTATUS;
typedef int BOOL, INT;
typedef int64_t LONG64, LONGLONG;
typedef uint64_t ULONG64, ULONGLONG;
typedef uintptr_t ULONG_PTR, SIZE_T;
typedef void *HANDLE, *PVOID, *LPVOID;
typedef const void *LPCVOID;
typedef unsigned short TCHAR, *LPTSTR, *PTCHAR;
typedef const unsigned short *LPCTSTR;
typedef long HRESULT;
typedef int32_t INT_PTR, LONG_PTR;      /* x86: pointer-sized integers are 32 bits */
typedef uint32_t UINT_PTR;

#define MAXULONG 0xffffffffU
#define MAXUSHORT 0xffff
#define ERROR_SUCCESS 0

#define IN
#define OUT
#define OPTIONAL
#define CONST const
#define STATIC static
#define WINAPI
#define WINAPIV
#define NTAPI
#define FASTCALL
#define __stdcall
#define __cdecl
#define TRUE 1
#define FALSE 0
#define TEXT(s) L##s
#define ARGUMENT_PRESENT(p) ((p) != NULL)
#define UNREFERENCED_PARAMETER(p) ((void)(p))

/* Checked builds (XP25's source-built binaries are checked builds) stop on a failed assertion. */
#define ASSERT(e) do { if (!(e)) { fprintf(stderr, "ASSERTION FAILED: %s (%s:%d)\n", #e, __FILE__, __LINE__); abort(); } } while (0)

/* 16-bit string helpers: glibc's wcs* functions assume a 32-bit wchar_t. */
static size_t xp_wcslen(const WCHAR *s) { size_t n = 0; while (s[n]) n++; return n; }
static WCHAR *xp_wcscpy(WCHAR *d, const WCHAR *s) { WCHAR *r = d; while ((*d++ = *s++) != 0) {} return r; }
static WCHAR *xp_wcscat(WCHAR *d, const WCHAR *s) { xp_wcscpy(d + xp_wcslen(d), s); return d; }
#define wcslen(s) xp_wcslen((const WCHAR *)(s))
#define wcscpy(d, s) xp_wcscpy((d), (s))
#define wcscat(d, s) xp_wcscat((d), (s))

static void xp_to_wide(WCHAR *out, const char *in, size_t cch)
{
    size_t i;
    for (i = 0; i + 1 < cch && in[i]; i++) out[i] = (unsigned char)in[i];
    if (cch) out[i] = 0;
}

static void xp_from_wide(char *out, const WCHAR *in, size_t cch)
{
    size_t i;
    for (i = 0; i + 1 < cch && in[i]; i++) out[i] = (char)(in[i] < 128 ? in[i] : '?');
    if (cch) out[i] = 0;
}

#endif
