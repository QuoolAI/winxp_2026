/* MerlinClient.dll internals shared between its source files. */
#ifndef MC_INTERNAL_H
#define MC_INTERNAL_H
#include "merlin_client.h"

#define MC_MAX_LIST 400
#ifndef ERROR_FILE_TOO_LARGE
#define ERROR_FILE_TOO_LARGE 223L
#endif
/* 64-bit constants: the NT 5.1 compiler (cl 13) has no ULL suffix. */
#ifdef _MSC_VER
#define MC_U64(x) x##ui64
#else
#define MC_U64(x) x##ULL
#endif
#define MC_MAX_FILE (8UL * 1024UL * 1024UL)

void *mc_alloc(SIZE_T bytes);
void mc_free(void *p);
/* Read a whole file (at most max bytes) into a NUL-terminated buffer. */
char *mc_read_file(const WCHAR *path, DWORD max, DWORD *len, DWORD *error);
/* Write via "<path>.tmp" and MoveFileEx(REPLACE_EXISTING|WRITE_THROUGH). */
DWORD mc_write_file_atomic(const WCHAR *path, const void *data, DWORD len);
BOOL mc_random(unsigned char *out, DWORD len);
void mc_random_hex(char *out, DWORD bytes);
unsigned long mc_now(void);                       /* seconds since 1970 UTC */
unsigned long mc_filetime_seconds(const FILETIME *ft);
/* Path of a queue file: <queue>\<name>. */
BOOL mc_queue_path(const char *name, WCHAR *path, DWORD chars);
/* Current account and computer names, UTF-8. */
void mc_identity_names(char *user, int user_size, char *computer, int computer_size);
DWORD mc_reg_read_string(HKEY root, const WCHAR *key, const WCHAR *name, WCHAR *out, DWORD chars);
DWORD mc_reg_read_dword(HKEY root, const WCHAR *key, const WCHAR *name, DWORD *value);
DWORD mc_reg_write_dword(HKEY root, const WCHAR *key, const WCHAR *name, DWORD value);
DWORD mc_reg_write_string(HKEY root, const WCHAR *key, const WCHAR *name, const WCHAR *value);
#endif
