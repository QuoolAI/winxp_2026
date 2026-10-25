/* Shared NT 5.1 operations. No policy decisions or test-mode selectors. */
#ifndef XP25_SESSION_NATIVE_H
#define XP25_SESSION_NATIVE_H
#include <windows.h>
PVOID wl_copy_user_environment(PVOID environment);
BOOL wl_same_logon(HANDLE reference,HANDLE candidate);
BOOL wl_watch_user_process(HANDLE token,DWORD pid,LPCWSTR image,HANDLE *result);
DWORD wl_user_process_exited(HANDLE process);
BOOL wl_spawn_user_process(HANDLE token,LPCWSTR image,LPWSTR command,LPWSTR desktop,
                          PVOID environment,PROCESS_INFORMATION *result);
#endif
