/* XP25 original Winlogon host. Interfaces are from the supplied NT 5.1 SDK. */
#ifndef XP25_WINLOGON_PLATFORM_H
#define XP25_WINLOGON_PLATFORM_H
#define WINVER 0x0501
#define _WIN32_WINNT 0x0501
#define UNICODE
#define _UNICODE
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winwlx.h>
#include <ntsecapi.h>
#include <userenv.h>
#include <sddl.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <wchar.h>
#include "state.h"
#define WL_APP_SAS (WM_APP+21)
#define WL_APP_NOTICE (WM_APP+22)
#define WL_LOGON_NOTIFY 0x004c
#define WL_HOTKEY 1
#define WL_MOD_SAS 0x8000
#define WL_WINSTA_ACCESS (STANDARD_RIGHTS_REQUIRED|WINSTA_ENUMDESKTOPS|WINSTA_READATTRIBUTES|WINSTA_ACCESSCLIPBOARD|WINSTA_CREATEDESKTOP|WINSTA_WRITEATTRIBUTES|WINSTA_ACCESSGLOBALATOMS|WINSTA_EXITWINDOWS|WINSTA_ENUMERATE|WINSTA_READSCREEN)
#define WL_DESKTOP_ACCESS (STANDARD_RIGHTS_REQUIRED|DESKTOP_READOBJECTS|DESKTOP_CREATEWINDOW|DESKTOP_CREATEMENU|DESKTOP_HOOKCONTROL|DESKTOP_JOURNALRECORD|DESKTOP_JOURNALPLAYBACK|DESKTOP_ENUMERATE|DESKTOP_WRITEOBJECTS|DESKTOP_SWITCHDESKTOP)
#define WL_WINLOGON_KEY L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
typedef char WL_X86_REQUIRED[(sizeof(void*)==4)?1:-1];
typedef char WL_DISPATCH_ABI[(sizeof(WLX_DISPATCH_VERSION_1_4)==27*4)?1:-1];
typedef char WL_NOTIFICATION_ABI[(sizeof(WLX_NOTIFICATION_INFO)==32)?1:-1];

typedef struct {
    BOOL (WINAPI *negotiate)(DWORD,PDWORD);
    BOOL (WINAPI *initialize)(LPWSTR,HANDLE,PVOID,PVOID,PVOID*);
    VOID (WINAPI *sas_notice)(PVOID);
    int (WINAPI *logged_out)(PVOID,DWORD,PLUID,PSID,PDWORD,PHANDLE,PWLX_MPR_NOTIFY_INFO,PVOID*);
    BOOL (WINAPI *activate_shell)(PVOID,PWSTR,PWSTR,PVOID);
    int (WINAPI *logged_on)(PVOID,DWORD,PVOID);
    VOID (WINAPI *locked_notice)(PVOID);
    int (WINAPI *locked_sas)(PVOID,DWORD);
    BOOL (WINAPI *lock_ok)(PVOID);
    BOOL (WINAPI *logoff_ok)(PVOID);
    VOID (WINAPI *logoff)(PVOID);
    VOID (WINAPI *shutdown)(PVOID,DWORD);
    BOOL (WINAPI *network)(PVOID,PWLX_MPR_NOTIFY_INFO);
} WL_GINA;

typedef struct {
    WL_MACHINE machine;
    HINSTANCE instance;
    HWINSTA station;
    HDESK secure, application;
    HWND window, dialog;
    HANDLE lsa, token, profile;
    HMODULE gina_module;
    PVOID gina_context;
    WL_GINA gina;
    WLX_DISPATCH_VERSION_1_4 dispatch;
    LUID authentication_id;
    BYTE logon_sid[SECURITY_MAX_SID_SIZE];
    WLX_MPR_NOTIFY_INFO mpr;
    PVOID gina_profile;
    PVOID environment;
    volatile DWORD lsa_pid;
    DWORD session_id, timeout, gina_version, pending_power;
    BOOL cad, no_switch, in_gina;
    ULONG_PTR ignore_auto, smartcard, force_logoff;
    WCHAR username[256], domain[256];
} WL_HOST;
extern WL_HOST wl;
void wl_log(const char *event,DWORD status);
void wl_fail(const char *operation,DWORD error);
BOOL wl_privilege(LPCWSTR name);
BOOL wl_security_init(void);
BOOL wl_switch_secure(void);
BOOL wl_switch_user(void);
BOOL wl_check_token(HANDLE token,const LUID *id,PSID sid);
BOOL wl_apply_user_security(HANDLE token);
BOOL wl_session_policy(void);
BOOL wl_wait_user_shell(DWORD *pid);
BOOL wl_system_services(void);
BOOL wl_gina_init(void);
void wl_free_gina_result(void);
void wl_attention(DWORD type);
BOOL wl_session_start(void);
BOOL wl_session_end(void);
BOOL wl_notify(LPCWSTR event);
BOOL wl_notifications_wait(void);
BOOL wl_notifications_wait_user(void);
void wl_notifications_probe(void);
BOOL wl_boot(void);
BOOL wl_bootkey_start(void);
BOOL wl_wait_sam(void);
BOOL wl_model_test(void);
#endif
