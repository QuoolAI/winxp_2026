/* ClippyAI: application-wide declarations. */
#ifndef CLIPPYAI_H
#define CLIPPYAI_H
#include <windows.h>
#include "resource.h"
#include "../../xp25-agent/runtime/xp25_win.h"
#include "../../xp25-agent/llm/xp25_offline.h"
#include "../mascot/mascot.h"

#define CLIPPY_CLASS L"XP25ClippyAI"
#define CHAT_CLASS L"XP25ChatView"
#define WM_CLIPPY_EVENT (WM_APP + 1)
#define WM_CLIPPY_APPROVE (WM_APP + 2)
#define WM_CLIPPY_SHARE (WM_APP + 3)
#define WM_CLIPPY_DONE (WM_APP + 4)
#define WM_CLIPPY_TRAY (WM_APP + 5)
#define XP25_IPC_MAGIC 0x58503235UL

typedef enum { CK_USER, CK_ASSISTANT, CK_TOOL, CK_NOTICE, CK_ERROR, CK_DENIED } CHAT_KIND;

typedef struct {
    HINSTANCE instance;
    HWND window, chat, input, send, stop, status, mascot_text;
    MASCOT *mascot;
    HFONT font, bold, mono;
    XP25W_PATHS paths;
    XP25_CONFIG config;
    XP25_REGISTRY registry;
    XP25W_TOOLS tool_context;
    XP25_OFFLINE offline_settings;
    XP25_PROVIDER offline;
    XP25_PROVIDER *remote;
    char provider_note[300];
    XP25_AGENT agent;
    HANDLE worker;
    volatile LONG cancel;
    int busy;
    int tray_hint_shown;
} CLIPPY_APP;

extern CLIPPY_APP g_app;

/* chat view (custom control) */
ATOM chat_register(HINSTANCE instance);
void chat_add(HWND chat, CHAT_KIND kind, const char *title, const char *text, const char *detail, int ok);
void chat_clear(HWND chat);
int chat_save(HWND chat, const WCHAR *path);

/* dialogs */
int dialog_approval(HWND owner, const char *tool, const XP25_PROPOSAL *proposal);
int dialog_share(HWND owner, const char *tool, const char *provider, const char *preview);
int dialog_settings(HWND owner);
void dialog_about(HWND owner);

/* controller */
int controller_init(void);
void controller_reconfigure(void);
void controller_send(const char *utf8);
void controller_stop(void);
void controller_shutdown(void);
void controller_event(XP25_EVENT *event);   /* UI thread: render one event */
void controller_free_event(XP25_EVENT *event);

/* app */
void app_set_status(const char *text);
int app_autostart(int set, int enable);
#endif
