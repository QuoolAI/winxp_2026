/* XP25 AI runtime: requests between XP25 agents (RoverAI -> ClippyAI). */
#ifndef XP25_IPC_H
#define XP25_IPC_H
#include <windows.h>

#define XP25_IPC_MAGIC 0x58503235UL
#define XP25_CLIPPY_WINDOW_CLASS L"XP25ClippyAI"

/* action: "show", "ask" or "explain_file". Delivered by WM_COPYDATA to a
   running ClippyAI, or by starting ClippyAI.exe from this DLL's folder.
   The receiver treats the request as an ordinary user request: it can never
   approve an action by itself. */
int xp25w_clippy_request(const char *action, const char *value);
#endif
