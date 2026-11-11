/* XP25 AI runtime: Microsoft Agent 2.0 character playback (Rover, optional Clippy .acs). */
#ifndef XP25_MSAGENT_H
#define XP25_MSAGENT_H
#include <windows.h>
#include "xp25_base.h"

typedef struct XP25_AGENTCHAR XP25_AGENTCHAR;
XP25_AGENTCHAR *xp25w_agentchar_load(const WCHAR *acs_path, char *error, size_t size);
void xp25w_agentchar_size(XP25_AGENTCHAR *character, long *width, long *height);
void xp25w_agentchar_move(XP25_AGENTCHAR *character, int x, int y);   /* screen pixels */
void xp25w_agentchar_show(XP25_AGENTCHAR *character, int visible);
int xp25w_agentchar_play(XP25_AGENTCHAR *character, const WCHAR *animation);
void xp25w_agentchar_free(XP25_AGENTCHAR *character);
#endif
