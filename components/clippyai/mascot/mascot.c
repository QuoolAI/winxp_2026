/* ClippyAI mascot factory and the Microsoft Agent backend. */
#include <windows.h>
#include <string.h>
#include "mascot.h"
#include "../../xp25-agent/runtime/xp25_win.h"
#include "../../xp25-agent/runtime/xp25_msagent.h"

typedef struct {
    MASCOT base;
    XP25_AGENTCHAR *character;
} AGENT;

/* Candidate animations per state; characters name them differently. */
static const WCHAR *const *names_for(MASCOT_STATE state)
{
    static const WCHAR *const idle[] = { L"RestPose", L"Idle1_1", L"Idle", NULL };
    static const WCHAR *const greet[] = { L"Greeting", L"Greet", L"Show", NULL };
    static const WCHAR *const thinking[] = { L"Thinking", L"Processing", L"Think", NULL };
    static const WCHAR *const working[] = { L"Searching", L"Processing", L"Writing", L"CheckingSomething", NULL };
    static const WCHAR *const success[] = { L"Congratulate", L"Pleased", L"CharacterSucceeds", NULL };
    static const WCHAR *const error[] = { L"Embarrassed", L"Sad", L"Alert", NULL };
    static const WCHAR *const attention[] = { L"GetAttention", L"Alert", L"Surprised", NULL };
    switch (state) {
    case MASCOT_GREET: return greet;
    case MASCOT_THINKING: return thinking;
    case MASCOT_WORKING: return working;
    case MASCOT_SUCCESS: return success;
    case MASCOT_ERROR: return error;
    case MASCOT_ATTENTION: return attention;
    default: return idle;
    }
}

static void agent_state(MASCOT *self, MASCOT_STATE state)
{
    AGENT *a = (AGENT *)self;
    const WCHAR *const *names = names_for(state);
    for (; *names; ++names) if (xp25w_agentchar_play(a->character, *names)) break;
}

static void agent_place(MASCOT *self, const RECT *screen)
{
    AGENT *a = (AGENT *)self;
    long w, h;
    xp25w_agentchar_size(a->character, &w, &h);
    xp25w_agentchar_move(a->character, (int)(screen->left + (screen->right - screen->left - w) / 2),
                         (int)(screen->bottom - h));
}

static void agent_show(MASCOT *self, int visible) { xp25w_agentchar_show(((AGENT *)self)->character, visible); }

static void agent_destroy(MASCOT *self)
{
    xp25w_agentchar_free(((AGENT *)self)->character);
    xp25_free(self);
}

MASCOT *mascot_create(HWND parent, HINSTANCE instance, const char *setting, char *note, size_t note_size)
{
    if (note && note_size) note[0] = 0;
    if (setting && *setting && !xp25_strieq(setting, "builtin")) {
        WCHAR *path = xp25w_wide(setting);
        char error[96] = "";
        AGENT *a = (AGENT *)xp25_alloc(sizeof(AGENT));
        if (a && path) a->character = xp25w_agentchar_load(path, error, sizeof(error));
        xp25_free(path);
        if (a && a->character) {
            a->base.name = "Microsoft Agent character";
            a->base.set_state = agent_state;
            a->base.place = agent_place;
            a->base.show = agent_show;
            a->base.destroy = agent_destroy;
            xp25w_agentchar_show(a->character, 1);
            agent_state(&a->base, MASCOT_GREET);
            return &a->base;
        }
        xp25_free(a);
        if (note) {
            lstrcpynA(note, "Mascot character could not be loaded (", (int)note_size);
            if (strlen(note) + strlen(error) + 30 < note_size) { lstrcatA(note, error); lstrcatA(note, "); using the built-in paperclip."); }
        }
    }
    return mascot_paperclip_create(parent, instance);
}
