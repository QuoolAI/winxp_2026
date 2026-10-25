/* ClippyAI mascot interface. Implementations are interchangeable: the
   built-in animated paperclip, or any Microsoft Agent character (.acs). */
#ifndef CLIPPYAI_MASCOT_H
#define CLIPPYAI_MASCOT_H
#include <windows.h>

typedef enum { MASCOT_IDLE, MASCOT_GREET, MASCOT_THINKING, MASCOT_WORKING, MASCOT_SUCCESS, MASCOT_ERROR,
               MASCOT_ATTENTION } MASCOT_STATE;

typedef struct MASCOT MASCOT;
struct MASCOT {
    const char *name;
    HWND window;                                   /* child window inside the app, may be NULL */
    void (*set_state)(MASCOT *self, MASCOT_STATE state);
    void (*place)(MASCOT *self, const RECT *screen); /* area to occupy, in screen pixels */
    void (*show)(MASCOT *self, int visible);
    void (*destroy)(MASCOT *self);
};

/* setting: "builtin" or the path of an Agent character such as clippit.acs. */
MASCOT *mascot_create(HWND parent, HINSTANCE instance, const char *setting, char *note, size_t note_size);
MASCOT *mascot_paperclip_create(HWND parent, HINSTANCE instance);
#endif
