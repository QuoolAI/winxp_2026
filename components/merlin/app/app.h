/* MerlinAI.exe shared declarations. */
#ifndef MERLIN_APP_H
#define MERLIN_APP_H
#include <windows.h>
#include <commctrl.h>
#include "../client/merlin_client.h"
#include "resource.h"

#define WM_MERLIN_DONE (WM_APP + 1)       /* wParam = operation, lParam = OPERATION * */

typedef enum {
    OpCollect = 1,
    OpTransfer,
    OpBuild,
    OpJobs,
    OpJob,
    OpCancel,
    OpDiscard,
    OpApply,
    OpRollback,
    OpDeployStatus
} OPERATION_KIND;

typedef struct {
    OPERATION_KIND kind;
    HWND notify;
    char ids[64][MERLIN_ID_SIZE];      /* problems or one job id */
    int id_count;
    char text[2048];                   /* request detail: approval text, build explanation */
    DWORD error;
    MERLIN_REPLY reply;
    MERLIN_COLLECT_STATS stats;
    char message[512];
} OPERATION;

/* install.c */
DWORD merlin_install(const WCHAR *directory, char *log, int log_size);
DWORD merlin_uninstall(char *log, int log_size);
void merlin_serial(const char *line);

/* worker (ui.c) */
BOOL merlin_start(OPERATION *op);

/* dialogs.c */
void merlin_settings_dialog(HWND owner);
void merlin_text_dialog(HWND owner, const WCHAR *title, const char *utf8);
int merlin_confirm_build(HWND owner, const MERLIN_PROBLEM *const *problems, int count, char *explanation, int size);
int merlin_review_job(HWND owner, const char *job_json, int allow_apply);
int merlin_approve(HWND owner, const char *job_json, char *approval, int size, BOOL rollback);
/* Render a builder job record as readable text (all sections Phase 10 lists). */
void merlin_job_text(const char *job_json, char *out, int size);

/* character.c: Microsoft Agent Merlin; every call is optional and silent on failure. */
void merlin_character_start(HWND near_window);
void merlin_character_state(const char *state, const char *speech);
void merlin_character_stop(void);

/* ui.c */
int merlin_run_ui(int show);

/* main.c */
extern HINSTANCE merlin_instance;
#endif
