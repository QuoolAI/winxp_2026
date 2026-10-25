/* RoverAI search panel shared by RoverAI.exe and the Explorer bar. */
#ifndef ROVER_PANEL_H
#define ROVER_PANEL_H
#include <windows.h>

#define ROVER_PANEL_CLASS L"XP25RoverAIPanel"

#define IDC_RV_TITLE 4001
#define IDC_RV_QUERY 4002
#define IDC_RV_GO 4003
#define IDC_RV_SCOPE 4004
#define IDC_RV_DATE 4005
#define IDC_RV_TYPE 4006
#define IDC_RV_SIZE 4007
#define IDC_RV_LOCATION 4008
#define IDC_RV_AI 4009
#define IDC_RV_STATUS 4010
#define IDC_RV_RESULTS 4011
#define IDC_RV_OPEN 4012
#define IDC_RV_FOLDER 4013
#define IDC_RV_EXPLAIN 4014
#define IDC_RV_ROVER 4015
#define IDC_RV_LABEL 4100

/* band_mode: narrow single-column layout inside an Explorer window. */
HWND rover_panel_create(HWND parent, HINSTANCE instance, int band_mode, int id);
void rover_panel_set_folder(HWND panel, const WCHAR *folder);
void rover_panel_set_query(HWND panel, const WCHAR *query, int run);
void rover_panel_activate(HWND panel);
void rover_panel_show_rover(HWND panel, int visible);
int rover_panel_owns(HWND panel, HWND child);
#endif
