/* XP-era APIs only. OEM branding check: oeminfo.ini, the HelpSvc OEMInfo copy,
   OEM logo files, NT 5.1 identity and the text System Properties displays.
   usage: oem_probe.exe [--expect] --out <file>
          oem_probe.exe --rename <NAME> --out <file>
   --rename sets the computer name with SetComputerNameExA
   (ComputerNamePhysicalDnsHostname, which also sets the NetBIOS name); it takes
   effect at the next start. Exit 0 on success.
   Without --expect every case is recorded as "observed"; with it the QuoolAI
   values are gates and the exit code is the number of failed cases. JSON lines
   go to <file> and, when it opens, COM1. System Properties is left open.
   A line "fits" when its text, measured in the control's font, is no wider than
   the control; the General page's Computer lines are fixed-width and clip.
   Layout checks: every single-line General page text fits and no text line
   overlaps another; every visible control that shows something (empty static
   and link lines do not) lies inside its page on every tab; the sheet's width
   fits the screen (at 640x480 its height already exceeds it); and the model fits the 124 DLU Computer line at
   96, 120 and 144 DPI (dialog base units from Tahoma 8 pt, as sysdm uses). */
#define WINVER 0x0501
#define _WIN32_WINNT 0x0501
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define MANUFACTURER "QuoolAI"
#define MODEL "Windows XP 25th Anniversary Edition"
#define MACHINE_LINE_DLU 124
#define PSM_SETCURSEL_ (WM_USER + 101)
#define PSM_GETTABCONTROL_ (WM_USER + 116)
#define PSM_GETCURRENTPAGEHWND_ (WM_USER + 118)
#define TCM_GETITEMCOUNT_ 0x1304

static HANDLE serial = INVALID_HANDLE_VALUE;
static char out[65536];
static DWORD used;
static unsigned failures;
static BOOL expect;

static void put(const char *text)
{
    while (*text && used < sizeof(out) - 1) out[used++] = *text++;
}
static void put_json(const char *text)
{
    char hex[8];
    put("\"");
    for (; *text; ++text) {
        BYTE c = (BYTE)*text;
        if (c == '"' || c == '\\') { char pair[3] = {'\\', (char)c, 0}; put(pair); }
        else if (c < 0x20 || c >= 0x80) { wsprintfA(hex, "\\u%04x", c); put(hex); }
        else { char one[2] = {(char)c, 0}; put(one); }
    }
    put("\"");
}
static void put_json_w(const WCHAR *text)
{
    char hex[8];
    put("\"");
    for (; *text; ++text) {
        if (*text == L'"' || *text == L'\\') { char pair[3] = {'\\', (char)*text, 0}; put(pair); }
        else if (*text < 0x20 || *text >= 0x80) { wsprintfA(hex, "\\u%04x", (unsigned)*text); put(hex); }
        else { char one[2] = {(char)*text, 0}; put(one); }
    }
    put("\"");
}
static void report(const char *name, BOOL ok, DWORD error)
{
    char line[200];
    if (expect && !ok) ++failures;
    wsprintfA(line, "{\"oem_case\":\"%s\",\"status\":\"%s\",\"holds\":%s,\"error\":%lu}\r\n", name,
              !expect ? "observed" : ok ? "pass" : "fail", ok ? "true" : "false", ok ? 0 : error);
    put(line);
}
static BOOL has(const char *text, const char *part)
{
    unsigned i, j;
    for (i = 0; text[i]; ++i) {
        for (j = 0; part[j] && (text[i+j] | 0x20) == (part[j] | 0x20); ++j) {}
        if (!part[j]) return TRUE;
    }
    return FALSE;
}
static BOOL has_w(const WCHAR *text, const char *part)
{
    unsigned i, j;
    for (i = 0; text[i]; ++i) {
        for (j = 0; part[j] && text[i+j] < 0x80 && ((char)text[i+j] | 0x20) == (part[j] | 0x20); ++j) {}
        if (!part[j]) return TRUE;
    }
    return FALSE;
}
static BOOL same_w(const WCHAR *text, const char *value)
{
    while (*value && *text == (WCHAR)(BYTE)*value) { ++text; ++value; }
    return !*value && !*text;
}
static BOOL third_party(const char *text)
{
    return has(text, "Maher") || has(text, "Digital World");
}
static BOOL exists(const char *path)
{
    return GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
}

static void oeminfo(void)
{
    char ini[MAX_PATH], logo[MAX_PATH], old_logo[MAX_PATH], maker[128], model[128], line1[128];
    GetSystemDirectoryA(ini, MAX_PATH); lstrcpyA(logo, ini);
    lstrcatA(ini, "\\oeminfo.ini"); lstrcatA(logo, "\\oemlogo.bmp");
    GetWindowsDirectoryA(old_logo, MAX_PATH); lstrcatA(old_logo, "\\system\\oemlogo.bmp");
    GetPrivateProfileStringA("General", "Manufacturer", "", maker, sizeof(maker), ini);
    GetPrivateProfileStringA("General", "Model", "", model, sizeof(model), ini);
    GetPrivateProfileStringA("Support Information", "Line1", "", line1, sizeof(line1), ini);
    put("{\"oem_observation\":\"oeminfo\",\"path\":"); put_json(ini);
    put(",\"present\":"); put(exists(ini) ? "true" : "false");
    put(",\"manufacturer\":"); put_json(maker); put(",\"model\":"); put_json(model);
    put(",\"support_line1\":"); put_json(line1);
    put(",\"logo_present\":"); put(exists(logo) ? "true" : "false");
    put(",\"win9x_logo_present\":"); put(exists(old_logo) ? "true" : "false"); put("}\r\n");
    report("oeminfo_manufacturer_quoolai", lstrcmpA(maker, MANUFACTURER) == 0, GetLastError());
    report("oeminfo_model_xp25", lstrcmpA(model, MODEL) == 0, GetLastError());
    report("oeminfo_no_support_section", line1[0] == 0, 0);
    report("oem_logo_absent", !exists(logo) && !exists(old_logo), 0);
    report("oeminfo_no_third_party_text", !third_party(maker) && !third_party(model) && !third_party(line1), 0);
}

static LONG reg_text(HKEY key, const char *name, char *value, DWORD size)
{
    DWORD type = 0; LONG error;
    value[0] = 0;
    error = RegQueryValueExA(key, name, NULL, &type, (BYTE *)value, &size);
    if (error == ERROR_SUCCESS && type != REG_SZ) error = ERROR_INVALID_DATA;
    if (error) value[0] = 0;
    return error;
}
static void helpsvc(void)
{
    char maker[128], model[128], text[512];
    HKEY key = NULL; LONG opened, a = 2, b = 2, c = 2;
    opened = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\PCHealth\\HelpSvc\\OEMInfo", 0, KEY_QUERY_VALUE, &key);
    maker[0] = model[0] = text[0] = 0;
    if (!opened) {
        a = reg_text(key, "Manufacturer", maker, sizeof(maker));
        b = reg_text(key, "Model", model, sizeof(model));
        c = reg_text(key, "Text", text, sizeof(text));
        RegCloseKey(key);
    }
    put("{\"oem_observation\":\"helpsvc_oeminfo\",\"open\":"); put(opened ? "false" : "true");
    put(",\"manufacturer\":"); put_json(maker); put(",\"model\":"); put_json(model);
    put(",\"text\":"); put_json(text); put("}\r\n");
    report("helpsvc_oeminfo_matches", !opened && !a && !b && c == ERROR_FILE_NOT_FOUND &&
           lstrcmpA(maker, MANUFACTURER) == 0 && lstrcmpA(model, MODEL) == 0, opened ? opened : a ? a : b ? b : c);
    report("helpsvc_no_third_party_text", !third_party(maker) && !third_party(model) && !third_party(text), 0);
}

static void identity(void)
{
    OSVERSIONINFOEXA v = {0}; SYSTEM_INFO system; HKEY key; char product[128] = {0}, line[400];
    BOOL ok;
    v.dwOSVersionInfoSize = sizeof(v);
    ok = GetVersionExA((OSVERSIONINFOA *)&v);
    GetSystemInfo(&system);
    if (!RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_QUERY_VALUE, &key)) {
        reg_text(key, "ProductName", product, sizeof(product));
        RegCloseKey(key);
    }
    wsprintfA(line, "{\"oem_observation\":\"identity\",\"major\":%lu,\"minor\":%lu,\"build\":%lu,\"sp_major\":%u,\"product_type\":%u,\"architecture\":%u,\"csd\":",
              v.dwMajorVersion, v.dwMinorVersion, v.dwBuildNumber, v.wServicePackMajor, v.wProductType, system.wProcessorArchitecture);
    put(line); put_json(v.szCSDVersion); put(",\"product_name\":"); put_json(product); put("}\r\n");
    report("nt51_x86_identity", ok && v.dwMajorVersion == 5 && v.dwMinorVersion == 1 && v.dwBuildNumber == 2600 &&
           v.dwPlatformId == VER_PLATFORM_WIN32_NT && v.wProductType == VER_NT_WORKSTATION &&
           system.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL, GetLastError());
    report("product_name_windows_xp", lstrcmpA(product, "Microsoft Windows XP") == 0, 0);
}

#define MAX_CONTROLS 128
static struct { HWND window; int id; BOOL visible; char cls[32]; WCHAR text[160]; } controls[MAX_CONTROLS];
static unsigned control_count;
static BOOL CALLBACK collect(HWND window, LPARAM unused)
{
    DWORD_PTR result;
    (void)unused;
    if (control_count >= MAX_CONTROLS) return FALSE;
    controls[control_count].window = window;
    controls[control_count].id = GetDlgCtrlID(window);
    controls[control_count].visible = IsWindowVisible(window);
    GetClassNameA(window, controls[control_count].cls, sizeof(controls[0].cls));
    controls[control_count].text[0] = 0;
    SendMessageTimeoutW(window, WM_GETTEXT, 160, (LPARAM)controls[control_count].text, SMTO_ABORTIFHUNG, 2000, &result);
    ++control_count;
    return TRUE;
}
/* Width in pixels of text drawn in the control's font. The font handle belongs
   to sysdm's process; when it cannot be read here, the system message font
   (the XP dialog font) is used instead and the method records which. */
static BOOL fits(unsigned i)
{
    DWORD_PTR font = 0; LOGFONTW face; NONCLIENTMETRICSW metrics; RECT client; SIZE size = {0, 0};
    HDC dc; HFONT mine; HGDIOBJ old; int method = 1; char line[200];
    SendMessageTimeoutW(controls[i].window, WM_GETFONT, 0, 0, SMTO_ABORTIFHUNG, 2000, &font);
    if (!font || GetObjectW((HFONT)font, sizeof(face), &face) != sizeof(face)) {
        metrics.cbSize = sizeof(metrics);
        SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(metrics), &metrics, 0);
        face = metrics.lfMessageFont; method = 2;
    }
    GetClientRect(controls[i].window, &client);
    dc = GetDC(NULL); mine = CreateFontIndirectW(&face); old = SelectObject(dc, mine);
    GetTextExtentPoint32W(dc, controls[i].text, lstrlenW(controls[i].text), &size);
    SelectObject(dc, old); DeleteObject(mine); ReleaseDC(NULL, dc);
    wsprintfA(line, "{\"oem_observation\":\"sysdm_fit\",\"id\":%d,\"text_px\":%ld,\"client_px\":%ld,\"font_height\":%ld,\"font_method\":%d,\"face\":",
              controls[i].id, size.cx, client.right - client.left, face.lfHeight, method);
    put(line); put_json_w(face.lfFaceName); put(size.cx && size.cx <= client.right - client.left ? ",\"fits\":true}\r\n" : ",\"fits\":false}\r\n");
    return size.cx && size.cx <= client.right - client.left;
}
static BOOL memory_line(void)
{
    unsigned i;
    for (i = 0; i < control_count; ++i)
        if (controls[i].visible && has_w(controls[i].text, " MB of RAM")) return TRUE;
    return FALSE;
}

static BOOL single_line_text(unsigned i)
{
    const WCHAR *t = controls[i].text;
    if (!controls[i].visible || !t[0]) return FALSE;
    if (lstrcmpA(controls[i].cls, "Static") && lstrcmpA(controls[i].cls, "Link Window") && lstrcmpA(controls[i].cls, "Edit")) return FALSE;
    for (; *t; ++t) if (*t == L'\r' || *t == L'\n') return FALSE;
    return TRUE;
}
static BOOL overlaps(unsigned i, unsigned j)
{
    RECT a, b, c;
    GetWindowRect(controls[i].window, &a); GetWindowRect(controls[j].window, &b);
    return IntersectRect(&c, &a, &b);
}
typedef struct { RECT page; unsigned count, outside; int first; } BOUNDS;
static BOOL CALLBACK inside(HWND window, LPARAM data)
{
    BOUNDS *b = (BOUNDS *)data; RECT r; char cls[32]; DWORD_PTR length = 0;
    if (!IsWindowVisible(window)) return TRUE;
    GetClassNameA(window, cls, sizeof(cls));
    SendMessageTimeoutW(window, WM_GETTEXTLENGTH, 0, 0, SMTO_ABORTIFHUNG, 2000, &length);
    if (!length) {
        LONG type = GetWindowLongA(window, GWL_STYLE) & SS_TYPEMASK;
        if (!lstrcmpA(cls, "Link Window")) return TRUE;
        if (!lstrcmpA(cls, "Static") && (type <= SS_RIGHT || type == SS_SIMPLE || type == SS_LEFTNOWORDWRAP)) return TRUE;
    }
    GetWindowRect(window, &r); ++b->count;
    if (r.left < b->page.left || r.top < b->page.top || r.right > b->page.right || r.bottom > b->page.bottom) {
        if (!b->outside++) b->first = GetDlgCtrlID(window);
    }
    return TRUE;
}
/* Visit every tab, then return to General. Pages are created when first shown. */
static BOOL pages_inside(HWND sheet)
{
    DWORD_PTR tab = 0, count = 0, page = 0; unsigned i; BOOL ok = TRUE; char line[240]; WCHAR title[64];
    SendMessageTimeoutW(sheet, PSM_GETTABCONTROL_, 0, 0, SMTO_ABORTIFHUNG, 5000, &tab);
    if (tab) SendMessageTimeoutW((HWND)tab, TCM_GETITEMCOUNT_, 0, 0, SMTO_ABORTIFHUNG, 5000, &count);
    for (i = 0; i < count; ++i) {
        BOUNDS b = {{0, 0, 0, 0}, 0, 0, 0}; DWORD_PTR result;
        unsigned tries;
        SendMessageTimeoutW(sheet, PSM_SETCURSEL_, i, 0, SMTO_ABORTIFHUNG, 15000, &result);
        for (tries = 0; tries < 10; ++tries) {      /* a slow page (System Restore) may still be created */
            Sleep(tries ? 500 : 1500);
            page = 0; title[0] = 0;
            SendMessageTimeoutW(sheet, PSM_GETCURRENTPAGEHWND_, 0, 0, SMTO_ABORTIFHUNG, 5000, &page);
            if (page && GetWindowRect((HWND)page, &b.page) && b.page.right > b.page.left) break;
        }
        if (page && b.page.right > b.page.left) {
            SendMessageTimeoutW((HWND)page, WM_GETTEXT, 64, (LPARAM)title, SMTO_ABORTIFHUNG, 2000, &result);
            EnumChildWindows((HWND)page, inside, (LPARAM)&b);
        }
        wsprintfA(line, "{\"oem_observation\":\"sysdm_page\",\"index\":%u,\"page\":%s,\"width_px\":%ld,\"height_px\":%ld,\"visible_controls\":%u,\"outside\":%u,\"first_outside_id\":%d,\"title\":",
                  i, page ? "true" : "false", b.page.right - b.page.left, b.page.bottom - b.page.top, b.count, b.outside, b.first);
        put(line); put_json_w(title); put("}\r\n");
        if (!page || b.page.right <= b.page.left || !b.count || b.outside) ok = FALSE;
    }
    if (count) SendMessageTimeoutW(sheet, PSM_SETCURSEL_, 0, 0, SMTO_ABORTIFHUNG, 15000, &page);
    return ok && count > 0;
}
static BOOL model_metrics(void)
{
    static const WCHAR alphabet[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    static const WCHAR model[] = L"" MODEL;
    NONCLIENTMETRICSW metrics; HDC dc = GetDC(NULL); unsigned dpi; BOOL ok = dc != NULL; char line[200];
    metrics.cbSize = sizeof(metrics);
    SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(metrics), &metrics, 0);
    for (dpi = 96; ok && dpi <= 144; dpi += 24) {
        LOGFONTW face = metrics.lfMessageFont; HFONT font; HGDIOBJ old; SIZE abc = {0, 0}, text = {0, 0}; int base;
        face.lfHeight = -MulDiv(8, dpi, 72); face.lfWidth = 0;
        font = CreateFontIndirectW(&face); old = SelectObject(dc, font);
        GetTextExtentPoint32W(dc, alphabet, 52, &abc); GetTextExtentPoint32W(dc, model, lstrlenW(model), &text);
        SelectObject(dc, old); DeleteObject(font);
        base = (abc.cx / 26 + 1) / 2;
        wsprintfA(line, "{\"oem_observation\":\"model_metrics\",\"dpi\":%u,\"text_px\":%ld,\"line_124_dlu_px\":%d,\"line_110_dlu_px\":%d}\r\n",
                  dpi, text.cx, MulDiv(MACHINE_LINE_DLU, base, 4), MulDiv(110, base, 4));
        put(line);
        ok = text.cx > 0 && text.cx <= MulDiv(MACHINE_LINE_DLU, base, 4);
    }
    if (dc) ReleaseDC(NULL, dc);
    return ok;
}
static void system_properties(void)
{
    char command[] = "rundll32.exe shell32.dll,Control_RunDLL sysdm.cpl,,0";
    STARTUPINFOA startup = {0}; PROCESS_INFORMATION process = {0};
    HWND window = NULL; DWORD start, pid = 0, error = 0; unsigned i, j;
    BOOL started, maker_then_model = FALSE, clean = TRUE, maker_fits = FALSE, model_fits = FALSE;
    BOOL all_fit = TRUE, no_overlap = TRUE, on_screen = FALSE, tabs_ok = FALSE;
    char line[200];
    start = GetTickCount();       /* a window left open by an earlier run would hold stale text */
    while ((window = FindWindowA("#32770", "System Properties")) != NULL && GetTickCount() - start < 10000) {
        PostMessageA(window, WM_CLOSE, 0, 0);
        Sleep(500);
    }
    startup.cb = sizeof(startup);
    started = CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process);
    if (!started) error = GetLastError();
    start = GetTickCount();
    do {
        window = FindWindowA("#32770", "System Properties");
        if (window) {
            control_count = 0;
            EnumChildWindows(window, collect, 0);
            if (memory_line()) break;
        }
        Sleep(500);
    } while (GetTickCount() - start < 30000);
    if (window) {
        Sleep(1000);              /* let the asynchronous General page settle, then read it again */
        control_count = 0;
        EnumChildWindows(window, collect, 0);
        GetWindowThreadProcessId(window, &pid);
    }
    wsprintfA(line, "{\"oem_observation\":\"system_properties\",\"started\":%s,\"window\":%s,\"same_process\":%s,\"controls\":%u,\"wait_ms\":%lu}\r\n",
              started ? "true" : "false", window ? "true" : "false", started && pid == process.dwProcessId ? "true" : "false",
              control_count, GetTickCount() - start);
    put(line);
    for (i = 0; i < control_count; ++i) {
        if (!controls[i].text[0]) continue;
        wsprintfA(line, "{\"oem_observation\":\"sysdm_control\",\"id\":%d,\"class\":", controls[i].id);
        put(line); put_json(controls[i].cls); put(controls[i].visible ? ",\"visible\":true,\"text\":" : ",\"visible\":false,\"text\":");
        put_json_w(controls[i].text); put("}\r\n");
        if (has_w(controls[i].text, "Maher") || has_w(controls[i].text, "Digital World")) clean = FALSE;
        if (controls[i].visible && same_w(controls[i].text, MANUFACTURER))
            for (j = 0; j < control_count; ++j)
                if (controls[j].id == controls[i].id + 1 && controls[j].visible && same_w(controls[j].text, MODEL)) {
                    maker_then_model = TRUE;
                    maker_fits = fits(i);
                    model_fits = fits(j);
                }
    }
    for (i = 0; i < control_count; ++i) {
        if (!single_line_text(i)) continue;
        if (!fits(i)) all_fit = FALSE;
        if (!lstrcmpA(controls[i].cls, "Link Window"))
            for (j = 0; j < control_count; ++j)
                if (j != i && controls[j].visible && controls[j].text[0] && lstrcmpA(controls[j].cls, "#32770") &&
                    lstrcmpA(controls[j].cls, "SysTabControl32") && overlaps(i, j)) {
                    wsprintfA(line, "{\"oem_observation\":\"sysdm_overlap\",\"id\":%d,\"with\":%d}\r\n", controls[i].id, controls[j].id);
                    put(line); no_overlap = FALSE;
                }
    }
    if (window) {
        RECT r; GetWindowRect(window, &r);
        on_screen = r.left >= 0 && r.right <= GetSystemMetrics(SM_CXSCREEN);
        wsprintfA(line, "{\"oem_observation\":\"sysdm_sheet\",\"left\":%ld,\"top\":%ld,\"width_px\":%ld,\"height_px\":%ld,\"screen\":\"%dx%d\"}\r\n",
                  r.left, r.top, r.right - r.left, r.bottom - r.top, GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN));
        put(line);
        tabs_ok = pages_inside(window);
    }
    if (started) { CloseHandle(process.hThread); CloseHandle(process.hProcess); }
    report("system_properties_opened", window != NULL && memory_line(), error ? error : GetLastError());
    report("system_properties_manufacturer_then_model", maker_then_model, 0);
    report("system_properties_no_third_party_text", window != NULL && clean, 0);
    report("system_properties_manufacturer_fully_visible", maker_fits, 0);
    report("system_properties_model_fully_visible", model_fits, 0);
    report("general_page_all_text_fits", window != NULL && all_fit, 0);
    report("general_page_no_overlapping_text", window != NULL && no_overlap, 0);
    report("system_properties_width_on_screen", on_screen, 0);
    report("property_pages_controls_inside", tabs_ok, 0);
    report("model_fits_124_dlu_96_120_144dpi", model_metrics(), GetLastError());
}

static void rename_computer(const char *name)
{
    char before[64], line[200]; DWORD size = sizeof(before), error = 0; BOOL ok;
    before[0] = 0;
    GetComputerNameExA(ComputerNamePhysicalDnsHostname, before, &size);
    ok = SetComputerNameExA(ComputerNamePhysicalDnsHostname, name);
    if (!ok) error = GetLastError();
    put("{\"oem_rename\":true,\"before\":"); put_json(before); put(",\"requested\":"); put_json(name);
    wsprintfA(line, ",\"ok\":%s,\"error\":%lu}\r\n", ok ? "true" : "false", error);
    put(line);
    if (!ok) ++failures;
}

/* Copy the token following option (for example "--out ") into value. */
static BOOL option(const char *args, const char *name, char *value, unsigned capacity)
{
    unsigned i, j, n = lstrlenA(name);
    for (i = 0; args[i]; ++i) {
        for (j = 0; j < n && args[i + j] == name[j]; ++j) {}
        if (j == n) {
            const char *p = args + i + n;
            while (*p == ' ') ++p;
            for (j = 0; p[j] && p[j] != ' ' && j + 1 < capacity; ++j) value[j] = p[j];
            value[j] = 0;
            return j > 0;
        }
    }
    return FALSE;
}

void WINAPI ProbeMain(void)
{
    char *args = GetCommandLineA(), path[MAX_PATH], name[64];
    HANDLE file; DWORD written; char line[120]; BOOL renaming;
    expect = has(args, "--expect");
    if (!option(args, "--out ", path, sizeof(path))) ExitProcess(91);
    renaming = option(args, "--rename ", name, sizeof(name));
    serial = CreateFileA("COM1", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    put("{\"oem_probe_started\":true,\"mode\":");
    put(renaming ? "\"rename\"}\r\n" : expect ? "\"expect\"}\r\n" : "\"observe\"}\r\n");
    if (renaming) rename_computer(name);
    else { oeminfo(); helpsvc(); identity(); system_properties(); }
    wsprintfA(line, "{\"oem_probe_done\":true,\"failures\":%u}\r\n", failures);
    put(line);
    file = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) ExitProcess(92);
    if (!WriteFile(file, out, used, &written, NULL) || written != used) ExitProcess(93);
    FlushFileBuffers(file); CloseHandle(file);
    if (serial != INVALID_HANDLE_VALUE) { WriteFile(serial, out, used, &written, NULL); CloseHandle(serial); }
    ExitProcess(failures);
}
