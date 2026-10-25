/* ClippyAI chat view: a custom control drawing conversation bubbles with
   expandable tool results. WM_GETTEXT returns the plain-text transcript so
   screen readers and automated checks see exactly what is displayed. */
#include <windows.h>
#include <string.h>
#include "../app/clippyai.h"

typedef struct {
    CHAT_KIND kind;
    int ok, expanded, height;
    WCHAR *title, *text, *detail;
} ITEM;

typedef struct {
    ITEM *items;
    int count, cap;
    int width, total, scroll, page;
    int menu_item;
} VIEW;

#define PAD 6
#define DETAIL_LIMIT 12000

static WCHAR *wide(const char *s)
{
    return s ? xp25w_wide(s) : NULL;
}

static COLORREF fill_of(const ITEM *it)
{
    switch (it->kind) {
    case CK_USER: return RGB(214, 232, 255);
    case CK_ASSISTANT: return RGB(255, 251, 224);
    case CK_TOOL: return it->ok ? RGB(236, 244, 236) : RGB(250, 232, 228);
    case CK_ERROR: return RGB(255, 226, 222);
    case CK_DENIED: return RGB(247, 240, 222);
    default: return RGB(240, 240, 240);
    }
}

static const WCHAR *body_of(const ITEM *it)
{
    if (it->kind == CK_TOOL && it->expanded && it->detail) return it->detail;
    return it->text ? it->text : L"";
}

static int measure(HWND hwnd, VIEW *v, ITEM *it)
{
    HDC dc = GetDC(hwnd);
    RECT r;
    int h = 2 * PAD, bubble = v->width - 70;
    HFONT old = (HFONT)SelectObject(dc, it->kind == CK_TOOL && it->expanded ? g_app.mono : g_app.font);
    if (bubble < 80) bubble = 80;
    if (it->kind == CK_TOOL || it->kind == CK_DENIED || it->kind == CK_ERROR) h += 16;
    SetRect(&r, 0, 0, bubble - 2 * PAD, 0);
    DrawTextW(dc, body_of(it), -1, &r, DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX | DT_EDITCONTROL);
    h += r.bottom - r.top;
    SelectObject(dc, old);
    ReleaseDC(hwnd, dc);
    it->height = h + PAD;
    return it->height;
}

static void relayout(HWND hwnd, VIEW *v)
{
    RECT rc;
    SCROLLINFO si;
    int i;
    GetClientRect(hwnd, &rc);
    v->width = rc.right - GetSystemMetrics(SM_CXVSCROLL);
    v->page = rc.bottom;
    v->total = PAD;
    for (i = 0; i < v->count; ++i) v->total += measure(hwnd, v, &v->items[i]);
    if (v->scroll > v->total - v->page) v->scroll = v->total - v->page;
    if (v->scroll < 0) v->scroll = 0;
    memset(&si, 0, sizeof(si));
    si.cbSize = sizeof(si);
    si.fMask = SIF_RANGE | SIF_PAGE | SIF_POS | SIF_DISABLENOSCROLL;
    si.nMax = v->total;
    si.nPage = (UINT)v->page;
    si.nPos = v->scroll;
    SetScrollInfo(hwnd, SB_VERT, &si, TRUE);
}

static void scroll_to(HWND hwnd, VIEW *v, int pos)
{
    if (pos > v->total - v->page) pos = v->total - v->page;
    if (pos < 0) pos = 0;
    v->scroll = pos;
    SetScrollPos(hwnd, SB_VERT, pos, TRUE);
    InvalidateRect(hwnd, NULL, FALSE);
}

static void paint(HWND hwnd, VIEW *v)
{
    PAINTSTRUCT ps;
    HDC dc = BeginPaint(hwnd, &ps), mem;
    RECT rc;
    HBITMAP bmp, oldbmp;
    int i, y = PAD - v->scroll;
    GetClientRect(hwnd, &rc);
    mem = CreateCompatibleDC(dc);
    bmp = CreateCompatibleBitmap(dc, rc.right, rc.bottom);
    oldbmp = (HBITMAP)SelectObject(mem, bmp);
    FillRect(mem, &rc, (HBRUSH)GetStockObject(WHITE_BRUSH));
    SetBkMode(mem, TRANSPARENT);
    for (i = 0; i < v->count; ++i) {
        ITEM *it = &v->items[i];
        int bubble = v->width - 70, left;
        RECT b, t;
        HBRUSH brush;
        HPEN pen, oldpen;
        if (bubble < 80) bubble = 80;
        if (y + it->height < 0 || y > rc.bottom) { y += it->height; continue; }
        left = it->kind == CK_USER ? v->width - bubble - PAD : PAD;
        SetRect(&b, left, y, left + bubble, y + it->height - PAD);
        brush = CreateSolidBrush(fill_of(it));
        pen = CreatePen(PS_SOLID, 1, it->kind == CK_ASSISTANT ? RGB(190, 170, 90) : RGB(160, 175, 200));
        oldpen = (HPEN)SelectObject(mem, pen);
        SelectObject(mem, brush);
        RoundRect(mem, b.left, b.top, b.right, b.bottom, 10, 10);
        SelectObject(mem, oldpen);
        DeleteObject(pen);
        DeleteObject(brush);
        t = b;
        InflateRect(&t, -PAD, -PAD);
        if (it->kind == CK_TOOL || it->kind == CK_DENIED || it->kind == CK_ERROR) {
            WCHAR header[300];
            SelectObject(mem, g_app.bold);
            SetTextColor(mem, it->kind == CK_TOOL ? (it->ok ? RGB(0, 100, 0) : RGB(160, 30, 20)) : RGB(130, 60, 0));
            lstrcpynW(header, it->kind == CK_TOOL ? (it->expanded ? L"[-] " : L"[+] ") : L"", 8);
            lstrcatW(header, L"");
            if (it->title) { lstrcpynW(header + lstrlenW(header), it->title, 280); }
            DrawTextW(mem, header, -1, &t, DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
            t.top += 16;
        }
        SelectObject(mem, it->kind == CK_TOOL && it->expanded ? g_app.mono : g_app.font);
        SetTextColor(mem, it->kind == CK_NOTICE ? RGB(90, 90, 90) : RGB(0, 0, 0));
        DrawTextW(mem, body_of(it), -1, &t, DT_WORDBREAK | DT_NOPREFIX | DT_EDITCONTROL);
        y += it->height;
    }
    BitBlt(dc, 0, 0, rc.right, rc.bottom, mem, 0, 0, SRCCOPY);
    SelectObject(mem, oldbmp);
    DeleteObject(bmp);
    DeleteDC(mem);
    EndPaint(hwnd, &ps);
}

static int hit(VIEW *v, int y)
{
    int i, top = PAD - v->scroll;
    for (i = 0; i < v->count; ++i) {
        if (y >= top && y < top + v->items[i].height) return i;
        top += v->items[i].height;
    }
    return -1;
}

static void append_item_text(XP25_BUF *b, const ITEM *it, int full)
{
    static const char *roles[] = { "You", "ClippyAI", "Tool", "Notice", "Error", "Not done" };
    xp25_buf_puts(b, roles[it->kind]);
    if (it->title) { xp25_buf_puts(b, " ["); xp25w_buf_wide(b, it->title); xp25_buf_puts(b, "]"); }
    xp25_buf_puts(b, ": ");
    xp25w_buf_wide(b, it->text ? it->text : L"");
    if (full && it->detail) { xp25_buf_puts(b, "\r\n    "); xp25w_buf_wide(b, it->detail); }
    xp25_buf_puts(b, "\r\n");
}

static WCHAR *transcript(VIEW *v, int only)
{
    XP25_BUF b;
    int i;
    WCHAR *w;
    xp25_buf_init(&b);
    for (i = 0; i < v->count; ++i)
        if (only < 0 || only == i) append_item_text(&b, &v->items[i], 1);
    w = xp25w_wide(xp25_buf_cstr(&b));
    xp25_buf_free(&b);
    return w;
}

static void copy_text(HWND hwnd, const WCHAR *text)
{
    HGLOBAL mem;
    size_t bytes;
    if (!text || !OpenClipboard(hwnd)) return;
    EmptyClipboard();
    bytes = ((size_t)lstrlenW(text) + 1) * sizeof(WCHAR);
    mem = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (mem) {
        memcpy(GlobalLock(mem), text, bytes);
        GlobalUnlock(mem);
        if (!SetClipboardData(CF_UNICODETEXT, mem)) GlobalFree(mem);
    }
    CloseClipboard();
}

static void free_item(ITEM *it)
{
    xp25_free(it->title);
    xp25_free(it->text);
    xp25_free(it->detail);
}

static LRESULT CALLBACK chat_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    VIEW *v = (VIEW *)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    switch (msg) {
    case WM_CREATE:
        v = (VIEW *)xp25_alloc(sizeof(VIEW));
        if (!v) return -1;
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)v);
        return 0;
    case WM_DESTROY:
        if (v) {
            int i;
            for (i = 0; i < v->count; ++i) free_item(&v->items[i]);
            xp25_free(v->items);
            xp25_free(v);
        }
        return 0;
    case WM_SIZE:
        relayout(hwnd, v);
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT:
        paint(hwnd, v);
        return 0;
    case WM_VSCROLL: {
        int pos = v->scroll;
        SCROLLINFO si;
        si.cbSize = sizeof(si);
        si.fMask = SIF_TRACKPOS;
        GetScrollInfo(hwnd, SB_VERT, &si);
        switch (LOWORD(wp)) {
        case SB_LINEUP: pos -= 20; break;
        case SB_LINEDOWN: pos += 20; break;
        case SB_PAGEUP: pos -= v->page; break;
        case SB_PAGEDOWN: pos += v->page; break;
        case SB_THUMBTRACK: case SB_THUMBPOSITION: pos = si.nTrackPos; break;
        case SB_TOP: pos = 0; break;
        case SB_BOTTOM: pos = v->total; break;
        }
        scroll_to(hwnd, v, pos);
        return 0;
    }
    case WM_MOUSEWHEEL:
        scroll_to(hwnd, v, v->scroll - (short)HIWORD(wp) / 2);
        return 0;
    case WM_LBUTTONDOWN: {
        int i = hit(v, (short)HIWORD(lp));
        SetFocus(hwnd);
        if (i >= 0 && v->items[i].kind == CK_TOOL && v->items[i].detail) {
            v->items[i].expanded = !v->items[i].expanded;
            relayout(hwnd, v);
            InvalidateRect(hwnd, NULL, FALSE);
        }
        return 0;
    }
    case WM_CONTEXTMENU: {
        HMENU menu = CreatePopupMenu();
        POINT pt;
        int cmd;
        pt.x = (short)LOWORD(lp);
        pt.y = (short)HIWORD(lp);
        if (pt.x == -1 && pt.y == -1) { pt.x = pt.y = 10; ClientToScreen(hwnd, &pt); }
        {
            POINT client = pt;
            ScreenToClient(hwnd, &client);
            v->menu_item = hit(v, client.y);
        }
        AppendMenuW(menu, MF_STRING | (v->menu_item < 0 ? MF_GRAYED : 0), IDM_COPY_ITEM, L"&Copy message");
        AppendMenuW(menu, MF_STRING, IDM_COPY_ALL, L"Copy &whole conversation");
        cmd = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
        DestroyMenu(menu);
        if (cmd == IDM_COPY_ITEM || cmd == IDM_COPY_ALL) {
            WCHAR *text = transcript(v, cmd == IDM_COPY_ITEM ? v->menu_item : -1);
            copy_text(hwnd, text);
            xp25_free(text);
        }
        return 0;
    }
    case WM_KEYDOWN:
        if (wp == VK_PRIOR || wp == VK_NEXT || wp == VK_UP || wp == VK_DOWN || wp == VK_HOME || wp == VK_END) {
            int delta = wp == VK_PRIOR ? -v->page : wp == VK_NEXT ? v->page : wp == VK_UP ? -20 : wp == VK_DOWN ? 20 : 0;
            scroll_to(hwnd, v, wp == VK_HOME ? 0 : wp == VK_END ? v->total : v->scroll + delta);
            return 0;
        }
        break;
    case WM_GETDLGCODE:
        return DLGC_WANTARROWS;
    case WM_GETTEXTLENGTH: {
        WCHAR *text = transcript(v, -1);
        LRESULT n = text ? lstrlenW(text) : 0;
        xp25_free(text);
        return n;
    }
    case WM_GETTEXT: {
        WCHAR *text = transcript(v, -1);
        LRESULT n = 0;
        if (wp && lp) {
            lstrcpynW((WCHAR *)lp, text ? text : L"", (int)wp);
            n = lstrlenW((WCHAR *)lp);
        }
        xp25_free(text);
        return n;
    }
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

ATOM chat_register(HINSTANCE instance)
{
    WNDCLASSW wc;
    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = chat_proc;
    wc.hInstance = instance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.lpszClassName = CHAT_CLASS;
    wc.style = CS_HREDRAW | CS_VREDRAW;
    return RegisterClassW(&wc);
}

void chat_add(HWND chat, CHAT_KIND kind, const char *title, const char *text, const char *detail, int ok)
{
    VIEW *v = (VIEW *)GetWindowLongPtrW(chat, GWLP_USERDATA);
    ITEM *it;
    if (!v) return;
    if (v->count == v->cap) {
        int cap = v->cap ? v->cap * 2 : 32;
        ITEM *bigger = (ITEM *)xp25_realloc(v->items, (size_t)cap * sizeof(ITEM));
        if (!bigger) return;
        v->items = bigger;
        v->cap = cap;
    }
    it = &v->items[v->count++];
    memset(it, 0, sizeof(*it));
    it->kind = kind;
    it->ok = ok;
    it->title = wide(title);
    it->text = wide(text);
    if (detail) {
        size_t n = xp25_utf8_clip(detail, DETAIL_LIMIT);
        char *clipped = xp25_strndup(detail, n);
        it->detail = wide(clipped);
        xp25_free(clipped);
    }
    relayout(chat, v);
    scroll_to(chat, v, v->total);
}

void chat_clear(HWND chat)
{
    VIEW *v = (VIEW *)GetWindowLongPtrW(chat, GWLP_USERDATA);
    int i;
    if (!v) return;
    for (i = 0; i < v->count; ++i) free_item(&v->items[i]);
    v->count = 0;
    relayout(chat, v);
    InvalidateRect(chat, NULL, FALSE);
}

int chat_save(HWND chat, const WCHAR *path)
{
    VIEW *v = (VIEW *)GetWindowLongPtrW(chat, GWLP_USERDATA);
    WCHAR *text = v ? transcript(v, -1) : NULL;
    char *u = text ? xp25w_utf8(text) : NULL;
    int ok = u && xp25w_write_file_atomic(path, u, (DWORD)strlen(u));
    xp25_free(u);
    xp25_free(text);
    return ok;
}
