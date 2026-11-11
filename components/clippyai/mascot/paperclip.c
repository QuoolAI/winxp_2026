/* ClippyAI built-in mascot: an animated paperclip drawn with GDI. This is
   XP25's own drawing; Windows XP ships no Clippy character to reuse. */
#include <windows.h>
#include <string.h>
#include "mascot.h"
#include "../../xp25-agent/runtime/xp25_base.h"
#include "../app/resource.h"

#define MASCOT_CLASS L"XP25PaperclipMascot"

typedef struct {
    MASCOT base;
    MASCOT_STATE state;
    unsigned long tick;
    unsigned long state_tick;
} CLIP;

static void wire(HDC dc, int ox, int oy, int bob, COLORREF color, int width)
{
    HPEN pen = CreatePen(PS_SOLID, width, color), old = (HPEN)SelectObject(dc, pen);
    HBRUSH oldb = (HBRUSH)SelectObject(dc, GetStockObject(NULL_BRUSH));
    int y = oy + bob;
    /* Three nested loops of a paperclip, standing upright. */
    Arc(dc, ox - 18, y + 8, ox + 18, y + 44, ox + 18, y + 26, ox - 18, y + 26);       /* top outer */
    MoveToEx(dc, ox - 18, y + 26, NULL); LineTo(dc, ox - 18, y + 112);
    Arc(dc, ox - 18, y + 94, ox + 12, y + 124, ox - 18, y + 110, ox + 12, y + 110);   /* bottom outer */
    MoveToEx(dc, ox + 12, y + 110, NULL); LineTo(dc, ox + 12, y + 46);
    Arc(dc, ox - 10, y + 32, ox + 12, y + 54, ox + 12, y + 44, ox - 10, y + 44);      /* inner top */
    MoveToEx(dc, ox - 10, y + 44, NULL); LineTo(dc, ox - 10, y + 96);
    MoveToEx(dc, ox + 18, y + 26, NULL); LineTo(dc, ox + 18, y + 84);
    SelectObject(dc, oldb);
    SelectObject(dc, old);
    DeleteObject(pen);
}

static void eye(HDC dc, int cx, int cy, int dx, int dy, int closed)
{
    HBRUSH white = (HBRUSH)GetStockObject(WHITE_BRUSH), black = (HBRUSH)GetStockObject(BLACK_BRUSH);
    HPEN pen = CreatePen(PS_SOLID, 1, RGB(40, 40, 40)), old = (HPEN)SelectObject(dc, pen);
    if (closed) {
        MoveToEx(dc, cx - 8, cy, NULL);
        LineTo(dc, cx + 8, cy);
    } else {
        SelectObject(dc, white);
        Ellipse(dc, cx - 9, cy - 11, cx + 9, cy + 11);
        SelectObject(dc, black);
        Ellipse(dc, cx - 4 + dx, cy - 4 + dy, cx + 4 + dx, cy + 4 + dy);
    }
    SelectObject(dc, old);
    DeleteObject(pen);
}

static void paint(HWND hwnd, CLIP *c)
{
    PAINTSTRUCT ps;
    HDC dc = BeginPaint(hwnd, &ps), mem;
    RECT rc;
    HBITMAP bmp, oldbmp;
    unsigned long t = c->tick, s = c->tick - c->state_tick;
    int ox, oy, bob = 0, dx = 0, dy = 0, closed = 0, brow = 0;
    HPEN pen, old;
    GetClientRect(hwnd, &rc);
    mem = CreateCompatibleDC(dc);
    bmp = CreateCompatibleBitmap(dc, rc.right, rc.bottom);
    oldbmp = (HBITMAP)SelectObject(mem, bmp);
    FillRect(mem, &rc, GetSysColorBrush(COLOR_BTNFACE));
    ox = rc.right / 2;
    oy = rc.bottom - 140 > 4 ? rc.bottom - 140 : 4;
    switch (c->state) {
    case MASCOT_THINKING: dx = (int)((t / 4) % 3) * 2 - 2; dy = -3; brow = 2; break;
    case MASCOT_WORKING: bob = (int)(t % 4 < 2 ? t % 4 : 4 - t % 4) * 2; dx = 2; break;
    case MASCOT_SUCCESS: bob = s < 6 ? -(int)(s % 3) * 3 : 0; brow = 4; break;
    case MASCOT_ERROR: dy = 3; brow = -3; break;
    case MASCOT_ATTENTION: bob = (int)(t % 2) * -4; brow = 4; break;
    case MASCOT_GREET: bob = s < 8 ? -(int)(s % 4) * 2 : 0; brow = 3; break;
    default: closed = (t % 40) == 0; bob = (t % 30) < 15 ? 0 : 1; break;
    }
    wire(mem, ox + 2, oy + 2, bob, RGB(150, 150, 160), 6);
    wire(mem, ox, oy, bob, RGB(110, 115, 125), 5);
    wire(mem, ox - 1, oy - 1, bob, RGB(225, 230, 238), 2);
    eye(mem, ox - 11, oy + 30 + bob, dx, dy, closed);
    eye(mem, ox + 11, oy + 30 + bob, dx, dy, closed);
    pen = CreatePen(PS_SOLID, 2, RGB(40, 40, 40));
    old = (HPEN)SelectObject(mem, pen);
    MoveToEx(mem, ox - 18, oy + 16 + bob - (brow > 0 ? brow : 0), NULL);
    LineTo(mem, ox - 5, oy + 16 + bob - brow);
    MoveToEx(mem, ox + 5, oy + 16 + bob - brow, NULL);
    LineTo(mem, ox + 18, oy + 16 + bob - (brow > 0 ? brow : 0));
    SelectObject(mem, old);
    DeleteObject(pen);
    BitBlt(dc, 0, 0, rc.right, rc.bottom, mem, 0, 0, SRCCOPY);
    SelectObject(mem, oldbmp);
    DeleteObject(bmp);
    DeleteDC(mem);
    EndPaint(hwnd, &ps);
}

static LRESULT CALLBACK proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    CLIP *c = (CLIP *)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    switch (msg) {
    case WM_CREATE:
        SetTimer(hwnd, 1, 120, NULL);
        return 0;
    case WM_TIMER:
        if (c) {
            ++c->tick;
            if ((c->state == MASCOT_SUCCESS || c->state == MASCOT_GREET) && c->tick - c->state_tick > 25) c->state = MASCOT_IDLE;
            InvalidateRect(hwnd, NULL, FALSE);
        }
        return 0;
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT:
        if (c) { paint(hwnd, c); return 0; }
        break;
    case WM_DESTROY:
        KillTimer(hwnd, 1);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static void set_state(MASCOT *self, MASCOT_STATE state)
{
    CLIP *c = (CLIP *)self;
    c->state = state;
    c->state_tick = c->tick;
    InvalidateRect(self->window, NULL, FALSE);
}

static void place(MASCOT *self, const RECT *screen)
{
    POINT pt;
    pt.x = screen->left;
    pt.y = screen->top;
    ScreenToClient(GetParent(self->window), &pt);
    MoveWindow(self->window, pt.x, pt.y, screen->right - screen->left, screen->bottom - screen->top, TRUE);
}

static void show(MASCOT *self, int visible) { ShowWindow(self->window, visible ? SW_SHOW : SW_HIDE); }

static void destroy(MASCOT *self)
{
    DestroyWindow(self->window);
    xp25_free(self);
}

MASCOT *mascot_paperclip_create(HWND parent, HINSTANCE instance)
{
    static ATOM atom;
    CLIP *c = (CLIP *)xp25_alloc(sizeof(CLIP));
    if (!c) return NULL;
    if (!atom) {
        WNDCLASSW wc;
        memset(&wc, 0, sizeof(wc));
        wc.lpfnWndProc = proc;
        wc.hInstance = instance;
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.lpszClassName = MASCOT_CLASS;
        atom = RegisterClassW(&wc);
    }
    c->base.name = "builtin paperclip";
    c->base.set_state = set_state;
    c->base.place = place;
    c->base.show = show;
    c->base.destroy = destroy;
    c->base.window = CreateWindowExW(0, MASCOT_CLASS, L"ClippyAI mascot", WS_CHILD | WS_VISIBLE, 0, 0, 120, 160,
                                     parent, (HMENU)IDC_MASCOT, instance, NULL);
    if (!c->base.window) { xp25_free(c); return NULL; }
    SetWindowLongPtrW(c->base.window, GWLP_USERDATA, (LONG_PTR)c);
    set_state(&c->base, MASCOT_GREET);
    return &c->base;
}
