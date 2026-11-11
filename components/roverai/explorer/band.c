/* RoverAIBand.dll: RoverAI as a vertical Explorer bar (CATID_InfoBand).
   Two classes share one implementation:
   - CLSID_RoverAIBand: the "RoverAI Search" bar and toolbar button.
   - CLSID_RoverAISearchBand / CLSID_RoverAIFileSearchBand: targets of an
     optional COM TreatAs emulation of the two Search Companion hosts,
     browseui's CLSID_SearchBand and shell32's CLSID_FileSearchBand (used by
     F3 in folder windows, defview.cpp _OnSearchFiles). browseui creates
     both with CoCreateInstance (shbrows2.cpp _GetInfoBandBS), so Explorer's
     Search button, F3 and Start > Search open RoverAI without any binary
     patch. Removing the TreatAs keys restores the original Search Companion. */
#include <windows.h>
#include <objbase.h>
#include <shlobj.h>
#include <shlguid.h>
#include <stddef.h>
#include <string.h>
#include "panel.h"
#include "band.h"

#define HOST_CLASS L"XP25RoverAIBandHost"
#ifndef SELFREG_E_CLASS
#define SELFREG_E_CLASS ((HRESULT)0x80040201L)
#endif

const CLSID CLSID_RoverAIBand = { 0xb5a7e6c0, 0x25a1, 0x4c2e, { 0x9a, 0x51, 0x58, 0xe1, 0xd2, 0xc0, 0xa1, 0x25 } };
const CLSID CLSID_RoverAISearchBand = { 0xb5a7e6c1, 0x25a1, 0x4c2e, { 0x9a, 0x51, 0x58, 0xe1, 0xd2, 0xc0, 0xa1, 0x25 } };
static const GUID button_guid = { 0xb5a7e6c2, 0x25a1, 0x4c2e, { 0x9a, 0x51, 0x58, 0xe1, 0xd2, 0xc0, 0xa1, 0x25 } };
const CLSID CLSID_RoverAIFileSearchBand = { 0xb5a7e6c3, 0x25a1, 0x4c2e, { 0x9a, 0x51, 0x58, 0xe1, 0xd2, 0xc0, 0xa1, 0x25 } };
const CLSID CLSID_XpSearchBand = { 0x30d02401, 0x6a81, 0x11d0, { 0x82, 0x74, 0x00, 0xc0, 0x4f, 0xd5, 0xae, 0x38 } };
const CLSID CLSID_XpFileSearchBand = { 0xc4ee31f3, 0x4768, 0x11d2, { 0xbe, 0x5c, 0x00, 0xa0, 0xc9, 0xa8, 0x3d, 0xa1 } };
static const GUID catid_info_band = { 0x00021493, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static const GUID sid_top_level_browser = { 0x4c96be40, 0x915c, 0x11cf, { 0x99, 0xd3, 0x00, 0xaa, 0x00, 0x4a, 0xe8, 0x37 } };
static const IID iid_input_object_site = { 0xf1db8392, 0x7331, 0x11d0, { 0x8c, 0x99, 0x00, 0xa0, 0xc9, 0x2d, 0xbf, 0xe8 } };
static const IID iid_input_object = { 0x68284faa, 0x6a48, 0x11d0, { 0x8c, 0x78, 0x00, 0xc0, 0x4f, 0xd9, 0x18, 0xb4 } };
static const IID iid_desk_band = { 0xeb0fe172, 0x1a3a, 0x11d0, { 0x89, 0xb3, 0x00, 0xa0, 0xc9, 0x0a, 0x90, 0xac } };
static const IID iid_docking_window = { 0x012dd920, 0x7b26, 0x11d0, { 0x8c, 0xa9, 0x00, 0xa0, 0xc9, 0x2d, 0xbf, 0xe8 } };
static const IID iid_folder_view = { 0xcde725b0, 0xccc9, 0x4519, { 0x91, 0x7e, 0x32, 0x5d, 0x72, 0xfa, 0xb4, 0xce } };
static const IID iid_persist_folder2 = { 0x1ac3d9f0, 0x175c, 0x11d1, { 0x95, 0xbe, 0x00, 0x60, 0x97, 0x97, 0xea, 0x4f } };
static const IID iid_shell_browser = { 0x000214e2, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static const IID iid_service_provider = { 0x6d5140c1, 0x7436, 0x11ce, { 0x80, 0x34, 0x00, 0xaa, 0x00, 0x60, 0x09, 0xfa } };
static const IID iid_object_with_site = { 0xfc4801a3, 0x2ba9, 0x11cf, { 0xa2, 0x29, 0x00, 0xaa, 0x00, 0x3d, 0x73, 0x52 } };
static const IID iid_ole_window = { 0x00000114, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static const IID iid_persist = { 0x0000010c, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static const IID iid_persist_stream = { 0x00000109, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static const IID iid_unknown = { 0x00000000, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static const IID iid_class_factory = { 0x00000001, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };

HINSTANCE band_module;
static volatile LONG objects, locks;

typedef struct {
    const IDeskBandVtbl *band;
    const IObjectWithSiteVtbl *site_vtbl;
    const IPersistStreamVtbl *persist;
    const IInputObjectVtbl *input;
    LONG refs;
    int emulate_search;
    IUnknown *site;
    IInputObjectSite *input_site;
    IShellBrowser *browser;
    HWND parent, host, panel;
} BAND;

#define FROM_SITE(p) ((BAND *)((char *)(p) - offsetof(BAND, site_vtbl)))
#define FROM_PERSIST(p) ((BAND *)((char *)(p) - offsetof(BAND, persist)))
#define FROM_INPUT(p) ((BAND *)((char *)(p) - offsetof(BAND, input)))

static void current_folder(BAND *b)
{
    IShellView *view = NULL;
    IFolderView *fv = NULL;
    IPersistFolder2 *pf = NULL;
    LPITEMIDLIST pidl = NULL;
    WCHAR path[MAX_PATH];
    if (!b->browser || !b->panel) return;
    if (SUCCEEDED(b->browser->lpVtbl->QueryActiveShellView(b->browser, &view)) && view &&
        SUCCEEDED(view->lpVtbl->QueryInterface(view, &iid_folder_view, (void **)&fv)) && fv &&
        SUCCEEDED(fv->lpVtbl->GetFolder(fv, &iid_persist_folder2, (void **)&pf)) && pf &&
        SUCCEEDED(pf->lpVtbl->GetCurFolder(pf, &pidl)) && pidl && SHGetPathFromIDListW(pidl, path) && path[0])
        rover_panel_set_folder(b->panel, path);
    if (pidl) CoTaskMemFree(pidl);
    if (pf) pf->lpVtbl->Release(pf);
    if (fv) fv->lpVtbl->Release(fv);
    if (view) view->lpVtbl->Release(view);
}

static LRESULT CALLBACK host_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    BAND *b = (BAND *)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    switch (msg) {
    case WM_SIZE:
        if (b && b->panel) MoveWindow(b->panel, 0, 0, LOWORD(lp), HIWORD(lp), TRUE);
        return 0;
    case WM_TIMER:
        if (b && IsWindowVisible(hwnd)) current_folder(b);
        return 0;
    case WM_SETFOCUS:
        if (b && b->panel) rover_panel_activate(b->panel);
        return 0;
    case WM_COMMAND:
        if (b && b->input_site && (HIWORD(wp) == EN_SETFOCUS || HIWORD(wp) == BN_SETFOCUS))
            b->input_site->lpVtbl->OnFocusChangeIS(b->input_site, (IUnknown *)&b->input, TRUE);
        break;
    case WM_DESTROY:
        KillTimer(hwnd, 1);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static HRESULT query(BAND *b, REFIID riid, void **out)
{
    *out = NULL;
    if (IsEqualIID(riid, &iid_unknown) || IsEqualIID(riid, &iid_ole_window) || IsEqualIID(riid, &iid_docking_window) ||
        IsEqualIID(riid, &iid_desk_band)) *out = (void *)&b->band;
    else if (IsEqualIID(riid, &iid_object_with_site)) *out = (void *)&b->site_vtbl;
    else if (IsEqualIID(riid, &iid_persist) || IsEqualIID(riid, &iid_persist_stream)) *out = (void *)&b->persist;
    else if (IsEqualIID(riid, &iid_input_object)) *out = (void *)&b->input;
    else return E_NOINTERFACE;
    InterlockedIncrement(&b->refs);
    return S_OK;
}

static ULONG release(BAND *b)
{
    LONG n = InterlockedDecrement(&b->refs);
    if (!n) {
        if (b->host) DestroyWindow(b->host);
        if (b->browser) b->browser->lpVtbl->Release(b->browser);
        if (b->input_site) b->input_site->lpVtbl->Release(b->input_site);
        if (b->site) b->site->lpVtbl->Release(b->site);
        CoTaskMemFree(b);
        InterlockedDecrement(&objects);
    }
    return (ULONG)n;
}

/* IDeskBand */
static HRESULT STDMETHODCALLTYPE db_qi(IDeskBand *t, REFIID r, void **o) { return query((BAND *)t, r, o); }
static ULONG STDMETHODCALLTYPE db_addref(IDeskBand *t) { return (ULONG)InterlockedIncrement(&((BAND *)t)->refs); }
static ULONG STDMETHODCALLTYPE db_release(IDeskBand *t) { return release((BAND *)t); }
static HRESULT STDMETHODCALLTYPE db_window(IDeskBand *t, HWND *out) { *out = ((BAND *)t)->host; return *out ? S_OK : E_FAIL; }
static HRESULT STDMETHODCALLTYPE db_help(IDeskBand *t, BOOL mode) { (void)t; (void)mode; return E_NOTIMPL; }

static HRESULT STDMETHODCALLTYPE db_show(IDeskBand *t, BOOL show)
{
    BAND *b = (BAND *)t;
    if (!b->host) return S_OK;
    ShowWindow(b->host, show ? SW_SHOW : SW_HIDE);
    if (show) current_folder(b);
    rover_panel_show_rover(b->panel, show);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE db_close(IDeskBand *t, DWORD reserved)
{
    BAND *b = (BAND *)t;
    (void)reserved;
    if (b->host) {
        rover_panel_show_rover(b->panel, 0);
        DestroyWindow(b->host);
        b->host = b->panel = NULL;
    }
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE db_border(IDeskBand *t, LPCRECT r, IUnknown *s, BOOL reserved)
{
    (void)t; (void)r; (void)s; (void)reserved;
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE db_info(IDeskBand *t, DWORD id, DWORD mode, DESKBANDINFO *info)
{
    (void)t; (void)id; (void)mode;
    if (!info) return E_INVALIDARG;
    if (info->dwMask & DBIM_MINSIZE) { info->ptMinSize.x = 210; info->ptMinSize.y = 200; }
    if (info->dwMask & DBIM_MAXSIZE) { info->ptMaxSize.x = -1; info->ptMaxSize.y = -1; }
    if (info->dwMask & DBIM_INTEGRAL) { info->ptIntegral.x = 1; info->ptIntegral.y = 1; }
    if (info->dwMask & DBIM_ACTUAL) { info->ptActual.x = 260; info->ptActual.y = 500; }
    if (info->dwMask & DBIM_TITLE) lstrcpynW(info->wszTitle, L"RoverAI Search", 256);
    if (info->dwMask & DBIM_MODEFLAGS) info->dwModeFlags = DBIMF_VARIABLEHEIGHT;
    if (info->dwMask & DBIM_BKCOLOR) info->dwMask &= ~DBIM_BKCOLOR;
    return S_OK;
}

static const IDeskBandVtbl band_vtbl = { db_qi, db_addref, db_release, db_window, db_help, db_show, db_close, db_border, db_info };

/* IObjectWithSite */
static HRESULT STDMETHODCALLTYPE ows_qi(IObjectWithSite *t, REFIID r, void **o) { return query(FROM_SITE(t), r, o); }
static ULONG STDMETHODCALLTYPE ows_addref(IObjectWithSite *t) { return (ULONG)InterlockedIncrement(&FROM_SITE(t)->refs); }
static ULONG STDMETHODCALLTYPE ows_release(IObjectWithSite *t) { return release(FROM_SITE(t)); }

static HRESULT STDMETHODCALLTYPE ows_set(IObjectWithSite *t, IUnknown *site)
{
    BAND *b = FROM_SITE(t);
    IOleWindow *ow = NULL;
    IServiceProvider *sp = NULL;
    if (b->input_site) { b->input_site->lpVtbl->Release(b->input_site); b->input_site = NULL; }
    if (b->browser) { b->browser->lpVtbl->Release(b->browser); b->browser = NULL; }
    if (b->site) { b->site->lpVtbl->Release(b->site); b->site = NULL; }
    if (!site) return S_OK;
    b->site = site;
    site->lpVtbl->AddRef(site);
    if (FAILED(site->lpVtbl->QueryInterface(site, &iid_ole_window, (void **)&ow)) || !ow) return E_FAIL;
    ow->lpVtbl->GetWindow(ow, &b->parent);
    ow->lpVtbl->Release(ow);
    site->lpVtbl->QueryInterface(site, &iid_input_object_site, (void **)&b->input_site);
    if (SUCCEEDED(site->lpVtbl->QueryInterface(site, &iid_service_provider, (void **)&sp)) && sp) {
        sp->lpVtbl->QueryService(sp, &sid_top_level_browser, &iid_shell_browser, (void **)&b->browser);
        sp->lpVtbl->Release(sp);
    }
    if (!b->host) {
        WNDCLASSW wc;
        RECT rc;
        memset(&wc, 0, sizeof(wc));
        wc.lpfnWndProc = host_proc;
        wc.hInstance = band_module;
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.lpszClassName = HOST_CLASS;
        RegisterClassW(&wc);
        GetClientRect(b->parent, &rc);
        b->host = CreateWindowExW(WS_EX_CONTROLPARENT, HOST_CLASS, L"RoverAI", WS_CHILD | WS_CLIPCHILDREN,
                                  0, 0, rc.right, rc.bottom, b->parent, NULL, band_module, NULL);
        if (!b->host) return E_FAIL;
        SetWindowLongPtrW(b->host, GWLP_USERDATA, (LONG_PTR)b);
        b->panel = rover_panel_create(b->host, band_module, 1, 1);
        SetTimer(b->host, 1, 1500, NULL);
    }
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE ows_get(IObjectWithSite *t, REFIID riid, void **out)
{
    BAND *b = FROM_SITE(t);
    *out = NULL;
    return b->site ? b->site->lpVtbl->QueryInterface(b->site, riid, out) : E_FAIL;
}

static const IObjectWithSiteVtbl site_vtbl = { ows_qi, ows_addref, ows_release, ows_set, ows_get };

/* IPersistStream: no state; reports the class Explorer asked for. */
static HRESULT STDMETHODCALLTYPE ps_qi(IPersistStream *t, REFIID r, void **o) { return query(FROM_PERSIST(t), r, o); }
static ULONG STDMETHODCALLTYPE ps_addref(IPersistStream *t) { return (ULONG)InterlockedIncrement(&FROM_PERSIST(t)->refs); }
static ULONG STDMETHODCALLTYPE ps_release(IPersistStream *t) { return release(FROM_PERSIST(t)); }

static HRESULT STDMETHODCALLTYPE ps_class(IPersistStream *t, CLSID *out)
{
    int emulate = FROM_PERSIST(t)->emulate_search;
    *out = emulate == 1 ? CLSID_XpSearchBand : emulate == 2 ? CLSID_XpFileSearchBand : CLSID_RoverAIBand;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE ps_dirty(IPersistStream *t) { (void)t; return S_FALSE; }
static HRESULT STDMETHODCALLTYPE ps_load(IPersistStream *t, IStream *s) { (void)t; (void)s; return S_OK; }
static HRESULT STDMETHODCALLTYPE ps_save(IPersistStream *t, IStream *s, BOOL c) { (void)t; (void)s; (void)c; return S_OK; }
static HRESULT STDMETHODCALLTYPE ps_size(IPersistStream *t, ULARGE_INTEGER *n) { (void)t; n->QuadPart = 0; return S_OK; }

static const IPersistStreamVtbl persist_vtbl = { ps_qi, ps_addref, ps_release, ps_class, ps_dirty, ps_load, ps_save, ps_size };

/* IInputObject: keyboard focus and keys for the search box inside Explorer. */
static HRESULT STDMETHODCALLTYPE io_qi(IInputObject *t, REFIID r, void **o) { return query(FROM_INPUT(t), r, o); }
static ULONG STDMETHODCALLTYPE io_addref(IInputObject *t) { return (ULONG)InterlockedIncrement(&FROM_INPUT(t)->refs); }
static ULONG STDMETHODCALLTYPE io_release(IInputObject *t) { return release(FROM_INPUT(t)); }

static HRESULT STDMETHODCALLTYPE io_activate(IInputObject *t, BOOL activate, MSG *msg)
{
    BAND *b = FROM_INPUT(t);
    (void)msg;
    if (activate && b->panel) {
        current_folder(b);
        rover_panel_activate(b->panel);
    }
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE io_hasfocus(IInputObject *t)
{
    BAND *b = FROM_INPUT(t);
    return b->host && rover_panel_owns(b->host, GetFocus()) ? S_OK : S_FALSE;
}

static HRESULT STDMETHODCALLTYPE io_accel(IInputObject *t, MSG *msg)
{
    BAND *b = FROM_INPUT(t);
    if (!b->host || !rover_panel_owns(b->host, msg->hwnd)) return S_FALSE;
    if (msg->message == WM_KEYDOWN && (msg->wParam == VK_RETURN || msg->wParam == VK_TAB)) {
        if (IsDialogMessageW(b->panel, msg)) return S_OK;
    }
    if (msg->message >= WM_KEYFIRST && msg->message <= WM_KEYLAST) {
        /* Keep Explorer accelerators (Backspace, Delete, F-keys) for the search box. */
        TranslateMessage(msg);
        DispatchMessageW(msg);
        return S_OK;
    }
    return S_FALSE;
}

static const IInputObjectVtbl input_vtbl = { io_qi, io_addref, io_release, io_activate, io_hasfocus, io_accel };

/* Class factory */
typedef struct { const IClassFactoryVtbl *vtbl; int emulate_search; } FACTORY;

static HRESULT STDMETHODCALLTYPE cf_qi(IClassFactory *t, REFIID r, void **o)
{
    if (IsEqualIID(r, &iid_unknown) || IsEqualIID(r, &iid_class_factory)) { *o = t; return S_OK; }
    *o = NULL;
    return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE cf_addref(IClassFactory *t) { (void)t; return 2; }
static ULONG STDMETHODCALLTYPE cf_release(IClassFactory *t) { (void)t; return 1; }

static HRESULT STDMETHODCALLTYPE cf_create(IClassFactory *t, IUnknown *outer, REFIID riid, void **out)
{
    BAND *b;
    HRESULT hr;
    *out = NULL;
    if (outer) return CLASS_E_NOAGGREGATION;
    b = (BAND *)CoTaskMemAlloc(sizeof(BAND));
    if (!b) return E_OUTOFMEMORY;
    memset(b, 0, sizeof(*b));
    b->band = &band_vtbl;
    b->site_vtbl = &site_vtbl;
    b->persist = &persist_vtbl;
    b->input = &input_vtbl;
    b->refs = 1;
    b->emulate_search = ((FACTORY *)t)->emulate_search;
    InterlockedIncrement(&objects);
    hr = query(b, riid, out);
    release(b);
    return hr;
}

static HRESULT STDMETHODCALLTYPE cf_lock(IClassFactory *t, BOOL lock)
{
    (void)t;
    if (lock) InterlockedIncrement(&locks); else InterlockedDecrement(&locks);
    return S_OK;
}

static const IClassFactoryVtbl factory_vtbl = { cf_qi, cf_addref, cf_release, cf_create, cf_lock };
static FACTORY band_factory = { &factory_vtbl, 0 };
static FACTORY search_factory = { &factory_vtbl, 1 };
static FACTORY file_search_factory = { &factory_vtbl, 2 };

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) { band_module = instance; DisableThreadLibraryCalls(instance); }
    return TRUE;
}

STDAPI DllGetClassObject(REFCLSID clsid, REFIID riid, void **out)
{
    FACTORY *f = IsEqualCLSID(clsid, &CLSID_RoverAIBand) ? &band_factory :
                 IsEqualCLSID(clsid, &CLSID_RoverAISearchBand) ? &search_factory :
                 IsEqualCLSID(clsid, &CLSID_RoverAIFileSearchBand) ? &file_search_factory : NULL;
    *out = NULL;
    if (!f) return CLASS_E_CLASSNOTAVAILABLE;
    return cf_qi((IClassFactory *)f, riid, out);
}

STDAPI DllCanUnloadNow(void) { return objects == 0 && locks == 0 ? S_OK : S_FALSE; }

/* ---- registration ---- */

static void guid_text(const GUID *g, WCHAR *out) { StringFromGUID2(g, out, 40); }

static LONG set_value(HKEY root, const WCHAR *key, const WCHAR *name, const WCHAR *value)
{
    HKEY h;
    LONG status = RegCreateKeyExW(root, key, 0, NULL, 0, KEY_WRITE, NULL, &h, NULL);
    if (status != ERROR_SUCCESS) return status;
    status = RegSetValueExW(h, name, 0, REG_SZ, (const BYTE *)value, (DWORD)((lstrlenW(value) + 1) * sizeof(WCHAR)));
    RegCloseKey(h);
    return status;
}

static void delete_tree(HKEY root, const WCHAR *key)
{
    HKEY h;
    WCHAR sub[256];
    DWORD n;
    if (RegOpenKeyExW(root, key, 0, KEY_READ | KEY_WRITE, &h) != ERROR_SUCCESS) return;
    for (;;) {
        WCHAR child[600];
        n = 256;
        if (RegEnumKeyExW(h, 0, sub, &n, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        if (lstrlenW(key) + lstrlenW(sub) + 2 > 600) break;
        lstrcpyW(child, key);
        lstrcatW(child, L"\\");
        lstrcatW(child, sub);
        delete_tree(root, child);
    }
    RegCloseKey(h);
    RegDeleteKeyW(root, key);
}

static LONG register_class(const CLSID *clsid, const WCHAR *name, const WCHAR *dll, int info_band)
{
    WCHAR g[40], key[200];
    LONG status;
    guid_text(clsid, g);
    lstrcpyW(key, L"CLSID\\");
    lstrcatW(key, g);
    status = set_value(HKEY_CLASSES_ROOT, key, NULL, name);
    if (status == ERROR_SUCCESS) {
        lstrcatW(key, L"\\InprocServer32");
        status = set_value(HKEY_CLASSES_ROOT, key, NULL, dll);
        if (status == ERROR_SUCCESS) status = set_value(HKEY_CLASSES_ROOT, key, L"ThreadingModel", L"Apartment");
    }
    if (status == ERROR_SUCCESS && info_band) {
        WCHAR cat[40];
        guid_text(&catid_info_band, cat);
        lstrcpyW(key, L"CLSID\\");
        lstrcatW(key, g);
        lstrcatW(key, L"\\Implemented Categories\\");
        lstrcatW(key, cat);
        status = set_value(HKEY_CLASSES_ROOT, key, NULL, L"");
    }
    return status;
}

STDAPI DllRegisterServer(void)
{
    WCHAR dll[MAX_PATH], g[40], cat[40], key[200], icon[MAX_PATH + 8];
    LONG status;
    GetModuleFileNameW(band_module, dll, MAX_PATH);
    status = register_class(&CLSID_RoverAIBand, L"RoverAI Search", dll, 1);
    if (status == ERROR_SUCCESS)
        status = register_class(&CLSID_RoverAISearchBand, L"RoverAI Search (Search Companion replacement)", dll, 0);
    if (status == ERROR_SUCCESS)
        status = register_class(&CLSID_RoverAIFileSearchBand, L"RoverAI Search (file search replacement)", dll, 0);
    if (status != ERROR_SUCCESS) return SELFREG_E_CLASS;
    /* Force Explorer to re-enumerate Explorer bars. */
    guid_text(&catid_info_band, cat);
    lstrcpyW(key, L"Component Categories\\");
    lstrcatW(key, cat);
    lstrcatW(key, L"\\Enum");
    delete_tree(HKEY_CLASSES_ROOT, key);
    /* Toolbar button that toggles the bar in Explorer windows. */
    guid_text(&button_guid, g);
    lstrcpyW(key, L"Software\\Microsoft\\Internet Explorer\\Extensions\\");
    lstrcatW(key, g);
    guid_text(&CLSID_RoverAIBand, cat);
    lstrcpyW(icon, dll);
    lstrcatW(icon, L",201");
    set_value(HKEY_LOCAL_MACHINE, key, L"CLSID", L"{E0DD6CAB-2D10-11D2-8F1A-0000F87ABD16}");
    set_value(HKEY_LOCAL_MACHINE, key, L"BandCLSID", cat);
    set_value(HKEY_LOCAL_MACHINE, key, L"ButtonText", L"RoverAI");
    set_value(HKEY_LOCAL_MACHINE, key, L"MenuText", L"RoverAI Search");
    set_value(HKEY_LOCAL_MACHINE, key, L"MenuStatusBar", L"Search this computer with RoverAI");
    set_value(HKEY_LOCAL_MACHINE, key, L"Icon", icon);
    set_value(HKEY_LOCAL_MACHINE, key, L"HotIcon", icon);
    set_value(HKEY_LOCAL_MACHINE, key, L"Default Visible", L"Yes");
    return S_OK;
}

STDAPI DllUnregisterServer(void)
{
    WCHAR g[40], key[200];
    RoverAIReplaceSearch(FALSE);
    guid_text(&button_guid, g);
    lstrcpyW(key, L"Software\\Microsoft\\Internet Explorer\\Extensions\\");
    lstrcatW(key, g);
    delete_tree(HKEY_LOCAL_MACHINE, key);
    guid_text(&CLSID_RoverAIBand, g);
    lstrcpyW(key, L"CLSID\\");
    lstrcatW(key, g);
    delete_tree(HKEY_CLASSES_ROOT, key);
    guid_text(&CLSID_RoverAISearchBand, g);
    lstrcpyW(key, L"CLSID\\");
    lstrcatW(key, g);
    delete_tree(HKEY_CLASSES_ROOT, key);
    guid_text(&CLSID_RoverAIFileSearchBand, g);
    lstrcpyW(key, L"CLSID\\");
    lstrcatW(key, g);
    delete_tree(HKEY_CLASSES_ROOT, key);
    return S_OK;
}

/* Install or remove the TreatAs emulation of one Search Companion host.
   A previous TreatAs value, if any, is saved and restored. */
static HRESULT treat_as(const CLSID *original, const CLSID *ours_clsid, const WCHAR *saved_name, BOOL enable)
{
    WCHAR search[40], ours[40], key[100], current[64];
    HKEY h;
    DWORD type, size = sizeof(current);
    LONG status;
    guid_text(original, search);
    guid_text(ours_clsid, ours);
    lstrcpyW(key, L"CLSID\\");
    lstrcatW(key, search);
    lstrcatW(key, L"\\TreatAs");
    current[0] = 0;
    if (RegOpenKeyExW(HKEY_CLASSES_ROOT, key, 0, KEY_READ, &h) == ERROR_SUCCESS) {
        if (RegQueryValueExW(h, NULL, NULL, &type, (BYTE *)current, &size) != ERROR_SUCCESS || type != REG_SZ) current[0] = 0;
        RegCloseKey(h);
    }
    if (enable) {
        if (current[0] && lstrcmpiW(current, ours))
            set_value(HKEY_LOCAL_MACHINE, L"SOFTWARE\\XP25\\RoverAI", saved_name, current);
        status = set_value(HKEY_CLASSES_ROOT, key, NULL, ours);
        return status == ERROR_SUCCESS ? S_OK : HRESULT_FROM_WIN32((DWORD)status);
    }
    if (!lstrcmpiW(current, ours)) {
        WCHAR previous[64];
        DWORD psize = sizeof(previous);
        HKEY saved;
        previous[0] = 0;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\XP25\\RoverAI", 0, KEY_READ | KEY_WRITE, &saved) == ERROR_SUCCESS) {
            if (RegQueryValueExW(saved, saved_name, NULL, &type, (BYTE *)previous, &psize) != ERROR_SUCCESS) previous[0] = 0;
            RegDeleteValueW(saved, saved_name);
            RegCloseKey(saved);
        }
        if (previous[0]) set_value(HKEY_CLASSES_ROOT, key, NULL, previous);
        else RegDeleteKeyW(HKEY_CLASSES_ROOT, key);
    }
    return S_OK;
}

/* Replace (or restore) both Search Companion hosts. Takes effect for
   Explorer windows created after the change in new Explorer processes, and
   everywhere after the next logon. */
STDAPI RoverAIReplaceSearch(BOOL enable)
{
    HRESULT a = treat_as(&CLSID_XpSearchBand, &CLSID_RoverAISearchBand, L"PreviousSearchBandTreatAs", enable);
    HRESULT b = treat_as(&CLSID_XpFileSearchBand, &CLSID_RoverAIFileSearchBand, L"PreviousFileSearchBandTreatAs", enable);
    if (SUCCEEDED(a) && SUCCEEDED(b))
        set_value(HKEY_LOCAL_MACHINE, L"SOFTWARE\\XP25\\RoverAI", L"SearchCompanionReplaced", enable ? L"1" : L"0");
    return FAILED(a) ? a : b;
}
