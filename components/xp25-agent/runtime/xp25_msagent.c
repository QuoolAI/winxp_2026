/* XP25 AI runtime: Microsoft Agent 2.0 characters (agentsvr.exe), the same
   engine XP's Search Companion uses to animate Rover. Interface layouts were
   taken from the type library embedded in the guest's own agentsvr.exe
   (IAgentEx 48D12BA0..., IAgentCharacterEx 98BBE491...). The caller's thread
   must be a COM apartment with a message loop. */
#include <windows.h>
#include <ole2.h>
#include <string.h>
#include "xp25_msagent.h"

typedef struct IAgentCharacterEx IAgentCharacterEx;
typedef struct IAgentEx IAgentEx;

typedef struct {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IAgentEx *, REFIID, void **);
    ULONG (STDMETHODCALLTYPE *AddRef)(IAgentEx *);
    ULONG (STDMETHODCALLTYPE *Release)(IAgentEx *);
    void *GetTypeInfoCount, *GetTypeInfo, *GetIDsOfNames, *Invoke;
    HRESULT (STDMETHODCALLTYPE *Load)(IAgentEx *, VARIANT key, long *char_id, long *req_id);
    HRESULT (STDMETHODCALLTYPE *Unload)(IAgentEx *, long char_id);
    void *Register, *Unregister, *GetCharacter, *GetSuspended;
    HRESULT (STDMETHODCALLTYPE *GetCharacterEx)(IAgentEx *, long char_id, IAgentCharacterEx **character);
    void *GetVersion, *ShowDefaultCharacterProperties;
} IAgentExVtbl;
struct IAgentEx { const IAgentExVtbl *lpVtbl; };

typedef struct {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IAgentCharacterEx *, REFIID, void **);
    ULONG (STDMETHODCALLTYPE *AddRef)(IAgentCharacterEx *);
    ULONG (STDMETHODCALLTYPE *Release)(IAgentCharacterEx *);
    void *GetTypeInfoCount, *GetTypeInfo, *GetIDsOfNames, *Invoke;          /* 0-6 */
    HRESULT (STDMETHODCALLTYPE *GetVisible)(IAgentCharacterEx *, long *);    /* 7 */
    HRESULT (STDMETHODCALLTYPE *SetPosition)(IAgentCharacterEx *, long, long);
    HRESULT (STDMETHODCALLTYPE *GetPosition)(IAgentCharacterEx *, long *, long *);
    HRESULT (STDMETHODCALLTYPE *SetSize)(IAgentCharacterEx *, long, long);
    HRESULT (STDMETHODCALLTYPE *GetSize)(IAgentCharacterEx *, long *, long *);
    void *GetName, *GetDescription, *GetTTSSpeed, *GetTTSPitch;              /* 12-15 */
    HRESULT (STDMETHODCALLTYPE *Activate)(IAgentCharacterEx *, short);       /* 16 */
    HRESULT (STDMETHODCALLTYPE *SetIdleOn)(IAgentCharacterEx *, long);
    void *GetIdleOn, *Prepare;                                               /* 18-19 */
    HRESULT (STDMETHODCALLTYPE *Play)(IAgentCharacterEx *, BSTR, long *);    /* 20 */
    HRESULT (STDMETHODCALLTYPE *Stop)(IAgentCharacterEx *, long);
    HRESULT (STDMETHODCALLTYPE *StopAll)(IAgentCharacterEx *, long);
    void *Wait, *Interrupt;                                                  /* 23-24 */
    HRESULT (STDMETHODCALLTYPE *Show)(IAgentCharacterEx *, long, long *);    /* 25 */
    HRESULT (STDMETHODCALLTYPE *Hide)(IAgentCharacterEx *, long, long *);
    HRESULT (STDMETHODCALLTYPE *Speak)(IAgentCharacterEx *, BSTR, BSTR, long *);
    HRESULT (STDMETHODCALLTYPE *MoveTo)(IAgentCharacterEx *, short, short, long, long *);
    void *GestureAt, *GetMoveCause, *GetVisibilityCause, *HasOtherClients;   /* 29-32 */
    HRESULT (STDMETHODCALLTYPE *SetSoundEffectsOn)(IAgentCharacterEx *, long); /* 33 */
    void *GetSoundEffectsOn, *SetName, *SetDescription, *GetExtraData;       /* 34-37 */
    void *ShowPopupMenu;                                                     /* 38 */
    HRESULT (STDMETHODCALLTYPE *SetAutoPopupMenu)(IAgentCharacterEx *, long); /* 39 */
    void *rest[21];                                                          /* 40-60 */
} IAgentCharacterExVtbl;
struct IAgentCharacterEx { const IAgentCharacterExVtbl *lpVtbl; };

static const CLSID CLSID_AgentServer = { 0xD45FD2FC, 0x5C6E, 0x11D1, { 0x9E, 0xC1, 0x00, 0xC0, 0x4F, 0xD7, 0x08, 0x1F } };
static const IID IID_IAgentEx = { 0x48D12BA0, 0x5B77, 0x11D1, { 0x9E, 0xC1, 0x00, 0xC0, 0x4F, 0xD7, 0x08, 0x1F } };

struct XP25_AGENTCHAR {
    IAgentEx *server;
    IAgentCharacterEx *character;
    long id;
    int visible;
};

XP25_AGENTCHAR *xp25w_agentchar_load(const WCHAR *acs_path, char *error, size_t size)
{
    XP25_AGENTCHAR *a;
    VARIANT key;
    long request = 0;
    HRESULT hr;
    if (GetFileAttributesW(acs_path) == INVALID_FILE_ATTRIBUTES) {
        if (error) lstrcpynA(error, "character file not found", (int)size);
        return NULL;
    }
    a = (XP25_AGENTCHAR *)xp25_alloc(sizeof(*a));
    if (!a) return NULL;
    hr = CoCreateInstance(&CLSID_AgentServer, NULL, CLSCTX_SERVER, &IID_IAgentEx, (void **)&a->server);
    if (FAILED(hr)) {
        if (error) lstrcpynA(error, "Microsoft Agent server unavailable", (int)size);
        xp25_free(a);
        return NULL;
    }
    VariantInit(&key);
    key.vt = VT_BSTR;
    key.bstrVal = SysAllocString(acs_path);
    hr = a->server->lpVtbl->Load(a->server, key, &a->id, &request);
    VariantClear(&key);
    if (SUCCEEDED(hr)) hr = a->server->lpVtbl->GetCharacterEx(a->server, a->id, &a->character);
    if (FAILED(hr) || !a->character) {
        if (error) lstrcpynA(error, "the character could not be loaded", (int)size);
        a->server->lpVtbl->Release(a->server);
        xp25_free(a);
        return NULL;
    }
    a->character->lpVtbl->SetIdleOn(a->character, TRUE);
    a->character->lpVtbl->SetSoundEffectsOn(a->character, FALSE);
    a->character->lpVtbl->SetAutoPopupMenu(a->character, FALSE);
    return a;
}

void xp25w_agentchar_size(XP25_AGENTCHAR *a, long *width, long *height)
{
    *width = *height = 0;
    if (a) a->character->lpVtbl->GetSize(a->character, width, height);
}

void xp25w_agentchar_move(XP25_AGENTCHAR *a, int x, int y)
{
    if (a) a->character->lpVtbl->SetPosition(a->character, x, y);
}

void xp25w_agentchar_show(XP25_AGENTCHAR *a, int visible)
{
    long request = 0;
    if (!a || a->visible == visible) return;
    if (visible) a->character->lpVtbl->Show(a->character, FALSE, &request);
    else a->character->lpVtbl->Hide(a->character, TRUE, &request);
    a->visible = visible;
}

int xp25w_agentchar_play(XP25_AGENTCHAR *a, const WCHAR *animation)
{
    BSTR name;
    long request = 0;
    HRESULT hr;
    if (!a) return 0;
    a->character->lpVtbl->StopAll(a->character, 0x1L /* STOP_TYPE_PLAY */);
    name = SysAllocString(animation);
    hr = a->character->lpVtbl->Play(a->character, name, &request);
    SysFreeString(name);
    return SUCCEEDED(hr);
}

void xp25w_agentchar_free(XP25_AGENTCHAR *a)
{
    if (!a) return;
    xp25w_agentchar_show(a, 0);
    a->character->lpVtbl->Release(a->character);
    a->server->lpVtbl->Unload(a->server, a->id);
    a->server->lpVtbl->Release(a->server);
    xp25_free(a);
}
