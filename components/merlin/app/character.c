/* MerlinAI.exe: Merlin, the Microsoft Agent 2.0 character XP installs as
   %windir%\msagent\chars\merlin.acs, played by the guest's own agentsvr.exe.
   No character data is copied into MerlinAI. The interface layouts follow the
   type library embedded in agentsvr.exe (IAgentEx 48D12BA0...,
   IAgentCharacterEx 98BBE491...), the same layout the XP25 AI runtime uses;
   this is an independent copy so MerlinAI does not load xp25agent.dll.

   Presentation only: every failure is ignored and nothing in the update
   process depends on the character. */
#include <windows.h>
#include <ole2.h>
#include "app.h"

typedef struct IAgentCharacterEx IAgentCharacterEx;
typedef struct IAgentEx IAgentEx;

typedef struct {
    HRESULT(STDMETHODCALLTYPE *QueryInterface)(IAgentEx *, REFIID, void **);
    ULONG(STDMETHODCALLTYPE *AddRef)(IAgentEx *);
    ULONG(STDMETHODCALLTYPE *Release)(IAgentEx *);
    void *GetTypeInfoCount, *GetTypeInfo, *GetIDsOfNames, *Invoke;
    HRESULT(STDMETHODCALLTYPE *Load)(IAgentEx *, VARIANT key, long *char_id, long *req_id);
    HRESULT(STDMETHODCALLTYPE *Unload)(IAgentEx *, long char_id);
    void *Register, *Unregister, *GetCharacter, *GetSuspended;
    HRESULT(STDMETHODCALLTYPE *GetCharacterEx)(IAgentEx *, long char_id, IAgentCharacterEx **character);
    void *GetVersion, *ShowDefaultCharacterProperties;
} IAgentExVtbl;
struct IAgentEx {
    const IAgentExVtbl *lpVtbl;
};

typedef struct {
    HRESULT(STDMETHODCALLTYPE *QueryInterface)(IAgentCharacterEx *, REFIID, void **);
    ULONG(STDMETHODCALLTYPE *AddRef)(IAgentCharacterEx *);
    ULONG(STDMETHODCALLTYPE *Release)(IAgentCharacterEx *);
    void *GetTypeInfoCount, *GetTypeInfo, *GetIDsOfNames, *Invoke;              /* 3-6 */
    HRESULT(STDMETHODCALLTYPE *GetVisible)(IAgentCharacterEx *, long *);         /* 7 */
    HRESULT(STDMETHODCALLTYPE *SetPosition)(IAgentCharacterEx *, long, long);
    HRESULT(STDMETHODCALLTYPE *GetPosition)(IAgentCharacterEx *, long *, long *);
    HRESULT(STDMETHODCALLTYPE *SetSize)(IAgentCharacterEx *, long, long);
    HRESULT(STDMETHODCALLTYPE *GetSize)(IAgentCharacterEx *, long *, long *);
    void *GetName, *GetDescription, *GetTTSSpeed, *GetTTSPitch;                  /* 12-15 */
    HRESULT(STDMETHODCALLTYPE *Activate)(IAgentCharacterEx *, short);            /* 16 */
    HRESULT(STDMETHODCALLTYPE *SetIdleOn)(IAgentCharacterEx *, long);
    void *GetIdleOn, *Prepare;                                                   /* 18-19 */
    HRESULT(STDMETHODCALLTYPE *Play)(IAgentCharacterEx *, BSTR, long *);         /* 20 */
    HRESULT(STDMETHODCALLTYPE *Stop)(IAgentCharacterEx *, long);
    HRESULT(STDMETHODCALLTYPE *StopAll)(IAgentCharacterEx *, long);
    void *Wait, *Interrupt;                                                      /* 23-24 */
    HRESULT(STDMETHODCALLTYPE *Show)(IAgentCharacterEx *, long, long *);         /* 25 */
    HRESULT(STDMETHODCALLTYPE *Hide)(IAgentCharacterEx *, long, long *);
    HRESULT(STDMETHODCALLTYPE *Speak)(IAgentCharacterEx *, BSTR, BSTR, long *);
    HRESULT(STDMETHODCALLTYPE *MoveTo)(IAgentCharacterEx *, short, short, long, long *);
    void *GestureAt, *GetMoveCause, *GetVisibilityCause, *HasOtherClients;       /* 29-32 */
    HRESULT(STDMETHODCALLTYPE *SetSoundEffectsOn)(IAgentCharacterEx *, long);    /* 33 */
    void *GetSoundEffectsOn, *SetName, *SetDescription, *GetExtraData;           /* 34-37 */
    void *ShowPopupMenu;                                                         /* 38 */
    HRESULT(STDMETHODCALLTYPE *SetAutoPopupMenu)(IAgentCharacterEx *, long);     /* 39 */
    void *rest[21];
} IAgentCharacterExVtbl;
struct IAgentCharacterEx {
    const IAgentCharacterExVtbl *lpVtbl;
};

static const CLSID CLSID_AgentServer = { 0xD45FD2FC, 0x5C6E, 0x11D1, { 0x9E, 0xC1, 0x00, 0xC0, 0x4F, 0xD7, 0x08, 0x1F } };
static const IID IID_IAgentEx = { 0x48D12BA0, 0x5B77, 0x11D1, { 0x9E, 0xC1, 0x00, 0xC0, 0x4F, 0xD7, 0x08, 0x1F } };

static IAgentEx *server;
static IAgentCharacterEx *merlin;
static long merlin_id;

void merlin_character_start(HWND near_window)
{
    WCHAR path[MAX_PATH];
    VARIANT key;
    long request = 0;
    RECT r;
    if (merlin || !GetWindowsDirectoryW(path, MAX_PATH - 32)) return;
    lstrcatW(path, L"\\msagent\\chars\\merlin.acs");
    if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) return;
    if (FAILED(CoCreateInstance(&CLSID_AgentServer, NULL, CLSCTX_SERVER, &IID_IAgentEx, (void **)&server))) {
        server = NULL;
        return;
    }
    VariantInit(&key);
    key.vt = VT_BSTR;
    key.bstrVal = SysAllocString(path);
    if (FAILED(server->lpVtbl->Load(server, key, &merlin_id, &request)) ||
        FAILED(server->lpVtbl->GetCharacterEx(server, merlin_id, &merlin)) || !merlin) {
        VariantClear(&key);
        server->lpVtbl->Release(server);
        server = NULL;
        merlin = NULL;
        return;
    }
    VariantClear(&key);
    merlin->lpVtbl->SetIdleOn(merlin, TRUE);
    merlin->lpVtbl->SetSoundEffectsOn(merlin, FALSE);
    merlin->lpVtbl->SetAutoPopupMenu(merlin, FALSE);
    if (GetWindowRect(near_window, &r)) merlin->lpVtbl->SetPosition(merlin, r.right + 8 < GetSystemMetrics(SM_CXSCREEN) - 128 ? r.right + 8 : r.left + 560, r.top + 40);
    merlin->lpVtbl->Show(merlin, FALSE, &request);
    merlin_character_state("idle", "Hello! I'm MerlinAI. I keep watch over this computer's problems.");
}

static void play(const WCHAR *animation)
{
    BSTR name;
    long request = 0;
    merlin->lpVtbl->StopAll(merlin, 0x1L /* STOP_TYPE_PLAY */);
    name = SysAllocString(animation);
    merlin->lpVtbl->Play(merlin, name, &request);
    SysFreeString(name);
}

void merlin_character_state(const char *state, const char *speech)
{
    static const struct {
        const char *state;
        const WCHAR *animation;
    } map[] = {
        { "idle", L"Greet" },         { "investigating", L"Searching" }, { "building", L"Processing" },
        { "testing", L"Reading" },    { "complete", L"Congratulate" },  { "failed", L"Sad" },
        { "no_change", L"Explain" },
    };
    unsigned i;
    if (!merlin) return;
    for (i = 0; i < sizeof(map) / sizeof(map[0]); ++i)
        if (!lstrcmpA(map[i].state, state)) {
            play(map[i].animation);
            break;
        }
    if (speech && speech[0]) {
        WCHAR w[300];
        BSTR text;
        long request = 0;
        MerlinUtf8ToWide(speech, w, 300);
        text = SysAllocString(w);
        merlin->lpVtbl->Speak(merlin, text, NULL, &request);
        SysFreeString(text);
    }
}

void merlin_character_stop(void)
{
    long request = 0;
    if (merlin) {
        merlin->lpVtbl->Hide(merlin, TRUE, &request);
        merlin->lpVtbl->Release(merlin);
        merlin = NULL;
    }
    if (server) {
        server->lpVtbl->Unload(server, merlin_id);
        server->lpVtbl->Release(server);
        server = NULL;
    }
}
