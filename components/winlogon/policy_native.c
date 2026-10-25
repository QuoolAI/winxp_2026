#include "platform.h"
#include <objbase.h>
#include <oleauto.h>
static BOOL key_protection_initialized;

BOOL wl_policy_initialize(void)
{
    LONG (NTAPI *lock_keys)(PULONG,PULONG);LONG status;ULONG a=0,b=0;
    /* @8 ABI, two output pointers and successful original calls are retained
       in the policy-control trace. This calls the supplied real kernel code;
       neither output is interpreted as an activation/entitlement decision. */
    if(key_protection_initialized)return TRUE;
    lock_keys=(LONG(NTAPI*)(PULONG,PULONG))GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtLockProductActivationKeys");
    if(!lock_keys){SetLastError(ERROR_PROC_NOT_FOUND);return FALSE;}
    status=lock_keys(&a,&b);wl_log("product_key_protection_ntstatus",(DWORD)status);
    if(status<0){SetLastError(LsaNtStatusToWinError(status));return FALSE;}
    key_protection_initialized=TRUE;
    wl_log("product_key_protection_output_a",a);wl_log("product_key_protection_output_b",b);return TRUE;
}

/* The supplied licensing agent decides activation state. CLSID and IID come
   from licdll.dll's REGISTRY and TYPELIB resources. The call sequence, IID and
   Initialize(BPC, mode 1, NULL) arguments are those of SP3 syssetup.dll's
   Activationrequired check, which also requires a zero Initialize status.
   Slot offsets are re-verified against the installed DLL's type library. */
static const CLSID license_class={0xacadf079,0xcbcd,0x4032,{0x83,0xf2,0xfa,0x47,0xc4,0xdb,0x09,0x6f}};
static const IID license_agent={0xb8cbad79,0x3f1f,0x481a,{0xbb,0x0c,0xe7,0xbb,0xd7,0x7b,0xdd,0xd1}};
#define WL_LICENSE_BPC 0xc475u
#define WL_LICENSE_MODE 1u
typedef struct WL_LICENSE_AGENT {const struct WL_LICENSE_VTBL *vtbl;} WL_LICENSE_AGENT;
typedef struct WL_LICENSE_VTBL {
    HRESULT (STDMETHODCALLTYPE *query)(WL_LICENSE_AGENT*,REFIID,void**);
    ULONG (STDMETHODCALLTYPE *add_ref)(WL_LICENSE_AGENT*);
    ULONG (STDMETHODCALLTYPE *release)(WL_LICENSE_AGENT*);
    void *dispatch[4];
    HRESULT (STDMETHODCALLTYPE *initialize)(WL_LICENSE_AGENT*,DWORD,DWORD,BSTR,DWORD*);
    void *agent[40];
    HRESULT (STDMETHODCALLTYPE *expiration)(WL_LICENSE_AGENT*,DWORD*,DWORD*);
} WL_LICENSE_VTBL;
typedef char WL_LICENSE_INITIALIZE_SLOT[(FIELD_OFFSET(WL_LICENSE_VTBL,initialize)==28)?1:-1];
typedef char WL_LICENSE_EXPIRATION_SLOT[(FIELD_OFFSET(WL_LICENSE_VTBL,expiration)==192)?1:-1];
typedef HRESULT (WINAPI *CO_INITIALIZE)(LPVOID,DWORD);
typedef void (WINAPI *CO_UNINITIALIZE)(void);
typedef HRESULT (WINAPI *CO_CREATE)(REFCLSID,LPUNKNOWN,DWORD,REFIID,LPVOID*);
typedef HRESULT (WINAPI *LOAD_TYPELIB)(LPCOLESTR,REGKIND,ITypeLib**);

static DWORD hresult_error(HRESULT hr)
{return HRESULT_FACILITY(hr)==FACILITY_WIN32?HRESULT_CODE(hr):(DWORD)hr;}

static DWORD agent_server(LPCWSTR expected)
{
    HKEY key;WCHAR value[MAX_PATH],expanded[MAX_PATH];DWORD type=0,bytes=sizeof(value)-sizeof(WCHAR);LONG error;
    error=RegOpenKeyExW(HKEY_CLASSES_ROOT,L"CLSID\\{ACADF079-CBCD-4032-83F2-FA47C4DB096F}\\InprocServer32",0,KEY_QUERY_VALUE,&key);
    if(error)return (DWORD)error;
    ZeroMemory(value,sizeof(value));error=RegQueryValueExW(key,NULL,NULL,&type,(BYTE*)value,&bytes);RegCloseKey(key);
    if(error)return (DWORD)error;
    if(type==REG_EXPAND_SZ){if(!ExpandEnvironmentStringsW(value,expanded,MAX_PATH))return GetLastError();}
    else if(type==REG_SZ)lstrcpyW(expanded,value);else return ERROR_INVALID_DATA;
    return lstrcmpiW(expanded,expected)?ERROR_ACCESS_DENIED:0;
}

static DWORD vtable_info(ITypeLib *lib,const IID *iid,ITypeInfo **result)
{
    ITypeInfo *info=NULL;TYPEATTR *attr;HREFTYPE href;HRESULT hr;BOOL dual;
    *result=NULL;hr=lib->lpVtbl->GetTypeInfoOfGuid(lib,iid,&info);if(FAILED(hr))return hresult_error(hr);
    hr=info->lpVtbl->GetTypeAttr(info,&attr);if(FAILED(hr)){info->lpVtbl->Release(info);return hresult_error(hr);}
    dual=attr->typekind==TKIND_DISPATCH&&(attr->wTypeFlags&TYPEFLAG_FDUAL);info->lpVtbl->ReleaseTypeAttr(info,attr);
    if(!dual){info->lpVtbl->Release(info);return ERROR_INVALID_DATA;}
    hr=info->lpVtbl->GetRefTypeOfImplType(info,(UINT)-1,&href);
    if(SUCCEEDED(hr))hr=info->lpVtbl->GetRefTypeInfo(info,href,result);
    info->lpVtbl->Release(info);return FAILED(hr)?hresult_error(hr):0;
}

static DWORD verify_slot(ITypeInfo *info,LPOLESTR name,SHORT offset,SHORT params)
{
    MEMBERID id;TYPEATTR *attr;FUNCDESC *f;UINT i;DWORD error=ERROR_INVALID_DATA;HRESULT hr;
    hr=info->lpVtbl->GetIDsOfNames(info,&name,1,&id);if(FAILED(hr))return hresult_error(hr);
    hr=info->lpVtbl->GetTypeAttr(info,&attr);if(FAILED(hr))return hresult_error(hr);
    for(i=0;i<attr->cFuncs;++i){
        if(FAILED(info->lpVtbl->GetFuncDesc(info,i,&f)))break;
        if(f->memid==id){
            if(f->oVft==offset&&f->cParams==params&&f->callconv==CC_STDCALL&&f->invkind==INVOKE_FUNC)error=0;
            info->lpVtbl->ReleaseFuncDesc(info,f);break;
        }
        info->lpVtbl->ReleaseFuncDesc(info,f);
    }
    info->lpVtbl->ReleaseTypeAttr(info,attr);return error;
}

static DWORD verify_agent_abi(LOAD_TYPELIB load,LPCWSTR path)
{
    ITypeLib *lib=NULL;ITypeInfo *base=NULL;HRESULT hr;DWORD error;
    hr=load(path,REGKIND_NONE,&lib);if(FAILED(hr))return hresult_error(hr);
    error=vtable_info(lib,&license_agent,&base);
    if(!error)error=verify_slot(base,L"Initialize",28,4);
    if(!error)error=verify_slot(base,L"GetExpirationInfo",192,2);
    if(base)base->lpVtbl->Release(base);lib->lpVtbl->Release(lib);return error;
}

static void query_license(WL_LICENSE_STATE *s)
{
    HMODULE ole=NULL,automation=NULL;CO_INITIALIZE initialize=NULL;CO_UNINITIALIZE uninitialize=NULL;CO_CREATE create=NULL;LOAD_TYPELIB load=NULL;
    WCHAR path[MAX_PATH];WL_LICENSE_AGENT *agent=NULL;HRESULT hr,com=E_FAIL;DWORD status=0,wpa=0,eval=0;
    if(!GetSystemDirectoryW(path,MAX_PATH)||lstrlenW(path)+12>=MAX_PATH){s->agent_error=ERROR_BUFFER_OVERFLOW;return;}
    lstrcatW(path,L"\\licdll.dll");
    s->agent_error=agent_server(path);if(s->agent_error){wl_log("licensing_agent_server_rejected",s->agent_error);return;}
    ole=LoadLibraryW(L"ole32.dll");automation=LoadLibraryW(L"oleaut32.dll");
    if(!ole||!automation){s->agent_error=GetLastError();goto done;}
    initialize=(CO_INITIALIZE)GetProcAddress(ole,"CoInitializeEx");uninitialize=(CO_UNINITIALIZE)GetProcAddress(ole,"CoUninitialize");
    create=(CO_CREATE)GetProcAddress(ole,"CoCreateInstance");load=(LOAD_TYPELIB)GetProcAddress(automation,"LoadTypeLibEx");
    if(!initialize||!uninitialize||!create||!load){s->agent_error=ERROR_PROC_NOT_FOUND;goto done;}
    com=initialize(NULL,COINIT_APARTMENTTHREADED);
    if(FAILED(com)&&com!=RPC_E_CHANGED_MODE){s->agent_error=hresult_error(com);goto done;}
    s->agent_error=verify_agent_abi(load,path);if(s->agent_error){wl_log("licensing_agent_abi_rejected",s->agent_error);goto done;}
    hr=create(&license_class,NULL,CLSCTX_INPROC_SERVER,&license_agent,(void**)&agent);
    if(FAILED(hr)||!agent){s->agent_error=FAILED(hr)?hresult_error(hr):ERROR_INVALID_DATA;wl_log("licensing_agent_create_failed",s->agent_error);goto done;}
    hr=agent->vtbl->initialize(agent,WL_LICENSE_BPC,WL_LICENSE_MODE,NULL,&status);
    wl_log("licensing_agent_initialize_hresult",(DWORD)hr);wl_log("licensing_agent_initialize_status",status);
    if(FAILED(hr)){s->agent_error=hresult_error(hr);goto done;}
    s->init_status=status;if(status)goto done;
    hr=agent->vtbl->expiration(agent,&wpa,&eval);wl_log("licensing_agent_expiration_hresult",(DWORD)hr);
    if(FAILED(hr)){s->agent_error=hresult_error(hr);goto done;}
    s->wpa_left=wpa;s->eval_left=eval;wl_log("licensing_activation_days_left",wpa);wl_log("licensing_evaluation_days_left",eval);
done:
    if(agent)agent->vtbl->release(agent);
    if(SUCCEEDED(com))uninitialize();
    if(automation)FreeLibrary(automation);if(ole)FreeLibrary(ole);
}

void wl_session_policy(WL_POLICY_RESULT *result)
{
    WL_LICENSE_STATE state;
    ZeroMemory(&state,sizeof(state));state.key_protected=key_protection_initialized;
    query_license(&state);wl_policy_from_license(&state,result);
    wl_log("licensing_policy_verified",result->verified);
    if(result->decision==WlPolicyAllowed)wl_log("licensing_policy_allowed",0);
    else if(result->decision==WlPolicyDenied)wl_log("licensing_activation_required_logon_denied",result->error);
    else wl_log("licensing_policy_unavailable",result->error);
}
