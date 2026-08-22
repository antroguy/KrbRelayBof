/* Minimal Cobalt Strike BOF ABI used by the launcher. The injected PIC core
   replaces these declarations with the self-contained pic_compat.h ABI. */
typedef struct {
    char *original;
    char *buffer;
    int length;
    int size;
} datap;

#define CALLBACK_OUTPUT 0x0
#define CALLBACK_ERROR  0x0d

DECLSPEC_IMPORT void BeaconDataParse(datap *parser, char *buffer, int size);
DECLSPEC_IMPORT char *BeaconDataExtract(datap *parser, int *size);
DECLSPEC_IMPORT int BeaconDataInt(datap *parser);
DECLSPEC_IMPORT void BeaconPrintf(int type, char *fmt, ...);
DECLSPEC_IMPORT BOOL BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, STARTUPINFO *si, PROCESS_INFORMATION *pi);
DECLSPEC_IMPORT void BeaconInjectTemporaryProcess(PROCESS_INFORMATION *pi, char *payload, int payload_len, int payload_offset, char *arg, int arg_len);
DECLSPEC_IMPORT void BeaconCleanupProcess(PROCESS_INFORMATION *pi);
