#pragma once

#include <stddef.h>

/* A raw blob has neither Cobalt's argument parser nor a COFF import table.
   These definitions preserve the source-level BOF interface while storing
   every resolved API pointer in a section retained by pic_link.ld. */
typedef struct { char *original; char *buffer; int length; int size; } datap;
#define CALLBACK_OUTPUT 0
#define CALLBACK_ERROR 13

#define PIC_DATA __attribute__((section(".picdata")))
#define BOF_IMPORT(dll, ret, call, name, args) \
    ret (call *dll##$##name) args PIC_DATA

static void BeaconDataParse(datap *p, char *buffer, int length) {
    /* Cobalt-style buffers begin with the total payload length. */
    p->original=buffer; p->buffer=buffer+4; p->length=*(int *)buffer;
    p->size=length;
}
static char *BeaconDataExtract(datap *p, int *length) {
    /* Strings are length-prefixed and include their trailing NUL. */
    int n;
    if (!p || p->length < 4) return NULL;
    n=*(int *)p->buffer; p->buffer+=4; p->length-=4;
    if (n < 0 || n > p->length) return NULL;
    if (length) *length=n;
    { char *result=p->buffer; p->buffer+=n; p->length-=n; return result; }
}
static int BeaconDataInt(datap *p) {
    /* Integers use the native little-endian representation emitted by CNA. */
    int value;
    if (!p || p->length < 4) return 0;
    value=*(int *)p->buffer; p->buffer+=4; p->length-=4; return value;
}

static void pic_printf(int,const char *,...);
#define BeaconPrintf pic_printf

/* Defined after the generated API slots in krbrelay.c. Resolution must happen
   before a single Windows API slot or PIC_DATA COM vtable is dereferenced. */
static int krbrelay_pic_resolve(void);
static void krbrelay_pic_prepare_interfaces(void);
