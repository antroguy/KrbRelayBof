SECTIONS
{
  /* Make the blob start with its thread entry, then co-locate every function,
     literal, API slot, vtable, and zero-initialized object. This allows the
     launcher to copy only .text and still retain the complete runtime. */
  .text 0 : SUBALIGN(1) {
    KEEP(*(.text.entry))
    *(.text*) *(.rdata*) *(.data*) *(.picdata*) *(.bss*) *(COMMON)
  }
  /* These PE/CRT metadata sections are invalid or unnecessary in a raw blob;
     retaining them would either increase size or imply loader support. */
  /DISCARD/ : { *(.pdata*) *(.xdata*) *(.eh_frame*) *(.comment*) *(.rdata$zzz*) *(.idata*) *(.edata*) *(.reloc*) }
}
