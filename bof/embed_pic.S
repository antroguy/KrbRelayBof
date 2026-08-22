    # These accessors return the embedded raw relay core and its byte length to
    # the C launcher without relying on linker-generated symbols.
    .text
    .globl embedded_pic_core
embedded_pic_core:
    leaq pic_core_blob(%rip), %rax
    ret
    .globl embedded_pic_core_size
embedded_pic_core_size:
    movl $(pic_core_blob_end-pic_core_blob), %eax
    ret

    # The target receives these bytes as part of the BOF object. incbin occurs
    # during the local build and is not a target-side loader action.
    .section .rdata,"dr"
pic_core_blob:
    .incbin "bof/krbrelay-pic-core.x64.bin"
pic_core_blob_end:
