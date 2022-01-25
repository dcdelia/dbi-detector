.intel_syntax noprefix
.text
.code32
.globl __block_32

__block_32:
    mov eax, [esp+0x4]
    call 0x33:__block_64
    ret

.code64
__block_64:
    mov [rax], cs
    retf
