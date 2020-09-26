// test.s
.globl _start

.text
_start:
    sub sp, sp, 256
    str lr,  [sp, #8]
    str x1,  [sp, #16]
    str x2,  [sp, #24]
    str x3,  [sp, #32]
    str x4,  [sp, #40]
    str x5,  [sp, #48]
    str x6,  [sp, #56]
    str x8,  [sp, #64]
    str x29, [sp, #72]
    bl _trick

_code:
    str lr, [sp, #80]
    mov x6, lr

_dlopen:
    mov x0, x6
    add x0, x0, #24
    mov x1, #1
    mov x29, sp
    sub x29, x29, 0x1000
    ldr x8, [x6, #0]
    blr x8
    cmp x0, 0
    beq _restore
    bl _dlsym

_symbol:
    .ascii "entry_point\0"

_dlsym:
    mov x1, lr
    ldr x6, [sp, #80]
    ldr x8, [x6, #8]
    blr x8

_next:
    cmp x0, 0
    beq _restore
    blr x0

_restore:
    ldr lr,  [sp, #8]
    ldr x1,  [sp, #16]
    ldr x2,  [sp, #24]
    ldr x3,  [sp, #32]
    ldr x4,  [sp, #40]
    ldr x5,  [sp, #48]
    ldr x6,  [sp, #56]
    ldr x8,  [sp, #64]
    ldr x29, [sp, #72]
    add sp, sp, 256

_ret:
    ret

_trick:
    bl _code
