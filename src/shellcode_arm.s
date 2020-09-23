// test.s
.globl _start

.text
_start:
    str x1, [sp, #-16]
    str x2, [sp, #-24]
    str x3, [sp, #-32]
    str x4, [sp, #-40]
    str x8, [sp, #-48]
    mov x4, lr
    bl _trick

_msg:
    .ascii "\n\nATTENTION PLEASE! You have been hacked!\n\n\n"
    .equ _len, .-_msg

_code:
    mov x0, #1         // unsigned int fd
    mov x1, x3         // const char *string
    mov x2, _len       // size_t count
    movz x8, #0x40     // [0x40] write
    svc #0
    mov lr, x4

_restore:
    ldr x1, [sp, #-16]
    ldr x2, [sp, #-24]
    ldr x3, [sp, #-32]
    ldr x4, [sp, #-40]
    ldr x8, [sp, #-48]
    ret

_trick:
    mov x3, lr
    bl _code

