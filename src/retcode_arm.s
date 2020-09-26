// test.s
.globl _start

.text
_start:
    str x1, [sp, #-16]
    str x2, [sp, #-24]
    str x3, [sp, #-32]
    str x4, [sp, #-40]
    str x5, [sp, #-48]
    str x6, [sp, #-56]
    str x7, [sp, #-64]
    str x8, [sp, #-72]
    str x9, [sp, #-80]
    str x10, [sp, #-88]
    mov x10, sp
    sub x10, x10, #8 // stack->ret
    bl _trick

_exit:
    mov x8, #0x5e    // [0x5e] exit
    svc #0

_code:
    //add sp, sp, #0x38
    ldr x4, [lr, #0] // stackbase pointer
    ldr x5, [x4]     // code ret (save)
    eor x3, x3, x3
    str x3, [x4]     // unreal ret to NULL
    //mov x5, sp     // current stack
    ldr x3, [x4, #8] // count
    mov x6, #8
    bl _loop

_catch:
    str x8, [x10]    // restore normal ret
    mov lr, x8
    cmp x5, 0
    bne _fix_addr
    bl _end

_loop:
    sub x3, x3, #1
    add x6, x6, #8

    ldr x7, [x4, x6] // stack->spoofed ret

    add x6, x6, #8
    ldr x8, [x4, x6] // real ret

    cmp x7, x10
    beq _catch

_fix_addr:
    cmp x5, 0
    beq _branch
    str x8, [x7]

_branch:
    cmp x3, #0
    bne _loop

_restore:
    str lr, [sp, #-8]
    mov x0, x5
    ldr x1, [sp, #-16]
    ldr x2, [sp, #-24]
    ldr x3, [sp, #-32]
    ldr x4, [sp, #-40]
    ldr x5, [sp, #-48]
    ldr x6, [sp, #-56]
    ldr x7, [sp, #-64]
    ldr x8, [sp, #-72]
    ldr x9, [sp, #-80]
    ldr x10, [sp, #-88]
    cmp x0, 0
    beq _ret
    br x0

_ret:
    ret

_trick:
    mov x6, lr
    bl _code

