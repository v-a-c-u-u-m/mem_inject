BITS 64

global _start

_start:
    push rax
    push rbx
    push rcx
    push rdx
    push rdi
    push rsi
    push rbp
    jmp short _trick

_code:
    xor rax, rax
    xor rdi, rdi
    xor rdx, rdx
    pop rbx;

_dlopen:
    mov rdi, rbx
    add rdi, 24                    ; rdi = *(msg)
    xor rsi, rsi
    inc rsi
    mov rbp, rsp
    sub rbp, 0x1000
    mov rcx, [rbx]
    call rcx
    test rax, rax
    je _restore

_next:
    call _dlsym

_symbol:
    db "entry_point", 0x0

_dlsym:
    pop rsi
    mov rdi, rax
    mov rcx, rbx
    add rcx, 8
    mov rcx, [rcx]
    call rcx
    test rax, rax
    je _restore
    call rax

_restore:
    pop rbp
    pop rsi
    pop rdi
    pop rdx
    pop rcx
    pop rbx
    pop rax

_ret:
    ret

_trick:
    call _code

