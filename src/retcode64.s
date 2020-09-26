BITS 64

global _start

_start:
    jmp short _portal

_nanosleep:
    push rax
    push rsi
    push rdi
    push 0x13;
    push 0x23;
    mov rdi, rsp
    mov rax, 35
    xor rsi, rsi
    syscall
    pop rax
    pop rax
    pop rdi
    pop rsi
    pop rax
    jmp _next

_portal:
    jmp short _trick

_code:
    push rax ; ret
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    mov rax, [rsp + 56] ; stackbase pointer
    mov rax, [rax]      ; stackbase
    xor rcx, rcx
    mov rbx, [rax]      ; code ret (save)
    mov [rax], rcx      ; unreal ret to NULL
    test rbx, rbx
    je _nanosleep

_next:
    mov rsi, rsp        
    add rsi, 56         ; stack_current
    mov rcx, [rax + 8]  ; count (2 * unsigned long)
    add rax, 16;
    jmp _loop

_catch:
    mov [rsi], rdx
    test rbx, rbx
    je _end

_loop:
    dec rcx
    mov rdi, [rax] ; stack_addr
    add rax, 8
    mov rdx, [rax] ; ret_addr
    add rax, 8
    test rbx, rbx
    je _loop2
    mov [rdi], rdx ; restore ret in stack

_loop2:
    xor rdi, rsi   ; stack_current == stack_addr
    jz _catch
    test rcx, rcx
    jne _loop

_end:
    mov [rsi-8], rbx
    test rbx, rbx
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    jne _ret
    add rsp, 8
    
_ret:
    ret
    
_trick:
    call _code
