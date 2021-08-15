BITS 64

global _start

_start:
    jmp short _portal

_code:
    push rax ;[rsp+120]  ; orig_ret
    push rbp ;[rsp+112]
    push r8  ;[rsp+104]
    push r9  ;[rsp+96]
    push r10 ;[rsp+88]
    push r11 ;[rsp+80]
    push r12 ;[rsp+72]
    push r13 ;[rsp+64]
    push r14 ;[rsp+56]
    push r15 ;[rsp+48]
    push rax ;[rsp+40]
    push rbx ;[rsp+32]
    push rcx ;[rsp+24]
    push rdx ;[rsp+16]
    push rsi ;[rsp+8]
    push rdi ;[rsp]
    mov rax, [rsp + 128] ; stackbase pointer
    mov rax, [rax]       ; stackbase
    xor rcx, rcx
    mov rbx, [rax]       ; code ret (save)
    mov [rax], rcx       ; NULL-pointer (1 hit code)

_next:
    mov rsi, rsp        
    add rsi, 128         ; stack_current
    mov rcx, [rax + 8]   ; count (2 * unsigned long)
    add rax, 16;
    jmp _loop

_portal:
    jmp short _trick

_catch:
    mov [rsp+120], rdx   ; orig_ret
    jmp _loop2

_loop:
    dec rcx
    mov rdi, [rax] ; stack_addr
    add rax, 8
    mov rdx, [rax] ; ret_addr
    add rax, 8
    mov [rdi], rdx ; restore orig_ret in the stack
    xor rdi, rsi   ; stack_current == stack_addr
    jz _catch
_loop2:
    test rcx, rcx
    jne _loop

_end:
    mov rdi, rsp       ; all arguments
    test rbx, rbx
    jz _ret

_call:
    call rbx
    
_ret:
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    add rsp, 8
    ret
    
_trick:
    call _code

; name="retcode64"; nasm $name.s -o $name.payload; nasm -f elf64 $name.s -o $name.o; ld $name.o -o $name; hexdump -C $name.payload; echo -e "\n\n"; ndisasm -b 64 $name.payload && ./bin_to_c.py $name.payload
