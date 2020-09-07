BITS 64

global _start

_start:
    push rax
    push rdi
    push rsi
    push rdx
    jmp short _trick

_code:
    xor rax, rax
    xor rdi, rdi
    xor rdx, rdx

_write:
    ; ssize_t write(int fd, const void *buf, size_t count);
    mov al, 1                      ; rax = 1 (syscall write)
    inc rdi                        ; rdi = 1 (fd = 1, STDOUT)
    pop rsi                        ; rsi = *(msg)
    mov dl, _len                   ; rdx = len(msg)
    syscall                        ; write(1, string, len(string))

_nanosleep:
    push 0x0;
    push 0x1;
    mov rdi, rsp
    mov rax, 35
    xor rsi, rsi
    syscall
    pop rax
    pop rax

_ret:
    pop rdx
    pop rsi
    pop rdi
    pop rax
    ret

_trick:
    call _code
    _msg: db 0xa, 0xa, "ATTENTION PLEASE! You have been hacked!", 0xa, 0xa, 0xa
    _len: equ $ - _msg

