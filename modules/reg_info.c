#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdlib.h>
#include <dlfcn.h>


int get_proc_id() {
    // linux
    return getpid();
}

int get_parent_proc_id() {
    // linux
    return getppid();
}

int reg_print(void ***stack) {
    int pid = get_proc_id();
    int ppid = get_parent_proc_id();
    printf("proc id is %d, parent proc id is %d\n\n", pid, ppid);
    printf("[rdi] <arg1> addr 0x%lx, value 0x%lx\n", &stack[0], stack[0]);
    printf("[rsi] <arg2> addr 0x%lx, value 0x%lx\n", &stack[1], stack[1]);
    printf("[rdx] <arg3> addr 0x%lx, value 0x%lx\n", &stack[2], stack[2]);
    printf("[rcx] <arg4> addr 0x%lx, value 0x%lx\n", &stack[3], stack[3]);
    printf("[rbx]        addr 0x%lx, value 0x%lx\n", &stack[4], stack[4]);
    printf("[rax]        addr 0x%lx, value 0x%lx\n", &stack[5], stack[5]);
    printf("[r15]        addr 0x%lx, value 0x%lx\n", &stack[6], stack[6]);
    printf("[r14]        addr 0x%lx, value 0x%lx\n", &stack[7], stack[7]);
    printf("[r13]        addr 0x%lx, value 0x%lx\n", &stack[8], stack[8]);
    printf("[r12]        addr 0x%lx, value 0x%lx\n", &stack[9], stack[9]);
    printf("[r11]        addr 0x%lx, value 0x%lx\n", &stack[10], stack[10]);
    printf("[r10]        addr 0x%lx, value 0x%lx\n", &stack[11], stack[11]);
    printf("[r9]  <arg6> addr 0x%lx, value 0x%lx\n", &stack[12], stack[12]);
    printf("[r8]  <arg5> addr 0x%lx, value 0x%lx\n", &stack[13], stack[13]);
    printf("[rbp]        addr 0x%lx, value 0x%lx\n", &stack[14], stack[14]);
    printf("[orig_ret]   addr 0x%lx, value 0x%lx\n", &stack[15], stack[15]);
    printf("\n");
    return 0;
}


int entry_point(void ***stack) {
    reg_print(stack);
    return 0;
}
