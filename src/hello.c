#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>

int test() {
    sleep(1);
    return 0;
}

int loop(unsigned int times, unsigned int delay) {
    char s[] = "hello world!";
    for (int i = 1; i < times; i++) {
        fprintf(stderr, "Round %d\r", i);
        test();
        //printf("\n");
        sleep(2);
    }
    return 0;
}

int main() {
    printf("./mem_inject $(pidof hello)\n");
    printf("OR\n");
    printf("./mem_inject.py $(pidof hello)\n\n\n");
    loop(500, 20);
    return 0;
}
