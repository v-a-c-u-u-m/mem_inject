#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void test() {
    printf("OK!\n");
    sleep(1);
}

void loop(unsigned int times, unsigned int delay) {
    char s[] = "hello world!";
    for (size_t i = 1; i < times; i++) {
        printf("Round %d\n", i);
        test();
        printf("\n");
        sleep(2);
    }
}

void main() {
    printf("./mem_inject $(pidof hello)\n");
    printf("OR\n");
    printf("./mem_inject.py $(pidof hello)\n\n\n");
    loop(500, 20);
}
