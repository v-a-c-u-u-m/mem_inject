#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>

int test() {
    sleep(1);
    return 0;
}

int ret1() {
    return 0;
};

int ret2() {
    return 0;
};

int f1(int i) {
    fprintf(stderr, "Round[f1] %d\n", i);
    ret1();
    return 0;
}

int f2(int i) {
    fprintf(stderr, "Round[f2] %d\n", i);
    ret2();
    return 0;
}

int loop(unsigned int times, unsigned int delay) {
    char s[] = "hello world!";
    for (int i = 1; i < times; i++) {
        if (i % 2 == 0) {
            f1(i);
        } else {
            f2(i);
        }
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
