typedef struct maps_t {
    unsigned long addr_start;
    unsigned long addr_finish;
    char str_start[17];
    char str_finish[17];
    char perms[5];
    char offset[9];
    char dev[6];
    char inode[9];
    char pathname[500];
    char isexec;
    char isread;
    char iswrite;
    char isstack;
    char isheap;
    char islibc;
    char isfirst;
    char istarget;
    char id;
} maps_t, *maps_p;

typedef struct link_t {
    unsigned long pointer;
    unsigned long value;
} link_t, *link_p;
