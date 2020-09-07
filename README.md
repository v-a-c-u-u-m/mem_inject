# mem_inject
Linux shellcode code memory injection library .so .dll injection without ptrace example PoC [x64 only!]



### BUILD
`
make
`

### LOOP
`
./hello
`

### INJECT (C)
`
./mem_inject $(pidof hello)
`

### INJECT (PYTHON)
`
./mem_inject.py $(pidof hello)
`



### CUSTOM SHELLCODE
change the file src/shellcode.c or src/shellcode.py as example RET only instruction

`
echo "unsigned const char shellcode[] = {0xc3};" > src/shellcode.h
`
