# mem_inject
Linux shellcode code memory injection library .so .dll injection without ptrace example PoC [x64 only!]



## Build
`
make
`

## Loop
`
./hello
`

## Inject (C)
`
./mem_inject $(pidof hello)
`

## Inject (PYTHON)
`
./mem_inject.py $(pidof hello)
`



## Custom Shellcode
change the file src/shellcode.c or src/shellcode.py as example RET only instruction

```
echo "unsigned const char shellcode[] = {0xc3};" > src/shellcode.h
make custom
```
