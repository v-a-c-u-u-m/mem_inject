# mem_inject
Linux shellcode code memory injection library .so .dll injection without ptrace example PoC [x86_64, ARM!] (own development)



## Build - library injection (x86_64, arm)
`
make
`

## Build - shellcode (x86_64, arm)
`
make BUILD=common
`

## Loop
`
./hello
`

## Inject - library (test)
`
./mem_inject $(pidof hello) modules/injected_library.so
`

## Inject - library (print registers)
`
./mem_inject $(pidof hello) modules/reg_info.so
`

## Inject - shellcode
`
./mem_inject.py $(pidof hello)
`

## Custom Shellcode
change the file src/shellcode.h or src/shellcode.py as example RET only instruction

```
echo "unsigned const char shellcode[] = {0xc3};" > src/shellcode.h
make
```

## Custom Library
change the file src/injected_library.c
