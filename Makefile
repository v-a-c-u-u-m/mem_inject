BUILD := libmode

cflags.common  := -ldl -D_GNU_SOURCE
cflags.debug   := -DDEBUG
cflags.libmode := -DLIBMODE

CFLAGS := ${cflags.common} ${cflags.${BUILD}}

shellcode64=shellcode64
retcode64=retcode64
mem_inject = mem_inject
hello = hello


all: chmod_x clean_before inject

shell: chmod_x clean_before genshell inject clean_shell

ret: chmod_x clean_before genret inject clean_ret


genshell:
	nasm src/$(shellcode64).s -o $(shellcode64).payload
	./src/bin_to_c.py $(shellcode64).payload src/shellcode_test.h

genret:
	nasm src/$(retcode64).s -o $(retcode64).payload
	./src/bin_to_c.py $(retcode64).payload src/retcode_test.h

inject:
	for filename in modules/*.c; do gcc $$filename -o $${filename%.c}.so -shared -fPIC; done
	gcc src/$(mem_inject).c -o $(mem_inject) $(CFLAGS)
	gcc src/$(hello).c -o $(hello) $(CFLAGS)

chmod_x:
	chmod +x mem_inject.py
	chmod +x src/bin_to_c.py

clean_before:
	for filename in modules/*.c; do rm -f $${filename%.c}.so; done
	rm -f $(hello) $(mem_inject)

clean_shell:
	rm -f $(shellcode64).payload

clean_ret:
	rm -f $(retcode64).payload
