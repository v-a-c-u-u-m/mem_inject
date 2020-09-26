BUILD := libmode

cflags.common  := -ldl -D_GNU_SOURCE
cflags.debug   := -DDEBUG
cflags.libmode := -DLIBMODE

CFLAGS := ${cflags.common} ${cflags.${BUILD}}

shellcode64=shellcode64
shellcode=shellcode
mem_inject = mem_inject
hello = hello
injected_library = injected_library


all: chmod_x clean_before inject clean_after

nasm: chmod_x clean_before genshell inject clean_after


genshell:
	nasm src/$(shellcode64).s -o $(shellcode64).payload
	./src/bin_to_c.py $(shellcode64).payload src/$(shellcode).h

inject:
	gcc src/$(injected_library).c -o $(injected_library).so -shared -fPIC
	gcc src/$(mem_inject).c -o $(mem_inject) $(CFLAGS)
	gcc src/$(hello).c -o $(hello) $(CFLAGS)

chmod_x:
	chmod +x mem_inject.py
	chmod +x src/bin_to_c.py

clean_before:
	rm -f $(hello) $(mem_inject) $(injected_library).so

clean_after:
	rm -f $(shellcode64).payload
