shellcode64=shellcode64
shellcode=shellcode
mem_inject = mem_inject
hello = hello


all: clean_before inject clean_after

inject:
	nasm src/$(shellcode64).s -o $(shellcode64).payload
	./src/bin_to_c.py $(shellcode64).payload src/$(shellcode).h
	gcc src/$(mem_inject).c -o $(mem_inject)
	gcc src/$(hello).c -o $(hello)

clean_before:
	rm -f $(hello) $(mem_inject)

clean_after:
	rm -f $(shellcode64).payload
