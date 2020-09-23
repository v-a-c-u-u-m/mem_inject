shellcode64=shellcode64
shellcode=shellcode
mem_inject = mem_inject
hello = hello


all: chmod_x clean_before inject clean_after

nasm: chmod_x clean_before genshell inject clean_after


genshell:
	nasm src/$(shellcode64).s -o $(shellcode64).payload
	./src/bin_to_c.py $(shellcode64).payload src/$(shellcode).h

inject:
	gcc src/$(mem_inject).c -o $(mem_inject)
	gcc src/$(hello).c -o $(hello)

chmod_x:
	chmod +x mem_inject.py
	chmod +x src/bin_to_c.py

clean_before:
	rm -f $(hello) $(mem_inject)

clean_after:
	rm -f $(shellcode64).payload
