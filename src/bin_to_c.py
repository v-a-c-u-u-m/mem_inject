#!/usr/bin/env python3

from sys import argv

def main(filepath, outfile):
    with open(filepath, "rb") as f:
        data = f.read()
    out_c  = 'unsigned const char shellcode[] = {'
    out_py = "shellcode = ["
    for byte in data:
        s = "{}, ".format(hex(byte))
        out_c  += s
        out_py += s
    out_c  += "};\n"
    out_py += "]\n"
    if outfile:
        outfile = outfile.replace(".h", "").replace(".py", "")
        with open(outfile + ".h", "w") as f:
            f.write(out_c)
        with open(outfile + ".py", "w") as f:
            f.write(out_py)
    else:
        print(data)

if __name__ == "__main__":
    if len(argv) >= 2:
        filepath = argv[1]
        outfile = None
        if len(argv) >= 3:
            outfile = argv[2]
        main(filepath, outfile)
    else:
        print("usage: ./bin_to_c.py shellcode64.bin src/shellcode.h")
