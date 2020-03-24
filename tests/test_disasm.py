#!/usr/bin/env python
# coding=utf-8

from capstone import *

md = Cs(CS_ARCH_X86, CS_MODE_64)

for i in md.disasm(b"\xc3",1):
    print(i,address, i.mnemonic, i.op_str)

