#!/usr/bin/env python
# coding=utf-8
# usage:
# python asm2hex
# > mov rsp, 0
# 48 bc 00 00 00 00 00 00 00 00

import os, time

while True:
        s = raw_input('> ')
        tempasm = file('/tmp/temp.s', 'w')
        tempasm.write('.code32\n\t_start:\n\t')
        tempasm.write('\t'+ s + '\n')
        tempasm.close()
        time.sleep(0.01)
        os.system(r"as -o /tmp/temp.o /tmp/temp.s; objdump -D /tmp/temp.o -M att | grep '^ ' | cut -f2-3 > /tmp/temp.x.asm")
        time.sleep(0.01)
        tempxasm = file('/tmp/temp.x.asm')
        hex_s = tempxasm.read().split('\t')
        print hex_s

        tempxasm.close()

