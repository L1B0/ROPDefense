#!/usr/bin/python3
# __Author__ = 'l1b0'

import compilerex
import angr
import subprocess
import logging

logging.basicConfig(level = logging.INFO,format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

if __name__ == '__main__':

    bin_filepath = "/home/l1b0/Desktop/cgc-linux/test_binaries/elf/test_add"
    #bin_filepath = "/home/l1b0/Desktop/cgc-linux/test_binaries/original/CROMU_00008"
    newbin_filepath = bin_filepath + "_new"
    asm_filepath = bin_filepath + ".s" \
                                  ""

    # reassembly
    p = angr.Project(bin_filepath, auto_load_libs=False)
    r = p.analyses.Reassembler(syntax="at&t")
    #r = p.analyses.Reassembler()
    r.symbolize()
    r.remove_unnecessary_stuff()
    assembly = r.assembly(comments=True, symbolized=True)

    assembly = assembly.replace('.globl _dl_relocate_static_pie','')

    # exe type: elf or cgc
    file_header = open(bin_filepath,'rb').read(5)
    logging.info(file_header)

    # cgc
    if file_header[:4] == b'\x7fCGC':

        f = open(asm_filepath, 'w')
        f.write("\t.code32\n")
        f.write(assembly)
        f.close()

        retcode, res = compilerex.assemble([asm_filepath, '-o', newbin_filepath])

        if retcode != 0:
            print(res)

    # elf
    elif file_header[:4] == b'\x7fELF':
        compile_list = ["gcc"]

        f = open(asm_filepath, 'w')
        if file_header[4] == 0x01: # x86
            f.write("\t.code32\n")
            compile_list.append("-m32")

        f.write(assembly)
        f.close()

        # no pie
        compile_list.append("-no-pie")
        # NX enabled
        compile_list.append("-z")
        compile_list.append("noexecstack")
        # canary open
        compile_list.append("-fstack-protector-all")
        compile_list.append(asm_filepath)
        compile_list.append("-o")
        compile_list.append(newbin_filepath)

        #"-z", "noexecstack",  "-fstack-protector-all"
        subprocess.check_call(compile_list)

    # other file
    else:
        raise Exception("Invalid executed file!")

