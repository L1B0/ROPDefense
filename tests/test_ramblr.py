#!/usr/bin/python3
# __Author__ = 'l1b0'

import os
import compilerex
import angr
import subprocess
import logging

# set log
logging.basicConfig(level = logging.INFO,format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def walkdir(dir_path):

    for root, dirs, files in os.walk(dir_path):

        for name in files:

            ropDefense(os.path.join(root,name))


def ropDefense(bin_filepath):

    #bin_filepath = "/home/l1b0/Desktop/cgc-linux/test_binaries/elf/level3"
    #bin_filepath = "/home/l1b0/Desktop/cgc-linux/test_binaries/original/CROMU_00008"

    logger.info(bin_filepath)
    newbin_filepath = bin_filepath + "_new"
    asm_filepath = bin_filepath + ".s"

    # reassembly
    p = angr.Project(bin_filepath, auto_load_libs=False)
    r = p.analyses.Reassembler(syntax="at&t")
    #r = p.analyses.Reassembler()
    r.symbolize()
    r.remove_unnecessary_stuff()
    # add by l1b0
    assembly = r.assembly(comments=True, symbolized=True)

    #assembly = assembly.replace('.globl _dl_relocate_static_pie','')
    #assembly = assembly.replace('.globl __libc_csu_init', '')
    # exe type: elf or cgc
    file_header = open(bin_filepath,'rb').read(5)
    #logging.info(file_header)

    # cgc
    if file_header[:4] == b'\x7fCGC':

        f = open(asm_filepath, 'w')
        f.write("\t.code32\n")
        f.write(assembly)
        f.close()

        retcode, res = compilerex.assemble([asm_filepath, '-o', newbin_filepath])

        if retcode != 0:
            logger.error(res)

    # elf
    elif file_header[:4] == b'\x7fELF':
        compile_list = ["gcc"]

        f = open(asm_filepath, 'w')
        if file_header[4] == 0x01: # x86
            f.write("\t.code32\n")
            compile_list.append("-m32")

        f.write(assembly)
        f.close()

        # checksec elf
        res = subprocess.Popen('./checksec.sh --file='+bin_filepath,
                               shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds = True)
        res = res.stdout.read()

        if b'Canary found' in res:
            compile_list.append("-fstack-protector-all")

        if b'NX disabled' in res:
            compile_list.append("-z")
            compile_list.append("execstack")

        if b'No PIE' in res:
            compile_list.append("-no-pie")

        #logging.warning(compile_list)

        compile_list.append(asm_filepath)
        compile_list.append("-o")
        compile_list.append(newbin_filepath)

        #"-z", "noexecstack",  "-fstack-protector-all"
        subprocess.check_call(compile_list)

    # other file
    else:
        raise Exception("Invalid executed file!")

if __name__ == '__main__':

    #ropDefense("/home/l1b0/Desktop/x86_64/df_gcc_-O1")
    #walkdir('/home/l1b0/Desktop/test_binaries/x86_64')
    ropDefense("/home/l1b0/Desktop/test_binaries/x86_64/ln_gcc_-O2")