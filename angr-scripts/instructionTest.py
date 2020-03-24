#!/usr/bin/python3
# __Author__ = 'l1b0'

from capstone import *
from capstone.x86 import *
import random
import utils
from utils import ASMConverter
import pdb
import os, time
import logging

logging.basicConfig(level = logging.INFO,format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class FreeBranchProtection():
    def __init__(self, assembly, name, bits):
        """
        use canary and xor to protect retn addr
        :param list assembly: [addr, asm], all asm in one predure
        :param int bits: binary arch bits, 32 or 64 
        """
        self.assembly = assembly
        self.name = name
        self.bits = bits
        self.new_assembly = []
        #self.original_code = "\t%s\t%s" % (self.insn.mnemonic, self.insn.op_str)
        #self.format_flag = 0
    
    def add_asm_into_block(self, block_asm, insert_flag, new_asm):
            
        block_asm_split = block_asm.split('\n')
        #logger.warning(block_asm_split)
        flag = False
        for ii,jj in enumerate(block_asm_split):
            
            if insert_flag == '' and '@function' in jj:
                block_asm_split[ii+2] = new_asm + block_asm_split[ii+2]
                flag = True
                break
                
            if jj == insert_flag:
                #if head:
                block_asm_split[ii] = new_asm + block_asm_split[ii]
                flag = True
                #else:
                #    block_asm_split[ii] = block_asm_split[ii] + new_asm
                break
        
        if flag == False:
            #logger.warning(block_asm_split)
            block_asm_split[0] = new_asm + block_asm_split[0]
            
        block_asm_split = '\n'.join(block_asm_split)
        
        return block_asm_split
        
    def dispatch(self):
        
        logger.warning(self.name)
        if self.name == '__stack_chk_fail_local':
            return self.assembly
        
        # x86 retn addr encode and decode
        if self.bits == 32:
            canary_flag = '%gs:0x14'
            func_start_flag = '\tpushl\t%ebp'
            #encode_offset = -1
            #decode_flag = '__stack_chk_fail'
            func_end_flag = '\tretl\t'
            
            encode_retn_addr = '\t%s\t%s\n'%('pushl','%eax')
            encode_retn_addr += '\t%s\t%s,%s\n'%('movl','%gs:0x14','%eax')
            encode_retn_addr += '\t%s\t%s,%s\n'%('xorl','%eax','4(%esp)')
            encode_retn_addr += '\t%s\t%s\n'%('popl','%eax')

        # x86-64
        else:
            canary_flag = '%fs:0x28' 
            func_start_flag = '\tpushq\t%rbp'
            #func_push_flag = '\tmovq\t%rsp, %rbp'
            #encode_offset = 0
            #decode_flag = '__stack_chk_fail'
            func_end_flag = '\tretq\t'
            
            encode_retn_addr = '\t%s\t%s\n'%('pushq','%r11')
            encode_retn_addr += '\t%s\t%s,%s\n'%('movq','%fs:0x28','%r11')
            encode_retn_addr += '\t%s\t%s,%s\n'%('xorq','%r11','8(%rsp)')
            encode_retn_addr += '\t%s\t%s\n'%('popq','%r11')
            
            #encode_jmp = '\n\t%s\t%s,%s'%('movq','%r11','-0x50(%rbp)')
            
        # encode all func retn addr     
        
        #logger.warning(self.assembly[1][1])
        #logger.warning(self.assembly[-1][1]) 
        func_start_asm = self.assembly[1][1]
        func_start_addr = self.assembly[1][0]

        if func_start_flag in func_start_asm:
            
            # add encode asm
            func_start_asm_split = self.add_asm_into_block(func_start_asm, '', encode_retn_addr)
            
            #logging.warning(func_start_asm_split)
            self.assembly[1] = (func_start_addr, func_start_asm_split)
            
            # decode the func retn addr
            flag = False
            for i in range(len(self.assembly)-1,-1,-1):
                func_end_asm = self.assembly[i][1]
                func_end_addr = self.assembly[i][0]
            
                #logging.warning(func_end_asm)
                # find retn
                if func_end_flag in func_end_asm:
                    
                    flag = True
                    func_end_asm_split = self.add_asm_into_block(func_end_asm, func_end_flag, encode_retn_addr)
                    
                    #logging.warning(func_end_asm_split)
                    self.assembly[i] = (func_end_addr, func_end_asm_split)
            
            # no retn, go back
            if not flag:
                self.assembly[1] = (func_start_addr, func_start_asm)

        
        return self.assembly           
        '''
        # find check_insn and add encode_retn_addr into asm
        # i is addr, j is block
        # just protect func who have __stack_chk_fail, that's not enough.
        for i,j in enumerate(self.assembly):
            addr = j[0]
            asm = j[1]
            #logging.info(addr,asm)
            # add encode
            if canary_flag in asm:
                logging.warning('canary\n'+asm)
                next_addr = self.assembly[i+encode_offset][0]
                next_asm = self.assembly[i+encode_offset][1]
                if func_start_flag in next_asm:
                    logging.warning('encode\n'+next_asm)
                    next_asm = next_asm.split('\n')
                    #logging.warning(next_asm)
                    for ii,jj in enumerate(next_asm):
                        if jj == func_start_flag:
                            next_asm[ii] = encode_retn_addr + next_asm[ii]
                            break
                    next_asm = '\n'.join(next_asm)
                    #logging.warning(next_asm)
                    self.assembly[i+encode_offset] = (addr, next_asm)
                    
            # add decode
            elif decode_flag in asm:
                
                next_addr = self.assembly[i+1][0]
                next_asm = self.assembly[i+1][1].split('\n')
                #logging.warning(next_asm)
                
                for ii,jj in enumerate(next_asm):
                    if jj == func_end_flag:
                        next_asm[ii] = encode_retn_addr + next_asm[ii]
                        break
                        
                next_asm = '\n'.join(next_asm)
                logging.warning(next_asm)
                self.assembly[i+1] = (next_addr, next_asm)        
        '''
        
        
class InsnObfuscated():
    def __init__(self, insn, addr, bits):
        """
        
        :param insn: Capstone Instr object
        :param int addr: Address of the instruction
        :param int bits: binary arch bits, 32 or 64 
        """
        self.insn = insn
        self.addr = addr
        self.bits = bits
        self.obf_code = []
        self.original_code = "\t%s\t%s" % (self.insn.mnemonic, self.insn.op_str)
        self.format_flag = 0
    
    def asm2hex_intel(self):
        
        #print(self.original_code)
        # write asm into open
        tempasm = open('/tmp/temp.asm', 'w')
        if self.insn.mnemonic == "lea":
            tempasm.write('_start:\n\t' + self.original_code.replace('dword ptr','') + '\n')
        else:
            tempasm.write('_start:\n\t' + self.original_code.replace('ptr','') + '\n')
        tempasm.close()
        
        time.sleep(0.01)
        os.system(r"nasm -f elf32 /tmp/temp.asm; objdump -D /tmp/temp.o -M intel | grep '^ ' | cut -f2-3 > /tmp/temp.x.asm")
        time.sleep(0.01)
        
        # read the machine code
        tempxasm = open('/tmp/temp.x.asm')
        hex_s = tempxasm.read()
        #print(hex_s,len(hex_s[0]))
        tempxasm.close()
        
        return hex_s
        
    def asm2hex_att(self):
        
        #print(self.original_code)
        # write asm into open
        tempasm = open('/tmp/temp.s', 'w')
        #x86
        if self.bits == 32:
            tempasm.write('.code32\n\t_start:\n\t' + self.original_code + '\n')
        #x86-64
        else:
            tempasm.write('_start:\n\t' + self.original_code + '\n')
        tempasm.close()
        
        # compile the open
        #time.sleep(0.01)
        os.system(r"as -o /tmp/temp.o /tmp/temp.s; objdump -D /tmp/temp.o -M att | grep '^ ' | cut -f2-3 > /tmp/temp.x.asm")
        #time.sleep(0.01)
        
        # read the machine code
        tempxasm = open('/tmp/temp.x.asm')
        hex_s = tempxasm.read()
        #print(hex_s,len(hex_s[0]))
        tempxasm.close()
        
        return hex_s
    
    def is_insn_danger(self):
        
        # retn
        if self.insn.id == X86_INS_RET:
            return False
            
        # 89 8c 85 68 ff ff ff 	mov    %ecx,-0x98(%rbp,%rax,4)
        asm_hex = self.asm2hex_att()
        #asm_hex = self.asm2hex_intel()
        
        # split as ' '
        # ['89 8c 85 68 ff ff ff ', 'mov    %ecx,-0x98(%rbp,%rax,4)\n']
        asm_hex = asm_hex.split('\t')[0]
        asm_hex = asm_hex.split(' ')
        #print(asm_hex)
        
        # delete space element
        for item in asm_hex[:]:
            if item == '':
                asm_hex.remove('')
        #print(asm_hex)
        
        asm_hex = [ eval('0x'+i) for i in asm_hex ]
        dangerImm = [0xc2, 0xc3, 0xca, 0xcb]
        for i in asm_hex:
            if i in dangerImm:
                #logging.warning("danger insn: %s"%str(asm_hex))
                return True
        
        return False
        
        
    def is_imm_danger(self):
        
        if len(self.insn.operands) == 0:
            return []
        
        if self.insn.operands[0].type != X86_OP_IMM:
            return []
        
        dangerImm = [0xc2, 0xc3, 0xca, 0xcb]
        imm = self.insn.operands[0].imm
        
        # split imm by byte
        # 0x12c3a1 -> [0x00, 0x12, 0xc3, 0xa1]
        imm_split = []
        temp_imm = imm
        for i in range(4):
            imm_split.append(temp_imm&0xff)
            temp_imm = (temp_imm >> 8)
        imm_split = imm_split[::-1]
        #print(imm_split)
        
        # find the danger index
        dangerIndex = -1
        for i,j in enumerate(imm_split):
            if j in dangerImm:
                dangerIndex = i
        #print(dangerIndex)
        
        # split imm in two parts
        # 0x12c3a1 -> 0x0012c000 + 0x3a1
        if dangerIndex != -1:
            hex_imm = hex(imm)[2:].zfill(8)
            l_imm = eval('0x'+hex_imm[:(dangerIndex*2+1)].ljust(8,'0'))
            r_imm = eval('0x'+hex_imm[(dangerIndex*2+1):])
            return [l_imm,r_imm]
        else:
            return []
    
    '''
    def set_flag(self):
    
        #flag = 0 ==> transfer Intel style to AT&T  
        
        self.format_flag = 1
        
        return      
    ''' 
    def mov_obf(self, insn_imm):

        #self.obf_code = []

        # movl IMM REG
        #if (self.insn.operands[0].type == X86_OP_IMM) and (self.insn.operands[1].type == X86_OP_REG):
        regindex = self.insn.operands[1].reg
        reg = self.insn.reg_name(regindex)
        #print(reg)
        
        # x86-64
        if self.bits == 64:
            reg = '%'+reg
            self.obf_code.append("\t%s\t$%d,%s" % ("movq", insn_imm[0], reg))
            self.obf_code.append("\t%s\t$%d,%s" % ("addq", insn_imm[1], reg))
            
            self.obf_code = "\n".join(self.obf_code)
            return 
            
        # x86
        #print("Find danger! %s\t%s"%(self.insn.mnemonic, self.insn.op_str))
        self.obf_code.append("\t%s\t%s,%d" % ("mov", reg, insn_imm[0]))
        self.obf_code.append("\t%s\t%s,%d" % ("add", reg, insn_imm[1]))
        
        self.obf_code = ASMConverter.intel_to_att("\n".join(self.obf_code))
        
        return 

    def add_obf(self, insn_imm):
        #obf_code = []

        regindex = self.insn.operands[1].reg
        reg = self.insn.reg_name(regindex)
        #print(reg)

        # x86-64
        if self.bits == 64:
            reg = '%'+reg
            self.obf_code.append("\t%s\t$%d,%s" % ("addq", insn_imm[0], reg))
            self.obf_code.append("\t%s\t$%d,%s" % ("addq", insn_imm[1], reg))
            
            self.obf_code = "\n".join(self.obf_code)
            return 
            
        # x86
        #print("Find danger! %s\t%s"%(self.insn.mnemonic, self.insn.op_str))
        self.obf_code.append("\t%s\t%s,%d" % ("add", reg, insn_imm[0]))
        self.obf_code.append("\t%s\t%s,%d" % ("add", reg, insn_imm[1]))
        
        self.obf_code = ASMConverter.intel_to_att("\n".join(self.obf_code))
        
        return 

    def sub_obf(self, insn_imm):
        #obf_code = []

        regindex = self.insn.operands[1].reg
        reg = self.insn.reg_name(regindex)
        #print(reg)

        # x86-64
        if self.bits == 64:
            reg = '%'+reg
            self.obf_code.append("\t%s\t$%d,%s" % ("subq", insn_imm[0], reg))
            self.obf_code.append("\t%s\t$%d,%s" % ("subq", insn_imm[1], reg))
            
            self.obf_code = "\n".join(self.obf_code)
            return 
            
        # x86
        #print("Find danger! %s\t%s"%(self.insn.mnemonic, self.insn.op_str))
        self.obf_code.append("\t%s\t%s,%d" % ("sub", reg, insn_imm[0]))
        self.obf_code.append("\t%s\t%s,%d" % ("sub", reg, insn_imm[1]))
        
        self.obf_code = ASMConverter.intel_to_att("\n".join(self.obf_code))
        
        return 

    def cmp_obf(self, insn_imm):
        #obf_code = []

        regindex = self.insn.operands[1].reg
        reg = self.insn.reg_name(regindex)
            
        #print("Find danger! %s\t%s"%(self.insn.mnemonic, self.insn.op_str))
        '''
        cmp ebx, 0xc3
        ==>
        push eax
        mov eax, 0xc0
        add eax, 0x3
        cmp ebx, eax
        pop eax
        '''
        # x86-64
        if self.bits == 64:
            temp_teg = "%rbx" if reg == "rax" else "%rax"
            reg = '%'+reg
            self.obf_code.append("\t%s\t%s" % ("pushq", temp_teg))
            self.obf_code.append("\t%s\t$%d,%s" % ("movq", insn_imm[0], temp_teg))
            self.obf_code.append("\t%s\t$%d,%s" % ("addq", insn_imm[1], temp_teg))
            self.obf_code.append("\t%s\t%s,%s" % ("cmpq", temp_teg, reg))
            self.obf_code.append("\t%s\t%s" % ("popq", temp_teg))
            
            self.obf_code = "\n".join(self.obf_code)
            return 
            
        # x86
        #print("Find danger! %s\t%s"%(self.insn.mnemonic, self.insn.op_str))
        temp_teg = "ebx" if reg == "eax" else "eax"
        self.obf_code.append("\t%s\t%s" % ("push", temp_teg))
        self.obf_code.append("\t%s\t%s,%d" % ("mov", temp_teg, insn_imm[0]))
        self.obf_code.append("\t%s\t%s,%d" % ("add", temp_teg, insn_imm[1]))
        self.obf_code.append("\t%s\t%s,%s" % ("cmp", reg, temp_teg))
        self.obf_code.append("\t%s\t%s" % ("pop", temp_teg))
        
        self.obf_code = ASMConverter.intel_to_att("\n".join(self.obf_code))
        return 
    
    def and_obf(self, insn_imm):
        #obf_code = []

        regindex = self.insn.operands[1].reg
        reg = self.insn.reg_name(regindex)

        #print("Find danger! %s\t%s"%(self.insn.mnemonic, self.insn.op_str))
        '''
        and ebx, 0xc3
        ==>
        push eax
        mov eax, 0xc0
        add eax, 0x3
        and ebx, eax
        pop eax
        '''
        # x86-64
        if self.bits == 64:
            temp_teg = "%rbx" if reg == "rax" else "%rax"
            reg = '%'+reg
            self.obf_code.append("\t%s\t%s" % ("pushq", temp_teg))
            self.obf_code.append("\t%s\t$%d,%s" % ("movq", insn_imm[0], temp_teg))
            self.obf_code.append("\t%s\t$%d,%s" % ("addq", insn_imm[1], temp_teg))
            self.obf_code.append("\t%s\t%s,%s" % ("andq", temp_teg, reg))
            self.obf_code.append("\t%s\t%s" % ("popq", temp_teg))
            
            self.obf_code = "\n".join(self.obf_code)
            return 
            
        # x86
        temp_teg = "ebx" if reg == "eax" else "eax"
        self.obf_code.append("\t%s\t%s" % ("push", temp_teg))
        self.obf_code.append("\t%s\t%s,%d" % ("mov", temp_teg, insn_imm[0]))
        self.obf_code.append("\t%s\t%s,%d" % ("add", temp_teg, insn_imm[1]))
        self.obf_code.append("\t%s\t%s,%s" % ("and", reg, temp_teg))
        self.obf_code.append("\t%s\t%s" % ("pop", temp_teg))

        return 
    
    def or_obf(self, insn_imm):
        
        #obf_code = []

        regindex = self.insn.operands[1].reg
        reg = self.insn.reg_name(regindex)
        
        # x86-64
        if self.bits == 64:
            reg = '%'+reg
            self.obf_code.append("\t%s\t$%d,%s" % ("orq", insn_imm[0], reg))
            self.obf_code.append("\t%s\t$%d,%s" % ("orq", insn_imm[1], reg))
            
            self.obf_code = "\n".join(self.obf_code)
            return 
            
        # x86
        #print("Find danger! %s\t%s"%(self.insn.mnemonic, self.insn.op_str))
        self.obf_code.append("\t%s\t%s,%d" % ("or", reg, insn_imm[0]))
        self.obf_code.append("\t%s\t%s,%d" % ("or", reg, insn_imm[1]))
        
        self.obf_code = ASMConverter.intel_to_att("\n".join(self.obf_code))
        return
    
    def xor_obf(self, insn_imm):
        
        #obf_code = []

        regindex = self.insn.operands[1].reg
        reg = self.insn.reg_name(regindex)

        if self.bits == 64:
            reg = '%'+reg
            self.obf_code.append("\t%s\t$%d,%s" % ("xorq", insn_imm[0], reg))
            self.obf_code.append("\t%s\t$%d,%s" % ("xorq", insn_imm[1], reg))
            
            self.obf_code = "\n".join(self.obf_code)
            return 
            
        # x86
        #print("Find danger! %s\t%s"%(self.insn.mnemonic, self.insn.op_str))
        self.obf_code.append("\t%s\t%s,%d" % ("xor", reg, transImm[0]))
        self.obf_code.append("\t%s\t%s,%d" % ("xor", reg, transImm[1]))
        
        self.obf_code = ASMConverter.intel_to_att("\n".join(self.obf_code))
        return

    def dispatch(self):
        
        #logger.info("arch bits: %d"%self.bits)
        #logger.info(hex(self.addr) + self.original_code)
        #logger.info(str(len(self.insn.operands))+self.original_code)
        #return self.original_code
        
        insn_type = self.insn.id
        # indirect jump, add check code
        if insn_type == X86_INS_JMP or insn_type == X86_INS_CALL:
            #logger.info(str(len(self.insn.operands))+self.original_code)
            # 1	jmpq	*%rax
            # logger.info(str(self.insn.operands[0].type == X86_OP_IMM))
            # False
            if self.insn.operands[0].type == X86_OP_REG and self.bits == 64:
                logger.info(self.original_code)
                # add check code
                '''
                movq    $0x800000000000,%r11
                cmpq    %r11,4(%rbp)
                ja	. + 3
                hlt
                jmpq    *%rax
                '''
                decode_jmp = '\tmovq\t$0x800000000000,%r11\n\tcmpq\t%r11,4(%rbp)\n\tja\t. + 3\n\thlt\n'
                self.obf_code.append(decode_jmp)
                self.obf_code.append(self.original_code)
                return "\n".join(self.obf_code)
            
            if self.insn.operands[0].type == X86_OP_REG and self.bits == 32:
                logger.info(self.original_code)
                # add check code
                '''
                pushl   %eax
                shrl    $24,%eax
                cmpl    $0xf7,%eax
                jne     . + 3
                hlt
                popl    %eax
                jmpq    *%eax
                '''
                decode_jmp = '\tpushl\t%eax\n\tshrl\t$24,%eax\n\tcmpl\t$0xf7,%eax\n\tjne\t. + 3\n\thlt\n\tpopl\t%eax\n'
                self.obf_code.append(decode_jmp)
                self.obf_code.append(self.original_code)
                return "\n".join(self.obf_code)
            
        # 1. if instruction includes 0xc2,c3,ca,cb, the insn is dangerous, but except retn.
        if self.is_insn_danger() == False:
            
            return self.original_code
        
        logger.warning("%s is danger!" % self.original_code)
            
        # 2. Insn is danger, and judge if imm includes ...
        insn_imm = self.is_imm_danger()
        
        # 2.1. imm is safty, so add nop
        if insn_imm == []:
            
            # the number of nop is important!!!
            '''
            jmp	. + 11
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            original_code
            '''
            self.obf_code.append("\t%s\t%s%d" % ("jmp", ". + ", 2+9))
            for i in range(9):
                self.obf_code.append("\tnop")
            self.obf_code.append(self.original_code)
                
            return "\n".join(self.obf_code)
        
        # 2.2. imm is danger
        logger.warning("%s imm danger!" % self.original_code)
        
        if insn_type == X86_INS_INVALID:
            logger.info("now asmcode is X86_INS_INVALID")
            return
        
        # Assignment and Operation
        elif insn_type == X86_INS_MOV:
            self.mov_obf(insn_imm)
            logger.info("now asmcode is X86_INS_MOV")
        
        elif insn_type == X86_INS_ADD:
            self.add_obf(insn_imm)
            logger.info("now asmcode is X86_INS_ADD")
            
        elif insn_type == X86_INS_SUB:
            self.sub_obf(insn_imm)
            logger.info("now asmcode is X86_INS_SUB")
            
        elif insn_type == X86_INS_CMP:
            self.cmp_obf(insn_imm)
            logger.info("now asmcode is X86_INS_CMP")
            
        elif insn_type == X86_INS_AND:
            self.and_obf(insn_imm)
            logger.info("now asmcode is X86_INS_AND")
            
        elif insn_type == X86_INS_OR:
            self.or_obf(insn_imm)
            logger.info("now asmcode is X86_INS_OR")
            
        elif insn_type == X86_INS_XOR:
            self.xor_obf(insn_imm)
            logger.info("now asmcode is X86_INS_XOR")
        
        else:
            logger.warning("cannot process %s" % self.original_code)
        
        return self.obf_code
        #return "\n".join(self.obf_code)
 
