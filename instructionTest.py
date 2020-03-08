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

class Obfuscated():
    def __init__(self, insn, addr):
        self.insn = insn
        self.addr = addr
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
        #tempasm.write('.code32\n\t_start:\n\t' + self.original_code + '\n')
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
    
    def isInsnDanger(self):
        
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
                logging.warning("danger insn: %s"%str(asm_hex))
                return True
        
        return False
        
        
    def isImmDanger(self):
        
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

        #print("Find danger! %s\t%s"%(self.insn.mnemonic, self.insn.op_str))
        self.obf_code.append("\t%s\t%s,%d" % ("mov", reg, insn_imm[0]))
        self.obf_code.append("\t%s\t%s,%d" % ("add", reg, insn_imm[1]))
        
        return 

    def add_obf(self, insn_imm):
        #obf_code = []

        regindex = self.insn.operands[1].reg
        reg = self.insn.reg_name(regindex)
        #print(reg)

        print("Find danger! %s\t%s"%(self.insn.mnemonic, self.insn.op_str))
        
        self.obf_code.append("\t%s\t%s,%d" % ("add", reg, insn_imm[0]))
        self.obf_code.append("\t%s\t%s,%d" % ("add", reg, insn_imm[1]))

        return 

    def sub_obf(self, insn_imm):
        #obf_code = []

        regindex = self.insn.operands[1].reg
        reg = self.insn.reg_name(regindex)
        #print(reg)

        print("Find danger! %s\t%s"%(self.insn.mnemonic, self.insn.op_str))
        self.obf_code.append("\t%s\t%s,%d" % ("sub", reg, insn_imm[0]))
        self.obf_code.append("\t%s\t%s,%d" % ("sub", reg, insn_imm[1]))
        
        return 

    def cmp_obf(self, insn_imm):
        #obf_code = []

        regindex = self.insn.operands[1].reg
        reg = self.insn.reg_name(regindex)
            
        print("Find danger! %s\t%s"%(self.insn.mnemonic, self.insn.op_str))
        '''
        cmp ebx, 0xc3
        ==>
        push eax
        mov eax, 0xc0
        add eax, 0x3
        cmp ebx, eax
        pop eax
        '''
        temp_teg = "ebx" if reg == "eax" else "eax"
        self.obf_code.append("\t%s\t%s" % ("push", temp_teg))
        self.obf_code.append("\t%s\t%s,%d" % ("mov", temp_teg, insn_imm[0]))
        self.obf_code.append("\t%s\t%s,%d" % ("add", temp_teg, insn_imm[1]))
        self.obf_code.append("\t%s\t%s,%s" % ("cmp", reg, temp_teg))
        self.obf_code.append("\t%s\t%s" % ("pop", temp_teg))

        return 
    
    def and_obf(self, insn_imm):
        #obf_code = []

        regindex = self.insn.operands[1].reg
        reg = self.insn.reg_name(regindex)

        print("Find danger! %s\t%s"%(self.insn.mnemonic, self.insn.op_str))
        '''
        and ebx, 0xc3
        ==>
        push eax
        mov eax, 0xc0
        add eax, 0x3
        and ebx, eax
        pop eax
        '''
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
            
        print("Find danger! %s\t%s"%(self.insn.mnemonic, self.insn.op_str))
        self.obf_code.append("\t%s\t%s,%d" % ("or", reg, insn_imm[0]))
        self.obf_code.append("\t%s\t%s,%d" % ("or", reg, insn_imm[1]))
        
        return
    
    def xor_obf(self, insn_imm):
        
        #obf_code = []

        regindex = self.insn.operands[1].reg
        reg = self.insn.reg_name(regindex)

        print("Find danger! %s\t%s"%(self.insn.mnemonic, self.insn.op_str))
        self.obf_code.append("\t%s\t%s,%d" % ("xor", reg, transImm[0]))
        self.obf_code.append("\t%s\t%s,%d" % ("xor", reg, transImm[1]))
            
        return

    def dispatch(self):
        
        logger.info(hex(self.addr) + self.original_code)
        #return self.original_code
        
        # 1. if instruction includes 0xc2,c3,ca,cb, the insn is dangerous, but except retn.
        if self.isInsnDanger() == False:
            
            return self.original_code
        
        logger.warning("%s is danger!" % self.original_code)
            
        # 2. Insn is danger, and judge if imm includes ...
        insn_imm = self.isImmDanger()
        
        # 2.1. imm is safty, so add nop
        if insn_imm == []:
            
            # the number of nop is important!!!
            self.obf_code.append("\t%s\t%s%d" % ("jmp", ". + ", 2+9))
            for i in range(9):
                self.obf_code.append("\tnop")
            self.obf_code.append(self.original_code)
                
            return "\n".join(self.obf_code)
        
        # 2.2. imm is danger
        logger.warning("%s imm danger!" % self.original_code)
        insn_type = self.insn.id
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
        
        return ASMConverter.intel_to_att("\n".join(self.obf_code))
        #return "\n".join(self.obf_code)
        


        
        
        
        
