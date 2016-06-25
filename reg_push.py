from idc import *
from idautils import *
import utils

class RegPush():
        
        def __init__(self):
                self.type = "register push function"
                self.op_map = op_reg = {
                        '4Fh':'eax',
                        '50h':'ecx',
                        '51h':'edx',
                        '52h':'ebx',
                        '54h':'ebp',
                        '55h':'esi',
                        '56h':'edi'
                        }

        def can_deobfuscate(self, address):
                return utils.get_instr_bytes(address) in ["837c24044f"]
        
        def deobfuscate(self, address):
                # Set repeatable function comment
                fn_comment = "Does a register push according to the previous argument"
                SetFunctionCmt(address, fn_comment, 1)

                # Set comment to show register push type at every xref
                for call_address in CodeRefsTo(address, 1):
                        push_address = PrevHead(call_address)
                        operand = self.get_operand(push_address)
                        if operand not in self.op_map:
                            print '[!] Unable to deobfuscate non-constant register push at 0x%x' % (push_address)
                            continue
                        register = self.op_map[operand]
                        comment1 = "argument for next instruction"
                        MakeComm(push_address, comment1)
                        comment2 = "push %s" % (register)
                        MakeComm(call_address, comment2)

        def get_operand(self, address):
                return GetOpnd(address, 0)

