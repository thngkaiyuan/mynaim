from idc import *
from idautils import *
import idaapi
import utils
import config
import sys

sys.path.append(config.PYEMU_PATH)
from PyEmu import *

class FnCall():
        
        def __init__(self):
                self.type = "function call"
                self.emu = IDAPyEmu()
                self.emu.steps_taken = 0
                self.emu.found_addr = None
                self.original_esp = self.emu.get_register("ESP")
                self.original_ebp = self.emu.get_register("EBP")
                textstart = config.TEXT_START
                textend = config.TEXT_END
                
                print "[*] Loading text section bytes into memory"
                currenttext = textstart
                while currenttext <= textend:
                    self.emu.set_memory(currenttext, GetOriginalByte(currenttext), size=1)
                    currenttext += 1
                print "[*] Text section loaded into memory"
                
                # Set up our memory access handler
                self.emu.set_mnemonic_handler("ret", self.ret_handler)
                self.emu.set_mnemonic_handler("retn", self.ret_handler)
                self.emu.set_mnemonic_handler("call", self.call_handler)

        def ret_handler(self, emu, opcode, eip, op1, op2, op3):
            emu.steps_taken = config.MAX_STEPS + 1
            emu.found_addr = eip

        def call_handler(self, emu, opcode, eip, op1, op2, op3):
            emu.call_count += 1
            if (emu.call_count == 1 and eip != emu.func_addr) or emu.call_count > 1:
                emu.steps_taken = config.MAX_STEPS + 1

        def can_deobfuscate(self, address):
                try:
                        # Just check one CodeRef
                        ref_addr = CodeRefsTo(address, 1).next()
                        next_addr = NextHead(ref_addr)
                        prev_addr = PrevHead(ref_addr)
                        prev1_addr = PrevHead(prev_addr)
                        prev2_addr = PrevHead(prev1_addr)
                        return (
                                GetMnem(prev_addr) == 'push' and
                                GetOpType(prev_addr, 0) == 5 and
                                GetMnem(prev1_addr) == 'push' and
                                GetOpType(prev1_addr, 0) == 5 and
                                GetMnem(prev2_addr) == 'push' and
                                self.get_final_addr(prev1_addr, address) not in (None, next_addr)
                                )
                except:
                        return False
        
        def deobfuscate(self, address):
                # Set repeatable function comment
                fn_comment = "Does a function call according to the previous arguments"
                SetFunctionCmt(address, fn_comment, 1)
                
                # Set comment to show callee at every xref
                for ref_addr in CodeRefsTo(address, 1):
                        prev_addr = PrevHead(ref_addr)
                        prev1_addr = PrevHead(prev_addr)
                        prev2_addr = PrevHead(prev1_addr)
                        final_addr = self.get_final_addr(prev1_addr, address)
                        
                        MakeComm(ref_addr, "obfuscated function call to 0x%x" % (final_addr))
                        MakeCode(final_addr)
                        idaapi.add_cref(ref_addr, final_addr, idaapi.fl_CN)

                        comment = '(you may ignore) argument for obfuscated function call'
                        MakeComm(prev_addr, comment)
                        MakeComm(prev1_addr, comment)
                        MakeComm(prev2_addr, comment)

        def get_final_addr(self, start_address, func_address):
                self.emu.set_register("EIP", start_address)
                self.emu.set_register("ESP", self.original_esp)
                self.emu.set_register("EBP", self.original_ebp)
                self.emu.steps_taken = 0
                self.emu.found_addr = None
                self.emu.call_count = 0
                self.emu.func_addr = func_address
                while (self.emu.steps_taken < config.MAX_STEPS and
                        config.TEXT_START <= self.emu.get_register("EIP") <= config.TEXT_END):
                    try:
                        self.emu.execute()
                        self.emu.steps_taken += 1
                    except:
                        return None
                return self.emu.found_addr

