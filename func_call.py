from idc import *
from idautils import *
from deobfuscator import Deobfuscator
import idaapi
import utils
import config
import sys

sys.path.append(config.PYEMU_PATH)
from PyEmu import *

class FnCall(Deobfuscator):

    def __init__(self, emu):
        super(FnCall, self).__init__()
        self.name = "obfuscated_fn_call"
        self.type = "function call"
        self.comment = "Does a function call according to the previous arguments"
        self.fn_pushes_map = {}
        if emu:
            self.emu = emu
        else:
            self.emu = IDAPyEmu()
            self.emu.steps_taken = 0
            self.emu.found_addr = None
            self.emu.original_esp = self.emu.get_register("ESP")
            self.emu.original_ebp = self.emu.get_register("EBP")
            textstart = config.TEXT_START
            textend = config.TEXT_END

            print "[*] Loading text section bytes into memory"
            currenttext = textstart
            while currenttext <= textend:
                self.emu.set_memory(currenttext, GetOriginalByte(currenttext), size=1)
                currenttext += 1
            print "[*] Text section loaded into memory"

    def can_deobfuscate(self, function_address):
        try:
            # Check just one CodeRef
            caller_address = CodeRefsTo(function_address, 1).next()

            # There should be at least one constant push before the call
            prev_address = PrevHead(caller_address)
            if GetMnem(caller_address) != 'call' or GetMnem(prev_address) != 'push' or GetOpType(prev_address, 0) != 5:
                return False

            # The function should not call another function or branch and it must use the retn instruction
            if (self.mnem_in_function(['call', 'cmp', 'jz', 'jnz', 'jne', 'je', 'jg', 'jle', 'jl', 'jge'], function_address, caller_address) or
                not self.mnem_in_function(['retn'], function_address, caller_address)):
                return False

            # There must be a matching number of constant pushes before the function call and it must return to a different address
            start_address, num_of_pushes = self.matching_num_of_const_pushes(function_address, caller_address)
            if not start_address or not self.returns_to_different_address(start_address, function_address, NextHead(caller_address)):
                return False

            # Looks matching!
            # Store the number of pushes for use later
            self.fn_pushes_map[function_address] = num_of_pushes
            return True
        except:
            return False

    def label_caller(self, function_address, caller_address):
        # Set comment to show caller at every xref
        start_address = caller_address
        push_addresses = []
        i = self.fn_pushes_map[function_address]
        while i > 0:
            start_address = PrevHead(start_address)
            push_addresses.append(start_address)
            i -= 1
        final_addr = self.get_final_addr(start_address, function_address)

        MakeComm(caller_address, "call %s" % (Name(final_addr) if Name(final_addr) else '0x' + hex(final_addr)))
        MakeCode(final_addr)
        idaapi.add_cref(caller_address, final_addr, idaapi.fl_CN)

        comment = '(irrelevant) argument for obfuscated function call'
        for push_address in push_addresses:
            MakeComm(push_address, comment)

    def retn_handler(self, emu, opcode, eip, op1, op2, op3):
        emu.should_stop_execution = True
        emu.found_addr = eip

    def validate_callee(self, emu, opcode, eip, op1, op2, op3):
        if eip != emu.func_addr:
            emu.should_stop_execution = True

    def mnem_found_handler(self, emu, opcode, eip, op1, op2, op3):
        emu.should_stop_execution = True
        emu.found_mnem = True

    def retn_operand_found_handler(self, emu, opcode, eip, op1, op2, op3):
        emu.should_stop_execution = True
        emu.found_operand = op1

    def call_handler(self, emu, opcode, eip, op1, op2, op3):
        emu.called = True
        emu.should_stop_execution = True

    def execute_emu(self, steps, return_attr=None):
        self.emu.steps_taken = 0
        while (not self.emu.should_stop_execution and
        self.emu.steps_taken < config.MAX_STEPS and
        config.TEXT_START <= self.emu.get_register("EIP") <= config.TEXT_END):
            try:
                if config.IS_DEBUGGING:
                    self.emu.execute()
                else:
                    with utils.SilenceStdStreams():
                        self.emu.execute()
                self.emu.steps_taken += 1
            except:
                break
        if return_attr:
            return getattr(self.emu, return_attr)

    def execute_until_call(self, steps, function_address):
        original_mnemonic_handlers = self.emu.mnemonic_handlers.copy()
        self.emu.called = False
        self.emu.set_mnemonic_handler('call', self.call_handler)
        self.execute_emu(steps)
        if not self.emu.called:
            raise Exception("Callee 0x%x was not called" % (function_address))
        self.emu.should_stop_execution = False
        self.emu.mnemonic_handlers = original_mnemonic_handlers

    def mnem_in_function(self, mnemonic_list, function_address, caller_address):
        self.reset_emu_at(caller_address)
        self.execute_until_call(4, function_address)
        self.emu.found_mnem = False
        for mnemonic in mnemonic_list:
            self.emu.set_mnemonic_handler(mnemonic, self.mnem_found_handler)
        return self.execute_emu(config.MAX_STEPS, 'found_mnem')

    def get_retn_operand(self, function_address, caller_address):
        self.reset_emu_at(caller_address)
        self.execute_until_call(4, function_address)
        self.emu.found_operand = None
        self.emu.set_mnemonic_handler('retn', self.retn_operand_found_handler)
        return self.execute_emu(config.MAX_STEPS, 'found_operand')

    def matching_num_of_const_pushes(self, function_address, caller_address):
        retn_operand = self.get_retn_operand(function_address, caller_address)
        if retn_operand is None:
            raise Exception('retn operand not found')
        num_of_pushes = retn_operand / 4
        addr = caller_address
        i = num_of_pushes
        while i > 0:
            addr = PrevHead(addr)
            if GetMnem(addr) != 'push' or GetOpType(addr, 0) != 5:
                return False
            i -= 1
        return addr, num_of_pushes

    def returns_to_different_address(self, start_address, function_address, original_return_address):
        return self.get_final_addr(start_address, function_address) not in (None, original_return_address)

    def reset_emu_at(self, start_address):
        self.emu.set_register("EIP", start_address)
        self.emu.set_register("ESP", self.emu.original_esp)
        self.emu.set_register("EBP", self.emu.original_ebp)
        self.emu.mnemonic_handlers.clear()
        self.emu.should_stop_execution = False

    def get_final_addr(self, start_address, func_address):
        self.reset_emu_at(start_address)
        self.emu.found_addr = None
        self.emu.func_addr = func_address
        self.emu.set_mnemonic_handler("call", self.validate_callee)
        self.emu.set_mnemonic_handler("retn", self.retn_handler)
        return self.execute_emu(config.MAX_STEPS, 'found_addr')
