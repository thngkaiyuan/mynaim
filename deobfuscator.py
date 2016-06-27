from idc import *
from idautils import *
import utils

class Deobfuscator(object):
    def __init__(self):
        self.name = '<unset name>'
        self.type = '<unset type>'
        self.comment = '<unset comment>'
        self.count = 0

    def can_deobfuscate(self, function_address):
        raise Exception('[!] Unimplemented can_deobfuscate for', self.name)

    def label_function(self, function_address):
        # Set repeatable function comment
        SetFunctionCmt(function_address, self.comment, 1)

        # Rename function
        self.count = utils.set_name(function_address, self.name, self.count)

    def label_callers(self, function_address):
        for caller_address in CodeRefsTo(function_address, 0):
            self.label_caller(function_address, caller_address)

    def label_caller(self, function_address, caller_address):
        raise Exception('[!] Unimplemented label_caller for', self.name)
