from idc import *
import config

class functions():
    def __init__(self):
        self.addr = config.TEXT_START - 1

    def __iter__(self):
        return self

    def next(self):
        self.addr = NextFunction(self.addr)
        if self.addr <= config.TEXT_END:
            return self.addr
        raise StopIteration()

def set_name(address, original_name, counter):
    if original_name in GetFunctionName(address):
        return counter
    name = "%s_%d" % (original_name, counter)
    while not MakeNameEx(address, name, SN_NOCHECK):
        counter += 1
        name = "%s_%d" % (original_name, counter)
    return counter + 1

def get_instr_bytes(address):
        return GetManyBytes(address, ItemSize(address)).encode("hex")
