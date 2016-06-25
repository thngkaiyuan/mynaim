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

def get_instr_bytes(address):
        return GetManyBytes(address, ItemSize(address)).encode("hex")
