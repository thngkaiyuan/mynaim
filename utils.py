from idc import *
import config
import os
import sys

class SilenceStdStreams(object):
    def __init__(self):
        devnull = open(os.devnull, 'w')
        self._stdout = devnull
        self._stderr = devnull

    def __enter__(self):
        self.old_stdout, self.old_stderr = sys.stdout, sys.stderr
        self.old_stdout.flush(); self.old_stderr.flush()
        sys.stdout, sys.stderr = self._stdout, self._stderr

    def __exit__(self, exc_type, exc_value, traceback):
        self._stdout.flush(); self._stderr.flush()
        sys.stdout = self.old_stdout
        sys.stderr = self.old_stderr

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
    while not MakeNameEx(address, name, SN_NOCHECK | SN_NOWARN):
        counter += 1
        name = "%s_%d" % (original_name, counter)
    return counter + 1

def get_instr_bytes(address):
        return GetManyBytes(address, ItemSize(address)).encode("hex")
