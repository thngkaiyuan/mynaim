from idc import *
from idautils import *
import utils
import config

# Define deobfuscators
from reg_push import RegPush
from func_call import FnCall

deobfuscator_list = ()
def init(emu=None):
    global deobfuscator_list
    config.TEXT_START, config.TEXT_END = utils.get_seg_start_and_end()
    deobfuscator_list = (RegPush(), FnCall(emu))

# Main deobfuscation function
def deobfuscate():
    for fn_address in utils.functions():
            for fn_deobfuscator in deobfuscator_list:
                    if fn_deobfuscator.can_deobfuscate(fn_address):
                            print "Deobfuscating a %s at 0x%x" % (fn_deobfuscator.type, fn_address)
                            fn_deobfuscator.label_function(fn_address)
                            fn_deobfuscator.label_callers(fn_address)
                            print "Done"
                            break
    deobfuscated_count = sum(map(lambda deobfuscator: deobfuscator.count, deobfuscator_list))
    print "Deobfuscated a total of %d functions. You might want to run another round of deobfuscation." % (deobfuscated_count)

def hash_and_xor(string, xor_key=0xe4289257):
    hsh = 0
    for c in string:
        x = 0
        if ord(c) < 0x5b:
            x += 1
        if ord(c) < 0x41:
            x -= 1
        x = x << 5
        hsh = utils.rol(hsh, 7)
        hsh = hsh ^ (ord(c) + x)
    return hex(hsh ^ xor_key)
