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
    newly_deobfuscated_count = sum(map(lambda deobfuscator: deobfuscator.count, deobfuscator_list))
    if newly_deobfuscated_count == 0:
        print "No new deobfuscations for now :)"
    else:
        print "Deobfuscated %d functions. You might want to run another round of deobfuscation." % (newly_deobfuscated_count)
