from idc import *
from idautils import *
import utils

# Define deobfuscators
from reg_push import RegPush
from func_call import FnCall
deobfuscator_list = (RegPush(), FnCall())

# Main deobfuscation function
def deobfuscate():
        for fn_address in utils.functions():
                for fn_deobfuscator in deobfuscator_list:
                        if fn_deobfuscator.can_deobfuscate(fn_address):
                                print "Deobfuscating a %s at %x" % (fn_deobfuscator.type, fn_address)
                                fn_deobfuscator.deobfuscate(fn_address)
                                print "Done"
                                break
        print "Deobfuscation complete. You are advised to run at least 2 rounds of deobfuscation to deobfuscate the newfound functions."
