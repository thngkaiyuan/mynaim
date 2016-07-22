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

def hash_and_xor_module_name(string, xor_key=0xe4289257):
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

def hash_and_xor_func_name(name, xor_key=0xe4289257):
    hsh = 0
    for c in name:
        hsh = utils.rol(hsh, 7)
        hsh ^= ord(c)
    return hex(hsh ^ xor_key)

def get_api_name_from_magic_value(magic_value, img_base=None):
    if not img_base:
        img_base = SegStart(ScreenEA())
    ea = get_api_address_from_magic_value(magic_value, img_base)
    print GetTrueName(ea)

def get_api_address_from_magic_value(magic_value, img_base=None):
    if not img_base:
        img_base = SegStart(ScreenEA())
    decrypted = decrypt_at_pos(4, magic_value + 4, img_base)
    offset = 0
    for i, b in enumerate(decrypted):
        offset += b << (i*8)
    ea = offset + img_base
    return DbgDword(ea) ^ 0xF1C9407D

def decrypt_at_pos(size, offset_from_img_base, img_base=None):
    if not img_base:
        img_base = SegStart(ScreenEA())
    decrypted = bytearray()
    special_val_1 = 0xD2EDE5B0
    special_val_2 = 0xA175B260
    ea = img_base + offset_from_img_base
    lower_bound = img_base + 0x85000
    byte_offset = ea - lower_bound
    if byte_offset < 0:
        print "Negative offset detected."
        return
    dword_offset = byte_offset >> 2
    key = (special_val_1 + (dword_offset * special_val_2)) & 0xffffffff
    for i in range(size):
        rotate_amt = ((byte_offset & 0x3) << 3) & 0xff
        byte_key = utils.ror(key, rotate_amt) & 0xff
        byte_offset += 1
        if (byte_offset & 0x3) == 0:
            key += special_val_2
        dec_byte = DbgByte(ea + i) ^ byte_key
        decrypted.append(dec_byte)
    return decrypted
