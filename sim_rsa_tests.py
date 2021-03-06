# Copyright lowRISC contributors.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

"""Runs RSA operations based on bignum binary.

Runs RSA operations based on the primitives contained in the binary blob of
the generic bignum library. Hence these are wrappers around mainly modexp and
montmul operations.
"""

from bignum_lib.machine import Machine
from bignum_lib.sim_helpers import *

# Switch to True to get a full instruction trace
ENABLE_TRACE_DUMP = False

# Configuration for the statistics prints
STATS_CONFIG = {
    'instruction_histo_sort_by': 'key',
}

BN_WORD_LEN = 256
BN_LIMB_LEN = 32
BN_MASK = 2**BN_WORD_LEN-1
BN_LIMB_MASK = 2**BN_LIMB_LEN-1
BN_MAX_WORDS = 16  # Max number of bn words per val (for 4096 bit words)
DMEM_DEPTH = 1024
PROGRAM_HEX_FILE = 'hex/dcrypto_bn.hex'

# pointers to dmem areas according to calling conventions for bignum lib
DMEMP_IN = 38
DMEMP_MOD = 4
DMEMP_RR = 22
DMEMP_EXP = 54
DMEMP_OUT = 71
DMEMP_DINV = 20
DMEMP_BLINDING = 21
DMEMP_BIN = 87
DMEMP_BOUT = 103

DMEM_LOC_IN_PTRS = 0
DMEM_LOC_SQR_PTRS = 1
DMEM_LOC_MUL_PTRS = 2
DMEM_LOC_OUT_PTRS = 3

# RSA private keys
RSA_D = {}
# noinspection LongLine
RSA_D[768] = 0xaeadb950258c1b5c9f42d33e7675df4546ab5ba6ceb972494e66c82431a7f961db12f2c132117b9023b0b9453f065da2d7350fddfc03df8d916b83f959ee671e1a209e8bf8f6e2b2f529714c2254cf7e97bc7024dd6d52fe17d9d6417b764001  # pylint: disable=line-too-long
# noinspection LongLine
RSA_D[1024] = 0x9a6d85f407a86d619a2f837bc8e3fb7cbdb5792e4826b7929c956ff5677698063bea9e7a106312136a4480869a95566fe0ba578c7ed4f87d95b8b1c9f88cc66ee57ba0afa04e4e84d797b95add32e52be580b3b2bf56ff01dce6a66c4a811d8fea4bed2408f467af0df2fd373f3125faee35b0db6611ff49e1e5ff1bccc30e09  # pylint: disable=line-too-long
# noinspection LongLine
RSA_D[2048] = 0x4e9d021fdf4a8b89bc8f14e26f15665a6770197fb9435668fbaaf326dbaddf6e7cb4a3d026bef3a3dc8fdf74f0895eca86312c3380ea291939ad329f142095c0401ba3a491f7eac1351687960a7696026ba2c0d38dc6324eaf8baedc4247c1856e5e94f252fa27e7222494eb67be1ee48291de710ab8231a02e7cc8206d22615549752cdf53f6dc6b97030bec588a6b065169c4c84e27a6ee9c7bdcf4527fc19c6231d2b88a2671fc2d6d3a079fbbfea38a8df4fbc9b8eee04b77c00d7951a03827ae841b8b1af7ff13089566d07115579dd680f82085ccc2447546886f1f03f5210ade4163316022162e32f5deb225b64b42922742429a94c668431ca9995f5  # pylint: disable=line-too-long

# RSA modulus
RSA_N = {}
# noinspection LongLine
RSA_N[768] = 0xb0dbed46d932f07cd42023d2355a8617db247236333bc2648ba4496e74fefad2820cc4123a4867e115cc94df441b4ec018ba461b512ce20fc03277ed5f8be5a300e63c2da7108953a82b337438f73600fddd5bbd7bc17ce175902b782d398569  # pylint: disable=line-too-long
# noinspection LongLine
RSA_N[1024] = 0xdf4eaf7345949834307e26ad4083f91721b04e1b0d6a44ce4e3e2e724c97df898a391025ae204cf23b20b2a510ddb26b624ea69f924ad98697cc70203b6a3263ca7f59fb57b6a999e9d02e0f1cd47d8ba0bd0fd2d53b1f11b46a94cf4f0a2b44e7fa6b2491b4821ff675b691c5a0f62fd5ff10739b34f67a8823a9423ca82491  # pylint: disable=line-too-long
# noinspection LongLine
RSA_N[2048] = 0x9cd7612e438e15becd739fb7f5864be395905c85194c1d2e2cef6e1fed75320f0ac1729f0c7850a299825390be642349757b0ceb2d6897d6afb1aa2ade5e9be3060df2acd9d71f506ec95debb4f0c0982304304610dcd46b57c730c306ddaf516e4041f810de491852b318ca4950a83acdb6947bdbf12d05ce570bbe3848bbc9b17636b8a8cce2075cc87bcfcff0faa3c5d73a5eb2f4bfeac2ed5116a2929c36a6860e24a56615e797225004ffc94db0bc27055e2cf7efdc5d58a13b6083b78cb7d0366d552e052363744a9737a77840ef3e66fdba6eb3724a21821f33ad620cf21ad26ab5a7f251691f38a5579ac58867e311a6534fb1e90741dee8df93a999  # pylint: disable=line-too-long

# RSA public exponent
EXP_PUB = 65537

ins_objects = []
dmem = []
inst_cnt = 0
cycle_cnt = 0
stats = init_stats()


# Helper functions
def bit_len(int_type):
    """Helper function returning the number of bits required to binary encode an integer."""
    length = 0
    while int_type:
        int_type >>= 1
        length += 1
    return length


def test_bit(int_type, offset):
    """Helper function indicationg if a specific bit in the bin representation of an int is set."""
    mask = 1 << offset
    return bool(int_type & mask)


def egcd(a, b):
    """Helper function to run the extended euclidian algorithm"""
    if a == 0:
        return b, 0, 1
    g, y, x = egcd(b % a, a)
    return g, x - (b // a) * y, y


def mod_inv(val, mod):
    """Helper function to compute a modular inverse"""
    g, x, _ = egcd(val, mod)
    if g != 1:
        raise Exception('modular inverse does not exist')
    return x % mod


def get_msg_val(msg):
    """Helper function to return a ascii encoded bignum value for a string"""
    msg_hex_str = ''.join(format(ord(x), '02x') for x in msg)
    msg_val = int(msg_hex_str, 16)
    return msg_val


def get_msg_str(val):
    """Helper function to return a string for an ascii bignum value"""
    hex_str = hex(val)
    ret = ''
    for i in range(2, len(hex_str), 2):
        ret += chr(int(hex_str[i:i+2], 16))
    return ret


# DMEM manipulation
def init_dmem():
    global dmem
    """Create the simulator side of dmem and init with zeros."""
    dmem = [0]*DMEM_DEPTH


def load_pointer(bn_words, p_loc, p_a, p_b, p_c):
    """Load pointers into 1st dmem word according to calling conventions"""
    pval = DMEMP_MOD
    pval += (DMEMP_DINV << BN_LIMB_LEN*1)
    pval += (DMEMP_RR << BN_LIMB_LEN*2)
    pval += (p_a << BN_LIMB_LEN*3)
    pval += (p_b << BN_LIMB_LEN*4)
    pval += (p_c << BN_LIMB_LEN*5)
    pval += (bn_words << BN_LIMB_LEN*6)
    pval += ((bn_words-1) << BN_LIMB_LEN*7)
    dmem[p_loc] = pval


def load_blinding(pubexp, rnd, pad1, pad2):
    """Load pointers into 1st dmem word according to calling conventions"""
    bval = pubexp
    bval += ((pad1 & BN_LIMB_MASK) << BN_LIMB_LEN*1)
    bval += (((pad1 >> BN_LIMB_LEN) & BN_LIMB_MASK) << BN_LIMB_LEN*2)
    bval += (((pad1 >> BN_LIMB_LEN*2) & BN_LIMB_MASK) << BN_LIMB_LEN*3)
    bval += ((rnd & BN_LIMB_MASK) << BN_LIMB_LEN*4)
    bval += (((rnd >> BN_LIMB_LEN) & BN_LIMB_MASK) << BN_LIMB_LEN*5)
    bval += ((pad2 & BN_LIMB_MASK) << BN_LIMB_LEN*6)
    bval += (((pad2 >> BN_LIMB_LEN) & BN_LIMB_MASK) << BN_LIMB_LEN*7)
    dmem[DMEMP_BLINDING] = bval


def load_full_bn_val(dmem_p, bn_val):
    """Load a full multi-word bignum value into dmem"""
    for i in range(0, BN_MAX_WORDS):
        dmem[dmem_p+i] = (bn_val >> (BN_WORD_LEN*i)) & BN_MASK


def get_full_bn_val(dmem_p, machine, bn_words=BN_MAX_WORDS):
    """Get a full multi-word bignum value form dmem"""
    bn_val = 0
    for i in range(0, bn_words):
        bn_val += machine.get_dmem(i+dmem_p) << (BN_WORD_LEN*i)
    return bn_val


def load_mod(mod):
    """Load the modulus in dmem at appropriate location according to calling conventions"""
    load_full_bn_val(DMEMP_MOD, mod)


# Program loading
def load_program():
    global ins_objects
    global ctx
    """Load binary executable from file"""
    insfile = open(PROGRAM_HEX_FILE)
    ins_objects, ctx = ins_objects_from_hex_file(insfile)
    insfile.close()


def dump_trace_str(trace_string):
    if ENABLE_TRACE_DUMP:
        print(trace_string)


# primitive access
def run_modload(bn_words):
    """Runs the modload primitive (modload).

    Other than it's name suggests this primitive computes RR and the
    montgomery inverse dinv. The modulus is actually directly loaded into dmem
    beforehand. This primitive has to be executed every time, dmem was cleared.
    """
    global dmem
    global inst_cnt
    global cycle_cnt
    global stats
    global ctx
    start_addr = 414
    stop_addr = 425
    load_pointer(bn_words, DMEM_LOC_IN_PTRS, DMEMP_IN, DMEMP_EXP, DMEMP_OUT)
    machine = Machine(dmem.copy(), ins_objects, start_addr, stop_addr, ctx=ctx)
    machine.stats = stats
    cont = True
    while cont:
        cont, trace_str, cycles = machine.step()
        dump_trace_str(trace_str)
        inst_cnt += 1
        cycle_cnt += cycles
    dmem = machine.dmem.copy()
    dinv_res = dmem[DMEMP_DINV]
    rr_res = get_full_bn_val(DMEMP_RR, machine, bn_words)
    return dinv_res, rr_res


def run_montmul(bn_words, p_a, p_b, p_out):
    """Runs the primitive for montgomery multiplication (mulx)"""
    global dmem
    global inst_cnt
    global cycle_cnt
    global stats
    global ctx
    start_addr = 172
    stop_addr = 190
    load_pointer(bn_words, DMEM_LOC_IN_PTRS, p_a, p_b, p_out)
    machine = Machine(dmem.copy(), ins_objects, start_addr, stop_addr, ctx=ctx)
    machine.stats = stats
    cont = True
    i = 0
    while cont:
        cont, trace_str, cycles = machine.step()
        i += 1
        dump_trace_str(trace_str)
        inst_cnt += 1
        cycle_cnt += cycles
    res = get_full_bn_val(DMEMP_OUT, machine, bn_words)
    dmem = machine.dmem.copy()
    return res


def run_montout(bn_words, p_a, p_out):
    """Runs the primitive for back-transformation from the montgomery domain (mul1)"""
    global dmem
    global inst_cnt
    global cycle_cnt
    global stats
    global ctx
    start_addr = 236
    stop_addr = 239
    load_pointer(bn_words, DMEM_LOC_IN_PTRS, p_a, 0, p_out)
    machine = Machine(dmem.copy(), ins_objects, start_addr, stop_addr, ctx=ctx)
    machine.stats = stats
    cont = True
    while cont:
        cont, trace_str, cycles = machine.step()
        dump_trace_str(trace_str)
        inst_cnt += 1
        cycle_cnt += cycles
    res = get_full_bn_val(DMEMP_OUT, machine, bn_words)
    dmem = machine.dmem.copy()
    return res


def run_modexp(bn_words, exp):
    """Runs the primitive for modular exponentiation (modexp)"""
    global dmem
    global inst_cnt
    global cycle_cnt
    global stats
    global ctx
    start_addr = 303
    stop_addr = 337
    load_full_bn_val(DMEMP_EXP, exp)
    load_pointer(bn_words, DMEM_LOC_IN_PTRS, DMEMP_IN, DMEMP_RR, DMEMP_IN)
    load_pointer(bn_words, DMEM_LOC_SQR_PTRS, DMEMP_OUT, DMEMP_OUT, DMEMP_OUT)
    load_pointer(bn_words, DMEM_LOC_MUL_PTRS, DMEMP_IN, DMEMP_OUT, DMEMP_OUT)
    load_pointer(bn_words, DMEM_LOC_OUT_PTRS, DMEMP_OUT, DMEMP_EXP, DMEMP_OUT)
    machine = Machine(dmem.copy(), ins_objects, start_addr, stop_addr, ctx=ctx)
    machine.stats = stats
    cont = True
    while cont:
        cont, trace_str, cycles = machine.step()
        dump_trace_str(trace_str)
        inst_cnt += 1
        cycle_cnt += cycles
    res = get_full_bn_val(DMEMP_OUT, machine, bn_words)
    dmem = machine.dmem.copy()
    return res

def run_modexp_blinded(bn_words, exp):
    """Runs the primitive for modular exponentiation (modexp)"""
    global dmem
    global inst_cnt
    global cycle_cnt
    global stats
    global ctx
    start_addr = 338
    stop_addr = 413
    load_full_bn_val(DMEMP_EXP, exp)
    load_pointer(bn_words, DMEM_LOC_IN_PTRS, DMEMP_IN, DMEMP_RR, DMEMP_IN)
    load_pointer(bn_words, DMEM_LOC_SQR_PTRS, DMEMP_OUT, DMEMP_OUT, DMEMP_OUT)
    load_pointer(bn_words, DMEM_LOC_MUL_PTRS, DMEMP_IN, DMEMP_OUT, DMEMP_OUT)
    load_pointer(bn_words, DMEM_LOC_OUT_PTRS, DMEMP_OUT, DMEMP_EXP, DMEMP_OUT)
    load_blinding(EXP_PUB,0,0,0)
    machine = Machine(dmem.copy(), ins_objects, start_addr, stop_addr, ctx=ctx)
    machine.stats = stats
    cont = True
    while cont:
        cont, trace_str, cycles = machine.step()
        dump_trace_str(trace_str)
        inst_cnt += 1
        cycle_cnt += cycles
    res = get_full_bn_val(DMEMP_OUT, machine, bn_words)
    dmem = machine.dmem.copy()
    return res


# Primitive wrappers
def modexp_word(bn_words, inval, exp):
    """Performs a full modular exponentiation with word sized exponent using several primitives.

    Performs a full modular exponentiation with a "small" exponent fitting into a single bignum
    word.
    After calculating constants (RR and dinv) the primitive for montgomery multiplication is wrapped
    with a standard square-and-multiply algorithm.
    Finally performs back-transformation from montgomery domain with the mul1 primitive
    """
    load_full_bn_val(DMEMP_IN, inval)
    run_montmul(bn_words, DMEMP_IN, DMEMP_RR, DMEMP_OUT)
    run_montmul(bn_words, DMEMP_IN, DMEMP_RR, DMEMP_IN)
    exp_bits = bit_len(exp)
    for i in range(exp_bits-2, -1, -1):
        run_montmul(bn_words, DMEMP_OUT, DMEMP_OUT, DMEMP_OUT)
        if test_bit(exp, i):
            run_montmul(bn_words, DMEMP_IN, DMEMP_OUT, DMEMP_OUT)
    res = run_montout(bn_words, DMEMP_OUT, DMEMP_OUT)
    return res


# tests
# noinspection PyPep8Naming
def check_rr(mod, rr_test):
    """Check if RR calculated with simulator matches a locally computed one"""
    R = 1 << bit_len(mod)
    RR = R*R % mod
    assert rr_test == RR, "Mismatch of local and machine calculated RR"


def check_dinv(dinv_test, r_mod, mod):
    """Check if montgomery modular inverse from simulator matches a locally computed one"""
    mod_i = mod_inv(mod, r_mod)
    dinv = (-mod_i) % r_mod
    assert dinv_test == dinv, "Mismatch of local and machine calculated montgomery constant"


def check_modexp(modexp_test, inval, exp, mod):
    """Check if modular exponentiation result from simulator matches locally computed result"""
    modexp_cmp = (inval**exp) % mod
    assert modexp_test == modexp_cmp,\
        "Mismatch of local and machine calculated modular exponentiation result"


def check_decrypt(msg_test, msg):
    """Check if decrypted string matches the original one"""
    assert msg_test == msg, "Mismatch between original and decrypted message"


# RSA
def rsa_encrypt(mod, bn_words, msg):
    """RSA encrypt"""
    #init_dmem()
    load_mod(mod)
    dinv, rr = run_modload(bn_words)
    check_rr(mod, rr)
    check_dinv(dinv, 2**BN_WORD_LEN, mod)
    load_full_bn_val(DMEMP_IN, msg)
    enc = modexp_word(bn_words, msg, EXP_PUB)
    check_modexp(enc, msg, EXP_PUB, mod)
    return enc


def rsa_decrypt(mod, bn_words, priv_key, enc):
    """RSA decrypt"""
    init_dmem()
    load_mod(mod)
    run_modload(bn_words)
    load_full_bn_val(DMEMP_IN, enc)
    decrypt = run_modexp(bn_words, priv_key)
    #decrypt = run_modexp_blinded(bn_words, priv_key)
    return decrypt

def main():
    """main"""
    global inst_cnt
    global cycle_cnt
    global stats
    global ctx
    init_dmem()
    load_program()

    msg_str = 'Hello bignum, can you encrypt and decrypt this for me?'
    msg = get_msg_val(msg_str)

    tests = [
        ('enc', 768),
        ('dec', 768),
        ('enc', 1024),
        ('dec', 1024),
        ('enc', 2048),
        ('dec', 2048),
    ]
    tests_results = []

    for i in range(len(tests)):
        test = tests[i]
        test_op, test_width = test
        print_test_headline(i+1, len(tests), str(test))
        test_results = {
            'inst_cnt': 0,
            'cycle_cnt': 0,
            'stats': {},
        }
        # reset global counter variables
        inst_cnt = 0
        cycle_cnt = 0
        stats = init_stats()

        if test_op == 'enc':
            enc = rsa_encrypt(RSA_N[test_width], test_width // 256, msg)
            #print('encrypted message: ' + hex(enc))
        elif test_op == 'dec':
            decrypt = rsa_decrypt(RSA_N[test_width], test_width // 256,
                                  RSA_D[test_width], enc)
            check_decrypt(msg, decrypt)
            #print('decrypted message: ' + get_msg_str(decrypt))
        else:
            assert True

        test_results['inst_cnt'] = inst_cnt
        test_results['cycle_cnt'] = cycle_cnt
        test_results['stats'] = stats

        tests_results.append(test_results)

        dump_stats(stats, STATS_CONFIG)

        print("\n\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Cancelled by user request.")
