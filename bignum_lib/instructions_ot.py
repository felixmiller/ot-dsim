# Copyright lowRISC contributors.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

from . machine import *


def _get_imm(asm_str):
    """return int for immediate string and check proper formatting (e.g "#42")"""
    if len(asm_str.split()) > 1:
        raise SyntaxError('Unexpected separator in immediate')
    if not asm_str.isdigit():
        raise SyntaxError('Immediate not a number')
    return int(asm_str)


def _get_limb(asm_str):
    """returns limb for immediate string and check proper formatting (e.g."*5")"""
    if len(asm_str.split()) > 1:
        raise SyntaxError('Unexpected separator in limb reference')
    if not asm_str.startswith('*'):
        raise SyntaxError('Missing \'*\' character at start of limb reference')
    if not asm_str[1:].isdigit():
        raise SyntaxError('limb reference not a number')
    return int(asm_str[1:])


def _get_index_imm(asm_str):
    """returns the index from an immediate index notation (e.g "[42]")"""
    if not asm_str.startswith('['):
        raise SyntaxError('Missing \'[\' character at start of index notation')
    if not asm_str.endswith(']'):
        raise SyntaxError('Missing \']\' character at end of index notation')
    return _get_imm(asm_str[1:-1].strip())


def _get_single_reg(asm_str):
    """returns a single register from string and check proper formatting (e.g "r5")"""
    if len(asm_str.split()) > 1:
        raise SyntaxError('Unexpected separator in reg reference')
    if not asm_str.lower().startswith('r'):
        raise SyntaxError('Missing \'r\' character at start of reg reference')
    if not asm_str[1:].isdigit():
        raise SyntaxError('reg reference not a number')
    return int(asm_str[1:])


def _get_single_reg_with_hw_sel(asm_str):
    """returns a single register from string and check proper formatting (e.g "r5")"""
    if len(asm_str.split()) > 1:
        raise SyntaxError('Unexpected separator in reg reference')
    if not asm_str.lower().startswith('r'):
        raise SyntaxError('Missing \'r\' character at start of reg reference')
    if not (asm_str.lower().endswith('u') or asm_str.lower().endswith('l')):
        raise SyntaxError('Missing \'L\' or \'U\' at end of reg reference')
    if not asm_str[1:-1].isdigit():
        raise SyntaxError('reg reference not a number')
    if asm_str[-1].lower() == 'u':
        hw_sel = 'upper'
    if asm_str[-1].lower() == 'l':
        hw_sel = 'lower'
    return int(asm_str[1:-1]), hw_sel


def _get_single_limb(asm_str):
    """returns a single limb with a potential increment (e.g "*6++" or "*7")"""
    if len(asm_str.split()) > 1:
        raise SyntaxError('Unexpected separator in limb reference')
    if not asm_str.startswith('*'):
        raise SyntaxError('Missing \'*\' character at start of limb reference')
    if asm_str.endswith('++'):
        inc = True
        limb = asm_str[1:-2]
    else:
        inc = False
        limb = asm_str[1:]
    if not limb.isdigit():
        raise SyntaxError('limb reference not a number')
    return int(limb), inc


def _get_single_reg_and_index_imm(asm_str):
    """decode a single reg and an immediate index (e.g. "r15, [#7]")"""
    substr = asm_str.split(',')
    if len(substr) != 2:
        raise SyntaxError('Syntax error in parameter set. Expected register and indexed immediate')
    reg = _get_single_reg(substr[0].strip())
    idx = _get_index_imm(substr[1].strip())
    return reg, idx


def _get_double_limb(asm_str):
    """decode a double limb notation (e.g. "*6++, *8")"""
    substr = asm_str.split(',')
    if len(substr) != 2:
        raise SyntaxError('Syntax error in parameter set. Expected two limb references')
    limbl, incl = _get_single_limb(substr[0].strip())
    limbr, incr = _get_single_limb(substr[1].strip())
    return limbl, incl, limbr, incr


def _get_double_reg(asm_str):
    """decode a double reg notation without shift (e.g. "r1, r2")"""
    substr = asm_str.split(',')
    if len(substr) != 2:
        raise SyntaxError('Syntax error in parameter set. Expected two reg references')
    regl = _get_single_reg(substr[0].strip())
    regr = _get_single_reg(substr[1].strip())
    return regl, regr


def _get_double_reg_with_imm(asm_str):
    """decode a double reg with immediate (e.g. "r3, r5, #254")"""
    substr = asm_str.split(',')
    if len(substr) != 3:
        raise SyntaxError('Syntax error in parameter set. Expected two reg references and immediate')
    rd = _get_single_reg(substr[0].strip())
    rs = _get_single_reg(substr[1].strip())
    imm = _get_imm(substr[2].strip())
    return rd, rs, imm


def _get_triple_reg(asm_str):
    """decode a triple reg notation without shift (e.g. "r1, r2, r3")"""
    substr = asm_str.split(',')
    if len(substr) != 3:
        raise SyntaxError('Syntax error in parameter set. Expected two reg references')
    rd = _get_single_reg(substr[0].strip())
    rs1 = _get_single_reg(substr[1].strip())
    rs2 = _get_single_reg(substr[2].strip())
    return rd, rs1, rs2


def _get_single_shifted_reg(asm_str):
    """decode a reg in (possible) shift notation (e.g. "r4 >> 128")"""
    if '>>' in asm_str:
        shift_type = 'right'
        substr = asm_str.split('>>')
    elif '<<' in asm_str:
        shift_type = 'left'
        substr = asm_str.split('<<')
    else:
        return _get_single_reg(asm_str), False, 0

    if len(substr) != 2:
        raise SyntaxError('Syntax error in parameter set in input shift notation. '
                          'Expected reg and shift immediate')

    reg = _get_single_reg(substr[0].strip())
    if substr[1].strip().lower().endswith('b'):
        shift_bytes = int(substr[1].strip()[:-1])
        if not shift_bytes.isdigit():
            raise SyntaxError('input shift immediate not a number')
        shift_bits = int(shift_bytes)*8
    else:
        shift_bits_str = substr[1].strip()
        if not shift_bits_str.isdigit():
            raise SyntaxError('input shift immediate not a number')
        shift_bits = int(shift_bits_str)

    return reg, shift_type, shift_bits


def _get_optional_flag_group_and_flag(asm_str):
    """decode a flag with optional flag group (e.g FGX.L or just M)"""
    substr = asm_str.split('.')
    if len(substr) > 2:
        raise SyntaxError('Malformed flag group and/or flag reference')
    if len(substr) == 2:
        if substr[0] == 'fgs':
            flag_group = 'standard'
        if substr[0] == 'fgx':
            flag_group = 'extension'
        else:
            raise SyntaxError('Flag group must be either FGS for standard or FGX for extension')
        flag = substr[1].lower()
    else:
        flag = asm_str.lower()
        flag_group = 'standard'
    if not (flag == 'c' or flag == 'm' or flag == 'l' or flag == 'z'):
        raise SyntaxError('Illegal flag reference')
    return flag_group, flag


def _get_single_reg_with_section(asm_str):
    """decode a reg with indication a upper/lower section (e.g. "r21l" or "r23u")"""
    if asm_str.endswith('u'):
        upper = True
    elif asm_str.endswith('l'):
        upper = False
    else:
        raise SyntaxError('Expecting \'u\' or \'l\' at end of register reference '
                          'with section indication')
    reg = _get_single_reg(asm_str[:-1].strip())
    return reg, upper


def _get_limb_section(asm_str):
    """decode the limb and the section (h or l) from limb (e.g "4l")"""
    if len(asm_str.split()) > 1:
        raise SyntaxError('Unexpected separator in limb reference')
    if asm_str.lower().endswith('l'):
        s = 0
    elif asm_str.lower().endswith('h'):
        s = 1
    else:
        raise SyntaxError('Expecting \'l\' or \'h\' at the end of limb section reference')
    limb = asm_str[:-1]
    if not limb.isdigit():
        raise SyntaxError('reg reference not a number')
    return int(limb), s


def _get_reg_with_limb(asm_str):
    """decode reference to 16 bit section of a register's limb (e.g "r15.3l")"""
    substr = asm_str.split('.')
    if len(substr) != 2:
        raise SyntaxError('Syntax error in parameter set. Expected reference to 16 bit '
                          'section of limb (e.g. \"r12.3l\")')
    reg = _get_single_reg(substr[0].strip())
    limb, s = _get_limb_section(substr[1].strip())
    return reg, limb, s


def _get_reg_limb_and_imm(asm_str):
    """decode the movi notation (reg+limb reference + immediate, e.g.: "r15.3l, #42" )"""
    substr = asm_str.split(',')
    if len(substr) != 2:
        raise SyntaxError('Syntax error in parameter set. Expected reg with limb + immediate')
    reg, limb, s = _get_reg_with_limb(substr[0].strip())
    imm = _get_imm(substr[1].strip())
    return reg, limb, s, imm


def _get_limb_with_paren(asm_str):
    """decode limb from a notation with parentheses as it is used in loop instructions (e.g "*0 (")"""
    if not asm_str.endswith('('):
        raise SyntaxError('Expecting \'(\'')
    return _get_limb(asm_str[:-1].strip())


def _get_imm_with_paren(asm_str):
    """decode immediate from a notation with parentheses as it is used in loop instructions (e.g "#4 (")"""
    if not asm_str.endswith('('):
        raise SyntaxError('Expecting \'(\'')
    return _get_imm(asm_str[:-1].strip())


def _get_loop_type_direct(asm_str):
    """decode loop type"""
    if asm_str.startswith('*'):
        return False
    elif asm_str.startswith('#'):
        return True
    else:
        raise SyntaxError('Syntax error in loop notation')

def _get_flag_group(asm_str):
    substr = asm_str.strip().lower()
    if substr == 'fgd':
        return 'default'
    elif substr == 'fgx':
        return 'extension'
    else:
        raise SyntaxError('Syntax error: invalid flag group')


def _get_three_regs_with_flag_group_and_shift(asm_str):
    """decode the full BN standard format with rd, rs1 and optional flag group and
    possibly shifted rs2 (e.g.: "r21, r5, r7 >> 128")"""
    substr = asm_str.split(',')
    if not (len(substr) == 3 or len(substr) == 4):
        raise SyntaxError('Syntax error in parameter set. Expected three reg references and optional flag group')
    rd = _get_single_reg(substr[0].strip())
    rs1 = _get_single_reg(substr[1].strip())
    rs2, shift_type, shift_bits = _get_single_shifted_reg(substr[2].strip())
    flag_group = 'standard'
    if len(substr) == 4:
        flag_group = _get_flag_group(substr[3].strip())
    return rd, rs1, rs2, shift_type, shift_bits, flag_group


def _get_three_regs_with_flag_group_and_flag(asm_str):
    """decode the full BN format with rd, rs1, optional flag group and flag"""
    substr = asm_str.split(',')
    if not (len(substr) == 4):
        raise SyntaxError('Syntax error in parameter set. Expected three reg references and flag')
    rd = _get_single_reg(substr[0].strip())
    rs1 = _get_single_reg(substr[1].strip())
    rs2 = _get_single_reg(substr[2].strip())
    flag_group, flag = _get_optional_flag_group_and_flag(substr[3].lower().strip())
    return rd, rs1, rs2, flag_group, flag


def _get_two_regs_with_shift(asm_str):
    """decode the BN format with rd, rs and possibly shifted rs (e.g.: "r21, r7 >> 128")"""
    substr = asm_str.split(',')
    if not (len(substr) == 2):
        raise SyntaxError('Syntax error in parameter set. Expected two reg references')
    rd = _get_single_reg(substr[0].strip())
    rs, shift_type, shift_bits = _get_single_shifted_reg(substr[1].strip())
    return rd, rs, shift_type, shift_bits


def _get_three_regs_with_two_half_word_sels(asm_str):
    """decode the BN format for half word mul with rd, rs1 and rs2 and half word selectors for the source regs"""
    substr = asm_str.split(',')
    if not (len(substr) == 3 or len(substr) == 4):
        raise SyntaxError('Syntax error in parameter set. Expected three reg references')
    rd = _get_single_reg(substr[0].strip())
    rs1, rs1_hw_sel = _get_single_reg_with_hw_sel(substr[1].strip())
    rs2, rs2_hw_sel = _get_single_reg_with_hw_sel(substr[2].strip())
    return rd, rs1, rs1_hw_sel, rs2, rs2_hw_sel

def _get_two_regs(asm_str):
    """decode the BN format with rd and rs"""
    substr = asm_str.split(',')
    if not (len(substr) == 2):
        raise SyntaxError('Syntax error in parameter set. Expected three reg references')
    rd = _get_single_reg(substr[0].strip())
    rs = _get_single_reg(substr[1].strip())
    return rd, rs

def _get_three_regs(asm_str):
    """decode the BN format with rd, rs1 and rs2 (e.g.: "r21, r5, r7")"""
    substr = asm_str.split(',')
    if not (len(substr) == 3):
        raise SyntaxError('Syntax error in parameter set. Expected three reg references')
    rd = _get_single_reg(substr[0].strip())
    rs1 = _get_single_reg(substr[1].strip())
    rs2 = _get_single_reg(substr[2].strip())
    return rd, rs1, rs2


def _get_two_regs_and_imm_with_flag_group(asm_str):
    """decode the BN immediate standard format with rd, rs and optional flag group"""
    substr = asm_str.split(',')
    if not (len(substr) == 3 or len(substr) == 4):
        raise SyntaxError('Syntax error in parameter set. Expected two reg references + '
                          'immediate and optional flag group')
    rd = _get_single_reg(substr[0].strip())
    rs = _get_single_reg(substr[1].strip())
    imm = _get_imm(substr[2].strip())
    flag_group = 'standard'
    if len(substr) == 4:
        flag_group = _get_flag_group(substr[3].strip())
    return rd, rs, imm, flag_group


def _get_two_regs_with_shift(asm_str):
    """decode standard format with possibly shifted rs but only a single source register (e.g.: "r21, r7 >> 128")"""
    substr = asm_str.split(',')
    if len(substr) != 2:
        raise SyntaxError('Syntax error in parameter set. Expected two reg references')
    rd = _get_single_reg(substr[0].strip())
    rs, shift_right, shift_bits = _get_single_shifted_reg(substr[1].strip())
    return rd, rs, shift_right, shift_bits


def _get_two_gprs_with_inc(asm_str):
    """decode standard format with two possibly incremented GPRs (e.g.: "x20, x21++")"""
    substr = asm_str.split(',')
    if len(substr) != 2:
        raise SyntaxError('Syntax error in parameter set. Expected two GPR references')
    xd, inc_xd = _get_single_inc_gpr(substr[0].strip())
    xs, inc_xs = _get_single_inc_gpr(substr[1].strip())
    return xd, inc_xd, xs, inc_xs


def _get_three_regs_with_sections(asm_str):
    """decode a notation with three regs, with indicating a upper and lower section for the source regs
    this is used with the mul instruction (e.g.: "r24, r29l, r21u")"""
    substr = asm_str.split(',')
    if len(substr) != 3:
        raise SyntaxError('Syntax error in parameter set. Expected three reg references')
    rd = _get_single_reg(substr[0].strip())
    rs1, rs1_upper = _get_single_reg_with_section(substr[1].strip())
    rs2, rs2_upper = _get_single_reg_with_section(substr[2].strip())
    return rd, rs1, rs1_upper, rs2, rs2_upper


def _get_limb(asm_str):
    """returns limb for immediate string and check proper formatting (e.g."*5")"""
    if len(asm_str.split()) > 1:
        raise SyntaxError('Unexpected separator in limb reference')
    if not asm_str.startswith('*'):
        raise SyntaxError('Missing \'*\' character at start of limb reference')
    if not asm_str[1:].isdigit():
        raise SyntaxError('limb reference not a number')
    return int(asm_str[1:])


def _get_index_imm(asm_str):
    """returns the index from an immediate index notation (e.g "[42]")"""
    if not asm_str.startswith('['):
        raise SyntaxError('Missing \'[\' character at start of index notation')
    if not asm_str.endswith(']'):
        raise SyntaxError('Missing \']\' character at end of index notation')
    return _get_imm(asm_str[1:-1].strip())


def _get_single_reg(asm_str):
    """returns a single register from string and check proper formatting (e.g "r5")"""
    if len(asm_str.split()) > 1:
        raise SyntaxError('Unexpected separator in reg reference')
    if not asm_str.lower().startswith('r'):
        raise SyntaxError('Missing \'r\' character at start of reg reference')
    if not asm_str[1:].isdigit():
        raise SyntaxError('reg reference not a number')
    return int(asm_str[1:])


def _get_single_inc_gpr(asm_str):
    """returns a single GPR from string and checks inc indicator (e.g "x5" or "x5++")"""
    inc = False
    if len(asm_str.split()) > 1:
        raise SyntaxError('Unexpected separator in reg reference')
    if not asm_str.lower().startswith('x'):
        raise SyntaxError('Missing \'x\' character at start of GPR reference')
    if asm_str.lower().endswith('++'):
        inc = True
        reg = asm_str[1:-2]
    else:
        reg = asm_str[1:]
    if not reg.isdigit():
        raise SyntaxError('GPR reference not a number')
    return int(reg), inc


def _get_single_limb(asm_str):
    """returns a single limb with a potential increment (e.g "*6++" or "*7")"""
    if len(asm_str.split()) > 1:
        raise SyntaxError('Unexpected separator in limb reference')
    if not asm_str.startswith('*'):
        raise SyntaxError('Missing \'*\' character at start of limb reference')
    if asm_str.endswith('++'):
        inc = True
        limb = asm_str[1:-2]
    else:
        inc = False
        limb = asm_str[1:]
    if not limb.isdigit():
        raise SyntaxError('limb reference not a number')
    return int(limb), inc


def _get_single_reg_and_index_imm(asm_str):
    """decode a single reg and an immediate index (e.g. "r15, [#7]")"""
    substr = asm_str.split(',')
    if len(substr) != 2:
        raise SyntaxError('Syntax error in parameter set. Expected register and indexed immediate')
    reg = _get_single_reg(substr[0].strip())
    idx = _get_index_imm(substr[1].strip())
    return reg, idx


def _get_double_limb(asm_str):
    """decode a double limb notation (e.g. "*6++, *8")"""
    substr = asm_str.split(',')
    if len(substr) != 2:
        raise SyntaxError('Syntax error in parameter set. Expected two limb references')
    limbl, incl = _get_single_limb(substr[0].strip())
    limbr, incr = _get_single_limb(substr[1].strip())
    return limbl, incl, limbr, incr


def _get_double_reg(asm_str):
    """decode a double reg notation without shift (e.g. "r1, r2")"""
    substr = asm_str.split(',')
    if len(substr) != 2:
        raise SyntaxError('Syntax error in parameter set. Expected two reg references')
    regl = _get_single_reg(substr[0].strip())
    regr = _get_single_reg(substr[1].strip())
    return regl, regr


def _get_double_reg_with_imm(asm_str):
    """decode a double reg with immediate (e.g. "r3, r5, #254")"""
    substr = asm_str.split(',')
    if len(substr) != 3:
        raise SyntaxError('Syntax error in parameter set. Expected two reg references and immediate')
    rd = _get_single_reg(substr[0].strip())
    rs = _get_single_reg(substr[1].strip())
    imm = _get_imm(substr[2].strip())
    return rd, rs, imm


def _get_triple_reg(asm_str):
    """decode a triple reg notation without shift (e.g. "r1, r2, r3")"""
    substr = asm_str.split(',')
    if len(substr) != 3:
        raise SyntaxError('Syntax error in parameter set. Expected two reg references')
    rd = _get_single_reg(substr[0].strip())
    rs1 = _get_single_reg(substr[1].strip())
    rs2 = _get_single_reg(substr[2].strip())
    return rd, rs1, rs2


def _get_single_reg_with_section(asm_str):
    """decode a reg with indication a upper/lower section (e.g. "r21l" or "r23u")"""
    if asm_str.endswith('u'):
        upper = True
    elif asm_str.endswith('l'):
        upper = False
    else:
        raise SyntaxError('Expecting \'u\' or \'l\' at end of register reference '
                          'with section indication')
    reg = _get_single_reg(asm_str[:-1].strip())
    return reg, upper


def _get_limb_section(asm_str):
    """decode the limb and the section (h or l) from limb (e.g "4l")"""
    if len(asm_str.split()) > 1:
        raise SyntaxError('Unexpected separator in limb reference')
    if asm_str.lower().endswith('l'):
        s = 0
    elif asm_str.lower().endswith('h'):
        s = 1
    else:
        raise SyntaxError('Expecting \'l\' or \'h\' at the end of limb section reference')
    limb = asm_str[:-1]
    if not limb.isdigit():
        raise SyntaxError('reg reference not a number')
    return int(limb), s


def _get_reg_with_limb(asm_str):
    """decode reference to 16 bit section of a register's limb (e.g "r15.3l")"""
    substr = asm_str.split('.')
    if len(substr) != 2:
        raise SyntaxError('Syntax error in parameter set. Expected reference to 16 bit '
                          'section of limb (e.g. \"r12.3l\")')
    reg = _get_single_reg(substr[0].strip())
    limb, s = _get_limb_section(substr[1].strip())
    return reg, limb, s


def _get_reg_limb_and_imm(asm_str):
    """decode the movi notation (reg+limb reference + immediate, e.g.: "r15.3l, #42" )"""
    substr = asm_str.split(',')
    if len(substr) != 2:
        raise SyntaxError('Syntax error in parameter set. Expected reg with limb + immediate')
    reg, limb, s = _get_reg_with_limb(substr[0].strip())
    imm = _get_imm(substr[1].strip())
    return reg, limb, s, imm


def _get_limb_with_paren(asm_str):
    """decode limb from a notation with parentheses as it is used in loop instructions (e.g "*0 (")"""
    if not asm_str.endswith('('):
        raise SyntaxError('Expecting \'(\'')
    return _get_limb(asm_str[:-1].strip())


def _get_imm_with_paren(asm_str):
    """decode immediate from a notation with parentheses as it is used in loop instructions (e.g "#4 (")"""
    if not asm_str.endswith('('):
        raise SyntaxError('Expecting \'(\'')
    return _get_imm(asm_str[:-1].strip())


def _get_loop_type_direct(asm_str):
    """decode loop type"""
    if asm_str.startswith('*'):
        return False
    elif asm_str.startswith('#'):
        return True
    else:
        raise SyntaxError('Syntax error in loop notation')


def _get_three_regs_with_shift(asm_str):
    """decode the full standard format with rd, rs1 and possibly shifted rs2 (e.g.: "r21, r5, r7 >> 128")"""
    substr = asm_str.split(',')
    if len(substr) != 3:
        raise SyntaxError('Syntax error in parameter set. Expected three reg references')
    rd = _get_single_reg(substr[0].strip())
    rs1 = _get_single_reg(substr[1].strip())
    rs2, shift_right, shift_bits = _get_single_shifted_reg(substr[2].strip())
    return rd, rs1, rs2, shift_right, shift_bits


def _get_two_regs_with_shift(asm_str):
    """decode standard format with possibly shifted rs but only a single source register (e.g.: "r21, r7 >> 128")"""
    substr = asm_str.split(',')
    if len(substr) != 2:
        raise SyntaxError('Syntax error in parameter set. Expected two reg references')
    rd = _get_single_reg(substr[0].strip())
    rs, shift_right, shift_bits = _get_single_shifted_reg(substr[1].strip())
    return rd, rs, shift_right, shift_bits


def _get_three_regs_with_sections(asm_str):
    """decode a notation with three regs, with indicating a upper and lower section for the source regs
    this is used with the mul instruction (e.g.: "r24, r29l, r21u")"""
    substr = asm_str.split(',')
    if len(substr) != 3:
        raise SyntaxError('Syntax error in parameter set. Expected three reg references')
    rd = _get_single_reg(substr[0].strip())
    rs1, rs1_upper = _get_single_reg_with_section(substr[1].strip())
    rs2, rs2_upper = _get_single_reg_with_section(substr[2].strip())
    return rd, rs1, rs1_upper, rs2, rs2_upper


class InstructionFactory(object):

    def __init__(self):
        # Mapping of mnemonics to instruction classes
        self.mnem_map = {}
        self.opcode_map = {}
        self.__register_mnemonics(GIns)

    def __register_mnemonics(self, class_p):
        """ Find all final classes derived from Ins and append their mnemonic and class type to dictionary"""
        for cls in class_p.__subclasses__():
            if len(cls.__subclasses__()) > 0:
                self.__register_mnemonics(cls)
            else:
                if isinstance(cls.MNEM, str):
                    if cls.MNEM in self.mnem_map:
                        raise Exception('Error adding mnemonic \'' + cls.MNEM + '\' for class ' + cls.__name__
                                        + '. Mnemonic already in use.')
                    self.mnem_map.update({cls.MNEM: cls})
                elif isinstance(cls.MNEM, dict):
                    for item in cls.MNEM.values():
                        if item in self.mnem_map:
                            raise Exception('Error adding mnemonic \'' + item + '\' for class ' + cls.__name__
                                            + '. Mnemonic already in use.')
                        self.mnem_map.update({item: cls})
                else:
                    raise Exception('Invalid mnemonic format for class ' + cls.__name__)

    def __register_opcodes(self, class_p):
        for cls in class_p.__subclasses__():
            if len(cls.__subclasses__()) > 0:
                self.__register_opcodes(cls)
            else:
                self.opcode_map.update({cls.OP: cls})

    def factory_asm(self, addr, asm_str, ctx):
        """Create instruction class object, based on assembly string"""
        asm_split = asm_str.split(maxsplit=1)
        mnem = asm_split[0].strip()
        params = ''
        if len(asm_split) == 2:
            params = asm_split[1].strip()
        if not self.is_valid_mnem(mnem):
            raise SyntaxError('Unknown instruction: \'' + mnem + '\'')
        ins_obj = self.mnem_map[mnem].from_assembly(addr, mnem, params, ctx)
        return ins_obj

    def factory_bin(self, ins_in, ctx):
        """Create instruction class object. Works for hexstrings or integers"""
        if isinstance(ins_in, str):
            if len(ins_in) == 8:
                ins = int(ins_in, 16)
            else:
                raise ValueError("Wrong length of instruction. Must be 8 hex digits.")
        else:
            ins = ins_in
        op_bits = ins >> Ins.OP_POS
        ins_class = self.opcode_map[op_bits]
        if ins_class:
            return ins_class.from_ins_word(ins, ctx)
        else:
            raise UnknownOpcodeError("Unknown opcode")

    def is_valid_mnem(self, mnem):
        return mnem in self.mnem_map


class GIns(object):
    """Generic instruction """

    CYCLES = 1

    def __init__(self, ctx):
        self.ctx = ctx
        self.malformed = False
        self.hex_str = 0

    @classmethod
    def from_assembly(cls, address, mnem, params, ctx):
        """Create instruction object from assembly string"""
        return cls.enc(address, mnem, params, ctx)

    @classmethod
    def enc(cls, addr, mnem, params, ctx):
        raise Exception('This method must be overridden in a derived class')

    def get_cycles(self):
        return self.CYCLES


class GInsBn(GIns):
    """Standard Bignum format BN.<ins> <rd>, <rs1>, <rs2>, FG<flag_group> """

    def __init__(self, rd, rs1, rs2, flag_group, ctx):
        self.rd = rd
        self.rs1 = rs1
        self.rs2 = rs2
        self.flag_group = flag_group
        super().__init__(ctx)

    def exec_set_all_flags(self, res, m):
        if self.flag_group == 'standard':
            m.set_c_z_m_l(res)
        else:
            m.setx_c_z_m_l(res)

    def exec_set_zml_flags(self, res, m):
        if self.flag_group == 'standard':
            m.set_z_m_l(res)
        else:
            m.setx_z_m_l(res)

    def exec_get_carry(self, m):
        if self.flag_group == 'standard':
            return m.get_flag('C')
        else:
            return m.get_flag('XC')


class GInsBnShift(GInsBn):
    """Standard Bignum format with immediate shift
    BN.<ins> <rd>, <rs1>, <rs2>, FG<flag_group> [, <shift_type> <shift_bytes>B]"""

    def __init__(self, rd, rs1, rs2, flag_group, shift_type, shift_bytes, ctx):
        self.shift_type = shift_type
        self.shift_bytes = shift_bytes
        super().__init__(rd, rs1, rs2, flag_group, ctx)

    def get_asm_str(self):
        asm_str = self.MNEM + ' r' + str(self.rd) + ', r' + str(self.rs1) + ', r' + str(self.rs2)
        if self.shift_type == 'right':
            asm_str += ' >> ' + str(self.shift_bytes*8)
        else:
            if self.shift_bytes:
                asm_str += ' << ' + str(self.shift_bytes*8)
        if self.flag_group == 'extension':
            asm_str += ', FGX'
        return self.hex_str, asm_str, self.malformed

    @classmethod
    def enc(cls, addr, mnem, params, ctx):
        rd, rs1, rs2, shift_type, shift_bits, flag_group = _get_three_regs_with_flag_group_and_shift(params)
        if shift_bits % 8:
            raise SyntaxError('Input shift immediate not byte aligned')
        return cls(rd, rs1, rs2, flag_group, shift_type, int(shift_bits/8), ctx.ins_ctx)

    def exec_shift(self, m):
        if self.shift_type == 'right':
            rs2op = (m.get_reg(self.rs2) >> self.shift_bytes*8) & m.xlen_mask
        else:
            rs2op = (m.get_reg(self.rs2) << self.shift_bytes*8) & m.xlen_mask
        return rs2op


class GInsBnImm(GInsBn):
    """Standard Bignum format with one source register and immediate
    BN.<ins> <rd>, <rs>, <imm>, [ FG<flag_group>]"""

    def __init__(self, rd, rs, imm, flag_group, ctx):
        self.imm = imm
        super().__init__(rd, rs, None, flag_group, ctx)

    def get_asm_str(self):
        asm_str = self.MNEM + ' r' + str(self.rd) + ', r' + str(self.rs1) + ', ' + str(self.imm)
        if self.flag_group == 'extension':
            asm_str += ', FGX'
        return self.hex_str, asm_str, self.malformed

    @classmethod
    def enc(cls, addr, mnem, params, ctx):
        rd, rs, imm, flag_group = _get_two_regs_and_imm_with_flag_group(params)
        return cls(rd, rs, imm, flag_group, ctx.ins_ctx)


class GInsBnMod(GInsBn):
    """Standard Bignum format for pseudo modulo operations
    BN.<ins> <rd>, <rs1>, <rs2>"""

    def __init__(self, rd, rs1, rs2, ctx):
        super().__init__(rd, rs1, rs2, None, ctx)

    def get_asm_str(self):
        asm_str = self.MNEM + ' r' + str(self.rd) + ', r' + str(self.rs1) + ', r' + str(self.rs2)
        return self.hex_str, asm_str, self.malformed

    @classmethod
    def enc(cls, addr, mnem, params, ctx):
        rd, rs1, rs2, = _get_three_regs(params)
        return cls(rd, rs1, rs2, ctx.ins_ctx)


class GInsIndReg(GIns):
    """Standard Bignum format for indirect load, store, move: BN.<ins> x<GPR>[++], x<GPR>[++] """

    def __init__(self, xd, inc_xd, xs, inc_xs, ctx):
        self.xd = xd
        self.inc_xd = inc_xd
        self.xs = xs
        self.inc_xs = inc_xs
        if inc_xd and inc_xs:
            raise SyntaxError("Only one increment allowed in indirect instructions")
        super().__init__(ctx)

    def get_asm_str(self):
        asm_str = self.MNEM + ' x' + str(self.xd)
        if self.inc_xd:
            asm_str += '++'
        asm_str += ', x' + str(self.xs)
        if self.inc_xs:
            asm_str += '++'
        return self.hex_str, asm_str, self.malformed

    @classmethod
    def enc(cls, addr, mnem, params, ctx):
        xd, inc_xd, xs, inc_xs = _get_two_gprs_with_inc(params)
        return cls(xd, inc_xd, xs, inc_xs, ctx.ins_ctx)

    def exec_inc(self, m):
        if self.inc_xd:
            m.inc_gpr(self.xd)
        if self.inc_xs:
            m.inc_gpr(self.xs)


#############################################
#              Arithmetic                   #
#############################################

class IBnAdd(GInsBnShift):
    """Add instruction with one shifted input"""

    MNEM = 'BN.ADD'

    def __init__(self, rd, rs1, rs2, flag_group, shift_type, shift_bytes, ctx):
        super().__init__(rd, rs1, rs2, flag_group, shift_type, shift_bytes, ctx)

    def get_asm_str(self):
        return super().get_asm_str()

    @classmethod
    def enc(cls, addr, mnem, params, ctx):
        return super().enc(addr, mnem, params, ctx)

    def execute(self, m):
        global debug_cnt
        rs2op = self.exec_shift(m)
        res = m.get_reg(self.rs1) + rs2op
        self.exec_set_all_flags(res, m)
        m.set_reg(self.rd, res & m.xlen_mask)
        trace_str = self.get_asm_str()[1]
        return trace_str, False


class IBnSub(GInsBnShift):
    """Sub instruction with one shifted input"""

    MNEM = 'BN.SUB'

    def __init__(self, rd, rs1, rs2, flag_group, shift_type, shift_bytes, ctx):
        super().__init__(rd, rs1, rs2, flag_group, shift_type, shift_bytes, ctx)

    def get_asm_str(self):
        return super().get_asm_str()

    @classmethod
    def enc(cls, addr, mnem, params, ctx):
        return super().enc(addr, mnem, params, ctx)

    def execute(self, m):
        rs2op = self.exec_shift(m)
        res = (m.get_reg(self.rs1) - rs2op)
        self.exec_set_all_flags(res, m)
        m.set_reg(self.rd, res  & m.xlen_mask)
        trace_str = self.get_asm_str()[1]
        return trace_str, False


class IBnCmp(GInsBnShift):
    """Cmp instruction with one shifted input"""

    MNEM = 'BN.CMP'

    def __init__(self, rd, rs1, rs2, flag_group, shift_type, shift_bytes, ctx):
        super().__init__(rd, rs1, rs2, flag_group, shift_type, shift_bytes, ctx)

    def get_asm_str(self):
        return super().get_asm_str()

    @classmethod
    def enc(cls, addr, mnem, params, ctx):
        return super().enc(addr, mnem, params, ctx)

    def execute(self, m):
        rs2op = self.exec_shift(m)
        res = (m.get_reg(self.rs1) - rs2op)
        self.exec_set_all_flags(res, m)
        trace_str = self.get_asm_str()[1]
        return trace_str, False


class IBnAddc(GInsBnShift):
    """Add with carry instruction with one shifted input"""

    MNEM = 'BN.ADDC'

    def __init__(self, rd, rs1, rs2, flag_group, shift_type, shift_bytes, ctx):
        super().__init__(rd, rs1, rs2, flag_group, shift_type, shift_bytes, ctx)

    def get_asm_str(self):
        return super().get_asm_str()

    @classmethod
    def enc(cls, addr, mnem, params, ctx):
        return super().enc(addr, mnem, params, ctx)

    def execute(self, m):
        rs2op = self.exec_shift(m)
        res = (m.get_reg(self.rs1) + rs2op + int(self.exec_get_carry(m)))
        self.exec_set_all_flags(res, m)
        m.set_reg(self.rd, res & m.xlen_mask)
        trace_str = self.get_asm_str()[1]
        return trace_str, False


class IBnSubb(GInsBnShift):
    """Sub with borrow instruction with one shifted input"""

    MNEM = 'BN.SUBB'

    def __init__(self, rd, rs1, rs2, flag_group, shift_type, shift_bytes, ctx):
        super().__init__(rd, rs1, rs2, flag_group, shift_type, shift_bytes, ctx)

    def get_asm_str(self):
        return super().get_asm_str()

    @classmethod
    def enc(cls, addr, mnem, params, ctx):
        return super().enc(addr, mnem, params, ctx)

    def execute(self, m):
        rs2op = self.exec_shift(m)
        res = (m.get_reg(self.rs1) - rs2op - int(self.exec_get_carry(m)))
        self.exec_set_all_flags(res, m)
        m.set_reg(self.rd, res & m.xlen_mask)
        trace_str = self.get_asm_str()[1]
        return trace_str, False


class IBnCmpb(GInsBnShift):
    """Cmp with borrow instruction with one shifted input"""

    MNEM = 'BN.CMPB'

    def __init__(self, rd, rs1, rs2, flag_group, shift_type, shift_bytes, ctx):
        super().__init__(rd, rs1, rs2, flag_group, shift_type, shift_bytes, ctx)

    def get_asm_str(self):
        return super().get_asm_str()

    @classmethod
    def enc(cls, addr, mnem, params, ctx):
        return super().enc(addr, mnem, params, ctx)

    def execute(self, m):
        rs2op = self.exec_shift(m)
        res = (m.get_reg(self.rs1) - rs2op - int(self.exec_get_carry(m)))
        self.exec_set_all_flags(res, m)
        trace_str = self.get_asm_str()[1]
        return trace_str, False


class IBnAddi(GInsBnImm):
    """Add with immediate"""

    MNEM = 'BN.ADDI'

    def __init__(self, rd, rs, imm, flag_group, ctx):
        super().__init__(rd, rs, imm, flag_group, ctx)

    def get_asm_str(self):
        return super().get_asm_str()

    @classmethod
    def enc(cls, addr, mnem, params, ctx):
        return super().enc(addr, mnem, params, ctx)

    def execute(self, m):
        res = (m.get_reg(self.rs1) + self.imm)
        self.exec_set_all_flags(res, m)
        m.set_reg(self.rd, res & m.xlen_mask)
        trace_str = self.get_asm_str()[1]
        return trace_str, False


class IBnSubi(GInsBnImm):
    """Sub with immediate"""

    MNEM = 'BN.SUBI'

    def __init__(self, rd, rs, imm, flag_group, ctx):
        super().__init__(rd, rs, imm, flag_group, ctx)

    def get_asm_str(self):
        return super().get_asm_str()

    @classmethod
    def enc(cls, addr, mnem, params, ctx):
        return super().enc(addr, mnem, params, ctx)

    def execute(self, m):
        res = (m.get_reg(self.rs1) - self.imm)
        self.exec_set_all_flags(res, m)
        m.set_reg(self.rd, res & m.xlen_mask)
        trace_str = self.get_asm_str()[1]
        return trace_str, False


class IBnAddm(GInsBnMod):
    """Pseudo modular add"""

    MNEM = 'BN.ADDM'

    def __init__(self, rd, rs1, rs2, ctx):
        super().__init__(rd, rs1, rs2, ctx)

    def get_asm_str(self):
        return super().get_asm_str()

    @classmethod
    def enc(cls, addr, mnem, params, ctx):
        return super().enc(addr, mnem, params, ctx)

    def execute(self, m):
        res = (m.get_reg(self.rs1) + m.get_reg(self.rs2))
        if res >= m.get_reg('mod'):
            res = res - m.get_reg('mod')
        m.set_reg(self.rd, res & m.xlen_mask)
        trace_str = self.get_asm_str()[1]
        return trace_str, False


class IBnSubm(GInsBnMod):
    """Pseudo modular sub"""

    MNEM = 'BN.SUBM'

    def __init__(self, rd, rs1, rs2, ctx):
        super().__init__(rd, rs1, rs2, ctx)

    def get_asm_str(self):
        return super().get_asm_str()

    @classmethod
    def enc(cls, addr, mnem, params, ctx):
        return super().enc(addr, mnem, params, ctx)

    def execute(self, m):
        res = m.get_reg(self.rs1) - m.get_reg(self.rs2)
        if res < 0:
            res = m.get_reg('mod') + res
        m.set_reg(self.rd, res & m.xlen_mask)
        trace_str = self.get_asm_str()[1]
        return trace_str, False


class IBnMulh(GInsBn):
    """Half Word Multiply
    BN.MULH <rd>, <rs1>[L|U], <rs2>[L|U]"""

    MNEM = 'BN.MULH'

    def __init__(self, rd, rs1, rs1_hw_sel, rs2, rs2_hw_sel, ctx):
        self.rs1_hw_sel = rs1_hw_sel
        self.rs2_hw_sel = rs2_hw_sel
        super().__init__(rd, rs1, rs2, None, ctx)

    def get_asm_str(self):
        asm_str = self.MNEM + ' r' + str(self.rd) + ', r' + str(self.rs1)
        if self.rs1_hw_sel == 'upper':
            asm_str += 'U'
        else:
            asm_str += 'L'
        asm_str += ', r' + str(self.rs2)
        if self.rs2_hw_sel == 'upper':
            asm_str += 'U'
        else:
            asm_str += 'L'
        return self.hex_str, asm_str, self.malformed

    @classmethod
    def enc(cls, addr, mnem, params, ctx):
        rd, rs1, rs1_hw_sel, rs2, rs2_hw_sel = _get_three_regs_with_two_half_word_sels(params)
        return cls(rd, rs1, rs1_hw_sel, rs2, rs2_hw_sel, ctx.ins_ctx)

    def execute(self, m):
        if self.rs1_hw_sel == 'upper':
            op1 = (m.get_reg(self.rs1) >> int(m.XLEN/2)) & m.half_xlen_mask
        else:
            op1 = m.get_reg(self.rs1) & m.half_xlen_mask
        if self.rs2_hw_sel == 'upper':
            op2 = (m.get_reg(self.rs2) >> int(m.XLEN/2)) & m.half_xlen_mask
        else:
            op2 = m.get_reg(self.rs2) & m.half_xlen_mask
        res = op1*op2
        m.set_reg(self.rd, res)
        trace_str = self.get_asm_str()[1]
        return trace_str, False


#############################################
#      Logical, select, shift, compare      #
#############################################


class IBnAnd(GInsBnShift):
    """And instruction with one shifted input"""

    MNEM = 'BN.AND'

    def __init__(self, rd, rs1, rs2, flag_group, shift_type, shift_bytes, ctx):
        super().__init__(rd, rs1, rs2, 'standard', shift_type, shift_bytes, ctx)

    def get_asm_str(self):
        return super().get_asm_str()

    @classmethod
    def enc(cls, addr, mnem, params, ctx):
        return super().enc(addr, mnem, params, ctx)

    def execute(self, m):
        rs2op = self.exec_shift(m)
        res = (m.get_reg(self.rs1) & rs2op) & m.xlen_mask
        m.set_reg(self.rd, res)
        trace_str = self.get_asm_str()[1]
        return trace_str, False


class IBnOr(GInsBnShift):
    """Or instruction with one shifted input"""

    MNEM = 'BN.OR'

    def __init__(self, rd, rs1, rs2, flag_group, shift_type, shift_bytes, ctx):
        super().__init__(rd, rs1, rs2, 'standard', shift_type, shift_bytes, ctx)

    def get_asm_str(self):
        return super().get_asm_str()

    @classmethod
    def enc(cls, addr, mnem, params, ctx):
        return super().enc(addr, mnem, params, ctx)

    def execute(self, m):
        rs2op = self.exec_shift(m)
        res = (m.get_reg(self.rs1) | rs2op) & m.xlen_mask
        self.exec_set_zml_flags(res, m)
        m.set_reg(self.rd, res)
        trace_str = self.get_asm_str()[1]
        return trace_str, False


class IBnXor(GInsBnShift):
    """Or instruction with one shifted input"""

    MNEM = 'BN.XOR'

    def __init__(self, rd, rs1, rs2, flag_group, shift_type, shift_bytes, ctx):
        super().__init__(rd, rs1, rs2, 'standard', shift_type, shift_bytes, ctx)

    def get_asm_str(self):
        return super().get_asm_str()

    @classmethod
    def enc(cls, addr, mnem, params, ctx):
        return super().enc(addr, mnem, params, ctx)

    def execute(self, m):
        rs2op = self.exec_shift(m)
        res = (m.get_reg(self.rs1) ^ rs2op) & m.xlen_mask
        self.exec_set_zml_flags(res, m)
        m.set_reg(self.rd, res)
        trace_str = self.get_asm_str()[1]
        return trace_str, False



class IBnNot(GIns):
    """Not instruction with one shifted input"""

    MNEM = 'BN.NOT'

    def __init__(self, rd, rs, shift_type, shift_bytes, ctx):
        self.rd = rd
        self.rs = rs
        self.shift_type = shift_type
        self.shift_bytes = shift_bytes
        super().__init__(ctx)

    def get_asm_str(self):
        asm_str = self.MNEM + ' r' + str(self.rd) + ', r' + str(self.rs)
        if self.shift_type == 'right':
            asm_str += ' >> ' + str(self.shift_bytes*8)
        else:
            if self.shift_bytes:
                asm_str += ' << ' + str(self.shift_bytes*8)
        return self.hex_str, asm_str, self.malformed

    @classmethod
    def enc(cls, addr, mnem, params, ctx):
        rd, rs, shift_type, shift_bits = _get_two_regs_with_shift(params)
        if shift_bits % 8:
            raise SyntaxError('Input shift immediate not byte aligned')
        return cls(rd, rs, shift_type, int(shift_bits / 8), ctx.ins_ctx)

    def execute(self, m):
        if self.shift_type == 'right':
            rs2op = (m.get_reg(self.rs) >> self.shift_bytes*8) & m.xlen_mask
        else:
            rs2op = (m.get_reg(self.rs) << self.shift_bytes*8) & m.xlen_mask
        res = (~rs2op) & m.xlen_mask
        m.set_reg(self.rd, res)
        trace_str = self.get_asm_str()[1]
        return trace_str, False


class IBnRshi(GInsBn):
    """Concatenate and Right shift"""

    MNEM = 'BN.RSHI'

    def __init__(self, rd, rs1, rs2, shift_bits, ctx):
        self.shift_bits = shift_bits
        super().__init__(rd, rs1, rs2, None, ctx)

    def get_asm_str(self):
        asm_str = self.MNEM + ' r' + str(self.rd) + ', r' + str(self.rs1) + ', r' + str(self.rs2)
        asm_str += ' >> ' + str(self.shift_bits)
        return self.hex_str, asm_str, self.malformed

    @classmethod
    def enc(cls, addr, mnem, params, ctx):
        rd, rs1, rs2, shift_type, shift_bits, flag_group = _get_three_regs_with_flag_group_and_shift(params)
        if shift_type != 'right':
            raise SyntaxError('Only right shift possible with this instruction')
        if flag_group != 'standard':
            raise SyntaxError('Only standard flag group possible with this instruction')
        return cls(rd, rs1, rs2, shift_bits, ctx.ins_ctx)

    def execute(self, m):
        conc = (m.get_reg(self.rs2) << m.XLEN) + m.get_reg(self.rs1)
        res = (conc >> self.shift_bits) & m.xlen_mask
        m.set_reg(self.rd, res)
        trace_str = self.get_asm_str()[1]
        return trace_str, False


class IBnSel(GInsBn):
    """Select by flag"""

    MNEM = 'BN.SEL'

    def __init__(self, rd, rs1, rs2, flag_group, flag, ctx):
        self.flag = flag
        super().__init__(rd, rs1, rs2, flag_group, ctx)

    def get_asm_str(self):
        asm_str = self.MNEM + ' r' + str(self.rd) + ', r' + str(self.rs1) + ', r' + str(self.rs2) + ', '
        if self.flag_group == 'extension':
            asm_str += 'FGX.'
        asm_str += self.flag.upper()
        return self.hex_str, asm_str, self.malformed

    @classmethod
    def enc(cls, addr, mnem, params, ctx):
        rd, rs1, rs2, flag_group, flag = _get_three_regs_with_flag_group_and_flag(params)
        return cls(rd, rs1, rs2, flag_group, flag, ctx.ins_ctx)

    def execute(self, m):
        flag_id = self.flag.upper()
        if self.flag_group == 'extension':
            flag_id = 'X' + flag_id
        flag_val = m.get_flag(flag_id)
        res = m.get_reg(self.rs1) if flag_val else m.get_reg(self.rs2)
        m.set_reg(self.rd, res)
        trace_str = self.get_asm_str()[1]
        return trace_str, False


#############################################
#            Load/Store/Move                #
#############################################

class IBnMov(GIns):
    """Direct move instruction"""

    MNEM = 'BN.MOV'

    def __init__(self, rd, rs, ctx):
        self.rd = rd
        self.rs = rs
        super().__init__(ctx)

    def get_asm_str(self):
        asm_str = self.MNEM + ' r' + str(self.rd) + ', r' + str(self.rs)
        return self.hex_str, asm_str, self.malformed

    @classmethod
    def enc(cls, addr, mnem, params, ctx):
        rd, rs = _get_two_regs(params)
        return cls(rd, rs, ctx.ins_ctx)

    def execute(self, m):
        m.set_reg(self.rd, m.get_reg(self.rs))
        trace_str = self.get_asm_str()[1]
        return trace_str, False


class IBnMovr(GInsIndReg):
    """Indirect move instruction"""

    MNEM = 'BN.MOVR'

    def __init__(self, xd, inc_xd, xs, inc_xs, ctx):
        super().__init__(xd, inc_xd, xs, inc_xs, ctx)

    def execute(self, m):
        dst_wdr = m.get_gpr(self.xd)
        src_wdr = m.get_gpr(self.xs)
        m.set_reg(dst_wdr, m.get_reg(src_wdr))
        super().exec_inc(m)
        trace_str = self.get_asm_str()[1]
        return trace_str, False


if __name__ == "__main__":
    raise Exception('This file is not executable')
