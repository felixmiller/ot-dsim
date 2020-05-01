# Copyright lowRISC contributors.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

from . machine import *


def _get_imm(asm_str):
    """return int for immediate string and check proper formatting (e.g "#42")"""
    if len(asm_str.split()) > 1:
        raise SyntaxError('Unexpected separator in immediate')
    if not asm_str.startswith('#'):
        raise SyntaxError('Missing \'#\' character at start of immediate')
    if not asm_str[1:].isdigit():
        raise SyntaxError('Immediate not a number')
    return int(asm_str[1:])


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
        shift_bytes = substr[1].strip()[:-1]
        if not shift_bytes.isdigit():
            raise SyntaxError('input shift immediate not a number')
        shift_bits = int(shift_bytes)*8
    else:
        shift_bits = substr[1].strip()
        if not shift_bits.isdigit():
            raise SyntaxError('input shift immediate not a number')

    return reg, shift_type, shift_bits


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


def _get_imm(asm_str):
    """return int for immediate string and check proper formatting (e.g "#42")"""
    if len(asm_str.split()) > 1:
        raise SyntaxError('Unexpected separator in immediate')
    if not asm_str.startswith('#'):
        raise SyntaxError('Missing \'#\' character at start of immediate')
    if not asm_str[1:].isdigit():
        raise SyntaxError('Immediate not a number')
    return int(asm_str[1:])


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

    # Mapping of mnemonics to instruction classes
    mnem_map = {}
    opcode_map = {}

    def __init__(self):
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

    def __init__(self, ctx):
        self.ctx = ctx

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
    """Standard Bignum format BN.<ins> <rd>, <rs1>, <rs2>, FG<flag_group> [, <shift_type> <shift_bytes>B]"""

    def __init__(self, rd, rs1, rs2, flag_group, ctx):
        self.rd = rd
        self.rs1 = rs1
        self.rs2 = rs2
        self.flag_group = flag_group
        super().__init__(ctx)


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
        return asm_str

    @classmethod
    def enc(cls, addr, mnem, params, ctx):
        rd, rs1, rs2, shift_type, shift_bits, flag_group = _get_three_regs_with_flag_group_and_shift(params)
        if shift_bits % 8:
            raise SyntaxError('Input shift immediate not byte aligned')
        return cls(rd, rs1, rs2, flag_group, shift_type, int(shift_bits/8), ctx.ins_ctx)


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
        if self.shift_type == 'right':
            rs2op = (m.get_reg(self.rs2) >> self.shift_bytes*8) & m.xlen_mask
        else:
            rs2op = (m.get_reg(self.rs2) << self.shift_bytes*8) & m.xlen_mask
        res = m.get_reg(self.rs1) + rs2op
        m.stat_record_flag_access('n', self.MNEM.get(self.fun))
        if self.flag_group == 'standard':
            m.set_c_z_m_l(res)
        else:
            m.setx_c_z_m_l(res)
        m.set_reg(self.rd, res & m.xlen_mask)
        trace_str = self.get_asm_str()[1]
        return trace_str, False


if __name__ == "__main__":
    raise Exception('This file is not executable')
