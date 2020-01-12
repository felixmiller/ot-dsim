# Copyright lowRISC contributors.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

from . assembler import Assembler
from . disassembler import Disassembler
from . machine import Machine


def read_dmem_from_file(dmemfile):
    line_cnt = 0
    dmem = []
    while True:
        line_str = dmemfile.readline()
        if not line_str:
            break
        if line_cnt == Machine.DMEM_DEPTH:
            raise OverflowError('Dmem file to large')
        if ':' in line_str:
            addr = line_str.split(':')[0].strip()
            if int(addr) != line_cnt:
                raise Exception('Error in Dmem file line ' + str(line_cnt+1)
                                + ' (non continues mem files currently not supported)')
            line_str = line_str.split(':')[1].lower().strip()
        words = line_str.split()
        if len(words) != 8:
            raise Exception('Error in Dmem file line ' + str(line_cnt+1)
                            + ' 8 32-bit words expected per line, found ' + str(len(words)) + '.')
        line_str = ''.join(words)
        if len(line_str) != 32*2:
            raise Exception('Error in Dmem file line ' + str(line_cnt+1) + '. Expecting data 32 bytes per line. Found '
                            + str(len(line_str)) + ' characters.')
        dmem.append(int(line_str, 16))
        line_cnt += 1
    return dmem


def ins_objects_from_hex_file(hex_file):
    lines = hex_file.readlines()
    disassembler = Disassembler(lines)
    return disassembler.get_instruction_objects(), disassembler.ctx


def ins_objects_from_asm_file(asm_file):
    lines = asm_file.readlines()
    assembler = Assembler(lines)
    assembler.assemble()
    return assembler.get_instruction_objects(), assembler.get_instruction_context()
