# Copyright lowRISC contributors.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

import argparse
import logging
from bignum_lib.sim_helpers import ins_objects_from_asm_file
from bignum_lib.disassembler import Disassembler


def main():
    logging.basicConfig(level=logging.DEBUG)
    argparser = argparse.ArgumentParser(description='Dcrypto to OTBN assembly converter')
    argparser.add_argument('infile', help="Input Assembly file")
    argparser.parse_args()
    args = argparser.parse_args()

    try:
        infile = open(args.infile)
    except IOError:
        print('Could not open file ' + args.infile)
        exit()

    """Load binary executable from file"""
    ins_objects, ctx = ins_objects_from_asm_file(infile)
    infile.close()

    for idx, item in enumerate(ins_objects):
        otbn_ins_obj = item.convert_otbn()
        if otbn_ins_obj:
            ins_objects[idx] = otbn_ins_obj

    disassembler = Disassembler.from_ins_objects_and_context(ins_objects, ctx)
    asm_lines = disassembler.create_assembly()
    for item in asm_lines:
        print(item)


if __name__ == "__main__":
    main()
