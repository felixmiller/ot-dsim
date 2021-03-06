# Copyright lowRISC contributors.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

from . instructions import *


class Assembler:
    # Tokens
    TOK_FUNCTION = "function"
    TOK_LOOP = 'loop'
    TOK_SPECIAL = [')', '}']

    # List of addresses where functions are closed
    funclose = []

    # the program (mnem, (param_string, line))
    instr = []

    ins_objects = []

    def __init__(self, lines):
        self.ins_fac = InstructionFactory()
        self.lines = lines
        self.ctx = self.__create_index()
        self.__check_fun_len()

    def __create_index(self):
        functions = {}
        loopclose = {}
        labels = {}
        loop_stack = []
        for i, line in enumerate(self.lines):
            tokens = line.strip().split()
            if not tokens:
                continue
            if self.ins_fac.is_valid_mnem(tokens[0]):
                params = ''
                if len(tokens) > 1:
                    params = line.strip().split(maxsplit=1)[1]
                if tokens[0] == self.TOK_LOOP:
                    loop_stack.append(len(self.instr))
                self.instr.append((tokens[0], (params, i)))

            elif tokens[0] == self.TOK_FUNCTION:
                if len(loop_stack) != 0:
                    raise SyntaxError('Unclosed loop at function boundary in line ' + str(i+1) + '. Missing \')\'')
                if len(tokens) == 3 and tokens[2] == '{':
                    if tokens[1].endswith(']'):
                        if '[' in tokens[1]:
                            splitforlen = tokens[1].rsplit('[', 1)
                            funname = splitforlen[0]
                            funlen = splitforlen[1][:-1]
                            if funlen.isdigit():
                                funtup = (len(self.instr), int(funlen))
                            else:
                                raise SyntaxError('Syntax error in line ' + str(i+1) + ': function length not a number')
                        else:
                            raise SyntaxError('Syntax error in line: ' + str(i+1) + ': missing \'[\'')
                    else:
                        funname = tokens[1]
                        funtup = (len(self.instr))
                    functions.update({funname: funtup})
                else:
                    raise SyntaxError('Syntax error in line ' + str(i+1))

            elif tokens[0] in self.TOK_SPECIAL:
                if tokens[0] == '}':
                    if len(loop_stack) != 0:
                        raise SyntaxError('Unclosed loop at function boundary in line ' + str(i+1) + '. Missing \')\'')
                    if len(self.instr) in self.funclose:
                        raise SyntaxError('Multiple \'}\' in line ' + str(i+1))
                    # append address to list of function endings for later consistency check
                    self.funclose.append(len(self.instr))

                if tokens[0] == ')':
                    if len(loop_stack) == 0:
                        raise SyntaxError('Redundant \')\' in line ' + str(i+1))
                    loopclose.update({loop_stack.pop(): len(self.instr)})

            else:
                if tokens[0].endswith(':'):
                    if len(tokens) == 1:
                        labels.update({tokens[0][:-1]: len(self.instr)})
                    else:
                        raise SyntaxError('Syntax error in line ' + str(i+1))
                else:
                    raise SyntaxError('Invalid identifier: ' + tokens[0] + ' (in line: ' + str(i+1) + ')')
        if len(loop_stack) != 0:
            raise SyntaxError('Unexpected EOF. Unclosed Loop. Missing \')\'')

        return AsmCtx(functions, loopclose, labels)

    def __check_fun_len(self):
        """Check for consitency of function definitions and closing characters
        If function length parameter is missing in function definition add based on calculated length"""
        if len(self.ctx.functions) > len(self.funclose):
            raise SyntaxError('Missing \'}\'')
        if len(self.ctx.functions) < len(self.funclose):
            raise SyntaxError('Redundant \'}\'')
        for idx, (key, value) in enumerate(self.ctx.functions.items()):
            if isinstance(value, tuple) and len(value) == 2:
                if not (str(value[0] + value[1]) == str(self.funclose[idx])):
                    raise IndexError('Function size parameter in function definition '
                                     'differs from actual function length for function: ' + key)
            else:
                closeaddr = self.funclose[idx]
                funlen = closeaddr-value
                if closeaddr <= value:
                    raise SyntaxError('Mismatch for positions of function definitions and function closing '
                                      'symbols \'}\', or empty function')

                # If not last element check if closing symbol really before next function definition
                if idx != (len(self.ctx.functions) - 1):
                    next_val = list(self.ctx.functions.values())[idx+1]
                    if isinstance(next_val, tuple):
                        next_val = next_val[0]

                    if closeaddr > next_val:
                        raise SyntaxError('Closing character \'}\'for function \'' + key
                                          + '\' only found after next function definition')

                self.ctx.functions[key] = (value, funlen)
                print('Warning: No length parameter for function \'' + key + '\' ')

    def assemble(self):
        for i, item in enumerate(self.instr):
            address = i
            line = item[1][1]
            mnem = item[0]
            params = item[1][0]
            asm_str = mnem + ' ' + params
            try:
                ins_obj = self.ins_fac.factory_asm(address, asm_str, self.ctx)
                if ins_obj != 0:
                    self.ins_objects.append(ins_obj)

            except Exception:
                print('Error at instruction address: ' + str(address) + ', assembly line: ' + str(line+1))
                raise

    def get_instruction_words(self):
        return [item.ins for item in self.ins_objects]

    def get_instruction_objects(self):
        return self.ins_objects

    def get_instruction_context(self):
        return self.ctx.ins_ctx

    def print_summary(self):
        print('Summary:')
        print('Lines of code: ' + str(len(self.lines)))
        print('Instructions / Code size: ' + str(len(self.instr)))
        print('Labels found: ' + str(len(self.ctx.labels)))
        print('Functions: ' + str(len(self.ctx.functions)))
