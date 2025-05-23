from __future__ import annotations
import logging

import claripy

import bisa

l = logging.getLogger(name=__name__)


class memcmp(bisa.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, s1_addr, s2_addr, n):
        max_memcmp_size = self.state.libc.max_buffer_size

        definite_size = self.state.solver.min_int(n)
        conditional_s1_start = s1_addr + definite_size
        conditional_s2_start = s2_addr + definite_size
        conditional_size = int(max(max_memcmp_size - definite_size, 0)) if self.state.solver.symbolic(n) else 0

        l.debug("Definite size %s and conditional size: %s", definite_size, conditional_size)

        int_bits = self.arch.sizeof["int"]
        if definite_size > 0:
            s1_part = self.state.memory.load(s1_addr, definite_size, endness="Iend_BE")
            s2_part = self.state.memory.load(s2_addr, definite_size, endness="Iend_BE")
            cases = [
                [s1_part == s2_part, claripy.BVV(0, int_bits)],
                [claripy.ULT(s1_part, s2_part), claripy.BVV(-1, int_bits)],
                [claripy.UGT(s1_part, s2_part), claripy.BVV(1, int_bits)],
            ]
            definite_answer = claripy.ite_cases(cases, 2)
            constraint = claripy.Or(*[c for c, _ in cases])
            self.state.add_constraints(constraint)

            l.debug("Created definite answer: %s", definite_answer)
            l.debug("Created constraint: %s", constraint)
            l.debug("... crom cases: %s", cases)
        else:
            definite_answer = claripy.BVV(0, int_bits)

        if not self.state.solver.symbolic(definite_answer) and self.state.solver.eval(definite_answer) != 0:
            return definite_answer

        if conditional_size > 0:
            s1_all = self.state.memory.load(conditional_s1_start, conditional_size, endness="Iend_BE")
            s2_all = self.state.memory.load(conditional_s2_start, conditional_size, endness="Iend_BE")
            conditional_rets = {0: definite_answer}

            for byte, bit in zip(range(conditional_size), range(conditional_size * 8, 0, -8)):
                s1_part = s1_all[conditional_size * 8 - 1 : bit - 8]
                s2_part = s2_all[conditional_size * 8 - 1 : bit - 8]
                cases = [
                    [s1_part == s2_part, claripy.BVV(0, int_bits)],
                    [claripy.ULT(s1_part, s2_part), claripy.BVV(-1, int_bits)],
                    [claripy.UGT(s1_part, s2_part), claripy.BVV(1, int_bits)],
                ]
                conditional_rets[byte + 1] = claripy.ite_cases(cases, 0)
                self.state.add_constraints(claripy.Or(*[c for c, _ in cases]))

            ret_expr = claripy.If(
                definite_answer == 0,
                claripy.ite_dict(n - definite_size, conditional_rets, 2),
                definite_answer,
            )
            self.state.add_constraints(claripy.Or(*[n - definite_size == c for c in conditional_rets]))
            return ret_expr
        return definite_answer
