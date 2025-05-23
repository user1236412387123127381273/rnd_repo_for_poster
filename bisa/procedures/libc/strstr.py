from __future__ import annotations
import logging

import claripy

import bisa
from bisa.sim_options import MEMORY_CHUNK_INDIVIDUAL_READS


l = logging.getLogger(name=__name__)


class strstr(bisa.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, haystack_addr, needle_addr, haystack_strlen=None, needle_strlen=None):
        strlen = bisa.SIM_PROCEDURES["libc"]["strlen"]
        strncmp = bisa.SIM_PROCEDURES["libc"]["strncmp"]

        haystack_strlen = self.inline_call(strlen, haystack_addr) if haystack_strlen is None else haystack_strlen
        needle_strlen = self.inline_call(strlen, needle_addr) if needle_strlen is None else needle_strlen

        # naive approach
        haystack_maxlen = haystack_strlen.max_null_index
        needle_maxlen = needle_strlen.max_null_index

        l.debug("strstr with size %d haystack and size %d needle...", haystack_maxlen, needle_maxlen)

        if needle_maxlen == 0:
            l.debug("... zero-length needle.")
            return haystack_addr
        if haystack_maxlen == 0:
            l.debug("... zero-length haystack.")
            return claripy.BVV(0, self.state.arch.bits)

        if self.state.solver.symbolic(needle_strlen.ret_expr):
            cases = [[needle_strlen.ret_expr == 0, haystack_addr]]
            exclusions = [needle_strlen.ret_expr != 0]
            not_terminated_yet_constraints = []
            remaining_symbolic = self.state.libc.max_symbolic_strstr

            for i in range(haystack_maxlen):
                l.debug("... case %d (%d symbolic checks remaining)", i, remaining_symbolic)
                not_terminated_yet_constraints.append(self.state.memory.load(haystack_addr + i, 1) != 0)

                # big hack!
                cmp_res = self.inline_call(
                    strncmp,
                    haystack_addr + i,
                    needle_addr,
                    needle_strlen.ret_expr,
                    a_len=haystack_strlen,
                    b_len=needle_strlen,
                )

                c = claripy.And(
                    *(
                        [
                            claripy.UGE(haystack_strlen.ret_expr, needle_strlen.ret_expr),
                            cmp_res.ret_expr == 0,
                            *not_terminated_yet_constraints,
                            *exclusions,
                        ]
                    )
                )

                exclusions.append(cmp_res.ret_expr != 0)

                if self.state.solver.symbolic(c):
                    remaining_symbolic -= 1

                cases.append([c, haystack_addr + i])
                haystack_strlen.ret_expr = haystack_strlen.ret_expr - 1

                if remaining_symbolic == 0:
                    l.debug("... exhausted remaining symbolic checks.")
                    break

            cases.append([claripy.And(*exclusions), claripy.BVV(0, self.state.arch.bits)])
            l.debug("... created %d cases", len(cases))
            r = claripy.ite_cases(cases, 0)
            c = [claripy.Or(*[c for c, _ in cases])]
        else:
            needle_length = self.state.solver.eval(needle_strlen.ret_expr)
            needle_str = self.state.memory.load(needle_addr, needle_length)

            chunk_size = None
            if MEMORY_CHUNK_INDIVIDUAL_READS in self.state.options:
                chunk_size = 1

            r, c, i = self.state.memory.find(
                haystack_addr,
                needle_str,
                haystack_strlen.max_null_index,
                max_symbolic_bytes=self.state.libc.max_symbolic_strstr,
                default=0,
                chunk_size=chunk_size,
            )

        self.state.add_constraints(*c)
        return r
