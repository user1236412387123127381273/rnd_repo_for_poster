from __future__ import annotations
import claripy

import bisa


class strcasecmp(bisa.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, a_addr, b_addr):
        strlen = bisa.SIM_PROCEDURES["libc"]["strlen"]

        a_strlen = self.inline_call(strlen, a_addr)
        b_strlen = self.inline_call(strlen, b_addr)
        maxlen = claripy.BVV(max(a_strlen.max_null_index, b_strlen.max_null_index), self.state.arch.bits)

        strncmp = self.inline_call(
            bisa.SIM_PROCEDURES["libc"]["strncmp"],
            a_addr,
            b_addr,
            maxlen,
            a_len=a_strlen,
            b_len=b_strlen,
            ignore_case=True,
        )
        return strncmp.ret_expr
