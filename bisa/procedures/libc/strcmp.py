from __future__ import annotations
import logging

import claripy

import bisa

l = logging.getLogger(name=__name__)


class strcmp(bisa.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, a_addr, b_addr, wchar=False, ignore_case=False):
        strlen = bisa.SIM_PROCEDURES["libc"]["strlen"]

        a_strlen = self.inline_call(strlen, a_addr, wchar=wchar)
        b_strlen = self.inline_call(strlen, b_addr, wchar=wchar)
        maxlen = claripy.BVV(max(a_strlen.max_null_index, b_strlen.max_null_index), self.state.arch.bits)

        strncmp = self.inline_call(
            bisa.SIM_PROCEDURES["libc"]["strncmp"],
            a_addr,
            b_addr,
            maxlen,
            a_len=a_strlen,
            b_len=b_strlen,
            wchar=wchar,
            ignore_case=ignore_case,
        )
        return strncmp.ret_expr
