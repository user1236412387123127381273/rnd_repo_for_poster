from __future__ import annotations
import claripy

import bisa


class b64_decode(bisa.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, src, dst, length):
        strncpy = bisa.SIM_PROCEDURES["libc"]["strncpy"]

        cpy = self.inline_call(strncpy, dst, src, length)
        self.state.memory.store(dst + 16, claripy.BVV(0, 8))
        return cpy.ret_expr
