from __future__ import annotations
import bisa


class strtoul(bisa.SimProcedure):
    # pylint:disable=arguments-differ
    def run(self, nptr, endptr, base):
        strtol = bisa.SIM_PROCEDURES["libc"]["strtol"]
        return self.inline_call(strtol, nptr, endptr, base).ret_expr
