from __future__ import annotations
import bisa


class unlink(bisa.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, path):
        # TODO: do this the other way around
        unlink_sys = bisa.SIM_PROCEDURES["linux_kernel"]["unlink"]
        return self.inline_call(unlink_sys, path).ret_expr
