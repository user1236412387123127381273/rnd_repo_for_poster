from __future__ import annotations
import bisa


class time(bisa.SimProcedure):
    # pylint:disable=arguments-differ
    def run(self, time_ptr):
        linux_time = bisa.SIM_PROCEDURES["linux_kernel"]["time"]
        return self.inline_call(linux_time, time_ptr).ret_expr
