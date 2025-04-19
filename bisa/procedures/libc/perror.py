from __future__ import annotations
import bisa


class perror(bisa.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, string):
        write = bisa.SIM_PROCEDURES["posix"]["write"]
        strlen = bisa.SIM_PROCEDURES["libc"]["strlen"]

        length = self.inline_call(strlen, string).ret_expr
        self.inline_call(write, 2, string, length)
