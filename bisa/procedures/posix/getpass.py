from __future__ import annotations
import bisa


class getpass(bisa.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, prompt):
        # write out the prompt
        self.inline_call(bisa.SIM_PROCEDURES["libc"]["puts"], prompt)

        # malloc a buffer
        buf = self.inline_call(bisa.SIM_PROCEDURES["libc"]["malloc"], 1024).ret_expr

        # read into the buffer
        self.inline_call(bisa.SIM_PROCEDURES["posix"]["read"], 0, buf, 1024)

        # return the buffer
        return buf
