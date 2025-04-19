from __future__ import annotations
import bisa


class rewind(bisa.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, file_ptr):
        fseek = bisa.SIM_PROCEDURES["libc"]["fseek"]
        self.inline_call(fseek, file_ptr, 0, 0)

        return
