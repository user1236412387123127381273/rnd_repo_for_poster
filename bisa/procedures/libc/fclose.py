from __future__ import annotations
import bisa

from cle.backends.externs.simdata.io_file import io_file_data_for_arch


class fclose(bisa.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, fd_p):
        # Resolve file descriptor
        fd_offset = io_file_data_for_arch(self.state.arch)["fd"]
        fileno = self.state.mem[fd_p + fd_offset :].int.resolved

        # TODO: use a procedure that's not a linux syscall
        sys_close = bisa.SIM_PROCEDURES["posix"]["close"]

        # Call system close and return
        return self.inline_call(sys_close, fileno).ret_expr
