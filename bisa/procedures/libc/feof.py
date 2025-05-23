from __future__ import annotations
import claripy
from cle.backends.externs.simdata.io_file import io_file_data_for_arch

import bisa


class feof(bisa.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, file_ptr):
        # TODO handle errors
        fd_offset = io_file_data_for_arch(self.state.arch)["fd"]
        fileno = self.state.mem[file_ptr + fd_offset :].int.concrete
        simfd = self.state.posix.get_fd(fileno)
        if simfd is None:
            return None
        return claripy.If(simfd.eof(), claripy.BVV(1, self.arch.sizeof["int"]), 0)


feof_unlocked = feof
