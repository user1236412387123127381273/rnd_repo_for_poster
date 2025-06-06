from __future__ import annotations
import bisa

from cle.backends.externs.simdata.io_file import io_file_data_for_arch


class fileno(bisa.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, f):
        # Get FILE struct
        io_file_data = io_file_data_for_arch(self.state.arch)

        # Get the file descriptor from FILE struct
        return self.state.mem[f + io_file_data["fd"]].int.resolved


fileno_unlocked = fileno
