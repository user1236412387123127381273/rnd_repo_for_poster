from __future__ import annotations
import bisa

from cle.backends.externs.simdata.io_file import io_file_data_for_arch


class fwrite(bisa.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, src, size, nmemb, file_ptr):
        fd_offset = io_file_data_for_arch(self.state.arch)["fd"]
        fileno = self.state.mem[file_ptr + fd_offset :].int.resolved
        simfd = self.state.posix.get_fd(fileno)
        if simfd is None:
            return -1
        return simfd.write(src, size * nmemb)


fwrite_unlocked = fwrite
