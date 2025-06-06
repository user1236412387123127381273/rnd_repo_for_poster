from __future__ import annotations
import bisa

import logging

l = logging.getLogger(name=__name__)


class pwrite64(bisa.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self, fd, buf, nbyte, offset):
        SEEK_SET = 0  # Seek from beginning of file.
        SEEK_CUR = 1  # Seek from current position.

        write = bisa.SIM_PROCEDURES["posix"]["write"]
        lseek = bisa.SIM_PROCEDURES["linux_kernel"]["lseek"]

        if self.state.solver.symbolic(offset):
            err = "Symbolic offset is not supported in pwrite64"
            l.error(err)
            raise bisa.errors.SimPosixError(err)

        offset = self.state.solver.eval(offset)

        old_offset = self.inline_call(lseek, fd, 0, SEEK_CUR).ret_expr
        old_offset = self.state.solver.eval(old_offset)

        if old_offset == -1:
            return -1

        lseek_ret = self.inline_call(lseek, fd, offset, SEEK_SET).ret_expr
        lseek_ret = self.state.solver.eval(lseek_ret)

        if lseek_ret == -1:
            return -1

        result = self.inline_call(write, fd, buf, nbyte).ret_expr
        result_val = self.state.solver.eval(result)

        restore_seek = self.inline_call(lseek, fd, old_offset, SEEK_SET).ret_expr
        restore_seek = self.state.solver.eval(restore_seek)

        if restore_seek == -1 or result_val == -1:
            return -1

        return result
