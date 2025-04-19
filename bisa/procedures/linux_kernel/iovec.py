from __future__ import annotations

import claripy

import bisa
from bisa.procedures.posix.read import read
from bisa.procedures.posix.write import write
from bisa.sim_type import register_types, parse_types

register_types(
    parse_types(
        """
struct iovec {
    void  *iov_base;    /* Starting address */
    size_t iov_len;     /* Number of bytes to transfer */
};
"""
    )
)


class readv(bisa.SimProcedure):
    def run(self, fd, iovec, iovcnt):
        if iovec.symbolic or iovcnt.symbolic:
            raise bisa.errors.SimPosixError("Can't handle symbolic arguments to readv")
        iovcnt = self.state.solver.eval(iovcnt)
        res = 0
        for element in self.state.mem[iovec].struct.iovec.array(iovcnt).resolved:
            tmpres = self.inline_call(read, fd, element.iov_base, element.iov_len).ret_expr
            if self.state.solver.is_true(claripy.SLT(tmpres, 0)):
                return tmpres

        return res


class writev(bisa.SimProcedure):
    def run(self, fd, iovec, iovcnt):
        if iovec.symbolic or iovcnt.symbolic:
            raise bisa.errors.SimPosixError("Can't handle symbolic arguments to writev")
        iovcnt = self.state.solver.eval(iovcnt)
        res = 0
        for element in self.state.mem[iovec].struct.iovec.array(iovcnt).resolved:
            tmpres = self.inline_call(write, fd, element.iov_base, element.iov_len).ret_expr
            if self.state.solver.is_true(claripy.SLT(tmpres, 0)):
                return tmpres

        return res
