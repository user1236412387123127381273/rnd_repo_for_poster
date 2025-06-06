from __future__ import annotations
import bisa


class openat(bisa.SimProcedure):
    # pylint:disable=arguments-differ,unused-argument

    def run(self, dirfd, p_addr, flags, mode):
        strlen = bisa.SIM_PROCEDURES["libc"]["strlen"]

        p_strlen = self.inline_call(strlen, p_addr)
        p_expr = self.state.memory.load(p_addr, p_strlen.max_null_index, endness="Iend_BE")
        path = self.state.solver.eval(p_expr, cast_to=bytes)

        # If path is absolute or dirfd is AT_FDCWD(-100), dirfd can be ignored.
        # Sometimes dirfd can be a 32 bit value in a 64 bit BV. So, instead of converting dirfd to signed integer, we
        # simply check the unsigned value.
        # TODO: Is above described way to check dirfd okay?
        dirfd_val = self.state.solver.eval(dirfd)
        # TODO: Implement support for opening path relative to directory corresponding to dirfd
        fd = self.state.posix.open(path, flags) if path.startswith(b"/") or dirfd_val == 4294967196 else None

        if fd is None:
            return -1

        return fd
