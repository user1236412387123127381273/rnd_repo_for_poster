from __future__ import annotations
import claripy

import bisa


class sigaction(bisa.SimProcedure):
    def run(self, signum, act, oldact):  # pylint:disable=arguments-differ,unused-argument
        # TODO: actually do something
        return claripy.BVV(0, self.arch.sizeof["long"])


class rt_sigaction(bisa.SimProcedure):
    def run(self, signum, act, oldact, sigsetsize):  # pylint:disable=arguments-differ,unused-argument
        # TODO: actually do something
        # ...hack
        if self.state.solver.is_true(signum == 33):
            return self.state.libc.ret_errno("EINVAL")
        return claripy.BVV(0, self.arch.sizeof["long"])
