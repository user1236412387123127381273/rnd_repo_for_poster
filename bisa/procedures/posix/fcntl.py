from __future__ import annotations
import bisa


class fcntl(bisa.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, fd, cmd):
        #  this is a stupid stub that does not do anything besides returning an unconstrained variable.
        return self.state.solver.BVS("sys_fcntl", self.arch.sizeof["int"], key=("api", "fcntl"))
