from __future__ import annotations
import claripy

import bisa


class access(bisa.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, path, mode):
        ret = claripy.BVS("access", self.arch.sizeof["int"])
        self.state.add_constraints(claripy.Or(ret == 0, ret == -1))
        return ret
