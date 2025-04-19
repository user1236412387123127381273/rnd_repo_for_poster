from __future__ import annotations
import bisa


class free(bisa.SimProcedure):
    # pylint:disable=arguments-differ,unused-argument

    def run(self, ptr):
        self.state.heap._free(ptr)
