from __future__ import annotations
import bisa


class realloc(bisa.SimProcedure):
    # pylint:disable=arguments-differ
    def run(self, ptr, size):
        return self.state.heap._realloc(ptr, size)
