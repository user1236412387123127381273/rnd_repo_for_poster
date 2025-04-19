from __future__ import annotations
import bisa
import itertools


malloc_mem_counter = itertools.count()


class malloc(bisa.SimProcedure):
    # pylint:disable=arguments-differ
    def run(self, sim_size):
        return self.state.heap._malloc(sim_size)
