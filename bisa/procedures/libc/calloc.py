from __future__ import annotations
import bisa


class calloc(bisa.SimProcedure):
    # pylint:disable=arguments-differ
    def run(self, sim_nmemb, sim_size):
        return self.state.heap._calloc(sim_nmemb, sim_size)
