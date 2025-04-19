from __future__ import annotations
import bisa


class _dl_initial_error_catch_tsd(bisa.SimProcedure):
    def run(self, static_addr=0):
        return static_addr
