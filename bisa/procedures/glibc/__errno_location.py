from __future__ import annotations
import bisa


class __errno_location(bisa.SimProcedure):
    def run(self):  # pylint:disable=arguments-differ
        return self.state.libc.errno_location
