from __future__ import annotations
import bisa


class gettid(bisa.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self):
        return self.state.posix.pid
