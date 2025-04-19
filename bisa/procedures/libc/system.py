from __future__ import annotations
import bisa

import logging

l = logging.getLogger(name=__name__)


class system(bisa.SimProcedure):
    # pylint:disable=arguments-differ,unused-argument
    def run(self, cmd):
        retcode = self.state.solver.Unconstrained("system_returncode", 8, key=("api", "system"))
        return retcode.zero_extend(self.arch.sizeof["int"] - 8)
