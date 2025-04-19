from __future__ import annotations
import bisa

import logging

l = logging.getLogger(name=__name__)


class atoi(bisa.SimProcedure):
    # pylint:disable=arguments-differ
    def run(self, s):
        strtol = bisa.SIM_PROCEDURES["libc"]["strtol"]
        val = strtol.strtol_inner(s, self.state, self.state.memory, 10, True)[1]
        return val[self.arch.sizeof["int"] - 1 : 0]
