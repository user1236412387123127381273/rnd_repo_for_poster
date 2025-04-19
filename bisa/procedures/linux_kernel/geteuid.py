from __future__ import annotations
import bisa
from bisa.sim_type import SimTypeInt


class geteuid(bisa.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self):
        self.return_type = SimTypeInt(16, True)
        return 1000


class geteuid32(bisa.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self):
        self.return_type = SimTypeInt(32, True)
        return 1000
