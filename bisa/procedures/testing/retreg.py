from __future__ import annotations
import bisa


class retreg(bisa.SimProcedure):
    def run(self, reg=None):
        return self.state.registers.load(reg)
        # print self.state.options
