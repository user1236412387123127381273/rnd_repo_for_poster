# pylint: disable=missing-class-docstring
from __future__ import annotations
import claripy

import bisa


class ExAllocatePool(bisa.SimProcedure):
    def run(self, PoolType, NumberOfBytes):  # pylint:disable=arguments-differ, unused-argument
        addr = self.state.heap._malloc(NumberOfBytes)
        memset = bisa.SIM_PROCEDURES["libc"]["memset"]
        self.inline_call(memset, addr, claripy.BVV(0, 8), NumberOfBytes)  # zerofill
        return addr
