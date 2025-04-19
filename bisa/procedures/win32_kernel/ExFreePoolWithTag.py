# pylint: disable=missing-class-docstring
from __future__ import annotations
from bisa import SimProcedure


class ExFreePoolWithTag(SimProcedure):
    def run(self, P, Tag):  # pylint:disable=arguments-differ, unused-argument
        self.state.heap._free(P)
