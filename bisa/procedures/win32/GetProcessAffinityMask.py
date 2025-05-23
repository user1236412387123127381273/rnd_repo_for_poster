from __future__ import annotations
import logging

import claripy

import bisa


l = logging.getLogger(name=__name__)

# BOOL GetProcessAffinityMask(
#   HANDLE     hProcess,
#   PDWORD_PTR lpProcessAffinityMask,
#   PDWORD_PTR lpSystemAffinityMask
# );


class GetProcessAffinityMask(bisa.SimProcedure):
    paffinity_mask = None
    saffinity_mask = None

    def run(self, _, lpProcessAffinityMask, lpSystemAffinityMask):  # pylint:disable=arguments-differ
        self.fill_symbolic()
        l.info("Setting symbolic memory at %s %s", str(lpProcessAffinityMask), str(lpSystemAffinityMask))

        self.state.mem[lpProcessAffinityMask].dword = self.paffinity_mask
        self.state.mem[lpSystemAffinityMask].dword = self.saffinity_mask

        return 1

    def fill_symbolic(self):
        self.paffinity_mask = self.state.solver.BVS("lpProcessAffinityMask", 32, key=("api", "lpProcessAffinityMask"))
        self.saffinity_mask = self.state.solver.BVS("lpSystemAffinityMask", 32, key=("api", "lpSystemAffinityMask"))

    def fill_concrete(self):
        self.paffinity_mask = claripy.BVV(3, 32)
        self.saffinity_mask = claripy.BVV(3, 32)
