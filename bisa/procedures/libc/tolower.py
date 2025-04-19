from __future__ import annotations
import claripy

import bisa


class tolower(bisa.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self, c):
        return claripy.If(claripy.And(c >= 65, c <= 90), c + 32, c)  # A - Z
