from __future__ import annotations
import bisa


class setvbuf(bisa.SimProcedure):
    def run(self, stream, buf, type_, size):
        return 0
