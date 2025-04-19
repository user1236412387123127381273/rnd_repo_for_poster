from __future__ import annotations
import bisa


class GetCurrentThreadId(bisa.SimProcedure):
    def run(self):
        return 0xBAD76EAD
