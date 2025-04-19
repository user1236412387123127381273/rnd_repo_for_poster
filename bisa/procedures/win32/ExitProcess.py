from __future__ import annotations
import bisa


class ExitProcess(bisa.SimProcedure):
    NO_RET = True

    def run(self, exit_status):
        self.exit(exit_status)
