from __future__ import annotations
import bisa


class abort(bisa.SimProcedure):
    NO_RET = True

    def run(self):
        self.exit(1)
