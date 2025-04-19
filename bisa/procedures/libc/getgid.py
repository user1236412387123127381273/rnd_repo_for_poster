from __future__ import annotations
import bisa


class getgid(bisa.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self):
        return 1000
