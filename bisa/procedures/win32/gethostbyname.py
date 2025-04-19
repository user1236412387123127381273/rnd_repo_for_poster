from __future__ import annotations
import logging


import bisa

l = logging.getLogger("bisa.procedures.win32.gethostbyname")


class gethostbyname(bisa.SimProcedure):
    def run(self, _):  # pylint:disable=arguments-differ
        return self.state.solver.BVS("gethostbyname_retval", 32, key=("api", "gethostbyname_retval"))
