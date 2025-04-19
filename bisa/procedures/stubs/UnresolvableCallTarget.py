from __future__ import annotations
import bisa


class UnresolvableCallTarget(bisa.SimProcedure):
    NO_RET = False

    def run(self):  # pylint: disable=arguments-differ
        return
