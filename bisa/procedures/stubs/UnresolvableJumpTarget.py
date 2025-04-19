from __future__ import annotations
import bisa


class UnresolvableJumpTarget(bisa.SimProcedure):
    NO_RET = True

    def run(self):  # pylint: disable=arguments-differ
        return
