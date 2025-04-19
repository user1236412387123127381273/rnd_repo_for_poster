from __future__ import annotations
import bisa


class xalloc_die(bisa.SimProcedure):
    """
    xalloc_die
    """

    NO_RET = True

    # pylint: disable=arguments-differ
    def run(self):
        self.exit(1)
