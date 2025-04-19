from __future__ import annotations
import bisa

import logging

l = logging.getLogger(name=__name__)


class fflush(bisa.SimProcedure):
    # pylint:disable=arguments-differ,unused-argument

    def run(self, fd):
        return 0


fflush_unlocked = fflush
