from __future__ import annotations
import bisa
import logging

l = logging.getLogger(name=__name__)


class CallReturn(bisa.SimProcedure):
    NO_RET = True

    def run(self):
        l.info("A factory.call_state-created path returned!")
        return
