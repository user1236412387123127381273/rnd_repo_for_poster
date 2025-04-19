from __future__ import annotations
import bisa
import logging

l = logging.getLogger(name=__name__)


class strnlen(bisa.SimProcedure):
    def run(self, s, n, wchar=False):  # pylint:disable=arguments-differ,unused-argument
        strlen = bisa.SIM_PROCEDURES["libc"]["strlen"]

        maxlen = self.state.solver.eval_one(n)
        return self.inline_call(strlen, s, maxlen=maxlen).ret_expr
