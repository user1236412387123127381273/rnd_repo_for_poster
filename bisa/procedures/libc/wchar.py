from __future__ import annotations
import bisa


class wcscmp(bisa.SimProcedure):
    # pylint:disable=arguments-differ
    def run(self, lpString1, lpString2):
        strcmp = bisa.SIM_PROCEDURES["libc"]["strcmp"]
        return self.inline_call(strcmp, lpString1, lpString2, wchar=True).ret_expr


class wcscasecmp(bisa.SimProcedure):
    # pylint:disable=arguments-differ
    def run(self, lpString1, lpString2):
        strcmp = bisa.SIM_PROCEDURES["libc"]["strcmp"]
        return self.inline_call(strcmp, lpString1, lpString2, wchar=True, ignore_case=True).ret_expr
