from __future__ import annotations
from bisa.procedures.java import JavaSimProcedure


class LoadLibrary(JavaSimProcedure):
    __provides__ = (("java.lang.System", "loadLibrary(java.lang.String)"),)

    def run(self, lib):  # pylint: disable=arguments-differ,unused-argument
        pass
