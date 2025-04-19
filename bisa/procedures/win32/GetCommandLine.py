from __future__ import annotations
import bisa


class GetCommandLineA(bisa.SimProcedure):
    def run(self):
        return self.project.simos.acmdln_ptr


class GetCommandLineW(bisa.SimProcedure):
    def run(self):
        return self.project.simos.wcmdln_ptr
