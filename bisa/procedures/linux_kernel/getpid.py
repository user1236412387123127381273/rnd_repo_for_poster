from __future__ import annotations
import bisa

# pylint:disable=arguments-differ


class getpid(bisa.SimProcedure):
    def run(self):
        return self.state.posix.pid


class getppid(bisa.SimProcedure):
    def run(self):
        return self.state.posix.ppid
