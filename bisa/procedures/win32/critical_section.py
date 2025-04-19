from __future__ import annotations
import bisa


class InitializeCriticalSectionAndSpinCount(bisa.SimProcedure):
    def run(self, lpCriticalSection, dwSpinCount):
        return 1


class InitializeCriticalSectionEx(bisa.SimProcedure):
    def run(self, lpCriticalSection, dwSpinCount, Flags):
        return 1
