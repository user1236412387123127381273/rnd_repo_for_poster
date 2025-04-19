from __future__ import annotations
import bisa


class CreateMutexA(bisa.SimProcedure):
    def run(self, lpMutexAttributes, bInitialOwner, lpName):
        return 1


class CreateMutexEx(CreateMutexA):
    pass
