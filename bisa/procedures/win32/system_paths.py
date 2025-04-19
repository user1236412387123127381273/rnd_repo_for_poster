from __future__ import annotations
import bisa
import claripy


class GetTempPathA(bisa.SimProcedure):
    RESULT = claripy.BVV(b"C:\\Temp\\")

    def run(self, nBufferLength, lpBuffer):
        try:
            length = self.state.solver.eval_one(nBufferLength)
        except bisa.errors.SimValueError as err:
            raise bisa.errors.SimProcedureError("Can't handle symbolic nBufferLength in GetTempPath") from err

        copy_len = min(self.RESULT.length // 8, length - 1)
        self.state.memory.store(
            lpBuffer, self.RESULT[self.RESULT.length - 1 : self.RESULT.length - copy_len * 8].concat(claripy.BVV(0, 8))
        )
        return self.RESULT.length // 8


class GetWindowsDirectoryA(bisa.SimProcedure):
    RESULT = claripy.BVV(b"C:\\Windows")

    def run(self, lpBuffer, uSize):
        try:
            length = self.state.solver.eval_one(uSize)
        except bisa.errors.SimValueError as err:
            raise bisa.errors.SimProcedureError("Can't handle symbolic uSize in GetWindowsDirectory") from err

        copy_len = min(self.RESULT.length // 8, length - 1)
        self.state.memory.store(
            lpBuffer, self.RESULT[self.RESULT.length - 1 : self.RESULT.length - copy_len * 8].concat(claripy.BVV(0, 8))
        )
        return self.RESULT.length // 8
