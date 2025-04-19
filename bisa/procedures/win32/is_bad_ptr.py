from __future__ import annotations
import bisa


class IsBadReadPtr(bisa.SimProcedure):
    def run(self, ptr, length):
        try:
            return (~self.state.memory.permissions(ptr)[0]).zero_extend(self.state.arch.bits - 1)
        except bisa.errors.SimMemoryError:
            return 1


class IsBadWritePtr(bisa.SimProcedure):
    def run(self, ptr, length):
        try:
            return (~self.state.memory.permissions(ptr)[1]).zero_extend(self.state.arch.bits - 1)
        except bisa.errors.SimMemoryError:
            return 1


class IsBadCodePtr(bisa.SimProcedure):
    def run(self, ptr, length):
        try:
            return (~self.state.memory.permissions(ptr)[2]).zero_extend(self.state.arch.bits - 1)
        except bisa.errors.SimMemoryError:
            return 1
