from __future__ import annotations
import claripy

import bisa


class select(bisa.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, nfds, readfds, writefds, exceptfds, timeout):  # pylint: disable=unused-argument
        try:
            nfds_v = self.state.solver.eval_one(nfds)
            # readfds_v = self.state.solver.eval_one(readfds)
            writefds_v = self.state.solver.eval_one(writefds)
            exceptfds_v = self.state.solver.eval_one(exceptfds)
        except bisa.errors.SimSolverError as err:
            raise bisa.errors.SimProcedureArgumentError("Can't handle symbolic select arguments") from err

        if writefds_v != 0 or exceptfds_v != 0:
            raise bisa.errors.SimProcedureError("Can't handle write or exception events in select")

        arch_bits = self.arch.bits
        arch_bytes = self.arch.bytes

        long_array = []
        long_array_size = ((nfds_v - 1) + arch_bits) // arch_bits
        for offset in range(long_array_size):
            long = self.state.memory.load(readfds + offset * arch_bytes, arch_bytes, endness=self.arch.memory_endness)
            long_array.append(long)
        for i in range(nfds_v - 1):
            # get a bit
            long_pos = i // arch_bits
            bit_offset = i % arch_bits
            bit = long_array[long_pos][bit_offset]

            if bit.symbolic or self.state.solver.eval(bit) == 1:
                # set this bit to symbolic
                long_array[long_pos] = (
                    long_array[long_pos][arch_bits - 1 : bit_offset + 1]
                    .concat(claripy.BVS("fd_state", 1))
                    .concat(long_array[long_pos][bit_offset - 1 :])
                )

        # write things back
        for offset in range(long_array_size):
            self.state.memory.store(readfds + offset * arch_bytes, long_array[offset], endness=self.arch.memory_endness)

        return claripy.BVV(0, 1).concat(claripy.BVS("select_ret", 31))
