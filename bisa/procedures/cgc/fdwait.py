from __future__ import annotations
import itertools

import claripy

import bisa

fdcount = itertools.count()


class fdwait(bisa.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, nfds, readfds, writefds, timeout, readyfds):
        run_count = next(fdcount)
        total_ready = claripy.BVV(0, self.state.arch.bits)

        read_fds = []
        for fd_set in range(0, 32, 8):
            sym_newbits = []
            for fd in range(fd_set, fd_set + 8):
                if bisa.options.CGC_NON_BLOCKING_FDS in self.state.options:
                    sym_bit = claripy.BVV(1, 1)
                else:
                    sym_bit = self.state.solver.Unconstrained(
                        f"fdwait_read_{run_count}_{fd}", 1, key=("syscall", "fdwait", fd, "read_ready")
                    )
                fd = claripy.BVV(fd, self.state.arch.bits)
                sym_newbit = claripy.If(claripy.ULT(fd, nfds), sym_bit, 0)
                total_ready += sym_newbit.zero_extend(self.state.arch.bits - 1)
                sym_newbits.append(sym_newbit)
            read_fds.extend(reversed(sym_newbits))
        self.state.memory.store(readfds, claripy.Concat(*read_fds), condition=readfds != 0)

        write_fds = []
        for fd_set in range(0, 32, 8):
            sym_newbits = []
            for fd in range(fd_set, fd_set + 8):
                if bisa.options.CGC_NON_BLOCKING_FDS in self.state.options:
                    sym_bit = claripy.BVV(1, 1)
                else:
                    sym_bit = self.state.solver.Unconstrained(
                        f"fdwait_write_{run_count}_{fd}", 1, key=("syscall", "fdwait", fd, "write_ready")
                    )

                fd = claripy.BVV(fd, self.state.arch.bits)
                sym_newbit = claripy.If(claripy.ULT(fd, nfds), sym_bit, 0)
                total_ready += sym_newbit.zero_extend(self.state.arch.bits - 1)
                sym_newbits.append(sym_newbit)
            write_fds.extend(reversed(sym_newbits))
        self.state.memory.store(writefds, claripy.Concat(*write_fds), condition=writefds != 0)

        self.state.memory.store(readyfds, total_ready, endness="Iend_LE", condition=readyfds != 0)

        tv_sec = self.state.memory.load(
            timeout, 4, endness=self.state.arch.memory_endness, condition=timeout != 0, fallback=0
        )
        tv_usec = self.state.memory.load(
            timeout + 4, 4, endness=self.state.arch.memory_endness, condition=timeout != 0, fallback=0
        )
        total_time = tv_sec * 1000000 + tv_usec
        self.state.cgc.time += claripy.If(total_ready == 0, total_time, 0)

        # TODO: errors
        return claripy.BVV(0, self.state.arch.bits)
