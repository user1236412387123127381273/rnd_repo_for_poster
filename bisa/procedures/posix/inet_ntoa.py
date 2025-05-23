from __future__ import annotations
from socket import inet_ntoa as _inet_ntoa

from claripy import BVS, BVV, Concat
from claripy.ast import BV

import bisa
from bisa.sim_type import SimStructValue


class inet_ntoa(bisa.SimProcedure):
    """
    inet_ntoa simprocedure
    """

    # inet_ntoa is for ipv4 addresses, so we do not need 4(6|8) bytes to store it
    INET_INADDRSTRLEN = 16

    def run(self, addr_in: SimStructValue):  # type: ignore # pylint:disable=arguments-differ,unused-argument
        """
        Run the simprocedure

        :param addr_in: inet_addr struct (which is just a 32-bit int)
        """

        static_buffer = self.project.loader.extern_object.make_extern(
            "bisa##inet_ntoa_static_buffer",
            size=self.INET_INADDRSTRLEN,
        ).rebased_addr

        rv_exprs: list[BV] = []
        addr_s_in = addr_in["s_addr"]

        if addr_s_in.concrete:
            addr_in_i32 = self.state.solver.eval_one(addr_s_in, default=0)
            inet_str = (
                # "big" is network byte ordering, we want to preserve it in net order
                # because `inet_ntoa` expects to be given that ordering (but in bytes
                # and not a python int)
                bytes(_inet_ntoa(addr_in_i32.to_bytes(4, "big")), "utf-8")
                + b"\x00"
            )
            rv_exprs.extend(BVV(b, size=self.state.arch.byte_width) for b in inet_str)
        else:
            rv_exprs.extend(
                BVS(f"inet_ntoa_{i}", size=self.state.arch.byte_width) for i in range(self.INET_INADDRSTRLEN)
            )

            rv_exprs.append(BVV(0, size=self.state.arch.byte_width))

        buf_data = Concat(*rv_exprs)

        self.state.memory.store(
            # No endness here -- would store it backward (nul-first)
            static_buffer,
            buf_data,
        )

        return static_buffer
