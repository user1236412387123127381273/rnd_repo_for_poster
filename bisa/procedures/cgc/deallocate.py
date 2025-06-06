from __future__ import annotations
import logging

import claripy
from unique_log_filter import UniqueLogFilter

import bisa
from bisa.state_plugins.sim_action_object import SimActionObject

l = logging.getLogger(name=__name__)
l.addFilter(UniqueLogFilter())


class deallocate(bisa.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, addr, length):
        if isinstance(addr, SimActionObject):
            addr = addr.ast
        if isinstance(length, SimActionObject):
            length = length.ast

        # return code (see deallocate() docs)
        r = claripy.ite_cases(
            (
                (addr % 0x1000 != 0, self.state.cgc.EINVAL),
                (length == 0, self.state.cgc.EINVAL),
                (self.state.cgc.addr_invalid(addr), self.state.cgc.EINVAL),
                (self.state.cgc.addr_invalid(addr + length), self.state.cgc.EINVAL),
            ),
            claripy.BVV(0, self.state.arch.bits),
        )

        if self.state.solver.symbolic(addr):
            l.warning("Concretizing symbolic address passed to deallocate to max_int")

        addr = self.state.solver.max_int(addr)

        # into a page
        page_size = self.state.memory.page_size
        base_page_num = addr // page_size

        if self.state.solver.symbolic(length):
            l.warning("Concretizing symbolic length passed to deallocate to max_int")

        length = self.state.solver.max_int(length)
        aligned_length = ((length + 0xFFF) // 0x1000) * 0x1000

        # only add sinkholes and unmap on success
        if self.state.solver.max_int(r) == 0:
            # shorten length
            allowed_pages = 0
            while (
                allowed_pages * page_size < aligned_length and base_page_num + allowed_pages in self.state.memory._pages
            ):
                allowed_pages += 1

            if allowed_pages == 0:
                return r

            allowed_length = allowed_pages * page_size
            self.state.cgc.add_sinkhole(addr, allowed_length)

            l.debug("Deallocating [%#x, %#x]", addr, addr + allowed_length - 1)
            self.state.memory.unmap_region(addr, allowed_length)

        return r
