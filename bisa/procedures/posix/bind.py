from __future__ import annotations
import bisa

import logging

l = logging.getLogger(name=__name__)


class bind(bisa.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, fd, addr_ptr, addr_len):  # pylint:disable=unused-argument
        return self.state.solver.Unconstrained("bind", self.arch.sizeof["int"], key=("api", "bind"))
