from __future__ import annotations
import bisa

import logging

l = logging.getLogger(name=__name__)


class listen(bisa.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, sockfd, backlog):  # pylint:disable=unused-argument
        return self.state.solver.Unconstrained("listen", self.arch.sizeof["int"], key=("api", "listen"))
