from __future__ import annotations
import bisa


class setsockopt(bisa.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, sockfd, level, optname, optval, optmain):
        return 0
