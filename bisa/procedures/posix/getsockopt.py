from __future__ import annotations
import bisa


class getsockopt(bisa.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, sockfd, level, optname, optval, optlen):
        # TODO: ...

        return 0
