from __future__ import annotations
import bisa


class xstrtol_fatal(bisa.SimProcedure):
    """
    xstrtol_fatal
    """

    NO_RET = True

    # pylint: disable=unused-argument,arguments-differ
    def run(self, err, opt_idx, c, long_options, arg):
        self.exit(1)
