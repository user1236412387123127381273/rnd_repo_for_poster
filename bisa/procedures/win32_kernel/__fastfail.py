from __future__ import annotations
import bisa


class __fastfail(bisa.SimProcedure):
    """
    Immediately terminates the calling process with minimum overhead.

    https://learn.microsoft.com/en-us/cpp/intrinsics/fastfail?view=msvc-170
    """

    NO_RET = True

    def run(self, _):  # pylint:disable=arguments-differ
        self.exit(0xC0000409)
