from __future__ import annotations
import bisa


class tzset(bisa.SimProcedure):
    # emulate as a no-op
    # important because on my libc this contains inlined iolib ops and thus can't be executed when simprocs are enabled.
    def run(self):  # pylint: disable=arguments-differ
        pass
