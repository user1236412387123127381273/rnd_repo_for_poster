from __future__ import annotations
import bisa


class exit(bisa.SimProcedure):  # pylint:disable=redefined-builtin
    # pylint:disable=arguments-differ

    NO_RET = True

    def run(self, exit_code):
        self.exit(exit_code)
