from __future__ import annotations
import bisa


class std__terminate(bisa.SimProcedure):  # pylint:disable=redefined-builtin
    # pylint:disable=arguments-differ

    NO_RET = True
    ALT_NAMES = ("std::terminate()",)

    def run(self):
        # FIXME: Call terminate handlers
        self.exit(1)
