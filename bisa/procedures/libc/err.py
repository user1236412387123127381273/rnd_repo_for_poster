from __future__ import annotations
import bisa


class err(bisa.SimProcedure):  # pylint:disable=redefined-builtin
    # pylint:disable=arguments-differ,missing-class-docstring,redefined-builtin

    NO_RET = True

    def run(self, eval, fmt):
        fd = self.state.posix.get_fd(1)
        fprintf = bisa.SIM_PROCEDURES["libc"]["fprintf"]
        self.inline_call(fprintf, fd, fmt)  # FIXME: This will not properly replace format strings
        self.exit(eval)
