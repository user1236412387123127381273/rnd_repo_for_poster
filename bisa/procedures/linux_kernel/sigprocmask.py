from __future__ import annotations
import claripy

import bisa


class sigprocmask(bisa.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, how, set_, oldset, sigsetsize):
        self.state.memory.store(oldset, self.state.posix.sigmask(sigsetsize=sigsetsize), condition=oldset != 0)
        self.state.posix.sigprocmask(how, self.state.memory.load(set_, sigsetsize), sigsetsize, valid_ptr=set_ != 0)

        # TODO: EFAULT
        return claripy.If(
            claripy.And(
                how != self.state.posix.SIG_BLOCK,
                how != self.state.posix.SIG_UNBLOCK,
                how != self.state.posix.SIG_SETMASK,
            ),
            claripy.BVV(self.state.posix.EINVAL, self.arch.sizeof["int"]),
            0,
        )
