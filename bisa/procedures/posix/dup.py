from __future__ import annotations
import bisa


class dup(bisa.SimProcedure):  # pylint:disable=W0622
    def run(self, oldfd):  # pylint:disable=arguments-differ
        oldfd = self.state.solver.eval(oldfd)
        if oldfd not in self.state.posix.fd:
            return self.state.libc.ret_errno("EBADF")

        # The new fd gets the lowest free number, so we search
        newfd = len(self.state.posix.fd.keys())  # e.g. '3' for [0, 1, 2]
        for i, fd in enumerate(sorted(self.state.posix.fd.keys())):
            if i != fd:  # "Free" slot in keys
                newfd = i

        self.state.posix.fd[newfd] = self.state.posix.fd[oldfd]
        return newfd


class dup2(bisa.SimProcedure):
    def run(self, oldfd, newfd):  # pylint:disable=arguments-differ
        oldfd = self.state.solver.eval(oldfd)
        newfd = self.state.solver.eval(newfd)

        if oldfd not in self.state.posix.fd:
            return self.state.libc.ret_errno("EBADF")

        if oldfd == newfd:
            return newfd

        if newfd >= 4096 or newfd < 0:  # ulimits 4096 is the default limit.
            return self.state.libc.ret_errno("EBADF")

        # copy old_fd to new_fd so they point to the same FD
        self.state.posix.fd[newfd] = self.state.posix.fd[oldfd]
        return newfd


class dup3(bisa.SimProcedure):
    def run(self, oldfd, newfd, flags):  # pylint:disable=arguments-differ
        oldfd = self.state.solver.eval(oldfd)
        newfd = self.state.solver.eval(newfd)

        if oldfd not in self.state.posix.fd:
            return self.state.libc.ret_errno("EBADF")

        if oldfd == newfd:
            return newfd

        if newfd >= 4096 or newfd < 0:  # ulimits 4096 is the default limit.
            return self.state.libc.ret_errno("EBADF")

        # copy old_fd to new_fd so they point to the same FD
        self.state.posix.fd[newfd] = self.state.posix.fd[oldfd]
        return newfd
