from __future__ import annotations
import bisa

# pylint: disable=unused-argument,arguments-differ


class GetStdHandle(bisa.SimProcedure):
    def run(self, handle):
        if handle.op != "BVV":
            raise bisa.errors.SimProcedureArgumentError("Can't deal with symbolic std handle")

        # for now, return file descriptors + 1000 as handles
        if (handle == -10).is_true():
            return 1000
        if (handle == -11).is_true():
            return 1001
        if (handle == -12).is_true():
            return 1002
        return -1


class ReadFile(bisa.SimProcedure):
    def run(self, hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped):
        self.state.mem[lpNumberOfBytesRead].long = 0

        fd = hFile - 1000
        simfd = self.state.posix.get_fd(fd)
        if simfd is None:
            return 0

        bytes_read = simfd.read(lpBuffer, nNumberOfBytesToRead)
        self.state.mem[lpNumberOfBytesRead].long = bytes_read
        return 1


class WriteFile(bisa.SimProcedure):
    def run(self, hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped):
        self.state.mem[lpNumberOfBytesWritten].long = 0

        fd = hFile - 1000
        simfd = self.state.posix.get_fd(fd)
        if simfd is None:
            return 0

        bytes_written = simfd.write(lpBuffer, nNumberOfBytesToWrite)
        self.state.mem[lpNumberOfBytesWritten].long = bytes_written
        return 1
