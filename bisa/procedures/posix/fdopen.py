from __future__ import annotations
import claripy
from cle.backends.externs.simdata.io_file import io_file_data_for_arch

import bisa


# Reference for implementation: glibc-2.25/libio/iofdopen.c


def mode_to_flag(mode):
    # TODO improve this: handle mode = strings
    if mode[-1] == b"b":  # lol who uses windows
        mode = mode[:-1]
    all_modes = {
        b"r": bisa.storage.file.Flags.O_RDONLY,
        b"r+": bisa.storage.file.Flags.O_RDWR,
        b"w": bisa.storage.file.Flags.O_WRONLY | bisa.storage.file.Flags.O_CREAT,
        b"w+": bisa.storage.file.Flags.O_RDWR | bisa.storage.file.Flags.O_CREAT,
        b"a": bisa.storage.file.Flags.O_WRONLY | bisa.storage.file.Flags.O_CREAT | bisa.storage.file.Flags.O_APPEND,
        b"a+": bisa.storage.file.Flags.O_RDWR | bisa.storage.file.Flags.O_CREAT | bisa.storage.file.Flags.O_APPEND,
    }
    if mode not in all_modes:
        raise bisa.SimProcedureError(f"unsupported file open mode {mode}")

    return all_modes[mode]


def create_file(mode):
    # TODO improve this: handle mode = strings
    if mode[-1] == b"b":  # lol who uses windows
        mode = mode[:-1]
    all_modes = {
        b"r": False,
        b"r+": False,
        b"w": True,
        b"w+": True,
        b"a": True,
        b"a+": True,
    }
    if mode not in all_modes:
        raise bisa.SimProcedureError(f"unsupported file open mode {mode}")

    return all_modes[mode]


class fdopen(bisa.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, fd_int, m_addr):
        # pylint:disable=unused-variable
        strlen = bisa.SIM_PROCEDURES["libc"]["strlen"]

        m_strlen = self.inline_call(strlen, m_addr)
        m_expr = self.state.memory.load(m_addr, m_strlen.max_null_index, endness="Iend_BE")
        mode = self.state.solver.eval(m_expr, cast_to=bytes)

        # TODO: handle append and other mode subtleties

        fd_concr = self.state.posix.get_concrete_fd(fd_int, create_file=create_file(mode))
        if fd_concr not in self.state.posix.fd:
            # if file descriptor not found return NULL
            return 0
        # Allocate a FILE struct in heap
        malloc = bisa.SIM_PROCEDURES["libc"]["malloc"]
        io_file_data = io_file_data_for_arch(self.state.arch)
        file_struct_ptr = self.inline_call(malloc, io_file_data["size"]).ret_expr

        # Write the fd
        fd_bvv = claripy.BVV(fd_concr, 4 * 8)  # int
        self.state.memory.store(file_struct_ptr + io_file_data["fd"], fd_bvv, endness=self.state.arch.memory_endness)

        if self.state.solver.is_true(fd_int == fd_concr):
            return file_struct_ptr
        null = claripy.BVV(0, self.state.arch.bits)
        return claripy.If(fd_int == fd_concr, file_struct_ptr, null)
