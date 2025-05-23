#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.sim.options"  # pylint:disable=redefined-builtin

import os
import sys
import unittest

import claripy

import bisa

from tests.common import bin_location


test_location = os.path.join(bin_location, "tests")


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
@unittest.skipIf(sys.platform == "win32", "broken on windows")
class Test0Div(unittest.TestCase):
    def _run_0div(self, arch):
        # check that we run in unicorn up to the zero-div site, fall back, try again in bisa, and error correctly.
        p = bisa.Project(os.path.join(test_location, arch, "test_0div"), auto_load_libs=False)
        s = p.factory.entry_state(add_options=bisa.options.unicorn)
        simgr = p.factory.simulation_manager(s)
        simgr.run(n=5)
        assert len(simgr.active) == 1
        simgr.step()
        assert len(simgr.errored) == 1
        assert isinstance(simgr.errored[0].error, bisa.errors.SimZeroDivisionException)

    def test_0div_i386(self):
        self._run_0div("i386")

    def test_0div_x86_64(self):
        self._run_0div("x86_64")

    def test_symbolic_0div(self):
        p = bisa.load_shellcode(b"X", arch="amd64")
        s = p.factory.blank_state()
        s.regs.rax = claripy.BVS("rax", 64)
        s.regs.rcx = claripy.BVS("rcx", 64)
        s.regs.rdx = claripy.BVS("rdx", 64)

        s.options.add(bisa.options.PRODUCE_ZERODIV_SUCCESSORS)
        successors = s.step(insn_bytes=b"\x48\xf7\xf1")  # div rcx
        assert len(successors.flat_successors) == 2

        s.options.discard(bisa.options.PRODUCE_ZERODIV_SUCCESSORS)
        successors = s.step(insn_bytes=b"\x48\xf7\xf1")  # div rcx
        assert len(successors.flat_successors) == 1


if __name__ == "__main__":
    unittest.main()
