#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

import unittest

import bisa


class TestSimTime(unittest.TestCase):
    def test_gettimeofday(self):
        proc = bisa.SIM_PROCEDURES["posix"]["gettimeofday"]()

        s = bisa.SimState(arch="amd64")
        s.regs.rdi = 0x8000
        s.regs.rsi = 0

        s.options.add(bisa.options.USE_SYSTEM_TIMES)
        proc.execute(s)
        assert not s.mem[0x8000].qword.resolved.symbolic
        assert not s.mem[0x8008].qword.resolved.symbolic

        s.options.discard(bisa.options.USE_SYSTEM_TIMES)
        proc.execute(s)
        assert s.mem[0x8000].qword.resolved.symbolic
        assert s.mem[0x8008].qword.resolved.symbolic

    def test_clock_gettime(self):
        proc = bisa.SIM_PROCEDURES["posix"]["clock_gettime"]()

        s = bisa.SimState(arch="amd64")
        s.regs.rdi = 0
        s.regs.rsi = 0x8000

        s.options.add(bisa.options.USE_SYSTEM_TIMES)
        proc.execute(s)
        assert not s.mem[0x8000].qword.resolved.symbolic
        assert not s.mem[0x8008].qword.resolved.symbolic

        s.options.discard(bisa.options.USE_SYSTEM_TIMES)
        proc.execute(s)
        assert s.mem[0x8000].qword.resolved.symbolic
        assert s.mem[0x8008].qword.resolved.symbolic


if __name__ == "__main__":
    unittest.main()
