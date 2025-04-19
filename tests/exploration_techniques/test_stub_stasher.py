#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.exploration_techniques"  # pylint:disable=redefined-builtin

import unittest

import bisa


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestStubStasher(unittest.TestCase):
    def test_stub_stasher(self):
        p = bisa.load_shellcode(
            """
            test rcx, rcx
            jz case_z

            case_nz:
            mov rdx, 0x12345678
            call rdx
            ret

            case_z:
            mov rax, 1
            ret
            """,
            "AMD64",
        )

        lib = bisa.procedures.definitions.SimLibrary()
        p.hook(0x12345678, lib.get_stub("__random_stub__", p.arch))

        sm = p.factory.simgr(p.factory.call_state(0))
        sm.use_technique(bisa.exploration_techniques.StubStasher())
        sm.explore()

        assert len(sm.stashes["stub"]) == 1
        assert len(sm.stashes["deadended"]) == 1


if __name__ == "__main__":
    unittest.main()
