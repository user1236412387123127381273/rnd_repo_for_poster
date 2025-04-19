from __future__ import annotations

import unittest

import bisa


class TestAstDeps(unittest.TestCase):
    """
    Previously we had a bug where with the AST_DEPS option enabled, SAO would be
    passed to claripy, which would cause an exception to be raised.

    TODO: These tests only test that we can step with AST_DEPS enabled. We
    should also test that the option is actually used and an expected result is
    produced.
    """

    # pylint: disable=no-self-use

    def test_stepping_vex(self):
        code = b"\x48\x8d\x54\x24\x08"  # lea rdx, [rsp + 0x8]
        proj = bisa.load_shellcode(code, arch="AMD64")

        state = proj.factory.entry_state()
        state.options.add(bisa.options.AST_DEPS)
        state.step()

    def test_stepping_pcode(self):
        code = b"\x48\x8d\x54\x24\x08"
        proj = bisa.load_shellcode(code, arch="AMD64", engine=bisa.engines.UberEnginePcode)

        state = proj.factory.entry_state()
        state.options.add(bisa.options.AST_DEPS)
