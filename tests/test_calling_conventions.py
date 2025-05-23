#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests"  # pylint:disable=redefined-builtin

import os
from unittest import TestCase, main

import archinfo

from bisa.calling_conventions import (
    SimReferenceArgument,
    SimStackArg,
    SimTypeInt,
    SimTypeFixedSizeArray,
    SimCCSystemVAMD64,
    SimTypeFunction,
    SimRegArg,
    SimCCMicrosoftAMD64,
)
from bisa.sim_type import parse_file, SimStructValue
from bisa import Project, load_shellcode

from .common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestCallingConvention(TestCase):
    def test_SystemVAMD64_flatten_int(self):
        arch = archinfo.arch_from_id("amd64")
        cc = SimCCSystemVAMD64(arch)

        int_type = SimTypeInt().with_arch(arch)
        flattened_int = cc._flatten(int_type)
        self.assertTrue(all(isinstance(key, int) for key in flattened_int))
        self.assertTrue(all(isinstance(value, list) for value in flattened_int.values()))
        for v in flattened_int.values():
            for subtype in v:
                self.assertIsInstance(subtype, SimTypeInt)

    def test_SystemVAMD64_flatten_array(self):
        arch = archinfo.arch_from_id("amd64")
        cc = SimCCSystemVAMD64(arch)

        int_type = SimTypeInt().with_arch(arch)
        array_type = SimTypeFixedSizeArray(int_type, 20).with_arch(arch)
        flattened_array = cc._flatten(array_type)
        self.assertTrue(all(isinstance(key, int) for key in flattened_array))
        self.assertTrue(all(isinstance(value, list) for value in flattened_array.values()))
        for v in flattened_array.values():
            for subtype in v:
                self.assertIsInstance(subtype, SimTypeInt)

    def test_arg_locs_array(self):
        arch = archinfo.arch_from_id("amd64")
        cc = SimCCSystemVAMD64(arch)
        proto = SimTypeFunction([SimTypeFixedSizeArray(SimTypeInt().with_arch(arch), 2).with_arch(arch)], None)

        # It should not raise any exception!
        cc.arg_locs(proto)

    def test_struct_ffi(self):
        with open(os.path.join(test_location, "../tests_src/test_structs.c")) as fp:
            decls = parse_file(fp.read())

        p = Project(os.path.join(test_location, "x86_64/test_structs.o"), auto_load_libs=False)

        def make_callable(name):
            return p.factory.callable(p.loader.find_symbol(name).rebased_addr, decls[0][name])

        test_small_struct_return = make_callable("test_small_struct_return")
        result = test_small_struct_return()
        self.assertIsInstance(result, SimStructValue)
        self.assertTrue((result.a == 1).is_true())
        self.assertTrue((result.b == 2).is_true())

    def test_array_ffi(self):
        # NOTE: if this test is failing and you think it is wrong, you might be right :)
        p = load_shellcode(b"\xc3", arch="amd64")
        s = p.factory.blank_state()
        s.regs.rdi = 123
        s.regs.rsi = 456
        s.regs.rdx = 789
        execve = parse_file("int execve(const char *pathname, char *const argv[], char *const envp[]);")[0]["execve"]
        cc = p.factory.cc()
        assert all((x == y).is_true() for x, y in zip(cc.get_args(s, execve), (123, 456, 789)))
        # however, this is definitely right
        assert [list(loc.get_footprint()) for loc in cc.arg_locs(execve)] == [
            [SimRegArg("rdi", 8)],
            [SimRegArg("rsi", 8)],
            [SimRegArg("rdx", 8)],
        ]

    def test_microsoft_amd64(self):
        arch = archinfo.ArchAMD64()
        cc = SimCCMicrosoftAMD64(arch)
        ty1 = parse_file("struct foo { int x; int y; };", arch=arch)[1]["struct foo"]
        loc1 = cc.return_val(ty1, perspective_returned=True)
        assert loc1 is not None
        assert loc1.get_footprint() == {SimRegArg("rax", 8)}
        loc2 = cc.return_val(ty1, perspective_returned=False)
        assert loc2 is not None
        assert loc2.get_footprint() == {SimRegArg("rax", 8)}

        ty3 = parse_file("struct foo { short x; int y; short z; };", arch=arch)[1]["struct foo"]
        loc3 = cc.return_val(ty3, perspective_returned=True)
        assert isinstance(loc3, SimReferenceArgument)
        assert loc3.ptr_loc == SimRegArg("rax", 8)
        assert loc3.main_loc.get_footprint() == {SimStackArg(0, 2), SimStackArg(4, 4), SimStackArg(8, 2)}
        loc4 = cc.return_val(ty3, perspective_returned=False)
        assert isinstance(loc4, SimReferenceArgument)
        assert loc4.ptr_loc == SimRegArg("rcx", 8)
        assert loc4.main_loc.get_footprint() == {SimStackArg(0, 2), SimStackArg(4, 4), SimStackArg(8, 2)}


if __name__ == "__main__":
    main()
