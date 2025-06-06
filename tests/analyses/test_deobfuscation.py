#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin


from unittest import TestCase, main
import os.path

import bisa

from tests.common import bin_location, skip


class TestDeobfuscation(TestCase):
    @skip
    def test_obfuscation_detection_c427(self):
        # the binary is not available in the public binaries repo
        binary_path = os.path.join(
            bin_location,
            "tests",
            "x86_64",
            "windows",
            "c4270d3a385f54ef44f1b7ac7f02b031f977934a566e8fcef0adfabade1daad3.sys",
        )
        proj = bisa.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFG(force_smart_scan=False, force_complete_scan=False)

        pd = proj.analyses.ObfuscationDetector(cfg=cfg.model)
        assert pd.obfuscated is True
        assert pd.possible_obfuscators == ["vmprotect"]

    def test_obfuscation_detection_vmprotect_project1(self):
        binary_path = os.path.join(
            bin_location,
            "tests",
            "x86_64",
            "windows",
            "Project1.vmp.exe",
        )
        proj = bisa.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFG(force_smart_scan=False, force_complete_scan=False)

        pd = proj.analyses.ObfuscationDetector(cfg=cfg.model)
        assert pd.obfuscated is True
        assert pd.possible_obfuscators == ["vmprotect"]


if __name__ == "__main__":
    main()
