#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin


from unittest import TestCase, main
import os.path

import bisa

from tests.common import bin_location


class TestUnpacking(TestCase):
    def test_packing_detection_444a(self):
        binary_path = os.path.join(
            bin_location,
            "tests",
            "x86_64",
            "windows",
            "444a401b900eb825f216e95111dcb6ef94b01a81fc7b88a48599867db8c50365.sys",
        )
        proj = bisa.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFG(force_smart_scan=False, force_complete_scan=False)

        pd = proj.analyses.PackingDetector(cfg=cfg.model)
        assert pd.packed is True

    def test_packing_detection_pitou(self):
        # pitou is virtualized, not packed
        binary_path = os.path.join(
            bin_location,
            "tests",
            "x86_64",
            "windows",
            "pitou.sys",
        )
        proj = bisa.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFG(force_smart_scan=False, force_complete_scan=False)

        pd = proj.analyses.PackingDetector(cfg=cfg.model)
        assert pd.packed is False

    def test_packing_detection_dirtymoe(self):
        binary_path = os.path.join(
            bin_location,
            "tests",
            "x86_64",
            "windows",
            "dirtymoe.sys",
        )
        proj = bisa.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFG(force_smart_scan=False, force_complete_scan=False)

        pd = proj.analyses.PackingDetector(cfg=cfg.model)
        assert pd.packed is False

    def test_packing_detection_3ware(self):
        binary_path = os.path.join(
            bin_location,
            "tests",
            "x86_64",
            "windows",
            "3ware.sys",
        )
        proj = bisa.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFG(force_smart_scan=False, force_complete_scan=False)

        pd = proj.analyses.PackingDetector(cfg=cfg.model)
        assert pd.packed is False

    def test_packing_detection_mimidrv(self):
        binary_path = os.path.join(
            bin_location,
            "tests",
            "x86_64",
            "windows",
            "mimidrv.sys",
        )
        proj = bisa.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFG(force_smart_scan=False, force_complete_scan=False)

        pd = proj.analyses.PackingDetector(cfg=cfg.model)
        assert pd.packed is False

    def test_packing_detection_rain_upx(self):
        binary_path = os.path.join(
            bin_location,
            "tests",
            "i386",
            "windows",
            "rain32.upx",
        )
        proj = bisa.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFG(force_smart_scan=False, force_complete_scan=False)

        pd = proj.analyses.PackingDetector(cfg=cfg.model)
        assert pd.packed is True


if __name__ == "__main__":
    main()
