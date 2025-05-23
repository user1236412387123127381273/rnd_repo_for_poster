#!/usr/bin/env python3
# pylint: disable=missing-class-docstring
from __future__ import annotations
from unittest import main, TestCase

from bisa.engines.light.data import SpOffset
from bisa.engines.light.engine import SimEngineLight


class TestSpOffset(TestCase):
    def test_difference_between_two_sp_offset_is_concrete(self):
        size = 8
        first_offset = SpOffset(size, 10)
        second_offset = SpOffset(size, 20)

        self.assertEqual(first_offset - second_offset, -10)

    def test_extract_offset_to_sp_sub(self):
        sp = SimEngineLight.sp_offset(64, 0)
        sp_offset_expr = sp - 0x10
        sp_offset = SimEngineLight.extract_offset_to_sp(sp_offset_expr)

        self.assertEqual(sp_offset, 0xFFFFFFFFFFFFFFF0)


if __name__ == "__main__":
    main()
