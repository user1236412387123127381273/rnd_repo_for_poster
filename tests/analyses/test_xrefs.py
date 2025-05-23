#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
import unittest

import bisa
from bisa.knowledge_plugins.xrefs import XRef, XRefType

from tests.common import bin_location


test_location = os.path.join(bin_location, "tests")


class TestXrefs(unittest.TestCase):
    def test_lwip_udpecho_bm(self):
        bin_path = os.path.join(test_location, "armel", "lwip_udpecho_bm.elf")
        p = bisa.Project(bin_path, auto_load_libs=False)
        cfg = p.analyses.CFG(data_references=True)

        func = cfg.functions[0x23C9]
        state = p.factory.blank_state()

        timenow_xrefs = p.kb.xrefs.get_xrefs_by_dst(0x1FFF36F4)  # the value in .bss
        assert len(timenow_xrefs) == 2
        assert timenow_xrefs == {
            XRef(ins_addr=0x23C9, dst=0x1FFF36F4, xref_type=XRefType.Offset),
            XRef(ins_addr=0x241D, dst=0x1FFF36F4, xref_type=XRefType.Offset),
        }

        # kill existing xrefs
        p.kb.xrefs.clear()
        prop = p.analyses.Propagator(func=func, base_state=state)
        _ = p.analyses.XRefs(func=func, replacements=prop.replacements)

        timenow_cp_xrefs = p.kb.xrefs.get_xrefs_by_dst(0x23D4)  # the constant in the constant pool
        timenow_xrefs = p.kb.xrefs.get_xrefs_by_dst(0x1FFF36F4)  # the value in .bss

        assert len(timenow_cp_xrefs) == 1
        assert next(iter(timenow_cp_xrefs)) == XRef(ins_addr=0x23C9, dst=0x23D4, xref_type=XRefType.Read)

        assert len(timenow_xrefs) == 3
        assert next(x for x in timenow_xrefs if x.type == XRefType.Offset) == XRef(
            ins_addr=0x23C9, dst=0x1FFF36F4, xref_type=XRefType.Offset
        )
        assert next(x for x in timenow_xrefs if x.type == XRefType.Read) == XRef(
            ins_addr=0x23CB, dst=0x1FFF36F4, xref_type=XRefType.Read
        )
        assert next(x for x in timenow_xrefs if x.type == XRefType.Write) == XRef(
            ins_addr=0x23CF, dst=0x1FFF36F4, xref_type=XRefType.Write
        )

    def test_lwip_udpecho_bm_the_better_way(self):
        bin_path = os.path.join(test_location, "armel", "lwip_udpecho_bm.elf")
        p = bisa.Project(bin_path, auto_load_libs=False)
        p.analyses.CFG(cross_references=True)

        timenow_cp_xrefs = p.kb.xrefs.get_xrefs_by_dst(0x23D4)  # the constant in the constant pool
        timenow_xrefs = p.kb.xrefs.get_xrefs_by_dst(0x1FFF36F4)  # the value in .bss

        assert len(timenow_cp_xrefs) == 1
        assert next(iter(timenow_cp_xrefs)) == XRef(ins_addr=0x23C9, dst=0x23D4, xref_type=XRefType.Read)
        # sys_now (2), time_isr (3) == 5
        assert len(timenow_xrefs) == 5

    def test_p2im_drone_with_inits(self):
        bin_path = os.path.join(test_location, "armel", "p2im_drone.elf")
        proj = bisa.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFG(data_references=True)

        func = cfg.functions["Peripherals_Init"]
        state = proj.factory.blank_state()
        prop = proj.analyses.Propagator(func=func, base_state=state)

        init_finder = proj.analyses.InitializationFinder(func=func, replacements=prop.replacements)
        overlay_state = init_finder.overlay_state

        cfg.do_full_xrefs(overlay_state=overlay_state)

        h12c1_inst_xrefs = proj.kb.xrefs.get_xrefs_by_dst(0x20001500)
        assert len(h12c1_inst_xrefs) == 5


if __name__ == "__main__":
    unittest.main()
