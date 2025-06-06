from __future__ import annotations
import logging

from . import Analysis

from bisa import SIM_LIBRARIES
from bisa.analyses import AnalysesHub
from bisa.errors import BISAValueError

l = logging.getLogger(name=__name__)


class StaticHooker(Analysis):
    """
    This analysis works on statically linked binaries - it finds the library functions statically
    linked into the binary and hooks them with the appropriate simprocedures.

    Right now it only works on unstripped binaries, but hey! There's room to grow!
    """

    def __init__(self, library, binary=None):
        self.results = {}
        try:
            libs = SIM_LIBRARIES[library]
        except KeyError as err:
            raise BISAValueError(f"No such library {library}") from err

        if binary is None:
            binary = self.project.loader.main_object

        for func in binary.symbols:
            if not func.is_function:
                continue

            if self.project.is_hooked(func.rebased_addr):
                l.debug("Skipping %s at %#x, already hooked", func.name, func.rebased_addr)
                continue

            for lib in libs:
                if lib.has_implementation(func.name):
                    proc = lib.get(func.name, self.project.arch)
                    self.results[func.rebased_addr] = proc
                    if self.project.is_hooked(func.rebased_addr):
                        l.debug("Skipping %s at %#x, already hooked", func.name, func.rebased_addr)
                    else:
                        self.project.hook(func.rebased_addr, proc)
                        l.info("Hooked %s at %#x", func.name, func.rebased_addr)
                    break
            else:
                l.debug("Failed to hook %s at %#x", func.name, func.rebased_addr)


AnalysesHub.register_default("StaticHooker", StaticHooker)
