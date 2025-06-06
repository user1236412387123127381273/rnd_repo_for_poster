from __future__ import annotations
from typing import TYPE_CHECKING

from bisa.knowledge_plugins.key_definitions import LiveDefinitions
from bisa.knowledge_plugins.key_definitions.constants import ObservationPointType
from bisa.knowledge_plugins.key_definitions.atoms import (
    AtomKind,
    Atom,
    Register,
    MemoryLocation,
    Tmp,
    GuardUse,
    ConstantSrc,
)
from bisa.knowledge_plugins.key_definitions.definition import Definition
from bisa.analyses import register_analysis
from .reaching_definitions import ReachingDefinitionsAnalysis, ReachingDefinitionsModel
from .function_handler import FunctionHandler, FunctionCallData, FunctionCallRelationships
from .rd_state import ReachingDefinitionsState

if TYPE_CHECKING:
    from bisa.storage.memory_object import SimMemoryObject
    from bisa.storage.memory_mixins import MultiValuedMemory
    from bisa.storage.memory_mixins.paged_memory.pages import MVListPage

__all__ = (
    "Atom",
    "AtomKind",
    "ConstantSrc",
    "Definition",
    "FunctionCallData",
    "FunctionCallRelationships",
    "FunctionHandler",
    "GuardUse",
    "LiveDefinitions",
    "MemoryLocation",
    "ObservationPointType",
    "ReachingDefinitionsAnalysis",
    "ReachingDefinitionsModel",
    "ReachingDefinitionsState",
    "Register",
    "Tmp",
    "get_all_definitions",
)


def get_all_definitions(region: MultiValuedMemory) -> set[Definition]:
    all_defs: set[Definition] = set()

    # MultiValuedMemory only uses ListPage internally
    for page in region._pages.values():
        page: MVListPage

        for idx in page.stored_offset:
            cnt_set: SimMemoryObject | set[SimMemoryObject] | None = page.content[idx]
            if cnt_set is None:
                continue
            if type(cnt_set) is not set:
                cnt_set = {cnt_set}
            for cnt in cnt_set:
                for def_ in LiveDefinitions.extract_defs(cnt.object):
                    all_defs.add(def_)

    return all_defs


register_analysis(ReachingDefinitionsAnalysis, "ReachingDefinitions")
