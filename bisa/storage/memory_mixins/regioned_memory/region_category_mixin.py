from __future__ import annotations

from bisa.storage.memory_mixins.memory_mixin import MemoryMixin


class RegionCategoryMixin(MemoryMixin):
    @property
    def category(self):
        return "mem"
