from __future__ import annotations

from collections.abc import Iterable, Callable
from typing import Any

from bisa.storage.memory_mixins.memory_mixin import MemoryMixin


class TopMergerMixin(MemoryMixin):
    """
    A memory mixin for merging values in memory to TOP.
    """

    def __init__(self, *args, top_func=None, **kwargs):
        self._top_func: Callable = top_func

        super().__init__(*args, **kwargs)

    def _merge_values(self, values: Iterable[tuple[Any, Any]], merged_size: int, **kwargs):
        return self._top_func(merged_size * self.state.arch.byte_width)

    def copy(self, memo=None):
        copied = super().copy(memo)
        copied._top_func = self._top_func
        return copied
