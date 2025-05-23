from __future__ import annotations

import logging

import claripy

from bisa import sim_options as o
from bisa.storage.memory_mixins.memory_mixin import MemoryMixin

l = logging.getLogger(__name__)


class UnderconstrainedMixin(MemoryMixin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._unconstrained_range = 1024

    @MemoryMixin.memo
    def copy(self, memo):
        out = super().copy(memo)
        out._unconstrained_range = self._unconstrained_range
        return out

    def load(self, addr, size=None, **kwargs):
        self._constrain_underconstrained_index(addr)
        return super().load(addr, size, **kwargs)

    def store(self, addr, data, size=None, **kwargs):
        self._constrain_underconstrained_index(addr)
        super().store(addr, data, size, **kwargs)

    def _default_value(self, addr, size, *, name=None, key=None, inspect=True, events=True, **kwargs):
        if o.UNDER_CONSTRAINED_SYMEXEC in self.state.options and type(addr) is int:
            if self.category == "mem":
                alloc_depth = self.state.uc_manager.get_alloc_depth(addr)
                uc_alloc_depth = 0 if alloc_depth is None else alloc_depth + 1
            else:
                uc_alloc_depth = 0

            if name is None:
                name = f"mem_{addr:x}"

            bits = size * self.state.arch.byte_width
            return self.state.solver.Unconstrained(
                name, bits, key=key, inspect=inspect, events=events, uc_alloc_depth=uc_alloc_depth
            )

        return super()._default_value(addr, size, name=name, key=key, inspect=inspect, events=events, **kwargs)

    def _constrain_underconstrained_index(self, addr):
        if (
            o.UNDER_CONSTRAINED_SYMEXEC in self.state.options
            and isinstance(addr, claripy.ast.Base)
            and addr.has_annotation_type(claripy.annotation.UninitializedAnnotation)
            and self.state.uc_manager.get_alloc_depth(addr) is not None
        ) and (
            not self.state.uc_manager.is_bounded(addr)
            or self.state.solver.max_int(addr) - self.state.solver.min_int(addr) >= self._unconstrained_range
        ):
            # in under-constrained symbolic execution, we'll assign a new memory region for this address
            mem_region = self.state.uc_manager.assign(addr)

            # ... but only if it's not already been constrained to something!
            if self.state.solver.solution(addr, mem_region):
                self.state.add_constraints(addr == mem_region)
            l.debug("Under-constrained symbolic execution: assigned a new memory region @ %s to %s", mem_region, addr)
