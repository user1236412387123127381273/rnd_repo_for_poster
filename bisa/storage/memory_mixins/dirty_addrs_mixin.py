from __future__ import annotations

from bisa.storage.memory_mixins.memory_mixin import MemoryMixin


class DirtyAddrsMixin(MemoryMixin):
    def store(self, addr, data, size=None, **kwargs):
        assert type(size) is int
        if self.category == "mem":
            self.state.scratch.dirty_addrs.update(range(addr, addr + size))
        super().store(addr, data, size=size, **kwargs)
