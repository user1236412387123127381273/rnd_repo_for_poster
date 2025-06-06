from __future__ import annotations

import claripy
from archinfo.arch_arm import is_arm_arch

from bisa.errors import SimMemoryError
from bisa.storage.memory_mixins.memory_mixin import MemoryMixin

stn_map = {f"st{n}": n for n in range(8)}
tag_map = {f"tag{n}": n for n in range(8)}


class NameResolutionMixin(MemoryMixin):
    """
    This mixin allows you to provide register names as load addresses, and will automatically translate this to an
    offset and size.
    """

    def _resolve_location_name(self, name, is_write=False):
        # Delayed load so SimMemory does not rely on SimEngines
        from bisa.engines.vex.claripy.ccall import _get_flags

        if self.category == "reg":
            if self.state.arch.name in ("X86", "AMD64"):
                if name in stn_map:
                    return (((stn_map[name] + self.load("ftop")) & 7) << 3) + self.state.arch.registers["fpu_regs"][
                        0
                    ], 8
                if name in tag_map:
                    return ((tag_map[name] + self.load("ftop")) & 7) + self.state.arch.registers["fpu_tags"][0], 1
                if name in ("flags", "eflags", "rflags"):
                    # we tweak the state to convert the vex condition registers into the flags register
                    if not is_write:  # this work doesn't need to be done if we're just gonna overwrite it
                        self.store("cc_dep1", _get_flags(self.state))  # constraints cannot be added by this
                    self.store("cc_op", 0)  # OP_COPY
                    return self.state.arch.registers["cc_dep1"]
            if (is_arm_arch(self.state.arch) or self.state.arch.name == "AARCH64") and name == "flags":
                if not is_write:
                    self.store("cc_dep1", _get_flags(self.state))
                self.store("cc_op", 0)
                return self.state.arch.registers["cc_dep1"]

            if name == "sp" and "sp" not in self.state.arch.registers:
                sp_reg_name = self.state.arch.register_names[self.state.arch.sp_offset]
                return self.state.arch.registers[sp_reg_name]
            if name == "lr" and "lr" not in self.state.arch.registers:
                lr_reg_name = self.state.arch.register_names[self.state.arch.lr_offset]
                return self.state.arch.registers[lr_reg_name]

            return self.state.arch.registers[name]
        if name[0] == "*":
            return self.state.registers.load(name[1:]), None
        raise SimMemoryError("Trying to address memory with a register name.")

    def store(self, addr, data, size=None, **kwargs):
        if isinstance(addr, str):
            named_addr, named_size = self._resolve_location_name(addr, is_write=True)
            if isinstance(data, claripy.ast.BV) and len(data) < named_size * self.state.arch.byte_width:
                data = data.zero_extend(named_size * self.state.arch.byte_width - len(data))
            return super().store(named_addr, data, size=named_size if size is None else size, **kwargs)
        return super().store(addr, data, size=size, **kwargs)

    def load(self, addr, size=None, **kwargs):
        if isinstance(addr, str):
            named_addr, named_size = self._resolve_location_name(addr, is_write=False)
            return super().load(named_addr, size=named_size if size is None else size, **kwargs)
        return super().load(addr, size=size, **kwargs)
