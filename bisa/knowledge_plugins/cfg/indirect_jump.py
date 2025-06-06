from __future__ import annotations
from bisa.serializable import Serializable


class IndirectJumpType:
    Jumptable_AddressLoadedFromMemory = 0
    Jumptable_AddressComputed = 1
    Vtable = 3
    Unknown = 255


class IndirectJump(Serializable):
    __slots__ = (
        "addr",
        "func_addr",
        "ins_addr",
        "jumpkind",
        "jumptable",
        "jumptable_addr",
        "jumptable_entries",
        "jumptable_entry_size",
        "jumptable_size",
        "resolved_targets",
        "stmt_idx",
        "type",
    )

    def __init__(
        self,
        addr: int,
        ins_addr: int,
        func_addr: int,
        jumpkind: str,
        stmt_idx: int,
        resolved_targets: list[int] | None = None,
        jumptable: bool = False,
        jumptable_addr: int | None = None,
        jumptable_size: int | None = None,
        jumptable_entry_size: int | None = None,
        jumptable_entries: list[int] | None = None,
        type_: int | None = IndirectJumpType.Unknown,
    ):
        self.addr = addr
        self.ins_addr = ins_addr
        self.func_addr = func_addr
        self.jumpkind = jumpkind
        self.stmt_idx = stmt_idx
        self.resolved_targets = set() if resolved_targets is None else set(resolved_targets)
        self.jumptable = jumptable
        self.jumptable_addr = jumptable_addr
        self.jumptable_size = jumptable_size
        self.jumptable_entry_size = jumptable_entry_size
        self.jumptable_entries = jumptable_entries
        self.type = type_

    def __repr__(self):
        status = ""
        if self.jumptable or self.jumptable_entries:
            status = "vtable" if self.type == IndirectJumpType.Vtable else "jumptable"
            if self.jumptable_addr is not None:
                status += f"@{self.jumptable_addr:#08x}"
            if self.jumptable_entries is not None:
                status += f" with {len(self.jumptable_entries)} entries"

        return "<IndirectJump {:#08x} - ins {:#08x}{}>".format(self.addr, self.ins_addr, " " + status if status else "")
