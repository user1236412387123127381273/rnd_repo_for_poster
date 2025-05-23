# pylint:disable=arguments-differ,no-member
from __future__ import annotations
from typing import TYPE_CHECKING

from bisa.code_location import CodeLocation
from bisa.serializable import Serializable
from bisa.protos import variables_pb2

if TYPE_CHECKING:
    from bisa.sim_variable import SimVariable


class VariableAccessSort:
    """
    Provides enums for variable access types.
    """

    WRITE = 0
    READ = 1
    REFERENCE = 2


class VariableAccess(Serializable):
    """
    Describes a variable access.
    """

    __slots__ = (
        "access_type",
        "atom_hash",
        "location",
        "offset",
        "variable",
    )

    def __init__(self, variable, access_type, location, offset, atom_hash=None):
        self.variable: SimVariable = variable
        self.access_type: int = access_type
        self.location: CodeLocation = location
        self.offset: int | None = offset
        self.atom_hash: int | None = atom_hash

    def __repr__(self):
        access_type = {
            VariableAccessSort.WRITE: "write",
            VariableAccessSort.READ: "read",
            VariableAccessSort.REFERENCE: "reference",
        }[self.access_type]
        return f"{access_type} {self.variable} @ {self.location} (offset {self.offset})"

    def __eq__(self, other):
        return (
            type(other) is VariableAccess
            and self.variable == other.variable
            and self.access_type == other.access_type
            and self.location == other.location
            and self.offset == other.offset
        )

    def __hash__(self):
        return hash((VariableAccess, self.variable, self.access_type, self.location, self.offset))

    @classmethod
    def _get_cmsg(cls):
        return variables_pb2.VariableAccess()

    def serialize_to_cmessage(self):
        # pylint:disable=no-member
        cmsg = self._get_cmsg()

        cmsg.ident = self.variable.ident
        cmsg.block_addr = self.location.block_addr
        cmsg.stmt_idx = self.location.stmt_idx
        cmsg.ins_addr = self.location.ins_addr
        if self.offset is not None and isinstance(self.offset, int):
            cmsg.offset = self.offset
        if self.atom_hash is not None:
            cmsg.atom_hash = self.atom_hash

        if self.access_type == VariableAccessSort.READ:
            cmsg.access_type = variables_pb2.VariableAccess.READ
        elif self.access_type == VariableAccessSort.WRITE:
            cmsg.access_type = variables_pb2.VariableAccess.WRITE
        elif self.access_type == VariableAccessSort.REFERENCE:
            cmsg.access_type = variables_pb2.VariableAccess.REFERENCE
        else:
            raise NotImplementedError

        return cmsg

    @classmethod
    def parse_from_cmessage(
        cls, cmsg, variable_by_ident: dict[str, SimVariable] | None = None, **kwargs
    ) -> VariableAccess:
        assert variable_by_ident is not None

        variable = variable_by_ident[cmsg.ident]
        location = CodeLocation(cmsg.block_addr, cmsg.stmt_idx, ins_addr=cmsg.ins_addr)
        if cmsg.access_type == variables_pb2.VariableAccess.READ:
            access_type = VariableAccessSort.READ
        elif cmsg.access_type == variables_pb2.VariableAccess.WRITE:
            access_type = VariableAccessSort.WRITE
        elif cmsg.access_type == variables_pb2.VariableAccess.REFERENCE:
            access_type = VariableAccessSort.REFERENCE
        else:
            raise NotImplementedError
        return VariableAccess(
            variable,
            access_type,
            location,
            cmsg.offset if cmsg.HasField("offset") else None,
            atom_hash=cmsg.atom_hash if cmsg.HasField("atom_hash") else None,
        )
