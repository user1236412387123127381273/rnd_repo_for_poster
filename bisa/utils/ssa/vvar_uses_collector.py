from __future__ import annotations
from collections import defaultdict

from ailment import AILBlockWalkerBase
from ailment.expression import VirtualVariable, Phi
from ailment.statement import Statement, Assignment
from ailment.block import Block

from bisa.code_location import CodeLocation


class VVarUsesCollector(AILBlockWalkerBase):
    """
    Collect all uses of virtual variables and their use locations in an AIL block. Skip collecting use locations if
    block is not specified.
    """

    def __init__(self):
        super().__init__()

        self.vvar_and_uselocs: dict[int, list[tuple[VirtualVariable, CodeLocation]]] = defaultdict(list)
        self.vvars: set[int] = set()

    def _handle_VirtualVariable(
        self, expr_idx: int, expr: VirtualVariable, stmt_idx: int, stmt: Statement, block: Block | None
    ):
        if isinstance(stmt, Assignment):
            if expr is stmt.dst:
                return
            if isinstance(stmt.dst, VirtualVariable) and isinstance(stmt.src, Phi) and expr.varid == stmt.dst.varid:
                # avoid phi loops
                return
        if block is not None:
            self.vvar_and_uselocs[expr.varid].append(
                (expr, CodeLocation(block.addr, stmt_idx, ins_addr=stmt.ins_addr, block_idx=block.idx))
            )
        self.vvars.add(expr.varid)
