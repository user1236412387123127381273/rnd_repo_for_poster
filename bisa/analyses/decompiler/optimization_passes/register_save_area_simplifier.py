# pylint:disable=too-many-boolean-expressions
from __future__ import annotations
from collections.abc import Iterable
import logging

import archinfo
import ailment

from bisa.calling_conventions import SimRegArg
from bisa.code_location import CodeLocation
from bisa.analyses.decompiler.stack_item import StackItem, StackItemType
from .optimization_pass import OptimizationPass, OptimizationPassStage


_l = logging.getLogger(name=__name__)


class RegisterSaveAreaSimplifier(OptimizationPass):
    """
    Optimizes away register spilling effects, including callee-saved registers.

    This optimization runs between SSA-level0 and SSA-level1, which means registers are converted to vvars but stack
    accesses stay unchanged.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_SINGLE_BLOCK_SIMPLIFICATION
    NAME = "Simplify register save areas"
    DESCRIPTION = __doc__.strip()

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)

        self.analyze()

    def _check(self):
        # Check the first block to see what external registers are stored on the stack
        stored_info = self._find_registers_stored_on_stack()
        if not stored_info:
            return False, None

        # Check all return sites to see what external registers are restored to registers from the stack
        restored_info = self._find_registers_restored_from_stack()
        if not restored_info:
            return False, None

        # Find common registers and stack offsets
        info = self._intersect_register_info(stored_info, restored_info)

        return bool(info), {"info": info}

    @staticmethod
    def _modify_statement(
        old_block, stmt_idx_: int, updated_blocks_, stack_offset: int | None = None
    ):  # pylint:disable=unused-argument
        if old_block not in updated_blocks_:
            block = old_block.copy()
            updated_blocks_[old_block] = block
        else:
            block = updated_blocks_[old_block]
        block.statements[stmt_idx_] = None

    def _analyze(self, cache=None):

        if cache is None:
            return

        info: dict[int, dict[str, list[tuple[int, CodeLocation]]]] = cache["info"]
        updated_blocks = {}

        for data in info.values():
            # remove storing statements
            for stack_offset, codeloc in data["stored"]:
                old_block = self._get_block(codeloc.block_addr, idx=codeloc.block_idx)
                self._modify_statement(old_block, codeloc.stmt_idx, updated_blocks, stack_offset=stack_offset)
            for stack_offset, codeloc in data["restored"]:
                old_block = self._get_block(codeloc.block_addr, idx=codeloc.block_idx)
                self._modify_statement(old_block, codeloc.stmt_idx, updated_blocks, stack_offset=stack_offset)

        for old_block, new_block in updated_blocks.items():
            # remove all statements that are None
            new_block.statements = [stmt for stmt in new_block.statements if stmt is not None]
            # update it
            self._update_block(old_block, new_block)

        if updated_blocks:
            # update stack_items
            for data in info.values():
                for stack_offset, _ in data["stored"]:
                    self.stack_items[stack_offset] = StackItem(
                        stack_offset, self.project.arch.bytes, "regs", StackItemType.SAVED_REGS
                    )

    def _find_registers_stored_on_stack(self) -> list[tuple[int, int, CodeLocation]]:
        first_block = self._get_block(self._func.addr)
        if first_block is None:
            return []

        results = []

        for idx, stmt in enumerate(first_block.statements):
            if (
                isinstance(stmt, ailment.Stmt.Store)
                and isinstance(stmt.addr, ailment.Expr.StackBaseOffset)
                and isinstance(stmt.addr.offset, int)
            ):
                if isinstance(stmt.data, ailment.Expr.VirtualVariable) and stmt.data.was_reg:
                    # it's storing registers to the stack!
                    stack_offset = stmt.addr.offset
                    reg_offset = stmt.data.reg_offset
                    codeloc = CodeLocation(first_block.addr, idx, block_idx=first_block.idx, ins_addr=stmt.ins_addr)
                    results.append((reg_offset, stack_offset, codeloc))
                elif (
                    self.project.arch.name == "AMD64"
                    and isinstance(stmt.data, ailment.Expr.Convert)
                    and isinstance(stmt.data.operand, ailment.Expr.VirtualVariable)
                    and stmt.data.operand.was_reg
                    and stmt.data.from_bits == 256
                    and stmt.data.to_bits == 128
                ):
                    # storing xmm registers to the stack
                    stack_offset = stmt.addr.offset
                    reg_offset = stmt.data.operand.reg_offset
                    codeloc = CodeLocation(first_block.addr, idx, block_idx=first_block.idx, ins_addr=stmt.ins_addr)
                    results.append((reg_offset, stack_offset, codeloc))

        return results

    def _find_registers_restored_from_stack(self) -> list[list[tuple[int, int, CodeLocation]]]:
        all_results = []
        for ret_site in self._func.ret_sites + self._func.jumpout_sites:
            for block in self._get_blocks(ret_site.addr):
                results = []
                for idx, stmt in enumerate(block.statements):
                    if (
                        isinstance(stmt, ailment.Stmt.Assignment)
                        and isinstance(stmt.dst, ailment.Expr.VirtualVariable)
                        and stmt.dst.was_reg
                        and isinstance(stmt.src, ailment.Expr.Load)
                        and isinstance(stmt.src.addr, ailment.Expr.StackBaseOffset)
                    ):
                        stack_offset = stmt.src.addr.offset
                        reg_offset = stmt.dst.reg_offset
                        codeloc = CodeLocation(block.addr, idx, block_idx=block.idx, ins_addr=stmt.ins_addr)
                        results.append((reg_offset, stack_offset, codeloc))

                if results:
                    all_results.append(results)

        return all_results

    def _intersect_register_info(
        self,
        stored: list[tuple[int, int, CodeLocation]],
        restored: Iterable[list[tuple[int, int, CodeLocation]]],
    ) -> dict[int, dict[str, list[tuple[int, CodeLocation]]]]:
        def _collect(info: list[tuple[int, int, CodeLocation]], output, keystr: str):
            for reg_offset, stack_offset, codeloc in info:
                if reg_offset not in output:
                    output[reg_offset] = {}
                if keystr not in output[reg_offset]:
                    output[reg_offset][keystr] = []
                output[reg_offset][keystr].append((stack_offset, codeloc))

        result: dict[int, dict[str, list[tuple[int, CodeLocation]]]] = {}
        _collect(stored, result, "stored")
        for item in restored:
            _collect(item, result, "restored")

        # remove registers that are
        # (a) stored but not restored
        # (b) restored but not stored
        # (c) from different offsets
        # (d) the same as the return value register

        cc = self._func.calling_convention
        if cc is not None and isinstance(cc.RETURN_VAL, SimRegArg):
            ret_val_reg_offset = self.project.arch.registers[cc.RETURN_VAL.reg_name][0]
        else:
            ret_val_reg_offset = None

        # link register
        if archinfo.arch_arm.is_arm_arch(self.project.arch):
            lr_reg_offset = self.project.arch.registers["lr"][0]
        elif self.project.arch.name in {"MIPS32", "MIPS64"}:
            lr_reg_offset = self.project.arch.registers["ra"][0]
        elif self.project.arch.name in {"PPC32", "PPC64"} or self.project.arch.name.startswith("PowerPC:"):
            lr_reg_offset = self.project.arch.registers["lr"][0]
        else:
            lr_reg_offset = None

        for reg in list(result.keys()):
            # stored link register should always be removed
            if lr_reg_offset is not None and reg == lr_reg_offset:
                if "restored" not in result[reg]:
                    # add a dummy one
                    result[reg]["restored"] = []
                continue

            if ret_val_reg_offset is not None and reg == ret_val_reg_offset:
                # (d)
                del result[reg]
                continue

            info = result[reg]
            if len(info.keys()) != 2:
                # (a) or (b)
                del result[reg]
                continue

            stack_offsets = {stack_offset for stack_offset, _ in info["stored"]} | {
                stack_offset for stack_offset, _ in info["restored"]
            }

            if len(stack_offsets) != 1:
                # (c)
                del result[reg]
                continue

        return result
