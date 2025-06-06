# pylint:disable=missing-class-docstring,unused-argument,consider-using-dict-items
from __future__ import annotations
from collections import defaultdict
from collections.abc import Iterable
from typing import Any, TYPE_CHECKING

import ailment
from ailment import Expression, Block, AILBlockWalker
from ailment.expression import ITE, Load
from ailment.statement import Statement, Assignment, Call, Return

from bisa.utils.ail import is_phi_assignment
from bisa.utils.ssa import VVarUsesCollector
from bisa.analyses.decompiler.sequence_walker import SequenceWalker
from bisa.analyses.decompiler.structuring.structurer_nodes import (
    ConditionNode,
    ConditionalBreakNode,
    LoopNode,
    CascadingConditionNode,
    SwitchCaseNode,
)

if TYPE_CHECKING:
    from ailment.expression import MultiStatementExpression


class LocationBase:
    __slots__ = ()


class StatementLocation(LocationBase):
    """
    Describes the location of a statement.
    """

    __slots__ = (
        "block_addr",
        "block_idx",
        "phi_stmt",
        "stmt_idx",
    )

    def __init__(self, block_addr, block_idx, stmt_idx, phi_stmt: bool = False):
        self.block_addr = block_addr
        self.block_idx = block_idx
        self.stmt_idx = stmt_idx
        self.phi_stmt = phi_stmt

    def __repr__(self):
        return f"Loc: Statement@{self.block_addr:x}.{self.block_idx}-{self.stmt_idx}{' phi' if self.phi_stmt else ''}"

    def __hash__(self):
        return hash((StatementLocation, self.block_addr, self.block_idx, self.stmt_idx, self.phi_stmt))

    def __eq__(self, other):
        return (
            isinstance(other, StatementLocation)
            and self.block_addr == other.block_addr
            and self.block_idx == other.block_idx
            and self.stmt_idx == other.stmt_idx
            and self.phi_stmt == other.phi_stmt
        )

    def copy(self):
        return StatementLocation(self.block_addr, self.block_idx, self.stmt_idx, phi_stmt=self.phi_stmt)


class ExpressionLocation(LocationBase):
    """
    Describes the location of an expression.
    """

    __slots__ = (
        "block_addr",
        "block_idx",
        "expr_idx",
        "phi_stmt",
        "stmt_idx",
    )

    def __init__(self, block_addr, block_idx, stmt_idx, expr_idx, phi_stmt: bool = False):
        self.block_addr = block_addr
        self.block_idx = block_idx
        self.stmt_idx = stmt_idx
        self.expr_idx = expr_idx
        self.phi_stmt = phi_stmt

    def __repr__(self):
        return (
            f"Loc: Expression@{self.block_addr:x}.{self.block_idx}-{self.stmt_idx}[{self.expr_idx}]"
            f"{'phi' if self.phi_stmt else ''}"
        )

    def statement_location(self) -> StatementLocation:
        return StatementLocation(self.block_addr, self.block_idx, self.stmt_idx, phi_stmt=self.phi_stmt)

    def __hash__(self):
        return hash((ExpressionLocation, self.block_addr, self.block_idx, self.stmt_idx, self.expr_idx, self.phi_stmt))

    def __eq__(self, other):
        return (
            isinstance(other, ExpressionLocation)
            and self.block_addr == other.block_addr
            and self.block_idx == other.block_idx
            and self.stmt_idx == other.stmt_idx
            and self.expr_idx == other.expr_idx
            and self.phi_stmt == other.phi_stmt
        )


class ConditionLocation(LocationBase):
    """
    Describes the location of a condition.
    """

    __slots__ = (
        "case_idx",
        "node_addr",
    )

    def __init__(self, cond_node_addr, case_idx: int | None = None):
        self.node_addr = cond_node_addr
        self.case_idx = case_idx

    def __repr__(self):
        return f"Loc: ConditionNode@{self.node_addr:x}.{self.case_idx}"

    def __hash__(self):
        return hash((ConditionLocation, self.node_addr, self.case_idx))

    def __eq__(self, other):
        return (
            isinstance(other, ConditionLocation)
            and self.node_addr == other.node_addr
            and self.case_idx == other.case_idx
        )


class ConditionalBreakLocation(LocationBase):
    """
    Describes the location of a conditional break.
    """

    __slots__ = ("node_addr",)

    def __init__(self, node_addr):
        self.node_addr = node_addr

    def __repr__(self):
        return f"Loc: ConditionalBreakNode@{self.node_addr:x}"

    def __hash__(self):
        return hash((ConditionalBreakLocation, self.node_addr))

    def __eq__(self, other):
        return isinstance(other, ConditionalBreakLocation) and self.node_addr == other.node_addr


class MultiStatementExpressionAssignmentFinder(AILBlockWalker):
    """
    Process statements in MultiStatementExpression objects and find assignments.
    """

    def __init__(self, stmt_handler):
        super().__init__()
        self._stmt_handler = stmt_handler

    def _handle_MultiStatementExpression(
        self, expr_idx, expr: MultiStatementExpression, stmt_idx: int, stmt: Statement, block: Block | None
    ):
        for idx, stmt_ in enumerate(expr.stmts):
            self._stmt_handler(idx, stmt_, block)
        return super()._handle_MultiStatementExpression(expr_idx, expr, stmt_idx, stmt, block)


class ExpressionUseFinder(AILBlockWalker):
    """
    Find where each variable is used.

    Additionally, determine if the expression being walked has load expressions inside. Such expressions can only be
    safely folded if there are no Store statements between the expression defining location and its use sites. For
    example, we can only safely fold variable assignments that use Load() when there are no Store()s between the
    assignment and its use site. Otherwise, the loaded expression may get updated later by a Store() statement.

    Here is a real AIL block:

    .. code-block:: none

        v16 = ((int)v23->field_5) + 1 & 255;
        v23->field_5 = ((char)(((int)v23->field_5) + 1 & 255));
        v13 = printf("Recieved packet %d for connection with %d\\n", v16, a0 & 255);

    In this case, folding v16 into the last printf() expression would be incorrect, since v23->field_5 is updated by
    the second statement.
    """

    __slots__ = (
        "has_load",
        "uses",
    )

    def __init__(self):
        super().__init__()
        self.uses: defaultdict[int, set[tuple[Expression, ExpressionLocation | None]]] = defaultdict(set)
        self.has_load = False

    def _handle_expr(
        self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Any:
        if isinstance(expr, ailment.Expr.VirtualVariable) and expr.was_reg:
            if not (isinstance(stmt, ailment.Stmt.Assignment) and stmt.dst is expr):
                if block is not None:
                    self.uses[expr.varid].add(
                        (
                            expr,
                            ExpressionLocation(
                                block.addr,
                                block.idx,
                                stmt_idx,
                                expr_idx,
                                phi_stmt=stmt is not None and is_phi_assignment(stmt),
                            ),
                        )
                    )
                else:
                    self.uses[expr.varid].add((expr, None))
            return None
        return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Load(self, expr_idx: int, expr: ailment.Expr.Load, stmt_idx: int, stmt: Statement, block: Block | None):
        self.has_load = True
        return super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)


class ExpressionCounter(SequenceWalker):
    """
    Find all expressions that are assigned once and only used once.
    """

    def __init__(self, node):
        handlers = {
            ConditionalBreakNode: self._handle_ConditionalBreak,
            ConditionNode: self._handle_Condition,
            LoopNode: self._handle_Loop,
            SwitchCaseNode: self._handle_SwitchCase,
            ailment.Block: self._handle_Block,
        }

        # each element in the set is a tuple of (source of the assignment statement, a tuple of unified variables that
        # the current assignment depends on, StatementLocation of the assignment statement, a Boolean variable that
        # indicates if ExpressionUseFinder has succeeded or not)
        self.assignments: defaultdict[Any, set[tuple]] = defaultdict(set)
        self.uses: dict[int, set[tuple[Expression, LocationBase | None]]] = {}

        super().__init__(handlers)
        self.walk(node)

    def _handle_Statement(self, idx: int, stmt: Statement, node: ailment.Block | LoopNode):
        if isinstance(stmt, ailment.Stmt.Assignment):
            if is_phi_assignment(stmt):
                return
            if isinstance(stmt.dst, ailment.Expr.VirtualVariable) and stmt.dst.was_reg:
                # dependency
                dependency_finder = ExpressionUseFinder()
                dependency_finder.walk_expression(stmt.src)
                dependencies = tuple(dependency_finder.uses)
                self.assignments[stmt.dst.varid].add(
                    (
                        stmt.src,
                        dependencies,
                        StatementLocation(node.addr, node.idx if isinstance(node, ailment.Block) else None, idx),
                        dependency_finder.has_load,
                    )
                )
        if (
            isinstance(stmt, ailment.Stmt.Call)
            and isinstance(stmt.ret_expr, ailment.Expr.VirtualVariable)
            and stmt.ret_expr.was_reg
        ):
            dependency_finder = ExpressionUseFinder()
            dependency_finder.walk_expression(stmt)
            dependencies = tuple(dependency_finder.uses)
            self.assignments[stmt.ret_expr.varid].add(
                (
                    stmt,
                    dependencies,
                    StatementLocation(node.addr, node.idx if isinstance(node, ailment.Block) else None, idx),
                    dependency_finder.has_load,
                )
            )

    def _handle_Block(self, node: ailment.Block, **kwargs):
        # find assignments and uses of variables
        use_finder = ExpressionUseFinder()
        for idx, stmt in enumerate(node.statements):
            self._handle_Statement(idx, stmt, node)
            use_finder.walk_statement(stmt, block=node)

        for varid, content in use_finder.uses.items():
            if varid not in self.uses:
                self.uses[varid] = set()
            self.uses[varid] |= content

    def _collect_assignments(self, expr: Expression, node) -> None:
        finder = MultiStatementExpressionAssignmentFinder(self._handle_Statement)
        finder.walk_expression(expr, None, None, node)

    def _collect_uses(self, expr: Expression | Statement, loc: LocationBase):
        use_finder = ExpressionUseFinder()
        if isinstance(expr, Statement):
            use_finder.walk_statement(expr)
        else:
            use_finder.walk_expression(expr, stmt_idx=-1)

        for varid, uses in use_finder.uses.items():
            for use in uses:
                if varid not in self.uses:
                    self.uses[varid] = set()
                self.uses[varid].add((use[0], loc))

    def _handle_ConditionalBreak(self, node: ConditionalBreakNode, **kwargs):
        # collect uses on the condition expression
        self._collect_assignments(node.condition, node)
        self._collect_uses(node.condition, ConditionalBreakLocation(node.addr))
        return super()._handle_ConditionalBreak(node, **kwargs)

    def _handle_Condition(self, node: ConditionNode, **kwargs):
        # collect uses on the condition expression
        self._collect_assignments(node.condition, node)
        self._collect_uses(node.condition, ConditionLocation(node.addr))
        return super()._handle_Condition(node, **kwargs)

    def _handle_CascadingCondition(self, node: CascadingConditionNode, **kwargs):
        for idx, (condition, _) in enumerate(node.condition_and_nodes):
            self._collect_assignments(condition, node)
            self._collect_uses(condition, ConditionLocation(node.addr, idx))
        return super()._handle_CascadingCondition(node, **kwargs)

    def _handle_Loop(self, node: LoopNode, **kwargs):
        # collect uses on the condition expression
        if node.initializer is not None:
            self._collect_uses(node.initializer, ConditionLocation(node.addr))
        if node.iterator is not None:
            self._collect_uses(node.iterator, ConditionLocation(node.addr))
        if node.condition is not None:
            self._collect_assignments(node.condition, node)
            self._collect_uses(node.condition, ConditionLocation(node.addr))
        return super()._handle_Loop(node, **kwargs)

    def _handle_SwitchCase(self, node: SwitchCaseNode, **kwargs):
        self._collect_uses(node.switch_expr, ConditionLocation(node.addr))
        return super()._handle_SwitchCase(node, **kwargs)


class ExpressionSpotter(VVarUsesCollector):
    """
    ExpressionSpotter collects uses of vvars and existence of Call expressions.
    """

    def __init__(self):
        super().__init__()
        self.has_calls: bool = False
        self.has_loads: bool = False

    def _handle_CallExpr(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement, block: Block | None):
        self.has_calls = True
        return super()._handle_CallExpr(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Load(self, expr_idx: int, expr: Load, stmt_idx: int, stmt: Statement, block: Block | None):
        self.has_loads = True
        return super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)


class InterferenceChecker(SequenceWalker):
    """
    Detect for every pair of definition (assignment) - use if there is anything that may interfere with the definition.

    Interferences may be caused by:

    - another call
    - function return
    - store statements
    - load expressions
    - Condition and CascadingCondition nodes
    """

    def __init__(self, assignments: dict[int, Any], uses: dict[int, Any], node):
        handlers = {
            ailment.Block: self._handle_Block,
            ConditionNode: self._handle_Condition,
            ConditionalBreakNode: self._handle_ConditionalBreak,
            SwitchCaseNode: self._handle_SwitchCase,
        }

        super().__init__(handlers, update_seqnode_in_place=False, force_forward_scan=True)
        self._assignments = assignments
        self._uses = uses
        self._assignment_interferences: dict[int, list] = {}
        self.interfered_assignments: set[int] = set()
        self.walk(node)

    def _after_spotting(self, obj, spotter: ExpressionSpotter) -> None:
        if spotter.has_calls or spotter.has_loads:
            # mark all existing assignments as interfered
            for vid in list(self._assignment_interferences):
                self._assignment_interferences[vid].append(obj)
        if set(self._assignment_interferences).intersection(spotter.vvars):
            for used_vvar_id in spotter.vvars:
                if used_vvar_id in self._assignment_interferences:
                    if self._assignment_interferences[used_vvar_id]:
                        self.interfered_assignments.add(used_vvar_id)
                    del self._assignment_interferences[used_vvar_id]

    def _handle_Block(self, node: ailment.Block, **kwargs):
        for stmt in node.statements:

            # deal with uses
            spotter = ExpressionSpotter()
            # special case: we process the call arguments first, then the call itself. this is to allow more expression
            # folding opportunities.
            the_call = None
            if isinstance(stmt, Assignment) and isinstance(stmt.src, ailment.Stmt.Call):
                the_call = stmt.src
            elif isinstance(stmt, ailment.Stmt.Call) and not isinstance(stmt.target, str):
                the_call = stmt
            if the_call is not None:
                spotter.walk_expression(the_call.target)
                if the_call.args:
                    for arg in the_call.args:
                        spotter.walk_expression(arg)
                self._after_spotting(the_call, spotter)
            spotter.walk_statement(stmt)
            self._after_spotting(stmt, spotter)

            if isinstance(stmt, Return):
                # mark all existing assignments as interfered
                for vid in self._assignment_interferences:
                    self._assignment_interferences[vid].append(stmt)

            if isinstance(stmt, ailment.Stmt.Store):
                # mark all existing assignments as interfered
                for vid in self._assignment_interferences:
                    self._assignment_interferences[vid].append(stmt)

            if isinstance(stmt, ailment.Stmt.Call):
                # mark all existing assignments as interfered
                for vid in self._assignment_interferences:
                    self._assignment_interferences[vid].append(stmt)

            # deal with defs
            if (
                isinstance(stmt, ailment.Stmt.Assignment)
                and isinstance(stmt.dst, ailment.Expr.VirtualVariable)
                and stmt.dst.was_reg
                and stmt.dst.varid in self._assignments
            ):
                # we found this def
                self._assignment_interferences[stmt.dst.varid] = []

            if (
                isinstance(stmt, ailment.Stmt.Call)
                and isinstance(stmt.ret_expr, ailment.Expr.VirtualVariable)
                and stmt.ret_expr.was_reg
                and stmt.ret_expr.variable is not None
                and stmt.ret_expr.varid in self._assignments
            ):
                # we found this def
                self._assignment_interferences[stmt.ret_expr.varid] = []

    def _handle_ConditionalBreak(self, node: ConditionalBreakNode, **kwargs):
        spotter = ExpressionSpotter()
        spotter.walk_expression(node.condition)
        self._after_spotting(node, spotter)
        return super()._handle_ConditionalBreak(node, **kwargs)

    def _handle_Condition(self, node: ConditionNode, **kwargs):
        spotter = ExpressionSpotter()
        spotter.walk_expression(node.condition)
        self._after_spotting(node, spotter)

        # mark all existing assignments as interfered
        for vid in self._assignment_interferences:
            self._assignment_interferences[vid].append(node)

        return super()._handle_Condition(node, **kwargs)

    def _handle_CascadingCondition(self, node: CascadingConditionNode, **kwargs):
        spotter = ExpressionSpotter()
        for cond, _ in node.condition_and_nodes:  # pylint:disable=consider-using-enumerate
            spotter.walk_expression(cond)
            self._after_spotting(node, spotter)

        # mark all existing assignments as interfered
        for vid in self._assignment_interferences:
            self._assignment_interferences[vid].append(node)

        return super()._handle_CascadingCondition(node, **kwargs)

    def _handle_Loop(self, node: LoopNode, **kwargs):
        spotter = ExpressionSpotter()

        # iterator
        if node.iterator is not None:
            spotter.walk_statement(node.iterator)

        # initializer
        if node.initializer is not None:
            spotter.walk_statement(node.initializer)

        # condition
        if node.condition is not None:
            spotter.walk_expression(node.condition)

        self._after_spotting(node, spotter)

        return super()._handle_Loop(node, **kwargs)

    def _handle_SwitchCase(self, node: SwitchCaseNode, **kwargs):
        spotter = ExpressionSpotter()
        spotter.walk_expression(node.switch_expr)
        self._after_spotting(node, spotter)
        return super()._handle_SwitchCase(node, **kwargs)


class ExpressionReplacer(AILBlockWalker):
    def __init__(self, assignments: dict[int, Any], uses: dict[int, Any]):
        super().__init__()
        self._assignments = assignments
        self._uses = uses

    def _handle_MultiStatementExpression(  # type: ignore
        self, expr_idx, expr: MultiStatementExpression, stmt_idx: int, stmt: Statement, block: Block | None
    ) -> Expression | None:
        changed = False
        new_statements = []
        for idx, stmt_ in enumerate(expr.stmts):
            if (
                isinstance(stmt_, Assignment)
                and isinstance(stmt_.dst, ailment.Expr.VirtualVariable)
                and stmt_.dst.was_reg
                and stmt_.dst.variable is not None
            ) and stmt_.dst.variable in self._assignments:
                # remove this statement
                changed = True
                continue

            new_stmt = self._handle_stmt(idx, stmt_, None)
            if new_stmt is not None and new_stmt is not stmt_:
                changed = True
                if isinstance(new_stmt, Assignment) and new_stmt.src.likes(new_stmt.dst):
                    # this statement is simplified into reg = reg. ignore it
                    continue
                new_statements.append(new_stmt)
            else:
                new_statements.append(stmt_)

        new_expr = self._handle_expr(0, expr.expr, stmt_idx, stmt, block)
        if new_expr is not None and new_expr is not expr.expr:
            changed = True
        else:
            new_expr = expr.expr

        if changed:
            if not new_statements:
                # it is no longer a multi-statement expression
                return new_expr  # type: ignore
            expr_ = expr.copy()
            expr_.expr = new_expr
            expr_.stmts = new_statements
            return expr_
        return None

    def _handle_Assignment(self, stmt_idx: int, stmt: Assignment, block: Block | None):
        # override the base handler and make sure we do not replace .dst with a Call expression or an ITE expression

        if is_phi_assignment(stmt):
            return None

        changed = False

        dst = self._handle_expr(0, stmt.dst, stmt_idx, stmt, block)
        if dst is not None and dst is not stmt.dst and not isinstance(dst, (Call, ITE)):
            changed = True
        else:
            dst = stmt.dst

        src = self._handle_expr(1, stmt.src, stmt_idx, stmt, block)
        if src is not None and src is not stmt.src:
            changed = True
        else:
            src = stmt.src

        if changed:
            new_stmt = Assignment(stmt.idx, dst, src, **stmt.tags)
            if block is not None:
                # update the statement directly in the block
                block.statements[stmt_idx] = new_stmt
            return new_stmt
        return None

    def _handle_expr(
        self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Any:
        if isinstance(expr, ailment.Expr.VirtualVariable) and expr.was_reg and expr.varid in self._uses:
            replace_with, _ = self._assignments[expr.varid]
            return replace_with
        return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)


class ExpressionFolder(SequenceWalker):
    def __init__(self, assignments: dict[int, Any], uses: dict[int, Any], node):
        handlers = {
            ailment.Block: self._handle_Block,
            ConditionNode: self._handle_Condition,
            ConditionalBreakNode: self._handle_ConditionalBreak,
            SwitchCaseNode: self._handle_SwitchCase,
        }

        super().__init__(handlers)
        self._assignments = assignments
        self._uses = uses
        self.walk(node)

    def _handle_Block(self, node: ailment.Block, **kwargs):
        # Walk the block to remove each assignment and replace uses of each variable
        new_stmts = []
        for stmt in node.statements:
            if (
                isinstance(stmt, ailment.Stmt.Assignment)
                and isinstance(stmt.dst, ailment.Expr.VirtualVariable)
                and stmt.dst.was_reg
                and stmt.dst.varid in self._assignments
            ):
                # remove this statement
                continue
            if (
                isinstance(stmt, ailment.Stmt.Call)
                and isinstance(stmt.ret_expr, ailment.Expr.VirtualVariable)
                and stmt.ret_expr.was_reg
                and stmt.ret_expr.variable is not None
                and stmt.ret_expr.varid in self._assignments
            ):
                # remove this statement
                continue
            new_stmts.append(stmt)
        node.statements = new_stmts

        # Walk the block to replace the use of each variable
        replacer = ExpressionReplacer(self._assignments, self._uses)
        replacer.walk(node)

    def _handle_ConditionalBreak(self, node: ConditionalBreakNode, **kwargs):
        replacer = ExpressionReplacer(self._assignments, self._uses)
        r = replacer.walk_expression(node.condition)
        if r is not None and r is not node.condition:
            node.condition = r
        return super()._handle_ConditionalBreak(node, **kwargs)

    def _handle_Condition(self, node: ConditionNode, **kwargs):
        replacer = ExpressionReplacer(self._assignments, self._uses)
        r = replacer.walk_expression(node.condition)
        if r is not None and r is not node.condition:
            node.condition = r
        return super()._handle_Condition(node, **kwargs)

    def _handle_CascadingCondition(self, node: CascadingConditionNode, **kwargs):
        replacer = ExpressionReplacer(self._assignments, self._uses)
        for idx in range(len(node.condition_and_nodes)):  # pylint:disable=consider-using-enumerate
            cond, _ = node.condition_and_nodes[idx]
            r = replacer.walk_expression(cond)
            if r is not None and r is not cond:
                node.condition_and_nodes[idx] = (r, node.condition_and_nodes[idx][1])
        return super()._handle_CascadingCondition(node, **kwargs)

    def _handle_Loop(self, node: LoopNode, **kwargs):
        replacer = ExpressionReplacer(self._assignments, self._uses)

        # iterator
        if node.iterator is not None:
            r = replacer.walk_statement(node.iterator)
            if r is not None and r is not node.iterator:
                node.iterator = r

        # initializer
        if node.initializer is not None:
            r = replacer.walk_statement(node.initializer)
            if r is not None and r is not node.initializer:
                node.initializer = r

        # condition
        if node.condition is not None:
            r = replacer.walk_expression(node.condition)
            if r is not None and r is not node.condition:
                node.condition = r

        return super()._handle_Loop(node, **kwargs)

    def _handle_SwitchCase(self, node: SwitchCaseNode, **kwargs):
        replacer = ExpressionReplacer(self._assignments, self._uses)

        r = replacer.walk_expression(node.switch_expr)
        if r is not None and r is not node.switch_expr:
            node.switch_expr = r

        return super()._handle_SwitchCase(node, **kwargs)


class StoreStatementFinder(SequenceWalker):
    """
    Determine if there are any Store statements between two given statements.

    This class overrides _handle_Sequence() and _handle_MultiNode() to ensure they traverse nodes from top to bottom.
    """

    def __init__(self, node, intervals: Iterable[tuple[StatementLocation, LocationBase]]):
        handlers = {
            ConditionNode: self._handle_Condition,
            CascadingConditionNode: self._handle_CascadingCondition,
            ConditionalBreakNode: self._handle_ConditionalBreak,
            ailment.Block: self._handle_Block,
        }

        self._intervals = intervals

        self._start_to_ends: defaultdict[StatementLocation, set[LocationBase]] = defaultdict(set)
        self._end_to_starts: defaultdict[LocationBase, set[StatementLocation]] = defaultdict(set)
        self.interval_to_hasstore: dict[tuple[StatementLocation, StatementLocation], bool] = {}
        for start, end in intervals:
            self._start_to_ends[start].add(end)
            self._end_to_starts[end].add(start)

        self._active_intervals = set()

        super().__init__(handlers)
        self.walk(node)

    def _handle_Sequence(self, node, **kwargs):
        i = 0
        while i < len(node.nodes):
            node_ = node.nodes[i]
            self._handle(node_, parent=node, index=i)
            i += 1

    def _handle_MultiNode(self, node, **kwargs):
        i = 0
        while i < len(node.nodes):
            node_ = node.nodes[i]
            self._handle(node_, parent=node, index=i)
            i += 1

    def _handle_Block(self, node: ailment.Block, **kwargs):
        stmt_loc = StatementLocation(node.addr, node.idx, None)
        for idx, stmt in enumerate(node.statements):
            stmt_loc.stmt_idx = idx
            if stmt_loc in self._start_to_ends:
                for end in self._start_to_ends[stmt_loc]:
                    self._active_intervals.add((stmt_loc.copy(), end))
            if stmt_loc in self._end_to_starts:
                for start in self._end_to_starts[stmt_loc]:
                    self._active_intervals.discard((start, stmt_loc))
            if isinstance(stmt, ailment.Stmt.Store):
                for interval in self._active_intervals:
                    self.interval_to_hasstore[interval] = True

    def _handle_Condition(self, node, **kwargs):
        cond_loc = ConditionLocation(node.addr)
        if cond_loc in self._end_to_starts:
            for start in self._end_to_starts[cond_loc]:
                self._active_intervals.discard((start, cond_loc))
        super()._handle_Condition(node, **kwargs)

    def _handle_CascadingCondition(self, node: CascadingConditionNode, **kwargs):
        cond_loc = ConditionLocation(node.addr, None)
        for idx in range(len(node.condition_and_nodes)):
            cond_loc.case_idx = idx
            if cond_loc in self._end_to_starts[cond_loc]:
                for start in self._end_to_starts[cond_loc]:
                    self._active_intervals.discard((start, cond_loc))
        super()._handle_CascadingCondition(node, **kwargs)

    def _handle_ConditionalBreak(self, node: ConditionalBreakNode, **kwargs):
        cond_break_loc = ConditionalBreakLocation(node.addr)
        if cond_break_loc in self._end_to_starts:
            for start in self._end_to_starts[cond_break_loc]:
                self._active_intervals.discard((start, cond_break_loc))
        super()._handle_ConditionalBreak(node, **kwargs)

    def has_store(self, start: StatementLocation, end: StatementLocation) -> bool:
        return self.interval_to_hasstore.get((start, end), False)
