from __future__ import annotations
import logging

from archinfo.arch_soot import SootAddressDescriptor

from bisa.engines.soot.exceptions import IncorrectLocationException
from bisa.engines.soot.expressions import translate_expr
from bisa.engines.soot.values import translate_value

l = logging.getLogger("bisa.engines.soot.statements.if")


class SimSootStmt:
    """
    The base class of all Soot statements.
    """

    def __init__(self, stmt, state):
        self.stmt = stmt
        self.state = state

        self.invoke_expr = None
        self.jmp_targets_with_conditions = []

    def process(self):
        """
        Process the statement and apply all effects on the state.
        :return: None
        """
        self._execute()

    def _execute(self):
        raise NotImplementedError

    def _translate_expr(self, expr):
        return translate_expr(expr, self.state)

    def _translate_value(self, value):
        return translate_value(value, self.state)

    def _get_bb_addr_from_instr(self, instr):
        """
        Returns the address of the methods basic block that contains the given
        instruction.

        :param instr: The index of the instruction (within the current method).
        :rtype: SootAddressDescriptor
        """
        current_method = self.state.addr.method
        try:
            bb = current_method.block_by_label[instr]
        except KeyError as err:
            l.error("Possible jump to a non-existing bb %s --> %d", self.state.addr, instr)
            raise IncorrectLocationException from err

        return SootAddressDescriptor(current_method, bb.idx, 0)

    #
    # Jumps
    #

    def _add_jmp_target(self, target, condition):
        self.jmp_targets_with_conditions += [(target, condition)]

    @property
    def has_jump_targets(self):
        return self.jmp_targets_with_conditions != []

    #
    # Invocations
    #

    def _add_invoke_target(self, invoke_expr, ret_var=None):
        self.invoke_expr = invoke_expr
        self.invoke_expr.ret_var = ret_var

    @property
    def has_invoke_target(self):
        return self.invoke_expr is not None
