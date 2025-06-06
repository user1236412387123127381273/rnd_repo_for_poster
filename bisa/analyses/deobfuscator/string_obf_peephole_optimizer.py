from __future__ import annotations
from ailment.statement import Call
from ailment.expression import Const
import claripy

from bisa.analyses.decompiler.peephole_optimizations.base import PeepholeOptimizationExprBase
from bisa.analyses.decompiler.peephole_optimizations import EXPR_OPTS
from bisa.errors import BISACallableMultistateError


class StringObfType1PeepholeOptimizer(PeepholeOptimizationExprBase):
    """
    Integrate type-1 deobfuscated strings into decompilation output.
    """

    __slots__ = ()

    NAME = "Simplify Type 1/2 string deobfuscation references"
    expr_classes = (Call,)

    def optimize(self, expr: Call, **kwargs):
        if isinstance(expr.target, Const) and (  # noqa: SIM102
            expr.target.value in self.kb.obfuscations.type1_string_loader_candidates
            or expr.target.value in self.kb.obfuscations.type2_string_loader_candidates
        ):
            # this is a function calling a type1 or a type2 string loader
            # optimize this call away if possible
            if expr.args and all(isinstance(arg, Const) for arg in expr.args):
                # execute the function with the given argument
                func = self.kb.functions[expr.target.value]
                func_call = self.project.factory.callable(
                    expr.target.value, concrete_only=True, cc=func.calling_convention, prototype=func.prototype
                )
                try:
                    out = func_call(*[claripy.BVV(arg.value, arg.bits) for arg in expr.args])
                except BISACallableMultistateError:
                    return None

                if out.concrete:
                    return Const(
                        None, None, out.concrete_value, self.project.arch.bits, **expr.tags
                    )  # FIXME: use out.bits when the function prototype recovery is more reliable

        return None


EXPR_OPTS.append(StringObfType1PeepholeOptimizer)
