from __future__ import annotations
import pycparser

from .sim_manager import SimulationManager
from .errors import BISACallableError, BISACallableMultistateError
from .calling_conventions import default_cc, SimCC


class Callable:
    """
    Callable is a representation of a function in the binary that can be
    interacted with like a native python function.

    If you set perform_merge=True (the default), the result will be returned to you, and
    you can get the result state with callable.result_state.

    Otherwise, you can get the resulting simulation manager at callable.result_path_group.
    """

    def __init__(
        self,
        project,
        addr,
        prototype=None,
        concrete_only=False,
        perform_merge=True,
        base_state=None,
        toc=None,
        cc=None,
        add_options=None,
        remove_options=None,
        step_limit: int | None = None,
    ):
        """
        :param project:         The project to operate on
        :param addr:            The address of the function to use

        The following parameters are optional:

        :param prototype:         The signature of the calls you would like to make. This really shouldn't be optional.
        :param concrete_only:   Throw an exception if the execution splits into multiple paths
        :param perform_merge:   Merge all result states into one at the end (only relevant if concrete_only=False)
        :param base_state:      The state from which to do these runs
        :param toc:             The address of the table of contents for ppc64
        :param cc:              The SimCC to use for a calling convention
        """

        self._project = project
        self._addr = addr
        self._concrete_only = concrete_only
        self._perform_merge = perform_merge
        self._base_state = base_state
        self._toc = toc
        self._cc = (
            cc
            if cc is not None
            else default_cc(project.arch.name, platform=project.simos.name if project.simos is not None else None)(
                project.arch
            )
        )
        self._deadend_addr = project.simos.return_deadend
        self._func_ty = prototype
        self._add_options = add_options if add_options else set()
        self._remove_options = remove_options if remove_options else set()
        self._step_limit = step_limit

        self.result_path_group = None
        self.result_state = None

    def set_base_state(self, state):
        """
        Swap out the state you'd like to use to perform the call
        :param state: The state to use to perform the call
        """
        self._base_state = state

    def __call__(self, *args):
        prototype = SimCC.guess_prototype(args, self._func_ty).with_arch(self._project.arch)
        self.perform_call(*args, prototype=prototype)
        if self.result_state is not None and prototype.returnty is not None:
            loc = self._cc.return_val(prototype.returnty)
            if loc is not None:
                val = loc.get_value(self.result_state, stack_base=self.result_state.regs.sp - self._cc.STACKARG_SP_DIFF)
                return self.result_state.solver.simplify(val)
        return None

    def perform_call(self, *args, prototype=None):
        prototype = SimCC.guess_prototype(args, prototype or self._func_ty).with_arch(self._project.arch)
        state = self._project.factory.call_state(
            self._addr,
            *args,
            prototype=prototype,
            cc=self._cc,
            base_state=self._base_state,
            ret_addr=self._deadend_addr,
            toc=self._toc,
            add_options=self._add_options,
            remove_options=self._remove_options,
        )

        caller = self._project.factory.simulation_manager(state)
        caller.run(step_func=self._step_func).unstash(from_stash="deadended")
        caller.prune(filter_func=lambda pt: pt.addr == self._deadend_addr)

        if "step_limited" in caller.stashes:
            caller.stash(from_stash="step_limited", to_stash="active")
        if len(caller.active) == 0:
            raise BISACallableError("No paths returned from function")

        self.result_path_group = caller.copy()

        if self._perform_merge:
            caller.merge()
            self.result_state = caller.active[0]
        elif len(caller.active) == 1:
            self.result_state = caller.active[0]

    def call_c(self, c_args):
        """
        Call this Callable with a string of C-style arguments.

        :param str c_args:  C-style arguments.
        :return:            The return value from the call.
        :rtype:             claripy.Ast
        """

        c_args = c_args.strip()
        if c_args[0] != "(":
            c_args = "(" + c_args
        if c_args[-1] != ")":
            c_args += ")"

        # Parse arguments
        content = f"int main() {{ func{c_args}; }}"
        ast = pycparser.CParser().parse(content)

        if not ast.ext or not isinstance(ast.ext[0], pycparser.c_ast.FuncDef):
            raise BISACallableError("Error in parsing the given C-style argument string.")

        if not ast.ext[0].body.block_items or not isinstance(ast.ext[0].body.block_items[0], pycparser.c_ast.FuncCall):
            raise BISACallableError(
                "Error in parsing the given C-style argument string: Cannot find the expected function call."
            )

        arg_exprs = ast.ext[0].body.block_items[0].args.exprs

        args = []
        for expr in arg_exprs:
            if isinstance(expr, pycparser.c_ast.Constant):
                # string
                if expr.type == "string":
                    args.append(expr.value[1:-1])
                elif expr.type == "int":
                    args.append(int(expr.value))
                else:
                    raise BISACallableError(f"Unsupported expression type {expr.type}.")
            else:
                raise BISACallableError(f"Unsupported expression type {type(expr)}.")

        return self.__call__(*args)

    def _step_func(self, pg: SimulationManager):
        pg2 = pg.prune()
        if self._concrete_only and len(pg2.active) > 1:
            raise BISACallableMultistateError("Execution split on symbolic condition!")
        if self._step_limit:
            pg2.stash(filter_func=lambda p: p.history.depth >= self._step_limit, to_stash="step_limited")
        return pg2
