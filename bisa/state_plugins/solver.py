from __future__ import annotations

import functools
import time
import logging
import os
from typing import TypeVar, overload

import claripy

from bisa import sim_options as o
from bisa.errors import SimValueError, SimUnsatError, SimSolverModeError, SimSolverOptionError
from bisa.sim_state import SimState
from .inspect import BP_AFTER, BP_BEFORE
from .plugin import SimStatePlugin
from .sim_action_object import ast_stripping_decorator, SimActionObject
from .sim_action import SimActionConstraint

l = logging.getLogger(name=__name__)

# pylint:disable=unidiomatic-typecheck,isinstance-second-argument-not-valid-type

#
# Timing stuff
#

_timing_enabled = False

lt = logging.getLogger("bisa.state_plugins.solver_timing")


def timed_function(f):
    if _timing_enabled:

        @functools.wraps(f)
        def timing_guy(*args, **kwargs):
            the_solver = kwargs.pop("the_solver", None)
            the_solver = args[0] if the_solver is None else the_solver
            s = the_solver.state

            start = time.time()
            r = f(*args, **kwargs)
            end = time.time()
            duration = end - start

            try:
                if s.scratch.sim_procedure is None and s.scratch.bbl_addr is not None:
                    location = "bbl {:#x}, stmt {} (inst {})".format(
                        s.scratch.bbl_addr,
                        s.scratch.stmt_idx,
                        (f"{s.scratch.ins_addr}" if s.scratch.ins_addr is None else f"{s.scratch.ins_addr:#x}"),
                    )
                elif s.scratch.sim_procedure is not None:
                    location = f"sim_procedure {s.scratch.sim_procedure}"
                else:
                    location = "unknown"
            except Exception:  # pylint:disable=broad-except
                l.error("Got exception while generating timer message:", exc_info=True)
                location = "unknown"
            lt.log(int((end - start) * 10), "%s took %s seconds at %s", f.__name__, round(duration, 2), location)

            assert not (0 <= break_time < duration), "Please report this."

            return r

        return timing_guy
    return f


# pylint:disable=global-variable-undefined
def enable_timing():
    global _timing_enabled
    _timing_enabled = True
    lt.setLevel(1)


def disable_timing():
    global _timing_enabled
    _timing_enabled = False


if os.environ.get("SOLVER_TIMING", False):
    enable_timing()
else:
    disable_timing()

break_time = float(os.environ.get("SOLVER_BREAK_TIME", -1))

#
# Various over-engineered crap
#


def error_converter(f):
    @functools.wraps(f)
    def wrapped_f(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except claripy.UnsatError as e:
            raise SimUnsatError("Got an unsat result") from e
        except claripy.ClaripyError as e:
            raise SimSolverModeError("Claripy threw an error") from e

    return wrapped_f


#
# Premature optimizations
#


def _concrete_bool(e):
    if isinstance(e, bool):
        return e
    if (isinstance(e, claripy.ast.Base) and e.op == "BoolV") or (isinstance(e, SimActionObject) and e.op == "BoolV"):
        return e.args[0]
    return None


def _concrete_value(e):
    # shortcuts for speed improvement
    if isinstance(e, (int, float, bool)):
        return e
    if isinstance(e, claripy.ast.Base | SimActionObject) and e.is_leaf() and not e.symbolic:
        return e.args[0]
    return None


def concrete_path_bool(f):
    @functools.wraps(f)
    def concrete_shortcut_bool(self, *args, **kwargs):
        v = _concrete_bool(args[0])
        if v is None:
            return f(self, *args, **kwargs)
        return v

    return concrete_shortcut_bool


def concrete_path_not_bool(f):
    @functools.wraps(f)
    def concrete_shortcut_not_bool(self, *args, **kwargs):
        v = _concrete_bool(args[0])
        if v is None:
            return f(self, *args, **kwargs)
        return not v

    return concrete_shortcut_not_bool


def concrete_path_scalar(f):
    @functools.wraps(f)
    def concrete_shortcut_scalar(self, *args, **kwargs):
        v = _concrete_value(args[0])
        if v is None:
            return f(self, *args, **kwargs)
        return v

    return concrete_shortcut_scalar


def concrete_path_tuple(f):
    @functools.wraps(f)
    def concrete_shortcut_tuple(self, *args, **kwargs):
        v = _concrete_value(args[0])
        if v is None:
            return f(self, *args, **kwargs)
        return (v,)

    return concrete_shortcut_tuple


def concrete_path_list(f):
    @functools.wraps(f)
    def concrete_shortcut_list(self, *args, **kwargs):
        v = _concrete_value(args[0])
        if v is None:
            return f(self, *args, **kwargs)
        return [v]

    return concrete_shortcut_list


#
# The main event
#


class SimSolver(SimStatePlugin):
    """
    This is the plugin you'll use to interact with symbolic variables, creating them and evaluating them.
    It should be available on a state as ``state.solver``.

    Any top-level variable of the claripy module can be accessed as a property of this object.
    """

    def __init__(
        self, solver=None, all_variables=None, temporal_tracked_variables=None, eternal_tracked_variables=None
    ):  # pylint:disable=redefined-outer-name
        super().__init__()

        self._stored_solver = solver
        self.all_variables = [] if all_variables is None else all_variables
        self.temporal_tracked_variables = {} if temporal_tracked_variables is None else temporal_tracked_variables
        self.eternal_tracked_variables = {} if eternal_tracked_variables is None else eternal_tracked_variables

    def reload_solver(self, constraints=None):
        """
        Reloads the solver. Useful when changing solver options.

        :param list constraints:    A new list of constraints to use in the reloaded solver instead of the current one
        """

        if constraints is None:
            constraints = self._solver.constraints
        self._stored_solver = None
        self._solver.add(constraints)

    def get_variables(self, *keys):
        """
        Iterate over all variables for which their tracking key is a prefix of the values provided.

        Elements are a tuple, the first element is the full tracking key, the second is the symbol.

        >>> list(s.solver.get_variables('mem'))
        [(('mem', 0x1000), <BV64 mem_1000_4_64>), (('mem', 0x1008), <BV64 mem_1008_5_64>)]

        >>> list(s.solver.get_variables('file'))
        [(('file', 1, 0), <BV8 file_1_0_6_8>), (('file', 1, 1), <BV8 file_1_1_7_8>),
            (('file', 2, 0), <BV8 file_2_0_8_8>)]

        >>> list(s.solver.get_variables('file', 2))
        [(('file', 2, 0), <BV8 file_2_0_8_8>)]

        >>> list(s.solver.get_variables())
        [(('mem', 0x1000), <BV64 mem_1000_4_64>), (('mem', 0x1008), <BV64 mem_1008_5_64>),
            (('file', 1, 0), <BV8 file_1_0_6_8>), (('file', 1, 1), <BV8 file_1_1_7_8>),
            (('file', 2, 0), <BV8 file_2_0_8_8>)]
        """
        for k, v in self.eternal_tracked_variables.items():
            if len(k) >= len(keys) and all(x == y for x, y in zip(keys, k)):
                yield k, v
        for k, v in self.temporal_tracked_variables.items():
            if k[-1] is None:
                continue
            if len(k) >= len(keys) and all(x == y for x, y in zip(keys, k)):
                yield k, v

    def register_variable(self, v, key, eternal=True):
        """
        Register a value with the variable tracking system

        :param v:       The BVS to register
        :param key:     A tuple to register the variable under
        :parma eternal: Whether this is an eternal variable, default True. If False, an incrementing counter will be
                        appended to the key.
        """
        if type(key) is not tuple:
            raise TypeError("Variable tracking key must be a tuple")
        if eternal:
            self.eternal_tracked_variables[key] = v
        else:
            self.temporal_tracked_variables = dict(self.temporal_tracked_variables)
            ctrkey = (*key, None)
            ctrval = self.temporal_tracked_variables.get(ctrkey, 0) + 1
            self.temporal_tracked_variables[ctrkey] = ctrval
            tempkey = (*key, ctrval)
            self.temporal_tracked_variables[tempkey] = v

    def describe_variables(self, v):
        """
        Given an AST, iterate over all the keys of all the BVS leaves in the tree which are registered.
        """
        # pylint: disable=stop-iteration-return
        # ??? wtf pylint
        reverse_mapping = {next(iter(var.variables)): k for k, var in self.eternal_tracked_variables.items()}
        reverse_mapping.update(
            {next(iter(var.variables)): k for k, var in self.temporal_tracked_variables.items() if k[-1] is not None}
        )

        for var in v.variables:
            if var in reverse_mapping:
                yield reverse_mapping[var]

    @property
    def _solver(self):
        """
        Creates or gets a Claripy solver, based on the state options.
        """
        if self._stored_solver is not None:
            return self._stored_solver

        track = o.CONSTRAINT_TRACKING_IN_SOLVER in self.state.options
        approximate_first = o.APPROXIMATE_FIRST in self.state.options

        if o.ABSTRACT_SOLVER in self.state.options:
            self._stored_solver = claripy.SolverVSA()
        elif o.SYMBOLIC in self.state.options and o.REPLACEMENT_SOLVER in self.state.options:
            self._stored_solver = claripy.SolverReplacement(auto_replace=False)
        elif o.SYMBOLIC in self.state.options and o.CACHELESS_SOLVER in self.state.options:
            self._stored_solver = claripy.SolverCacheless(track=track)
        elif o.SYMBOLIC in self.state.options and o.COMPOSITE_SOLVER in self.state.options:
            self._stored_solver = claripy.SolverComposite(track=track)
        elif (
            o.SYMBOLIC in self.state.options and any(opt in self.state.options for opt in o.approximation)
        ) or o.HYBRID_SOLVER in self.state.options:
            self._stored_solver = claripy.SolverHybrid(track=track, approximate_first=approximate_first)
        elif o.SYMBOLIC in self.state.options:
            self._stored_solver = claripy.Solver(track=track)
        else:
            self._stored_solver = claripy.SolverConcrete()

        return self._stored_solver

    #
    # Get unconstrained stuff
    #
    def Unconstrained(
        self,
        name,
        bits,
        uninitialized=True,
        inspect=True,
        events=True,
        key=None,
        eternal=False,
        uc_alloc_depth=None,
        **kwargs,
    ):
        """
        Creates an unconstrained symbol or a default concrete value (0), based on the state options.

        :param name:            The name of the symbol.
        :param bits:            The size (in bits) of the symbol.
        :param uninitialized:   Whether this value should be counted as an "uninitialized" value in the course of an
                                analysis.
        :param inspect:         Set to False to avoid firing SimInspect breakpoints
        :param events:          Set to False to avoid generating a SimEvent for the occasion
        :param key:             Set this to a tuple of increasingly specific identifiers (for example,
                                ``('mem', 0xffbeff00)`` or ``('file', 4, 0x20)`` to cause it to be tracked, i.e.
                                accessible through ``solver.get_variables``.
        :param eternal:         Set to True in conjunction with setting a key to cause all states with the same
                                ancestry to retrieve the same symbol when trying to create the value. If False, a
                                counter will be appended to the key.

        :returns:               an unconstrained symbol (or a concrete value of 0).
        """
        if o.SYMBOLIC_INITIAL_VALUES in self.state.options:
            # Return a symbolic value
            l.debug("Creating new unconstrained BV named %s", name)
            r = self.BVS(
                name,
                bits,
                uninitialized=uninitialized,
                key=key,
                eternal=eternal,
                inspect=inspect,
                events=events,
                **kwargs,
            )
            if uc_alloc_depth is not None:
                self.state.uc_manager.set_alloc_depth(r, uc_alloc_depth)

            return r
        # Return a default value, aka. 0
        return claripy.BVV(0, bits)

    def BVS(
        self,
        name,
        size,
        min=None,
        max=None,
        stride=None,
        uninitialized=False,
        explicit_name=False,
        key=None,
        eternal=False,
        inspect=True,
        events=True,
        **kwargs,
    ):  # pylint:disable=redefined-builtin
        """
        Creates a bit-vector symbol (i.e., a variable). Other keyword parameters are passed directly on to the
        constructor of claripy.ast.BV.

        :param name:            The name of the symbol.
        :param size:            The size (in bits) of the bit-vector.
        :param min:             The minimum value of the symbol. Note that this **only** work when using VSA.
        :param max:             The maximum value of the symbol. Note that this **only** work when using VSA.
        :param stride:          The stride of the symbol. Note that this **only** work when using VSA.
        :param uninitialized:   Whether this value should be counted as an "uninitialized" value in the course of an
                                analysis.
        :param explicit_name:   Set to True to prevent an identifier from appended to the name to ensure uniqueness.
        :param key:             Set this to a tuple of increasingly specific identifiers (for example,
                                ``('mem', 0xffbeff00)`` or ``('file', 4, 0x20)`` to cause it to be tracked, i.e.
                                accessible through ``solver.get_variables``.
        :param eternal:         Set to True in conjunction with setting a key to cause all states with the same
                                ancestry to retrieve the same symbol when trying to create the value. If False, a
                                counter will be appended to the key.
        :param inspect:         Set to False to avoid firing SimInspect breakpoints
        :param events:          Set to False to avoid generating a SimEvent for the occasion

        :return:                A BV object representing this symbol.
        """

        # should this be locked for multithreading?
        if key is not None and eternal and key in self.eternal_tracked_variables:
            r = self.eternal_tracked_variables[key]
            # pylint: disable=too-many-boolean-expressions
            if (
                size != r.length
                or uninitialized != r.has_annotation_type(claripy.annotation.UninitializedAnnotation)
                or bool(explicit_name) ^ (r.args[0] == name)
            ):
                l.warning("Variable %s being retrieved with different settings than it was tracked with", name)
        else:
            r = claripy.BVS(
                name,
                size,
                explicit_name=explicit_name,
                **kwargs,
            )
            if any(x is not None for x in (min, max, stride)):
                r = r.annotate(claripy.annotation.StridedIntervalAnnotation(stride, min, max))
            if uninitialized:
                r = r.annotate(claripy.annotation.UninitializedAnnotation())
            if key is not None:
                self.register_variable(r, key, eternal)

        if inspect:
            self.state._inspect(
                "symbolic_variable",
                BP_AFTER,
                symbolic_name=next(iter(r.variables)),
                symbolic_size=size,
                symbolic_expr=r,
            )
        if events:
            self.state.history.add_event("unconstrained", name=next(iter(r.variables)), bits=size, **kwargs)
        if o.TRACK_SOLVER_VARIABLES in self.state.options:
            self.all_variables = list(self.all_variables)
            self.all_variables.append(r)
        return r

    #
    # Branching stuff
    #

    @SimStatePlugin.memo
    def copy(self, memo):  # pylint: disable=unused-argument
        c = super().copy(memo)

        c._stored_solver = self._solver.branch()
        c.all_variables = self.all_variables
        c.temporal_tracked_variables = self.temporal_tracked_variables
        c.eternal_tracked_variables = self.eternal_tracked_variables

        return c

    @error_converter
    def merge(self, others, merge_conditions, common_ancestor=None):  # pylint: disable=W0613
        merging_occurred, self._stored_solver = self._solver.merge(
            [oc._solver for oc in others],
            merge_conditions,
            common_ancestor=common_ancestor._solver if common_ancestor is not None else None,
        )
        return merging_occurred

    @error_converter
    def widen(self, others):
        c = claripy.BVS("random_widen_condition", 32)
        merge_conditions = [[c == i] for i in range(len(others) + 1)]
        return self.merge(others, merge_conditions)

    #
    # Frontend passthroughs
    #

    def downsize(self):
        """
        Frees memory associated with the constraint solver by clearing all of
        its internal caches.
        """
        self._solver.downsize()

    @property
    def constraints(self):
        """
        Returns the constraints of the state stored by the solver.
        """
        return self._solver.constraints

    def _adjust_constraint(self, c):
        if self.state._global_condition is None:
            return c
        if c is None:  # this should never happen
            l.critical("PLEASE REPORT THIS MESSAGE, AND WHAT YOU WERE DOING, TO YAN")
            return self.state._global_condition
        return claripy.Or(claripy.Not(self.state._global_condition), c)

    def _adjust_constraint_list(self, constraints):
        if self.state._global_condition is None:
            return constraints
        if len(constraints) == 0:
            return constraints.__class__((self.state._global_condition,))
        return constraints.__class__((self._adjust_constraint(claripy.And(*constraints)),))

    @timed_function
    @ast_stripping_decorator
    @error_converter
    def eval_to_ast(self, e, n, extra_constraints=(), exact=None):
        """
        Evaluate an expression, using the solver if necessary. Returns AST objects.

        :param e: the expression
        :param n: the number of desired solutions
        :param extra_constraints: extra constraints to apply to the solver
        :param exact: if False, returns approximate solutions
        :return: a tuple of the solutions, in the form of claripy AST nodes
        :rtype: tuple
        """
        return self._solver.eval_to_ast(
            e, n, extra_constraints=self._adjust_constraint_list(extra_constraints), exact=exact
        )

    @concrete_path_tuple
    @timed_function
    @ast_stripping_decorator
    @error_converter
    def _eval(self, e, n, extra_constraints=(), exact=None):
        """
        Evaluate an expression, using the solver if necessary. Returns primitives.

        :param e: the expression
        :param n: the number of desired solutions
        :param extra_constraints: extra constraints to apply to the solver
        :param exact: if False, returns approximate solutions
        :return: a tuple of the solutions, in the form of Python primitives
        :rtype: tuple
        """
        return self._solver.eval(e, n, extra_constraints=self._adjust_constraint_list(extra_constraints), exact=exact)

    @concrete_path_scalar
    @timed_function
    @ast_stripping_decorator
    @error_converter
    def max(self, e, extra_constraints=(), exact=None, signed=False):
        """
        Return the maximum value of expression `e`.

        :param e                : expression (an AST) to evaluate
        :param extra_constraints: extra constraints (as ASTs) to add to the solver for this solve
        :param exact            : if False, return approximate solutions.
        :param signed           : Whether the expression should be treated as a signed value.
        :return: the maximum possible value of e (backend object)
        """
        if exact is False and o.VALIDATE_APPROXIMATIONS in self.state.options:
            ar = self._solver.max(
                e, extra_constraints=self._adjust_constraint_list(extra_constraints), exact=False, signed=signed
            )
            er = self._solver.max(e, extra_constraints=self._adjust_constraint_list(extra_constraints), signed=signed)
            assert er <= ar
            return ar
        return self._solver.max(
            e, extra_constraints=self._adjust_constraint_list(extra_constraints), exact=exact, signed=signed
        )

    @concrete_path_scalar
    @timed_function
    @ast_stripping_decorator
    @error_converter
    def min(self, e, extra_constraints=(), exact=None, signed=False):
        """
        Return the minimum value of expression `e`.

        :param e                : expression (an AST) to evaluate
        :param extra_constraints: extra constraints (as ASTs) to add to the solver for this solve
        :param exact            : if False, return approximate solutions.
        :param signed           : Whether the expression should be treated as a signed value.
        :return: the minimum possible value of e (backend object)
        """
        if exact is False and o.VALIDATE_APPROXIMATIONS in self.state.options:
            ar = self._solver.min(
                e, extra_constraints=self._adjust_constraint_list(extra_constraints), exact=False, signed=signed
            )
            er = self._solver.min(e, extra_constraints=self._adjust_constraint_list(extra_constraints), signed=signed)
            assert ar <= er
            return ar
        return self._solver.min(
            e, extra_constraints=self._adjust_constraint_list(extra_constraints), exact=exact, signed=signed
        )

    @timed_function
    @ast_stripping_decorator
    @error_converter
    def solution(self, e, v, extra_constraints=(), exact=None):
        """
        Return True if `v` is a solution of `expr` with the extra constraints, False otherwise.

        :param e:                   An expression (an AST) to evaluate
        :param v:                   The proposed solution (an AST)
        :param extra_constraints:   Extra constraints (as ASTs) to add to the solver for this solve.
        :param exact:               If False, return approximate solutions.
        :return:                    True if `v` is a solution of `expr`, False otherwise
        """
        if exact is False and o.VALIDATE_APPROXIMATIONS in self.state.options:
            ar = self._solver.solution(
                e, v, extra_constraints=self._adjust_constraint_list(extra_constraints), exact=False
            )
            er = self._solver.solution(e, v, extra_constraints=self._adjust_constraint_list(extra_constraints))
            if er is True:
                assert ar is True
            return ar
        return self._solver.solution(
            e, v, extra_constraints=self._adjust_constraint_list(extra_constraints), exact=exact
        )

    @concrete_path_bool
    @timed_function
    @ast_stripping_decorator
    @error_converter
    def is_true(self, e, extra_constraints=(), exact=None):
        """
        If the expression provided is absolutely, definitely a true boolean, return True.
        Note that returning False doesn't necessarily mean that the expression can be false, just that we couldn't
        figure that out easily.

        :param e:                   An expression (an AST) to evaluate
        :param extra_constraints:   Extra constraints (as ASTs) to add to the solver for this solve.
        :param exact:               If False, return approximate solutions.
        :return:                    True if `v` is definitely true, False otherwise
        """
        if exact is False and o.VALIDATE_APPROXIMATIONS in self.state.options:
            ar = self._solver.is_true(e, extra_constraints=self._adjust_constraint_list(extra_constraints), exact=False)
            er = self._solver.is_true(e, extra_constraints=self._adjust_constraint_list(extra_constraints))
            if er is False:
                assert ar is False
            return ar
        return self._solver.is_true(e, extra_constraints=self._adjust_constraint_list(extra_constraints), exact=exact)

    @concrete_path_not_bool
    @timed_function
    @ast_stripping_decorator
    @error_converter
    def is_false(self, e, extra_constraints=(), exact=None):
        """
        If the expression provided is absolutely, definitely a false boolean, return True.
        Note that returning False doesn't necessarily mean that the expression can be true, just that we couldn't
        figure that out easily.

        :param e:                   An expression (an AST) to evaluate
        :param extra_constraints:   Extra constraints (as ASTs) to add to the solver for this solve.
        :param exact:               If False, return approximate solutions.
        :return:                    True if `v` is definitely false, False otherwise
        """
        if exact is False and o.VALIDATE_APPROXIMATIONS in self.state.options:
            ar = self._solver.is_false(
                e, extra_constraints=self._adjust_constraint_list(extra_constraints), exact=False
            )
            er = self._solver.is_false(e, extra_constraints=self._adjust_constraint_list(extra_constraints))
            if er is False:
                assert ar is False
            return ar
        return self._solver.is_false(e, extra_constraints=self._adjust_constraint_list(extra_constraints), exact=exact)

    @timed_function
    @ast_stripping_decorator
    @error_converter
    def unsat_core(self, extra_constraints=()):
        """
        This function returns the unsat core from the backend solver.

        :param extra_constraints:   Extra constraints (as ASTs) to add to the solver for this solve.
        :return: The unsat core.
        """
        if o.CONSTRAINT_TRACKING_IN_SOLVER not in self.state.options:
            raise SimSolverOptionError("CONSTRAINT_TRACKING_IN_SOLVER must be enabled before calling unsat_core().")
        return self._solver.unsat_core(extra_constraints=extra_constraints)

    @timed_function
    @ast_stripping_decorator
    @error_converter
    def satisfiable(self, extra_constraints=(), exact=None):
        """
        This function does a constraint check and checks if the solver is in a sat state.

        :param extra_constraints:   Extra constraints (as ASTs) to add to s for this solve
        :param exact:               If False, return approximate solutions.

        :return:                    True if sat, otherwise false
        """
        if o.ABSTRACT_SOLVER in self.state.options or o.SYMBOLIC not in self.state.options:
            return all(not self.is_false(e) for e in extra_constraints)

        if exact is False and o.VALIDATE_APPROXIMATIONS in self.state.options:
            er = self._solver.satisfiable(extra_constraints=self._adjust_constraint_list(extra_constraints))
            ar = self._solver.satisfiable(
                extra_constraints=self._adjust_constraint_list(extra_constraints), exact=False
            )
            if er is True:
                assert ar is True
            return ar
        return self._solver.satisfiable(extra_constraints=self._adjust_constraint_list(extra_constraints), exact=exact)

    @timed_function
    @ast_stripping_decorator
    @error_converter
    def add(self, *constraints):
        """
        Add some constraints to the solver.

        :param constraints:     Pass any constraints that you want to add (ASTs) as varargs.
        """
        if len(constraints) > 0 and isinstance(constraints[0], (list, tuple)):
            raise Exception("Tuple or list passed to add!")

        if o.TRACK_CONSTRAINTS in self.state.options and len(constraints) > 0:
            constraints = (
                [self.simplify(a) for a in constraints] if o.SIMPLIFY_CONSTRAINTS in self.state.options else constraints
            )

            self.state._inspect("constraints", BP_BEFORE, added_constraints=constraints)
            constraints = self.state._inspect_getattr("added_constraints", constraints)
            cc = self._adjust_constraint_list(constraints)
            added = self._solver.add(cc)
            self.state._inspect("constraints", BP_AFTER)

            # add actions for the added constraints
            if o.TRACK_CONSTRAINT_ACTIONS in self.state.options:
                for c in added:
                    sac = SimActionConstraint(self.state, c)
                    self.state.history.add_action(sac)

        if o.ABSTRACT_SOLVER in self.state.options and len(constraints) > 0:
            for arg in constraints:
                if self.is_false(arg):
                    return

                if self.is_true(arg):
                    continue

                # It's neither True or False. Let's try to apply the condition

                # We take the argument, extract a list of constrained SIs out of
                # it (if we could, of course), and then replace each original SI
                # the intersection of original SI and the constrained one.

                _, converted = claripy.constraint_to_si(arg)

                for original_expr, constrained_si in converted:
                    if not original_expr.variables:
                        l.error(
                            "Incorrect original_expression to replace in add(). "
                            "This is due to defects in VSA logics inside claripy. "
                            "Please report to Fish and he will fix it if he's free."
                        )
                        continue

                    new_expr = constrained_si
                    self.state.registers.replace_all(original_expr, new_expr)
                    self.state.memory.replace_all(original_expr, new_expr)
                    # tmps
                    temps = self.state.scratch.temps
                    for idx in range(len(temps)):  # pylint:disable=consider-using-enumerate
                        t = temps[idx]
                        if t is None:
                            continue
                        if t.variables.intersection(original_expr.variables):
                            # replace
                            temps[idx] = claripy.replace(t, original_expr, new_expr)

                    l.debug("SimSolver.add: Applied to final state.")
        elif o.SYMBOLIC not in self.state.options and len(constraints) > 0:
            for arg in constraints:
                if self.is_false(arg):
                    return

    #
    # And some convenience stuff
    #

    CastType = TypeVar("CastType", int, bytes)

    @staticmethod
    def _cast_to(
        e: claripy.ast.Bool | claripy.ast.BV | claripy.ast.FP,
        solution: bool | float | int,
        cast_to: type[CastType] | None,
    ) -> CastType:
        """
        Casts a solution for the given expression to type `cast_to`.

        :param e: The expression `solution` is a solution for
        :param solution: The solution to be cast
        :param cast_to: The type `solution` should be cast to. Must be one of the currently supported types (bytes|int)
        :raise ValueError: If cast_to is a currently unsupported cast target.
        :return: The value of `solution` cast to type `cast_to`
        """
        if cast_to is None:
            return solution

        if type(solution) is bool:
            if cast_to is bytes:
                return bytes([int(solution)])
            if cast_to is int:
                return int(solution)
        elif type(solution) is float:
            solution = _concrete_value(claripy.FPV(solution, claripy.fp.FSort.from_size(len(e))).raw_to_bv())

        if cast_to is bytes:
            if len(e) == 0:
                return b""
            if len(e) % 8:
                raise ValueError("bit string length is not a multiple of 8")
            return solution.to_bytes(len(e) // 8, byteorder="big")

        if cast_to is not int:
            raise ValueError(
                f"cast_to parameter {cast_to!r} is not a valid cast target, currently supported are only int and bytes!"
            )

        return solution

    @overload
    def eval_upto(self, e: claripy.ast.BV, n: int, cast_to: None = ..., **kwargs) -> list[int]: ...

    @overload
    def eval_upto(self, e: claripy.ast.BV, n: int, cast_to: type[CastType], **kwargs) -> list[CastType]: ...

    @overload
    def eval_upto(self, e: claripy.ast.Bool, n: int, cast_to: None = ..., **kwargs) -> list[bool]: ...

    @overload
    def eval_upto(self, e: claripy.ast.Bool, n: int, cast_to: type[CastType], **kwargs) -> list[CastType]: ...

    @overload
    def eval_upto(self, e: claripy.ast.FP, n: int, cast_to: None = ..., **kwargs) -> list[float]: ...

    @overload
    def eval_upto(self, e: claripy.ast.FP, n: int, cast_to: type[CastType], **kwargs) -> list[CastType]: ...

    def eval_upto(self, e, n, cast_to=None, **kwargs):
        """
        Evaluate an expression, using the solver if necessary. Returns primitives as specified by the `cast_to`
        parameter. Only certain primitives are supported, check the implementation of `_cast_to` to see which ones.

        :param e: the expression
        :param n: the number of desired solutions
        :param extra_constraints: extra constraints to apply to the solver
        :param exact: if False, returns approximate solutions
        :param cast_to: desired type of resulting values
        :return: a tuple of the solutions, in the form of Python primitives
        :rtype: tuple
        """
        concrete_val = _concrete_value(e)
        if concrete_val is not None:
            return [self._cast_to(e, concrete_val, cast_to)]

        cast_vals = [self._cast_to(e, v, cast_to) for v in self._eval(e, n, **kwargs)]
        if len(cast_vals) == 0:
            raise SimUnsatError(f"Not satisfiable: {e.shallow_repr()}, expected up to {n} solutions")
        return cast_vals

    @overload
    def eval(self, e: claripy.ast.BV, cast_to: None = ..., **kwargs) -> int: ...

    @overload
    def eval(self, e: claripy.ast.BV, cast_to: type[CastType], **kwargs) -> CastType: ...

    @overload
    def eval(self, e: claripy.ast.Bool, cast_to: None = ..., **kwargs) -> bool: ...

    @overload
    def eval(self, e: claripy.ast.Bool, cast_to: type[CastType], **kwargs) -> CastType: ...

    @overload
    def eval(self, e: claripy.ast.FP, cast_to: None = ..., **kwargs) -> float: ...

    @overload
    def eval(self, e: claripy.ast.FP, cast_to: type[CastType], **kwargs) -> CastType: ...

    def eval(self, e, cast_to=None, **kwargs):
        """
        Evaluate an expression to get any possible solution. The desired output types can be specified using the
        `cast_to` parameter. `extra_constraints` can be used to specify additional constraints the returned values
        must satisfy.

        :param e: the expression to get a solution for
        :param kwargs: Any additional kwargs will be passed down to `eval_upto`
        :param cast_to: desired type of resulting values
        :raise SimUnsatError: if no solution could be found satisfying the given constraints
        :return:
        """
        # eval_upto already throws the UnsatError, no reason for us to worry about it
        concrete_val = _concrete_value(e)
        if concrete_val is not None:
            return self._cast_to(e, concrete_val, cast_to)

        return self.eval_upto(e, 1, cast_to, **kwargs)[0]

    @overload
    def eval_one(self, e: claripy.ast.BV, cast_to: None = ..., **kwargs) -> int: ...

    @overload
    def eval_one(self, e: claripy.ast.BV, cast_to: type[CastType], **kwargs) -> CastType: ...

    @overload
    def eval_one(self, e: claripy.ast.Bool, cast_to: None = ..., **kwargs) -> bool: ...

    @overload
    def eval_one(self, e: claripy.ast.Bool, cast_to: type[CastType], **kwargs) -> CastType: ...

    @overload
    def eval_one(self, e: claripy.ast.FP, cast_to: None = ..., **kwargs) -> float: ...

    @overload
    def eval_one(self, e: claripy.ast.FP, cast_to: type[CastType], **kwargs) -> CastType: ...

    def eval_one(self, e, cast_to=None, **kwargs):
        """
        Evaluate an expression to get the only possible solution. Errors if either no or more than one solution is
        returned. A kwarg parameter `default` can be specified to be returned instead of failure!

        :param e: the expression to get a solution for
        :param cast_to: desired type of resulting values
        :param default: A value can be passed as a kwarg here. It will be returned in case of failure.
        :param kwargs: Any additional kwargs will be passed down to `eval_upto`
        :raise SimUnsatError: if no solution could be found satisfying the given constraints
        :raise SimValueError: if more than one solution was found to satisfy the given constraints
        :return: The value for `e`
        """
        try:
            return self.eval_exact(e, 1, cast_to, **{k: v for (k, v) in kwargs.items() if k != "default"})[0]
        except (SimUnsatError, SimValueError, SimSolverModeError):
            if "default" in kwargs:
                return kwargs.pop("default")
            raise

    @overload
    def eval_atmost(self, e: claripy.ast.BV, n: int, cast_to: None = ..., **kwargs) -> list[int]: ...

    @overload
    def eval_atmost(self, e: claripy.ast.BV, n: int, cast_to: type[CastType], **kwargs) -> list[CastType]: ...

    @overload
    def eval_atmost(self, e: claripy.ast.Bool, n: int, cast_to: None = ..., **kwargs) -> list[bool]: ...

    @overload
    def eval_atmost(self, e: claripy.ast.Bool, n: int, cast_to: type[CastType], **kwargs) -> list[CastType]: ...

    @overload
    def eval_atmost(self, e: claripy.ast.FP, n: int, cast_to: None = ..., **kwargs) -> list[float]: ...

    @overload
    def eval_atmost(self, e: claripy.ast.FP, n: int, cast_to: type[CastType], **kwargs) -> list[CastType]: ...

    def eval_atmost(self, e, n, cast_to=None, **kwargs):
        """
        Evaluate an expression to get at most `n` possible solutions. Errors if either none or more than `n` solutions
        are returned.

        :param e: the expression to get a solution for
        :param n: the inclusive upper limit on the number of solutions
        :param cast_to: desired type of resulting values
        :param kwargs: Any additional kwargs will be passed down to `eval_upto`
        :raise SimUnsatError: if no solution could be found satisfying the given constraints
        :raise SimValueError: if more than `n` solutions were found to satisfy the given constraints
        :return: The solutions for `e`
        """
        r = self.eval_upto(e, n + 1, cast_to, **kwargs)
        if len(r) > n:
            raise SimValueError(f"Concretized {len(r)} values (must be at most {n}) in eval_atmost")
        return r

    @overload
    def eval_atleast(self, e: claripy.ast.BV, n: int, cast_to: None = ..., **kwargs) -> list[int]: ...

    @overload
    def eval_atleast(self, e: claripy.ast.BV, n: int, cast_to: type[CastType], **kwargs) -> list[CastType]: ...

    @overload
    def eval_atleast(self, e: claripy.ast.Bool, n: int, cast_to: None = ..., **kwargs) -> list[bool]: ...

    @overload
    def eval_atleast(self, e: claripy.ast.Bool, n: int, cast_to: type[CastType], **kwargs) -> list[CastType]: ...

    @overload
    def eval_atleast(self, e: claripy.ast.FP, n: int, cast_to: None = ..., **kwargs) -> list[float]: ...

    @overload
    def eval_atleast(self, e: claripy.ast.FP, n: int, cast_to: type[CastType], **kwargs) -> list[CastType]: ...

    def eval_atleast(self, e, n, cast_to=None, **kwargs):
        """
        Evaluate an expression to get at least `n` possible solutions. Errors if less than `n` solutions were found.

        :param e: the expression to get a solution for
        :param n: the inclusive lower limit on the number of solutions
        :param cast_to: desired type of resulting values
        :param kwargs: Any additional kwargs will be passed down to `eval_upto`
        :raise SimUnsatError: if no solution could be found satisfying the given constraints
        :raise SimValueError: if less than `n` solutions were found to satisfy the given constraints
        :return: The solutions for `e`
        """
        r = self.eval_upto(e, n, cast_to, **kwargs)
        if len(r) != n:
            raise SimValueError(f"Concretized {len(r)} values (must be at least {n}) in eval_atleast")
        return r

    @overload
    def eval_exact(self, e: claripy.ast.BV, n: int, cast_to: None = ..., **kwargs) -> list[int]: ...

    @overload
    def eval_exact(self, e: claripy.ast.BV, n: int, cast_to: type[CastType], **kwargs) -> list[CastType]: ...

    @overload
    def eval_exact(self, e: claripy.ast.Bool, n: int, cast_to: None = ..., **kwargs) -> list[bool]: ...

    @overload
    def eval_exact(self, e: claripy.ast.Bool, n: int, cast_to: type[CastType], **kwargs) -> list[CastType]: ...

    @overload
    def eval_exact(self, e: claripy.ast.FP, n: int, cast_to: None = ..., **kwargs) -> list[float]: ...

    @overload
    def eval_exact(self, e: claripy.ast.FP, n: int, cast_to: type[CastType], **kwargs) -> list[CastType]: ...

    def eval_exact(self, e, n, cast_to=None, **kwargs):
        """
        Evaluate an expression to get exactly the `n` possible solutions. Errors if any number of solutions other
        than `n` was found to exist.

        :param e: the expression to get a solution for
        :param n: the inclusive lower limit on the number of solutions
        :param cast_to: desired type of resulting values
        :param kwargs: Any additional kwargs will be passed down to `eval_upto`
        :raise SimUnsatError: if no solution could be found satisfying the given constraints
        :raise SimValueError: if any number of solutions other than `n` were found to satisfy the given constraints
        :return: The solutions for `e`
        """
        r = self.eval_upto(e, n + 1, cast_to, **kwargs)
        if len(r) != n:
            raise SimValueError(f"Concretized {len(r)} values (must be exactly {n}) in eval_exact")
        return r

    min_int = min
    max_int = max

    #
    # Other methods
    #

    @timed_function
    @ast_stripping_decorator
    def unique(self, e, **kwargs):
        """
        Returns True if the expression `e` has only one solution by querying
        the constraint solver. It does also add that unique solution to the
        solver's constraints.
        """
        if not isinstance(e, claripy.ast.Base):
            return True

        # if we don't want to do symbolic checks, assume symbolic variables are multivalued
        if o.SYMBOLIC not in self.state.options and self.symbolic(e):
            return False

        r = self.eval_upto(e, 2, **kwargs)
        if len(r) == 1:
            self.add(e == r[0])
            return True
        if len(r) == 0:
            raise SimValueError("unsatness during uniqueness check(ness)")
        return False

    def symbolic(self, e):  # pylint:disable=R0201
        """
        Returns True if the expression `e` is symbolic.
        """
        if isinstance(e, (int, bytes, float, bool)):
            return False
        return e.symbolic

    def single_valued(self, e):
        """
        Returns True whether `e` is a concrete value or is a value set with
        only 1 possible value. This differs from `unique` in that this *does*
        not query the constraint solver.
        """
        if self.state.mode == "static":
            if type(e) in (int, bytes, float, bool):
                return True
            return e.cardinality <= 1

        # All symbolic expressions are not single-valued
        return not self.symbolic(e)

    def simplify(self, e=None):
        """
        Simplifies `e`. If `e` is None, simplifies the constraints of this
        state.
        """
        if e is None:
            return self._solver.simplify()
        if (
            isinstance(e, (int, float, bool))
            or (isinstance(e, claripy.ast.Base | SimActionObject) and e.is_leaf() and not e.symbolic)
            or (not isinstance(e, claripy.ast.Base | SimActionObject))
        ):
            return e
        return self._claripy_simplify(e)

    @timed_function
    @ast_stripping_decorator
    @error_converter
    def _claripy_simplify(self, *args):  # pylint:disable=no-self-use
        return claripy.simplify(args[0])

    def variables(self, e):  # pylint:disable=no-self-use
        """
        Returns the symbolic variables present in the AST of `e`.
        """
        return e.variables


SimState.register_default("solver", SimSolver)
