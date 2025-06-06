# pylint:disable=no-self-use
from __future__ import annotations
from collections import defaultdict
from typing import TYPE_CHECKING
import logging

import networkx
import capstone

from pyvex.stmt import Put
from pyvex.expr import RdTmp
import ailment

from bisa.code_location import ExternalCodeLocation

from bisa.calling_conventions import (
    SimFunctionArgument,
    SimRegArg,
    SimStackArg,
    SimCC,
    default_cc,
    SimCCMicrosoftThiscall,
)
from bisa.errors import SimTranslationError
from bisa.sim_type import (
    SimTypeCppFunction,
    SimTypeInt,
    SimTypeFunction,
    SimType,
    SimTypeLongLong,
    SimTypeShort,
    SimTypeChar,
    SimTypeBottom,
    SimTypeFloat,
    SimTypeDouble,
    parse_cpp_file,
)
from bisa.sim_variable import SimStackVariable, SimRegisterVariable
from bisa.knowledge_plugins.key_definitions.atoms import Register, MemoryLocation, SpOffset
from bisa.knowledge_plugins.key_definitions.tag import ReturnValueTag
from bisa.knowledge_plugins.key_definitions.constants import OP_BEFORE, OP_AFTER
from bisa.knowledge_plugins.key_definitions.rd_model import ReachingDefinitionsModel
from bisa.knowledge_plugins.variables.variable_access import VariableAccessSort
from bisa.knowledge_plugins.functions import Function
from bisa.utils.constants import DEFAULT_STATEMENT
from bisa.utils.ssa import get_reg_offset_base_and_size, get_reg_offset_base
from bisa import SIM_PROCEDURES
from bisa.analyses import Analysis, register_analysis, ReachingDefinitionsAnalysis
from bisa.analyses.reaching_definitions import get_all_definitions
from .utils import is_sane_register_variable

if TYPE_CHECKING:
    from bisa.knowledge_plugins.cfg import CFGModel
    from bisa.knowledge_plugins.key_definitions.uses import Uses
    from bisa.knowledge_plugins.key_definitions.definition import Definition

l = logging.getLogger(name=__name__)


class CallSiteFact:
    """
    Store facts about each call site.
    """

    def __init__(self, return_value_used):
        self.return_value_used: bool = return_value_used
        self.args = []


class UpdateArgumentsOption:
    """
    Enums for controlling the argument updating behavior in _adjust_cc.
    """

    DoNotUpdate = 0
    AlwaysUpdate = 1
    UpdateWhenCCHasNoArgs = 2


class CallingConventionAnalysis(Analysis):
    """
    Analyze the calling convention of a function and guess a probable prototype.

    The calling convention of a function can be inferred at both its call sites and the function itself. At call sites,
    we consider all register and stack variables that are not alive after the function call as parameters to this
    function. In the function itself, we consider all register and stack variables that are read but without
    initialization as parameters. Then we synthesize the information from both locations and make a reasonable
    inference of calling convention of this function.

    :ivar _function:    The function to recover calling convention for.
    :ivar _variable_manager:    A handy accessor to the variable manager.
    :ivar _cfg:         A reference of the CFGModel of the current binary. It is used to discover call sites of the
                        current function in order to perform analysis at call sites.
    :ivar analyze_callsites:    True if we should analyze all call sites of the current function to determine the
                                calling convention and arguments. This can be time-consuming if there are many call
                                sites to analyze.
    :ivar cc:           The recovered calling convention for the function.
    """

    def __init__(
        self,
        func: Function | int | str | None,
        cfg: CFGModel | None = None,
        analyze_callsites: bool = False,
        caller_func_addr: int | None = None,
        callsite_block_addr: int | None = None,
        callsite_insn_addr: int | None = None,
        func_graph: networkx.DiGraph | None = None,
        input_args: list[SimRegArg | SimStackArg] | None = None,
        retval_size: int | None = None,
    ):
        if func is not None and not isinstance(func, Function):
            func = self.kb.functions[func]
        self._function = func
        self._variable_manager = self.kb.variables
        self._cfg = cfg
        self.analyze_callsites = analyze_callsites
        self.caller_func_addr = caller_func_addr
        self.callsite_block_addr = callsite_block_addr
        self.callsite_insn_addr = callsite_insn_addr
        self._func_graph = func_graph
        self._input_args = input_args
        self._retval_size = retval_size

        if self._retval_size is not None and self._input_args is None:
            # retval size will be ignored if input_args is not specified - user error?
            raise TypeError(
                "input_args must be provided to use retval_size. Otherwise please set both input_args and "
                "retval_size to None."
            )

        self.cc: SimCC | None = None
        self.prototype: SimTypeFunction | None = None
        self.prototype_libname: str | None = None

        if self._cfg is None and "CFGFast" in self.kb.cfgs:
            self._cfg = self.kb.cfgs["CFGFast"]

        if self._function is not None:
            # caller function analysis mode
            self._analyze()
        elif (
            self.analyze_callsites
            and self.caller_func_addr is not None
            and self.callsite_block_addr is not None
            and self.callsite_insn_addr is not None
        ):
            # callsite analysis mode
            self._analyze_callsite_only()
        else:
            raise TypeError(
                'You must specify a function to analyze, or specify "caller_func_addr",'
                ' "callsite_block_addr" and "callsite_insn_addr" to only analyze a call site.'
            )

        if self.prototype is not None:
            self.prototype = self.prototype.with_arch(self.project.arch)

    def _analyze(self):
        """
        The major analysis routine.
        """

        assert self._function is not None

        demangled_name = self._function.demangled_name
        if demangled_name != self._function.name:
            r_demangled = self._analyze_demangled_name(demangled_name)
            if r_demangled is not None:
                self.cc, self.prototype, self.prototype_libname = r_demangled
                return

        if self._function.is_simprocedure:
            hooker = self.project.hooked_by(self._function.addr)
            if isinstance(
                hooker,
                (
                    SIM_PROCEDURES["stubs"]["UnresolvableCallTarget"],
                    SIM_PROCEDURES["stubs"]["UnresolvableJumpTarget"],
                    SIM_PROCEDURES["stubs"]["UserHook"],
                ),
            ):
                return

            if (
                hooker is not None
                and hooker.cc is not None
                and hooker.is_function
                and not hooker.guessed_prototype
                and hooker.prototype is not None
            ):
                # copy the calling convention and prototype from the SimProcedure instance
                self.cc = hooker.cc
                self.prototype = hooker.prototype
                self.prototype_libname = hooker.library_name
                return

            if self._function.prototype is None:
                # try our luck
                # we set ignore_binary_name to True because the binary name SimProcedures is "cle##externs" and does not
                # match any library name
                self._function.find_declaration(ignore_binary_name=True)

            self.cc = self._function.calling_convention
            self.prototype = self._function.prototype
            self.prototype_libname = self._function.prototype_libname

            if self.cc is None or self.prototype is None:
                for include_callsite_preds in [False, True]:
                    callsite_facts = self._extract_and_analyze_callsites(
                        max_analyzing_callsites=1,
                        include_callsite_preds=include_callsite_preds,
                    )
                    cc_cls = default_cc(
                        self.project.arch.name,
                        platform=(
                            self.project.simos.name
                            if self.project is not None and self.project.simos is not None
                            else None
                        ),
                    )
                    cc = cc_cls(self.project.arch) if cc_cls is not None else None
                    prototype = None
                    if callsite_facts:
                        if self.prototype is None:
                            proto = SimTypeFunction([], SimTypeBottom(label="void"))
                        else:
                            proto = self.prototype
                        prototype = self._adjust_prototype(
                            proto,
                            callsite_facts,
                            update_arguments=UpdateArgumentsOption.AlwaysUpdate,
                        )
                        if prototype.args:
                            break
                self.cc = cc  # type: ignore
                self.prototype = prototype  # type: ignore
            return
        if self._function.is_plt:
            r_plt = self._analyze_plt()
            if r_plt is not None:
                self.cc, self.prototype, self.prototype_libname = r_plt
            return

        r = self._analyze_function()
        if r is None:
            l.warning("Cannot determine calling convention for %r.", self._function)
        else:
            # adjust prototype if needed
            cc, prototype = r
            if self.analyze_callsites:
                # only take the first 3 because running reaching definition analysis on all functions is costly
                callsite_facts = self._extract_and_analyze_callsites(max_analyzing_callsites=3)
                prototype = (
                    self._adjust_prototype(
                        prototype, callsite_facts, update_arguments=UpdateArgumentsOption.UpdateWhenCCHasNoArgs
                    )
                    if prototype is not None
                    else None
                )

            self.cc = cc
            self.prototype = prototype

    def _analyze_callsite_only(self):
        assert self.caller_func_addr is not None
        assert self.callsite_block_addr is not None
        assert self.callsite_insn_addr is not None
        cc, prototype = None, None

        for include_callsite_preds in [False, True]:
            fact = self._analyze_callsite(
                self.caller_func_addr,
                self.callsite_block_addr,
                self.callsite_insn_addr,
                include_preds=include_callsite_preds,
            )
            if fact is None:
                continue
            callsite_facts = [fact]
            cc_cls = default_cc(
                self.project.arch.name,
                platform=(
                    self.project.simos.name if self.project is not None and self.project.simos is not None else None
                ),
            )
            cc = cc_cls(self.project.arch) if cc_cls is not None else None
            prototype = SimTypeFunction([], None)
            prototype = self._adjust_prototype(
                prototype, callsite_facts, update_arguments=UpdateArgumentsOption.AlwaysUpdate
            )
            if prototype.args:
                break

        self.cc = cc
        self.prototype = prototype

    def _analyze_plt(self) -> tuple[SimCC, SimTypeFunction | None, str | None] | None:
        """
        Get the calling convention for a PLT stub.

        :return:    A calling convention, the function type, as well as the library name if available.
        """
        assert self._function is not None

        if len(self._function.jumpout_sites) != 1:
            l.warning(
                "%r has more than one jumpout sites. It does not look like a PLT stub. Please report to GitHub.",
                self._function,
            )
            return None

        jo_site = self._function.jumpout_sites[0]

        successors = list(self._function.transition_graph.successors(jo_site))
        if len(successors) != 1:
            l.warning(
                "%r has more than one successors. It does not look like a PLT stub. Please report to GitHub.",
                self._function,
            )
            return None

        try:
            real_func = self.kb.functions.get_by_addr(successors[0].addr)
        except KeyError:
            # the real function does not exist for some reason
            real_func = None

        if real_func is not None:
            if real_func.calling_convention is None:
                cc_cls = default_cc(self.project.arch.name)
                if cc_cls is None:
                    # can't determine the default calling convention for this architecture
                    return None
                cc = cc_cls(self.project.arch)
            else:
                cc = real_func.calling_convention
            if real_func.is_simprocedure:
                if self.project.is_hooked(real_func.addr):
                    # prioritize the hooker
                    hooker = self.project.hooked_by(real_func.addr)
                    if hooker is not None and hooker.is_function and not hooker.guessed_prototype:
                        # we only take the prototype from the SimProcedure if
                        # - the SimProcedure is a function
                        # - the prototype of the SimProcedure is not guessed
                        return cc, hooker.prototype, hooker.library_name
                if real_func.prototype is not None:
                    return cc, real_func.prototype, real_func.prototype_libname
            else:
                return cc, real_func.prototype, real_func.prototype_libname

        if self.analyze_callsites:
            # determine the calling convention by analyzing its callsites
            callsite_facts = self._extract_and_analyze_callsites(max_analyzing_callsites=1)
            cc_cls = default_cc(self.project.arch.name)
            if cc_cls is None:
                # can't determine the default calling convention for this architecture
                return None
            cc = cc_cls(self.project.arch)
            prototype = SimTypeFunction([], None)
            prototype = self._adjust_prototype(
                prototype, callsite_facts, update_arguments=UpdateArgumentsOption.AlwaysUpdate
            )
            return cc, prototype, None

        return None

    def _analyze_demangled_name(self, name: str) -> tuple[SimCC, SimTypeFunction, str | None] | None:
        """
        Analyze a function with a demangled name. Only C++ names are supported for now.

        :param name:    The demangled name of the function.
        :return:        A tuple of the calling convention, the function type, and the library name if available.
        """
        parsed, _ = parse_cpp_file(name)
        if not parsed or len(parsed) != 1:
            return None
        proto = next(iter(parsed.values()))
        if (
            isinstance(proto, SimTypeCppFunction)
            and self.project.simos.name == "Win32"
            and self.project.arch.name == "X86"
            and proto.convention == "__thiscall"
        ):
            cc_cls = SimCCMicrosoftThiscall
        else:
            cc_cls = default_cc(self.project.arch.name, self.project.simos.name)
            assert cc_cls is not None
        cc = cc_cls(self.project.arch)
        return cc, proto, None

    def _analyze_function(self) -> tuple[SimCC, SimTypeFunction] | None:
        """
        Go over the variable information in variable manager for this function, and return all uninitialized
        register/stack variables.
        """
        assert self._function is not None

        if self._function.is_simprocedure or self._function.is_plt:
            # we do not analyze SimProcedures or PLT stubs
            return None

        if self._input_args is None:
            if not self._variable_manager.has_function_manager(self._function.addr):
                l.warning("Please run variable recovery on %r before analyzing its calling convention.", self._function)
                return None
            vm = self._variable_manager[self._function.addr]
            retval_size = vm.ret_val_size
            input_variables = vm.input_variables()
            input_args = self._args_from_vars(input_variables, vm)
        else:
            input_args = set(self._input_args)
            retval_size = self._retval_size

        # check if this function is a variadic function
        if self.project.arch.name == "AMD64":
            is_variadic, fixed_args = self.is_va_start_amd64(self._function)
        else:
            is_variadic = False
            fixed_args = None

        # TODO: properly determine sp_delta
        sp_delta = self.project.arch.bytes if self.project.arch.call_pushes_ret else 0

        full_input_args = self._consolidate_input_args(input_args)
        full_input_args_copy = list(full_input_args)  # input_args might be modified by find_cc()
        cc = SimCC.find_cc(self.project.arch, full_input_args_copy, sp_delta, platform=self.project.simos.name)

        # update input_args according to the difference between full_input_args and full_input_args_copy
        for a in full_input_args:
            if a not in full_input_args_copy and a in input_args:
                input_args.remove(a)

        if cc is None:
            l.warning(
                "_analyze_function(): Cannot find a calling convention for %r that fits the given arguments.",
                self._function,
            )
            return None
        # reorder args
        args = self._reorder_args(input_args, cc)
        if fixed_args is not None:
            args = args[:fixed_args]

        # guess the type of the return value -- it's going to be a wild guess...
        ret_type = self._guess_retval_type(cc, retval_size)
        if self._function.name == "main" and self.project.arch.bits == 64 and isinstance(ret_type, SimTypeLongLong):
            # hack - main must return an int even in 64-bit binaries
            ret_type = SimTypeInt()
        prototype = SimTypeFunction([self._guess_arg_type(arg, cc) for arg in args], ret_type, variadic=is_variadic)

        return cc, prototype

    def _analyze_callsite(
        self,
        caller_addr: int,
        caller_block_addr: int,
        call_insn_addr: int,
        include_preds: bool = False,
    ) -> CallSiteFact | None:
        func = self.kb.functions[caller_addr]
        subgraph = self._generate_callsite_subgraph(func, caller_block_addr, include_preds=include_preds)
        if subgraph is None:
            # failed to generate a subgraph when the caller block cannot be found in the function graph
            return None

        observation_points: list = [("insn", call_insn_addr, OP_BEFORE), ("node", caller_block_addr, OP_AFTER)]

        # find the return site
        caller_block = next(iter(bb for bb in subgraph if bb.addr == caller_block_addr))
        return_site_block = next(iter(subgraph.successors(caller_block)), None)
        if return_site_block is not None:
            observation_points.append(("node", return_site_block.addr, OP_AFTER))

        rda = self.project.analyses[ReachingDefinitionsAnalysis].prep()(
            func,
            func_graph=subgraph,
            observation_points=observation_points,
        )
        # rda_model: Optional[ReachingDefinitionsModel] = self.kb.defs.get_model(caller.addr)
        return self._collect_callsite_fact(caller_block, call_insn_addr, rda.model)

    def _extract_and_analyze_callsites(
        self,
        max_analyzing_callsites: int = 3,
        include_callsite_preds: bool = False,
    ) -> list[CallSiteFact]:  # pylint:disable=no-self-use
        """
        Analyze all call sites of the function and determine the possible number of arguments and if the function
        returns anything or not.
        """

        assert self._function is not None

        if self._cfg is None:
            l.warning("CFG is not provided. Skip calling convention analysis at call sites.")
            return []

        node = self._cfg.get_any_node(self._function.addr)
        if node is None:
            l.warning("%r is not in the CFG. Skip calling convention analysis at call sites.", self._function)

        facts = []
        in_edges = self._cfg.graph.in_edges(node, data=True)

        call_sites_by_function: dict[Function, list[tuple[int, int]]] = defaultdict(list)

        if len(in_edges) == 1:
            src, _, data = next(iter(in_edges))
            if (
                data.get("jumpkind", "Ijk_Call") == "Ijk_Boring"
                and self.kb.functions.contains_addr(src.function_address)
                and self.kb.functions[src.function_address].is_plt
            ):
                # find callers to the PLT stub instead
                in_edges = self._cfg.graph.in_edges(src, data=True)

        for src, _, data in sorted(in_edges, key=lambda x: x[0].addr):
            edge_type = data.get("jumpkind", "Ijk_Call")
            if not (edge_type == "Ijk_Call" or (edge_type == "Ijk_Boring" and self._cfg.graph.out_degree[src] == 1)):
                continue
            if not self.kb.functions.contains_addr(src.function_address):
                continue
            caller = self.kb.functions[src.function_address]
            if caller.is_simprocedure or caller.is_alignment:
                # do not analyze SimProcedures or alignment stubs
                continue
            if src.instruction_addrs:
                call_sites_by_function[caller].append((src.addr, src.instruction_addrs[-1]))

        call_sites_by_function_list = sorted(call_sites_by_function.items(), key=lambda x: x[0].addr)[
            :max_analyzing_callsites
        ]
        ctr = 0

        for caller, call_site_tuples in call_sites_by_function_list:
            if ctr >= max_analyzing_callsites:
                break

            # generate a subgraph that only contains the basic block that does the call and the basic block after the
            # call.
            for call_site_tuple in call_site_tuples:
                caller_block_addr, call_insn_addr = call_site_tuple
                fact = self._analyze_callsite(
                    caller.addr,
                    caller_block_addr,
                    call_insn_addr,
                    include_preds=include_callsite_preds,
                )
                if fact is None:
                    continue
                facts.append(fact)

                ctr += 1
                if ctr >= max_analyzing_callsites:
                    break

        return facts

    def _generate_callsite_subgraph(
        self,
        func: Function,
        callsite_block_addr: int,
        include_preds: bool = False,
    ) -> networkx.DiGraph | None:
        func_graph = self._func_graph if self._func_graph is not None else func.graph

        the_block = next(iter(nn for nn in func_graph if nn.addr == callsite_block_addr), None)
        if the_block is None:
            return None

        subgraph = networkx.DiGraph()
        subgraph.add_node(the_block)

        if include_preds:
            # add a predecessor
            for src, _, data in func_graph.in_edges(the_block, data=True):
                if src is not the_block:
                    subgraph.add_edge(src, the_block, **data)
                    break  # only add the first non-cycle in-edge

        for _, dst, data in func_graph.out_edges(the_block, data=True):
            subgraph.add_edge(the_block, dst, **data)

            # If the target block contains only direct jump statements and has only one successor,
            # include its successor.

            # Re-lift the target block
            dst_block_size = func.get_block_size(dst.addr)
            if dst_block_size is not None and dst_block_size > 0:
                dst_bb = self.project.factory.block(dst.addr, dst_block_size, opt_level=1)
                try:
                    vex_block = dst_bb.vex
                except SimTranslationError:
                    # failed to lift the block
                    continue

                # If there is only one 'IMark' statement in vex --> the target block contains only direct jump
                if (
                    len(vex_block.statements) == 1
                    and vex_block.statements[0].tag == "Ist_IMark"
                    and func.graph.out_degree(dst) == 1
                ):
                    for _, jmp_dst, jmp_data in func_graph.out_edges(dst, data=True):
                        subgraph.add_edge(dst, jmp_dst, **jmp_data)

        return subgraph

    def _collect_callsite_fact(
        self,
        caller_block,
        call_insn_addr: int,
        rda: ReachingDefinitionsModel,
    ) -> CallSiteFact:
        fact = CallSiteFact(
            True,  # by default we treat all return values as used
        )

        default_cc_cls = default_cc(
            self.project.arch.name,
            platform=self.project.simos.name if self.project is not None and self.project.simos is not None else None,
        )
        if default_cc_cls is not None:
            cc: SimCC = default_cc_cls(self.project.arch)
            self._analyze_callsite_return_value_uses(cc, caller_block.addr, rda, fact)
            self._analyze_callsite_arguments(cc, caller_block, call_insn_addr, rda, fact)

        return fact

    def _analyze_callsite_return_value_uses(
        self, cc: SimCC, caller_block_addr: int, rda: ReachingDefinitionsModel, fact: CallSiteFact
    ) -> None:
        all_defs: set[Definition] = {
            def_
            for def_ in rda.all_uses._uses_by_definition
            if (
                (def_.codeloc.block_addr == caller_block_addr and def_.codeloc.stmt_idx == DEFAULT_STATEMENT)
                or any(isinstance(tag, ReturnValueTag) for tag in def_.tags)
            )
        }
        all_uses: Uses = rda.all_uses

        # determine if the return value is used
        return_val = cc.RETURN_VAL
        if return_val is not None and isinstance(return_val, SimRegArg):
            return_reg_offset, _ = self.project.arch.registers[return_val.reg_name]

            # find the def of the return val
            try:
                return_def = next(
                    iter(d for d in all_defs if isinstance(d.atom, Register) and d.atom.reg_offset == return_reg_offset)
                )
            except StopIteration:
                return_def = None
                fact.return_value_used = False

            if return_def is not None:
                # is it used?
                uses = all_uses.get_uses(return_def)
                if uses:
                    # the return value is used!
                    fact.return_value_used = True
                else:
                    fact.return_value_used = False

    def _analyze_callsite_arguments(
        self,
        cc: SimCC,
        caller_block,
        call_insn_addr: int,
        rda: ReachingDefinitionsModel,
        fact: CallSiteFact,
    ) -> None:
        # determine if potential register and stack arguments are set
        observation_key = "insn", call_insn_addr, OP_BEFORE
        state = rda.observed_results.get(observation_key)
        if state is None:
            # the observation state is not found. it can happen if call_insn_addr is incorrect, which may happen (but
            # rarely) on incorrect CFGs.
            return

        defs_by_reg_offset: dict[int, list[Definition]] = defaultdict(list)
        all_reg_defs: set[Definition] = get_all_definitions(state.registers)
        all_stack_defs: set[Definition] = get_all_definitions(state.stack)
        for d in all_reg_defs:
            if (
                isinstance(d.atom, Register)
                and not isinstance(d.codeloc, ExternalCodeLocation)
                and not (d.codeloc.block_addr == caller_block.addr and d.codeloc.stmt_idx == DEFAULT_STATEMENT)
            ):
                # do an extra check because of how entry and callN work on Xtensa
                if isinstance(caller_block, ailment.Block) and self._likely_saving_temp_reg(
                    caller_block, d, all_reg_defs
                ):
                    continue
                defs_by_reg_offset[d.offset].append(d)
        defined_reg_offsets = set(defs_by_reg_offset.keys())
        sp_offset = 0
        if self.project.arch.bits in {32, 64}:
            # Calculate the offsets between sp and stack defs
            sp_offset = state.get_sp_offset()
            if sp_offset is None:
                # We can not find the sp_offset when sp is concrete
                # e.g.,
                # LDR     R2, =0x20070000
                # STR     R1, [R3,#0x38]
                # MOV     SP, R2
                # In this case, just assume sp_offset = 0
                sp_offset = 0
        defs_by_stack_offset = {
            d.atom.addr.offset - sp_offset: d
            for d in all_stack_defs
            if isinstance(d.atom, MemoryLocation) and isinstance(d.atom.addr, SpOffset)
        }

        default_type_cls = SimTypeInt if self.project.arch.bits == 32 else SimTypeLongLong
        arg_session = cc.arg_session(default_type_cls().with_arch(self.project.arch))
        temp_args: list[SimFunctionArgument | None] = []
        expected_args: list[SimFunctionArgument] = []
        for _ in range(30):  # at most 30 arguments
            arg_loc = cc.next_arg(arg_session, default_type_cls().with_arch(self.project.arch))
            expected_args.append(arg_loc)
            if isinstance(arg_loc, SimRegArg):
                reg_offset = self.project.arch.registers[arg_loc.reg_name][0]
                # is it initialized?
                if reg_offset in defined_reg_offsets:
                    temp_args.append(arg_loc)
                else:
                    # no more arguments
                    temp_args.append(None)
            elif isinstance(arg_loc, SimStackArg):
                if arg_loc.stack_offset - cc.STACKARG_SP_DIFF in defs_by_stack_offset:
                    temp_args.append(arg_loc)
                else:
                    # no more arguments
                    break
            else:
                break

        if None in temp_args:
            # we be very conservative here and ignore all arguments starting from the first missing one
            first_none_idx = temp_args.index(None)
            fact.args = temp_args[:first_none_idx]
        else:
            fact.args = temp_args

    def _adjust_prototype(
        self,
        proto: SimTypeFunction,
        facts: list[CallSiteFact],
        update_arguments: int = UpdateArgumentsOption.DoNotUpdate,
    ) -> SimTypeFunction:
        # is the return value used anywhere?
        if facts:
            if all(fact.return_value_used is False for fact in facts):
                proto.returnty = SimTypeBottom(label="void")
            else:
                if proto.returnty is None or isinstance(proto.returnty, SimTypeBottom):
                    proto.returnty = SimTypeInt().with_arch(self.project.arch)

        if (
            update_arguments == UpdateArgumentsOption.AlwaysUpdate
            or (update_arguments == UpdateArgumentsOption.UpdateWhenCCHasNoArgs and not proto.args)
        ) and len({len(fact.args) for fact in facts}) == 1:
            fact = next(iter(facts))
            proto.args = tuple(
                self._guess_arg_type(arg) if arg is not None else SimTypeInt().with_arch(self.project.arch)
                for arg in fact.args
            )

        return proto

    def _args_from_vars(self, variables: list, var_manager):
        """
        Derive function arguments from input variables.

        :param variables:
        :param var_manager: The variable manager of this function.
        :return:
        """

        assert self._function is not None

        args = set()
        ret_addr_offset = 0 if not self.project.arch.call_pushes_ret else self.project.arch.bytes

        reg_vars_with_single_access: list[SimRegisterVariable] = []

        def_cc = default_cc(
            self.project.arch.name,
            platform=self.project.simos.name if self.project is not None and self.project.simos is not None else None,
        )
        for variable in variables:
            if isinstance(variable, SimStackVariable):
                # a stack variable. convert it to a stack argument.
                # TODO: deal with the variable base
                if self.project.arch.call_pushes_ret and variable.offset <= 0:
                    # skip the return address on the stack
                    # TODO: make sure it was the return address
                    continue
                if variable.offset - ret_addr_offset >= 0:
                    arg = SimStackArg(variable.offset - ret_addr_offset, variable.size)
                    args.add(arg)
            elif isinstance(variable, SimRegisterVariable):
                # a register variable, convert it to a register argument
                if not is_sane_register_variable(self.project.arch, variable.reg, variable.size, def_cc=def_cc):
                    continue
                reg_name = self.project.arch.translate_register_name(variable.reg, size=variable.size)
                arg = SimRegArg(reg_name, variable.size)
                args.add(arg)

                accesses = var_manager.get_variable_accesses(variable)
                if len(accesses) == 1:
                    reg_vars_with_single_access.append(variable)
            else:
                l.error("Unsupported type of variable %s.", type(variable))

        # the function might be saving registers at the beginning and restoring them at the end
        # we should remove all registers that are strictly callee-saved and are not used anywhere in this function
        end_blocks = [(endpoint.addr, endpoint.size) for endpoint in self._function.endpoints_with_type["return"]]

        restored_reg_vars: set[SimRegArg] = set()

        # is there any instruction that restores this register in any end blocks?
        if reg_vars_with_single_access:
            if self._function.returning is False:
                # no restoring is required if this function does not return
                for var_ in reg_vars_with_single_access:
                    reg_name = self.project.arch.translate_register_name(var_.reg, size=var_.size)
                    restored_reg_vars.add(SimRegArg(reg_name, var_.size))

            else:
                reg_offsets: set[int] = {r.reg for r in reg_vars_with_single_access}
                for var_ in var_manager.get_variables(sort="reg"):
                    if var_.reg in (reg_offsets - {self.project.arch.ret_offset}):
                        # check if there is only a write to it
                        accesses = var_manager.get_variable_accesses(var_)
                        if len(accesses) == 1 and accesses[0].access_type == VariableAccessSort.WRITE:
                            found = False
                            for end_block_addr, end_block_size in end_blocks:
                                if end_block_addr <= accesses[0].location.ins_addr < end_block_addr + end_block_size:
                                    found = True
                                    break

                            if found:
                                reg_name = self.project.arch.translate_register_name(var_.reg, size=var_.size)
                                restored_reg_vars.add(SimRegArg(reg_name, var_.size))

        return args.difference(restored_reg_vars)

    def _consolidate_input_args(self, input_args: set[SimRegArg | SimStackArg]) -> set[SimRegArg | SimStackArg]:
        """
        Consolidate register arguments by converting partial registers to full registers on certain architectures.

        :param input_args:  A set of input arguments.
        :return:            A set of consolidated input args.
        """

        if self.project.arch.name in {"AMD64", "X86"}:
            new_input_args = set()
            for a in input_args:
                if isinstance(a, SimRegArg) and a.size < self.project.arch.bytes:
                    # use complete registers on AMD64 and X86
                    reg_offset, reg_size = self.project.arch.registers[a.reg_name]
                    full_reg_offset, full_reg_size = get_reg_offset_base_and_size(
                        reg_offset, self.project.arch, size=reg_size
                    )
                    full_reg_name = self.project.arch.translate_register_name(full_reg_offset, size=full_reg_size)
                    arg = SimRegArg(full_reg_name, full_reg_size)
                    if arg not in new_input_args:
                        new_input_args.add(arg)
                else:
                    new_input_args.add(a)
            return new_input_args

        return input_args

    def _reorder_args(self, args: set[SimRegArg | SimStackArg], cc: SimCC) -> list[SimRegArg | SimStackArg]:
        """
        Reorder arguments according to the calling convention identified.

        :param args:   A set of arguments that haven't been ordered.
        :param cc:    The identified calling convention.
        :return:            A reordered list of args.
        """

        def _is_same_reg(rn0: str, rn1: str) -> bool:
            """
            Check if rn0 and rn1 belong to the same base register.

            :param rn0:     Register name of the first register.
            :param rn1:     Register name of the second register.
            :return:        True if they belong to the same base register; False otherwise.
            """
            if rn0 == rn1:
                return True
            off0, sz0 = self.project.arch.registers[rn0]
            full_off0 = get_reg_offset_base(off0, self.project.arch, sz0)
            off1, sz1 = self.project.arch.registers[rn1]
            full_off1 = get_reg_offset_base(off1, self.project.arch, sz1)
            return full_off0 == full_off1

        reg_args = []

        # split args into two lists
        int_args = []
        fp_args = []
        for arg in args:
            if isinstance(arg, SimRegArg):
                if cc.FP_ARG_REGS and arg.reg_name in cc.FP_ARG_REGS:
                    fp_args.append(arg)
                else:
                    int_args.append(arg)

        initial_stack_args = sorted([a for a in args if isinstance(a, SimStackArg)], key=lambda a: a.stack_offset)
        # ensure stack args are consecutive if necessary
        if cc.STACKARG_SP_DIFF is not None and initial_stack_args:
            arg_by_offset = {a.stack_offset: a for a in initial_stack_args}
            init_stackarg_offset = cc.STACKARG_SP_DIFF + cc.STACKARG_SP_BUFF
            int_arg_size = self.project.arch.bytes
            for stackarg_offset in range(init_stackarg_offset, max(arg_by_offset), int_arg_size):
                if stackarg_offset not in arg_by_offset:
                    arg_by_offset[stackarg_offset] = SimStackArg(stackarg_offset, int_arg_size)
            stack_args = [arg_by_offset[offset] for offset in sorted(arg_by_offset)]
        else:
            stack_args = initial_stack_args

        stack_int_args = [a for a in stack_args if not a.is_fp]
        stack_fp_args = [a for a in stack_args if a.is_fp]
        # match int args first
        for reg_name in cc.ARG_REGS:
            try:
                arg = next(iter(a for a in int_args if isinstance(a, SimRegArg) and _is_same_reg(a.reg_name, reg_name)))
            except StopIteration:
                # have we reached the end of the args list?
                if [a for a in int_args if isinstance(a, SimRegArg)] or len(stack_int_args) > 0:
                    # haven't reached the end yet or there are stack args
                    arg = SimRegArg(reg_name, self.project.arch.bytes)
                else:
                    break
            reg_args.append(arg)
            if arg in int_args:
                int_args.remove(arg)

        # match fp args later
        if fp_args:
            for reg_name in cc.FP_ARG_REGS:
                try:
                    arg = next(
                        iter(a for a in fp_args if isinstance(a, SimRegArg) and _is_same_reg(a.reg_name, reg_name))
                    )
                except StopIteration:
                    # have we reached the end of the args list?
                    if [a for a in fp_args if isinstance(a, SimRegArg)] or len(stack_fp_args) > 0:
                        # haven't reached the end yet or there are stack args
                        arg = SimRegArg(reg_name, self.project.arch.bytes)
                    else:
                        break
                reg_args.append(arg)
                if arg in fp_args:
                    fp_args.remove(arg)

        return reg_args + int_args + fp_args + stack_args

    def _guess_arg_type(self, arg: SimFunctionArgument, cc: SimCC | None = None) -> SimType:
        if cc is not None and cc.FP_ARG_REGS and isinstance(arg, SimRegArg) and arg.reg_name in cc.FP_ARG_REGS:
            if arg.size == 4:
                return SimTypeFloat()
            if arg.size == 8:
                return SimTypeDouble()

        if arg.size == 4:
            return SimTypeInt()
        if arg.size == 8:
            return SimTypeLongLong()
        if arg.size == 2:
            return SimTypeShort()
        if arg.size == 1:
            return SimTypeChar()
        # Unsupported for now
        return SimTypeBottom()

    def _guess_retval_type(self, cc: SimCC, ret_val_size: int | None) -> SimType:
        assert self._function is not None

        if cc.FP_RETURN_VAL and self._function.ret_sites:
            # examine the last block of the function and see which registers are assigned to
            for ret_block in self._function.ret_sites:
                fpretval_updated, retval_updated = False, False
                fp_reg_size = 0
                irsb = self.project.factory.block(ret_block.addr, size=ret_block.size).vex
                for stmt in irsb.statements:
                    if isinstance(stmt, Put) and isinstance(stmt.data, RdTmp):
                        reg_size = irsb.tyenv.sizeof(stmt.data.tmp) // self.project.arch.byte_width  # type: ignore
                        reg_name = self.project.arch.translate_register_name(stmt.offset, size=reg_size)
                        if isinstance(cc.FP_RETURN_VAL, SimRegArg) and reg_name == cc.FP_RETURN_VAL.reg_name:
                            fpretval_updated = True
                            fp_reg_size = reg_size
                        elif isinstance(cc.RETURN_VAL, SimRegArg) and reg_name == cc.RETURN_VAL.reg_name:
                            retval_updated = True

                if fpretval_updated and not retval_updated:
                    # possibly float
                    return SimTypeFloat() if fp_reg_size == 4 else SimTypeDouble()

        if ret_val_size is not None:
            if ret_val_size == 1:
                return SimTypeChar()
            if ret_val_size == 2:
                return SimTypeShort()
            if 3 <= ret_val_size <= 4:
                return SimTypeInt()
            if 5 <= ret_val_size <= 8:
                return SimTypeLongLong()

        return SimTypeBottom(label="void")

    @staticmethod
    def _likely_saving_temp_reg(ail_block: ailment.Block, d: Definition, all_reg_defs: set[Definition]) -> bool:
        if (
            d.codeloc.block_addr == ail_block.addr
            and d.codeloc.stmt_idx is not None
            and d.codeloc.stmt_idx < len(ail_block.statements)
        ):
            stmt = ail_block.statements[d.codeloc.stmt_idx]
            if isinstance(stmt, ailment.Stmt.Assignment) and isinstance(stmt.src, ailment.Expr.Register):
                src_offset = stmt.src.reg_offset
                src_reg_def = next(
                    iter(
                        d_ for d_ in all_reg_defs if isinstance(d_.atom, Register) and d_.atom.reg_offset == src_offset
                    ),
                    None,
                )
                if src_reg_def is not None and isinstance(src_reg_def.codeloc, ExternalCodeLocation):
                    return True
        return False

    def is_va_start_amd64(self, func: Function) -> tuple[bool, int | None]:
        # TODO: Use a better pattern matching approach
        if len(func.block_addrs_set) < 3:
            return False, None
        if func.startpoint is None:
            return False, None

        head = func.startpoint
        out_edges = list(func.transition_graph.out_edges(head, data=True))
        if len(out_edges) != 2:
            return False, None
        succ0, succ1 = out_edges[0][1], out_edges[1][1]
        if func.transition_graph.has_edge(succ0, succ1):
            mid = succ0
        elif func.transition_graph.has_edge(succ1, succ0):
            mid = succ1
        else:
            return False, None

        # compare instructions
        for insn in self.project.factory.block(mid.addr, size=mid.size).capstone.insns:
            if insn.mnemonic != "movaps":
                return False, None

        spilled_regs = []
        allowed_spilled_regs = [
            capstone.x86.X86_REG_RDI,
            capstone.x86.X86_REG_RSI,
            capstone.x86.X86_REG_RDX,
            capstone.x86.X86_REG_RCX,
            capstone.x86.X86_REG_R8,
            capstone.x86.X86_REG_R9,
        ]
        for insn in reversed(self.project.factory.block(head.addr, size=head.size).capstone.insns[:-2]):
            if (
                insn.mnemonic == "mov"
                and insn.operands[0].type == capstone.x86.X86_OP_MEM
                and insn.operands[1].type == capstone.x86.X86_OP_REG
            ):
                spilled_regs.append(insn.operands[1].reg)
            else:
                break

        if not set(spilled_regs).issubset(set(allowed_spilled_regs)):
            return False, None

        i = next(
            (i for i, reg in enumerate(allowed_spilled_regs) if reg in spilled_regs),
            len(allowed_spilled_regs),
        )

        return True, i


register_analysis(CallingConventionAnalysis, "CallingConvention")
