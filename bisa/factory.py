from __future__ import annotations

import logging
import threading
from typing import overload, TYPE_CHECKING

import archinfo
from archinfo.arch_soot import ArchSoot, SootAddressDescriptor

from .knowledge_plugins.functions import Function
from .sim_state import SimState
from .calling_conventions import default_cc, SimRegArg, SimStackArg, PointerWrapper, SimCCUnknown
from .callable import Callable
from .errors import BISAError
from .engines import UberEngine, ProcedureEngine
from .sim_type import SimTypeFunction, SimTypeInt
from .codenode import HookNode, SyscallNode
from .block import Block, SootBlock
from .sim_manager import SimulationManager

try:
    from .engines import UberEnginePcode
    from .engines.pcode import register_pcode_arch_default_cc
except ImportError:
    UberEnginePcode = None

if TYPE_CHECKING:
    from bisa import Project, SimCC
    from bisa.engines import SimEngine


l = logging.getLogger(name=__name__)


class BISAObjectFactory:
    """
    This factory provides access to important analysis elements.
    """

    project: Project
    default_engine_factory: type[SimEngine]
    procedure_engine: ProcedureEngine
    _default_cc: type[SimCC] | None

    # We use thread local storage to cache engines on a per-thread basis
    _tls: threading.local

    def __init__(self, project, default_engine: type[SimEngine] | None = None):
        self._tls = threading.local()

        if default_engine is None:
            if isinstance(project.arch, archinfo.ArchPcode) and UberEnginePcode is not None:
                l.warning("Creating project with the experimental 'UberEnginePcode' engine")
                self.default_engine_factory = UberEnginePcode
            else:
                self.default_engine_factory = UberEngine
        else:
            self.default_engine_factory = default_engine

        if isinstance(project.arch, archinfo.ArchPcode):
            register_pcode_arch_default_cc(project.arch)

        self.project = project
        self._default_cc = default_cc(
            project.arch.name, platform=project.simos.name if project.simos is not None else None, default=SimCCUnknown
        )
        self.procedure_engine = ProcedureEngine(project)

    def __getstate__(self):
        return self.project, self.default_engine_factory, self.procedure_engine, self._default_cc

    def __setstate__(self, state):
        self.project, self.default_engine_factory, self.procedure_engine, self._default_cc = state
        self._tls = threading.local()

    @property
    def default_engine(self):
        if not hasattr(self._tls, "default_engine"):
            self._tls.default_engine = self.default_engine_factory(self.project)
        return self._tls.default_engine

    def snippet(self, addr, jumpkind=None, **block_opts):
        if self.project.is_hooked(addr) and jumpkind != "Ijk_NoHook":
            hook = self.project._sim_procedures[addr]
            size = hook.kwargs.get("length", 0)
            return HookNode(addr, size, self.project.hooked_by(addr))
        if self.project.simos.is_syscall_addr(addr):
            syscall = self.project.simos.syscall_from_addr(addr)
            size = syscall.kwargs.get("length", 0)
            return SyscallNode(addr, size, syscall)
        return self.block(addr, **block_opts).codenode  # pylint: disable=no-member

    def successors(self, *args, engine=None, **kwargs):
        """
        Perform execution using an engine. Generally, return a SimSuccessors object classifying the results of the run.

        :param state:           The state to analyze
        :param engine:          The engine to use. If not provided, will use the project default.
        :param addr:            optional, an address to execute at instead of the state's ip
        :param jumpkind:        optional, the jumpkind of the previous exit
        :param inline:          This is an inline execution. Do not bother copying the state.

        Additional keyword arguments will be passed directly into each engine's process method.
        """
        if engine is not None:
            return engine.process(*args, **kwargs)
        return self.default_engine.process(*args, **kwargs)

    def blank_state(self, **kwargs):
        """
        Returns a mostly-uninitialized state object. All parameters are optional.

        :param addr:            The address the state should start at instead of the entry point.
        :param initial_prefix:  If this is provided, all symbolic registers will hold symbolic values with names
                                prefixed by this string.
        :param fs:              A dictionary of file names with associated preset SimFile objects.
        :param concrete_fs:     bool describing whether the host filesystem should be consulted when opening files.
        :param chroot:          A path to use as a fake root directory, Behaves similarly to a real chroot. Used only
                                when concrete_fs is set to True.
        :param kwargs:          Any additional keyword args will be passed to the SimState constructor.
        :return:                The blank state.
        :rtype:                 SimState
        """
        return self.project.simos.state_blank(**kwargs)

    def entry_state(self, **kwargs) -> SimState:
        """
        Returns a state object representing the program at its entry point. All parameters are optional.

        :param addr:            The address the state should start at instead of the entry point.
        :param initial_prefix:  If this is provided, all symbolic registers will hold symbolic values with names
                                prefixed by this string.
        :param fs:              a dictionary of file names with associated preset SimFile objects.
        :param concrete_fs:     boolean describing whether the host filesystem should be consulted when opening files.
        :param chroot:          a path to use as a fake root directory, behaves similar to a real chroot. used only when
                                concrete_fs is set to True.
        :param argc:            a custom value to use for the program's argc. May be either an int or a bitvector. If
                                not provided, defaults to the length of args.
        :param args:            a list of values to use as the program's argv. May be mixed strings and bitvectors.
        :param env:             a dictionary to use as the environment for the program. Both keys and values may be
                                mixed strings and bitvectors.
        :return:                The entry state.
        :rtype:                 SimState
        """

        return self.project.simos.state_entry(**kwargs)

    def full_init_state(self, **kwargs):
        """
        Very much like :meth:`entry_state()`, except that instead of starting execution at the program entry point,
        execution begins at a special SimProcedure that plays the role of the dynamic loader, calling each of the
        initializer functions that should be called before execution reaches the entry point.

        It can take any of the arguments that can be provided to ``entry_state``, except for ``addr``.
        """
        return self.project.simos.state_full_init(**kwargs)

    def call_state(self, addr, *args, **kwargs):
        """
        Returns a state object initialized to the start of a given function, as if it were called with given parameters.

        :param addr:            The address the state should start at instead of the entry point.
        :param args:            Any additional positional arguments will be used as arguments to the function call.

        The following parameters are optional.

        :param base_state:      Use this SimState as the base for the new state instead of a blank state.
        :param cc:              Optionally provide a SimCC object to use a specific calling convention.
        :param ret_addr:        Use this address as the function's return target.
        :param stack_base:      An optional pointer to use as the top of the stack, circa the function entry point
        :param alloc_base:      An optional pointer to use as the place to put excess argument data
        :param grow_like_stack: When allocating data at alloc_base, whether to allocate at decreasing addresses
        :param toc:             The address of the table of contents for ppc64
        :param initial_prefix:  If this is provided, all symbolic registers will hold symbolic values with names
                                prefixed by this string.
        :param fs:              A dictionary of file names with associated preset SimFile objects.
        :param concrete_fs:     bool describing whether the host filesystem should be consulted when opening files.
        :param chroot:          A path to use as a fake root directory, Behaves similarly to a real chroot. Used only
                                when concrete_fs is set to True.
        :param kwargs:          Any additional keyword args will be passed to the SimState constructor.
        :return:                The state at the beginning of the function.
        :rtype:                 SimState

        The idea here is that you can provide almost any kind of python type in `args` and it'll be translated to a
        binary format to be placed into simulated memory. Lists (representing arrays) must be entirely elements of the
        same type and size, while tuples (representing structs) can be elements of any type and size.
        If you'd like there to be a pointer to a given value, wrap the value in a `SimCC.PointerWrapper`. Any value
        that can't fit in a register will be automatically put in a
        PointerWrapper.

        If stack_base is not provided, the current stack pointer will be used, and it will be updated.
        If alloc_base is not provided, the current stack pointer will be used, and it will be updated.
        You might not like the results if you provide stack_base but not alloc_base.

        grow_like_stack controls the behavior of allocating data at alloc_base. When data from args needs to be wrapped
        in a pointer, the pointer needs to point somewhere, so that data is dumped into memory at alloc_base. If you
        set alloc_base to point to somewhere other than the stack, set grow_like_stack to False so that sequential
        allocations happen at increasing addresses.
        """
        return self.project.simos.state_call(addr, *args, **kwargs)

    def simulation_manager(self, thing: list[SimState] | SimState | None = None, **kwargs) -> SimulationManager:
        """
        Constructs a new simulation manager.

        :param thing:           What to put in the new SimulationManager's active stash (either a SimState or a list of
                                SimStates).
        :param kwargs:          Any additional keyword arguments will be passed to the SimulationManager constructor
        :returns:               The new SimulationManager
        :rtype:                 bisa.sim_manager.SimulationManager

        Many different types can be passed to this method:

        * If nothing is passed in, the SimulationManager is seeded with a state initialized for the program
          entry point, i.e. :meth:`entry_state()`.
        * If a :class:`SimState` is passed in, the SimulationManager is seeded with that state.
        * If a list is passed in, the list must contain only SimStates and the whole list will be used to seed the
          SimulationManager.
        """
        if thing is None:
            thing = [self.entry_state()]
        elif isinstance(thing, (list, tuple)):
            if any(not isinstance(val, SimState) for val in thing):
                raise BISAError("Bad type to initialize SimulationManager")
        elif isinstance(thing, SimState):
            thing = [thing]
        else:
            raise BISAError(f"BadType to initialize SimulationManager: {thing!r}")

        return SimulationManager(self.project, active_states=thing, **kwargs)

    def simgr(self, *args, **kwargs):
        """
        Alias for `simulation_manager` to save our poor fingers
        """
        return self.simulation_manager(*args, **kwargs)

    def callable(
        self,
        addr: int | Function,
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
        A Callable is a representation of a function in the binary that can be interacted with like a native python
        function.

        :param addr:            The address of the function to use. If you pass in the function object, we will take
                                its addr.
        :param prototype:       The prototype of the call to use, as a string or a SimTypeFunction
        :param concrete_only:   Throw an exception if the execution splits into multiple states
        :param perform_merge:   Merge all result states into one at the end (only relevant if concrete_only=False)
        :param base_state:      The state from which to do these runs
        :param toc:             The address of the table of contents for ppc64
        :param cc:              The SimCC to use for a calling convention
        :param step_limit:      The maximum number of blocks that Callable will execute before pruning the path.
        :returns:               A Callable object that can be used as a interface for executing guest code like a
                                python function.
        :rtype:                 bisa.callable.Callable
        """
        if isinstance(addr, Function):
            addr = addr.addr

        return Callable(
            self.project,
            addr=addr,
            prototype=prototype,
            concrete_only=concrete_only,
            perform_merge=perform_merge,
            base_state=base_state,
            toc=toc,
            cc=cc,
            add_options=add_options,
            remove_options=remove_options,
            step_limit=step_limit,
        )

    def cc(self):
        """
        Return a SimCC (calling convention) parameterized for this project.

        Relevant subclasses of SimFunctionArgument are SimRegArg and SimStackArg, and shortcuts to them can be found on
        this `cc` object.

        For stack arguments, offsets are relative to the stack pointer on function entry.
        """

        return self._default_cc(arch=self.project.arch)

    def function_prototype(self):
        """
        Return a default function prototype parameterized for this project and SimOS.
        """
        return SimTypeFunction((), SimTypeInt()).with_arch(self.project.arch)

    # pylint: disable=unused-argument, no-self-use, function-redefined
    @overload
    def block(
        self,
        addr: int,
        size=None,
        max_size=None,
        byte_string=None,
        thumb=False,
        backup_state=None,
        extra_stop_points=None,
        opt_level=None,
        num_inst=None,
        traceflags=0,
        insn_bytes=None,
        strict_block_end=None,
        collect_data_refs=False,
        cross_insn_opt=True,
        load_from_ro_regions=False,
        const_prop=False,
        initial_regs=None,
        skip_stmts=False,
    ) -> Block: ...

    # pylint: disable=unused-argument, no-self-use, function-redefined
    @overload
    def block(
        self,
        addr: SootAddressDescriptor,
        size=None,
        max_size=None,
        byte_string=None,
        thumb=False,
        backup_state=None,
        extra_stop_points=None,
        opt_level=None,
        num_inst=None,
        traceflags=0,
        insn_bytes=None,
        strict_block_end=None,
        collect_data_refs=False,
        load_from_ro_regions=False,
        const_prop=False,
        cross_insn_opt=True,
        skip_stmts=False,
    ) -> SootBlock: ...

    def block(
        self,
        addr,
        size=None,
        max_size=None,
        byte_string=None,
        thumb=False,
        backup_state=None,
        extra_stop_points=None,
        opt_level=None,
        num_inst=None,
        traceflags=0,
        insn_bytes=None,
        strict_block_end=None,
        collect_data_refs=False,
        cross_insn_opt=True,
        load_from_ro_regions=False,
        const_prop=False,
        initial_regs=None,
        skip_stmts=False,
    ):
        if isinstance(self.project.arch, ArchSoot) and isinstance(addr, SootAddressDescriptor):
            return SootBlock(addr, arch=self.project.arch, project=self.project)

        if insn_bytes is not None:
            byte_string = insn_bytes

        return Block(
            addr,
            project=self.project,
            size=size,
            max_size=max_size,
            byte_string=byte_string,
            extra_stop_points=extra_stop_points,
            thumb=thumb,
            backup_state=backup_state,
            opt_level=opt_level,
            num_inst=num_inst,
            traceflags=traceflags,
            strict_block_end=strict_block_end,
            collect_data_refs=collect_data_refs,
            cross_insn_opt=cross_insn_opt,
            load_from_ro_regions=load_from_ro_regions,
            const_prop=const_prop,
            initial_regs=initial_regs,
            skip_stmts=skip_stmts,
        )

    def fresh_block(self, addr, size, backup_state=None):
        return Block(addr, project=self.project, size=size, backup_state=backup_state)

    cc.SimRegArg = SimRegArg
    cc.SimStackArg = SimStackArg
    callable.PointerWrapper = PointerWrapper
    call_state.PointerWrapper = PointerWrapper
