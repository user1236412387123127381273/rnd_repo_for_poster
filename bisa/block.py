# pylint:disable=wrong-import-position,arguments-differ
from __future__ import annotations
import logging
from typing import TYPE_CHECKING

import pyvex
from pyvex import IRSB
from archinfo import Arch, ArchARM

from .protos import primitives_pb2 as pb2
from .serializable import Serializable

try:
    from .engines import pcode
except ImportError:
    pcode = None

if TYPE_CHECKING:
    from bisa import Project
    from bisa.engines.vex import VEXLifter
    from bisa.engines.pcode.lifter import PcodeLifterEngineMixin, IRSB as PcodeIRSB
    from bisa.engines.soot.engine import SootMixin


l = logging.getLogger(name=__name__)


class DisassemblerBlock:
    """
    Helper class to represent a block of disassembled target architecture
    instructions
    """

    __slots__ = ["addr", "arch", "insns", "thumb"]

    def __init__(self, addr, insns, thumb, arch):
        self.addr = addr
        self.insns = insns
        self.thumb = thumb
        self.arch = arch

    def pp(self):
        print(str(self))

    def __str__(self):
        return "\n".join(str(x) for x in self.insns)

    def __repr__(self):
        return f"<DisassemblerBlock for {self.addr:#x}>"


class DisassemblerInsn:
    """
    Helper class to represent a disassembled target architecture instruction
    """

    __slots__ = ()

    @property
    def size(self) -> int:
        raise NotImplementedError

    @property
    def address(self) -> int:
        raise NotImplementedError

    @property
    def mnemonic(self) -> str:
        raise NotImplementedError

    @property
    def op_str(self) -> str:
        raise NotImplementedError

    def __str__(self):
        return f"{self.address:#x}:\t{self.mnemonic}\t{self.op_str}"

    def __repr__(self):
        return f'<DisassemblerInsn "{self.mnemonic}" for {self.address:#x}>'


class CapstoneBlock(DisassemblerBlock):
    """
    Deep copy of the capstone blocks, which have serious issues with having extended lifespans
    outside of capstone itself
    """

    __slots__ = ()


class CapstoneInsn(DisassemblerInsn):
    """
    Represents a capstone instruction.
    """

    __slots__ = ("insn",)

    def __init__(self, capstone_insn):
        self.insn = capstone_insn

    @property
    def size(self) -> int:
        return self.insn.size

    @property
    def address(self) -> int:
        return self.insn.address

    @property
    def mnemonic(self) -> str:
        return self.insn.mnemonic

    @property
    def op_str(self) -> str:
        return self.insn.op_str

    def __getattr__(self, item):
        if item in ("__str__", "__repr__"):
            return self.__getattribute__(item)
        if hasattr(self.insn, item):
            return getattr(self.insn, item)
        raise AttributeError


class Block(Serializable):
    """
    Represents a basic block in a binary or a program.
    """

    BLOCK_MAX_SIZE = 4096

    __slots__ = [
        "_backup_state",
        "_bytes",
        "_capstone",
        "_collect_data_refs",
        "_const_prop",
        "_cross_insn_opt",
        "_disassembly",
        "_extra_stop_points",
        "_initial_regs",
        "_instruction_addrs",
        "_instructions",
        "_load_from_ro_regions",
        "_max_size",
        "_opt_level",
        "_project",
        "_strict_block_end",
        "_traceflags",
        "_vex",
        "_vex_nostmt",
        "addr",
        "arch",
        "size",
        "thumb",
    ]

    def __init__(
        self,
        addr,
        project=None,
        arch: Arch | None = None,
        size=None,
        max_size=None,
        byte_string=None,
        thumb=False,
        backup_state=None,
        extra_stop_points=None,
        opt_level=None,
        num_inst=None,
        traceflags=0,
        strict_block_end=None,
        collect_data_refs=False,
        cross_insn_opt=True,
        load_from_ro_regions=False,
        const_prop=False,
        initial_regs=None,
        skip_stmts=False,
    ):
        if arch is not None:
            self.arch = arch
        elif project is not None:
            self.arch = project.arch
        else:
            raise ValueError('Either "project" or "arch" has to be specified.')

        if project is not None and backup_state is None and project.kb.patches.values():
            backup_state = project.kb.patches.patched_entry_state

        if isinstance(self.arch, ArchARM):
            if addr & 1 == 1:
                thumb = True
            elif thumb:
                addr |= 1
        else:
            thumb = False

        self._project = project
        self.addr = addr
        self._backup_state = backup_state
        self.thumb = thumb
        self._opt_level = opt_level
        self._initial_regs = initial_regs if (collect_data_refs or const_prop) else None
        self._traceflags = traceflags
        self._extra_stop_points = extra_stop_points
        self._max_size = max_size if max_size is not None else self.BLOCK_MAX_SIZE

        if self._project is None and byte_string is None:
            raise ValueError('"byte_string" has to be specified if "project" is not provided.')

        self._vex = None
        self._vex_nostmt = None
        self._disassembly = None
        self._capstone = None
        self._collect_data_refs = collect_data_refs
        self._strict_block_end = strict_block_end
        self._cross_insn_opt = cross_insn_opt
        self._load_from_ro_regions = load_from_ro_regions
        self._const_prop = const_prop

        self._instructions: int | None = num_inst
        self._instruction_addrs: list[int] = []

        self._bytes = byte_string
        self.size = size

        if size is None:
            if byte_string is not None:
                size = len(byte_string)
            else:
                vex = self._lift_nocache(skip_stmts)
                size = vex.size

                if skip_stmts:
                    self._vex_nostmt = vex
                else:
                    self._vex = vex

        self.size = size

        if skip_stmts:
            self._parse_vex_info(self._vex_nostmt)
        else:
            self._parse_vex_info(self._vex)

        if byte_string is None:
            if backup_state is not None:
                buffer, _, offset = self._vex_engine._load_bytes(addr - thumb, size, state=backup_state)
                self._bytes = buffer[offset:]
                if type(self._bytes) is memoryview:
                    self._bytes = bytes(self._bytes)
                elif type(self._bytes) is not bytes:
                    self._bytes = bytes(pyvex.ffi.buffer(self._bytes, size))  # type:ignore
            else:
                self._bytes = None
        elif type(byte_string) is bytes:
            if self.size is not None:
                self._bytes = byte_string[: self.size]
            else:
                self._bytes = byte_string
        else:
            # Convert bytestring to a str
            # size will ALWAYS be known at this point
            self._bytes = bytes(pyvex.ffi.buffer(byte_string, self.size))  # type:ignore

    def _parse_vex_info(self, vex_block):
        if vex_block is not None:
            self._instructions = vex_block.instructions
            self._instruction_addrs = vex_block.instruction_addresses
            self.size = vex_block.size

    def __repr__(self):
        return f"<Block for {self.addr:#x}, {self.size} bytes>"

    def __getstate__(self):
        return {k: getattr(self, k) for k in self.__slots__ if k not in {"_capstone", "_disassembly", "_project"}}

    def __setstate__(self, data):
        for k, v in data.items():
            setattr(self, k, v)
        self._capstone = None
        self._disassembly = None
        self._project = None

    def __hash__(self):
        return hash((type(self), self.addr, self.bytes))

    def __eq__(self, other):
        return type(self) is type(other) and self.addr == other.addr and self.bytes == other.bytes

    def __ne__(self, other):
        return not self == other

    def pp(self, **kwargs):
        if self._project is not None:
            addr = self.addr - 1 if self.thumb else self.addr
            print(
                self._project.analyses.Disassembly(
                    ranges=[(addr, addr + self.size)],
                    thumb=self.thumb,
                    block_bytes=self.bytes,
                ).render(**kwargs)
            )
        else:
            self.disassembly.pp()

    def set_initial_regs(self):
        # for data reference collection, on some architectures, we need to set up initial registers
        if self._initial_regs is not None:
            for offset, size, value in self._initial_regs:  # pylint:disable=not-an-iterable
                pyvex.pvc.register_initial_register_value(offset, size, value)

    @staticmethod
    def reset_initial_regs():
        pyvex.pvc.reset_initial_register_values()

    @property
    def _vex_engine(self) -> VEXLifter | PcodeLifterEngineMixin:
        if self._project is None:
            raise ValueError("Project is not set")
        return self._project.factory.default_engine  # type:ignore

    def _lift_nocache(self, skip_stmts: bool) -> IRSB | PcodeIRSB:
        clemory = None
        if self._project is not None:
            clemory = (
                self._project.loader.memory_ro_view
                if self._project.loader.memory_ro_view is not None
                else self._project.loader.memory
            )

        if self._initial_regs:
            self.set_initial_regs()

        vex = self._vex_engine.lift_vex(
            addr=self.addr,
            state=self._backup_state,
            clemory=clemory,
            insn_bytes=self._bytes,
            arch=self.arch,
            size=self.size,
            num_inst=self._instructions,
            traceflags=self._traceflags,
            thumb=self.thumb,
            extra_stop_points=self._extra_stop_points,
            opt_level=self._opt_level,
            strict_block_end=self._strict_block_end,
            skip_stmts=skip_stmts,
            collect_data_refs=self._collect_data_refs,
            cross_insn_opt=self._cross_insn_opt,
            load_from_ro_regions=self._load_from_ro_regions,
            const_prop=self._const_prop,
        )

        if self._initial_regs:
            self.reset_initial_regs()

        return vex

    @property
    def vex(self) -> IRSB | PcodeIRSB:
        if not self._vex:
            self._vex = self._lift_nocache(False)
            self._parse_vex_info(self._vex)

        return self._vex

    @property
    def vex_nostmt(self):
        if self._vex_nostmt:
            return self._vex_nostmt
        if self._vex:
            return self._vex

        self._vex_nostmt = self._lift_nocache(True)
        self._parse_vex_info(self._vex_nostmt)

        return self._vex_nostmt

    @property
    def _using_pcode_engine(self) -> bool:
        return (pcode is not None) and isinstance(self._vex_engine, pcode.HeavyPcodeMixin)

    @property
    def disassembly(self) -> DisassemblerBlock:
        """
        Provide a disassembly object using whatever disassembler is available
        """
        if self._disassembly is None:
            if self._using_pcode_engine:
                self._disassembly = self.vex.disassembly  # type:ignore
            else:
                self._disassembly = self.capstone
        return self._disassembly

    @property
    def capstone(self) -> CapstoneBlock:
        if self._capstone:
            return self._capstone

        cs = self.arch.capstone if not self.thumb else self.arch.capstone_thumb  # type:ignore

        insns = []

        block_bytes = self.bytes
        if self.size is not None:
            block_bytes = block_bytes[: self.size]
        for cs_insn in cs.disasm(block_bytes, self.addr):
            insns.append(CapstoneInsn(cs_insn))
        block = CapstoneBlock(self.addr, insns, self.thumb, self.arch)

        self._capstone = block
        return block

    @property
    def codenode(self):
        return BlockNode(self.addr, self.size, bytestr=self.bytes, thumb=self.thumb)

    @property
    def bytes(self) -> bytes | None:
        if self._bytes is None:
            addr = self.addr
            if self.thumb:
                addr = (addr >> 1) << 1
            if self._project is not None:
                mem = (
                    self._project.loader.memory_ro_view
                    if self._project.loader.memory_ro_view is not None
                    else self._project.loader.memory
                )
                self._bytes = mem.load(addr, self.size)
        return self._bytes

    @property
    def instructions(self) -> int:
        if not self._instructions and self._vex is None and self._vex_nostmt is None:
            # initialize from VEX, but we do not need statements to know instructions
            _ = self.vex_nostmt

        assert self._instructions is not None
        return self._instructions

    @property
    def instruction_addrs(self):
        if self.size == 0:
            # hooks and other pseudo-functions
            return []

        if not self._instruction_addrs and self._vex is None and self._vex_nostmt is None:
            # initialize instruction addrs, but we do not need statements
            _ = self.vex_nostmt

        return self._instruction_addrs

    @classmethod
    def _get_cmsg(cls):
        return pb2.Block()  # pylint: disable=no-member

    def serialize_to_cmessage(self):
        obj = self._get_cmsg()
        obj.ea = self.addr
        obj.size = self.size
        obj.bytes = self.bytes

        return obj

    @classmethod
    def parse_from_cmessage(cls, cmsg):
        return cls(
            cmsg.ea,
            size=cmsg.size,
            byte_string=cmsg.bytes,
        )


class SootBlock:
    """
    Represents a Soot IR basic block.
    """

    def __init__(self, addr, *, project: Project, arch: Arch):
        self.addr = addr
        self.arch = arch
        self._project = project
        self._the_binary = project.loader.main_object

    @property
    def _soot_engine(self) -> SootMixin:
        if self._project is None:
            assert False, "This should be unreachable"
        return self._project.factory.default_engine  # type:ignore

    @property
    def soot(self):
        return self._soot_engine.lift_soot(self.addr, the_binary=self._the_binary)

    @property
    def size(self):
        stmts = None if self.soot is None else self.soot.statements
        return len(stmts) if stmts else 0

    @property
    def codenode(self):
        stmts = None if self.soot is None else self.soot.statements
        stmts_len = len(stmts) if stmts else 0
        return SootBlockNode(self.addr, stmts_len, stmts=stmts)


from .codenode import BlockNode, SootBlockNode
