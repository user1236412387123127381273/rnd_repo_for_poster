from __future__ import annotations
import claripy
import logging

from bisa.procedures.java import JavaSimProcedure

log = logging.getLogger(name=__name__)


class CharacterIsDigit(JavaSimProcedure):
    __provides__ = (("java.lang.Character", "isDigit(char)"),)

    def run(self, char_ref):
        log.debug(f"Called SimProcedure java.lang.Character.isDigit with args: {char_ref}")
        char_str = self.state.memory.load(char_ref)

        constraint = claripy.StrIsDigit(char_str)

        return claripy.If(constraint, claripy.BVV(1, 32), claripy.BVV(0, 32))


class CharacterIsSpaceChar(JavaSimProcedure):
    __provides__ = (("java.lang.Character", "isSpaceChar(char)"),)

    def run(self, char_ref):
        log.debug(f"Called SimProcedure java.lang.Character.isSpaceChar with args: {char_ref}")
        char_str = self.state.memory.load(char_ref)

        # Should we add other unicode SPACE_SEPARATOR?
        return claripy.If(char_str == " ", claripy.BVV(1, 32), claripy.BVV(0, 32))
