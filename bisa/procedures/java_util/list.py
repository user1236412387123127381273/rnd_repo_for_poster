from __future__ import annotations
import claripy
import logging

from bisa.procedures.java import JavaSimProcedure
from bisa.engines.soot.expressions import SimSootExpr_NewArray
from bisa.engines.soot.values import SimSootValue_ThisRef
from .collection import ELEMS, SIZE

log = logging.getLogger(name=__name__)


class ListInit(JavaSimProcedure):
    __provides__ = (("java.util.List", "<init>()"), ("java.util.LinkedList", "<init>()"))

    def run(self, this_ref):
        log.debug(f"Called SimProcedure java.util.List.<init> with args: {this_ref}")

        array_ref = SimSootExpr_NewArray.new_array(self.state, "java.lang.Object", claripy.BVV(1000, 32))
        this_ref.store_field(self.state, ELEMS, "java.lang.Object[]", array_ref)
        this_ref.store_field(self.state, SIZE, "int", claripy.BVV(0, 32))

        return


class ListAdd(JavaSimProcedure):
    __provides__ = (("java.util.List", "add(java.lang.Object)"), ("java.util.LinkedList", "add(java.lang.Object)"))

    def run(self, this_ref, obj_ref):
        log.debug(f"Called SimProcedure java.util.List.add with args: {this_ref} {obj_ref}")

        if this_ref.symbolic:
            return claripy.BoolS("list.append")

        try:
            array_ref = this_ref.load_field(self.state, ELEMS, "java.lang.Object[]")
            array_len = this_ref.load_field(self.state, SIZE, "int")
            self.state.javavm_memory.store_array_element(array_ref, array_len, obj_ref)
            # Update size
            new_array_len = claripy.BVV(self.state.solver.eval(array_len) + 1, 32)
            this_ref.store_field(self.state, SIZE, "int", new_array_len)
        except KeyError:
            log.warning(f"Could not add element to list {this_ref}")

        return claripy.BoolV(1)


class ListGet(JavaSimProcedure):
    __provides__ = (("java.util.List", "get(int)"), ("java.util.LinkedList", "get(int)"))

    def run(self, this_ref, index):
        log.debug(f"Called SimProcedure java.util.List.get with args: {this_ref} {index}")

        if this_ref.symbolic:
            return SimSootValue_ThisRef.new_object(self.state, "java.lang.Object", symbolic=True)

        try:
            array_ref = this_ref.load_field(self.state, ELEMS, "java.lang.Object[]")
            this_ref.load_field(self.state, SIZE, "int")
            # TODO should check boundaries?

            return self.state.javavm_memory.load_array_element(array_ref, index)
        except KeyError:
            return SimSootValue_ThisRef.new_object(self.state, "java.lang.Object", symbolic=True)


class ListGetFirst(JavaSimProcedure):
    __provides__ = (("java.util.LinkedList", "getFirst()"),)

    def run(self, this_ref):
        log.debug(f"Called SimProcedure java.util.List.getFirst with args: {this_ref}")

        if this_ref.symbolic:
            return SimSootValue_ThisRef.new_object(self.state, "java.lang.Object", symbolic=True)

        try:
            array_ref = this_ref.load_field(self.state, ELEMS, "java.lang.Object[]")
            this_ref.load_field(self.state, SIZE, "int")

            # TODO should check boundaries?

            return self.state.javavm_memory.load_array_element(array_ref, claripy.BVV(0, 32))
        except KeyError:
            return SimSootValue_ThisRef.new_object(self.state, "java.lang.Object", symbolic=True)


class ListSize(JavaSimProcedure):
    __provides__ = (("java.util.List", "size()"), ("java.util.LinkedList", "size()"))

    def run(self, this_ref):
        log.debug(f"Called SimProcedure java.util.List.size with args: {this_ref}")

        if this_ref.symbolic:
            return claripy.BVS("list_size", 32)

        try:
            return this_ref.load_field(self.state, SIZE, "int")
        except KeyError:
            return claripy.BVS("list_size", 32)
