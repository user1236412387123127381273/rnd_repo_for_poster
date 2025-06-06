from __future__ import annotations

from bisa.sim_type import SimCppClass, SimTypeCppFunction
from bisa.analyses import AnalysesHub
from bisa.utils.cpp import is_cpp_funcname_ctor
from . import Analysis, CFGFast, VtableFinder


class ClassIdentifier(Analysis):
    """
    This is a class identifier for non stripped or partially stripped binaries, it identifies classes based on the
    demangled function names, and also assigns functions to their respective classes based on their names. It also uses
    the results from the VtableFinder analysis to assign the corresponding vtable to the classes.

     self.classes contains a mapping between class names and SimCppClass objects

     e.g. A::tool() and A::qux() belong to the class A
    """

    def __init__(self):
        if "CFGFast" not in self.project.kb.cfgs:
            self.project.analyses[CFGFast].prep()(cross_references=True)
        self.classes = {}
        vtable_analysis = self.project.analyses[VtableFinder].prep()()
        self.vtables_list = vtable_analysis.vtables_list
        self._analyze()

    def _analyze(self):
        # Assigning function to classes
        for func in self.project.kb.functions.values():
            if func.is_plt:
                continue
            col_ind = func.demangled_name.rfind("::")
            class_name = func.demangled_name[:col_ind]
            class_name = class_name.removeprefix("non-virtual thunk for ")
            if col_ind != -1:
                if class_name not in self.classes:
                    ctor = is_cpp_funcname_ctor(func.demangled_name)
                    function_members = {func.addr: SimTypeCppFunction([], None, label=func.demangled_name, ctor=ctor)}
                    new_class = SimCppClass(name=class_name, function_members=function_members)
                    self.classes[class_name] = new_class

                else:
                    ctor = is_cpp_funcname_ctor(func.demangled_name)
                    cur_class = self.classes[class_name]
                    cur_class.function_members[func.addr] = SimTypeCppFunction(
                        [], None, label=func.demangled_name, ctor=ctor
                    )

        # Assigning a vtable to a class
        for vtable in self.vtables_list:
            for ref in self.project.kb.xrefs.xrefs_by_dst[vtable.vaddr]:
                vtable_calling_func = self.project.kb.functions.floor_func(ref.ins_addr)
                tmp_col_ind = vtable_calling_func.demangled_name.rfind("::")
                possible_constructor_class_name = vtable_calling_func.demangled_name[:tmp_col_ind]
                if (
                    is_cpp_funcname_ctor(vtable_calling_func.demangled_name)
                    and possible_constructor_class_name in self.classes
                ):
                    self.classes[possible_constructor_class_name].vtable_ptrs.append(vtable.vaddr)


AnalysesHub.register_default("ClassIdentifier", ClassIdentifier)
