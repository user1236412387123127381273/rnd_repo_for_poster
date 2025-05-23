from __future__ import annotations
import logging

from . import JNISimProcedure, jni_functions

l = logging.getLogger("bisa.procedures.java_jni.NotImplemented")

# pylint: disable=arguments-differ,unused-argument


class UnsupportedJNIFunction(JNISimProcedure):
    return_ty = "void"

    def run(self):
        # get name of the missing function
        native_arch_size = self.state.project.simos.native_arch.bits
        jni_function_table = self.state.project.simos.jni_function_table
        function_idx = (self.state.addr - jni_function_table) // (native_arch_size // 8)
        function_name = jni_functions.keys()[function_idx]

        # show warning
        l.warning("SimProcedure for JNI function %s is not implemented. Returning unconstrained symbol.", function_name)

        # return unconstrained
        symbol_name = f"unconstrained_ret_of_jni_func_{function_name}"
        return self.state.solver.Unconstrained(symbol_name, native_arch_size)
