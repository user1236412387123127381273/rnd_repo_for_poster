from __future__ import annotations
import claripy

import bisa


def mutate_dict(state, KEY):
    d = dict(state.globals.get(KEY, {}))
    state.globals[KEY] = d
    return d


def has_index(state, idx, KEY):
    if KEY not in state.globals:
        return False
    return idx in state.globals[KEY]


class TlsAlloc(bisa.SimProcedure):
    KEY = "win32_tls"

    def run(self):
        d = mutate_dict(self.state, self.KEY)
        new_key = len(d) + 1
        d[new_key] = claripy.BVV(0, self.state.arch.bits)
        return new_key


class TlsSetValue(bisa.SimProcedure):
    KEY = "win32_tls"

    def run(self, index, value):
        conc_indexes = self.state.solver.eval_upto(index, 2)
        if len(conc_indexes) != 1:
            raise bisa.errors.SimValueError("Can't handle symbolic index in TlsSetValue/FlsSetValue")
        conc_index = conc_indexes[0]

        if not has_index(self.state, conc_index, self.KEY):
            return 0

        mutate_dict(self.state, self.KEY)[conc_index] = value
        return 1


class TlsGetValue(bisa.SimProcedure):
    KEY = "win32_tls"

    def run(self, index):
        conc_indexes = self.state.solver.eval_upto(index, 2)
        if len(conc_indexes) != 1:
            raise bisa.errors.SimValueError("Can't handle symbolic index in TlsGetValue/FlsGetValue")
        conc_index = conc_indexes[0]

        if not has_index(self.state, conc_index, self.KEY):
            return 0

        return self.state.globals[self.KEY][conc_index]


class TlsFree(bisa.SimProcedure):
    KEY = "win32_tls"
    SETTER = TlsSetValue

    def run(self, index):
        set_val = self.inline_call(self.SETTER, index, claripy.BVV(0, self.state.arch.bits))
        return set_val.ret_expr


class FlsAlloc(TlsAlloc):
    KEY = "win32_fls"

    def run(self, callback):
        if not self.state.solver.is_true(callback == 0):
            raise bisa.errors.SimValueError("Can't handle callback function in FlsAlloc")
        return super().run()


class FlsGetValue(TlsGetValue):
    KEY = "win32_fls"


class FlsSetValue(TlsSetValue):
    KEY = "win32_fls"


class FlsFree(TlsFree):
    KEY = "win32_fls"
    SETTER = FlsSetValue
