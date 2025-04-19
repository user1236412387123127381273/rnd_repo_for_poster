from __future__ import annotations

import bisa


class SimSootExpr:
    def __init__(self, expr, state):
        self.expr = expr
        self.state = state

    def process(self):
        self._execute()

    def _execute(self):
        raise NotImplementedError

    def _translate_expr(self, expr):
        return bisa.engines.soot.expressions.translate_expr(expr, self.state)

    def _translate_value(self, value):
        return bisa.engines.soot.values.translate_value(value, self.state)
