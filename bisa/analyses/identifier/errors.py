from __future__ import annotations
from bisa.errors import BISAAnalysisError


class IdentifierException(BISAAnalysisError):
    pass


class FunctionNotInitialized(BISAAnalysisError):
    pass
