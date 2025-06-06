# pylint:disable=import-outside-toplevel
from __future__ import annotations

from typing import Any, TYPE_CHECKING

from .plugin import KnowledgeBasePlugin

if TYPE_CHECKING:
    from bisa.analyses.decompiler.structured_codegen import BaseStructuredCodeGenerator
    from bisa.analyses.decompiler.decompilation_cache import DecompilationCache


class StructuredCodeManager(KnowledgeBasePlugin):
    """A knowledge base plugin to store structured code generator results."""

    def __init__(self, kb):
        super().__init__(kb=kb)
        self.cached: dict[Any, DecompilationCache] = {}

    def _normalize_key(self, item):
        if type(item) is not tuple:
            raise TypeError("Structured code can only be queried by tuples of (func, flavor)")
        if type(item[0]) is str:
            item = (self._kb.labels.lookup(item[0]), *item[1:])
        return item

    def __getitem__(self, item) -> DecompilationCache:
        return self.cached[self._normalize_key(item)]

    def __setitem__(self, key, value: DecompilationCache | BaseStructuredCodeGenerator):
        from bisa.analyses.decompiler.structured_codegen import BaseStructuredCodeGenerator
        from bisa.analyses.decompiler.decompilation_cache import DecompilationCache

        nkey = self._normalize_key(key)

        if isinstance(value, BaseStructuredCodeGenerator):
            cache = DecompilationCache(nkey)
            cache.codegen = value
        else:
            cache = value
        self.cached[nkey] = cache

    def __contains__(self, key):
        return self._normalize_key(key) in self.cached

    def __delitem__(self, key):
        del self.cached[self._normalize_key(key)]

    def discard(self, key):
        normalized_key = self._normalize_key(key)
        if normalized_key in self.cached:
            del self.cached[normalized_key]

    def available_flavors(self, item):
        if type(item) is str:
            item = self._kb.labels.lookup(item)
        return [flavor for func, flavor in self.cached if func == item]

    def copy(self):
        raise NotImplementedError


KnowledgeBasePlugin.register_default("decompilations", StructuredCodeManager)
