from __future__ import annotations

import typing

from bisa.storage.memory_mixins.memory_mixin import MemoryMixin
from .cooperation import CooperationBase
from .ispo_mixin import ISPOMixin
from .refcount_mixin import RefcountMixin
from .permissions_mixin import PermissionsMixin
from .history_tracking_mixin import HistoryTrackingMixin


class PageBase(HistoryTrackingMixin, RefcountMixin, CooperationBase, ISPOMixin, PermissionsMixin, MemoryMixin):
    """
    This is a fairly succinct definition of the contract between PagedMemoryMixin and its constituent pages:

    - Pages must implement the MemoryMixin model for loads, stores, copying, merging, etc
    - However, loading/storing may not necessarily use the same data domain as PagedMemoryMixin. In order to do more
      efficient loads/stores across pages, we use the CooperationBase interface which allows the page class to
      determine how to generate and unwrap the objects which are actually stored.
    - To support COW, we use the RefcountMixin and the ISPOMixin (which adds the contract element that ``memory=self``
      be passed to every method call)
    - Pages have permissions associated with them, stored in the PermissionsMixin.

    Read the docstrings for each of the constituent classes to understand the nuances of their functionalities
    """


PageType = typing.TypeVar("PageType", bound=PageBase)

__all__ = ("PageBase", "PageType")
