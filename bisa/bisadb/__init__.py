from __future__ import annotations

try:
    import sqlalchemy
except ImportError as err:
    sqlalchemy = None
    raise ImportError(
        "BISADB relies on SQLAlchemy. Please install SQLAlchemy first by running:\n\tpip install sqlalchemy"
    ) from err

from .db import BISADB


__all__ = ("BISADB",)
