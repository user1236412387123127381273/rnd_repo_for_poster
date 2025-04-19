from __future__ import annotations
from bisa.procedures.cgc.random import random as orig_random


class random(orig_random):
    """
    This a passthrough to the CGC version. Removing this requires regenerating bisaop caches used by rex and so this is
    being retained.
    """
