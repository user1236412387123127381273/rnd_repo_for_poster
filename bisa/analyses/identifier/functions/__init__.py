from __future__ import annotations

import importlib
import logging
import os

from bisa.analyses.identifier.func import Func

l = logging.getLogger(name=__name__)


# Import all classes under the current directory, and group them based on
# lib names.
Functions = {}
path = os.path.dirname(os.path.abspath(__file__))
skip_dirs = ["__init__.py"]
skip_procs = ["__init__", "func"]

for proc_file_name in os.listdir(path):
    if not proc_file_name.endswith(".py"):
        continue
    proc_module_name = proc_file_name[:-3]
    if proc_file_name.startswith("skip"):
        continue
    if proc_module_name in skip_procs:
        continue

    try:
        proc_module = importlib.import_module(f".{proc_module_name}", "bisa.analyses.identifier.functions")
    except ImportError:
        l.warning("Unable to import procedure %s", proc_module_name)
        continue

    for attr_name in dir(proc_module):
        attr = getattr(proc_module, attr_name)
        if isinstance(attr, type) and issubclass(attr, Func) and attr_name != "Func":
            Functions[attr_name] = attr
