# pylint:disable=line-too-long
from __future__ import annotations
import logging
from collections import OrderedDict

from bisa.sim_type import SimTypeFunction, SimTypeShort, SimTypeInt, SimTypeLong, SimTypeLongLong, SimTypeDouble, SimTypeFloat, SimTypePointer, SimTypeChar, SimStruct, SimTypeArray, SimTypeBottom, SimUnion, SimTypeBool, SimTypeRef
from bisa.calling_conventions import SimCCStdcall, SimCCMicrosoftAMD64
from bisa.procedures import SIM_PROCEDURES as P
from . import SimLibrary


_l = logging.getLogger(name=__name__)


lib = SimLibrary()
lib.type_collection_names = ["win32"]
lib.set_default_cc("X86", SimCCStdcall)
lib.set_default_cc("AMD64", SimCCMicrosoftAMD64)
lib.set_library_names("query.dll")
prototypes = \
    {
        #
        'LoadIFilter': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwcsPath", "pUnkOuter", "ppIUnk"]),
        #
        'LoadIFilterEx': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwcsPath", "dwFlags", "riid", "ppIUnk"]),
        #
        'BindIFilterFromStorage': SimTypeFunction([SimTypeBottom(label="IStorage"), SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pStg", "pUnkOuter", "ppIUnk"]),
        #
        'BindIFilterFromStream': SimTypeFunction([SimTypeBottom(label="IStream"), SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pStm", "pUnkOuter", "ppIUnk"]),
    }

lib.set_prototypes(prototypes)
