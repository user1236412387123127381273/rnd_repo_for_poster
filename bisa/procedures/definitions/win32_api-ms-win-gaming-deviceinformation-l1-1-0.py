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
lib.set_library_names("api-ms-win-gaming-deviceinformation-l1-1-0.dll")
prototypes = \
    {
        #
        'GetGamingDeviceModelInformation': SimTypeFunction([SimTypePointer(SimTypeRef("GAMING_DEVICE_MODEL_INFORMATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["information"]),
    }

lib.set_prototypes(prototypes)
