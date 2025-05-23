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
lib.set_library_names("api-ms-win-dx-d3dkmt-l1-1-4.dll")
prototypes = \
    {
        #
        'D3DKMTSubmitPresentBltToHwQueue': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_SUBMITPRESENTBLTTOHWQUEUE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTSubmitPresentToHwQueue': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_SUBMITPRESENTTOHWQUEUE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'D3DKMTOutputDuplPresentToHwQueue': SimTypeFunction([SimTypePointer(SimTypeRef("D3DKMT_OUTPUTDUPLPRESENTTOHWQUEUE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
    }

lib.set_prototypes(prototypes)
