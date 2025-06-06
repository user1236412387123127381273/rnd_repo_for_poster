# pylint:disable=line-too-long
from __future__ import annotations
import logging

from bisa.sim_type import SimTypeFunction, SimTypeShort, SimTypeInt, SimTypeLong, SimTypeLongLong, SimTypeDouble, SimTypeFloat, SimTypePointer, SimTypeChar, SimStruct, SimTypeFixedSizeArray, SimTypeBottom, SimUnion, SimTypeBool
from bisa.calling_conventions import SimCCStdcall, SimCCMicrosoftAMD64
from bisa.procedures import SIM_PROCEDURES as P
from . import SimLibrary


_l = logging.getLogger(name=__name__)


lib = SimLibrary()
lib.set_default_cc('X86', SimCCStdcall)
lib.set_default_cc('AMD64', SimCCMicrosoftAMD64)
lib.set_library_names("coremessaging.dll")
prototypes = \
    {
        #
        'CreateDispatcherQueueController': SimTypeFunction([SimStruct({"dwSize": SimTypeInt(signed=False, label="UInt32"), "threadType": SimTypeInt(signed=False, label="DISPATCHERQUEUE_THREAD_TYPE"), "apartmentType": SimTypeInt(signed=False, label="DISPATCHERQUEUE_THREAD_APARTMENTTYPE")}, name="DispatcherQueueOptions", pack=False, align=None), SimTypePointer(SimTypeBottom(label="MissingClrType"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["options", "dispatcherQueueController"]),
    }

lib.set_prototypes(prototypes)
