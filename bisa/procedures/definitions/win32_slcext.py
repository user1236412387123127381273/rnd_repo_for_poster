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
lib.set_library_names("slcext.dll")
prototypes = \
    {
        #
        'SLActivateProduct': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("SL_ACTIVATION_INFO_HEADER", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=True, label="Int32"), arg_names=["hSLC", "pProductSkuId", "cbAppSpecificData", "pvAppSpecificData", "pActivationInfo", "pwszProxyServer", "wProxyPort"]),
        #
        'SLGetServerStatus': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwszServerURL", "pwszAcquisitionType", "pwszProxyServer", "wProxyPort", "phrStatus"]),
        #
        'SLAcquireGenuineTicket': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppTicketBlob", "pcbTicketBlob", "pwszTemplateId", "pwszServerUrl", "pwszClientToken"]),
        #
        'SLGetReferralInformation': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="SLREFERRALTYPE"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSLC", "eReferralType", "pSkuOrAppId", "pwszValueName", "ppwszValue"]),
    }

lib.set_prototypes(prototypes)
