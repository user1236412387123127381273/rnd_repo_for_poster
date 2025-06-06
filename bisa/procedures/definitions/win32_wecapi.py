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
lib.set_library_names("wecapi.dll")
prototypes = \
    {
        #
        'EcOpenSubscriptionEnum': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["Flags"]),
        #
        'EcEnumNextSubscription': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SubscriptionEnum", "SubscriptionNameBufferSize", "SubscriptionNameBuffer", "SubscriptionNameBufferUsed"]),
        #
        'EcOpenSubscription': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["SubscriptionName", "AccessMask", "Flags"]),
        #
        'EcSetSubscriptionProperty': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="EC_SUBSCRIPTION_PROPERTY_ID"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("EC_VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Subscription", "PropertyId", "Flags", "PropertyValue"]),
        #
        'EcGetSubscriptionProperty': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="EC_SUBSCRIPTION_PROPERTY_ID"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("EC_VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Subscription", "PropertyId", "Flags", "PropertyValueBufferSize", "PropertyValueBuffer", "PropertyValueBufferUsed"]),
        #
        'EcSaveSubscription': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Subscription", "Flags"]),
        #
        'EcDeleteSubscription': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["SubscriptionName", "Flags"]),
        #
        'EcGetObjectArraySize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ObjectArray", "ObjectArraySize"]),
        #
        'EcSetObjectArrayProperty': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="EC_SUBSCRIPTION_PROPERTY_ID"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("EC_VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ObjectArray", "PropertyId", "ArrayIndex", "Flags", "PropertyValue"]),
        #
        'EcGetObjectArrayProperty': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="EC_SUBSCRIPTION_PROPERTY_ID"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("EC_VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ObjectArray", "PropertyId", "ArrayIndex", "Flags", "PropertyValueBufferSize", "PropertyValueBuffer", "PropertyValueBufferUsed"]),
        #
        'EcInsertObjectArrayElement': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ObjectArray", "ArrayIndex"]),
        #
        'EcRemoveObjectArrayElement': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ObjectArray", "ArrayIndex"]),
        #
        'EcGetSubscriptionRunTimeStatus': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="EC_SUBSCRIPTION_RUNTIME_STATUS_INFO_ID"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("EC_VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SubscriptionName", "StatusInfoId", "EventSourceName", "Flags", "StatusValueBufferSize", "StatusValueBuffer", "StatusValueBufferUsed"]),
        #
        'EcRetrySubscription': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["SubscriptionName", "EventSourceName", "Flags"]),
        #
        'EcClose': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Object"]),
    }

lib.set_prototypes(prototypes)
