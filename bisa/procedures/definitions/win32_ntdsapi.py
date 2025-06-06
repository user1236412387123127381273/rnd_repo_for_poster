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
lib.set_library_names("ntdsapi.dll")
prototypes = \
    {
        #
        'DsBindW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["DomainControllerName", "DnsDomainName", "phDS"]),
        #
        'DsBindA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["DomainControllerName", "DnsDomainName", "phDS"]),
        #
        'DsBindWithCredW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["DomainControllerName", "DnsDomainName", "AuthIdentity", "phDS"]),
        #
        'DsBindWithCredA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["DomainControllerName", "DnsDomainName", "AuthIdentity", "phDS"]),
        #
        'DsBindWithSpnW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["DomainControllerName", "DnsDomainName", "AuthIdentity", "ServicePrincipalName", "phDS"]),
        #
        'DsBindWithSpnA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["DomainControllerName", "DnsDomainName", "AuthIdentity", "ServicePrincipalName", "phDS"]),
        #
        'DsBindWithSpnExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["DomainControllerName", "DnsDomainName", "AuthIdentity", "ServicePrincipalName", "BindFlags", "phDS"]),
        #
        'DsBindWithSpnExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["DomainControllerName", "DnsDomainName", "AuthIdentity", "ServicePrincipalName", "BindFlags", "phDS"]),
        #
        'DsBindByInstanceW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerName", "Annotation", "InstanceGuid", "DnsDomainName", "AuthIdentity", "ServicePrincipalName", "BindFlags", "phDS"]),
        #
        'DsBindByInstanceA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerName", "Annotation", "InstanceGuid", "DnsDomainName", "AuthIdentity", "ServicePrincipalName", "BindFlags", "phDS"]),
        #
        'DsBindToISTGW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["SiteName", "phDS"]),
        #
        'DsBindToISTGA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["SiteName", "phDS"]),
        #
        'DsBindingSetTimeout': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDS", "cTimeoutSecs"]),
        #
        'DsUnBindW': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["phDS"]),
        #
        'DsUnBindA': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["phDS"]),
        #
        'DsMakePasswordCredentialsW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["User", "Domain", "Password", "pAuthIdentity"]),
        #
        'DsMakePasswordCredentialsA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["User", "Domain", "Password", "pAuthIdentity"]),
        #
        'DsFreePasswordCredentials': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["AuthIdentity"]),
        #
        'DsCrackNamesW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="DS_NAME_FLAGS"), SimTypeInt(signed=False, label="DS_NAME_FORMAT"), SimTypeInt(signed=False, label="DS_NAME_FORMAT"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), label="LPArray", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DS_NAME_RESULTW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDS", "flags", "formatOffered", "formatDesired", "cNames", "rpNames", "ppResult"]),
        #
        'DsCrackNamesA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="DS_NAME_FLAGS"), SimTypeInt(signed=False, label="DS_NAME_FORMAT"), SimTypeInt(signed=False, label="DS_NAME_FORMAT"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), label="LPArray", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DS_NAME_RESULTA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDS", "flags", "formatOffered", "formatDesired", "cNames", "rpNames", "ppResult"]),
        #
        'DsFreeNameResultW': SimTypeFunction([SimTypePointer(SimTypeRef("DS_NAME_RESULTW", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pResult"]),
        #
        'DsFreeNameResultA': SimTypeFunction([SimTypePointer(SimTypeRef("DS_NAME_RESULTA", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pResult"]),
        #
        'DsGetSpnA': SimTypeFunction([SimTypeInt(signed=False, label="DS_SPN_NAME_TYPE"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), label="LPArray", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServiceType", "ServiceClass", "ServiceName", "InstancePort", "cInstanceNames", "pInstanceNames", "pInstancePorts", "pcSpn", "prpszSpn"]),
        #
        'DsGetSpnW': SimTypeFunction([SimTypeInt(signed=False, label="DS_SPN_NAME_TYPE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), label="LPArray", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServiceType", "ServiceClass", "ServiceName", "InstancePort", "cInstanceNames", "pInstanceNames", "pInstancePorts", "pcSpn", "prpszSpn"]),
        #
        'DsFreeSpnArrayA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), label="LPArray", offset=0)], SimTypeBottom(label="Void"), arg_names=["cSpn", "rpszSpn"]),
        #
        'DsFreeSpnArrayW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), label="LPArray", offset=0)], SimTypeBottom(label="Void"), arg_names=["cSpn", "rpszSpn"]),
        #
        'DsWriteAccountSpnA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="DS_SPN_WRITE_OP"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDS", "Operation", "pszAccount", "cSpn", "rpszSpn"]),
        #
        'DsWriteAccountSpnW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="DS_SPN_WRITE_OP"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDS", "Operation", "pszAccount", "cSpn", "rpszSpn"]),
        #
        'DsClientMakeSpnForTargetServerW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServiceClass", "ServiceName", "pcSpnLength", "pszSpn"]),
        #
        'DsClientMakeSpnForTargetServerA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServiceClass", "ServiceName", "pcSpnLength", "pszSpn"]),
        #
        'DsServerRegisterSpnA': SimTypeFunction([SimTypeInt(signed=False, label="DS_SPN_WRITE_OP"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Operation", "ServiceClass", "UserObjectDN"]),
        #
        'DsServerRegisterSpnW': SimTypeFunction([SimTypeInt(signed=False, label="DS_SPN_WRITE_OP"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Operation", "ServiceClass", "UserObjectDN"]),
        #
        'DsReplicaSyncA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDS", "NameContext", "pUuidDsaSrc", "Options"]),
        #
        'DsReplicaSyncW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDS", "NameContext", "pUuidDsaSrc", "Options"]),
        #
        'DsReplicaAddA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("SCHEDULE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDS", "NameContext", "SourceDsaDn", "TransportDn", "SourceDsaAddress", "pSchedule", "Options"]),
        #
        'DsReplicaAddW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("SCHEDULE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDS", "NameContext", "SourceDsaDn", "TransportDn", "SourceDsaAddress", "pSchedule", "Options"]),
        #
        'DsReplicaDelA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDS", "NameContext", "DsaSrc", "Options"]),
        #
        'DsReplicaDelW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDS", "NameContext", "DsaSrc", "Options"]),
        #
        'DsReplicaModifyA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("SCHEDULE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDS", "NameContext", "pUuidSourceDsa", "TransportDn", "SourceDsaAddress", "pSchedule", "ReplicaFlags", "ModifyFields", "Options"]),
        #
        'DsReplicaModifyW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("SCHEDULE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDS", "NameContext", "pUuidSourceDsa", "TransportDn", "SourceDsaAddress", "pSchedule", "ReplicaFlags", "ModifyFields", "Options"]),
        #
        'DsReplicaUpdateRefsA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDS", "NameContext", "DsaDest", "pUuidDsaDest", "Options"]),
        #
        'DsReplicaUpdateRefsW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDS", "NameContext", "DsaDest", "pUuidDsaDest", "Options"]),
        #
        'DsReplicaSyncAllA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeRef("DS_REPSYNCALL_ERRINFOA", SimStruct), offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDS", "pszNameContext", "ulFlags", "pFnCallBack", "pCallbackData", "pErrors"]),
        #
        'DsReplicaSyncAllW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeRef("DS_REPSYNCALL_ERRINFOW", SimStruct), offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDS", "pszNameContext", "ulFlags", "pFnCallBack", "pCallbackData", "pErrors"]),
        #
        'DsRemoveDsServerW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDs", "ServerDN", "DomainDN", "fLastDcInDomain", "fCommit"]),
        #
        'DsRemoveDsServerA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDs", "ServerDN", "DomainDN", "fLastDcInDomain", "fCommit"]),
        #
        'DsRemoveDsDomainW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDs", "DomainDN"]),
        #
        'DsRemoveDsDomainA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDs", "DomainDN"]),
        #
        'DsListSitesA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DS_NAME_RESULTA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDs", "ppSites"]),
        #
        'DsListSitesW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DS_NAME_RESULTW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDs", "ppSites"]),
        #
        'DsListServersInSiteA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DS_NAME_RESULTA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDs", "site", "ppServers"]),
        #
        'DsListServersInSiteW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DS_NAME_RESULTW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDs", "site", "ppServers"]),
        #
        'DsListDomainsInSiteA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DS_NAME_RESULTA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDs", "site", "ppDomains"]),
        #
        'DsListDomainsInSiteW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DS_NAME_RESULTW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDs", "site", "ppDomains"]),
        #
        'DsListServersForDomainInSiteA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DS_NAME_RESULTA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDs", "domain", "site", "ppServers"]),
        #
        'DsListServersForDomainInSiteW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DS_NAME_RESULTW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDs", "domain", "site", "ppServers"]),
        #
        'DsListInfoForServerA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DS_NAME_RESULTA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDs", "server", "ppInfo"]),
        #
        'DsListInfoForServerW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DS_NAME_RESULTW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDs", "server", "ppInfo"]),
        #
        'DsListRolesA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DS_NAME_RESULTA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDs", "ppRoles"]),
        #
        'DsListRolesW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DS_NAME_RESULTW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDs", "ppRoles"]),
        #
        'DsQuerySitesByCostW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DS_SITE_COST_INFO", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDS", "pwszFromSite", "rgwszToSites", "cToSites", "dwFlags", "prgSiteInfo"]),
        #
        'DsQuerySitesByCostA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DS_SITE_COST_INFO", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDS", "pszFromSite", "rgszToSites", "cToSites", "dwFlags", "prgSiteInfo"]),
        #
        'DsQuerySitesFree': SimTypeFunction([SimTypePointer(SimTypeRef("DS_SITE_COST_INFO", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["rgSiteInfo"]),
        #
        'DsMapSchemaGuidsA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), label="LPArray", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DS_SCHEMA_GUID_MAPA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDs", "cGuids", "rGuids", "ppGuidMap"]),
        #
        'DsFreeSchemaGuidMapA': SimTypeFunction([SimTypePointer(SimTypeRef("DS_SCHEMA_GUID_MAPA", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pGuidMap"]),
        #
        'DsMapSchemaGuidsW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), label="LPArray", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DS_SCHEMA_GUID_MAPW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDs", "cGuids", "rGuids", "ppGuidMap"]),
        #
        'DsFreeSchemaGuidMapW': SimTypeFunction([SimTypePointer(SimTypeRef("DS_SCHEMA_GUID_MAPW", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pGuidMap"]),
        #
        'DsGetDomainControllerInfoA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDs", "DomainName", "InfoLevel", "pcOut", "ppInfo"]),
        #
        'DsGetDomainControllerInfoW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDs", "DomainName", "InfoLevel", "pcOut", "ppInfo"]),
        #
        'DsFreeDomainControllerInfoA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), label="LPArray", offset=0)], SimTypeBottom(label="Void"), arg_names=["InfoLevel", "cInfo", "pInfo"]),
        #
        'DsFreeDomainControllerInfoW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), label="LPArray", offset=0)], SimTypeBottom(label="Void"), arg_names=["InfoLevel", "cInfo", "pInfo"]),
        #
        'DsReplicaConsistencyCheck': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="DS_KCC_TASKID"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDS", "TaskID", "dwFlags"]),
        #
        'DsReplicaVerifyObjectsW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDS", "NameContext", "pUuidDsaSrc", "ulOptions"]),
        #
        'DsReplicaVerifyObjectsA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDS", "NameContext", "pUuidDsaSrc", "ulOptions"]),
        #
        'DsReplicaGetInfoW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="DS_REPL_INFO_TYPE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDS", "InfoType", "pszObject", "puuidForSourceDsaObjGuid", "ppInfo"]),
        #
        'DsReplicaGetInfo2W': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="DS_REPL_INFO_TYPE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDS", "InfoType", "pszObject", "puuidForSourceDsaObjGuid", "pszAttributeName", "pszValue", "dwFlags", "dwEnumerationContext", "ppInfo"]),
        #
        'DsReplicaFreeInfo': SimTypeFunction([SimTypeInt(signed=False, label="DS_REPL_INFO_TYPE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["InfoType", "pInfo"]),
        #
        'DsAddSidHistoryW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDS", "Flags", "SrcDomain", "SrcPrincipal", "SrcDomainController", "SrcDomainCreds", "DstDomain", "DstPrincipal"]),
        #
        'DsAddSidHistoryA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDS", "Flags", "SrcDomain", "SrcPrincipal", "SrcDomainController", "SrcDomainCreds", "DstDomain", "DstPrincipal"]),
        #
        'DsInheritSecurityIdentityW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDS", "Flags", "SrcPrincipal", "DstPrincipal"]),
        #
        'DsInheritSecurityIdentityA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDS", "Flags", "SrcPrincipal", "DstPrincipal"]),
    }

lib.set_prototypes(prototypes)
