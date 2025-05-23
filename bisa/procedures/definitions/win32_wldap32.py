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
lib.set_library_names("wldap32.dll")
prototypes = \
    {
        #
        'ldap_openW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), arg_names=["HostName", "PortNumber"]),
        #
        'ldap_openA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), arg_names=["HostName", "PortNumber"]),
        #
        'ldap_initW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), arg_names=["HostName", "PortNumber"]),
        #
        'ldap_initA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), arg_names=["HostName", "PortNumber"]),
        #
        'ldap_sslinitW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), arg_names=["HostName", "PortNumber", "secure"]),
        #
        'ldap_sslinitA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), arg_names=["HostName", "PortNumber", "secure"]),
        #
        'ldap_connect': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeRef("LDAP_TIMEVAL", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "timeout"]),
        #
        'ldap_open': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), arg_names=["HostName", "PortNumber"]),
        #
        'ldap_init': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), arg_names=["HostName", "PortNumber"]),
        #
        'ldap_sslinit': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), arg_names=["HostName", "PortNumber", "secure"]),
        #
        'cldap_openW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), arg_names=["HostName", "PortNumber"]),
        #
        'cldap_openA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), arg_names=["HostName", "PortNumber"]),
        #
        'cldap_open': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), arg_names=["HostName", "PortNumber"]),
        #
        'ldap_unbind': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld"]),
        #
        'ldap_unbind_s': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld"]),
        #
        'ldap_get_option': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "option", "outvalue"]),
        #
        'ldap_get_optionW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "option", "outvalue"]),
        #
        'ldap_set_option': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "option", "invalue"]),
        #
        'ldap_set_optionW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "option", "invalue"]),
        #
        'ldap_simple_bindW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "passwd"]),
        #
        'ldap_simple_bindA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "passwd"]),
        #
        'ldap_simple_bind_sW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "passwd"]),
        #
        'ldap_simple_bind_sA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "passwd"]),
        #
        'ldap_bindW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "cred", "method"]),
        #
        'ldap_bindA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "cred", "method"]),
        #
        'ldap_bind_sW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "cred", "method"]),
        #
        'ldap_bind_sA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "cred", "method"]),
        #
        'ldap_sasl_bindA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ExternalHandle", "DistName", "AuthMechanism", "cred", "ServerCtrls", "ClientCtrls", "MessageNumber"]),
        #
        'ldap_sasl_bindW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ExternalHandle", "DistName", "AuthMechanism", "cred", "ServerCtrls", "ClientCtrls", "MessageNumber"]),
        #
        'ldap_sasl_bind_sA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ExternalHandle", "DistName", "AuthMechanism", "cred", "ServerCtrls", "ClientCtrls", "ServerData"]),
        #
        'ldap_sasl_bind_sW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ExternalHandle", "DistName", "AuthMechanism", "cred", "ServerCtrls", "ClientCtrls", "ServerData"]),
        #
        'ldap_simple_bind': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "passwd"]),
        #
        'ldap_simple_bind_s': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "passwd"]),
        #
        'ldap_bind': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "cred", "method"]),
        #
        'ldap_bind_s': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "cred", "method"]),
        #
        'ldap_searchW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "base", "scope", "filter", "attrs", "attrsonly"]),
        #
        'ldap_searchA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "base", "scope", "filter", "attrs", "attrsonly"]),
        #
        'ldap_search_sW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "base", "scope", "filter", "attrs", "attrsonly", "res"]),
        #
        'ldap_search_sA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "base", "scope", "filter", "attrs", "attrsonly", "res"]),
        #
        'ldap_search_stW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LDAP_TIMEVAL", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "base", "scope", "filter", "attrs", "attrsonly", "timeout", "res"]),
        #
        'ldap_search_stA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LDAP_TIMEVAL", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "base", "scope", "filter", "attrs", "attrsonly", "timeout", "res"]),
        #
        'ldap_search_extW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "base", "scope", "filter", "attrs", "attrsonly", "ServerControls", "ClientControls", "TimeLimit", "SizeLimit", "MessageNumber"]),
        #
        'ldap_search_extA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "base", "scope", "filter", "attrs", "attrsonly", "ServerControls", "ClientControls", "TimeLimit", "SizeLimit", "MessageNumber"]),
        #
        'ldap_search_ext_sW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeRef("LDAP_TIMEVAL", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "base", "scope", "filter", "attrs", "attrsonly", "ServerControls", "ClientControls", "timeout", "SizeLimit", "res"]),
        #
        'ldap_search_ext_sA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeRef("LDAP_TIMEVAL", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "base", "scope", "filter", "attrs", "attrsonly", "ServerControls", "ClientControls", "timeout", "SizeLimit", "res"]),
        #
        'ldap_search': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "base", "scope", "filter", "attrs", "attrsonly"]),
        #
        'ldap_search_s': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "base", "scope", "filter", "attrs", "attrsonly", "res"]),
        #
        'ldap_search_st': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LDAP_TIMEVAL", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "base", "scope", "filter", "attrs", "attrsonly", "timeout", "res"]),
        #
        'ldap_search_ext': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "base", "scope", "filter", "attrs", "attrsonly", "ServerControls", "ClientControls", "TimeLimit", "SizeLimit", "MessageNumber"]),
        #
        'ldap_search_ext_s': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeRef("LDAP_TIMEVAL", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "base", "scope", "filter", "attrs", "attrsonly", "ServerControls", "ClientControls", "timeout", "SizeLimit", "res"]),
        #
        'ldap_check_filterW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "SearchFilter"]),
        #
        'ldap_check_filterA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "SearchFilter"]),
        #
        'ldap_modifyW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPModW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "mods"]),
        #
        'ldap_modifyA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPModA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "mods"]),
        #
        'ldap_modify_sW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPModW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "mods"]),
        #
        'ldap_modify_sA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPModA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "mods"]),
        #
        'ldap_modify_extW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPModW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "mods", "ServerControls", "ClientControls", "MessageNumber"]),
        #
        'ldap_modify_extA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPModA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "mods", "ServerControls", "ClientControls", "MessageNumber"]),
        #
        'ldap_modify_ext_sW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPModW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "mods", "ServerControls", "ClientControls"]),
        #
        'ldap_modify_ext_sA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPModA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "mods", "ServerControls", "ClientControls"]),
        #
        'ldap_modify': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPModA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "mods"]),
        #
        'ldap_modify_s': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPModA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "mods"]),
        #
        'ldap_modify_ext': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPModA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "mods", "ServerControls", "ClientControls", "MessageNumber"]),
        #
        'ldap_modify_ext_s': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPModA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "mods", "ServerControls", "ClientControls"]),
        #
        'ldap_modrdn2W': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExternalHandle", "DistinguishedName", "NewDistinguishedName", "DeleteOldRdn"]),
        #
        'ldap_modrdn2A': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExternalHandle", "DistinguishedName", "NewDistinguishedName", "DeleteOldRdn"]),
        #
        'ldap_modrdnW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExternalHandle", "DistinguishedName", "NewDistinguishedName"]),
        #
        'ldap_modrdnA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExternalHandle", "DistinguishedName", "NewDistinguishedName"]),
        #
        'ldap_modrdn2_sW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExternalHandle", "DistinguishedName", "NewDistinguishedName", "DeleteOldRdn"]),
        #
        'ldap_modrdn2_sA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExternalHandle", "DistinguishedName", "NewDistinguishedName", "DeleteOldRdn"]),
        #
        'ldap_modrdn_sW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExternalHandle", "DistinguishedName", "NewDistinguishedName"]),
        #
        'ldap_modrdn_sA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExternalHandle", "DistinguishedName", "NewDistinguishedName"]),
        #
        'ldap_modrdn2': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExternalHandle", "DistinguishedName", "NewDistinguishedName", "DeleteOldRdn"]),
        #
        'ldap_modrdn': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExternalHandle", "DistinguishedName", "NewDistinguishedName"]),
        #
        'ldap_modrdn2_s': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExternalHandle", "DistinguishedName", "NewDistinguishedName", "DeleteOldRdn"]),
        #
        'ldap_modrdn_s': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExternalHandle", "DistinguishedName", "NewDistinguishedName"]),
        #
        'ldap_rename_extW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "NewRDN", "NewParent", "DeleteOldRdn", "ServerControls", "ClientControls", "MessageNumber"]),
        #
        'ldap_rename_extA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "NewRDN", "NewParent", "DeleteOldRdn", "ServerControls", "ClientControls", "MessageNumber"]),
        #
        'ldap_rename_ext_sW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "NewRDN", "NewParent", "DeleteOldRdn", "ServerControls", "ClientControls"]),
        #
        'ldap_rename_ext_sA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "NewRDN", "NewParent", "DeleteOldRdn", "ServerControls", "ClientControls"]),
        #
        'ldap_rename_ext': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "NewRDN", "NewParent", "DeleteOldRdn", "ServerControls", "ClientControls", "MessageNumber"]),
        #
        'ldap_rename_ext_s': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "NewRDN", "NewParent", "DeleteOldRdn", "ServerControls", "ClientControls"]),
        #
        'ldap_addW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPModW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "attrs"]),
        #
        'ldap_addA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPModA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "attrs"]),
        #
        'ldap_add_sW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPModW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "attrs"]),
        #
        'ldap_add_sA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPModA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "attrs"]),
        #
        'ldap_add_extW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPModW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "attrs", "ServerControls", "ClientControls", "MessageNumber"]),
        #
        'ldap_add_extA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPModA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "attrs", "ServerControls", "ClientControls", "MessageNumber"]),
        #
        'ldap_add_ext_sW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPModW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "attrs", "ServerControls", "ClientControls"]),
        #
        'ldap_add_ext_sA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPModA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "attrs", "ServerControls", "ClientControls"]),
        #
        'ldap_add': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPModA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "attrs"]),
        #
        'ldap_add_s': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPModA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "attrs"]),
        #
        'ldap_add_ext': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPModA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "attrs", "ServerControls", "ClientControls", "MessageNumber"]),
        #
        'ldap_add_ext_s': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPModA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "attrs", "ServerControls", "ClientControls"]),
        #
        'ldap_compareW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "attr", "value"]),
        #
        'ldap_compareA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "attr", "value"]),
        #
        'ldap_compare_sW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "attr", "value"]),
        #
        'ldap_compare_sA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "attr", "value"]),
        #
        'ldap_compare': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "attr", "value"]),
        #
        'ldap_compare_s': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "attr", "value"]),
        #
        'ldap_compare_extW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "Attr", "Value", "Data", "ServerControls", "ClientControls", "MessageNumber"]),
        #
        'ldap_compare_extA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "Attr", "Value", "Data", "ServerControls", "ClientControls", "MessageNumber"]),
        #
        'ldap_compare_ext_sW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "Attr", "Value", "Data", "ServerControls", "ClientControls"]),
        #
        'ldap_compare_ext_sA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "Attr", "Value", "Data", "ServerControls", "ClientControls"]),
        #
        'ldap_compare_ext': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "Attr", "Value", "Data", "ServerControls", "ClientControls", "MessageNumber"]),
        #
        'ldap_compare_ext_s': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "Attr", "Value", "Data", "ServerControls", "ClientControls"]),
        #
        'ldap_deleteW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn"]),
        #
        'ldap_deleteA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn"]),
        #
        'ldap_delete_sW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn"]),
        #
        'ldap_delete_sA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn"]),
        #
        'ldap_delete_extW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "ServerControls", "ClientControls", "MessageNumber"]),
        #
        'ldap_delete_extA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "ServerControls", "ClientControls", "MessageNumber"]),
        #
        'ldap_delete_ext_sW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "ServerControls", "ClientControls"]),
        #
        'ldap_delete_ext_sA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "ServerControls", "ClientControls"]),
        #
        'ldap_delete': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn"]),
        #
        'ldap_delete_s': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn"]),
        #
        'ldap_delete_ext': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "ServerControls", "ClientControls", "MessageNumber"]),
        #
        'ldap_delete_ext_s': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "dn", "ServerControls", "ClientControls"]),
        #
        'ldap_abandon': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "msgid"]),
        #
        'ldap_result': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LDAP_TIMEVAL", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "msgid", "all", "timeout", "res"]),
        #
        'ldap_msgfree': SimTypeFunction([SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["res"]),
        #
        'ldap_result2error': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "res", "freeit"]),
        #
        'ldap_parse_resultW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=False, label="UInt32"), arg_names=["Connection", "ResultMessage", "ReturnCode", "MatchedDNs", "ErrorMessage", "Referrals", "ServerControls", "Freeit"]),
        #
        'ldap_parse_resultA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=False, label="UInt32"), arg_names=["Connection", "ResultMessage", "ReturnCode", "MatchedDNs", "ErrorMessage", "Referrals", "ServerControls", "Freeit"]),
        #
        'ldap_parse_extended_resultA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=False, label="UInt32"), arg_names=["Connection", "ResultMessage", "ResultOID", "ResultData", "Freeit"]),
        #
        'ldap_parse_extended_resultW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=False, label="UInt32"), arg_names=["Connection", "ResultMessage", "ResultOID", "ResultData", "Freeit"]),
        #
        'ldap_controls_freeA': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Controls"]),
        #
        'ldap_control_freeA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Controls"]),
        #
        'ldap_controls_freeW': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Control"]),
        #
        'ldap_control_freeW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Control"]),
        #
        'ldap_free_controlsW': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Controls"]),
        #
        'ldap_free_controlsA': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Controls"]),
        #
        'ldap_parse_result': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=False, label="UInt32"), arg_names=["Connection", "ResultMessage", "ReturnCode", "MatchedDNs", "ErrorMessage", "Referrals", "ServerControls", "Freeit"]),
        #
        'ldap_controls_free': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Controls"]),
        #
        'ldap_control_free': SimTypeFunction([SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Control"]),
        #
        'ldap_free_controls': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Controls"]),
        #
        'ldap_err2stringW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["err"]),
        #
        'ldap_err2stringA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["err"]),
        #
        'ldap_err2string': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["err"]),
        #
        'ldap_perror': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ld", "msg"]),
        #
        'ldap_first_entry': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0)], SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0), arg_names=["ld", "res"]),
        #
        'ldap_next_entry': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0)], SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0), arg_names=["ld", "entry"]),
        #
        'ldap_count_entries': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "res"]),
        #
        'ldap_first_attributeW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("BerElement", SimStruct), offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["ld", "entry", "ptr"]),
        #
        'ldap_first_attributeA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("BerElement", SimStruct), offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["ld", "entry", "ptr"]),
        #
        'ldap_first_attribute': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("BerElement", SimStruct), offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["ld", "entry", "ptr"]),
        #
        'ldap_next_attributeW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0), SimTypePointer(SimTypeRef("BerElement", SimStruct), offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["ld", "entry", "ptr"]),
        #
        'ldap_next_attributeA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0), SimTypePointer(SimTypeRef("BerElement", SimStruct), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["ld", "entry", "ptr"]),
        #
        'ldap_next_attribute': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0), SimTypePointer(SimTypeRef("BerElement", SimStruct), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["ld", "entry", "ptr"]),
        #
        'ldap_get_valuesW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), arg_names=["ld", "entry", "attr"]),
        #
        'ldap_get_valuesA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), arg_names=["ld", "entry", "attr"]),
        #
        'ldap_get_values': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), arg_names=["ld", "entry", "attr"]),
        #
        'ldap_get_values_lenW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0), offset=0), arg_names=["ExternalHandle", "Message", "attr"]),
        #
        'ldap_get_values_lenA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0), offset=0), arg_names=["ExternalHandle", "Message", "attr"]),
        #
        'ldap_get_values_len': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0), offset=0), arg_names=["ExternalHandle", "Message", "attr"]),
        #
        'ldap_count_valuesW': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["vals"]),
        #
        'ldap_count_valuesA': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["vals"]),
        #
        'ldap_count_values': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["vals"]),
        #
        'ldap_count_values_len': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["vals"]),
        #
        'ldap_value_freeW': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["vals"]),
        #
        'ldap_value_freeA': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["vals"]),
        #
        'ldap_value_free': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["vals"]),
        #
        'ldap_value_free_len': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["vals"]),
        #
        'ldap_get_dnW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["ld", "entry"]),
        #
        'ldap_get_dnA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["ld", "entry"]),
        #
        'ldap_get_dn': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["ld", "entry"]),
        #
        'ldap_explode_dnW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), arg_names=["dn", "notypes"]),
        #
        'ldap_explode_dnA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), arg_names=["dn", "notypes"]),
        #
        'ldap_explode_dn': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), arg_names=["dn", "notypes"]),
        #
        'ldap_dn2ufnW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["dn"]),
        #
        'ldap_dn2ufnA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["dn"]),
        #
        'ldap_dn2ufn': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["dn"]),
        #
        'ldap_memfreeW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Block"]),
        #
        'ldap_memfreeA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Block"]),
        #
        'ber_bvfree': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["bv"]),
        #
        'ldap_memfree': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Block"]),
        #
        'ldap_ufn2dnW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ufn", "pDn"]),
        #
        'ldap_ufn2dnA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ufn", "pDn"]),
        #
        'ldap_ufn2dn': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ufn", "pDn"]),
        #
        'ldap_startup': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP_VERSION_INFO", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["version", "Instance"]),
        #
        'ldap_cleanup': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hInstance"]),
        #
        'ldap_escape_filter_elementW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["sourceFilterElement", "sourceLength", "destFilterElement", "destLength"]),
        #
        'ldap_escape_filter_elementA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["sourceFilterElement", "sourceLength", "destFilterElement", "destLength"]),
        #
        'ldap_escape_filter_element': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["sourceFilterElement", "sourceLength", "destFilterElement", "destLength"]),
        #
        'ldap_set_dbg_flags': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["NewFlags"]),
        #
        'ldap_set_dbg_routine': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Format"]), offset=0)], SimTypeBottom(label="Void"), arg_names=["DebugPrintRoutine"]),
        #
        'LdapUTF8ToUnicode': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpSrcStr", "cchSrc", "lpDestStr", "cchDest"]),
        #
        'LdapUnicodeToUTF8': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpSrcStr", "cchSrc", "lpDestStr", "cchDest"]),
        #
        'ldap_create_sort_controlA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPSortKeyA", SimStruct), offset=0), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExternalHandle", "SortKeys", "IsCritical", "Control"]),
        #
        'ldap_create_sort_controlW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPSortKeyW", SimStruct), offset=0), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExternalHandle", "SortKeys", "IsCritical", "Control"]),
        #
        'ldap_parse_sort_controlA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExternalHandle", "Control", "Result", "Attribute"]),
        #
        'ldap_parse_sort_controlW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExternalHandle", "Control", "Result", "Attribute"]),
        #
        'ldap_create_sort_control': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPSortKeyA", SimStruct), offset=0), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExternalHandle", "SortKeys", "IsCritical", "Control"]),
        #
        'ldap_parse_sort_control': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExternalHandle", "Control", "Result", "Attribute"]),
        #
        'ldap_encode_sort_controlW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPSortKeyW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExternalHandle", "SortKeys", "Control", "Criticality"]),
        #
        'ldap_encode_sort_controlA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPSortKeyA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExternalHandle", "SortKeys", "Control", "Criticality"]),
        #
        'ldap_create_page_controlW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExternalHandle", "PageSize", "Cookie", "IsCritical", "Control"]),
        #
        'ldap_create_page_controlA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExternalHandle", "PageSize", "Cookie", "IsCritical", "Control"]),
        #
        'ldap_parse_page_controlW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExternalHandle", "ServerControls", "TotalCount", "Cookie"]),
        #
        'ldap_parse_page_controlA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExternalHandle", "ServerControls", "TotalCount", "Cookie"]),
        #
        'ldap_create_page_control': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExternalHandle", "PageSize", "Cookie", "IsCritical", "Control"]),
        #
        'ldap_parse_page_control': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExternalHandle", "ServerControls", "TotalCount", "Cookie"]),
        #
        'ldap_search_init_pageW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("LDAPSortKeyW", SimStruct), offset=0), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["ExternalHandle", "DistinguishedName", "ScopeOfSearch", "SearchFilter", "AttributeList", "AttributesOnly", "ServerControls", "ClientControls", "PageTimeLimit", "TotalSizeLimit", "SortKeys"]),
        #
        'ldap_search_init_pageA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("LDAPSortKeyA", SimStruct), offset=0), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["ExternalHandle", "DistinguishedName", "ScopeOfSearch", "SearchFilter", "AttributeList", "AttributesOnly", "ServerControls", "ClientControls", "PageTimeLimit", "TotalSizeLimit", "SortKeys"]),
        #
        'ldap_search_init_page': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("LDAPSortKeyA", SimStruct), offset=0), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["ExternalHandle", "DistinguishedName", "ScopeOfSearch", "SearchFilter", "AttributeList", "AttributesOnly", "ServerControls", "ClientControls", "PageTimeLimit", "TotalSizeLimit", "SortKeys"]),
        #
        'ldap_get_next_page': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExternalHandle", "SearchHandle", "PageSize", "MessageNumber"]),
        #
        'ldap_get_next_page_s': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("LDAP_TIMEVAL", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExternalHandle", "SearchHandle", "timeout", "PageSize", "TotalCount", "Results"]),
        #
        'ldap_get_paged_count': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExternalHandle", "SearchBlock", "TotalCount", "Results"]),
        #
        'ldap_search_abandon_page': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExternalHandle", "SearchBlock"]),
        #
        'ldap_create_vlv_controlW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeRef("LDAPVLVInfo", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ExternalHandle", "VlvInfo", "IsCritical", "Control"]),
        #
        'ldap_create_vlv_controlA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeRef("LDAPVLVInfo", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ExternalHandle", "VlvInfo", "IsCritical", "Control"]),
        #
        'ldap_parse_vlv_controlW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ExternalHandle", "Control", "TargetPos", "ListCount", "Context", "ErrCode"]),
        #
        'ldap_parse_vlv_controlA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ExternalHandle", "Control", "TargetPos", "ListCount", "Context", "ErrCode"]),
        #
        'ldap_start_tls_sW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExternalHandle", "ServerReturnValue", "result", "ServerControls", "ClientControls"]),
        #
        'ldap_start_tls_sA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExternalHandle", "ServerReturnValue", "result", "ServerControls", "ClientControls"]),
        #
        'ldap_stop_tls_s': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["ExternalHandle"]),
        #
        'ldap_first_reference': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0)], SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0), arg_names=["ld", "res"]),
        #
        'ldap_next_reference': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0)], SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0), arg_names=["ld", "entry"]),
        #
        'ldap_count_references': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "res"]),
        #
        'ldap_parse_referenceW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Connection", "ResultMessage", "Referrals"]),
        #
        'ldap_parse_referenceA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Connection", "ResultMessage", "Referrals"]),
        #
        'ldap_parse_reference': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Connection", "ResultMessage", "Referrals"]),
        #
        'ldap_extended_operationW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "Oid", "Data", "ServerControls", "ClientControls", "MessageNumber"]),
        #
        'ldap_extended_operationA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "Oid", "Data", "ServerControls", "ClientControls", "MessageNumber"]),
        #
        'ldap_extended_operation_sA': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExternalHandle", "Oid", "Data", "ServerControls", "ClientControls", "ReturnedOid", "ReturnedData"]),
        #
        'ldap_extended_operation_sW': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExternalHandle", "Oid", "Data", "ServerControls", "ClientControls", "ReturnedOid", "ReturnedData"]),
        #
        'ldap_extended_operation': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAPControlA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "Oid", "Data", "ServerControls", "ClientControls", "MessageNumber"]),
        #
        'ldap_close_extended_op': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ld", "MessageNumber"]),
        #
        'LdapGetLastError': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'LdapMapErrorToWin32': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["LdapError"]),
        #
        'ldap_conn_from_msg': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), SimTypePointer(SimTypeRef("LDAPMessage", SimStruct), offset=0)], SimTypePointer(SimTypeRef("LDAP", SimStruct), offset=0), arg_names=["PrimaryConn", "res"]),
        #
        'ber_init': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0)], SimTypePointer(SimTypeRef("BerElement", SimStruct), offset=0), arg_names=["pBerVal"]),
        #
        'ber_free': SimTypeFunction([SimTypePointer(SimTypeRef("BerElement", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["pBerElement", "fbuf"]),
        #
        'ber_bvecfree': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["pBerVal"]),
        #
        'ber_bvdup': SimTypeFunction([SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0)], SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0), arg_names=["pBerVal"]),
        #
        'ber_alloc_t': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeRef("BerElement", SimStruct), offset=0), arg_names=["options"]),
        #
        'ber_skip_tag': SimTypeFunction([SimTypePointer(SimTypeRef("BerElement", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pBerElement", "pLen"]),
        #
        'ber_peek_tag': SimTypeFunction([SimTypePointer(SimTypeRef("BerElement", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pBerElement", "pLen"]),
        #
        'ber_first_element': SimTypeFunction([SimTypePointer(SimTypeRef("BerElement", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pBerElement", "pLen", "ppOpaque"]),
        #
        'ber_next_element': SimTypeFunction([SimTypePointer(SimTypeRef("BerElement", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pBerElement", "pLen", "opaque"]),
        #
        'ber_flatten': SimTypeFunction([SimTypePointer(SimTypeRef("BerElement", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LDAP_BERVAL", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pBerElement", "pBerVal"]),
        #
        'ber_printf': SimTypeFunction([SimTypePointer(SimTypeRef("BerElement", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pBerElement", "fmt"]),
        #
        'ber_scanf': SimTypeFunction([SimTypePointer(SimTypeRef("BerElement", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pBerElement", "fmt"]),
    }

lib.set_prototypes(prototypes)
