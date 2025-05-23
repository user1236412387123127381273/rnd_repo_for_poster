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
lib.set_library_names("t2embed.dll")
prototypes = \
    {
        #
        'TTEmbedFont': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TTEMBED_FLAGS"), SimTypeInt(signed=False, label="EMBED_FONT_CHARSET"), SimTypePointer(SimTypeInt(signed=False, label="EMBEDDED_FONT_PRIV_STATUS"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), label="LPArray", offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("TTEMBEDINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hDC", "ulFlags", "ulCharSet", "pulPrivStatus", "pulStatus", "lpfnWriteToStream", "lpvWriteStream", "pusCharCodeSet", "usCharCodeCount", "usLanguage", "pTTEmbedInfo"]),
        #
        'TTEmbedFontFromFileA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypeInt(signed=False, label="TTEMBED_FLAGS"), SimTypeInt(signed=False, label="EMBED_FONT_CHARSET"), SimTypePointer(SimTypeInt(signed=False, label="EMBEDDED_FONT_PRIV_STATUS"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), label="LPArray", offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("TTEMBEDINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hDC", "szFontFileName", "usTTCIndex", "ulFlags", "ulCharSet", "pulPrivStatus", "pulStatus", "lpfnWriteToStream", "lpvWriteStream", "pusCharCodeSet", "usCharCodeCount", "usLanguage", "pTTEmbedInfo"]),
        #
        'TTLoadEmbeddedFont': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="EMBEDDED_FONT_PRIV_STATUS"), offset=0), SimTypeInt(signed=False, label="FONT_LICENSE_PRIVS"), SimTypePointer(SimTypeInt(signed=False, label="TTLOAD_EMBEDDED_FONT_STATUS"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("TTLOADINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["phFontReference", "ulFlags", "pulPrivStatus", "ulPrivs", "pulStatus", "lpfnReadFromStream", "lpvReadStream", "szWinFamilyName", "szMacFamilyName", "pTTLoadInfo"]),
        #
        'TTGetEmbeddedFontInfo': SimTypeFunction([SimTypeInt(signed=False, label="TTEMBED_FLAGS"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="FONT_LICENSE_PRIVS"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("TTLOADINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ulFlags", "pulPrivStatus", "ulPrivs", "pulStatus", "lpfnReadFromStream", "lpvReadStream", "pTTLoadInfo"]),
        #
        'TTDeleteEmbeddedFont': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFontReference", "ulFlags", "pulStatus"]),
        #
        'TTGetEmbeddingType': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="EMBEDDED_FONT_PRIV_STATUS"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hDC", "pulEmbedType"]),
        #
        'TTCharToUnicode': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hDC", "pucCharCodes", "ulCharCodeSize", "pusShortCodes", "ulShortCodeSize", "ulFlags"]),
        #
        'TTRunValidationTests': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("TTVALIDATIONTESTSPARAMS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hDC", "pTestParam"]),
        #
        'TTIsEmbeddingEnabled': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hDC", "pbEnabled"]),
        #
        'TTIsEmbeddingEnabledForFacename': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszFacename", "pbEnabled"]),
        #
        'TTEnableEmbeddingForFacename': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszFacename", "bEnable"]),
        #
        'TTEmbedFontEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TTEMBED_FLAGS"), SimTypeInt(signed=False, label="EMBED_FONT_CHARSET"), SimTypePointer(SimTypeInt(signed=False, label="EMBEDDED_FONT_PRIV_STATUS"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("TTEMBEDINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hDC", "ulFlags", "ulCharSet", "pulPrivStatus", "pulStatus", "lpfnWriteToStream", "lpvWriteStream", "pulCharCodeSet", "usCharCodeCount", "usLanguage", "pTTEmbedInfo"]),
        #
        'TTRunValidationTestsEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("TTVALIDATIONTESTSPARAMSEX", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hDC", "pTestParam"]),
        #
        'TTGetNewFontName': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["phFontReference", "wzWinFamilyName", "cchMaxWinName", "szMacFamilyName", "cchMaxMacName"]),
    }

lib.set_prototypes(prototypes)
