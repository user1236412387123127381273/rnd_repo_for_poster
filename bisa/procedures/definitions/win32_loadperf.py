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
lib.set_library_names("loadperf.dll")
prototypes = \
    {
        #
        'InstallPerfDllW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szComputerName", "lpIniFile", "dwFlags"]),
        #
        'InstallPerfDllA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szComputerName", "lpIniFile", "dwFlags"]),
        #
        'LoadPerfCounterTextStringsA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpCommandLine", "bQuietModeArg"]),
        #
        'LoadPerfCounterTextStringsW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpCommandLine", "bQuietModeArg"]),
        #
        'UnloadPerfCounterTextStringsW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpCommandLine", "bQuietModeArg"]),
        #
        'UnloadPerfCounterTextStringsA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpCommandLine", "bQuietModeArg"]),
        #
        'UpdatePerfNameFilesA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szNewCtrFilePath", "szNewHlpFilePath", "szLanguageID", "dwFlags"]),
        #
        'UpdatePerfNameFilesW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szNewCtrFilePath", "szNewHlpFilePath", "szLanguageID", "dwFlags"]),
        #
        'SetServiceAsTrustedA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szReserved", "szServiceName"]),
        #
        'SetServiceAsTrustedW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szReserved", "szServiceName"]),
        #
        'BackupPerfRegistryToFileW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szFileName", "szCommentString"]),
        #
        'RestorePerfRegistryFromFileW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szFileName", "szLangId"]),
    }

lib.set_prototypes(prototypes)
