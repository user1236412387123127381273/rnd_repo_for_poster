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
lib.set_library_names("msi.dll")
prototypes = \
    {
        #
        'MsiCloseHandle': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hAny"]),
        #
        'MsiCloseAllHandles': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'MsiSetInternalUI': SimTypeFunction([SimTypeInt(signed=False, label="INSTALLUILEVEL"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="INSTALLUILEVEL"), arg_names=["dwUILevel", "phWnd"]),
        #
        'MsiSetExternalUIA': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvContext", "iMessageType", "szMessage"]), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvContext", "iMessageType", "szMessage"]), offset=0), arg_names=["puiHandler", "dwMessageFilter", "pvContext"]),
        #
        'MsiSetExternalUIW': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvContext", "iMessageType", "szMessage"]), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvContext", "iMessageType", "szMessage"]), offset=0), arg_names=["puiHandler", "dwMessageFilter", "pvContext"]),
        #
        'MsiSetExternalUIRecord': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pvContext", "iMessageType", "hRecord"]), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pvContext", "iMessageType", "hRecord"]), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["puiHandler", "dwMessageFilter", "pvContext", "ppuiPrevHandler"]),
        #
        'MsiEnableLogA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwLogMode", "szLogFile", "dwLogAttributes"]),
        #
        'MsiEnableLogW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwLogMode", "szLogFile", "dwLogAttributes"]),
        #
        'MsiQueryProductStateA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="INSTALLSTATE"), arg_names=["szProduct"]),
        #
        'MsiQueryProductStateW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="INSTALLSTATE"), arg_names=["szProduct"]),
        #
        'MsiGetProductInfoA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProduct", "szAttribute", "lpValueBuf", "pcchValueBuf"]),
        #
        'MsiGetProductInfoW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProduct", "szAttribute", "lpValueBuf", "pcchValueBuf"]),
        #
        'MsiGetProductInfoExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProductCode", "szUserSid", "dwContext", "szProperty", "szValue", "pcchValue"]),
        #
        'MsiGetProductInfoExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProductCode", "szUserSid", "dwContext", "szProperty", "szValue", "pcchValue"]),
        #
        'MsiInstallProductA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szPackagePath", "szCommandLine"]),
        #
        'MsiInstallProductW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szPackagePath", "szCommandLine"]),
        #
        'MsiConfigureProductA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="INSTALLLEVEL"), SimTypeInt(signed=False, label="INSTALLSTATE")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProduct", "iInstallLevel", "eInstallState"]),
        #
        'MsiConfigureProductW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="INSTALLLEVEL"), SimTypeInt(signed=False, label="INSTALLSTATE")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProduct", "iInstallLevel", "eInstallState"]),
        #
        'MsiConfigureProductExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="INSTALLLEVEL"), SimTypeInt(signed=False, label="INSTALLSTATE"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProduct", "iInstallLevel", "eInstallState", "szCommandLine"]),
        #
        'MsiConfigureProductExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="INSTALLLEVEL"), SimTypeInt(signed=False, label="INSTALLSTATE"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProduct", "iInstallLevel", "eInstallState", "szCommandLine"]),
        #
        'MsiReinstallProductA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProduct", "szReinstallMode"]),
        #
        'MsiReinstallProductW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProduct", "szReinstallMode"]),
        #
        'MsiAdvertiseProductExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szPackagePath", "szScriptfilePath", "szTransforms", "lgidLanguage", "dwPlatform", "dwOptions"]),
        #
        'MsiAdvertiseProductExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szPackagePath", "szScriptfilePath", "szTransforms", "lgidLanguage", "dwPlatform", "dwOptions"]),
        #
        'MsiAdvertiseProductA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szPackagePath", "szScriptfilePath", "szTransforms", "lgidLanguage"]),
        #
        'MsiAdvertiseProductW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szPackagePath", "szScriptfilePath", "szTransforms", "lgidLanguage"]),
        #
        'MsiProcessAdvertiseScriptA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szScriptFile", "szIconFolder", "hRegData", "fShortcuts", "fRemoveItems"]),
        #
        'MsiProcessAdvertiseScriptW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szScriptFile", "szIconFolder", "hRegData", "fShortcuts", "fRemoveItems"]),
        #
        'MsiAdvertiseScriptA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szScriptFile", "dwFlags", "phRegData", "fRemoveItems"]),
        #
        'MsiAdvertiseScriptW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szScriptFile", "dwFlags", "phRegData", "fRemoveItems"]),
        #
        'MsiGetProductInfoFromScriptA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szScriptFile", "lpProductBuf39", "plgidLanguage", "pdwVersion", "lpNameBuf", "pcchNameBuf", "lpPackageBuf", "pcchPackageBuf"]),
        #
        'MsiGetProductInfoFromScriptW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szScriptFile", "lpProductBuf39", "plgidLanguage", "pdwVersion", "lpNameBuf", "pcchNameBuf", "lpPackageBuf", "pcchPackageBuf"]),
        #
        'MsiGetProductCodeA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szComponent", "lpBuf39"]),
        #
        'MsiGetProductCodeW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szComponent", "lpBuf39"]),
        #
        'MsiGetUserInfoA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="USERINFOSTATE"), arg_names=["szProduct", "lpUserNameBuf", "pcchUserNameBuf", "lpOrgNameBuf", "pcchOrgNameBuf", "lpSerialBuf", "pcchSerialBuf"]),
        #
        'MsiGetUserInfoW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="USERINFOSTATE"), arg_names=["szProduct", "lpUserNameBuf", "pcchUserNameBuf", "lpOrgNameBuf", "pcchOrgNameBuf", "lpSerialBuf", "pcchSerialBuf"]),
        #
        'MsiCollectUserInfoA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProduct"]),
        #
        'MsiCollectUserInfoW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProduct"]),
        #
        'MsiApplyPatchA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="INSTALLTYPE"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szPatchPackage", "szInstallPackage", "eInstallType", "szCommandLine"]),
        #
        'MsiApplyPatchW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="INSTALLTYPE"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szPatchPackage", "szInstallPackage", "eInstallType", "szCommandLine"]),
        #
        'MsiGetPatchInfoA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szPatch", "szAttribute", "lpValueBuf", "pcchValueBuf"]),
        #
        'MsiGetPatchInfoW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szPatch", "szAttribute", "lpValueBuf", "pcchValueBuf"]),
        #
        'MsiEnumPatchesA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProduct", "iPatchIndex", "lpPatchBuf", "lpTransformsBuf", "pcchTransformsBuf"]),
        #
        'MsiEnumPatchesW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProduct", "iPatchIndex", "lpPatchBuf", "lpTransformsBuf", "pcchTransformsBuf"]),
        #
        'MsiRemovePatchesA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="INSTALLTYPE"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szPatchList", "szProductCode", "eUninstallType", "szPropertyList"]),
        #
        'MsiRemovePatchesW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="INSTALLTYPE"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szPatchList", "szProductCode", "eUninstallType", "szPropertyList"]),
        #
        'MsiExtractPatchXMLDataA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szPatchPath", "dwReserved", "szXMLData", "pcchXMLData"]),
        #
        'MsiExtractPatchXMLDataW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szPatchPath", "dwReserved", "szXMLData", "pcchXMLData"]),
        #
        'MsiGetPatchInfoExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szPatchCode", "szProductCode", "szUserSid", "dwContext", "szProperty", "lpValue", "pcchValue"]),
        #
        'MsiGetPatchInfoExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szPatchCode", "szProductCode", "szUserSid", "dwContext", "szProperty", "lpValue", "pcchValue"]),
        #
        'MsiApplyMultiplePatchesA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szPatchPackages", "szProductCode", "szPropertiesList"]),
        #
        'MsiApplyMultiplePatchesW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szPatchPackages", "szProductCode", "szPropertiesList"]),
        #
        'MsiDeterminePatchSequenceA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MSIPATCHSEQUENCEINFOA", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProductCode", "szUserSid", "dwContext", "cPatchInfo", "pPatchInfo"]),
        #
        'MsiDeterminePatchSequenceW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MSIPATCHSEQUENCEINFOW", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProductCode", "szUserSid", "dwContext", "cPatchInfo", "pPatchInfo"]),
        #
        'MsiDetermineApplicablePatchesA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MSIPATCHSEQUENCEINFOA", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProductPackagePath", "cPatchInfo", "pPatchInfo"]),
        #
        'MsiDetermineApplicablePatchesW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MSIPATCHSEQUENCEINFOW", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProductPackagePath", "cPatchInfo", "pPatchInfo"]),
        #
        'MsiEnumPatchesExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProductCode", "szUserSid", "dwContext", "dwFilter", "dwIndex", "szPatchCode", "szTargetProductCode", "pdwTargetProductContext", "szTargetUserSid", "pcchTargetUserSid"]),
        #
        'MsiEnumPatchesExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProductCode", "szUserSid", "dwContext", "dwFilter", "dwIndex", "szPatchCode", "szTargetProductCode", "pdwTargetProductContext", "szTargetUserSid", "pcchTargetUserSid"]),
        #
        'MsiQueryFeatureStateA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="INSTALLSTATE"), arg_names=["szProduct", "szFeature"]),
        #
        'MsiQueryFeatureStateW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="INSTALLSTATE"), arg_names=["szProduct", "szFeature"]),
        #
        'MsiQueryFeatureStateExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="INSTALLSTATE"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProductCode", "szUserSid", "dwContext", "szFeature", "pdwState"]),
        #
        'MsiQueryFeatureStateExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="INSTALLSTATE"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProductCode", "szUserSid", "dwContext", "szFeature", "pdwState"]),
        #
        'MsiUseFeatureA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="INSTALLSTATE"), arg_names=["szProduct", "szFeature"]),
        #
        'MsiUseFeatureW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="INSTALLSTATE"), arg_names=["szProduct", "szFeature"]),
        #
        'MsiUseFeatureExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="INSTALLSTATE"), arg_names=["szProduct", "szFeature", "dwInstallMode", "dwReserved"]),
        #
        'MsiUseFeatureExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="INSTALLSTATE"), arg_names=["szProduct", "szFeature", "dwInstallMode", "dwReserved"]),
        #
        'MsiGetFeatureUsageA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProduct", "szFeature", "pdwUseCount", "pwDateUsed"]),
        #
        'MsiGetFeatureUsageW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProduct", "szFeature", "pdwUseCount", "pwDateUsed"]),
        #
        'MsiConfigureFeatureA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="INSTALLSTATE")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProduct", "szFeature", "eInstallState"]),
        #
        'MsiConfigureFeatureW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="INSTALLSTATE")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProduct", "szFeature", "eInstallState"]),
        #
        'MsiReinstallFeatureA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProduct", "szFeature", "dwReinstallMode"]),
        #
        'MsiReinstallFeatureW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProduct", "szFeature", "dwReinstallMode"]),
        #
        'MsiProvideComponentA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProduct", "szFeature", "szComponent", "dwInstallMode", "lpPathBuf", "pcchPathBuf"]),
        #
        'MsiProvideComponentW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProduct", "szFeature", "szComponent", "dwInstallMode", "lpPathBuf", "pcchPathBuf"]),
        #
        'MsiProvideQualifiedComponentA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szCategory", "szQualifier", "dwInstallMode", "lpPathBuf", "pcchPathBuf"]),
        #
        'MsiProvideQualifiedComponentW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szCategory", "szQualifier", "dwInstallMode", "lpPathBuf", "pcchPathBuf"]),
        #
        'MsiProvideQualifiedComponentExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szCategory", "szQualifier", "dwInstallMode", "szProduct", "dwUnused1", "dwUnused2", "lpPathBuf", "pcchPathBuf"]),
        #
        'MsiProvideQualifiedComponentExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szCategory", "szQualifier", "dwInstallMode", "szProduct", "dwUnused1", "dwUnused2", "lpPathBuf", "pcchPathBuf"]),
        #
        'MsiGetComponentPathA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="INSTALLSTATE"), arg_names=["szProduct", "szComponent", "lpPathBuf", "pcchBuf"]),
        #
        'MsiGetComponentPathW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="INSTALLSTATE"), arg_names=["szProduct", "szComponent", "lpPathBuf", "pcchBuf"]),
        #
        'MsiGetComponentPathExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="INSTALLSTATE"), arg_names=["szProductCode", "szComponentCode", "szUserSid", "dwContext", "lpOutPathBuffer", "pcchOutPathBuffer"]),
        #
        'MsiGetComponentPathExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="INSTALLSTATE"), arg_names=["szProductCode", "szComponentCode", "szUserSid", "dwContext", "lpOutPathBuffer", "pcchOutPathBuffer"]),
        #
        'MsiProvideAssemblyA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="MSIASSEMBLYINFO"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szAssemblyName", "szAppContext", "dwInstallMode", "dwAssemblyInfo", "lpPathBuf", "pcchPathBuf"]),
        #
        'MsiProvideAssemblyW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="MSIASSEMBLYINFO"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szAssemblyName", "szAppContext", "dwInstallMode", "dwAssemblyInfo", "lpPathBuf", "pcchPathBuf"]),
        #
        'MsiQueryComponentStateA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="INSTALLSTATE"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProductCode", "szUserSid", "dwContext", "szComponentCode", "pdwState"]),
        #
        'MsiQueryComponentStateW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="INSTALLSTATE"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProductCode", "szUserSid", "dwContext", "szComponentCode", "pdwState"]),
        #
        'MsiEnumProductsA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["iProductIndex", "lpProductBuf"]),
        #
        'MsiEnumProductsW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["iProductIndex", "lpProductBuf"]),
        #
        'MsiEnumProductsExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProductCode", "szUserSid", "dwContext", "dwIndex", "szInstalledProductCode", "pdwInstalledContext", "szSid", "pcchSid"]),
        #
        'MsiEnumProductsExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProductCode", "szUserSid", "dwContext", "dwIndex", "szInstalledProductCode", "pdwInstalledContext", "szSid", "pcchSid"]),
        #
        'MsiEnumRelatedProductsA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpUpgradeCode", "dwReserved", "iProductIndex", "lpProductBuf"]),
        #
        'MsiEnumRelatedProductsW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpUpgradeCode", "dwReserved", "iProductIndex", "lpProductBuf"]),
        #
        'MsiEnumFeaturesA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProduct", "iFeatureIndex", "lpFeatureBuf", "lpParentBuf"]),
        #
        'MsiEnumFeaturesW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProduct", "iFeatureIndex", "lpFeatureBuf", "lpParentBuf"]),
        #
        'MsiEnumComponentsA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["iComponentIndex", "lpComponentBuf"]),
        #
        'MsiEnumComponentsW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["iComponentIndex", "lpComponentBuf"]),
        #
        'MsiEnumComponentsExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szUserSid", "dwContext", "dwIndex", "szInstalledComponentCode", "pdwInstalledContext", "szSid", "pcchSid"]),
        #
        'MsiEnumComponentsExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szUserSid", "dwContext", "dwIndex", "szInstalledComponentCode", "pdwInstalledContext", "szSid", "pcchSid"]),
        #
        'MsiEnumClientsA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szComponent", "iProductIndex", "lpProductBuf"]),
        #
        'MsiEnumClientsW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szComponent", "iProductIndex", "lpProductBuf"]),
        #
        'MsiEnumClientsExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szComponent", "szUserSid", "dwContext", "dwProductIndex", "szProductBuf", "pdwInstalledContext", "szSid", "pcchSid"]),
        #
        'MsiEnumClientsExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szComponent", "szUserSid", "dwContext", "dwProductIndex", "szProductBuf", "pdwInstalledContext", "szSid", "pcchSid"]),
        #
        'MsiEnumComponentQualifiersA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szComponent", "iIndex", "lpQualifierBuf", "pcchQualifierBuf", "lpApplicationDataBuf", "pcchApplicationDataBuf"]),
        #
        'MsiEnumComponentQualifiersW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szComponent", "iIndex", "lpQualifierBuf", "pcchQualifierBuf", "lpApplicationDataBuf", "pcchApplicationDataBuf"]),
        #
        'MsiOpenProductA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProduct", "hProduct"]),
        #
        'MsiOpenProductW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProduct", "hProduct"]),
        #
        'MsiOpenPackageA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szPackagePath", "hProduct"]),
        #
        'MsiOpenPackageW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szPackagePath", "hProduct"]),
        #
        'MsiOpenPackageExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szPackagePath", "dwOptions", "hProduct"]),
        #
        'MsiOpenPackageExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szPackagePath", "dwOptions", "hProduct"]),
        #
        'MsiGetPatchFileListA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProductCode", "szPatchPackages", "pcFiles", "pphFileRecords"]),
        #
        'MsiGetPatchFileListW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProductCode", "szPatchPackages", "pcFiles", "pphFileRecords"]),
        #
        'MsiGetProductPropertyA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hProduct", "szProperty", "lpValueBuf", "pcchValueBuf"]),
        #
        'MsiGetProductPropertyW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hProduct", "szProperty", "lpValueBuf", "pcchValueBuf"]),
        #
        'MsiVerifyPackageA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szPackagePath"]),
        #
        'MsiVerifyPackageW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szPackagePath"]),
        #
        'MsiGetFeatureInfoA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hProduct", "szFeature", "lpAttributes", "lpTitleBuf", "pcchTitleBuf", "lpHelpBuf", "pcchHelpBuf"]),
        #
        'MsiGetFeatureInfoW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hProduct", "szFeature", "lpAttributes", "lpTitleBuf", "pcchTitleBuf", "lpHelpBuf", "pcchHelpBuf"]),
        #
        'MsiInstallMissingComponentA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="INSTALLSTATE")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProduct", "szComponent", "eInstallState"]),
        #
        'MsiInstallMissingComponentW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="INSTALLSTATE")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProduct", "szComponent", "eInstallState"]),
        #
        'MsiInstallMissingFileA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProduct", "szFile"]),
        #
        'MsiInstallMissingFileW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProduct", "szFile"]),
        #
        'MsiLocateComponentA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="INSTALLSTATE"), arg_names=["szComponent", "lpPathBuf", "pcchBuf"]),
        #
        'MsiLocateComponentW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="INSTALLSTATE"), arg_names=["szComponent", "lpPathBuf", "pcchBuf"]),
        #
        'MsiSourceListClearAllA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProduct", "szUserName", "dwReserved"]),
        #
        'MsiSourceListClearAllW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProduct", "szUserName", "dwReserved"]),
        #
        'MsiSourceListAddSourceA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProduct", "szUserName", "dwReserved", "szSource"]),
        #
        'MsiSourceListAddSourceW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProduct", "szUserName", "dwReserved", "szSource"]),
        #
        'MsiSourceListForceResolutionA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProduct", "szUserName", "dwReserved"]),
        #
        'MsiSourceListForceResolutionW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProduct", "szUserName", "dwReserved"]),
        #
        'MsiSourceListAddSourceExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProductCodeOrPatchCode", "szUserSid", "dwContext", "dwOptions", "szSource", "dwIndex"]),
        #
        'MsiSourceListAddSourceExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProductCodeOrPatchCode", "szUserSid", "dwContext", "dwOptions", "szSource", "dwIndex"]),
        #
        'MsiSourceListAddMediaDiskA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProductCodeOrPatchCode", "szUserSid", "dwContext", "dwOptions", "dwDiskId", "szVolumeLabel", "szDiskPrompt"]),
        #
        'MsiSourceListAddMediaDiskW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProductCodeOrPatchCode", "szUserSid", "dwContext", "dwOptions", "dwDiskId", "szVolumeLabel", "szDiskPrompt"]),
        #
        'MsiSourceListClearSourceA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProductCodeOrPatchCode", "szUserSid", "dwContext", "dwOptions", "szSource"]),
        #
        'MsiSourceListClearSourceW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProductCodeOrPatchCode", "szUserSid", "dwContext", "dwOptions", "szSource"]),
        #
        'MsiSourceListClearMediaDiskA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProductCodeOrPatchCode", "szUserSid", "dwContext", "dwOptions", "dwDiskId"]),
        #
        'MsiSourceListClearMediaDiskW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProductCodeOrPatchCode", "szUserSid", "dwContext", "dwOptions", "dwDiskId"]),
        #
        'MsiSourceListClearAllExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProductCodeOrPatchCode", "szUserSid", "dwContext", "dwOptions"]),
        #
        'MsiSourceListClearAllExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProductCodeOrPatchCode", "szUserSid", "dwContext", "dwOptions"]),
        #
        'MsiSourceListForceResolutionExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProductCodeOrPatchCode", "szUserSid", "dwContext", "dwOptions"]),
        #
        'MsiSourceListForceResolutionExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProductCodeOrPatchCode", "szUserSid", "dwContext", "dwOptions"]),
        #
        'MsiSourceListSetInfoA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProductCodeOrPatchCode", "szUserSid", "dwContext", "dwOptions", "szProperty", "szValue"]),
        #
        'MsiSourceListSetInfoW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProductCodeOrPatchCode", "szUserSid", "dwContext", "dwOptions", "szProperty", "szValue"]),
        #
        'MsiSourceListGetInfoA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProductCodeOrPatchCode", "szUserSid", "dwContext", "dwOptions", "szProperty", "szValue", "pcchValue"]),
        #
        'MsiSourceListGetInfoW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProductCodeOrPatchCode", "szUserSid", "dwContext", "dwOptions", "szProperty", "szValue", "pcchValue"]),
        #
        'MsiSourceListEnumSourcesA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProductCodeOrPatchCode", "szUserSid", "dwContext", "dwOptions", "dwIndex", "szSource", "pcchSource"]),
        #
        'MsiSourceListEnumSourcesW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProductCodeOrPatchCode", "szUserSid", "dwContext", "dwOptions", "dwIndex", "szSource", "pcchSource"]),
        #
        'MsiSourceListEnumMediaDisksA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProductCodeOrPatchCode", "szUserSid", "dwContext", "dwOptions", "dwIndex", "pdwDiskId", "szVolumeLabel", "pcchVolumeLabel", "szDiskPrompt", "pcchDiskPrompt"]),
        #
        'MsiSourceListEnumMediaDisksW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="MSIINSTALLCONTEXT"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProductCodeOrPatchCode", "szUserSid", "dwContext", "dwOptions", "dwIndex", "pdwDiskId", "szVolumeLabel", "pcchVolumeLabel", "szDiskPrompt", "pcchDiskPrompt"]),
        #
        'MsiGetFileVersionA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szFilePath", "lpVersionBuf", "pcchVersionBuf", "lpLangBuf", "pcchLangBuf"]),
        #
        'MsiGetFileVersionW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szFilePath", "lpVersionBuf", "pcchVersionBuf", "lpLangBuf", "pcchLangBuf"]),
        #
        'MsiGetFileHashA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MSIFILEHASHINFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szFilePath", "dwOptions", "pHash"]),
        #
        'MsiGetFileHashW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MSIFILEHASHINFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szFilePath", "dwOptions", "pHash"]),
        #
        'MsiGetFileSignatureInformationA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("CERT_CONTEXT", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["szSignedObjectPath", "dwFlags", "ppcCertContext", "pbHashData", "pcbHashData"]),
        #
        'MsiGetFileSignatureInformationW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("CERT_CONTEXT", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["szSignedObjectPath", "dwFlags", "ppcCertContext", "pbHashData", "pcbHashData"]),
        #
        'MsiGetShortcutTargetA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szShortcutPath", "szProductCode", "szFeatureId", "szComponentCode"]),
        #
        'MsiGetShortcutTargetW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szShortcutPath", "szProductCode", "szFeatureId", "szComponentCode"]),
        #
        'MsiIsProductElevatedA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProduct", "pfElevated"]),
        #
        'MsiIsProductElevatedW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szProduct", "pfElevated"]),
        #
        'MsiNotifySidChangeA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pOldSid", "pNewSid"]),
        #
        'MsiNotifySidChangeW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pOldSid", "pNewSid"]),
        #
        'MsiBeginTransactionA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szName", "dwTransactionAttributes", "phTransactionHandle", "phChangeOfOwnerEvent"]),
        #
        'MsiBeginTransactionW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szName", "dwTransactionAttributes", "phTransactionHandle", "phChangeOfOwnerEvent"]),
        #
        'MsiEndTransaction': SimTypeFunction([SimTypeInt(signed=False, label="MSITRANSACTIONSTATE")], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwTransactionState"]),
        #
        'MsiJoinTransaction': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hTransactionHandle", "dwTransactionAttributes", "phChangeOfOwnerEvent"]),
        #
        'MsiDatabaseOpenViewA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDatabase", "szQuery", "phView"]),
        #
        'MsiDatabaseOpenViewW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDatabase", "szQuery", "phView"]),
        #
        'MsiViewGetErrorA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="MSIDBERROR"), arg_names=["hView", "szColumnNameBuffer", "pcchBuf"]),
        #
        'MsiViewGetErrorW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="MSIDBERROR"), arg_names=["hView", "szColumnNameBuffer", "pcchBuf"]),
        #
        'MsiViewExecute': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hView", "hRecord"]),
        #
        'MsiViewFetch': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hView", "phRecord"]),
        #
        'MsiViewModify': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="MSIMODIFY"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hView", "eModifyMode", "hRecord"]),
        #
        'MsiViewGetColumnInfo': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="MSICOLINFO"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hView", "eColumnInfo", "phRecord"]),
        #
        'MsiViewClose': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hView"]),
        #
        'MsiDatabaseGetPrimaryKeysA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDatabase", "szTableName", "phRecord"]),
        #
        'MsiDatabaseGetPrimaryKeysW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDatabase", "szTableName", "phRecord"]),
        #
        'MsiDatabaseIsTablePersistentA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="MSICONDITION"), arg_names=["hDatabase", "szTableName"]),
        #
        'MsiDatabaseIsTablePersistentW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="MSICONDITION"), arg_names=["hDatabase", "szTableName"]),
        #
        'MsiGetSummaryInformationA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDatabase", "szDatabasePath", "uiUpdateCount", "phSummaryInfo"]),
        #
        'MsiGetSummaryInformationW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDatabase", "szDatabasePath", "uiUpdateCount", "phSummaryInfo"]),
        #
        'MsiSummaryInfoGetPropertyCount': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hSummaryInfo", "puiPropertyCount"]),
        #
        'MsiSummaryInfoSetPropertyA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hSummaryInfo", "uiProperty", "uiDataType", "iValue", "pftValue", "szValue"]),
        #
        'MsiSummaryInfoSetPropertyW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hSummaryInfo", "uiProperty", "uiDataType", "iValue", "pftValue", "szValue"]),
        #
        'MsiSummaryInfoGetPropertyA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hSummaryInfo", "uiProperty", "puiDataType", "piValue", "pftValue", "szValueBuf", "pcchValueBuf"]),
        #
        'MsiSummaryInfoGetPropertyW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hSummaryInfo", "uiProperty", "puiDataType", "piValue", "pftValue", "szValueBuf", "pcchValueBuf"]),
        #
        'MsiSummaryInfoPersist': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hSummaryInfo"]),
        #
        'MsiOpenDatabaseA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szDatabasePath", "szPersist", "phDatabase"]),
        #
        'MsiOpenDatabaseW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szDatabasePath", "szPersist", "phDatabase"]),
        #
        'MsiDatabaseImportA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDatabase", "szFolderPath", "szFileName"]),
        #
        'MsiDatabaseImportW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDatabase", "szFolderPath", "szFileName"]),
        #
        'MsiDatabaseExportA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDatabase", "szTableName", "szFolderPath", "szFileName"]),
        #
        'MsiDatabaseExportW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDatabase", "szTableName", "szFolderPath", "szFileName"]),
        #
        'MsiDatabaseMergeA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDatabase", "hDatabaseMerge", "szTableName"]),
        #
        'MsiDatabaseMergeW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDatabase", "hDatabaseMerge", "szTableName"]),
        #
        'MsiDatabaseGenerateTransformA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDatabase", "hDatabaseReference", "szTransformFile", "iReserved1", "iReserved2"]),
        #
        'MsiDatabaseGenerateTransformW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDatabase", "hDatabaseReference", "szTransformFile", "iReserved1", "iReserved2"]),
        #
        'MsiDatabaseApplyTransformA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="MSITRANSFORM_ERROR")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDatabase", "szTransformFile", "iErrorConditions"]),
        #
        'MsiDatabaseApplyTransformW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="MSITRANSFORM_ERROR")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDatabase", "szTransformFile", "iErrorConditions"]),
        #
        'MsiCreateTransformSummaryInfoA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="MSITRANSFORM_ERROR"), SimTypeInt(signed=False, label="MSITRANSFORM_VALIDATE")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDatabase", "hDatabaseReference", "szTransformFile", "iErrorConditions", "iValidation"]),
        #
        'MsiCreateTransformSummaryInfoW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="MSITRANSFORM_ERROR"), SimTypeInt(signed=False, label="MSITRANSFORM_VALIDATE")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDatabase", "hDatabaseReference", "szTransformFile", "iErrorConditions", "iValidation"]),
        #
        'MsiDatabaseCommit': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDatabase"]),
        #
        'MsiGetDatabaseState': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="MSIDBSTATE"), arg_names=["hDatabase"]),
        #
        'MsiCreateRecord': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["cParams"]),
        #
        'MsiRecordIsNull': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hRecord", "iField"]),
        #
        'MsiRecordDataSize': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hRecord", "iField"]),
        #
        'MsiRecordSetInteger': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hRecord", "iField", "iValue"]),
        #
        'MsiRecordSetStringA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hRecord", "iField", "szValue"]),
        #
        'MsiRecordSetStringW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hRecord", "iField", "szValue"]),
        #
        'MsiRecordGetInteger': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hRecord", "iField"]),
        #
        'MsiRecordGetStringA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hRecord", "iField", "szValueBuf", "pcchValueBuf"]),
        #
        'MsiRecordGetStringW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hRecord", "iField", "szValueBuf", "pcchValueBuf"]),
        #
        'MsiRecordGetFieldCount': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hRecord"]),
        #
        'MsiRecordSetStreamA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hRecord", "iField", "szFilePath"]),
        #
        'MsiRecordSetStreamW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hRecord", "iField", "szFilePath"]),
        #
        'MsiRecordReadStream': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hRecord", "iField", "szDataBuf", "pcbDataBuf"]),
        #
        'MsiRecordClearData': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hRecord"]),
        #
        'MsiGetActiveDatabase': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hInstall"]),
        #
        'MsiSetPropertyA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hInstall", "szName", "szValue"]),
        #
        'MsiSetPropertyW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hInstall", "szName", "szValue"]),
        #
        'MsiGetPropertyA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hInstall", "szName", "szValueBuf", "pcchValueBuf"]),
        #
        'MsiGetPropertyW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hInstall", "szName", "szValueBuf", "pcchValueBuf"]),
        #
        'MsiGetLanguage': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeShort(signed=False, label="UInt16"), arg_names=["hInstall"]),
        #
        'MsiGetMode': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="MSIRUNMODE")], SimTypeInt(signed=True, label="Int32"), arg_names=["hInstall", "eRunMode"]),
        #
        'MsiSetMode': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="MSIRUNMODE"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hInstall", "eRunMode", "fState"]),
        #
        'MsiFormatRecordA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hInstall", "hRecord", "szResultBuf", "pcchResultBuf"]),
        #
        'MsiFormatRecordW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hInstall", "hRecord", "szResultBuf", "pcchResultBuf"]),
        #
        'MsiDoActionA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hInstall", "szAction"]),
        #
        'MsiDoActionW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hInstall", "szAction"]),
        #
        'MsiSequenceA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hInstall", "szTable", "iSequenceMode"]),
        #
        'MsiSequenceW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hInstall", "szTable", "iSequenceMode"]),
        #
        'MsiProcessMessage': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="INSTALLMESSAGE"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hInstall", "eMessageType", "hRecord"]),
        #
        'MsiEvaluateConditionA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="MSICONDITION"), arg_names=["hInstall", "szCondition"]),
        #
        'MsiEvaluateConditionW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="MSICONDITION"), arg_names=["hInstall", "szCondition"]),
        #
        'MsiGetFeatureStateA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="INSTALLSTATE"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="INSTALLSTATE"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hInstall", "szFeature", "piInstalled", "piAction"]),
        #
        'MsiGetFeatureStateW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="INSTALLSTATE"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="INSTALLSTATE"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hInstall", "szFeature", "piInstalled", "piAction"]),
        #
        'MsiSetFeatureStateA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="INSTALLSTATE")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hInstall", "szFeature", "iState"]),
        #
        'MsiSetFeatureStateW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="INSTALLSTATE")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hInstall", "szFeature", "iState"]),
        #
        'MsiSetFeatureAttributesA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hInstall", "szFeature", "dwAttributes"]),
        #
        'MsiSetFeatureAttributesW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hInstall", "szFeature", "dwAttributes"]),
        #
        'MsiGetComponentStateA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="INSTALLSTATE"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="INSTALLSTATE"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hInstall", "szComponent", "piInstalled", "piAction"]),
        #
        'MsiGetComponentStateW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="INSTALLSTATE"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="INSTALLSTATE"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hInstall", "szComponent", "piInstalled", "piAction"]),
        #
        'MsiSetComponentStateA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="INSTALLSTATE")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hInstall", "szComponent", "iState"]),
        #
        'MsiSetComponentStateW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="INSTALLSTATE")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hInstall", "szComponent", "iState"]),
        #
        'MsiGetFeatureCostA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="MSICOSTTREE"), SimTypeInt(signed=False, label="INSTALLSTATE"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hInstall", "szFeature", "iCostTree", "iState", "piCost"]),
        #
        'MsiGetFeatureCostW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="MSICOSTTREE"), SimTypeInt(signed=False, label="INSTALLSTATE"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hInstall", "szFeature", "iCostTree", "iState", "piCost"]),
        #
        'MsiEnumComponentCostsA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="INSTALLSTATE"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hInstall", "szComponent", "dwIndex", "iState", "szDriveBuf", "pcchDriveBuf", "piCost", "piTempCost"]),
        #
        'MsiEnumComponentCostsW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="INSTALLSTATE"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hInstall", "szComponent", "dwIndex", "iState", "szDriveBuf", "pcchDriveBuf", "piCost", "piTempCost"]),
        #
        'MsiSetInstallLevel': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hInstall", "iInstallLevel"]),
        #
        'MsiGetFeatureValidStatesA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hInstall", "szFeature", "lpInstallStates"]),
        #
        'MsiGetFeatureValidStatesW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hInstall", "szFeature", "lpInstallStates"]),
        #
        'MsiGetSourcePathA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hInstall", "szFolder", "szPathBuf", "pcchPathBuf"]),
        #
        'MsiGetSourcePathW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hInstall", "szFolder", "szPathBuf", "pcchPathBuf"]),
        #
        'MsiGetTargetPathA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hInstall", "szFolder", "szPathBuf", "pcchPathBuf"]),
        #
        'MsiGetTargetPathW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hInstall", "szFolder", "szPathBuf", "pcchPathBuf"]),
        #
        'MsiSetTargetPathA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hInstall", "szFolder", "szFolderPath"]),
        #
        'MsiSetTargetPathW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hInstall", "szFolder", "szFolderPath"]),
        #
        'MsiVerifyDiskSpace': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hInstall"]),
        #
        'MsiEnableUIPreview': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDatabase", "phPreview"]),
        #
        'MsiPreviewDialogA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hPreview", "szDialogName"]),
        #
        'MsiPreviewDialogW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hPreview", "szDialogName"]),
        #
        'MsiPreviewBillboardA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hPreview", "szControlName", "szBillboard"]),
        #
        'MsiPreviewBillboardW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hPreview", "szControlName", "szBillboard"]),
        #
        'MsiGetLastErrorRecord': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
    }

lib.set_prototypes(prototypes)
