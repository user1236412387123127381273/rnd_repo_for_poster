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
lib.set_library_names("wdsclientapi.dll")
prototypes = \
    {
        #
        'WdsCliClose': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Handle"]),
        #
        'WdsCliRegisterTrace': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pwszFormat", "Params"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pfn"]),
        #
        'WdsCliFreeStringArray': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ppwszArray", "ulCount"]),
        #
        'WdsCliFindFirstImage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSession", "phFindHandle"]),
        #
        'WdsCliFindNextImage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Handle"]),
        #
        'WdsCliGetEnumerationFlags': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Handle", "pdwFlags"]),
        #
        'WdsCliGetImageHandleFromFindHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FindHandle", "phImageHandle"]),
        #
        'WdsCliGetImageHandleFromTransferHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTransfer", "phImageHandle"]),
        #
        'WdsCliCreateSession': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("WDS_CLI_CRED", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwszServer", "pCred", "phSession"]),
        #
        'WdsCliAuthorizeSession': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("WDS_CLI_CRED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSession", "pCred"]),
        #
        'WdsCliInitializeLog': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="CPU_ARCHITECTURE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSession", "ulClientArchitecture", "pwszClientId", "pwszClientAddress"]),
        #
        'WdsCliLog': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hSession", "ulLogLevel", "ulMessageCode"]),
        #
        'WdsCliGetImageName': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hIfh", "ppwszValue"]),
        #
        'WdsCliGetImageDescription': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hIfh", "ppwszValue"]),
        #
        'WdsCliGetImageType': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="WDS_CLI_IMAGE_TYPE"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hIfh", "pImageType"]),
        #
        'WdsCliGetImageFiles': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hIfh", "pppwszFiles", "pdwCount"]),
        #
        'WdsCliGetImageLanguage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hIfh", "ppwszValue"]),
        #
        'WdsCliGetImageLanguages': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hIfh", "pppszValues", "pdwNumValues"]),
        #
        'WdsCliGetImageVersion': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hIfh", "ppwszValue"]),
        #
        'WdsCliGetImagePath': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hIfh", "ppwszValue"]),
        #
        'WdsCliGetImageIndex': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hIfh", "pdwValue"]),
        #
        'WdsCliGetImageArchitecture': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="CPU_ARCHITECTURE"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hIfh", "pdwValue"]),
        #
        'WdsCliGetImageLastModifiedTime': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SYSTEMTIME", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hIfh", "ppSysTimeValue"]),
        #
        'WdsCliGetImageSize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hIfh", "pullValue"]),
        #
        'WdsCliGetImageHalName': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hIfh", "ppwszValue"]),
        #
        'WdsCliGetImageGroup': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hIfh", "ppwszValue"]),
        #
        'WdsCliGetImageNamespace': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hIfh", "ppwszValue"]),
        #
        'WdsCliGetImageParameter': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="WDS_CLI_IMAGE_PARAM_TYPE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hIfh", "ParamType", "pResponse", "uResponseLen"]),
        #
        'WdsCliGetTransferSize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hIfh", "pullValue"]),
        #
        'WdsCliSetTransferBufferSize': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["ulSizeInBytes"]),
        #
        'WdsCliTransferImage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="PFN_WDS_CLI_CALLBACK_MESSAGE_ID"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["dwMessageId", "wParam", "lParam", "pvUserData"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hImage", "pwszLocalPath", "dwFlags", "dwReserved", "pfnWdsCliCallback", "pvUserData", "phTransfer"]),
        #
        'WdsCliTransferFile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="PFN_WDS_CLI_CALLBACK_MESSAGE_ID"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["dwMessageId", "wParam", "lParam", "pvUserData"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwszServer", "pwszNamespace", "pwszRemoteFilePath", "pwszLocalFilePath", "dwFlags", "dwReserved", "pfnWdsCliCallback", "pvUserData", "phTransfer"]),
        #
        'WdsCliCancelTransfer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTransfer"]),
        #
        'WdsCliWaitForTransfer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTransfer"]),
        #
        'WdsCliObtainDriverPackages': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hImage", "ppwszServerName", "pppwszDriverPackages", "pulCount"]),
        #
        'WdsCliObtainDriverPackagesEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSession", "pwszMachineInfo", "ppwszServerName", "pppwszDriverPackages", "pulCount"]),
        #
        'WdsCliGetDriverQueryXml': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwszWinDirPath", "ppwszDriverQuery"]),
    }

lib.set_prototypes(prototypes)
