# pylint:disable=unused-argument,no-self-use
from __future__ import annotations
from itertools import count

from bisa import sim_type
from bisa.sim_type import SimType
from . import typeconsts
from .typeconsts import TypeConstant


class SimTypeTempRef(sim_type.SimType):
    """
    Represents a temporary reference to another type. TypeVariableReference is translated to SimTypeTempRef.
    """

    def __init__(self, typevar):
        super().__init__()
        self.typevar = typevar

    def c_repr(self, **kwargs):
        return "<SimTypeTempRef>"


class TypeTranslator:
    """
    Translate type variables to SimType equivalence.
    """

    def __init__(self, arch=None):
        self.arch = arch

        self.translated: dict[TypeConstant, SimType] = {}
        self.translated_simtypes: dict[SimType, TypeConstant] = {}
        self.structs = {}
        self._struct_ctr = count()

        # will be updated every time .translate() is called
        self._has_nonexistent_ref = False

    #
    # Naming
    #

    def struct_name(self):
        return f"struct_{next(self._struct_ctr)}"

    #
    # Type translation
    #

    def tc2simtype(self, tc):
        self._has_nonexistent_ref = False
        return self._tc2simtype(tc), self._has_nonexistent_ref

    def _tc2simtype(self, tc):
        if tc is None:
            return sim_type.SimTypeBottom().with_arch(self.arch)

        try:
            handler = TypeConstHandlers[tc.__class__]
        except KeyError:
            return sim_type.SimTypeBottom().with_arch(self.arch)

        return handler(self, tc)

    def simtype2tc(self, simtype: sim_type.SimType) -> typeconsts.TypeConstant:
        return self._simtype2tc(simtype)

    def _simtype2tc(self, simtype: sim_type.SimType) -> typeconsts.TypeConstant:
        if simtype in self.translated_simtypes:
            return self.translated_simtypes[simtype]
        try:
            handler = SimTypeHandlers[simtype.__class__]
            return handler(self, simtype)
        except KeyError:
            return typeconsts.BottomType()

    #
    # Typehoon type handlers
    #

    def _translate_Pointer64(self, tc):
        if isinstance(tc.basetype, typeconsts.BottomType):
            # void *
            internal = sim_type.SimTypeBottom(label="void").with_arch(self.arch)
        else:
            internal = self._tc2simtype(tc.basetype)
        return sim_type.SimTypePointer(internal).with_arch(self.arch)

    def _translate_Pointer32(self, tc):
        if isinstance(tc.basetype, typeconsts.BottomType):
            # void *
            internal = sim_type.SimTypeBottom(label="void").with_arch(self.arch)
        else:
            internal = self._tc2simtype(tc.basetype)
        return sim_type.SimTypePointer(internal).with_arch(self.arch)

    def _translate_Array(self, tc: typeconsts.Array) -> sim_type.SimTypeArray:
        elem_type = self._tc2simtype(tc.element)
        return sim_type.SimTypeArray(elem_type, length=tc.count).with_arch(self.arch)

    def _translate_Struct(self, tc: typeconsts.Struct):
        if tc in self.structs:
            return self.structs[tc]

        name = tc.name if tc.name else self.struct_name()

        if tc.is_cppclass:
            s = sim_type.SimCppClass(name=name).with_arch(self.arch)
        else:
            s = sim_type.SimStruct({}, name=name).with_arch(self.arch)
        self.structs[tc] = s

        next_offset = 0
        for offset, typ in sorted(tc.fields.items(), key=lambda item: item[0]):
            if offset > next_offset:
                # we need padding!
                padding_size = offset - next_offset
                s.fields[f"padding_{next_offset:x}"] = sim_type.SimTypeFixedSizeArray(
                    sim_type.SimTypeChar(signed=False).with_arch(self.arch), padding_size
                ).with_arch(self.arch)

            translated_type = self._tc2simtype(typ)
            if isinstance(translated_type, sim_type.SimTypeBottom):
                # we cannot have bottom types in a struct since that would mess with offsets of all future types
                # for now, we replace it with an unsigned char
                translated_type = sim_type.SimTypeChar(signed=False).with_arch(self.arch)

            field_name = tc.field_names[offset] if tc.field_names and offset in tc.field_names else f"field_{offset:x}"
            s.fields[field_name] = translated_type

            if isinstance(translated_type, SimTypeTempRef):
                next_offset = self.arch.bytes + offset
            else:
                next_offset = translated_type.size // self.arch.byte_width + offset

        return s

    def _translate_Int8(self, tc):  # pylint:disable=unused-argument
        return sim_type.SimTypeChar(signed=False).with_arch(self.arch)

    def _translate_Int16(self, tc):  # pylint:disable=unused-argument
        return sim_type.SimTypeShort(signed=False).with_arch(self.arch)

    def _translate_Int32(self, tc):  # pylint:disable=unused-argument
        return sim_type.SimTypeInt(signed=False).with_arch(self.arch)

    def _translate_Int64(self, tc):  # pylint:disable=unused-argument
        return sim_type.SimTypeLongLong(signed=False).with_arch(self.arch)

    def _translate_Int128(self, tc):  # pylint:disable=unused-argument
        return sim_type.SimTypeInt128(signed=False).with_arch(self.arch)

    def _translate_Int256(self, tc):  # pylint:disable=unused-argument
        return sim_type.SimTypeInt256(signed=False).with_arch(self.arch)

    def _translate_Int512(self, tc):  # pylint:disable=unused-argument
        return sim_type.SimTypeInt512(signed=False).with_arch(self.arch)

    def _translate_TypeVariableReference(self, tc):
        if tc.typevar in self.translated:
            return self.translated[tc.typevar]

        self._has_nonexistent_ref = True
        return SimTypeTempRef(tc.typevar)

    def _translate_Float32(self, tc: typeconsts.Float32) -> sim_type.SimTypeFloat:  # pylint:disable=unused-argument
        return sim_type.SimTypeFloat().with_arch(self.arch)

    def _translate_Float64(self, tc: typeconsts.Float64) -> sim_type.SimTypeDouble:  # pylint:disable=unused-argument
        return sim_type.SimTypeDouble().with_arch(self.arch)

    #
    # Backpatching
    #

    def backpatch(self, st, translated):
        """

        :param sim_type.SimType st:
        :param dict translated:
        :return:
        """

        if isinstance(st, sim_type.SimTypePointer):
            self.backpatch(st.pts_to, translated)

        elif isinstance(st, sim_type.SimStruct):
            fields_patch = {}
            for offset, fld in st.fields.items():
                if isinstance(fld, SimTypeTempRef) and fld.typevar in translated:
                    fields_patch[offset] = translated[fld.typevar]
                st.fields.update(fields_patch)

    #
    # SimType handlers
    #

    def _translate_SimTypeInt128(self, st: sim_type.SimTypeChar) -> typeconsts.Int128:
        return typeconsts.Int128()

    def _translate_SimTypeInt256(self, st: sim_type.SimTypeChar) -> typeconsts.Int256:
        return typeconsts.Int256()

    def _translate_SimTypeInt512(self, st: sim_type.SimTypeChar) -> typeconsts.Int512:
        return typeconsts.Int512()

    def _translate_SimTypeInt(self, st: sim_type.SimTypeInt) -> typeconsts.Int32:
        return typeconsts.Int32()

    def _translate_SimTypeLong(self, st: sim_type.SimTypeLong) -> typeconsts.Int32:
        return typeconsts.Int32()

    def _translate_SimTypeLongLong(self, st: sim_type.SimTypeLongLong) -> typeconsts.Int64:
        return typeconsts.Int64()

    def _translate_SimTypeChar(self, st: sim_type.SimTypeChar) -> typeconsts.Int8:
        return typeconsts.Int8()

    def _translate_SimStruct(self, st: sim_type.SimStruct) -> typeconsts.Struct:
        fields = {}
        offsets = st.offsets
        for name, ty in st.fields.items():
            offset = offsets[name]
            fields[offset] = self._simtype2tc(ty)

        return typeconsts.Struct(fields=fields)

    def _translate_SimTypeArray(self, st: sim_type.SimTypeArray) -> typeconsts.Array:
        elem_type = self._simtype2tc(st.elem_type)
        return typeconsts.Array(elem_type, count=st.length)

    def _translate_SimTypePointer(self, st: sim_type.SimTypePointer) -> typeconsts.Pointer32 | typeconsts.Pointer64:
        base = self._simtype2tc(st.pts_to)
        if self.arch.bits == 32:
            return typeconsts.Pointer32(base)
        if self.arch.bits == 64:
            return typeconsts.Pointer64(base)
        raise TypeError(f"Unsupported pointer size {self.arch.bits}")

    def _translate_SimTypeFloat(self, st: sim_type.SimTypeFloat) -> typeconsts.Float32:
        return typeconsts.Float32()

    def _translate_SimTypeDouble(self, st: sim_type.SimTypeDouble) -> typeconsts.Float64:
        return typeconsts.Float64()


TypeConstHandlers = {
    typeconsts.Pointer64: TypeTranslator._translate_Pointer64,
    typeconsts.Pointer32: TypeTranslator._translate_Pointer32,
    typeconsts.Array: TypeTranslator._translate_Array,
    typeconsts.Struct: TypeTranslator._translate_Struct,
    typeconsts.Int8: TypeTranslator._translate_Int8,
    typeconsts.Int16: TypeTranslator._translate_Int16,
    typeconsts.Int32: TypeTranslator._translate_Int32,
    typeconsts.Int64: TypeTranslator._translate_Int64,
    typeconsts.Int128: TypeTranslator._translate_Int128,
    typeconsts.Int256: TypeTranslator._translate_Int256,
    typeconsts.Int512: TypeTranslator._translate_Int512,
    typeconsts.TypeVariableReference: TypeTranslator._translate_TypeVariableReference,
    typeconsts.Float32: TypeTranslator._translate_Float32,
    typeconsts.Float64: TypeTranslator._translate_Float64,
}


SimTypeHandlers = {
    sim_type.SimTypePointer: TypeTranslator._translate_SimTypePointer,
    sim_type.SimTypeInt: TypeTranslator._translate_SimTypeInt,
    sim_type.SimTypeLong: TypeTranslator._translate_SimTypeLong,
    sim_type.SimTypeLongLong: TypeTranslator._translate_SimTypeLongLong,
    sim_type.SimTypeChar: TypeTranslator._translate_SimTypeChar,
    sim_type.SimTypeInt128: TypeTranslator._translate_SimTypeInt128,
    sim_type.SimTypeInt256: TypeTranslator._translate_SimTypeInt256,
    sim_type.SimTypeInt512: TypeTranslator._translate_SimTypeInt512,
    sim_type.SimStruct: TypeTranslator._translate_SimStruct,
    sim_type.SimTypeArray: TypeTranslator._translate_SimTypeArray,
    sim_type.SimTypeFloat: TypeTranslator._translate_SimTypeFloat,
    sim_type.SimTypeDouble: TypeTranslator._translate_SimTypeDouble,
}
