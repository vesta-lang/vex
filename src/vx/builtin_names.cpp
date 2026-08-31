/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vx/builtin_names.cpp
 * @brief La tabla plana de nombres de builtin y su busqueda.
 *
 * La tabla queda en `.rodata`: nombre, longitud e identificador, contiguos,
 * sin punteros que perseguir mas alla del texto.  El orden
 * es por longitud y luego por bytes -- el mismo que usa el comparador --, y no
 * se confia en que quien anada un nombre lo respete: hay un `static_assert`
 * que recorre la tabla al compilar.  Una entrada mal colocada es un error de
 * compilacion, no una busqueda que falla en silencio.
 *
 * Guardar la longitud aparte del puntero no es redundante: es lo que permite
 * que el comparador descarte con un entero.  Y viene gratis, porque el
 * `constexpr` la calcula al compilar.
 */
#include "vx/builtin_names.h"

#include <algorithm>
#include <array>

namespace vx {
namespace {

/**
 * @brief Longitud de un literal, calculada al compilar.
 *
 * No se usa `strlen` porque hace falta en contexto `constexpr`, y porque en la
 * tabla es un valor conocido: nadie lo va a calcular en ejecucion.
 *
 * @param s El literal.
 * @return Cuantos caracteres tiene, sin el terminador.
 */
constexpr uint16_t ct_len(const char *s) {
    uint16_t n = 0;
    while (s[n] != '\0')
        ++n;
    return n;
}

/**
 * @brief Una entrada de la tabla: el texto, su longitud y que builtin es.
 *
 * La longitud se guarda porque es lo que permite descartar comparando un
 * entero, pero NO se escribe en la tabla: la calcula el constructor al
 * compilar.  Escribirla a mano seria un tercer dato que mantener a la vez que
 * el nombre y el valor del enum, y equivocarse no daria error -- daria una
 * busqueda que no encuentra.
 */
struct BuiltinEntry {
    const char *text; ///< El nombre, sin terminador contado en @ref len.
    uint16_t len;     ///< Su longitud, para descartar sin leer bytes.
    Builtin id;       ///< Que builtin es.

    /**
     * @brief Construye una entrada calculando la longitud del texto.
     *
     * @param t El nombre.
     * @param i Que builtin es.
     */
    constexpr BuiltinEntry(const char *t, Builtin i)
        : text(t), len(ct_len(t)), id(i) {}
};

/// @brief La tabla, ordenada por longitud y luego por bytes.
constexpr BuiltinEntry kTable[] = {

    /* --- 2 caracteres --- */
    {"Ok", Builtin::Ok},

    /* --- 3 caracteres --- */
    {"Err", Builtin::Err},
    {"abs", Builtin::Abs},
    {"chr", Builtin::Chr},
    {"clz", Builtin::Clz},
    {"cos", Builtin::Cos},
    {"ctz", Builtin::Ctz},
    {"log", Builtin::Log},
    {"ord", Builtin::Ord},
    {"pid", Builtin::Pid},
    {"pow", Builtin::Pow},
    {"sin", Builtin::Sin},
    {"tan", Builtin::Tan},

    /* --- 4 caracteres --- */
    {"None", Builtin::None},
    {"Some", Builtin::Some},
    {"ceil", Builtin::Ceil},
    {"echo", Builtin::Echo},
    {"fabs", Builtin::Fabs},
    {"fmax", Builtin::Fmax},
    {"fmin", Builtin::Fmin},
    {"free", Builtin::Free},
    {"imax", Builtin::Imax},
    {"imin", Builtin::Imin},
    {"isOk", Builtin::IsOk},
    {"kind", Builtin::Kind},
    {"lend", Builtin::Lend},
    {"log2", Builtin::Log2},
    {"move", Builtin::Move},
    {"rotl", Builtin::Rotl},
    {"rotr", Builtin::Rotr},
    {"sqrt", Builtin::Sqrt},
    {"wait", Builtin::Wait},

    /* --- 5 caracteres --- */
    {"bswap", Builtin::Bswap},
    {"clamp", Builtin::Clamp},
    {"deque", Builtin::Deque},
    {"error", Builtin::Error},
    {"floor", Builtin::Floor},
    {"flush", Builtin::Flush},
    {"fopen", Builtin::Fopen},
    {"ilog2", Builtin::Ilog2},
    {"imaxu", Builtin::Imaxu},
    {"iminu", Builtin::Iminu},
    {"log10", Builtin::Log10},
    {"panic", Builtin::Panic},
    {"print", Builtin::Print},
    {"queue", Builtin::Queue},
    {"round", Builtin::Round},
    {"share", Builtin::Share},
    {"stack", Builtin::Stack},
    {"trunc", Builtin::Trunc},
    {"value", Builtin::Value},

    /* --- 6 caracteres --- */
    {"bg_rgb", Builtin::BgRgb},
    {"expect", Builtin::Expect},
    {"extent", Builtin::Extent},
    {"fclose", Builtin::Fclose},
    {"fg_rgb", Builtin::FgRgb},
    {"fwrite", Builtin::Fwrite},
    {"gc_box", Builtin::GcBox},
    {"gensym", Builtin::Gensym},
    {"invoke", Builtin::Invoke},
    {"malloc", Builtin::Malloc},
    {"notify", Builtin::Notify},
    {"parent", Builtin::Parent},
    {"ptr_of", Builtin::PtrOf},
    {"repeat", Builtin::Repeat},
    {"sizeof", Builtin::Sizeof},
    {"substr", Builtin::Substr},
    {"to_str", Builtin::ToStr},
    {"unwrap", Builtin::Unwrap},

    /* --- 7 caracteres --- */
    {"alignof", Builtin::Alignof},
    {"bitcast", Builtin::Bitcast},
    {"dispose", Builtin::Dispose},
    {"ffi_sym", Builtin::FfiSym},
    {"forName", Builtin::ForName},
    {"fulfill", Builtin::Fulfill},
    {"hashmap", Builtin::Hashmap},
    {"hashset", Builtin::Hashset},
    {"is_bool", Builtin::IsBool},
    {"is_char", Builtin::IsChar},
    {"is_enum", Builtin::IsEnum},
    {"is_same", Builtin::IsSame},
    {"msgrecv", Builtin::Msgrecv},
    {"msgsend", Builtin::Msgsend},
    {"println", Builtin::Println},
    {"proceed", Builtin::Proceed},
    {"replace", Builtin::Replace},
    {"treemap", Builtin::Treemap},
    {"treeset", Builtin::Treeset},
    {"type_id", Builtin::TypeId},
    {"unshare", Builtin::Unshare},
    {"vacount", Builtin::Vacount},

    /* --- 8 caracteres --- */
    {"args_get", Builtin::ArgsGet},
    {"contains", Builtin::Contains},
    {"ct_print", Builtin::CtPrint},
    {"ffi_call", Builtin::FfiCall},
    {"ffi_open", Builtin::FfiOpen},
    {"getClass", Builtin::GetClass},
    {"getField", Builtin::GetField},
    {"is_class", Builtin::IsClass},
    {"is_float", Builtin::IsFloat},
    {"lend_mut", Builtin::LendMut},
    {"offsetof", Builtin::Offsetof},
    {"popcount", Builtin::Popcount},
    {"str_cstr", Builtin::StrCstr},
    {"str_hash", Builtin::StrHash},
    {"str_make", Builtin::StrMake},
    {"str_wstr", Builtin::StrWstr},
    {"typename", Builtin::Typename},

    /* --- 9 caracteres --- */
    {"arraylist", Builtin::Arraylist},
    {"field_get", Builtin::FieldGet},
    {"field_set", Builtin::FieldSet},
    {"find_type", Builtin::FindType},
    {"getFields", Builtin::GetFields},
    {"getMethod", Builtin::GetMethod},
    {"has_field", Builtin::HasField},
    {"in_bounds", Builtin::InBounds},
    {"isPresent", Builtin::IsPresent},
    {"is_opaque", Builtin::IsOpaque},
    {"is_shared", Builtin::IsShared},
    {"is_signed", Builtin::IsSigned},
    {"is_string", Builtin::IsString},
    {"is_struct", Builtin::IsStruct},
    {"notifyAll", Builtin::NotifyAll},
    {"print_bin", Builtin::PrintBin},
    {"print_hex", Builtin::PrintHex},
    {"print_int", Builtin::PrintInt},
    {"print_oct", Builtin::PrintOct},
    {"print_pad", Builtin::PrintPad},
    {"print_ptr", Builtin::PrintPtr},
    {"str_bytes", Builtin::StrBytes},
    {"term_move", Builtin::TermMove},
    {"to_string", Builtin::ToString},
    {"unwrap_or", Builtin::UnwrapOr},
    {"use_count", Builtin::UseCount},

    /* --- 10 caracteres --- */
    {"args_count", Builtin::ArgsCount},
    {"atomic_add", Builtin::AtomicAdd},
    {"atomic_cas", Builtin::AtomicCas},
    {"field_name", Builtin::FieldName},
    {"field_type", Builtin::FieldType},
    {"gc_collect", Builtin::GcCollect},
    {"getFieldAt", Builtin::GetFieldAt},
    {"getMethods", Builtin::GetMethods},
    {"has_method", Builtin::HasMethod},
    {"is_integer", Builtin::IsInteger},
    {"is_newtype", Builtin::IsNewtype},
    {"is_numeric", Builtin::IsNumeric},
    {"is_pointer", Builtin::IsPointer},
    {"is_subtype", Builtin::IsSubtype},
    {"loadmodule", Builtin::Loadmodule},
    {"print_bool", Builtin::PrintBool},
    {"print_char", Builtin::PrintChar},
    {"print_cstr", Builtin::PrintCstr},
    {"print_uint", Builtin::PrintUint},
    {"shared_box", Builtin::SharedBox},
    {"str_concat", Builtin::StrConcat},
    {"str_equals", Builtin::StrEquals},
    {"str_intern", Builtin::StrIntern},
    {"str_length", Builtin::StrLength},
    {"term_clear", Builtin::TermClear},
    {"term_reset", Builtin::TermReset},
    {"unique_box", Builtin::UniqueBox},

    /* --- 11 caracteres --- */
    {"atomic_load", Builtin::AtomicLoad},
    {"fiber_entry", Builtin::FiberEntry},
    {"field_count", Builtin::FieldCount},
    {"getMethodAt", Builtin::GetMethodAt},
    {"is_unsigned", Builtin::IsUnsigned},
    {"newInstance", Builtin::NewInstance},
    {"print_color", Builtin::PrintColor},
    {"print_float", Builtin::PrintFloat},
    {"read_borrow", Builtin::ReadBorrow},
    {"section_end", Builtin::SectionEnd},
    {"shared_free", Builtin::SharedFree},
    {"shared_with", Builtin::SharedWith},
    {"str_convert", Builtin::StrConvert},
    {"unique_with", Builtin::UniqueWith},

    /* --- 12 caracteres --- */
    {"atomic_store", Builtin::AtomicStore},
    {"comptime_chr", Builtin::ComptimeChr},
    {"comptime_ord", Builtin::ComptimeOrd},
    {"cpu_features", Builtin::CpuFeatures},
    {"future_alloc", Builtin::FutureAlloc},
    {"is_primitive", Builtin::IsPrimitive},
    {"method_count", Builtin::MethodCount},
    {"section_size", Builtin::SectionSize},
    {"unloadmodule", Builtin::Unloadmodule},
    {"write_borrow", Builtin::WriteBorrow},

    /* --- 13 caracteres --- */
    {"fiber_swapctx", Builtin::FiberSwapctx},
    {"section_start", Builtin::SectionStart},
    {"shared_malloc", Builtin::SharedMalloc},
    {"static_assert", Builtin::StaticAssert},
    {"underlying_of", Builtin::UnderlyingOf},

    /* --- 14 caracteres --- */
    {"atomic_add_i64", Builtin::AtomicAddI64},
    {"atomic_cas_i64", Builtin::AtomicCasI64},
    {"comptime_print", Builtin::ComptimePrint},
    {"comptime_streq", Builtin::ComptimeStreq},
    {"for_each_field", Builtin::ForEachField},
    {"print_gchandle", Builtin::PrintGchandle},
    {"type_info_kind", Builtin::TypeInfoKind},
    {"type_info_name", Builtin::TypeInfoName},
    {"type_info_size", Builtin::TypeInfoSize},

    /* --- 15 caracteres --- */
    {"atomic_load_i64", Builtin::AtomicLoadI64},
    {"comptime_concat", Builtin::ComptimeConcat},
    {"comptime_repeat", Builtin::ComptimeRepeat},
    {"comptime_strlen", Builtin::ComptimeStrlen},
    {"comptime_substr", Builtin::ComptimeSubstr},
    {"comptime_to_str", Builtin::ComptimeToStr},
    {"for_each_method", Builtin::ForEachMethod},
    {"gc_finalize_all", Builtin::GcFinalizeAll},
    {"term_clear_line", Builtin::TermClearLine},
    {"type_info_align", Builtin::TypeInfoAlign},

    /* --- 16 caracteres --- */
    {"atomic_store_i64", Builtin::AtomicStoreI64},
    {"comptime_replace", Builtin::ComptimeReplace},
    {"term_hide_cursor", Builtin::TermHideCursor},
    {"term_save_cursor", Builtin::TermSaveCursor},
    {"term_show_cursor", Builtin::TermShowCursor},
    {"unwrap_unchecked", Builtin::UnwrapUnchecked},

    /* --- 17 caracteres --- */
    {"comptime_contains", Builtin::ComptimeContains},
    {"shared_gc_collect", Builtin::SharedGcCollect},
    {"shared_heap_bytes", Builtin::SharedHeapBytes},

    /* --- 18 caracteres --- */
    {"as_native_callback", Builtin::AsNativeCallback},
    {"comptime_type_kind", Builtin::ComptimeTypeKind},

    /* --- 19 caracteres --- */
    {"term_restore_cursor", Builtin::TermRestoreCursor},

    /* --- 20 caracteres --- */
    {"comptime_type_sizeof", Builtin::ComptimeTypeSizeof},
    {"type_info_field_name", Builtin::TypeInfoFieldName},
    {"type_info_field_size", Builtin::TypeInfoFieldSize},

    /* --- 21 caracteres --- */
    {"comptime_type_alignof", Builtin::ComptimeTypeAlignof},
    {"type_info_field_count", Builtin::TypeInfoFieldCount},

    /* --- 22 caracteres --- */
    {"shared_heap_live_count", Builtin::SharedHeapLiveCount},
    {"type_info_field_offset", Builtin::TypeInfoFieldOffset},
};

/// @brief Cuantas entradas tiene la tabla.
constexpr size_t kTableSize = sizeof(kTable) / sizeof(kTable[0]);

/**
 * @brief Compara dos textos con el criterio de la tabla: longitud, luego
 *        bytes.
 *
 * Poner la longitud delante no es un detalle de eficiencia sino LA razon de
 * que la busqueda sea barata: dos nombres de distinta longitud se ordenan sin
 * mirar su contenido.
 *
 * @param a_text Texto del primero.
 * @param a_len  Longitud del primero.
 * @param b_text Texto del segundo.
 * @param b_len  Longitud del segundo.
 * @return Negativo si el primero va antes, cero si son iguales, positivo si va
 *         despues.
 */
constexpr int ct_cmp(const char *a_text, uint16_t a_len, const char *b_text,
                     uint16_t b_len) {
    if (a_len != b_len) return (a_len < b_len) ? -1 : 1;
    for (uint16_t i = 0; i < a_len; ++i) {
        if (a_text[i] != b_text[i]) return (a_text[i] < b_text[i]) ? -1 : 1;
    }
    return 0;
}

/**
 * @brief Comprueba al compilar que la tabla esta en orden.
 *
 * Recorre las entradas y exige que cada una vaya estrictamente despues de la
 * anterior.  Estricta, no laxa: dos nombres iguales serian dos builtins con el
 * mismo texto, y uno de los dos no se alcanzaria nunca.
 *
 * @return @c true si la tabla esta ordenada y sin repetidos.
 */
constexpr bool table_is_sorted() {
    for (size_t i = 1; i < kTableSize; ++i) {
        if (ct_cmp(kTable[i - 1].text, kTable[i - 1].len, kTable[i].text,
                   kTable[i].len) >= 0)
            return false;
    }
    return true;
}

static_assert(table_is_sorted(),
              "kTable tiene que ir ordenada por LONGITUD y luego por bytes, "
              "sin nombres repetidos.  Coloca la entrada nueva en su sitio o "
              "la busqueda binaria no la encontrara.");

static_assert(kTableSize + 1 == static_cast<size_t>(Builtin::Count),
              "kTable y Builtin salen de la misma lista: si una tiene una "
              "entrada que a la otra le falta, hay un builtin que no se "
              "reconoce o un valor del enum que no corresponde a ningun "
              "nombre.  (El +1 es Builtin::Unknown, que no esta en la tabla.)");

} // namespace

/**
 * @copydoc vx::builtin_from_name
 */
Builtin builtin_from_name(std::string_view name) noexcept {
    /* Los nombres mas largos y mas cortos de la tabla acotan la busqueda: un
     * identificador cualquiera del programa casi nunca cae dentro, y salir
     * aqui evita entrar en la busqueda binaria. */
    const uint16_t n = static_cast<uint16_t>(name.size());
    if (n < kTable[0].len || n > kTable[kTableSize - 1].len)
        return Builtin::Unknown;

    const BuiltinEntry *lo = kTable;
    const BuiltinEntry *hi = kTable + kTableSize;
    while (lo < hi) {
        const BuiltinEntry *mid = lo + (hi - lo) / 2;
        const int c = ct_cmp(mid->text, mid->len, name.data(), n);
        if (c < 0)
            lo = mid + 1;
        else if (c > 0)
            hi = mid;
        else
            return mid->id;
    }
    return Builtin::Unknown;
}

/**
 * @copydoc vx::builtin_name
 */
std::string_view builtin_name(Builtin b) noexcept {
    /* La tabla NO esta indexada por el valor del enum -- va ordenada por
     * longitud --, asi que hay que buscarlo.  Solo lo usan los diagnosticos,
     * asi que recorrerla entera sale mas barato que mantener una segunda tabla
     * en el orden del enum solo para esto. */
    for (size_t i = 0; i < kTableSize; ++i) {
        if (kTable[i].id == b)
            return std::string_view(kTable[i].text, kTable[i].len);
    }
    return {};
}

namespace {

/**
 * @brief El reparto: que familia atiende cada builtin.
 *
 * Escrito como `switch` a proposito, y no como una tabla de doscientas
 * entradas indexada a mano: asi el reparto se LEE -- los nombres de una
 * familia van juntos y se ve de un vistazo que no falta ninguno --, y no hay
 * que respetar ningun orden.  La tabla la construye el compilador a partir de
 * esto, de modo que en ejecucion sigue siendo una lectura y no un recorrido.
 *
 * Las familias son disjuntas y eso NO es casual: es lo que hace correcto ir
 * directo a una.  Si un builtin acabara en dos, la segunda no se ejecutaria
 * nunca.
 *
 * @param b El builtin.
 * @return Su familia, u Other si la atiende el despacho general.
 */
constexpr BuiltinFamily family_of(Builtin b) {
    switch (b) {
    case Builtin::ComptimePrint:
    case Builtin::CtPrint:
    case Builtin::Echo:
    case Builtin::Flush:
    case Builtin::GcCollect:
    case Builtin::GcFinalizeAll:
    case Builtin::Print:
    case Builtin::PrintBin:
    case Builtin::PrintBool:
    case Builtin::PrintChar:
    case Builtin::PrintColor:
    case Builtin::PrintCstr:
    case Builtin::PrintFloat:
    case Builtin::PrintGchandle:
    case Builtin::PrintHex:
    case Builtin::PrintInt:
    case Builtin::PrintOct:
    case Builtin::PrintPad:
    case Builtin::PrintPtr:
    case Builtin::PrintUint:
    case Builtin::Println:
    case Builtin::TermClear:
    case Builtin::TermClearLine:
    case Builtin::TermHideCursor:
    case Builtin::TermMove:
    case Builtin::TermReset:
    case Builtin::TermRestoreCursor:
    case Builtin::TermSaveCursor:
    case Builtin::TermShowCursor: return BuiltinFamily::Print;

    case Builtin::Dispose:
    case Builtin::Fclose:
    case Builtin::FiberSwapctx:
    case Builtin::Fopen:
    case Builtin::Free:
    case Builtin::Fwrite:
    case Builtin::Loadmodule:
    case Builtin::Malloc:
    case Builtin::Unloadmodule:
    case Builtin::FfiOpen:
    case Builtin::FfiSym:
    case Builtin::FfiCall:
    case Builtin::Pid:
    case Builtin::CpuFeatures:
    case Builtin::ArgsCount:
    case Builtin::ArgsGet: return BuiltinFamily::Runtime;

    case Builtin::AtomicAddI64:
    case Builtin::AtomicCasI64:
    case Builtin::AtomicLoadI64:
    case Builtin::AtomicStoreI64:
    case Builtin::Fulfill:
    case Builtin::FutureAlloc:
    case Builtin::IsShared:
    case Builtin::Msgrecv:
    case Builtin::Msgsend:
    case Builtin::Share:
    case Builtin::SharedFree:
    case Builtin::SharedGcCollect:
    case Builtin::SharedHeapBytes:
    case Builtin::SharedHeapLiveCount:
    case Builtin::SharedMalloc:
    case Builtin::Unshare:
    case Builtin::AtomicLoad:
    case Builtin::AtomicStore:
    case Builtin::AtomicCas:
    case Builtin::AtomicAdd:
    case Builtin::Wait:
    case Builtin::Notify:
    case Builtin::NotifyAll: return BuiltinFamily::Concurrent;

    case Builtin::Err:
    case Builtin::Error:
    case Builtin::Expect:
    case Builtin::IsOk:
    case Builtin::IsPresent:
    case Builtin::None:
    case Builtin::Ok:
    case Builtin::Some:
    case Builtin::Unwrap:
    case Builtin::UnwrapOr:
    case Builtin::UnwrapUnchecked:
    case Builtin::Value: return BuiltinFamily::Optional;

    case Builtin::ForName:
    case Builtin::GetClass:
    case Builtin::GetField:
    case Builtin::GetFieldAt:
    case Builtin::GetFields:
    case Builtin::GetMethod:
    case Builtin::GetMethodAt:
    case Builtin::GetMethods:
    case Builtin::Invoke:
    case Builtin::NewInstance:
    case Builtin::Proceed: return BuiltinFamily::Reflect;

    case Builtin::GcBox:
    case Builtin::Lend:
    case Builtin::LendMut:
    case Builtin::Move:
    case Builtin::PtrOf:
    case Builtin::ReadBorrow:
    case Builtin::SharedBox:
    case Builtin::SharedWith:
    case Builtin::UniqueBox:
    case Builtin::UniqueWith:
    case Builtin::UseCount:
    case Builtin::WriteBorrow: return BuiltinFamily::Ownership;

    case Builtin::Chr:
    case Builtin::ComptimeChr:
    case Builtin::ComptimeConcat:
    case Builtin::ComptimeContains:
    case Builtin::ComptimeOrd:
    case Builtin::ComptimeRepeat:
    case Builtin::ComptimeReplace:
    case Builtin::ComptimeStreq:
    case Builtin::ComptimeStrlen:
    case Builtin::ComptimeSubstr:
    case Builtin::ComptimeToStr:
    case Builtin::Contains:
    case Builtin::Ord:
    case Builtin::Repeat:
    case Builtin::Replace:
    case Builtin::StrBytes:
    case Builtin::StrConcat:
    case Builtin::StrConvert:
    case Builtin::StrCstr:
    case Builtin::StrEquals:
    case Builtin::StrHash:
    case Builtin::StrIntern:
    case Builtin::StrLength:
    case Builtin::StrMake:
    case Builtin::StrWstr:
    case Builtin::Substr:
    case Builtin::ToStr: return BuiltinFamily::String;

    case Builtin::Abs:
    case Builtin::Bswap:
    case Builtin::Ceil:
    case Builtin::Clamp:
    case Builtin::Clz:
    case Builtin::Cos:
    case Builtin::Ctz:
    case Builtin::Fabs:
    case Builtin::Floor:
    case Builtin::Fmax:
    case Builtin::Fmin:
    case Builtin::Ilog2:
    case Builtin::Imax:
    case Builtin::Imaxu:
    case Builtin::Imin:
    case Builtin::Iminu:
    case Builtin::Log:
    case Builtin::Log10:
    case Builtin::Log2:
    case Builtin::Popcount:
    case Builtin::Pow:
    case Builtin::Rotl:
    case Builtin::Rotr:
    case Builtin::Round:
    case Builtin::Sin:
    case Builtin::Sqrt:
    case Builtin::Tan:
    case Builtin::Trunc: return BuiltinFamily::Math;

    case Builtin::Alignof:
    case Builtin::Bitcast:
    case Builtin::ComptimeTypeAlignof:
    case Builtin::ComptimeTypeKind:
    case Builtin::ComptimeTypeSizeof:
    case Builtin::Extent:
    case Builtin::FieldCount:
    case Builtin::FieldGet:
    case Builtin::FieldName:
    case Builtin::FieldSet:
    case Builtin::FieldType:
    case Builtin::FindType:
    case Builtin::ForEachField:
    case Builtin::ForEachMethod:
    case Builtin::HasField:
    case Builtin::HasMethod:
    case Builtin::InBounds:
    case Builtin::IsBool:
    case Builtin::IsChar:
    case Builtin::IsClass:
    case Builtin::IsEnum:
    case Builtin::IsFloat:
    case Builtin::IsInteger:
    case Builtin::IsNewtype:
    case Builtin::IsNumeric:
    case Builtin::IsOpaque:
    case Builtin::IsPointer:
    case Builtin::IsPrimitive:
    case Builtin::IsSame:
    case Builtin::IsSigned:
    case Builtin::IsString:
    case Builtin::IsStruct:
    case Builtin::IsSubtype:
    case Builtin::IsUnsigned:
    case Builtin::Kind:
    case Builtin::MethodCount:
    case Builtin::Offsetof:
    case Builtin::Parent:
    case Builtin::Sizeof:
    case Builtin::StaticAssert:
    case Builtin::TypeId:
    case Builtin::TypeInfoAlign:
    case Builtin::TypeInfoFieldCount:
    case Builtin::TypeInfoFieldName:
    case Builtin::TypeInfoFieldOffset:
    case Builtin::TypeInfoFieldSize:
    case Builtin::TypeInfoKind:
    case Builtin::TypeInfoName:
    case Builtin::TypeInfoSize:
    case Builtin::Typename:
    case Builtin::UnderlyingOf: return BuiltinFamily::Introspect;

    default: return BuiltinFamily::Other;
    }
}

/// @brief Cuantas entradas tiene la tabla: una por builtin, mas Unknown.
constexpr size_t kFamilyCount = static_cast<size_t>(Builtin::Count);

/// @brief La tabla, construida al compilar desde @ref family_of.
constexpr std::array<BuiltinFamily, kFamilyCount> kFamilyTable = [] {
    std::array<BuiltinFamily, kFamilyCount> t{};
    for (size_t i = 0; i < kFamilyCount; ++i)
        t[i] = family_of(static_cast<Builtin>(i));
    return t;
}();

} // namespace

/**
 * @copydoc vx::builtin_family
 */
BuiltinFamily builtin_family(Builtin b) noexcept {
    const size_t i = static_cast<size_t>(b);
    if (i >= kFamilyCount) return BuiltinFamily::Other;
    return kFamilyTable[i];
}

} // namespace vx
