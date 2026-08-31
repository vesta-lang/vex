/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/ir/test_ir_type_info.cpp
 * @brief Tests del vocabulario UNICO de propiedades de @c ir::IrType.
 *
 * Lo que se comprueba no es solo que las respuestas sean "razonables", sino que
 * son EXACTAMENTE las que hoy dan las doce implementaciones repartidas por el
 * arbol, porque de eso depende que la migracion no mueva la suite ni un paso.
 * Por eso los oraculos de este fichero son copias LITERALES de las tablas
 * viejas: cuando el ultimo llamador migre, este test es lo que demuestra que
 * nada cambio de comportamiento por el camino.
 */
#include "analysis/memory/memory_access.h"
#include "ir/ir_type_info.h"
#include "ir/ssa_ir.h"

#include <cstdio>

using ir::IrType;

static int g_checks = 0, g_fail = 0;
#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        ++g_checks;                                                            \
        if (!(cond)) {                                                         \
            ++g_fail;                                                          \
            std::printf("FALLO [%s:%d]: %s\n", __FILE__, __LINE__, msg);       \
        }                                                                      \
    } while (0)

/// Todos los tipos del IR, para barrer sin olvidarse de ninguno.  Si entra un
/// tipo nuevo y no se anade aqui, los tests de barrido dejan de cubrirlo -- el
/// switch exhaustivo del modulo es lo que avisa en ese caso.
static const IrType kAllTypes[] = {
    IrType::VOID, IrType::I8,  IrType::I16,    IrType::I32, IrType::I64,
    IrType::U8,   IrType::U16, IrType::U32,    IrType::U64, IrType::F32,
    IrType::F64,  IrType::PTR, IrType::HANDLE, IrType::BOOL};
static const int kTypeCount =
    static_cast<int>(sizeof(kAllTypes) / sizeof(kAllTypes[0]));

// --------------------------------------------------------------------------
//  Oraculos: las tablas VIEJAS, copiadas tal cual de donde vivian.
// --------------------------------------------------------------------------

/// Copia literal de @c ir_type_size (src/ir/ir_emitter.cpp) y de
/// @c sr_type_size, @c ir_type_size_bytes, @c ir_type_bytes y @c bytes_for,
/// que son la misma tabla repetida.  Eje de RANURA: HANDLE cae en el default
/// y vale 8.
static uint32_t oracle_slot_bytes(IrType t) {
    switch (t) {
    case IrType::I8:
    case IrType::U8:
    case IrType::BOOL: return 1;
    case IrType::I16:
    case IrType::U16: return 2;
    case IrType::I32:
    case IrType::U32:
    case IrType::F32: return 4;
    default: return 8;
    }
}

/// Copia literal de @c type_size_bytes (src/analyze/fingerprint.cpp).  Eje de
/// ALMACENAMIENTO: VOID vale 0 porque no ocupa marco.
static uint32_t oracle_storage_bytes(IrType t) {
    switch (t) {
    case IrType::I8:
    case IrType::U8:
    case IrType::BOOL: return 1;
    case IrType::I16:
    case IrType::U16: return 2;
    case IrType::I32:
    case IrType::U32:
    case IrType::F32:
    case IrType::HANDLE: return 4;
    case IrType::I64:
    case IrType::U64:
    case IrType::F64:
    case IrType::PTR: return 8;
    case IrType::VOID:
    default: return 0;
    }
}

/// Copia literal de @c type_mask (src/ir/ir_optimizer.cpp).
static uint64_t oracle_mask(IrType t) {
    switch (t) {
    case IrType::I8:
    case IrType::U8:
    case IrType::BOOL: return 0xFFu;
    case IrType::I16:
    case IrType::U16: return 0xFFFFu;
    case IrType::I32:
    case IrType::U32:
    case IrType::F32: return 0xFFFFFFFFu;
    default: return ~static_cast<uint64_t>(0u);
    }
}

/// Copia literal de las dos lambdas @c narrow_bits (src/ir/ir_optimizer.cpp).
static uint32_t oracle_narrow_bits(IrType t) {
    switch (t) {
    case IrType::I8:
    case IrType::U8: return 8;
    case IrType::I16:
    case IrType::U16: return 16;
    case IrType::I32:
    case IrType::U32: return 32;
    default: return 0;
    }
}

/// Copia literal de @c sr_type_is_int (src/ir/ir_optimizer.cpp).
static bool oracle_is_integer(IrType t) {
    switch (t) {
    case IrType::I8:
    case IrType::I16:
    case IrType::I32:
    case IrType::I64:
    case IrType::U8:
    case IrType::U16:
    case IrType::U32:
    case IrType::U64:
    case IrType::BOOL: return true;
    default: return false;
    }
}

// --------------------------------------------------------------------------
// 1) Cada eje reproduce EXACTAMENTE la tabla que sustituye.
// --------------------------------------------------------------------------
static void test_matches_old_tables() {
    for (int i = 0; i < kTypeCount; ++i) {
        const IrType t = kAllTypes[i];
        // El eje de acceso ya tenia una fuente designada como canonica en el
        // arbol (la cita el adaptador de tipo de rbank): se comprueba contra
        // ella, no contra una copia, para que no puedan separarse.
        CHECK(ir::type_access_bytes(t) ==
                  static_cast<uint32_t>(analysis::memory_access_size(t)),
              "el eje de acceso debe dar lo mismo que memory_access_size");
        CHECK(ir::type_slot_bytes(t) == oracle_slot_bytes(t),
              "el eje de ranura debe dar lo mismo que ir_type_size");
        CHECK(ir::type_storage_bytes(t) == oracle_storage_bytes(t),
              "el eje de almacenamiento debe dar lo mismo que type_size_bytes");
        CHECK(ir::type_mask(t) == oracle_mask(t),
              "la mascara debe dar lo mismo que la vieja type_mask");
        CHECK(ir::type_narrow_bits(t) == oracle_narrow_bits(t),
              "los bits estrechables deben dar lo mismo que narrow_bits");
        CHECK(ir::type_is_integer(t) == oracle_is_integer(t),
              "la clase entera debe dar lo mismo que sr_type_is_int");
    }
}

// --------------------------------------------------------------------------
// 2) Los tres ejes difieren SOLO donde deben, y coinciden en todo lo demas.
// --------------------------------------------------------------------------
static void test_axes_differ_only_where_documented() {
    // HANDLE: 32 bits de dato en una ranura de 64.
    CHECK(ir::type_access_bytes(IrType::HANDLE) == 4,
          "un GcHandle toca 4 bytes de memoria");
    CHECK(ir::type_slot_bytes(IrType::HANDLE) == 8,
          "pero ocupa una ranura de 8 (paso de array, registro)");
    CHECK(ir::type_storage_bytes(IrType::HANDLE) == 4,
          "y en el marco se cuenta por lo que ocupa el dato");

    // VOID: no hay valor, pero el acceso se trata conservadoramente.
    CHECK(ir::type_storage_bytes(IrType::VOID) == 0, "void no reserva marco");
    CHECK(ir::type_access_bytes(IrType::VOID) == 8,
          "pero el eje de acceso NUNCA sub-estima");

    // En todo lo que no sea HANDLE ni VOID, los tres ejes deben coincidir: si
    // alguno se separa por su cuenta, es que alguien metio un caso especial
    // sin documentarlo en la tabla del modulo.
    for (int i = 0; i < kTypeCount; ++i) {
        const IrType t = kAllTypes[i];
        if (t == IrType::HANDLE || t == IrType::VOID) continue;
        CHECK(ir::type_access_bytes(t) == ir::type_slot_bytes(t) &&
                  ir::type_slot_bytes(t) == ir::type_storage_bytes(t),
              "los tres ejes solo pueden separarse en HANDLE y VOID");
    }
}

// --------------------------------------------------------------------------
// 3) El defecto concreto que se cierra: F32 mide 4, nunca 8.
// --------------------------------------------------------------------------
static void test_f32_is_four_bytes() {
    // Dos de las tablas viejas (bytes_of y bytes_of_local, en lowering.cpp)
    // omitian F32 y lo dejaban caer en el default con valor 8.  No fallaba
    // porque la rama en que vivian excluye los flotantes -- protegidas por el
    // contexto, no por ser correctas.  Aqui no hay contexto que proteja.
    CHECK(ir::type_access_bytes(IrType::F32) == 4, "f32 toca 4 bytes");
    CHECK(ir::type_slot_bytes(IrType::F32) == 4, "f32 ocupa una ranura de 4");
    CHECK(ir::type_storage_bytes(IrType::F32) == 4, "f32 reserva 4 de marco");
    CHECK(ir::type_access_bytes(IrType::F64) == 8, "f64 toca 8 bytes");
}

// --------------------------------------------------------------------------
// 4) Clase: entero, flotante y signo son tres preguntas distintas.
// --------------------------------------------------------------------------
static void test_class_predicates() {
    // Un puntero y un handle se representan con enteros pero NO son enteros:
    // decir que si abriria la puerta a sumarles o truncarlos como aritmetica.
    CHECK(!ir::type_is_integer(IrType::PTR), "un puntero no es un entero");
    CHECK(!ir::type_is_integer(IrType::HANDLE), "un handle no es un entero");
    CHECK(ir::type_is_integer(IrType::BOOL), "bool si cuenta como entero");

    CHECK(ir::type_is_float(IrType::F32) && ir::type_is_float(IrType::F64),
          "f32 y f64 son flotantes");
    CHECK(!ir::type_is_float(IrType::I64), "y ningun entero lo es");

    // El signo decide extender con signo o con ceros: bool va con ceros.
    CHECK(ir::type_is_signed(IrType::I8) && ir::type_is_signed(IrType::I64),
          "los i* llevan signo");
    CHECK(!ir::type_is_signed(IrType::U8) && !ir::type_is_signed(IrType::U64),
          "los u* no");
    CHECK(!ir::type_is_signed(IrType::BOOL), "bool se extiende con ceros");

    // Ningun tipo puede ser entero y flotante a la vez.
    for (int i = 0; i < kTypeCount; ++i) {
        const IrType t = kAllTypes[i];
        CHECK(!(ir::type_is_integer(t) && ir::type_is_float(t)),
              "entero y flotante son excluyentes");
        if (ir::type_is_signed(t))
            CHECK(ir::type_is_integer(t), "lo que lleva signo es un entero");
    }
}

// --------------------------------------------------------------------------
// 5) La mascara se deriva del eje de ranura, y es coherente con el.
// --------------------------------------------------------------------------
static void test_mask_matches_slot() {
    for (int i = 0; i < kTypeCount; ++i) {
        const IrType t = kAllTypes[i];
        const uint32_t bytes = ir::type_slot_bytes(t);
        const uint64_t expected =
            bytes >= 8 ? ~static_cast<uint64_t>(0u)
                       : ((static_cast<uint64_t>(1u) << (bytes * 8u)) - 1u);
        CHECK(ir::type_mask(t) == expected,
              "la mascara debe cubrir exactamente la ranura del tipo");
    }
    CHECK(ir::type_mask(IrType::I32) == 0xFFFFFFFFull, "i32 -> 32 bits");
    CHECK(ir::type_mask(IrType::HANDLE) == ~0ull,
          "handle enmascara su RANURA de 64, no sus 32 de dato");
}

// --------------------------------------------------------------------------
// 6) narrow_bits: 0 significa "no estrechar", y hay que respetarlo.
// --------------------------------------------------------------------------
static void test_narrow_bits_semantics() {
    CHECK(ir::type_narrow_bits(IrType::BOOL) == 0,
          "bool mide un byte pero NO es estrechable: es una bandera");
    CHECK(ir::type_narrow_bits(IrType::F32) == 0, "un flotante no se estrecha");
    CHECK(ir::type_narrow_bits(IrType::PTR) == 0, "ni un puntero");
    CHECK(ir::type_narrow_bits(IrType::HANDLE) == 0, "ni un handle");
    CHECK(ir::type_narrow_bits(IrType::I64) == 0,
          "ni un entero que ya es del ancho maximo");
    CHECK(ir::type_narrow_bits(IrType::I32) == 32, "i32 -> 32 bits");
    CHECK(ir::type_narrow_bits(IrType::U8) == 8, "u8 -> 8 bits");

    // Cuando dice un numero, tiene que casar con el ancho real del tipo.
    for (int i = 0; i < kTypeCount; ++i) {
        const IrType t = kAllTypes[i];
        const uint32_t bits = ir::type_narrow_bits(t);
        if (bits == 0) continue;
        CHECK(bits == ir::type_slot_bytes(t) * 8u,
              "los bits estrechables son el ancho real del tipo");
        CHECK(ir::type_is_integer(t), "solo los enteros se estrechan");
    }
}

// --------------------------------------------------------------------------
// 7) El eje del VALOR: contesta por el valor, y dice que no sabe si no existe.
// --------------------------------------------------------------------------
static void test_value_axis() {
    ir::IrFunction fn;
    fn.name = "probe";

    const ir::IrValueId v_i32 = fn.new_value(IrType::I32, "%a");
    const ir::IrValueId v_h = fn.new_value(IrType::HANDLE, "%h");
    const ir::IrValueId v_f32 = fn.new_value(IrType::F32, "%f");

    CHECK(ir::value_bytes(fn, v_i32) == 4, "un i32 ocupa 4");
    CHECK(ir::value_bytes(fn, v_f32) == 4, "un f32 ocupa 4");
    CHECK(ir::value_bytes(fn, v_h) == 8,
          "un handle ocupa su RANURA: el valor vive en un registro de 64");

    // Un identificador que no existe no recibe una anchura inventada.  Es la
    // regla del ASA: lo que no se sabe se dice, no se rellena con un valor
    // permisivo que luego nadie distingue de una respuesta buena.
    CHECK(ir::value_bytes(fn, ir::IR_NO_VALUE) == 0,
          "un valor inexistente no tiene anchura");
    CHECK(ir::value_bytes(fn, static_cast<ir::IrValueId>(fn.values.size())) ==
              0,
          "un identificador fuera de rango tampoco");
}

int main() {
    test_matches_old_tables();
    test_axes_differ_only_where_documented();
    test_f32_is_four_bytes();
    test_class_predicates();
    test_mask_matches_slot();
    test_narrow_bits_semantics();
    test_value_axis();
    std::printf("=== ir-type-info (vocabulario unico): %d checks, %d fallos "
                "===\n",
                g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}
