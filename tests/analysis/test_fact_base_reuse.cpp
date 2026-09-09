/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/analysis/test_fact_base_reuse.cpp
 * @brief Que la base de hechos REUTILICE de verdad, y que no sirva lo rancio.
 *
 * Los dos lados, y hacen falta los dos: una base que recalcula siempre es
 * correcta y no ahorra nada -- o sea, un computo con otro nombre --, y una que
 * reutiliza sin comprobar sirve hechos de un codigo que ya no existe.  Ningun
 * test anterior mira ninguna de las dos cosas, y por eso esto pudo estar mal
 * mucho tiempo: `FactBase` hacia ONCE llamadas a la puerta sin versionar y cero
 * a la versionada, y nada fallaba.
 *
 * Se mide con los contadores que la base ya lleva -- @c queries() y
 * @c computations() --, que es exactamente para lo que estan: si una base
 * compartida no ahorra ninguna pregunta, eso se ve o no se ve.
 */

#include "analysis/asa/fact_base.h"
#include "ir/ssa_ir.h"
#include "vx/compiler.h"      // CompileOptions: la configuracion que entra en la clave
#include "vx/project_cache.h" // asa_facts_key / asa_facts_path_for_stage

#include "analysis/asa/fact_file.h" // serialize / read_facts: la cache en disco
#include "analysis/asa/producers.h" // registered_producers / current_inputs

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace analysis;
using namespace analysis::asa;

static int g_checks = 0, g_fail = 0;
#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        ++g_checks;                                                            \
        if (!(cond)) {                                                         \
            ++g_fail;                                                          \
            std::printf("FALLO [%s:%d]: %s\n", __FILE__, __LINE__, msg);       \
        }                                                                      \
    } while (0)

/// @brief Un modulo minimo con una funcion que tiene algo que analizar.
static ir::IrModule make_module(const char *fn_name) {
    ir::IrModule mod;
    ir::IrFunction fn;
    fn.name = fn_name;
    fn.ret_type = ir::IrType::I32;
    fn.values.resize(3);
    fn.values[0].type = ir::IrType::I32;
    fn.values[1].type = ir::IrType::I32;
    fn.values[2].type = ir::IrType::I32;

    ir::IrBlock b;
    ir::IrInstr k;
    k.op = ir::IrOp::CONST;
    k.type = ir::IrType::I32;
    k.dst = 0;
    k.imm = 7;
    b.instrs.push_back(k);

    ir::IrInstr add;
    add.op = ir::IrOp::ADD;
    add.type = ir::IrType::I32;
    add.dst = 1;
    add.operands.push_back(0);
    add.operands.push_back(0);
    b.instrs.push_back(add);

    ir::IrInstr ret;
    ret.op = ir::IrOp::RET;
    ret.type = ir::IrType::I32;
    ret.dst = ir::IR_NO_VALUE;
    ret.operands.push_back(1);
    b.instrs.push_back(ret);

    fn.blocks.push_back(std::move(b));
    mod.functions.push_back(std::move(fn));
    return mod;
}

/// @brief Un modulo con DOS funciones, que es el minimo para que "una cambia y
///        la otra no" se pueda distinguir de "cambio el modulo".
static ir::IrModule two_function_module() {
    ir::IrModule mod = make_module("f");
    ir::IrModule other = make_module("g");
    mod.functions.push_back(other.functions[0]);
    return mod;
}

/// @brief La tabla por funcion de @p dom, o nulo si ese dominio no la trae.
static const std::vector<std::pair<uint64_t, uint64_t>> *
by_function_of(const std::vector<asa::DomainCost> &v, const char *dom) {
    for (const asa::DomainCost &c : v)
        if (c.domain != nullptr && std::strcmp(c.domain, dom) == 0)
            return c.by_function.empty() ? nullptr : &c.by_function;
    return nullptr;
}

/// @brief La huella de dominio de @p dom.
static uint64_t fingerprint_of(const std::vector<asa::DomainCost> &v,
                               const char *dom) {
    for (const asa::DomainCost &c : v)
        if (c.domain != nullptr && std::strcmp(c.domain, dom) == 0)
            return c.fingerprint;
    return 0;
}

/// @brief La clave de la funcion cuyo nombre hashea a @p h.
static uint64_t key_for(const std::vector<std::pair<uint64_t, uint64_t>> &t,
                        uint64_t h) {
    for (const auto &kv : t)
        if (kv.first == h) return kv.second;
    return 0;
}

/// @brief Un hecho cualquiera atribuido a @p fn, del dominio de rangos.
///
/// Lo que se afirma da igual: lo que estos tests miran es de QUE FUNCIoN habla,
/// que es lo unico que decide si sobrevive a una carga parcial.
static Fact fact_about(const char *fn) {
    Fact f;
    f.what.domain = asa::kProducerRanges;
    f.what.code = "range.const";
    f.what.a = 7;
    f.what.b = 7;
    f.about.kind = Subject::Kind::Value;
    f.about.function = fn;
    f.about.id = 0;
    f.about.stage = kStagePreOpt;
    f.scope.stage = kStagePreOpt;
    f.seal.certainty = Certainty::Proven;
    f.seal.origin.source = Source::Static;
    f.seal.origin.producer = asa::kProducerRanges;
    return f;
}

// --------------------------------------------------------------------------
// 1) La misma pregunta dos veces se computa UNA.  Es la razon de existir de la
//    base: si no ahorra, es un computo con otro nombre.
// --------------------------------------------------------------------------
static void test_reuse_same_version() {
    ir::IrModule mod = make_module("f");
    FactBase base(kStagePreOpt);

    (void)base.structure(mod.functions[0]);
    const size_t after_first = base.computations();
    CHECK(after_first >= 1, "la primera pregunta computa");

    for (int i = 0; i < 5; ++i) (void)base.structure(mod.functions[0]);
    CHECK(base.computations() == after_first,
          "cinco preguntas mas no computan ninguna vez");
    CHECK(base.queries() >= 6, "pero las preguntas SI se cuentan");
}

// --------------------------------------------------------------------------
// 2) Al avanzar la version, se RECALCULA.  Sin esto se sirven hechos de un
//    codigo que ya no existe -- y como guardan punteros a instrucciones, eso no
//    es imprecision: es leer memoria liberada.
// --------------------------------------------------------------------------
static void test_version_forces_recompute() {
    ir::IrModule mod = make_module("f");
    FactBase base(kStagePreOpt);

    (void)base.structure(mod.functions[0]);
    const size_t before = base.computations();

    /* Lo que hace un pase que dice haber cambiado algo.  Se simula igual que en
     * el optimizador: un solo sitio sube la version. */
    ++mod.functions[0].version;
    (void)base.structure(mod.functions[0]);
    CHECK(base.computations() > before,
          "otra version obliga a recalcular, se haya invalidado o no");

    // Y una vez recalculado, vuelve a reutilizarse.
    const size_t after = base.computations();
    (void)base.structure(mod.functions[0]);
    CHECK(base.computations() == after,
          "y lo recalculado se reutiliza a su vez");
}

// --------------------------------------------------------------------------
// 3) Dos MOMENTOS son dos entradas.  Antes de optimizar y despues se habla de
//    codigos distintos, asi que compartir la respuesta es contestar de uno
//    sobre el otro.
// --------------------------------------------------------------------------
static void test_stage_separates() {
    ir::IrModule mod = make_module("f");
    FactBase base(kStagePreOpt);

    (void)base.structure(mod.functions[0], kStagePreOpt);
    const size_t after_pre = base.computations();
    (void)base.structure(mod.functions[0], kStagePostOpt);
    CHECK(base.computations() > after_pre,
          "el mismo analisis en otro momento es otra entrada");

    // Y cada uno se reutiliza por su lado.
    const size_t after_both = base.computations();
    (void)base.structure(mod.functions[0], kStagePreOpt);
    (void)base.structure(mod.functions[0], kStagePostOpt);
    CHECK(base.computations() == after_both,
          "y los dos se reutilizan, cada uno el suyo");
}

// --------------------------------------------------------------------------
// 4) Tocar una funcion NO invalida a la otra.  Es lo que hace que la
//    granularidad sea por funcion y no por modulo: sin esto, cambiar una linea
//    tira el trabajo de todas.
// --------------------------------------------------------------------------
static void test_other_function_survives() {
    ir::IrModule mod = make_module("f");
    ir::IrModule otro = make_module("g");
    mod.functions.push_back(otro.functions[0]);

    FactBase base(kStagePreOpt);
    (void)base.structure(mod.functions[0]);
    (void)base.structure(mod.functions[1]);
    const size_t before = base.computations();

    ++mod.functions[0].version; // cambia SOLO la primera
    (void)base.structure(mod.functions[1]);
    CHECK(base.computations() == before,
          "cambiar 'f' no obliga a recalcular 'g'");

    (void)base.structure(mod.functions[0]);
    CHECK(base.computations() > before, "pero 'f' si se recalcula");
}

// --------------------------------------------------------------------------
// 5) La version del MoDULO se mueve con cualquiera de sus funciones, que es lo
//    que necesitan los analisis interprocedurales.  Y NO es una suma: dos
//    funciones que se intercambiaran versiones darian la misma suma.
// --------------------------------------------------------------------------
static void test_module_version() {
    ir::IrModule mod = make_module("f");
    ir::IrModule otro = make_module("g");
    mod.functions.push_back(otro.functions[0]);

    const uint64_t v0 = FactBase::module_version(mod);
    ++mod.functions[1].version;
    const uint64_t v1 = FactBase::module_version(mod);
    CHECK(v0 != v1, "cambiar una funcion mueve la version del modulo");

    /* El intercambio: (1,0) y (0,1) suman lo mismo.  Si esto fallara, un
     * modulo se serviria con los resumenes del otro. */
    ir::IrModule a = make_module("f");
    a.functions.push_back(make_module("g").functions[0]);
    ir::IrModule b = make_module("f");
    b.functions.push_back(make_module("g").functions[0]);
    a.functions[0].version = 1;
    a.functions[1].version = 0;
    b.functions[0].version = 0;
    b.functions[1].version = 1;
    CHECK(FactBase::module_version(a) != FactBase::module_version(b),
          "versiones intercambiadas NO dan la misma clave");
}

// --------------------------------------------------------------------------
// 6) La clave de los hechos es HERMETICA, y por CAPAS.
//
//    Los hechos de post-opt dependen del optimizador, asi que cambiar `-O` les
//    tiene que cambiar la clave -- si no, se sirven los del otro nivel, que es
//    responder sobre otro programa --.  Los de pre-opt NO dependen de el, y su
//    clave debe quedarse igual: ahi el reuso entre niveles es correcto y
//    tirarlo seria invalidar de mas.
//
//    Las dos mitades juntas a proposito: una clave que lo mezclara todo pasaria
//    la primera comprobacion y fallaria la segunda sin que nadie lo viera.
// --------------------------------------------------------------------------
static void test_facts_key_is_hermetic() {
    vx::CompileOptions o2;
    o2.opt_level = 2;
    vx::CompileOptions o0;
    o0.opt_level = 0;

    const uint64_t post2 =
        vx::asa_facts_key(1234, o2, analysis::asa::kStagePostOpt);
    const uint64_t post0 =
        vx::asa_facts_key(1234, o0, analysis::asa::kStagePostOpt);
    CHECK(post2 != post0,
          "otro nivel de optimizacion = otra clave para los hechos POST-opt");

    const uint64_t pre2 =
        vx::asa_facts_key(1234, o2, analysis::asa::kStagePreOpt);
    const uint64_t pre0 =
        vx::asa_facts_key(1234, o0, analysis::asa::kStagePreOpt);
    CHECK(pre2 == pre0,
          "pero los de PRE-opt no dependen del optimizador: misma clave");

    CHECK(pre2 != post2, "y los dos momentos nunca comparten clave");

    // Y el contenido del modulo sigue mandando, claro.
    CHECK(vx::asa_facts_key(1234, o2, analysis::asa::kStagePreOpt) !=
              vx::asa_facts_key(5678, o2, analysis::asa::kStagePreOpt),
          "otro contenido = otra clave");
}

// --------------------------------------------------------------------------
// 7) Y cada momento tiene su FICHERO.  Con clave por momento, uno compartido no
//    se puede validar: su cabecera lleva una sola huella y la puerta rechaza el
//    fichero entero, asi que el segundo en escribir invalidaria al primero.
// --------------------------------------------------------------------------
static void test_facts_path_per_stage() {
    const std::string base = "algo/x.vxfacts";
    const std::string pre =
        vx::asa_facts_path_for_stage(base, analysis::asa::kStagePreOpt);
    const std::string post =
        vx::asa_facts_path_for_stage(base, analysis::asa::kStagePostOpt);
    CHECK(pre != post, "cada momento, su fichero");
    CHECK(pre.find(".vxfacts") != std::string::npos &&
              post.find(".vxfacts") != std::string::npos,
          "y los dos siguen siendo ficheros de hechos");
    CHECK(vx::asa_facts_path_for_stage(std::string(),
                                       analysis::asa::kStagePreOpt).empty(),
          "sin ruta base no se inventa ninguna: es 'no tocar disco'");
}

// --------------------------------------------------------------------------
// 8) TODOS los dominios saben decir de que dependen.
//
//    Un dominio que no lo dice se acepta de disco sin comprobar y, peor, en el
//    lector NI SIQUIERA PUEDE CADUCAR -- `caduco` solo se marca si la huella no
//    es cero --.  Su unica proteccion era que la puerta del modulo fuese
//    gruesa, asi que en cuanto esa se afine (granularidad por funcion) empezaria
//    a servir hechos rancios en silencio.
//
//    Este test es el que impide que vuelva a colarse uno: anadir un dominio sin
//    declarar sus entradas lo rompe.
// --------------------------------------------------------------------------
static void test_every_domain_declares_inputs() {
    ir::IrModule mod = make_module("f");
    const std::vector<const char *> all_domains = asa::registered_producers();
    CHECK(!all_domains.empty(), "hay dominios registrados");

    const std::vector<asa::DomainCost> checkable = asa::current_inputs(mod);
    for (const char *d : all_domains) {
        bool found = false;
        for (const asa::DomainCost &c : checkable)
            if (c.domain != nullptr && std::strcmp(c.domain, d) == 0) {
                found = true;
                /* Y con huella distinta de cero: en el lector, cero es
                 * justamente lo que impide caducar. */
                CHECK(c.fingerprint != 0,
                      "la huella de un dominio no puede ser cero");
                break;
            }
        if (!found) {
            ++g_fail;
            std::printf("FALLO: el dominio '%s' no declara de que depende; "
                        "se aceptaria de disco sin comprobar\n", d);
        }
        ++g_checks;
    }
}

// --------------------------------------------------------------------------
// 9) Y declarar MENOS invalida menos, que es para lo que sirve declarar.
//
//    `layout` mira los datos estaticos, no el codigo: cambiar una instruccion
//    NO tiene que moverle la huella.  Si todos acabaran dependiendo de todo,
//    esto seria contabilidad sin ahorro.
// --------------------------------------------------------------------------
static void test_declaring_less_invalidates_less() {
    ir::IrModule a = make_module("f");
    ir::IrModule b = make_module("f");
    // Un cambio de CoDIGO en b: una constante distinta.
    b.functions[0].blocks[0].instrs[0].imm = 99;

    const auto keys_a = asa::current_inputs(a);
    const auto keys_b = asa::current_inputs(b);

    auto key_of_domain = [](const std::vector<asa::DomainCost> &v,
                            const char *dom) -> uint64_t {
        for (const asa::DomainCost &c : v)
            if (c.domain != nullptr && std::strcmp(c.domain, dom) == 0)
                return c.fingerprint;
        return 0;
    };

    CHECK(key_of_domain(keys_a,asa::kProducerRanges) !=
              key_of_domain(keys_b,asa::kProducerRanges),
          "cambiar el codigo mueve la huella de quien mira el codigo");
    CHECK(key_of_domain(keys_a,asa::kProducerLayout) ==
              key_of_domain(keys_b,asa::kProducerLayout),
          "pero NO la de quien solo mira los datos estaticos");
}

// --------------------------------------------------------------------------
// 10) La clave se reparte POR FUNCIoN: tocar `g` mueve la de `g` y deja la de
//     `f` quieta.  Sin esto, la granularidad del fichero es decorativa: la
//     tabla se escribe pero todas sus entradas caducan a la vez.
// --------------------------------------------------------------------------
static void test_per_function_keys_are_split() {
    ir::IrModule a = two_function_module();
    ir::IrModule b = two_function_module();
    b.functions[1].blocks[0].instrs[0].imm = 99; // solo cambia `g`

    const auto ka = asa::current_inputs(a);
    const auto kb = asa::current_inputs(b);
    const std::vector<std::pair<uint64_t, uint64_t>> *fa =
        by_function_of(ka, asa::kProducerRanges);
    const std::vector<std::pair<uint64_t, uint64_t>> *fb =
        by_function_of(kb, asa::kProducerRanges);
    CHECK(fa != nullptr && fb != nullptr,
          "un dominio que declara entradas trae ademas su tabla por funcion");
    if (fa == nullptr || fb == nullptr) return;
    CHECK(fa->size() == 2 && fb->size() == 2,
          "una entrada por funcion con nombre");

    const uint64_t hf = asa::function_name_hash("f");
    const uint64_t hg = asa::function_name_hash("g");
    CHECK(key_for(*fa, hf) == key_for(*fb, hf),
          "tocar `g` NO mueve la clave de `f`");
    CHECK(key_for(*fa, hg) != key_for(*fb, hg),
          "pero si la de `g`, que es la que cambio");
    /* Y la de dominio se mueve igual, que es justo el problema que esto viene a
     * resolver: con ella sola, cambiar `g` invalidaba tambien a `f`. */
    CHECK(fingerprint_of(ka, asa::kProducerRanges) !=
              fingerprint_of(kb, asa::kProducerRanges),
          "la huella de dominio si se mueve: se pliega sobre TODAS");
}

// --------------------------------------------------------------------------
// 11) Y el escalon completo: se guarda con dos funciones, cambia una, y al
//     volver del disco entra lo de la que NO cambio.  Esto es lo que mide si el
//     mecanismo AHORRA: sin ello se escribe, se lee y no sirve de nada.
// --------------------------------------------------------------------------
static void test_partial_load_reuses_work() {
    asa::register_asa_canonical_names();
    ir::IrModule a = two_function_module();

    // Lo que se sabria de `a`: un hecho por funcion, del mismo dominio.
    FactStore written;
    written.add(fact_about("f"));
    written.add(fact_about("g"));

    std::vector<asa::DomainCost> keys = asa::current_inputs(a);
    for (asa::DomainCost &c : keys) c.recomputable = false; // que se guarde

    const std::vector<uint8_t> bytes = asa::serialize(
        written, 0x1234u, asa::CacheLevel::All, keys, /*compiler*/ 0x99u);
    CHECK(!bytes.empty(), "algo se escribio");

    // Ahora `g` cambia y `f` no.
    ir::IrModule b = two_function_module();
    b.functions[1].blocks[0].instrs[0].imm = 99;
    const std::vector<asa::DomainCost> keys_now = asa::current_inputs(b);

    FactStore read;
    const asa::ReadResult r =
        asa::read_facts(bytes.data(), bytes.size(), 0x1234u, read, keys_now,
                        /*compiler*/ 0x99u);
    CHECK(r.ok, "el fichero se leyo");
    CHECK(r.stale == 0, "el registro NO se tira entero: solo cambio una funcion");
    CHECK(r.partial_domains == 1, "se leyo a medias, y queda dicho");
    CHECK(r.facts == 1, "entra el hecho de `f`");
    CHECK(r.stale_facts == 1, "y se queda fuera el de `g`");
    CHECK(r.reused_functions == 1, "una funcion se dio por hecha");

    /* Y lo que hace que esto no duplique: el DOMINIO no se marca -- el
     * productor tiene que correr para rehacer `g` -- pero `f` si, para que se
     * la salte. */
    CHECK(!read.has_domain(asa::kProducerRanges, asa::kStagePreOpt),
          "el dominio queda SIN marcar: falta `g` por producir");
    CHECK(read.has_function(asa::kProducerRanges, asa::kStagePreOpt, "f"),
          "pero `f` si esta marcada: ya vino de disco");
    CHECK(!read.has_function(asa::kProducerRanges, asa::kStagePreOpt, "g"),
          "y `g` no, que es la que hay que rehacer");
}

// --------------------------------------------------------------------------
// 12) Si cambian TODAS, no hay nada que rescatar y se vuelve al todo-o-nada.
//     Importa que sea asi y no "parcial con cero funciones": un dominio parcial
//     no se marca, y dejarlo en ese estado sin nada cargado seria contar un
//     ahorro que no existe.
// --------------------------------------------------------------------------
static void test_all_stale_is_whole_record() {
    asa::register_asa_canonical_names();
    ir::IrModule a = two_function_module();
    FactStore written;
    written.add(fact_about("f"));
    written.add(fact_about("g"));
    std::vector<asa::DomainCost> keys = asa::current_inputs(a);
    for (asa::DomainCost &c : keys) c.recomputable = false;
    const std::vector<uint8_t> bytes =
        asa::serialize(written, 0x1234u, asa::CacheLevel::All, keys, 0x99u);

    ir::IrModule b = two_function_module();
    b.functions[0].blocks[0].instrs[0].imm = 41; // las DOS cambian
    b.functions[1].blocks[0].instrs[0].imm = 99;

    FactStore read;
    const asa::ReadResult r =
        asa::read_facts(bytes.data(), bytes.size(), 0x1234u, read,
                        asa::current_inputs(b), 0x99u);
    CHECK(r.stale == 1, "el registro entero caduca");
    CHECK(r.partial_domains == 0, "y no se cuenta como parcial");
    CHECK(r.facts == 0, "no entra ningun hecho");
    CHECK(read.marked_functions() == 0, "ni se marca ninguna funcion");
}

// --------------------------------------------------------------------------
// 13) Sin tabla por funcion se vuelve a lo de siempre: todo-o-nada por la
//     huella de dominio.  Es el caso de un fichero escrito antes y el de un
//     dominio que trae su propia huella del modulo.
// --------------------------------------------------------------------------
static void test_without_table_is_all_or_nothing() {
    asa::register_asa_canonical_names();
    ir::IrModule a = two_function_module();
    FactStore written;
    written.add(fact_about("f"));
    written.add(fact_about("g"));
    std::vector<asa::DomainCost> keys = asa::current_inputs(a);
    for (asa::DomainCost &c : keys) {
        c.recomputable = false;
        c.by_function.clear(); // se escribe SIN tabla por funcion
    }
    const std::vector<uint8_t> bytes =
        asa::serialize(written, 0x1234u, asa::CacheLevel::All, keys, 0x99u);

    // El mismo modulo: la huella de dominio cuadra y entra todo.
    FactStore same;
    const asa::ReadResult r1 =
        asa::read_facts(bytes.data(), bytes.size(), 0x1234u, same,
                        asa::current_inputs(a), 0x99u);
    CHECK(r1.facts == 2, "sin tabla, si la huella cuadra entra todo");
    CHECK(r1.partial_domains == 0, "y no hay nada parcial");
    CHECK(same.has_domain(asa::kProducerRanges, asa::kStagePreOpt),
          "el dominio se marca entero, que es lo de siempre");

    // Cambiando UNA funcion, la huella de dominio ya no cuadra: cae todo.
    ir::IrModule b = two_function_module();
    b.functions[1].blocks[0].instrs[0].imm = 99;
    FactStore other;
    const asa::ReadResult r2 =
        asa::read_facts(bytes.data(), bytes.size(), 0x1234u, other,
                        asa::current_inputs(b), 0x99u);
    CHECK(r2.stale == 1 && r2.facts == 0,
          "sin tabla, tocar una funcion tira el dominio entero");
}

// --------------------------------------------------------------------------
// 14) Y el eslabon que cierra el ahorro: el PRODUCTOR se salta la funcion que
//     ya vino de disco.  Sin esto todo lo anterior es decorativo -- la lectura
//     parcial deja el dominio sin marcar a proposito, asi que el productor
//     correria sobre las dos funciones y el almacen acabaria con lo de `f`
//     afirmado DOS veces.
// --------------------------------------------------------------------------
static void test_producer_skips_reused_function() {
    asa::register_asa_canonical_names();
    ir::IrModule mod = two_function_module();

    // Lo que haria una compilacion entera, sin cache: se produce todo.
    FactStore full;
    const auto s_full = asa::produce(mod, full, {asa::kProducerRanges},
                                     asa::kStagePreOpt);
    CHECK(s_full.size() == 1, "corre solo el dominio pedido");
    const uint32_t looked_full = s_full.empty() ? 0 : s_full[0].looked_at;
    CHECK(s_full.empty() || s_full[0].reused == 0,
          "sin cache no se reutiliza nada");

    // Y ahora lo mismo diciendo que `f` ya esta.
    FactStore partial;
    partial.mark_function(asa::kProducerRanges, asa::kStagePreOpt, "f");
    const auto s_part = asa::produce(mod, partial, {asa::kProducerRanges},
                                     asa::kStagePreOpt);
    CHECK(s_part.size() == 1, "el dominio corre igual: no esta marcado entero");
    if (s_part.empty()) return;
    CHECK(s_part[0].reused == 1, "y se salta UNA funcion, la que ya estaba");
    CHECK(s_part[0].looked_at < looked_full,
          "mirando MENOS que sin cache, que es el ahorro que se buscaba");
    CHECK(partial.of_function("f").empty(),
          "y no produce ni un hecho de `f`: lo suyo ya vino de disco");
    CHECK(!full.of_function("f").empty(),
          "mientras que sin cache si los produce (si no, el test no prueba "
          "nada)");
    CHECK(!partial.of_function("g").empty(),
          "pero `g` si se produce: es la que faltaba");
}

// --------------------------------------------------------------------------
// 15) Un dominio INTERPROCEDURAL no puede tener clave por funcion.
//
//     Es el unico error de esta cache que sirve hechos FALSOS en vez de rehacer
//     trabajo: `boundary` dice de una funcion lo que le llega a sus parametros,
//     y eso solo se sabe mirando a QUIEN LA LLAMA.  Con clave por funcion,
//     cambiar el llamante deja en pie una frontera que ya no es la suya.
// --------------------------------------------------------------------------
static void test_interprocedural_has_no_per_function_key() {
    ir::IrModule mod = two_function_module();
    const auto keys = asa::current_inputs(mod);
    CHECK(by_function_of(keys, asa::kProducerBoundary) == nullptr,
          "`boundary` NO trae tabla por funcion: mira mas alla de la funcion");
    CHECK(fingerprint_of(keys, asa::kProducerBoundary) != 0,
          "pero si su huella de dominio, que si pliega sobre todas");
    /* Y el resto si la trae: si esto se rompiera, el test de arriba pasaria por
     * el motivo equivocado -- porque NADIE tiene tabla --. */
    CHECK(by_function_of(keys, asa::kProducerRanges) != nullptr,
          "un dominio por funcion si la trae");
    CHECK(asa::current_inputs_per_function(mod, asa::kProducerBoundary).empty(),
          "y la consulta suelta dice lo mismo");
    /* `value_shape` es el otro: su recorrido de agregados SIGUE LAS LLAMADAS,
     * que es justo por lo que se le pasa la base. */
    CHECK(by_function_of(keys, asa::kProducerValueShape) == nullptr,
          "`value_shape` tampoco: sigue las llamadas");
}

// --------------------------------------------------------------------------
// 16) La POSICION sigue al codigo en vez de quedarse congelada.
//
//     Es la otra mitad del problema: un hecho no guarda su linea, guarda a QUE
//     entidad se refiere, y la linea se resuelve contra el intermedio que se
//     tenga delante.  Sin esto habia que elegir entre servir una linea rancia o
//     meter las posiciones en la clave -- y meterlas hacia que reindentar
//     tirara analisis que seguian siendo validos.
// --------------------------------------------------------------------------
static void test_position_follows_the_code() {
    ir::IrModule mod = make_module("f");
    ir::IrFunction &fn = mod.functions[0];
    /* Posiciones de fuente: el que las pone es el frontend, y aqui hacen falta
     * porque lo que se mide es justo que se muevan. */
    uint32_t n = 10;
    for (ir::IrBlock &b : fn.blocks)
        for (ir::IrInstr &in : b.instrs)
            in.source_line = n++;

    /* El ancla al valor que define la suma: la instruccion ADD, que es la
     * segunda del unico bloque -> linea 11. */
    const Anchor at{Anchor::Kind::Value, 1};
    {
        const AnchorLines lines(fn);
        CHECK(lines.of(at) == 11, "la linea sale de la instruccion que define");
    }

    /* Y ahora se REINDENTA: mismo codigo, todo una linea mas abajo.  Es lo que
     * hace meter una linea en blanco arriba, o `vm fmt`. */
    for (ir::IrBlock &b : fn.blocks)
        for (ir::IrInstr &in : b.instrs)
            ++in.source_line;
    {
        const AnchorLines lines(fn);
        CHECK(lines.of(at) == 12,
              "la MISMA ancla da la linea nueva: la posicion sigue al codigo");
    }

    /* Y lo que decide que esto sea gratis: mover el texto NO mueve la clave, o
     * sea que no caduca nada.  Antes esto fallaba en los dos sentidos a la vez
     * -- o la linea mentia, o se tiraba el analisis para que no mintiera --. */
    ir::IrModule movido = make_module("f");
    for (ir::IrBlock &b : movido.functions[0].blocks)
        for (ir::IrInstr &in : b.instrs)
            in.source_line += 100;
    const auto k0 = asa::current_inputs(make_module("f"));
    const auto k1 = asa::current_inputs(movido);
    CHECK(fingerprint_of(k0, asa::kProducerRanges) ==
              fingerprint_of(k1, asa::kProducerRanges),
          "mover el texto no mueve la clave: reindentar no invalida nada");

    /* La clase `Line` es la excepcion declarada: una posicion ya materializada,
     * para lo que no cuelga de ninguna entidad -- o para un hecho hecho para
     * sobrevivir a su momento --.  Se resuelve a si misma. */
    const AnchorLines lines(fn);
    CHECK(lines.of(Anchor{Anchor::Kind::Line, 77}) == 77,
          "una linea materializada se devuelve tal cual");
    CHECK(lines.of(Anchor{}) == 0,
          "sin ancla, cero: `no consta` NO es la linea 1");
}

int main() {
    test_every_domain_declares_inputs();
    test_position_follows_the_code();
    test_interprocedural_has_no_per_function_key();
    test_declaring_less_invalidates_less();
    test_per_function_keys_are_split();
    test_partial_load_reuses_work();
    test_all_stale_is_whole_record();
    test_without_table_is_all_or_nothing();
    test_producer_skips_reused_function();
    test_facts_key_is_hermetic();
    test_facts_path_per_stage();
    test_reuse_same_version();
    test_version_forces_recompute();
    test_stage_separates();
    test_other_function_survives();
    test_module_version();
    std::printf("=== fact-base reuse: %d checks, %d fallos ===\n", g_checks,
                g_fail);
    return g_fail == 0 ? 0 : 1;
}
