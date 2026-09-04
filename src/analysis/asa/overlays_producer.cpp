/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 *
 * Software libre bajo GPLv2.  La salida del compilador (programas
 * escritos en Vesta) NO queda sujeta a la GPL (excepcion de runtime).
 */

/**
 * @file analysis/asa/overlays_producer.cpp
 * @brief El dominio `asa.overlays`: que bytes cubre cada campo de una vista.
 *
 * Una vista `@overlay` DESCRIBE como esta puesto un formato en memoria, y ese
 * es conocimiento que hasta ahora se quedaba dentro del comprobador de tipos.
 * Aqui se publica, y con eso tres preguntas distintas pasan a tener el mismo
 * sitio donde hacerse:
 *
 *   - "que bytes de la vista no describe nadie" -- el hueco, que el linter
 *     saca a peticion;
 *   - "pueden estos dos campos ser la misma direccion" -- lo que hace falta
 *     para no recargar la cabecera despues de cada escritura;
 *   - "cubre esta vista el formato entero".
 *
 * El productor NO calcula nada: el tramo de cada campo -- con su marco de
 * simbolos -- lo resolvio el frontend, que es el unico que tiene la expresion
 * del offset delante, y viaja en @c ir::IrModule::overlays.  Aqui solo se
 * afirma, que es lo que separa un productor de un analisis.
 */

#include "analysis/asa/fact_base.h"
#include "analysis/asa/producers.h"
#include "codegen/rbank/physical_bank.h" // la geometria de lanes, no una copia
#include "ir/ssa_ir.h"
#include "jit/backend_caps.h" // los niveles de --float-isa, no una copia

#include <algorithm>
#include <string>
#include <unordered_map>
#include <vector>

namespace analysis {
namespace asa {

namespace {

/// Une el marco de simbolos de un tramo para que viaje en el detalle del
/// hecho.  Vacio = el tramo cuelga del principio de la vista.
std::string frame_of(const ir::IrOverlayField &f) {
    std::string out;
    for (const std::string &t : f.terms) {
        if (!out.empty()) out.push_back('+');
        out += t;
    }
    return out;
}

/**
 * @brief Huella de las ENTRADAS del dominio, sin producir nada.
 *
 * Las vistas y NADA MAS: la cobertura de un `@overlay` no depende de una sola
 * linea del codigo de las funciones, asi que tocar un cuerpo no puede
 * cambiarla.  Con la huella del modulo entero, cualquier edicion tiraba estos
 * hechos y habia que rehacerlos para llegar al mismo sitio.
 *
 * @param mod Modulo que se esta compilando.
 * @return La huella; nunca cero, que esta reservado para "no se decirlo".
 */
uint64_t overlays_inputs(const ir::IrModule &mod) {
    uint64_t h = 0xCBF29CE484222325ull; // FNV-1a de 64
    auto mezcla = [&h](uint64_t v) {
        h ^= v;
        h *= 0x100000001B3ull;
    };
    auto texto = [&](const std::string &s) {
        for (unsigned char c : s)
            mezcla(c);
        mezcla(0);
    };
    for (const ir::IrOverlay &ov : mod.overlays) {
        texto(ov.name);
        mezcla(ov.extent);
        mezcla(ov.line);
        for (const ir::IrOverlayField &f : ov.fields) {
            texto(f.name);
            for (const std::string &t : f.terms)
                texto(t);
            mezcla(static_cast<uint64_t>(f.begin));
            mezcla(static_cast<uint64_t>(f.end));
            mezcla(f.known ? 1u : 0u);
            mezcla(f.shares_on_purpose ? 1u : 0u);
        }
    }
    return h == 0 ? 1ull : h;
}

} // namespace

/**
 * @brief Afirma la cobertura de cada vista `@overlay` del modulo.
 * @param p Lo que el productor recibe (modulo, base y almacen).
 */
/**
 * @brief Responde, POR ISA, con que ancho de lane se puede tratar un tramo.
 *
 * El tramo contiguo dice que los bytes se pueden tratar juntos; esto dice CON
 * QUE.  Son dos preguntas distintas y la segunda no tiene una sola respuesta:
 * el mismo tramo de 152 bytes va en tres piezas de 64 donde hay lanes de 64, en
 * cinco de 32 donde llegan a 32, y en una ISA sin banco ancho no va en ninguna.
 * Por eso la respuesta viaja con su AMBITO en vez de resolverse aqui a la ISA
 * de esta compilacion: el mismo modulo se compila a varias, y el hecho se
 * guarda en disco entre compilaciones.
 *
 * La geometria NO se escribe aqui: se pregunta al banco de registros, que es
 * quien la tiene (@c descriptor_x86_64 y companeros).  Copiarla seria tener dos
 * tablas de anchos que se separan en cuanto una de las dos cambie, y la que se
 * quedaria vieja es esta -- nadie compila con ella --.
 *
 * Y cuando una ISA no puede, lo DICE con el motivo: "no lo se" y "se que no"
 * llevan a decisiones opuestas, y un consumidor que no distinga las dos
 * ensancharia donde no se puede o dejaria de ensanchar donde si.
 *
 * @param p       Produccion en curso.
 * @param view    Nombre de la vista, ya internado.
 * @param subject Sujeto base al que colgar el hecho.
 * @param first   Indice del primer campo del tramo (lo une con el tramo).
 * @param begin   Primer byte del tramo.
 * @param end     Byte siguiente al ultimo.
 */
void say_run_lanes(Production &p, const char *view, const Subject &subject,
                   uint32_t first, int64_t begin, int64_t end) {
    const int64_t len = end - begin;
    /* Las ISAs que el banco sabe describir, con la geometria que el mismo da.
     * Para x86-64 se pregunta por los TRES niveles y no por el del anfitrion:
     * lo que se guarda es "si hay lanes de 64, caben tres piezas", que es
     * cierto en cualquier maquina, y elegir nivel es de quien emite. */
    struct IsaLanes {
        const char *isa;
        /// Codigo del catalogo que dice DE DONDE salen estas lanes.  El texto
        /// no se escribe aqui: sale traducido al idioma de quien lo lea.
        const char *why;
        std::vector<codegen::rbank::ViewWidth> widths;
        /** Codigo del catalogo si la ISA puede tener lanes MAS anchas de las
         *  que el banco enumera, o nullptr si lo enumerado es todo lo que hay.
         *  Ver el caso de aarch64 mas abajo. */
        const char *may_exceed = nullptr;
    };
    /* Las vistas de la clase ancha de un descriptor, que es donde vive la
     * geometria.  Se pide asi y no se copia: dos tablas de anchos se separan en
     * cuanto una cambie, y la que se quedaria vieja es la copia. */
    const auto wide_of = [](const codegen::rbank::TargetDescriptor &d) {
        return d.classes[static_cast<size_t>(
                             codegen::rbank::ResourceClass::FP_VECTOR)]
            .widths;
    };
    /* x86-64 se responde por NIVEL, no con el techo de la arquitectura: con
     * `--float-isa sse2` no hay lanes de 64 por mucho que la ISA las tenga, y
     * afirmarlas seria emitir codigo que el objetivo no admite.  Los niveles y
     * lo que da cada uno los define @c backend_caps_from_float_isa, que es el
     * unico sitio que lo sabe. */
    const IsaLanes isas[] = {
        {kIsaX8664, "overlay.lanes_sse2",
         codegen::rbank::x86_fp_widths(
             jit::backend_caps_from_float_isa(jit::FloatIsa::SSE2))},
        {kIsaX8664, "overlay.lanes_avx",
         codegen::rbank::x86_fp_widths(
             jit::backend_caps_from_float_isa(jit::FloatIsa::AVX))},
        {kIsaX8664, "overlay.lanes_avx512f",
         codegen::rbank::x86_fp_widths(
             jit::backend_caps_from_float_isa(jit::FloatIsa::AVX512F))},
        {kIsaX8632, "overlay.lanes_x86_32",
         wide_of(codegen::rbank::descriptor_x86_32())},
        /* aarch64: lo que el banco enumera hoy son las lanes obligatorias de la
         * base, y eso es DEMOSTRABLE.  No es el techo de la arquitectura, y el
         * ancho de las mas anchas SI se puede fijar en el binario -- igual que
         * en x86 se fija con @c --float-isa --.  Lo que falta es el eje para
         * declararlo: @c BackendCaps solo lleva bits de x86 y
         * @c descriptor_arm64 ni mira las capacidades que recibe.
         *
         * O sea que no se sabe, pero NO porque dependa de la maquina: porque
         * nadie lo ha declarado todavia.  Son cosas distintas y llevan a
         * acciones distintas -- la primera obligaria a una guarda en ejecucion,
         * la segunda se arregla anadiendo el eje --, asi que se dice cual es.
         *
         * Se afirma el SUELO y por encima se dice que hay mas.  Afirmar el
         * suelo como MAXIMO seria peor que callarse: un consumidor lo leeria
         * como demostrado y dejaria de ensanchar donde si se puede. */
        /* Capacidades vacias, y no un nivel de x86: `descriptor_arm64` no las
         * mira -- de ahi que su suelo sea lo unico que hoy se puede afirmar --
         * y pasarle `--float-isa avx512f` sugeriria que ese eje gobierna algo
         * aqui, que es justo lo que NO pasa todavia. */
        {kIsaArm64, "overlay.lanes_arm64_baseline",
         wide_of(codegen::rbank::descriptor_arm64(jit::BackendCaps{})),
         "overlay.arm64_wide_lane_axis_missing"},
        {kIsaVelb, "overlay.lanes_velb",
         wide_of(codegen::rbank::descriptor_interp())},
    };

    for (const IsaLanes &il : isas) {
        /* La lane mas ancha que CABE en el tramo.  Una mas ancha que el propio
         * tramo no sirve: leeria o escribiria bytes de detras, que no son de
         * esta vista. */
        int64_t best = 0;
        for (codegen::rbank::ViewWidth w : il.widths) {
            const int64_t bytes = static_cast<int64_t>(w);
            if (bytes <= len && bytes > best) best = bytes;
        }
        Subject about = subject;
        about.function = view;
        about.id = first;
        /* Sin lane que quepa no hay nada que ensanchar, y se dice cual de las
         * dos cosas pasa: la ISA no tiene banco, o lo tiene y el tramo es mas
         * corto que su lane mas estrecha. */
        if (best <= 1) {
            /* No es ignorancia: se sabe perfectamente que aqui no se puede, y
             * por cual de las dos razones.  Mezclarlo con los "no supe"
             * inflaria el recuento con casos donde no hay nada que arreglar. */
            p.say_unknown(about, UnknownReason::NothingToSay,
                          il.widths.empty() ? "overlay.no_wide_bank"
                                            : "overlay.run_shorter_than_lane",
                          kProducerOverlays, view,
                          Scope::only_in_isa(il.isa, il.why));
            continue;
        }
        Fact f;
        f.what.domain = kProducerOverlays;
        f.what.code = "overlay.run_lane_width";
        f.what.a = begin;
        f.what.b = best;
        /* Cuantas piezas enteras de esa lane y cuantos bytes sobran al final:
         * es lo que quien emite tiene que producir, y sale de una division que
         * no tiene por que repetir cada consumidor. */
        f.what.detail = p.store.intern(std::to_string(len / best) + "+" +
                                       std::to_string(len % best));
        f.about = about;
        f.seal.certainty = Certainty::Proven;
        f.seal.origin.source = Source::Static;
        f.seal.origin.producer = kProducerOverlays;
        f.proof.rule = "overlay.bank_lane_geometry";
        f.scope = Scope::only_in_isa(il.isa, il.why);
        p.assert_fact(f);
        /* El suelo esta dicho; si la ISA da mas, se dice tambien -- y que no
         * se sabe cuanto --.  Son dos respuestas a dos preguntas: "cuanto
         * puedo asegurar" y "puedo asegurar que no hay mas".  La segunda es la
         * que evita que un consumidor lea el suelo como techo. */
        if (il.may_exceed != nullptr)
            p.say_unknown(about, UnknownReason::MissingDependency,
                          "overlay.wider_lane_not_declarable",
                          kProducerOverlays, view,
                          Scope::only_in_isa(il.isa, il.may_exceed));
    }
}

/**
 * @brief Publica los TRAMOS CONTIGUOS de una vista: rangos de bytes que sus
 *        campos embaldosan sin hueco y sin solape.
 *
 * Es lo que autoriza a tratar varios campos de una vez con una palabra mas
 * ancha que cualquiera de ellos.  Ese permiso no lo puede dar quien transforma:
 * necesita saber que entre `r0` y `r1` no queda un byte sin describir (o
 * escribiria encima de algo que no es suyo) y que ningun campo pisa a otro (o
 * el orden de las escrituras cambiaria el resultado).  Las dos cosas las sabe
 * la vista, y solo la vista.
 *
 * El tramo se declara del LAYOUT, no de ningun uso concreto: es igual de cierto
 * para poner a cero, para copiar y para comparar, y ninguno de los tres tiene
 * que volver a mirarlo.  Por eso vive aqui y no dentro del pase que lo gasta.
 *
 * Solo se juntan campos del MISMO marco.  Dos tramos colgados de simbolos
 * distintos no se pueden comparar entre si -- el propio productor ya separa
 * @c overlay.covers de @c overlay.covers_relative por esa razon --, y sumarlos
 * daria un rango que nadie ha demostrado contiguo.
 *
 * @param p       Produccion en curso.
 * @param ov      Vista de la que salen los tramos.
 * @param view    Nombre de la vista, ya internado.
 * @param subject Sujeto base (simbolo) al que colgar el hecho.
 */
void produce_contiguous_runs(Production &p, const ir::IrOverlay &ov,
                             const char *view, const Subject &subject) {
    /* Campos de offset conocido, agrupados por marco y ordenados por donde
     * empiezan.  El orden de DECLARACION no sirve: nada obliga a escribir los
     * campos de una vista en orden de direccion, y darlo por hecho partiria un
     * tramo perfectamente contiguo en cuanto alguien reordene el fuente. */
    struct Piece {
        int64_t begin;
        int64_t end;
        uint32_t idx;
    };
    std::unordered_map<std::string, std::vector<Piece>> by_frame;
    uint32_t idx = 0;
    for (const ir::IrOverlayField &fi : ov.fields) {
        const uint32_t here = idx++;
        if (!fi.known) continue;
        by_frame[frame_of(fi)].push_back(Piece{fi.begin, fi.end, here});
    }

    for (auto &entry : by_frame) {
        std::vector<Piece> &ps = entry.second;
        std::sort(ps.begin(), ps.end(), [](const Piece &x, const Piece &y) {
            return x.begin < y.begin;
        });
        size_t i = 0;
        while (i < ps.size()) {
            size_t j = i;
            int64_t end = ps[i].end;
            /* Un tramo crece mientras el siguiente campo EMPIECE justo donde
             * acaba el anterior.  Cualquier otra cosa lo corta: si empieza
             * antes hay solape (y el orden importaria), si empieza despues hay
             * un hueco (y ensancharlo escribiria en bytes de nadie). */
            while (j + 1 < ps.size() && ps[j + 1].begin == end) {
                ++j;
                end = ps[j].end;
            }
            const size_t count = j - i + 1;
            /* Un campo solo no es un tramo: decirlo no anade nada a su propio
             * `overlay.covers` y llenaria la base de hechos de ruido. */
            if (count > 1) {
                say_run_lanes(p, view, subject, ps[i].idx, ps[i].begin, end);
                Fact f;
                f.what.domain = kProducerOverlays;
                f.what.code = "overlay.contiguous_run";
                f.what.a = ps[i].begin;
                f.what.b = end;
                /* Cuantos campos lo forman y en que marco: lo primero es lo
                 * que un consumidor ahorra, lo segundo con quien se puede
                 * comparar.  Sin marco no se pone el separador. */
                const std::string &frame = entry.first;
                f.what.detail = p.store.intern(
                    std::to_string(count) + (frame.empty() ? "" : "|" + frame));
                f.about = subject;
                f.about.function = view;
                /* El PRIMER campo del tramo, que es por donde empieza a
                 * mirarlo quien lo consuma. */
                f.about.id = ps[i].idx;
                f.seal.origin.site = ov.line;
                f.seal.certainty = Certainty::Proven;
                f.seal.origin.source = Source::Static;
                f.seal.origin.producer = kProducerOverlays;
                f.proof.rule = "overlay.declared_layout";
                p.assert_fact(f);
            }
            i = j + 1;
        }
    }
}

void produce_overlays(Production &p) {
    Subject subject;
    subject.kind = Subject::Kind::Symbol;

    /* Un modulo sin vistas NO es un modulo sin mirar, y los dos se distinguen:
     * callarse dejaria "aqui no hay vistas" indistinguible de "este dominio no
     * corrio", y ademas obligaria a volver a no encontrar nada en cada
     * compilacion, porque un dominio que no deposita nada no tiene que
     * guardar. */
    if (p.mod.overlays.empty()) {
        p.say_unknown(subject, UnknownReason::NothingToSay,
                      "overlays.none_declared", kProducerOverlays, "",
                      Scope::everywhere());
        return;
    }

    for (const ir::IrOverlay &ov : p.mod.overlays) {
        const char *view = p.store.intern(ov.name);
        ++p.summary.looked_at;

        /* La HUELLA de la vista: hasta donde llega lo que describen sus campos
         * de offset constante.  Es lo que `sizeof(T)` devuelve, y quien reserva
         * el buffer de respaldo necesita saberlo sin volver a mirar el
         * layout. */
        {
            Fact f;
            f.what.domain = kProducerOverlays;
            f.what.code = "overlay.extent";
            f.what.a = static_cast<int64_t>(ov.extent);
            f.what.detail = view;
            /* Donde se declara: una vista no es una funcion, asi que quien
             * quiera senalarla no la puede localizar por el codigo. */
            f.seal.origin.site = ov.line;
            f.about = subject;
            f.about.function = view;
            f.seal.certainty = Certainty::Proven;
            f.seal.origin.source = Source::Static;
            f.seal.origin.producer = kProducerOverlays;
            f.proof.rule = "overlay.declared_layout";
            p.assert_fact(f);
        }

        uint32_t idx = 0;
        for (const ir::IrOverlayField &fi : ov.fields) {
            Subject about = subject;
            about.function = view;
            about.id = idx++;
            /* Un campo cuyo tramo no se sabe NO se calla: sin el motivo, un
             * consumidor no puede distinguir "este campo no pisa a nadie" de
             * "no se pudo mirar", y las dos respuestas llevan a decisiones
             * opuestas -- la primera permite reordenar dos accesos, la segunda
             * lo prohibe. */
            if (!fi.known) {
                p.say_unknown(about, UnknownReason::RuntimeDependent,
                              "overlay.address_is_computed", kProducerOverlays,
                              p.store.intern(ov.name + "." + fi.name),
                              /* La direccion de un campo la decide su
                               * declaracion, no el objetivo: si no se sabe
                               * donde cae, no se sabe en ninguno. */
                              Scope::everywhere());
                continue;
            }
            Fact f;
            f.what.domain = kProducerOverlays;
            /* Dos codigos y no uno con una bandera: un tramo que cuelga de un
             * simbolo solo se puede comparar con otro del MISMO marco, y quien
             * consume tiene que poder filtrarlos sin leer el detalle. */
            f.what.code =
                fi.terms.empty() ? "overlay.covers" : "overlay.covers_relative";
            f.what.a = fi.begin;
            f.what.b = fi.end;
            /* Nombre del campo y su marco, separados: el marco es lo que decide
             * con quien se puede comparar el tramo.  Sin marco no se pone el
             * separador -- un `kind|` colgando en el volcado sugiere un dato
             * que falta, y lo que hay es que no hace falta. */
            const std::string frame = frame_of(fi);
            f.what.detail = p.store.intern(
                frame.empty() ? fi.name : (fi.name + "|" + frame));
            f.about = about;
            f.seal.certainty = Certainty::Proven;
            f.seal.origin.source = Source::Static;
            f.seal.origin.producer = kProducerOverlays;
            f.proof.rule = fi.shares_on_purpose ? "overlay.declared_sharing"
                                                : "overlay.declared_offset";
            p.assert_fact(f);
        }

        produce_contiguous_runs(p, ov, view, subject);
    }
}

void register_overlays_producer() {
    register_producer(kProducerOverlays, &produce_overlays,
                      &overlays_inputs);
}

} // namespace asa
} // namespace analysis
