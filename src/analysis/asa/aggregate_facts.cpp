/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file aggregate_facts.cpp
 * @brief Implementacion del dominio de FORMA de un valor (ver
 * aggregate_facts.h).
 *
 * Tres partes en el orden de los tres niveles: se OBSERVA (con contexto), se
 * DERIVA un perfil de uso, y solo al final se PROYECTA.  El recorrido no
 * concluye nada; anota lo que ve, por donde se le escapa el valor, y que no ha
 * podido seguir.
 */
#include "util/env_flags.h"
#include "analysis/asa/aggregate_facts.h"

#include "analysis/asa/fact_base.h" // la base compartida, cuando la hay
#include "analysis/memory/fn_targets.h"
#include "analysis/memory/points_to.h"
#include "ir/ssa_ir.h"

#include <cstdio>
#include <cstdlib>
#include <memory>
#include <map>
#include <unordered_map>
#include <unordered_set>

namespace analysis {
namespace asa {

// =========================================================================
//  Nombres estables (para volcados; el texto de usuario sale del catalogo)
// =========================================================================

const char *nombre_forma(FormaDeValor f) {
    switch (f) {
    case FormaDeValor::Agregado: return "agregado";
    case FormaDeValor::Compuesto: return "compuesto";
    case FormaDeValor::Desconocida: return "desconocida";
    default: return "sin-evidencia";
    }
}

const char *nombre_relacion(RelacionAcceso r) {
    switch (r) {
    case RelacionAcceso::EnPropietario: return "en-propietario";
    case RelacionAcceso::EnOperacion: return "en-operacion";
    default: return "ninguna";
    }
}

const char *nombre_frontera(CodigoFrontera c) {
    switch (c) {
    case CodigoFrontera::ComponenteSeLleva: return "componente-se-lleva";
    default: return "direccion-guardada";
    }
}

const char *nombre_identidad(IdentidadUniverso i) {
    return i == IdentidadUniverso::Desconocido ? "desconocido" : "conocido";
}

const char *nombre_observacion(EstadoObservacion o) {
    return o == EstadoObservacion::NoObservado ? "no-observado" : "observado";
}

const char *nombre_limitacion(CodigoLimitacion c) {
    switch (c) {
    case CodigoLimitacion::DestinoIndirectoNoUnico: return "destino-no-unico";
    case CodigoLimitacion::DestinoNoVisible: return "destino-no-visible";
    case CodigoLimitacion::ParametroFueraDeRango: return "parametro-fuera";
    default: return "profundidad-agotada";
    }
}

const char *nombre_motivo(MotivoForma m) {
    switch (m) {
    case MotivoForma::UniversoIncompleto: return "universo-incompleto";
    case MotivoForma::ParticipaComoUnidad: return "participa-como-unidad";
    case MotivoForma::SinParticipacionUnidadObservada:
        return "sin-participacion-observada";
    case MotivoForma::AccesoEnPropietario: return "acceso-en-propietario";
    case MotivoForma::AccesoEnOperacion: return "acceso-en-operacion";
    case MotivoForma::AccesoDinamico: return "acceso-dinamico";
    case MotivoForma::AccesoIndependienteDeOperacion:
        return "acceso-independiente-de-operacion";
    default: return "sin-observacion";
    }
}

/**
 * @brief Liga cada acceso del propietario al ciclo de vida del valor, si lo
 * esta.
 *
 * Se hace al final, cuando ya se ha visto todo: hasta entonces no se sabe que
 * desplazamientos escriben sus operaciones.
 *
 * ESCRIBIR y LEER desde el propietario no son lo mismo, y tratarlos igual era
 * un error medido:
 *
 *   escribir -> CONSTRUIR el valor.  Pertenece a su ciclo de vida siempre, use
 *               o no ese campo la operacion a la que se pasa despues.
 *   leer     -> depende.  Leer lo que una operacion escribio es CONSUMIR su
 *               resultado; leer un sitio que ninguna produce es usar una parte
 *               al margen de lo que el valor hace.
 *
 * Solo lo ultimo hace que "participa como unidad" y "se tocan sus partes" sean
 * de verdad incompatibles.
 */
void ligar_accesos(std::vector<AccesoComponente> &accesos) {
    std::unordered_set<int64_t> escritos_por_operacion;
    for (const AccesoComponente &a : accesos)
        if (a.relacion == RelacionAcceso::EnOperacion && a.offset_sabido &&
            a.escribe)
            escritos_por_operacion.insert(a.offset);
    for (AccesoComponente &a : accesos) {
        if (a.relacion != RelacionAcceso::EnPropietario) continue;
        if (!a.offset_sabido) continue; // ya se anota como acceso dinamico
        /* ESCRIBIR desde el propietario es CONSTRUIR el valor: se establece su
         * contenido, y eso pertenece a su ciclo de vida tanto si alguna
         * operacion lee ese sitio como si no.  Tratarlo igual que una lectura
         * era el error -- MEDIDO: un valor que se construye campo a campo y se
         * pasa entero a una operacion que solo mira uno de ellos salia
         * "evidencia contradictoria", cuando lo unico que pasa es que se
         * inicializo algo que esa operacion no necesita. */
        if (a.escribe) {
            a.ligado_a_operacion = true;
            continue;
        }
        /* LEER, en cambio, si distingue: leer lo que una operacion escribio es
         * consumir su resultado; leer un sitio que ninguna produce es usar una
         * parte al margen de lo que el valor hace. */
        a.ligado_a_operacion = escritos_por_operacion.count(a.offset) > 0;
    }
}

// =========================================================================
//  NIVEL B -- perfil derivado
// =========================================================================

uint32_t AggregateFacts::accesos_con(RelacionAcceso r) const {
    uint32_t n = 0;
    for (const AccesoComponente &a : accesos)
        if (a.relacion == r) ++n;
    return n;
}

uint32_t AggregateFacts::offsets_tocados() const {
    std::unordered_set<int64_t> vistos;
    for (const AccesoComponente &a : accesos)
        if (a.offset_sabido) vistos.insert(a.offset);
    return static_cast<uint32_t>(vistos.size());
}

PerfilDeUso AggregateFacts::perfil() const {
    PerfilDeUso p;
    p.unidad = !participaciones.empty();
    for (const AccesoComponente &a : accesos) {
        if (a.relacion == RelacionAcceso::EnPropietario) {
            p.acceso_en_propietario = true;
            if (a.offset_sabido && !a.ligado_a_operacion)
                p.acceso_independiente = true;
        } else if (a.relacion == RelacionAcceso::EnOperacion) {
            p.acceso_en_operacion = true;
        }
        if (!a.offset_sabido) p.acceso_dinamico = true;
    }
    p.escapa = !fronteras.empty();
    p.transferencia_entera = transferido_como_bloque;
    p.retorno_entero = devuelto_entero;
    p.paso_por_abi = pasado_por_abi;
    /* Observarlo TODO exige las dos cosas, y por motivos distintos: sin
     * limitaciones porque si no hay trozos del programa que no se han mirado, y
     * sin fronteras porque una direccion que se va deja usos que no pasan por
     * aqui.  Lo primero es del analisis; lo segundo, del programa. */
    p.universo_completo = cerrado(0);
    return p;
}

// =========================================================================
//  NIVEL C -- proyecciones.  Las dos, del MISMO perfil.
// =========================================================================

bool AggregateFacts::cerrado(uint32_t universo) const {
    return universo < universos.size() && universos[universo].cerrado;
}

/**
 * @brief Forma vista DESDE un ambito: solo cuenta lo observado ahi dentro.
 *
 * Es lo que impide que una frontera lejana borre una verdad local.  Si el
 * ambito de `mul` esta cerrado y ahi el valor participa como unidad, eso es
 * cierto en `mul` por mucho que el modulo siga abierto por un `callind` de otra
 * funcion. Las dos respuestas son correctas; solo hay que decir desde donde se
 * mira.
 */
FormaDeValor AggregateFacts::forma_en(uint32_t universo) const {
    if (!cerrado(universo)) return FormaDeValor::SinEvidencia;
    bool unidad = false, propietario = false, independiente = false,
         dinamico = false;
    // Cuenta lo de este ambito y lo de los que cuelgan de el: la implementacion
    // de una operacion pertenece al ambito que la contiene.
    auto dentro = [&](uint32_t u) {
        while (u < universos.size()) {
            if (u == universo) return true;
            if (u == universos[u].padre) return false;
            u = universos[u].padre;
        }
        return false;
    };
    for (const ParticipacionUnidad &p : participaciones)
        if (dentro(p.sitio.universo)) unidad = true;
    for (const AccesoComponente &a : accesos) {
        if (!dentro(a.sitio.universo)) continue;
        if (!a.offset_sabido) dinamico = true;
        if (a.relacion != RelacionAcceso::EnPropietario) continue;
        propietario = true;
        if (a.offset_sabido && !a.ligado_a_operacion) independiente = true;
    }
    if (dinamico) return FormaDeValor::Desconocida;
    if (unidad && independiente) return FormaDeValor::Desconocida;
    if (unidad) return FormaDeValor::Compuesto;
    if (propietario) return FormaDeValor::Agregado;
    return FormaDeValor::SinEvidencia;
}

std::vector<AggregateFacts::EfectoAlcance> AggregateFacts::efectos() const {
    std::vector<EfectoAlcance> out;
    for (const Universo &u : universos) {
        // Solo hay efecto si aqui SE DEMOSTRO algo y ahi fuera no se puede
        // sostener: una verdad local que no sube.
        if (!u.cerrado || u.id == u.padre) continue;
        const FormaDeValor f = forma_en(u.id);
        if (f == FormaDeValor::SinEvidencia) continue;
        if (cerrado(u.padre)) continue; // sube sin problema: no hay efecto
        EfectoAlcance e;
        e.universo = u.id;
        e.forma = f;
        e.bloqueado_en = u.padre;
        /* La CAUSA es la frontera registrada en el ambito que no cierra.  Se
         * busca ahi y no en cualquier sitio: lo que abre a otro universo no
         * explica por que este no eleva. */
        /* La causa se busca por CONTENCION, no solo en el ambito exacto: un
         * ambito puede estar abierto por una frontera que sale de otro que
         * contiene, y esa frontera SIGUE SIENDO la razon por la que la verdad
         * no sube.  Mirar solo el ambito exacto dejaba sin explicar mas de un
         * tercio de los efectos (134 de 366 medidos). */
        auto contenido_en = [&](UniversoId u2, UniversoId ancestro) {
            while (u2 < universos.size()) {
                if (u2 == ancestro) return true;
                if (u2 == universos[u2].padre) return false;
                u2 = universos[u2].padre;
            }
            return false;
        };
        bool hallada = false;
        for (const Frontera &es : fronteras)
            if (contenido_en(es.desde, u.padre)) {
                e.por_frontera = true;
                e.frontera = es.codigo;
                e.causa = es.sitio;
                hallada = true;
                break;
            }
        if (!hallada)
            for (const Limitacion &l : limitaciones)
                if (contenido_en(l.sitio.universo, u.padre)) {
                    e.limitacion = l.codigo;
                    e.causa = l.sitio;
                    hallada = true;
                    break;
                }
        /* El padre puede estar abierto por otro ambito que contiene, no por si
         * mismo.  Entonces la causa NO esta aqui, y eso se DICE: callarse haria
         * pensar que no hay efecto, e inventar una causa seria mentir.  El
         * efecto es igual de real; lo que falta es donde se origina. */
        e.causa_localizada = hallada;
        out.push_back(e);
    }
    return out;
}

FormaDeValor AggregateFacts::forma() const {
    const PerfilDeUso p = perfil();
    /* Sin haber observado el universo entero no se afirma ninguna forma.  La
     * tentacion esta en "no he visto que participe como unidad": concluir
     * `Agregado` ahi convierte "no lo he visto" en "no lo hay". */
    if (!p.universo_completo) return FormaDeValor::SinEvidencia;
    /* Hay evidencia relevante -- se accede a un componente sin saber a cual --
     * pero no permite separar interpretaciones.  Eso es `Desconocida`, que no
     * es lo mismo que no tener evidencia. */
    if (p.acceso_dinamico) return FormaDeValor::Desconocida;
    /* Participar como unidad y que se toquen sus partes NO se contradice: asi
     * es como se implementa una unidad, y como se construye y se consume.  Lo
     * que SI son dos interpretaciones incompatibles es que participe como
     * unidad y ademas se use una parte que ninguna de sus operaciones produce
     * ni consume: ahi hay dos modos de uso que no se pueden reconciliar, y se
     * calla. */
    if (p.unidad && p.acceso_independiente) return FormaDeValor::Desconocida;
    if (p.unidad) return FormaDeValor::Compuesto;
    if (p.acceso_en_propietario) return FormaDeValor::Agregado;
    return FormaDeValor::SinEvidencia;
}

std::vector<MotivoForma> AggregateFacts::motivos_forma() const {
    const PerfilDeUso p = perfil();
    std::vector<MotivoForma> m;
    if (!p.universo_completo) {
        m.push_back(MotivoForma::UniversoIncompleto);
        return m; // sin universo no se afirma nada mas
    }
    if (p.acceso_dinamico) m.push_back(MotivoForma::AccesoDinamico);
    m.push_back(p.unidad ? MotivoForma::ParticipaComoUnidad
                         : MotivoForma::SinParticipacionUnidadObservada);
    if (p.acceso_en_propietario) m.push_back(MotivoForma::AccesoEnPropietario);
    if (p.acceso_independiente)
        m.push_back(MotivoForma::AccesoIndependienteDeOperacion);
    if (p.acceso_en_operacion) m.push_back(MotivoForma::AccesoEnOperacion);
    return m;
}

// =========================================================================
//  NIVEL A -- el recorrido que observa
// =========================================================================

namespace {

using ir::IrOp;

constexpr const char *kProductor = "asa.value_shape";
/// Cuantas funciones se siguen persiguiendo un valor.  Mas hondo no es mas
/// verdad: agotarla NO concluye nada, se anota como limitacion.
constexpr int kProfundidadFrontera = 3;

/// Hechos por funcion, calculados UNA vez: los hechos se consultan, no se
/// rehacen.  Sin esto, un valor que pasa por varias operaciones volvia a pagar
/// el analisis de memoria en cada una.
struct CacheHechos {
    /**
     * @brief Lo que hace falta de una funcion, APUNTADO y no copiado.
     *
     * Punteros porque los dos hechos pueden venir de DOS sitios: de la base
     * compartida -- cuando quien llama la trae -- o de la reserva propia de
     * abajo.  Con copias no se podria consumir la base sin duplicarla, que es
     * justo lo que se quiere evitar; y copiar un points-to no es barato.
     */
    struct Entrada {
        const IrFacts *hechos = nullptr;
        const PointsTo *direcciones = nullptr;
    };

    /**
     * @brief La base de hechos, si quien llama la tiene.
     *
     * Con ella, esta cache deja de calcular: pide.  Sin ella sigue calculando
     * como siempre -- hay llamantes que no tienen base, y quitarles el camino
     * seria cambiar una duplicacion por una regresion.
     *
     * Es la Regla 1 aplicada donde no se veia: el desperdicio no estaba en dos
     * criterios distintos, sino en dos COMPUTOS del mismo, uno de ellos
     * escondido dentro de una cache privada que muere con la llamada.
     */
    FactBase *base = nullptr;

    /// Reserva propia: solo se usa para lo que la base no da.
    struct Propia {
        IrFacts hechos;
        PointsTo direcciones;
    };
    std::unordered_map<std::string, std::unique_ptr<Propia>> por_funcion;
    std::unordered_map<std::string, Entrada> vistas;

    const Entrada &de(const ir::IrFunction &fn) {
        auto v = vistas.find(fn.name);
        if (v != vistas.end()) return v->second;

        Entrada e;
        if (base != nullptr) {
            /* De la base, que ya los tiene o los calculara UNA vez para todos
             * sus consumidores.  Las referencias viven lo que la base, y la
             * base vive mas que este recorrido. */
            e.hechos = &base->structure(fn);
            e.direcciones = &base->memory(fn);
        } else {
            auto p = std::unique_ptr<Propia>(new Propia());
            p->hechos = build_ir_facts(fn);
            p->direcciones = compute_points_to(fn, p->hechos);
            e.hechos = &p->hechos;
            e.direcciones = &p->direcciones;
            por_funcion.emplace(fn.name, std::move(p));
        }
        return vistas.emplace(fn.name, e).first->second;
    }
};

bool acceso_de(const ir::IrInstr &in, ir::IrValueId &ptr, bool &escribe) {
    if (in.op == IrOp::LOAD && !in.operands.empty()) {
        ptr = in.operands[0];
        escribe = false;
        return true;
    }
    if (in.op == IrOp::STORE && in.operands.size() > 1) {
        ptr = in.operands[1];
        escribe = true;
        return true;
    }
    return false;
}

/**
 * @brief Toda forma de llamada, no solo las que se pueden seguir.
 *
 * Contaba tres -- CALL, TAILCALL, CALLIND -- y dejaba fuera el despacho
 * dinamico (CALLVIRT / CALLM / CALLITF / CALLCLOSURE / CALLSUPER) y las
 * nativas.  El bucle que la usa hace `continue` con lo que no es llamada, asi
 * que un agregado que se pasaba a un metodo virtual no se anotaba ni como
 * frontera ni como limitacion: se perdia el rastro EN SILENCIO, y el analisis
 * seguia como si el valor no hubiera ido a ninguna parte.
 *
 * Que no se pueda seguir el destino es una respuesta legitima -- y este modulo
 * ya sabe darla, @c CodigoLimitacion la tiene --; lo que no vale es no decir
 * nada.
 */
bool es_llamada(IrOp op) {
    switch (op) {
    case IrOp::CALL:
    case IrOp::TAILCALL:
    case IrOp::CALLIND:
    case IrOp::CALLN:
    case IrOp::CALLVIRT:
    case IrOp::CALLM:
    case IrOp::CALLITF:
    case IrOp::CALLSUPER:
    case IrOp::CALLCLOSURE: return true;
    default: return false;
    }
}

/**
 * @brief Si de @p op se puede sacar UN destino con IR que mirar.
 *
 * @c CALL / @c TAILCALL lo llevan en el nombre y @c CALLIND se intenta
 * resolver.  El despacho dinamico depende del tipo en ejecucion: obligaria a
 * que TODOS los destinos posibles conservaran la propiedad, y basta con que uno
 * la rompa.  Una nativa tiene destino sabido pero no tiene IR dentro.
 */
bool is_followable_target(IrOp op) {
    return op == IrOp::CALL || op == IrOp::TAILCALL || op == IrOp::CALLIND;
}

/// Todo lo observado de un valor mientras se le sigue por el modulo.
struct Observado {
    std::vector<AccesoComponente> accesos;
    std::vector<ParticipacionUnidad> participaciones;
    std::vector<Frontera> fronteras;
    std::vector<Limitacion> limitaciones;
    std::unordered_set<std::string> frontera;
    std::vector<Universo> universos;
    bool pasado_por_abi = false;
    bool devuelto_entero = false;
    bool transferido_como_bloque = false;

    /// Abre un ambito nuevo colgando del actual y devuelve su id.
    UniversoId
    abrir_universo(UniversoId padre, const std::string &ambito,
                   IdentidadUniverso identidad = IdentidadUniverso::Conocido,
                   EstadoObservacion obs = EstadoObservacion::Observado) {
        Universo u;
        u.id = static_cast<UniversoId>(universos.size());
        u.padre = padre;
        u.ambito = ambito;
        u.identidad = identidad;
        u.observacion = obs;
        /* Un ambito que no se ha mirado no puede estar cerrado: cerrado
         * significa "se ha visto todo lo que podria contradecir lo de aqui", y
         * ahi no se ha visto nada. */
        u.cerrado = (obs == EstadoObservacion::Observado);
        universos.push_back(u);
        return u.id;
    }
    /* Una frontera o un limite abren el ambito DONDE aparecen y todos los que
     * lo contienen: lo que no se ha visto ahi tampoco se ha visto desde fuera.
     * Pero NO abre a los hermanos ni a los hijos ya cerrados: la verdad que
     * ellos demostraron sigue en pie, y borrarla seria tirar conocimiento
     * calculado. */
    void abrir_hacia_arriba(uint32_t u) {
        while (true) {
            if (u >= universos.size()) return;
            if (!universos[u].cerrado)
                return; // ya abierto: y sus padres tambien
            universos[u].cerrado = false;
            if (u == universos[u].padre) return;
            u = universos[u].padre;
        }
    }

    /// Anota una FRONTERA: de que ambito sale, a cual va y por que.  El destino
    /// se abre como universo sin observar -- que es lo que de verdad se sabe de
    /// el -- y con su identidad, que es otro eje: se puede saber quien esta al
    /// otro lado sin haber mirado dentro.
    void anotar_frontera(CodigoFrontera c, SitioIr s, ir::IrValueId v,
                         const std::string &destino,
                         IdentidadUniverso identidad) {
        const UniversoId desde = s.universo;
        abrir_hacia_arriba(desde);
        Frontera f;
        f.codigo = c;
        f.desde = desde;
        f.hacia = identidad == IdentidadUniverso::Desconocido
                      ? kUniversoDesconocido
                      : abrir_universo(desde, destino, identidad,
                                       EstadoObservacion::NoObservado);
        f.sitio = std::move(s);
        f.valor = v;
        fronteras.push_back(std::move(f));
    }
    void limitar(CodigoLimitacion c, SitioIr s, const std::string &destino = {},
                 uint32_t profundidad = 0, ir::IrValueId valor = 0,
                 UnknownReason reason = UnknownReason::NotAsked,
                 const char *reason_code = "") {
        abrir_hacia_arriba(s.universo);
        Limitacion l;
        l.codigo = c;
        l.sitio = std::move(s);
        l.destino = destino;
        l.profundidad = profundidad;
        l.valor = valor;
        /* De que CLASE es, en el vocabulario comun.  Por defecto "no
         * preguntado": quien limita sin decirlo queda contado como tal en vez
         * de pasar por una clase que no es suya. */
        l.reason = reason;
        l.reason_code = reason_code;
        limitaciones.push_back(std::move(l));
    }
};

/**
 * @brief Observa que hace UNA funcion con el valor cuya raiz es @p raiz.
 *
 * La misma rutina sirve para el sitio donde nace y para cada funcion que lo
 * recibe.  Lo que cambia es la RELACION con la que se anota cada acceso, y esa
 * es toda la diferencia entre implementar una unidad y destriparla.
 *
 * No concluye nada: anota.
 */
void observar(const ir::IrModule &mod, const ir::IrFunction &fn,
              const IrFacts &facts, const PointsTo &pt, uint32_t raiz,
              Observado &o, int hondura, RelacionAcceso relacion,
              uint32_t universo, CacheHechos &cache) {
    for (uint32_t bi = 0; bi < fn.blocks.size(); ++bi) {
        const ir::IrBlock &b = fn.blocks[bi];
        for (uint32_t ii = 0; ii < b.instrs.size(); ++ii) {
            const ir::IrInstr &in = b.instrs[ii];
            SitioIr sitio{fn.name, universo, bi, ii, in.source_line};

            ir::IrValueId ptr = ir::IR_NO_VALUE;
            bool escribe = false;
            if (acceso_de(in, ptr, escribe)) {
                const PointsToEntry &e = pt.at(ptr);
                /* Solo cuenta como componente si la direccion se DERIVA del
                 * ancla: un `[x + 8]` cualquiera puede ser otra cosa, y quien
                 * lo sabe es el resolvedor de direcciones. */
                if (e.root != raiz) continue;
                AccesoComponente a;
                a.sitio = sitio;
                a.offset = e.off;
                a.offset_sabido = e.off_exact;
                a.escribe = escribe;
                a.relacion = relacion;
                a.puntero = ptr;
                o.accesos.push_back(std::move(a));
                continue;
            }
            // Guardar el PUNTERO (no un componente) es perderlo de vista.
            if (in.op == IrOp::STORE && !in.operands.empty() &&
                pt.at(in.operands[0]).root == raiz) {
                /* Se guarda el puntero en memoria: al otro lado esta quien lea
                 * ese sitio, y a ese no se le puede ni nombrar. */
                o.anotar_frontera(CodigoFrontera::DireccionGuardada, sitio,
                                  in.operands[0], "<memoria>",
                                  IdentidadUniverso::Desconocido);
                continue;
            }
            if (in.op == IrOp::RET && !in.operands.empty() &&
                pt.at(in.operands[0]).root == raiz) {
                o.devuelto_entero = true;
                continue;
            }
            if (in.op == IrOp::MEMCPY) {
                // Los BYTES viajan juntos: representacion, no semantica.
                for (size_t k = 0; k < in.operands.size() && k < 2; ++k)
                    if (pt.at(in.operands[k]).root == raiz)
                        o.transferido_como_bloque = true;
                continue;
            }
            /* Cualquier otra op que toque el puntero NO es usarlo de unidad.  A
             * este nivel del IR un valor con componentes ES memoria: todo pasa
             * por su direccion, y calcular la de un componente empieza por el
             * propio ancla.  Contarlo como "lo consume entero" hacia que la
             * senal disparase en el 100% de los agregados del corpus. */
            if (!es_llamada(in.op)) continue;

            // --- llamada: puede ser donde vive su comportamiento ---
            int arg = -1;
            for (size_t a = 0; a < in.operands.size(); ++a) {
                const PointsToEntry &e = pt.at(in.operands[a]);
                if (e.root != raiz) continue;
                if (e.off_exact && e.off == 0) {
                    /* De momento solo dice que los bytes viajan juntos: por el
                     * convenio de llamada, un saco y un numero de 256 bits se
                     * pasan igual.  Solo es evidencia semantica si la operacion
                     * se puede ver entera. */
                    o.pasado_por_abi = true;
                    arg = static_cast<int>(a);
                } else {
                    /* Se llevan una PARTE a otra funcion: el destino SI se
                     * puede nombrar, aunque no se haya mirado dentro. */
                    o.anotar_frontera(CodigoFrontera::ComponenteSeLleva, sitio,
                                      in.operands[a], in.func_name,
                                      IdentidadUniverso::Conocido);
                }
            }
            if (arg < 0) continue;
            /* El valor entra entero en una llamada cuyo destino no se puede
             * mirar.  Se DICE, con el motivo: una nativa no tiene IR dentro; un
             * despacho dinamico tendria varios destinos y basta con que uno
             * rompa la propiedad.  Antes esto no llegaba aqui siquiera -- la op
             * no contaba como llamada y el bucle la saltaba --, asi que el
             * rastro se perdia sin dejar constancia. */
            if (!is_followable_target(in.op)) {
                o.limitar(in.op == IrOp::CALLN
                              ? CodigoLimitacion::DestinoNoVisible
                              : CodigoLimitacion::DestinoIndirectoNoUnico,
                          sitio, in.func_name, 0, in.operands[arg]);
                continue;
            }
            if (hondura <= 0) {
                o.limitar(CodigoLimitacion::ProfundidadAgotada, sitio,
                          in.func_name,
                          static_cast<uint32_t>(kProfundidadFrontera));
                continue;
            }
            /* El destino tiene que ser UNO y sabido.  Una llamada indirecta que
             * pudiera ir a varios sitios obligaria a que TODOS conservaran la
             * propiedad -- basta con que uno destripe el valor --, y el
             * resolvedor solo responde cuando el destino es unico.  Nunca se
             * elige uno de los posibles. */
            std::string destino = in.func_name;
            if (in.op == IrOp::CALLIND) {
                /* Y si no se sabe, se pregunta POR QUE.  Antes las siete formas
                 * de no saberlo daban la misma limitacion, asi que un destino
                 * que varia segun el camino -- especulable con guarda -- se
                 * leia igual que una operacion que no modelamos. */
                FnTargetUnknown why;
                destino = pointed_function(fn, facts, in.func_ptr, &why);
                if (destino.empty()) {
                    o.limitar(CodigoLimitacion::DestinoIndirectoNoUnico, sitio,
                              {}, 0, in.func_ptr, why.reason, why.code);
                    continue;
                }
            }
            const ir::IrFunction *g = nullptr;
            for (const ir::IrFunction &c : mod.functions)
                if (c.name == destino) {
                    g = &c;
                    break;
                }
            if (g == nullptr || g->blocks.empty()) {
                o.limitar(CodigoLimitacion::DestinoNoVisible, sitio, destino);
                continue;
            }
            if (static_cast<size_t>(arg) >= g->params.size()) {
                o.limitar(CodigoLimitacion::ParametroFueraDeRango, sitio,
                          destino);
                continue;
            }
            if (!o.frontera.insert(g->name).second) continue; // ya observada

            /* Se entra a ver la operacion ENTERA.  Si desde dentro no se pierde
             * nada, esta llamada deja de ser "los bytes viajan juntos" y pasa a
             * ser lo unico que sostiene la unidad. */
            /* La operacion es un UNIVERSO propio: dentro puede demostrarse algo
             * aunque el de fuera siga abierto, y esa verdad local no se tira.
             */
            const uint32_t u_op = o.abrir_universo(universo, g->name);
            const CacheHechos::Entrada &e = cache.de(*g);
            observar(mod, *g, *e.hechos, *e.direcciones, g->params[arg], o,
                     hondura - 1, RelacionAcceso::EnOperacion, u_op, cache);
            if (o.universos[u_op].cerrado) {
                ParticipacionUnidad p;
                p.sitio = sitio;
                p.sitio.universo = u_op;
                p.operacion = g->name;
                p.parametro = static_cast<uint32_t>(arg);
                o.participaciones.push_back(std::move(p));
            }
        }
    }
}

AggregateFactsMap observar_con_cache(const ir::IrModule &mod,
                                     const ir::IrFunction &fn,
                                     const IrFacts &facts, const PointsTo &pt,
                                     CacheHechos &cache) {
    AggregateFactsMap out;
    /* Anclas: donde NACE un valor con componentes en esta funcion.  Hoy son dos
     * clases y la segunda faltaba:
     *
     *   la RESERVA local, que lo crea aqui;
     *   el PARAMETRO que lo recibe, que no lo crea pero es igual de observable
     *   -- el modelo de efectos ya hablaba de `arg#0+8/8` mientras este dominio
     *   se callaba sobre las mismas funciones, y dos partes del mismo informe
     *   con distinta cobertura sobre lo mismo confunden a quien lee.
     *
     * El ancla no es la definicion de un valor con componentes: es como se le
     * sigue.  Anadir una clase de ancla amplia la cobertura sin tocar el
     * dominio. */
    for (size_t pi = 0; pi < fn.params.size(); ++pi) {
        const ir::IrValueId p = fn.params[pi];
        /* De un parametro NO se sabe la extension -- el tamano lo sabe quien
         * llama --, asi que la guarda de las reservas no sirve aqui.  La
         * evidencia de que tiene componentes son sus propios accesos: se
         * observa primero y se emite despues solo si los hubo.  Pedir extension
         * constante era usar un sustituto de "tiene componentes" que para un
         * parametro nunca se cumple. */
        const RegionExtent &ex = pt.extent_of(p);
        Observado o;
        const UniversoId u_raiz = o.abrir_universo(0, fn.name);
        observar(mod, fn, facts, pt, p, o, kProfundidadFrontera,
                 RelacionAcceso::EnPropietario, u_raiz, cache);
        AggregateFacts a;
        a.ancla = p;
        a.bytes = ex.constante() ? ex.bytes : -1; // -1 = no se sabe, y se dice
        /* Un parametro no se declara en una linea del cuerpo: se declara en la
         * firma.  Se marca cual es (indice+1, para que 0 signifique "no es un
         * parametro") en vez de inventar una linea 0 que parece un error. */
        a.declaracion =
            SitioIr{fn.name, 0, 0, static_cast<uint32_t>(pi + 1), 0};
        a.accesos = std::move(o.accesos);
        ligar_accesos(a.accesos);
        /* Con componentes o sin ellos: un parametro al que solo se accede en el
         * desplazamiento 0 es un puntero a un escalar, no un valor con partes,
         * y meterlo aqui ensuciaria el informe sin decir nada. */
        bool con_componentes = a.offsets_tocados() >= 2;
        for (const AccesoComponente &ac : a.accesos)
            if (ac.offset_sabido && ac.offset > 0) con_componentes = true;
        if (!con_componentes) continue;
        a.participaciones = std::move(o.participaciones);
        a.fronteras = std::move(o.fronteras);
        a.limitaciones = std::move(o.limitaciones);
        a.frontera.assign(o.frontera.begin(), o.frontera.end());
        a.universos = std::move(o.universos);
        a.pasado_por_abi = o.pasado_por_abi;
        a.devuelto_entero = o.devuelto_entero;
        a.transferido_como_bloque = o.transferido_como_bloque;
        a.seal.origin = {Source::Static, kProductor, fn.name.c_str(), p};
        a.seal.support.add("analysis.points_to");
        const FormaDeValor f = a.forma();
        a.seal.certainty =
            (f == FormaDeValor::SinEvidencia || f == FormaDeValor::Desconocida)
                ? Certainty::Unknown
                : (a.perfil().universo_completo ? Certainty::Proven
                                                : Certainty::Inferred);
        out.agregados.push_back(std::move(a));
    }
    for (const ir::IrBlock &b : fn.blocks) {
        for (const ir::IrInstr &in : b.instrs) {
            if (in.op != IrOp::ALLOCA || in.dst == ir::IR_NO_VALUE) continue;
            const RegionExtent &ex = pt.extent_of(in.dst);
            /* Un valor con componentes necesita SITIO para varios.  Un hueco
             * del tamano de un escalar es una variable, y meterla aqui
             * ensuciaria la medida sin anadir un caso real. */
            if (!ex.constante() || ex.bytes <= 8) continue;

            Observado o;
            const uint32_t u_raiz = o.abrir_universo(0, fn.name);
            observar(mod, fn, facts, pt, in.dst, o, kProfundidadFrontera,
                     RelacionAcceso::EnPropietario, u_raiz, cache);

            /* Sin un solo acceso con desplazamiento conocido no hay evidencia
             * de componentes: afirmarlo por el tamano seria clasificar por la
             * representacion, justo lo que este dominio no hace.
             *
             * Pero eso decide la FORMA, no si el valor se observa: `a.forma()`
             * ya devuelve "sin evidencia" en ese caso.  Descartar la
             * observacion entera -- que es lo que se hacia -- tiraba con ella
             * las fronteras y las limitaciones del valor, que son lo unico que
             * explica POR QUE no hay evidencia: una reserva que se pasa a otra
             * funcion y se pierde de vista deja de contarse como algo que el
             * analisis no alcanzo y pasa a no existir.  Quien quiera solo los
             * que tienen forma demostrada filtra por forma; eso es una
             * proyeccion, no una perdida. */
            AggregateFacts a;
            a.ancla = in.dst;
            /* La identidad que cruza el pipeline: donde nace el valor en el
             * fuente.  El value-id no vale -- la optimizacion los renumera. */
            a.declaracion = SitioIr{fn.name, 0, 0, 0, in.source_line};
            a.declaracion.indice = in.source_column;
            /* El sitio del fuente no siempre es unico: si una funcion se inlina
             * dos veces en el mismo llamante, la misma linea produce dos
             * valores distintos.  Con una reserva local normal esto vale "sin
             * sitio de inlinado" y no cambia nada. */
            a.instancia = in.inline_site;
            a.bytes = ex.bytes;
            a.accesos = std::move(o.accesos);
            // Se liga al final: hasta ahora no se sabia que desplazamientos
            // tocan sus operaciones.
            ligar_accesos(a.accesos);
            a.participaciones = std::move(o.participaciones);
            a.fronteras = std::move(o.fronteras);
            a.limitaciones = std::move(o.limitaciones);
            a.frontera.assign(o.frontera.begin(), o.frontera.end());
            a.universos = std::move(o.universos);
            a.pasado_por_abi = o.pasado_por_abi;
            a.devuelto_entero = o.devuelto_entero;
            a.transferido_como_bloque = o.transferido_como_bloque;

            a.seal.origin = {Source::Static, kProductor, fn.name.c_str(),
                             in.dst};
            a.seal.support.add("analysis.points_to");
            if (!a.frontera.empty()) a.seal.support.add("analysis.fn_targets");

            /* La certeza depende de si se pudo observar el universo entero.  No
             * de lo ordenados que sean los accesos ni de lo convencido que este
             * el analisis.  Es un eje INDEPENDIENTE de la forma:
             * `compuesto/inferida` le vale a un optimizador que deje red y no a
             * un verificador que vaya a rechazar un programa. */
            const FormaDeValor f = a.forma();
            if (f == FormaDeValor::SinEvidencia ||
                f == FormaDeValor::Desconocida)
                a.seal.certainty = Certainty::Unknown;
            else
                a.seal.certainty = a.perfil().universo_completo
                                       ? Certainty::Proven
                                       : Certainty::Inferred;

            out.agregados.push_back(std::move(a));
        }
    }
    return out;
}

} // namespace

AggregateFactsMap observar_agregados(const ir::IrModule &mod,
                                     const ir::IrFunction &fn,
                                     const IrFacts &facts) {
    if (fn.blocks.empty()) return AggregateFactsMap{};
    /* Sin nadie que lo traiga, se calcula aqui.  Quien YA lo tenga -- la base
     * de hechos lo cachea -- debe usar la forma de abajo: repetir el computo es
     * la otra manera de desperdiciar lo que el ASA existe para compartir. */
    const PointsTo pt = compute_points_to(fn, facts);
    return observar_agregados(mod, fn, facts, pt);
}

AggregateFactsMap observar_agregados(const ir::IrModule &mod,
                                     const ir::IrFunction &fn,
                                     const IrFacts &facts, const PointsTo &pt,
                                     FactBase *base) {
    if (fn.blocks.empty()) return AggregateFactsMap{};
    CacheHechos cache;
    /* Con base, las funciones que se visiten al seguir llamadas se PIDEN en vez
     * de calcularse.  Sin ella, la cache hace lo de siempre. */
    cache.base = base;
    return observar_con_cache(mod, fn, facts, pt, cache);
}

const char *nombre_transicion(TipoTransicion t) {
    switch (t) {
    case TipoTransicion::Desaparece: return "desaparece";
    case TipoTransicion::CambiaForma: return "cambia-de-forma";
    case TipoTransicion::Aparece: return "aparece";
    case TipoTransicion::NoEmparejable: return "no-emparejable";
    default: return "sobrevive";
    }
}

ObservacionModulo observar_modulo(const ir::IrModule &mod) {
    ObservacionModulo out;
    std::map<IdentidadValor, uint32_t> por_sitio; // cuantos van de cada sitio
    CacheHechos cache; // una sola para todo el modulo: los hechos se consultan
    for (const ir::IrFunction &fn : mod.functions) {
        if (fn.blocks.empty()) continue;
        const CacheHechos::Entrada &e = cache.de(fn);
        for (AggregateFacts &a :
             observar_con_cache(mod, fn, *e.hechos, *e.direcciones, cache)
                 .agregados) {
            IdentidadValor id;
            id.funcion = fn.name;
            id.linea = a.declaracion.linea;
            id.indice = a.declaracion.indice;
            id.instancia = a.instancia;
            /* Varios valores pueden compartir sitio -- un macro expandido
             * varias veces --, asi que se numeran por orden de aparicion DENTRO
             * de este estado.  Sirve para distinguirlos aqui, no para
             * emparejarlos con otro estado. */
            id.orden = por_sitio[id]++;
            out.valores.emplace_back(std::move(id), std::move(a));
        }
    }
    return out;
}

std::vector<TransicionValor>
comparar_estados(const ObservacionModulo &antes,
                 const ObservacionModulo &despues) {
    std::map<IdentidadValor, FormaDeValor> a_antes, a_despues;
    for (const auto &p : antes.valores)
        a_antes[p.first] = p.second.forma();
    for (const auto &p : despues.valores)
        a_despues[p.first] = p.second.forma();

    /* Cuantos valores hay en cada SITIO a cada lado.  Si el numero cambio, el
     * orden de aparicion ya no dice quien es quien: emparejar por posicion
     * describiria cambios que no ocurrieron. */
    auto sitio_de = [](IdentidadValor i) {
        i.orden = 0;
        return i;
    };
    std::map<IdentidadValor, uint32_t> n_antes, n_despues;
    for (const auto &kv : a_antes)
        ++n_antes[sitio_de(kv.first)];
    for (const auto &kv : a_despues)
        ++n_despues[sitio_de(kv.first)];
    auto emparejable = [&](const IdentidadValor &id) {
        const IdentidadValor s = sitio_de(id);
        auto a = n_antes.find(s);
        auto b = n_despues.find(s);
        const uint32_t na = a == n_antes.end() ? 0 : a->second;
        const uint32_t nb = b == n_despues.end() ? 0 : b->second;
        // Un solo valor en el sitio, o el mismo numero a los dos lados.
        return (na <= 1 && nb <= 1) || na == nb;
    };

    std::vector<TransicionValor> out;
    for (const auto &kv : a_antes) {
        if (!emparejable(kv.first)) {
            TransicionValor t;
            t.valor = kv.first;
            t.antes = kv.second;
            t.tipo = TipoTransicion::NoEmparejable;
            out.push_back(std::move(t));
            continue;
        }
        TransicionValor t;
        t.valor = kv.first;
        t.antes = kv.second;
        auto it = a_despues.find(kv.first);
        if (it == a_despues.end()) {
            t.tipo = TipoTransicion::Desaparece;
        } else {
            t.despues = it->second;
            t.tipo = (it->second == kv.second) ? TipoTransicion::Sobrevive
                                               : TipoTransicion::CambiaForma;
        }
        out.push_back(std::move(t));
    }
    for (const auto &kv : a_despues) {
        if (a_antes.count(kv.first) != 0) continue;
        if (!emparejable(kv.first)) continue; // ya se dijo desde el otro lado
        TransicionValor t;
        t.valor = kv.first;
        t.tipo = TipoTransicion::Aparece;
        t.despues = kv.second;
        out.push_back(std::move(t));
    }
    return out;
}

void volcar_formas(const ir::IrModule &mod, const char *momento) {
    if (!util::flag_on(util::FlagId::AsaFormas)) return;
    /* Cada recorrido es un ESTADO distinto, aunque la etapa se llame igual: el
     * emisor se invoca varias veces por compilacion y entre una y otra el
     * modulo cambia.  Sin el contador, dos estados comparten nombre y el mismo
     * valor aparece con dos formas a la vez. */
    static uint32_t estado = 0;
    const uint32_t id_estado = estado++;
    /* Un estado se identifica ademas por el MODULO que representa: dos estados
     * de modulos distintos no estan en la misma cadena de transformacion, y
     * comparar hechos entre ellos no compara nada.  Antes de relacionar dos
     * estados hay que demostrar que estan relacionados. */
    std::fprintf(stderr, "[forma] estado=%u etapa=%s modulo=%s funciones=%u\n",
                 id_estado, momento,
                 mod.name.empty() ? "<anonimo>" : mod.name.c_str(),
                 static_cast<uint32_t>(mod.functions.size()));
    CacheHechos cache; // una sola para todo el modulo
    for (const ir::IrFunction &fn : mod.functions) {
        if (fn.blocks.empty()) continue;
        const CacheHechos::Entrada &e = cache.de(fn);
        const AggregateFactsMap m =
            observar_con_cache(mod, fn, *e.hechos, *e.direcciones, cache);
        for (const AggregateFacts &a : m.agregados) {
            const PerfilDeUso p = a.perfil();
            // El PERFIL, no solo la forma: es lo que permite ver si el analisis
            // distingue algo antes de que nadie consuma su veredicto.
            std::fprintf(
                stderr,
                "[forma] momento=%s#%u fn=%s decl=%u:%u ancla=%u "
                "bytes=%lld "
                "offsets=%u forma=%s "
                "certeza=%s completo=%d unidad=%d accprop=%d accop=%d "
                "indep=%d dinamico=%d escapa=%d abi=%d dev=%d bloque=%d "
                "frontera=%u lim=%u esc=%u\n",
                momento, id_estado, fn.name.c_str(), a.declaracion.linea,
                a.declaracion.indice, a.ancla, static_cast<long long>(a.bytes),
                a.offsets_tocados(), nombre_forma(a.forma()),
                certainty_name(a.seal.certainty), p.universo_completo ? 1 : 0,
                p.unidad ? 1 : 0, p.acceso_en_propietario ? 1 : 0,
                p.acceso_en_operacion ? 1 : 0, p.acceso_independiente ? 1 : 0,
                p.acceso_dinamico ? 1 : 0, p.escapa ? 1 : 0,
                p.paso_por_abi ? 1 : 0, p.retorno_entero ? 1 : 0,
                p.transferencia_entera ? 1 : 0,
                static_cast<uint32_t>(a.frontera.size()),
                static_cast<uint32_t>(a.limitaciones.size()),
                static_cast<uint32_t>(a.fronteras.size()));
            /* Las verdades LOCALES: un ambito cerrado demuestra lo suyo aunque
             * el de fuera siga abierto, y sin esto se tiraban. */
            for (const Universo &u : a.universos)
                std::fprintf(stderr,
                             "[forma]   universo=%u padre=%u ambito=%s "
                             "cerrado=%d forma=%s\n",
                             u.id, u.padre, u.ambito.c_str(), u.cerrado ? 1 : 0,
                             nombre_forma(a.forma_en(u.id)));
            for (const Universo &u : a.universos)
                std::fprintf(stderr,
                             "[forma]   universo=%u identidad=%s obs=%s\n",
                             u.id, nombre_identidad(u.identidad),
                             nombre_observacion(u.observacion));
            /* ORIGEN + CAUSA + EFECTO: donde esta demostrado, que lo bloquea y
             * hasta donde no llega. */
            for (const AggregateFacts::EfectoAlcance &ef : a.efectos())
                std::fprintf(
                    stderr,
                    "[forma]   efecto=no-eleva universo=%u forma=%s "
                    "bloqueado_en=%u causa=%s fn=%s bloque=%u "
                    "instr=%u linea=%u\n",
                    ef.universo, nombre_forma(ef.forma), ef.bloqueado_en,
                    !ef.causa_localizada
                        ? "no-localizada-en-este-ambito"
                        : (ef.por_frontera ? nombre_frontera(ef.frontera)
                                           : nombre_limitacion(ef.limitacion)),
                    ef.causa.funcion.c_str(), ef.causa.bloque, ef.causa.indice,
                    ef.causa.linea);
            /* Los accesos que DECIDEN el veredicto: el dinamico y el que no se
             * liga a ninguna operacion.  Sin verlos, un "desconocida" obliga a
             * reconstruir a mano por que lo es. */
            for (const AccesoComponente &ac : a.accesos) {
                const bool decide =
                    !ac.offset_sabido ||
                    (ac.relacion == RelacionAcceso::EnPropietario &&
                     !ac.ligado_a_operacion);
                if (!decide) continue;
                std::fprintf(
                    stderr,
                    "[forma]   acceso=%s off=%lld sabido=%d escribe=%d "
                    "ligado=%d fn=%s bloque=%u instr=%u linea=%u\n",
                    nombre_relacion(ac.relacion),
                    static_cast<long long>(ac.offset), ac.offset_sabido ? 1 : 0,
                    ac.escribe ? 1 : 0, ac.ligado_a_operacion ? 1 : 0,
                    ac.sitio.funcion.c_str(), ac.sitio.bloque, ac.sitio.indice,
                    ac.sitio.linea);
            }
            for (MotivoForma mo : a.motivos_forma())
                std::fprintf(stderr, "[forma]   motivo=%s\n",
                             nombre_motivo(mo));
            for (const Frontera &es : a.fronteras)
                std::fprintf(stderr,
                             "[forma]   frontera=%s desde=%u hacia=%d fn=%s "
                             "bloque=%u instr=%u linea=%u\n",
                             nombre_frontera(es.codigo), es.desde,
                             es.hacia == kUniversoDesconocido
                                 ? -1
                                 : static_cast<int>(es.hacia),
                             es.sitio.funcion.c_str(), es.sitio.bloque,
                             es.sitio.indice, es.sitio.linea);
            for (const Limitacion &l : a.limitaciones)
                std::fprintf(stderr,
                             "[forma]   limite=%s fn=%s bloque=%u instr=%u "
                             "linea=%u destino=%s\n",
                             nombre_limitacion(l.codigo),
                             l.sitio.funcion.c_str(), l.sitio.bloque,
                             l.sitio.indice, l.sitio.linea, l.destino.c_str());
        }
    }
}

} // namespace asa
} // namespace analysis
