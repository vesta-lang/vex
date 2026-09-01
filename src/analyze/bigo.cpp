/**
 * @file bigo.cpp
 * @brief Implementacion del analisis de complejidad estatico (Big-O).
 *
 * Ver bigo.h para la descripcion del subsistema.  Algoritmo del nivel 1
 * (estatico estructural):
 *
 *   (a) Detectar loops naturales via back-edges del CFG.  Un back-edge es
 *       una arista @c (u -> h) donde @c h DOMINA a @c u (o, en la
 *       aproximacion conservadora que usamos: @c h aparece ANTES que @c u
 *       en el orden de bloques Y es alcanzable hacia atras desde @c u).
 *       El frontend Vesta emite los loops con el header ANTES del body, asi
 *       que un sucesor con id <= id del bloque actual que ademas alcanza al
 *       bloque actual es un back-edge.
 *   (b) Profundidad de anidamiento: cuantos headers de loop CONTIENEN a
 *       otro.  La profundidad maxima -> grado polinomico:
 *           depth 0 -> O(1), 1 -> O(n), 2 -> O(n^2), 3 -> O(n^3), k -> O(n^k).
 *   (c) Recursion: la funcion contiene un CALL/TAILCALL a su propio nombre.
 *       Sin loops -> O(n) lineal (HEURISTIC).  Con el patron
 *       divide-y-venceras (>=2 self-calls + el argumento se reduce a la
 *       mitad via SHR/DIV-by-2) -> O(n log n) (HEURISTIC).
 *
 * Conservador: donde el patron no encaja, @c O_UNKNOWN con confianza
 * @c UNKNOWN (que NUNCA genera warning de contrato).
 *
 * --- Nivel 3 (EMPIRICO, --measure): DISENO documentado, no implementado ---
 * El harness compilaria el .vx a .velb, ejecutaria el interp con tamanos
 * crecientes n = 10, 100, 1000, ... contando instrucciones VM (el scheduler
 * ya lleva un instr-counter determinista).  Al doblar n se observa el ratio
 * de crecimiento del conteo:
 *       ratio ~ 1     -> O(1)
 *       ratio ~ 2     -> O(n)         (lineal: doblar n dobla el trabajo)
 *       ratio ~ 2+eps -> O(n log n)
 *       ratio ~ 4     -> O(n^2)
 *       ratio ~ 8     -> O(n^3)
 *       ratio crece sin tope -> O(2^n)
 * La variable de tamano sale de @c @complexity(O(n), n = <expr>).  Como la
 * cuenta de instrucciones del interp es DETERMINISTA, el ajuste es
 * reproducible (a diferencia de medir wall-time).  El hook para enchufar
 * esto es @c MeasureResult (reservado) + una rama --measure en main.cpp.
 */
#include "analyze/bigo.h"

#include "analysis/asa/fact_base.h"  // el vocabulario de productores
#include "analysis/asa/fact_store.h" // el coste PREGUNTA cuantas vueltas da
#include "analysis/facts/loop_facts.h" // ...y CUALES son los bucles, y su anidamiento
#include "ir/ssa_ir.h"
#include "vx/asm/asm_analyze.h" // un `asm` puede llevar un bucle dentro
#include "vx/asm/asm_cfg.h" // ...y su grafo de flujo dice cuantos y anidados
#include "vx/asm/asm_effects.h" // arquitectura del objetivo (tabla de efectos)

#include <algorithm>
#include <cctype>
#include <functional>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace analyze {

/* ===================================================================== */
/*  Helpers de clases de coste                                            */
/* ===================================================================== */

const char *cost_class_str(CostClass c) {
    switch (c) {
    case CostClass::O_1: return "O(1)";
    case CostClass::O_LOGN: return "O(log n)";
    case CostClass::O_N: return "O(n)";
    case CostClass::O_NLOGN: return "O(n log n)";
    case CostClass::O_N2: return "O(n^2)";
    case CostClass::O_N3: return "O(n^3)";
    case CostClass::O_NK: return "O(n^k)";
    case CostClass::O_2N: return "O(2^n)";
    case CostClass::O_UNKNOWN:
    default: return "O(?)";
    }
}

const char *confidence_str(Confidence c) {
    switch (c) {
    case Confidence::EXACT: return "exacta";
    case Confidence::HEURISTIC: return "heuristica";
    case Confidence::UNKNOWN:
    default: return "desconocida";
    }
}

CostClass parse_cost_class(const std::string &expr) {
    // Normalizar: minusculas + sin espacios.
    std::string s;
    s.reserve(expr.size());
    for (char c : expr) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        s.push_back(
            static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    // Quitar prefijo "o(" y sufijo ")" si estan presentes.
    if (s.size() >= 3 && s.rfind("o(", 0) == 0 && s.back() == ')')
        s = s.substr(2, s.size() - 3);
    // Tabla de equivalencias canonicas.  Comparamos contra la forma sin
    // espacios.  "nlogn" es la forma normalizada de "n log n".
    if (s == "1") return CostClass::O_1;
    if (s == "logn" || s == "log(n)") return CostClass::O_LOGN;
    if (s == "n") return CostClass::O_N;
    if (s == "nlogn" || s == "n*logn" || s == "n*log(n)")
        return CostClass::O_NLOGN;
    if (s == "n^2" || s == "n2" || s == "n*n" || s == "n*m" || s == "nm")
        return CostClass::O_N2;
    if (s == "n^3" || s == "n3" || s == "n*n*n") return CostClass::O_N3;
    if (s == "2^n" || s == "2n") return CostClass::O_2N;
    // n^k con k >= 4: reconocer "n^<digito>".
    if (s.size() >= 3 && s[0] == 'n' && s[1] == '^') {
        bool all_digit = true;
        for (size_t i = 2; i < s.size(); ++i)
            if (!std::isdigit(static_cast<unsigned char>(s[i])))
                all_digit = false;
        if (all_digit) return CostClass::O_NK;
    }
    return CostClass::O_UNKNOWN;
}

/**
 * @brief Que cabeceras tienen las vueltas DEMOSTRADAS constantes.
 *
 * No lo averigua: lo PREGUNTA.  Quien cuenta vueltas es el dominio de bucles
 * del ASA, y el coste es un consumidor mas -- si lo dedujera por su cuenta
 * habria dos respuestas a la misma pregunta y una se quedaria vieja sin que
 * nadie se entere.
 *
 * Vacio si no se dan hechos: entonces el coste se comporta como siempre, que
 * es lo correcto para quien llama sin ASA (un test, una herramienta suelta).
 */
struct BoundedLoops {
    std::unordered_set<ir::IrBlockId> constant;
    /**
     * @brief Cabeceras que el dominio de bucles no llego a entender.
     *
     * Se pregunta aparte de las contadas porque son cosas distintas: un bucle
     * acotado por un valor de EJECUCION se entiende y es O(n); estos ni se
     * reconocieron como bucle contado, y de ellos no se sabe si son O(n) o
     * O(1).  Confundirlos es lo que hacia que el informe afirmara una clase
     * que no habia medido.
     */
    std::unordered_set<ir::IrBlockId> not_understood;
    /**
     * @brief De cuantas de las de arriba la cota es una COTA, no el numero.
     *
     * "Da 64 vueltas" y "da como mucho 64" acotan igual -- un tope fijo es
     * O(1), sea cual sea --, pero no se saben igual de bien: el primero sale
     * de lo que el programa escribe y el segundo de un punto fijo que puede
     * pararse por presupuesto.  Cuenta para bajar la confianza del resultado,
     * no para cambiar la clase: la clase seria la misma y anunciarla con la
     * misma seguridad seria afirmar de mas.
     */
    uint32_t only_bounded = 0;
    /**
     * @brief Cabeceras cuya variable MULTIPLICA en vez de sumar.
     *
     * `for (i = 1; i < n; i *= 2)` da del orden de `log n` vueltas, no `n`.
     * Aporta al coste -- no es constante --, pero aporta un LOGARITMO, y eso
     * es otra clase: sin distinguirlo el coste decia O(n) donde la respuesta
     * es O(log n), y O(n^2) donde es O(n log n).
     */
    std::unordered_set<ir::IrBlockId> geometric;
    bool is_constant(ir::IrBlockId header) const {
        return constant.count(header) != 0;
    }
    bool is_geometric(ir::IrBlockId header) const {
        return geometric.count(header) != 0;
    }
};

/// Cuantos bucles aporta un sitio, separados por COMO crecen.
struct Depth {
    uint32_t linear = 0; ///< cada uno multiplica por `n`.
    uint32_t log = 0;    ///< cada uno multiplica por `log n`.
    uint32_t total() const { return linear + log; }
};

/**
 * @brief Cuantos bucles que APORTAN contienen al bloque @p b.
 *
 * Es la profundidad que le importa al coste, y no es la del anidamiento: un
 * bucle de vueltas acotadas multiplica por una constante, no por `n`.  Con
 * `for (i < 64) { for (j < n) }` el anidamiento es dos y el coste es LINEAL.
 *
 * Sube por el arbol de bucles del dominio -- dominadores y aristas de
 * retroceso -- descontando los acotados.  Antes se deducia por contencion de
 * INDICES de bloque, apoyandose en que el frontend numera el bucle de dentro
 * despues del de fuera: cierto en el codigo recien generado, FALSO en cuanto
 * el optimizador toca.  El desenrollado anade sus bloques al final, con lo que
 * el bucle de resto -- que va DETRAS, en secuencia -- quedaba con un indice
 * por debajo del principal y parecia contenerlo: dos bucles en fila se
 * contaban como anidados y un `for` lineal salia CUADRATICO al optimizar.
 *
 * El tope de saltos es por si el arbol llegara con un ciclo: un analisis no
 * debe colgar el compilador ni cuando le mienten.
 */
static Depth effective_depth(const analysis::LoopFacts &lf,
                             const BoundedLoops &bounded, ir::IrBlockId b) {
    uint32_t loop = lf.innermost(b);
    Depth d;
    for (int hops = 0; hops < 64 && loop != analysis::LoopFacts::NO_LOOP;
         ++hops) {
        const ir::IrBlockId h =
            static_cast<ir::IrBlockId>(lf.header_block_of(loop));
        if (!bounded.is_constant(h)) {
            if (bounded.is_geometric(h))
                ++d.log;
            else
                ++d.linear;
        }
        loop = lf.parent_of(loop);
    }
    return d;
}

/// @brief Mapea una profundidad de loop a la clase polinomica que aporta.
/**
 * @brief Cuantos bucles anidados lleva DENTRO un bloque de asm.
 *
 * Un `asm { }` es UNA instruccion del IR por muy dentro que salte, asi que el
 * conteo de bucles del IR no ve nada y una funcion cuyo cuerpo entero es un
 * bucle de copia salia declarada como O(1).  Decir "no se" tampoco vale: la
 * CLASE si se sabe -- un `rep` es una pasada lineal y el bucle de una copia por
 * bloques tampoco esta anidado --; lo que no se sabe es CUANTAS VECES da la
 * vuelta, que es otra pregunta.
 *
 * La forma sale del grafo de flujo del propio bloque: una arista que vuelve a
 * un bloque anterior es un bucle, y su cuerpo es el tramo entre los dos.  Un
 * bucle metido dentro del tramo de otro esta anidado, y eso es exactamente lo
 * que multiplica el coste.
 *
 * @param cuerpo Texto del bloque asm.
 * @param isa    ISA con la que clasificar los saltos.
 * @param seguro Sale a false si el grafo es impreciso (salto indirecto o a una
 *               etiqueta que no esta): entonces la profundidad es una cota
 *               inferior, no un hecho.
 * @return Anidamiento maximo (0 = sin bucles).
 */
static uint32_t asm_loop_depth(const std::string &cuerpo, vx::instr_db::Isa isa,
                               bool &seguro) {
    const vx::AsmCfg cfg = vx::build_asm_cfg(isa, cuerpo);
    /* La forma solo se sabe si TODO el control se puede seguir.
     *
     * No basta con mirar los saltos indirectos: dentro de un bloque `asm` un
     * `ret` no devuelve de nada -- el bloque no es una funcion --, es un salto
     * a lo que haya en la cima de la pila, y `push etiqueta` + `ret` es un
     * bucle perfectamente escribible que el grafo no ve.  Lo mismo una llamada
     * o un terminador que no se supo clasificar.  Dar eso por "sin bucles"
     * seria afirmar O(1) de algo que puede dar vueltas, que es exactamente la
     * direccion en la que equivocarse hace dano. */
    seguro = !cfg.has_indirect && !cfg.has_unresolved_target &&
             !cfg.has_external_target;
    for (const vx::AsmBasicBlock &b : cfg.blocks) {
        if (b.term == vx::AsmTerm::Ret || b.term == vx::AsmTerm::Indirect ||
            b.term == vx::AsmTerm::Unknown || b.term == vx::AsmTerm::Call) {
            seguro = false;
            break;
        }
    }
    /* Un bucle por CABECERA, no por arista hacia atras.
     *
     * A la cabecera de un mismo bucle se vuelve por VARIOS sitios: un
     * `continue`, dos ramas que reintentan, un `jne .loop` seguido de un
     * `jmp .loop`.  Contando aristas, cada retorno de mas se veia como otro
     * bucle -- y como todos empiezan en la misma cabecera, el rango de uno
     * contiene al del otro y se contaban ANIDADOS --: un solo bucle con tres
     * retornos salia O(n^3) sin que hubiera un solo anidamiento.
     *
     * El cuerpo del bucle llega hasta el retorno MAS LEJANO: es el tramo que
     * de verdad puede repetirse. */
    std::unordered_map<uint32_t, uint32_t> cola_de;
    for (uint32_t b = 0; b < cfg.blocks.size(); ++b)
        for (uint32_t s : cfg.blocks[b].succs)
            if (s <= b) {
                auto it = cola_de.find(s);
                if (it == cola_de.end())
                    cola_de.emplace(s, b);
                else if (b > it->second)
                    it->second = b;
            }
    std::vector<std::pair<uint32_t, uint32_t>> tramos;
    tramos.reserve(cola_de.size());
    for (const auto &kv : cola_de)
        tramos.emplace_back(kv.first, kv.second);
    uint32_t max_prof = 0;
    for (const auto &t : tramos) {
        uint32_t prof = 1; // el suyo
        for (const auto &otro : tramos) {
            if (&otro == &t) continue;
            // Contenido ESTRICTAMENTE dentro de otro -> un nivel mas.
            if (otro.first <= t.first && t.second <= otro.second &&
                (otro.first < t.first || t.second < otro.second))
                ++prof;
        }
        if (prof > max_prof) max_prof = prof;
    }
    return max_prof;
}

static CostClass class_from_depth(uint32_t depth) {
    switch (depth) {
    case 0: return CostClass::O_1;
    case 1: return CostClass::O_N;
    case 2: return CostClass::O_N2;
    case 3: return CostClass::O_N3;
    default: return CostClass::O_NK;
    }
}

/**
 * @brief La clase de una profundidad SEPARADA por como crece cada bucle.
 *
 * Un bucle que suma multiplica el trabajo por `n`; uno que multiplica, por
 * `log n`.  El vocabulario de clases no tiene `n log^2 n` ni `log^2 n`, asi
 * que a partir de dos logaritmos se da el mismo nombre y se avisa con la
 * confianza: decir una clase que no se tiene seria afirmar de mas, y callarse
 * seria perder la unica parte que si se sabe.
 *
 * @param exacta sale en false cuando la clase se queda corta por lo de arriba.
 */
static CostClass class_from_depth(const Depth &d, bool &exacta) {
    exacta = true;
    if (d.log == 0) return class_from_depth(d.linear);
    if (d.log > 1) exacta = false; // log^2 y mas arriba no tienen nombre
    if (d.linear == 0) return CostClass::O_LOGN;
    if (d.linear == 1) return CostClass::O_NLOGN;
    /* Con dos o mas lineales el logaritmo se absorbe: `n^2 log n` tampoco
     * tiene nombre, y `n^2` es la parte que manda. */
    exacta = false;
    return class_from_depth(d.linear);
}

/* ===================================================================== */
/*  Deteccion de recursion + divide-y-venceras                            */
/* ===================================================================== */

/**
 * @brief Cuenta las llamadas recursivas (a la propia fn) y detecta si el
 *        cuerpo reduce el argumento a la mitad (SHR por 1 / DIV por 2).
 */
static void detect_recursion(const ir::IrFunction &fn, uint32_t &self_calls,
                             bool &halves_arg) {
    self_calls = 0;
    halves_arg = false;
    for (const auto &b : fn.blocks) {
        for (const auto &ins : b.instrs) {
            if ((ins.op == ir::IrOp::CALL || ins.op == ir::IrOp::TAILCALL) &&
                ins.func_name == fn.name) {
                ++self_calls;
            }
            // Patron divide-y-venceras: shift a la derecha por 1 (a >> 1) o
            // division por la constante 2.  Buscamos un SHR cuyo operando de
            // desplazamiento sea el valor constante 1, o un DIV por 2.  Como
            // aproximacion barata, marcamos halves_arg si HAY un SHR o un DIV
            // en el cuerpo (el frontend genera /2 como SHR para potencias de
            // 2).  Conservador: solo se usa para subir O(n) -> O(n log n)
            // cuando ademas hay >=2 self-calls.
            if (ins.op == ir::IrOp::SHR || ins.op == ir::IrOp::SAR ||
                ins.op == ir::IrOp::DIV) {
                halves_arg = true;
            }
        }
    }
}

/* ===================================================================== */
/*  Analisis de funcion                                                   */
/* ===================================================================== */

/**
 * @brief Pregunta al ASA que bucles de @p fn tienen vueltas constantes.
 *
 * Solo las DEMOSTRADAS (`Certainty::Proven`): una cota inferida por rangos
 * acota el bucle, pero no dice que sea constante para toda entrada, y
 * descontarla del coste seria afirmar de mas.
 *
 * Se pregunta por el MOMENTO del modulo que se esta mirando, y es obligatorio:
 * un hecho de bucle nombra su cabecera por ID DE BLOQUE, y el optimizador los
 * renumera.  Un hecho de antes leido sobre el codigo de despues no habla de un
 * bloque parecido: habla de OTRO.
 */
static BoundedLoops ask_bounded_loops(const ir::IrFunction &fn,
                                      const analysis::asa::FactStore *facts,
                                      const char *stage) {
    BoundedLoops b;
    if (facts == nullptr || stage == nullptr) return b;
    analysis::asa::Scope here;
    here.stage = stage;
    for (const analysis::asa::Fact *f :
         facts->find_all("loop.trip_count", fn.name.c_str(), here)) {
        if (f->seal.certainty != analysis::asa::Certainty::Proven) continue;
        if (f->about.kind != analysis::asa::Subject::Kind::Block) continue;
        b.constant.insert(static_cast<ir::IrBlockId>(f->about.id));
    }
    /* Y los que solo tienen COTA.  Para el coste acotan igual: un bucle que no
     * puede dar mas de N vueltas, con N fijo, aporta una constante -- da igual
     * si se sabe el numero exacto o solo el tope.
     *
     * Es el caso del bucle de RESTO que fabrica el desenrollado, y sin esto se
     * pagaba caro: el resto no lleva la cuenta escrita en ningun sitio (la
     * hereda de donde dejo el bucle principal), asi que nunca tenia trip
     * exacto, y una funcion de vueltas fijas se declaraba O(n) DESPUES de
     * optimizar por culpa del bucle que el optimizador acababa de crear.
     *
     * No cuela un bucle de verdad variable: la cota sale de los rangos, y el
     * rango ENTERO del tipo -- que es como el analisis dice "cualquier valor"
     * -- esta rechazado en origen.  Un `for (i = 0; i < n; i++)` con `n` sin
     * acotar no produce este hecho. */
    for (const analysis::asa::Fact *f :
         facts->find_all("loop.trip_at_most", fn.name.c_str(), here)) {
        if (f->about.kind != analysis::asa::Subject::Kind::Block) continue;
        const ir::IrBlockId h = static_cast<ir::IrBlockId>(f->about.id);
        if (b.constant.insert(h).second) ++b.only_bounded;
    }
    /* Y los que MULTIPLICAN.  No son constantes -- dependen de `n` --, pero lo
     * que aportan es un logaritmo: `for (i = 1; i < n; i *= 2)` da del orden
     * de `log n` vueltas.  Sin este hecho el coste decia O(n) donde la
     * respuesta es O(log n), que no es una imprecision: es otra clase. */
    for (const analysis::asa::Fact *f :
         facts->find_all("loop.geometric", fn.name.c_str(), here)) {
        if (f->about.kind != analysis::asa::Subject::Kind::Block) continue;
        b.geometric.insert(static_cast<ir::IrBlockId>(f->about.id));
    }
    /* Y los que NO se entendieron, que es otra cosa: aqui no entra el bucle
     * cuyo limite depende de la ejecucion -- ese se entiende y es O(n) --,
     * sino el que ni se reconocio como bucle contado.
     *
     * Se pregunta por el MOTIVO, no por una lista de codigos.  Antes se
     * miraban dos (`loop.shape_unsupported` y `loop.no_induction`) y el
     * dominio paso a dar veinticuatro -- uno por condicion, para que se sepa
     * CUAL fallo --; desde entonces el coste creia entender todos los bucles
     * que no entendia.  No dio un error: dio CONFIANZA EXACTA sobre una clase
     * que no habia medido, y con ella un aviso de "contrato incumplido"
     * contra codigo correcto -- los bucles CAS de `std.atomic`, siete por
     * compilacion --.  Que un aviso conservador se vuelva ruidoso es
     * exactamente lo que la regla de validacion venia a impedir.
     *
     * La lista de codigos de otro dominio se queda vieja EN SILENCIO; la
     * clase de hueco no, porque son cuatro y son del vocabulario comun. */
    for (const analysis::asa::Fact *f : facts->find_unknown(
             analysis::asa::kProducerLoops, fn.name.c_str(),
             analysis::asa::UnknownReason::ShapeNotRecognized, here)) {
        if (f->about.kind != analysis::asa::Subject::Kind::Block) continue;
        b.not_understood.insert(static_cast<ir::IrBlockId>(f->about.id));
    }
    return b;
}

CostResult analyze_function(const ir::IrFunction &fn,
                            const analysis::asa::FactStore *facts,
                            const char *stage) {
    CostResult r;
    r.function = fn.name;

    /* 1. Bucles y anidamiento, DEL PRODUCTOR, no deducidos aqui.
     *
     * Este analisis tenia su propio detector: cabecera = destino de una arista
     * hacia un indice menor, cuerpo = intervalo de indices, anidamiento =
     * contencion de esos intervalos.  Todo eso da por hecho como numera el
     * frontend, y deja de valer en cuanto el optimizador reordena -- que es
     * justo el codigo del que se informa en POST-opt.
     *
     * El dominio lo saca de los dominadores, que no dependen del orden. */
    const analysis::LoopFacts lf = analysis::compute_loop_facts(fn);
    std::vector<ir::IrBlockId> headers;
    headers.reserve(lf.loop_count);
    for (uint32_t L = 0; L < lf.loop_count; ++L)
        headers.push_back(
            static_cast<ir::IrBlockId>(lf.header_block_of(L)));
    const BoundedLoops bounded = ask_bounded_loops(fn, facts, stage);

    /* La profundidad que manda es la del bucle mas caro, y "mas caro" no es
     * "mas anidado": dos bucles lineales pesan mas que uno lineal y dos
     * logaritmicos.  Se compara por la clase que produce cada uno. */
    Depth max_depth;
    bool max_exacta = true;
    for (ir::IrBlockId h : headers) {
        const Depth depth = effective_depth(lf, bounded, h);
        bool ex = true;
        const CostClass c = class_from_depth(depth, ex);
        bool ex_max = true;
        const CostClass c_max = class_from_depth(max_depth, ex_max);
        if (static_cast<int>(c) > static_cast<int>(c_max)) {
            max_depth = depth;
            max_exacta = ex;
        }
        // Linea fuente aproximada del header (primera instr con source_line).
        uint32_t line = 0;
        if (h < fn.blocks.size())
            for (const auto &ins : fn.blocks[h].instrs)
                if (ins.source_line != 0) {
                    line = ins.source_line;
                    break;
                }
        r.loops.push_back({h, depth.total(), line});
    }
    /* Cuantos de los bucles QUE ESTE ANALISIS CUENTA no se entendieron.
     *
     * Se cruza con `headers` y no se coge el tamano del conjunto: el dominio
     * habla tambien de bucles que aqui no se cuentan -- los que mete el
     * andamiaje de excepciones --, asi que comparar las cuentas a pelo daba
     * "no se entendio ninguno" en funciones con un `for` perfectamente
     * reconocido, y las tiraba a O(?). */
    uint32_t not_understood_here = 0;
    for (ir::IrBlockId h : headers)
        if (bounded.not_understood.count(h) != 0) ++not_understood_here;
    r.loops_not_understood = not_understood_here;
    r.max_loop_depth = max_depth.total();

    // 1.b. Recolectar los call sites (CALL/TAILCALL a una funcion con nombre)
    //      anotando la profundidad de loop del bloque donde ocurren.  Estos
    //      datos los consume la composicion interprocedural (compose_interproc)
    //      para multiplicar el coste del callee por n^loop_depth.  Se ignoran
    //      las self-calls (ya las modela la deteccion de recursion) y las
    //      llamadas sin func_name (indirectas: closures/virtuales).
    for (ir::IrBlockId bi = 0; bi < fn.blocks.size(); ++bi) {
        /* Para componer con el callee cuenta el TOTAL: un bucle logaritmico
         * repite la llamada menos veces, pero la repite -- afinar eso pide un
         * modelo de composicion que no es este, y suponer que no multiplica
         * seria suponer a favor. */
        const uint32_t depth = effective_depth(lf, bounded, bi).total();
        for (const auto &ins : fn.blocks[bi].instrs) {
            if ((ins.op == ir::IrOp::CALL || ins.op == ir::IrOp::TAILCALL) &&
                !ins.func_name.empty() && ins.func_name != fn.name) {
                r.calls.push_back({ins.func_name, depth});
            }
        }
    }

    /* 1.c. Bucles que NO estan en el IR: los que lleva dentro un bloque `asm`.
     *
     * Se MODELAN, no se dan por desconocidos.  El grafo de flujo del bloque
     * dice cuantos bucles hay y si estan anidados, que es lo que fija la clase;
     * y esa profundidad se suma a la del sitio donde esta el `asm`, porque un
     * bucle de copia dentro de un bucle del programa multiplica igual que dos
     * bucles del IR.
     *
     * Lo que sigue sin saberse es CUANTAS VUELTAS da -- la cota sale de una
     * comparacion entre registros que este analisis no sigue --, pero eso es la
     * constante, no la clase. */
    uint32_t asm_depth_total = 0;
    bool asm_forma_segura = true;
    for (ir::IrBlockId bi = 0; bi < fn.blocks.size(); ++bi) {
        const uint32_t depth_ir = effective_depth(lf, bounded, bi).total();
        for (const auto &ins : fn.blocks[bi].instrs) {
            /* El cuerpo NO esta siempre en el mismo sitio: un `asm` con
             * operandos ligados lo lleva en @c func_name, y uno opaco (sin
             * operandos, el que sale de `asm { }` con variables `register`) en
             * la tabla @c asm_micros.  Leer solo el primero dejaba a los
             * segundos con cuerpo vacio -- ningun bloque, ningun salto -- y por
             * tanto declarados O(1) por no mirar donde estaban. */
            std::string cuerpo;
            if (ins.op == ir::IrOp::INLINE_ASM) {
                cuerpo = ins.func_name;
            } else if (ins.op == ir::IrOp::ASM_MICRO &&
                       ins.imm < fn.asm_micros.size()) {
                cuerpo = fn.asm_micros[ins.imm].tmpl;
            } else {
                continue;
            }
            if (cuerpo.empty()) continue;
            bool seguro = true;
            uint32_t d = asm_loop_depth(cuerpo, vx::isa_actual(), seguro);
            /* Repetir tampoco es dar una vuelta en el texto: un `rep movsb`
             * recorre tantos bytes como diga su contador sin un solo salto.  El
             * grafo no lo ve, la extension del acceso si. */
            if (d == 0) {
                const vx::AsmBlockEffects ef = vx::asm_analyze_block_no_classes(
                    cuerpo, vx::asm_arch_actual());
                for (const vx::AsmBlockEffects::Acceso &a : ef.accesos)
                    if (!a.extension.una_vez()) {
                        d = 1;
                        break;
                    }
            }
            if (d == 0) continue;
            if (!seguro) asm_forma_segura = false;
            const uint32_t total = depth_ir + d;
            if (total > asm_depth_total) asm_depth_total = total;
        }
    }
    /* Un bucle escrito a mano dentro de un `asm` se cuenta como LINEAL: el
     * grafo del bloque dice cuantos hay y si estan anidados, pero no como
     * avanza su contador -- eso sale de una comparacion entre registros que
     * este analisis no sigue --, y suponer que crece despacio seria suponer a
     * favor. */
    if (asm_depth_total > max_depth.total()) {
        max_depth.linear = asm_depth_total;
        max_depth.log = 0;
    }
    /* Y se vuelve a apuntar.  Se habia fijado ANTES de mirar dentro de los
     * bloques `asm`, asi que el COSTE contaba esos bucles pero el numero que se
     * informa se quedaba en el del IR: una funcion cuyo cuerpo entero es un
     * bucle escrito a mano salia como "O(n)" y "0 bucles" a la vez, dos cifras
     * que se contradicen en la misma linea. */
    r.max_loop_depth = max_depth.total();

    // 2. Recursion + divide-y-venceras.
    uint32_t self_calls = 0;
    bool halves = false;
    detect_recursion(fn, self_calls, halves);
    r.is_recursive = (self_calls > 0);
    r.is_divide_conquer = (self_calls >= 2 && halves);

    // 3. Combinar: el coste es el MAYOR entre el aporte de los loops y el
    //    de la recursion.
    bool clase_exacta = max_exacta;
    CostClass loop_class = class_from_depth(max_depth, clase_exacta);
    /* Con mas de un logaritmo -- o con logaritmos bajo dos lineales -- la
     * clase que se puede nombrar se queda corta: se dice la que hay y se
     * rebaja la confianza, en vez de callarse la parte que si se sabe. */
    Confidence loop_conf =
        clase_exacta ? Confidence::EXACT : Confidence::HEURISTIC;

    CostClass rec_class = CostClass::O_1;
    Confidence rec_conf = Confidence::EXACT;
    if (r.is_divide_conquer) {
        rec_class = CostClass::O_NLOGN;
        rec_conf = Confidence::HEURISTIC;
    } else if (r.is_recursive) {
        rec_class = CostClass::O_N;
        rec_conf = Confidence::HEURISTIC;
    }

    // Elegir el mayor coste (mayor valor del enum, salvo O_UNKNOWN que es el
    // ultimo y representa "no se").
    if (static_cast<int>(loop_class) >= static_cast<int>(rec_class)) {
        r.big_o = loop_class;
        r.confidence = loop_conf;
    } else {
        r.big_o = rec_class;
        r.confidence = rec_conf;
    }
    // Si hay loops Y recursion, baja la confianza (la composicion exacta no
    // esta modelada) pero mantenemos la cota dominante.
    if (max_depth.total() > 0 && r.is_recursive)
        r.confidence = Confidence::HEURISTIC;

    /* Si la forma del asm no se pudo seguir entera, lo que se cuenta es una
     * cota INFERIOR: puede haber vueltas que el grafo no ve.  Y cuando ademas
     * no se vio ningun bucle, no se sabe NADA de la forma -- decir O(1) ahi
     * seria afirmar lo que no consta --, asi que se dice desconocida. */
    if (!asm_forma_segura) {
        r.confidence = Confidence::HEURISTIC;
        if (r.big_o == CostClass::O_1) r.big_o = CostClass::O_UNKNOWN;
    }

    /* Con bucles que no se llegaron a entender, la clase sigue siendo la que
     * la ESTRUCTURA dice -- este analisis funciona por su cuenta y los hechos
     * solo lo afinan --, pero baja la confianza: lo contado es una cota
     * INFERIOR, porque un bucle que no se reconoce puede dar mas vueltas de
     * las que se ven.
     *
     * NO se degrada a desconocida.  Se probo y estaba mal: convertia una
     * herramienta que siempre responde en una que se calla en cuanto el ASA no
     * llega, y el analisis estructural es justamente lo que hay cuando no hay
     * nada mas.  Lo que si cambia es que quien COMPARA dos clases mire esto
     * antes de afirmar que una empeoro. */
    if (r.loops_not_understood > 0 && !headers.empty())
        r.confidence = Confidence::HEURISTIC;

    /* Y si algun bucle se descarto por una COTA y no por el numero exacto, la
     * clase es la misma pero no se sabe igual de bien: un tope que sale de un
     * punto fijo admite que ese punto fijo se parara por presupuesto.  Baja la
     * confianza; no cambia la cota, porque un tope fijo es un tope fijo. */
    if (bounded.only_bounded > 0 && r.confidence == Confidence::EXACT)
        r.confidence = Confidence::HEURISTIC;

    // 4. Construir la explicacion legible.
    std::ostringstream det;
    if (!asm_forma_segura && asm_depth_total == 0 && headers.empty() &&
        !r.is_recursive) {
        det << "un bloque asm mueve el control por una via que no se puede "
               "seguir (salto indirecto, `ret`, llamada o etiqueta ausente): "
               "no consta que no de vueltas";
    } else if (asm_depth_total > 0 && headers.empty() && !r.is_recursive) {
        det << asm_depth_total
            << " bucle(s) dentro de un asm (el numero de vueltas no se acota "
               "aqui; declaralo con @complexity si lo sabes)";
    } else if (max_depth.total() == 0 && !r.is_recursive) {
        det << "sin loops ni recursion";
    } else {
        bool first = true;
        if (max_depth.total() > 0) {
            det << headers.size() << " loop(s), anidamiento max "
                << max_depth.total();
            /* Que parte del anidamiento crece despacio.  Sin decirlo, dos
             * cifras de la misma linea se contradicen: "O(n log n)" con
             * "anidamiento max 2" parece un error de cuenta. */
            if (max_depth.log > 0)
                det << " (" << max_depth.log << " de ellos multiplicativo"
                    << (max_depth.log == 1 ? "" : "s") << ": log n)";
            first = false;
        }
        if (r.is_recursive) {
            if (!first) det << "; ";
            det << "recursiva (" << self_calls << " self-call"
                << (self_calls == 1 ? "" : "s") << ")";
            if (r.is_divide_conquer) det << " divide-y-venceras";
        }
    }
    // 4.a. Detectar la ESTRATEGIA de dispatch de match/switch y anotarla.
    //      No cambia la clase Big-O en n (un match sobre k casos fijos es O(1)
    //      respecto al tamano de entrada), pero informa el coste del dispatch
    //      en numero de CASOS k -- reflejando las optimizaciones del backend:
    //        - SWITCH_DENSE  -> O(1) jump table (computed-goto, caso denso).
    //        - bloques sw_lt/sw_ge -> O(log k) BST balanceado (caso disperso).
    //        - cadena match_arm/match_next -> O(k) lineal (pocos casos/guards).
    {
        bool has_dense = false, has_bst = false, has_linear = false;
        for (const auto &blk : fn.blocks) {
            if (!has_bst && (blk.name.rfind("sw_lt", 0) == 0 ||
                             blk.name.rfind("sw_ge", 0) == 0))
                has_bst = true;
            if (!has_linear && (blk.name.rfind("match_arm", 0) == 0 ||
                                blk.name.rfind("match_next", 0) == 0))
                has_linear = true;
            for (const auto &ins : blk.instrs)
                if (ins.op == ir::IrOp::SWITCH_DENSE) has_dense = true;
        }
        const char *sw = nullptr;
        if (has_dense)
            sw = "switch O(1) jump table (denso)";
        else if (has_bst)
            sw = "switch O(log k) BST (k casos)";
        else if (has_linear)
            sw = "switch O(k) lineal (k casos)";
        if (sw) {
            if (det.tellp() > 0) det << "; ";
            det << sw;
        }
    }
    r.detail = det.str();

    // 4.b. Inicializar el coste TOTAL = PARCIAL.  Si la funcion no tiene
    //      call sites (o si no corre la composicion interprocedural), el
    //      total coincide con el parcial.  @c compose_interproc lo refina.
    r.total_class = r.big_o;
    r.total_confidence = r.confidence;
    r.total_detail = "= parcial (sin composicion)";

    // 5. Contrato @complexity: capturar las expresiones declaradas.  Los
    //    cuatro contratos por dimension viajan en la IrFunction y son los
    //    mismos en el CostResult PRE y POST de la funcion; la VALIDACION de
    //    cada dimension contra su coste inferido la hace el consumidor
    //    (main.cpp) que tiene los cuatro modulos.  Aqui solo los copiamos.
    r.decl_partial_pre = fn.complexity_partial_pre;
    r.decl_partial_post = fn.complexity_partial_post;
    r.decl_total_pre = fn.complexity_total_pre;
    // total_post: preferir el campo nombrado; si esta vacio caer al
    // @c complexity_expr legacy (forma posicional @complexity(O(...))).
    r.decl_total_post = !fn.complexity_total_post.empty()
                            ? fn.complexity_total_post
                            : fn.complexity_expr;

    // Legacy: @c declared_expr / @c declared_class + @c contract_mismatch
    // siguen representando la dimension TOTAL (validada contra el total
    // POST-opt en compose_interproc).  Usar el contrato total_post si existe.
    const std::string &legacy_expr =
        !r.decl_total_post.empty() ? r.decl_total_post : fn.complexity_expr;
    if (!legacy_expr.empty()) {
        r.declared_expr = legacy_expr;
        r.declared_class = parse_cost_class(legacy_expr);
        // Solo avisar si: confianza EXACT, ambas clases conocidas, y
        // difieren.  Nunca avisar cuando inferimos O(?) o la declarada es
        // O(?) (la conservadora exige certeza para senalar el error).
        if (r.confidence == Confidence::EXACT &&
            r.big_o != CostClass::O_UNKNOWN &&
            r.declared_class != CostClass::O_UNKNOWN &&
            r.declared_class != r.big_o) {
            r.contract_mismatch = true;
        }
    }
    return r;
}

ModuleCost analyze_module(const ir::IrModule &mod,
                          const analysis::asa::FactStore *facts,
                          const char *stage) {
    ModuleCost mc;
    for (const auto &fn : mod.functions) {
        // Saltar stubs nativos (sin cuerpo IR) y macros compiladas (solo
        // existen en compile-time, no representan trabajo runtime).
        if (fn.is_native) continue;
        if (fn.is_macro_compiled) continue;
        mc.functions.push_back(analyze_function(fn, facts, stage));
    }
    return mc;
}

/* ===================================================================== */
/*  Composicion interprocedural (call-graph bottom-up)                    */
/* ===================================================================== */

/**
 * @brief Descompone una @c CostClass en (grado polinomico, factor log,
 *        factor exponencial) para poder componerla aritmeticamente.
 *
 * O(1)=g0; O(log n)=g0+log; O(n)=g1; O(n log n)=g1+log; O(n^2)=g2;
 * O(n^3)=g3; O(n^k)=g4; O(2^n)=exp.  El factor log se preserva al
 * multiplicar pero no se acumula (n log n * n = n^2 log n, que colapsamos
 * conservadoramente a n^2 log n -> aproximado por O(n^k) si k crece).
 */
struct CostShape {
    uint32_t degree = 0;  ///< grado del termino polinomico (n^degree).
    bool has_log = false; ///< multiplica por log n.
    bool is_exp = false;  ///< O(2^n): domina todo.
    bool unknown = false; ///< O(?): se propaga como desconocido.
};

static CostShape shape_of(CostClass c) {
    CostShape s;
    switch (c) {
    case CostClass::O_1: s.degree = 0; break;
    case CostClass::O_LOGN:
        s.degree = 0;
        s.has_log = true;
        break;
    case CostClass::O_N: s.degree = 1; break;
    case CostClass::O_NLOGN:
        s.degree = 1;
        s.has_log = true;
        break;
    case CostClass::O_N2: s.degree = 2; break;
    case CostClass::O_N3: s.degree = 3; break;
    case CostClass::O_NK: s.degree = 4; break;
    case CostClass::O_2N: s.is_exp = true; break;
    case CostClass::O_UNKNOWN:
    default: s.unknown = true; break;
    }
    return s;
}

/// @brief Recompone una @c CostShape a la @c CostClass canonica mas cercana.
static CostClass class_of(const CostShape &s) {
    if (s.unknown) return CostClass::O_UNKNOWN;
    if (s.is_exp) return CostClass::O_2N;
    switch (s.degree) {
    case 0: return s.has_log ? CostClass::O_LOGN : CostClass::O_1;
    case 1: return s.has_log ? CostClass::O_NLOGN : CostClass::O_N;
    case 2: return CostClass::O_N2;
    case 3: return CostClass::O_N3;
    default: return CostClass::O_NK;
    }
}

/**
 * @brief Multiplica un coste por @c n^depth (el factor de los loops que
 *        contienen un call site).
 *
 * Suma @c depth al grado polinomico.  El factor log y el exponencial se
 * preservan.  O(2^n) dentro de un loop sigue siendo dominado por el
 * exponencial (no lo subimos mas; ya es la clase tope).
 */
static CostShape multiply_by_n_pow(CostShape s, uint32_t depth) {
    if (s.unknown) return s;
    if (s.is_exp) return s; // el exponencial ya domina.
    s.degree += depth;
    return s;
}

/// @brief Combina dos costes en SECUENCIA: en Big-O, O(f)+O(g)=O(max(f,g)).
static CostShape combine_max(const CostShape &a, const CostShape &b) {
    // Desconocido domina (conservador: si no sabemos uno de los terminos,
    // el total es desconocido).
    if (a.unknown || b.unknown) {
        CostShape u;
        u.unknown = true;
        return u;
    }
    if (a.is_exp || b.is_exp) {
        CostShape e;
        e.is_exp = true;
        return e;
    }
    if (a.degree != b.degree) return a.degree > b.degree ? a : b;
    // Mismo grado: el que tenga log domina (n log n > n).
    CostShape r = a;
    r.has_log = a.has_log || b.has_log;
    return r;
}

/// @brief Combina dos confianzas: la mas debil gana (EXACT < HEURISTIC <
///        UNKNOWN en "fuerza", pero como enum EXACT=0 es la mas fuerte).
static Confidence weaker(Confidence a, Confidence b) {
    return static_cast<uint8_t>(a) >= static_cast<uint8_t>(b) ? a : b;
}

void compose_interproc(ModuleCost &mc) {
    // Indice nombre -> posicion en mc.functions para resolver callees.
    std::unordered_map<std::string, size_t> idx;
    for (size_t i = 0; i < mc.functions.size(); ++i)
        idx[mc.functions[i].function] = i;

    // Memoizacion del coste TOTAL ya resuelto + set de "en progreso" para
    // cortar ciclos del call-graph (recursion mutua).
    std::vector<CostShape> total_shape(mc.functions.size());
    std::vector<Confidence> total_conf(mc.functions.size(), Confidence::EXACT);
    std::vector<char> resolved(mc.functions.size(), 0);
    std::vector<char> on_stack(mc.functions.size(), 0);

    // Resuelve el coste TOTAL de la funcion en la posicion @c i (DFS
    // bottom-up con memoizacion).  @c out_shape / @c out_conf reciben el
    // resultado.  En un ciclo del call-graph (callee ya en la pila) usa el
    // coste PARCIAL del nodo en curso (conservador, evita bucle infinito).
    std::function<void(size_t, CostShape &, Confidence &)> resolve =
        [&](size_t i, CostShape &out_shape, Confidence &out_conf) {
            if (resolved[i]) {
                out_shape = total_shape[i];
                out_conf = total_conf[i];
                return;
            }
            const CostResult &r = mc.functions[i];
            // Punto de partida: el coste PARCIAL del cuerpo de esta funcion.
            CostShape acc = shape_of(r.big_o);
            Confidence conf = r.confidence;

            on_stack[i] = 1;
            for (const CallSite &cs : r.calls) {
                CostShape callee_shape;
                Confidence callee_conf = Confidence::EXACT;
                auto it = idx.find(cs.callee);
                if (it == idx.end()) {
                    // Callee externo / nativo sin cuerpo IR en el modulo:
                    // O(1) por defecto.  (Si declarara @complexity y lo
                    // tuvieramos, lo respetariamos; aqui no esta disponible.)
                    callee_shape = shape_of(CostClass::O_1);
                    callee_conf = Confidence::EXACT;
                } else if (on_stack[it->second]) {
                    // Ciclo en el call-graph (recursion directa o mutua):
                    // conservador, usamos el coste PARCIAL del callee y
                    // bajamos la confianza (la recurrencia exacta no se
                    // modela).
                    callee_shape = shape_of(mc.functions[it->second].big_o);
                    callee_conf = Confidence::HEURISTIC;
                } else {
                    resolve(it->second, callee_shape, callee_conf);
                }
                // Multiplicar el coste del callee por n^loop_depth del site.
                CostShape contrib =
                    multiply_by_n_pow(callee_shape, cs.loop_depth);
                // Si el call site esta dentro de un loop, la composicion es
                // heuristica (no modelamos exactamente cuantas veces se
                // ejecuta vs el tamano del problema).
                if (cs.loop_depth > 0)
                    callee_conf = weaker(callee_conf, Confidence::HEURISTIC);
                acc = combine_max(acc, contrib);
                conf = weaker(conf, callee_conf);
            }
            on_stack[i] = 0;

            total_shape[i] = acc;
            total_conf[i] = conf;
            resolved[i] = 1;
            out_shape = acc;
            out_conf = conf;
        };

    for (size_t i = 0; i < mc.functions.size(); ++i) {
        CostShape s;
        Confidence c = Confidence::EXACT;
        resolve(i, s, c);
        CostResult &r = mc.functions[i];
        r.total_class = class_of(s);
        r.total_confidence = c;

        // Detalle legible del total: indicar si difiere del parcial y por
        // que (callees que aportan).
        std::ostringstream td;
        if (r.total_class == r.big_o) {
            td << "= parcial (callees no elevan el coste)";
        } else {
            td << "parcial " << cost_class_str(r.big_o) << " elevado a "
               << cost_class_str(r.total_class) << " por callees";
        }
        r.total_detail = td.str();

        // Re-validar el contrato @complexity contra el coste TOTAL (la
        // complejidad efectiva real).  Conservador: solo si EXACT y ambas
        // clases conocidas y difieren.
        r.contract_mismatch = false;
        if (!r.declared_expr.empty() &&
            r.total_confidence == Confidence::EXACT &&
            r.total_class != CostClass::O_UNKNOWN &&
            r.declared_class != CostClass::O_UNKNOWN &&
            r.declared_class != r.total_class) {
            r.contract_mismatch = true;
        }
    }
}

/* ===================================================================== */
/*  Serializacion JSON (hook para diagramas)                              */
/* ===================================================================== */

/// @brief Escapa una cadena para insertarla en un literal JSON.
static std::string json_escape(const std::string &s) {
    std::string out;
    out.reserve(s.size() + 4);
    for (char c : s) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default: out.push_back(c);
        }
    }
    return out;
}

std::string cost_result_to_json(const CostResult &r) {
    std::ostringstream o;
    o << "{";
    o << "\"function\":\"" << json_escape(r.function) << "\",";
    // big_o = coste PARCIAL (cuerpo, calls=O(1)).
    o << "\"big_o\":\"" << cost_class_str(r.big_o) << "\",";
    o << "\"partial\":\"" << cost_class_str(r.big_o) << "\",";
    o << "\"confidence\":\"" << confidence_str(r.confidence) << "\",";
    // total = coste TOTAL (interprocedural, callees compuestos).
    o << "\"total\":\"" << cost_class_str(r.total_class) << "\",";
    o << "\"total_confidence\":\"" << confidence_str(r.total_confidence)
      << "\",";
    o << "\"max_loop_depth\":" << r.max_loop_depth << ",";
    o << "\"is_recursive\":" << (r.is_recursive ? "true" : "false") << ",";
    o << "\"is_divide_conquer\":" << (r.is_divide_conquer ? "true" : "false")
      << ",";
    o << "\"declared\":\""
      << json_escape(r.declared_expr.empty() ? std::string() : r.declared_expr)
      << "\",";
    // Contratos por dimension declarados (vacio => no declarada).
    o << "\"declared_partial_pre\":\"" << json_escape(r.decl_partial_pre)
      << "\",";
    o << "\"declared_partial_post\":\"" << json_escape(r.decl_partial_post)
      << "\",";
    o << "\"declared_total_pre\":\"" << json_escape(r.decl_total_pre) << "\",";
    o << "\"declared_total_post\":\"" << json_escape(r.decl_total_post)
      << "\",";
    o << "\"contract_mismatch\":" << (r.contract_mismatch ? "true" : "false")
      << ",";
    o << "\"detail\":\"" << json_escape(r.detail) << "\",";
    o << "\"total_detail\":\"" << json_escape(r.total_detail) << "\",";
    o << "\"calls\":[";
    for (size_t i = 0; i < r.calls.size(); ++i) {
        const CallSite &c = r.calls[i];
        if (i) o << ",";
        o << "{\"callee\":\"" << json_escape(c.callee)
          << "\",\"loop_depth\":" << c.loop_depth << "}";
    }
    o << "],";
    o << "\"loops\":[";
    for (size_t i = 0; i < r.loops.size(); ++i) {
        const LoopCost &l = r.loops[i];
        if (i) o << ",";
        o << "{\"header_block\":" << l.header_block << ",\"depth\":" << l.depth
          << ",\"source_line\":" << l.source_line << "}";
    }
    o << "]";
    o << "}";
    return o.str();
}

std::string module_cost_to_json(const ModuleCost &m) {
    std::ostringstream o;
    o << "[";
    for (size_t i = 0; i < m.functions.size(); ++i) {
        if (i) o << ",";
        o << cost_result_to_json(m.functions[i]);
    }
    o << "]";
    return o.str();
}

std::string cost_label_for_function(const ModuleCost &mc,
                                    const std::string &name) {
    const CostResult *r = nullptr;
    for (const auto &f : mc.functions) {
        if (f.function == name) {
            r = &f;
            break;
        }
    }
    if (!r) return std::string();
    std::ostringstream o;
    o << "coste: parcial " << cost_class_str(r->big_o) << " | total "
      << cost_class_str(r->total_class);
    // Si hay contrato declarado, indicar si concuerda o discrepa.
    if (!r->declared_expr.empty()) {
        if (r->contract_mismatch)
            o << " [!= @complexity " << r->declared_expr << "]";
        else
            o << " [@complexity " << r->declared_expr << " ok]";
    }
    return o.str();
}

} // namespace analyze
