/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file alignment.cpp
 * @brief Implementacion del hecho de alineacion (ver el header para el porque).
 */

#include "analysis/facts/alignment.h"

#include <algorithm>

namespace analysis {

namespace {

/// Tope de la escala.  Mas alla de una linea de cache no hay instruccion que
/// pida mas, asi que seguir subiendo solo daria numeros que nadie usa.
constexpr uint32_t kTope = 64;

/// La mayor potencia de dos que divide a @p k, acotada al tope.  Para 0 se
/// devuelve el tope: el cero es multiplo de todo.
uint32_t potencia_que_divide(uint64_t k) {
    if (k == 0) return kTope;
    uint32_t a = 1;
    while (a < kTope && (k & a) == 0)
        a <<= 1;
    return ((k & (a - 1)) == 0) ? a : 1;
}

/// Alineacion que garantiza el asignador para un bloque de @p bytes.
///
/// No es una suposicion: es lo que el asignador del lenguaje hace.  Los
/// bloques que pasan por el slab se entregan con la cabecera de 8 delante de
/// un chunk alineado, y los grandes con una de 64 sobre una arena del sistema
/// -- que llega alineada a pagina.  Si esa politica cambia, cambia aqui, y por
/// eso esta en un solo sitio en vez de repartida por quien la aproveche.
uint32_t alineacion_de_reserva(int64_t bytes, uint32_t cabecera_slab) {
    if (bytes > 4096) return kTope; // arena directa: cabecera de 64.
    return cabecera_slab;           // slab: payload justo tras la cabecera.
}

} // namespace

AlignmentFacts compute_alignment(const ir::IrFunction &fn) {
    return compute_alignment(fn, nullptr);
}

AlignmentFacts compute_alignment(const ir::IrFunction &fn,
                                 const AlignmentSummaries *resumen) {
    return compute_alignment(fn, resumen, nullptr);
}

AlignmentFacts compute_alignment(const ir::IrFunction &fn,
                                 const AlignmentSummaries *resumen,
                                 const ir::IrModule *mod) {
    /* Sin garantia dicha, la generica: nadie afirma por omision. */
    return compute_alignment(fn, resumen, mod, 0u, 8u);
}

AlignmentFacts compute_alignment(const ir::IrFunction &fn,
                                 const AlignmentSummaries *resumen,
                                 const ir::IrModule *mod,
                                 uint32_t garantia_datos,
                                 uint32_t cabecera_slab) {
    AlignmentFacts f;
    f.de_valor.assign(fn.values.size(), 1u);
    f.resto.assign(fn.values.size(), 0u);
    if (fn.blocks.empty()) return f;

    /* Los parametros no valen "no se sabe nada" si el modulo ya dijo lo que
     * le llega a esta funcion.  Es lo que hace que un `asm` que exige
     * alineacion pueda comprobarse donde ESTA -- dentro de la funcion que
     * recibe el destino -- y no solo donde se reserva. */
    if (resumen != nullptr) {
        if (const auto *r = resumen->buscar(fn.name)) {
            const auto &ps = r->params;
            for (size_t i = 0; i < fn.params.size() && i < ps.size(); ++i) {
                const ir::IrValueId v = fn.params[i];
                if (v >= f.de_valor.size()) continue;
                f.de_valor[v] = ps[i].modulo;
                f.resto[v] = ps[i].resto;
            }
        }
    }

    /* Se recorre en el orden de los bloques y se repite hasta que nada cambia.
     * Hace falta por los PHI: la rama que viene del final del bucle define un
     * valor que aun no se ha visto, y con una sola pasada se le daria el peor
     * caso sin razon.  El punto fijo baja siempre -- una alineacion solo se
     * revisa a la baja --, asi que termina. */
    /* Que valor guarda cada hueco, cuando guarda uno solo.
     *
     * Un valor que pasa por un hueco de pila sigue siendo el mismo valor, pero
     * la cadena se corta al pasar por memoria y con ella todo lo que se sabia
     * de el.  Eso hacia que una direccion demostrablemente mal alineada dejara
     * de serlo en cuanto el compilador la guardaba en algun sitio -- y el
     * programa, que revienta igual, pasaba el compilador.
     *
     * Solo cuenta si al hueco se guarda UNA vez: con dos escrituras no se sabe
     * cual esta viva en cada lectura, y suponerlo seria inventar. */
    std::vector<ir::IrValueId> unico_guardado(fn.values.size(),
                                              ir::IR_NO_VALUE);
    {
        std::vector<uint8_t> veces(fn.values.size(), 0);
        for (const ir::IrBlock &b : fn.blocks)
            for (const ir::IrInstr &in : b.instrs) {
                if (in.op != ir::IrOp::STORE || in.operands.size() < 2)
                    continue;
                const ir::IrValueId hueco = in.operands[1];
                if (hueco >= veces.size()) continue;
                if (veces[hueco] < 2) ++veces[hueco];
                unico_guardado[hueco] = in.operands[0];
            }
        for (size_t i = 0; i < veces.size(); ++i)
            if (veces[i] != 1) unico_guardado[i] = ir::IR_NO_VALUE;
    }

    bool cambio = true;
    int vueltas = 0;
    while (cambio && vueltas < 8) {
        cambio = false;
        ++vueltas;
        for (const ir::IrBlock &b : fn.blocks) {
            for (const ir::IrInstr &in : b.instrs) {
                if (in.dst == ir::IR_NO_VALUE || in.dst >= f.de_valor.size())
                    continue;
                uint32_t nueva = 1;
                uint32_t nuevo_resto = 0;
                switch (in.op) {
                case ir::IrOp::CONST:
                    /* De una constante se sabe TODO: es congruente consigo
                     * misma modulo lo que sea.  Se toma el tope para tener el
                     * mayor modulo util, y el resto es la propia constante. */
                    nueva = kTope;
                    nuevo_resto = (uint32_t)((uint64_t)in.imm & (kTope - 1));
                    break;
                case ir::IrOp::STR_LIT_ADDR: {
                    /* La direccion de un dato ESTATICO.  No se estima: se
                     * calcula, porque la disposicion es nuestra.
                     *
                     * La seccion arranca alineada a `alignment_default` (o a lo
                     * que pida la entrada, si pide mas) y el dato cae en un
                     * desplazamiento conocido dentro de ella.  Lo que se puede
                     * afirmar de la suma de las dos cosas es su maximo comun
                     * divisor -- y con potencias de dos, la menor.
                     *
                     * Un compilador con enlazador ajeno no puede pasar de la
                     * garantia generica: no sabe donde acabara el dato.  Aqui
                     * si, y no aprovecharlo dejaba en "no se puede probar"
                     * casos que son un numero exacto. */
                    if (mod == nullptr) break;
                    const auto &sd = mod->static_data;
                    const size_t slot = (size_t)in.imm;
                    if (slot >= sd.size()) break;
                    /* De donde sale la garantia depende de DONDE acabe el
                     * dato, y no todos acaban en el mismo sitio.
                     *
                     * Los de seccion `.data` van al bloque de globales en
                     * memoria host, que se reserva con una alineacion conocida
                     * (@ref analysis::kAlineacionBloqueGlobales) -- y en el
                     * nativo, a una seccion que se coloca en pagina, que es
                     * mas.  Se toma la menor de las dos: quedarse corto solo
                     * pierde una optimizacion; pasarse deja pasar un programa
                     * que revienta.
                     *
                     * Los demas viven en memoria de la maquina virtual, cuya
                     * colocacion es otra historia, asi que ahi se sigue con la
                     * garantia generica.  Distinguirlos importa: dar por buena
                     * la del bloque de globales para un dato que no esta en el
                     * seria afirmar algo de una memoria que no es. */
                    /* Y aqui NO se usa todavia la del bloque de globales, que
                     * es mayor, porque quien coloca la seccion depende del
                     * destino y en uno de ellos manda el usuario:
                     *
                     *   - VM/JIT: el bloque lo reserva el cargador con
                     *     @ref analysis::kAlineacionBloqueGlobales.  Ahi el
                     *     numero es firme.
                     *   - Nativo: las secciones caen en pagina POR DEFECTO,
                     *     pero un guion de enlazado puede colocarlas donde
                     *     quiera (`place_section(nombre, dir)`), y esa
                     *     direccion no tiene por que ser multiplo de 64.
                     *
                     * Afirmar el numero bueno sin saber cual de los dos es
                     * seria justo el fallo contra el que existe este analisis:
                     * prometer una alineacion que la memoria no da.  Falta el
                     * eje que ya tiene el modelo de efectos -- para QUE backend
                     * se analiza -- y con el, la del guion de enlazado cuando
                     * lo haya.  Hasta entonces, la garantia generica. */
                    /* La garantia de la seccion la trae quien pregunta,
                     * porque depende de DONDE vaya a correr esto -- y eso el
                     * analisis no lo decide.  Si no la sabe manda 0 y aqui se
                     * usa la generica: quedarse corto solo pierde una
                     * optimizacion; pasarse deja pasar un programa que
                     * revienta. */
                    const bool en_datos =
                        sd.meta_at(slot).section_name == ".data";
                    uint32_t base = (en_datos && garantia_datos != 0)
                                        ? garantia_datos
                                        : sd.alignment_default;
                    const uint32_t pedida = sd.meta_at(slot).alignment;
                    if (pedida > base) base = pedida;
                    if (base == 0) break;
                    /* La seccion arranca alineada a `base`, asi que la
                     * direccion del dato es congruente con su DESPLAZAMIENTO
                     * modulo `base`.  Eso es lo que hay que decir -- no "es
                     * multiplo de algo".
                     *
                     * La diferencia no es cosmetica: guardar el resto es lo que
                     * permite DEMOSTRAR que algo NO esta alineado.  Un dato en
                     * el desplazamiento 8 de una seccion alineada a 8 no es
                     * multiplo de 32, y decirlo convierte un "no puedo
                     * probarlo" en un error con nombre. */
                    if (base > kTope) base = kTope;
                    const uint32_t off = sd.entries[slot].byte_offset;
                    nueva = base;
                    nuevo_resto = off % base;
                    break;
                }
                case ir::IrOp::ALLOCA:
                    // Una reserva de pila la coloca el marco; el minimo que
                    // garantiza cualquier ABI de los que se compilan es 8.
                    nueva = 8;
                    break;
                case ir::IrOp::RAW_ALLOC:
                case ir::IrOp::GC_ALLOC:
                case ir::IrOp::GC_ALLOCP:
                case ir::IrOp::NEWOBJ: {
                    int64_t bytes = 0;
                    if (!in.operands.empty()) {
                        const ir::IrValueId v = in.operands[0];
                        if (v < fn.values.size() && fn.values[v].is_const)
                            bytes = fn.values[v].const_val;
                    }
                    nueva = alineacion_de_reserva(bytes, cabecera_slab);
                    break;
                }
                case ir::IrOp::TAILCALL:
                case ir::IrOp::CALLSUPER:
                case ir::IrOp::CALLN:
                case ir::IrOp::CALL: {
                    /* Lo que devuelve una llamada vale lo que su funcion
                     * GARANTICE, y eso sale de mirar su cuerpo -- no de
                     * reconocerla por el nombre.
                     *
                     * La diferencia importa: por nombre solo se acertaria con
                     * los que alguien haya escrito en una lista, y quedarian
                     * fuera el envoltorio del asignador, el asignador propio de
                     * quien lo sustituya, o cualquier funcion que devuelva algo
                     * ya alineado.  Mirando el cuerpo salen todos, y el dia que
                     * el asignador cambie su cabecera esto se entera solo. */
                    if (resumen == nullptr || in.func_name.empty()) break;
                    const auto *r = resumen->buscar(in.func_name);
                    if (r == nullptr || !r->retorno_valido) break;
                    nueva = r->retorno.modulo;
                    nuevo_resto = r->retorno.resto;
                    break;
                }
                // Prestar no mueve la direccion, asi que conserva su
                // alineacion.
                case ir::IrOp::BORROW:
                case ir::IrOp::MOV:
                case ir::IrOp::BITCAST:
                case ir::IrOp::CAST:
                    // No cambian el valor: heredan lo que se sepa de el.
                    if (!in.operands.empty()) {
                        nueva = f.de(in.operands[0]);
                        nuevo_resto = f.resto_de(in.operands[0]);
                    }
                    break;
                case ir::IrOp::LOAD:
                    /* Leer de un hueco en el que solo se guardo una cosa es
                     * esa cosa: pasar por memoria no cambia el valor.
                     *
                     * Solo se hereda un hecho CONOCIDO.  Heredar "no se sabe"
                     * es peor que no heredar: en la primera prueba, un acceso
                     * que estaba demostrado mal alineado paso a no decir nada,
                     * y no decir nada se lee como que cumple.  Un analisis que
                     * se equivoca hacia el lado comodo es peor que uno que no
                     * sabe, porque el que no sabe avisa. */
                    if (!in.operands.empty() &&
                        in.operands[0] < unico_guardado.size()) {
                        const ir::IrValueId v = unico_guardado[in.operands[0]];
                        if (v != ir::IR_NO_VALUE && f.de(v) > 1u) {
                            nueva = f.de(v);
                            nuevo_resto = f.resto_de(v);
                        }
                    }
                    break;
                case ir::IrOp::ADD:
                case ir::IrOp::SUB:
                    /* Sumar dos multiplos de 8 da un multiplo de 8; sumar uno
                     * de 8 y uno de 4 solo garantiza 4.  Con potencias de dos,
                     * el maximo comun divisor es la menor de las dos. */
                    if (in.operands.size() == 2) {
                        nueva = std::min(f.de(in.operands[0]),
                                         f.de(in.operands[1]));
                        /* Los restos se suman o se restan igual que los
                         * valores, y luego se reducen al modulo comun.  Es lo
                         * que hace que `base + 1` sepa que le sobra 1. */
                        const uint32_t ra = f.resto_de(in.operands[0]) % nueva;
                        const uint32_t rb = f.resto_de(in.operands[1]) % nueva;
                        nuevo_resto = (in.op == ir::IrOp::ADD)
                                          ? ((ra + rb) % nueva)
                                          : ((ra + nueva - rb) % nueva);
                    }
                    break;
                case ir::IrOp::MUL: {
                    /* Multiplicar por una constante MULTIPLICA la alineacion:
                     * un multiplo de 8 por 4 es multiplo de 32.  Es lo que
                     * hace que `base + i * 32` se sepa alineado a 32 aunque
                     * `i` sea cualquier cosa. */
                    if (in.operands.size() != 2) break;
                    uint64_t k = 0;
                    ir::IrValueId otro = ir::IR_NO_VALUE;
                    const ir::IrValueId a = in.operands[0], c = in.operands[1];
                    if (c < fn.values.size() && fn.values[c].is_const) {
                        k = (uint64_t)fn.values[c].const_val;
                        otro = a;
                    } else if (a < fn.values.size() && fn.values[a].is_const) {
                        k = (uint64_t)fn.values[a].const_val;
                        otro = c;
                    }
                    if (otro == ir::IR_NO_VALUE) break;
                    const uint64_t prod =
                        (uint64_t)f.de(otro) * potencia_que_divide(k);
                    nueva = (uint32_t)std::min<uint64_t>(prod, kTope);
                    break;
                }
                case ir::IrOp::SHL: {
                    if (in.operands.size() != 2) break;
                    const ir::IrValueId s = in.operands[1];
                    if (s >= fn.values.size() || !fn.values[s].is_const) break;
                    const int64_t sh = fn.values[s].const_val;
                    if (sh < 0 || sh > 6) break;
                    const uint64_t prod = (uint64_t)f.de(in.operands[0])
                                          << (uint64_t)sh;
                    nueva = (uint32_t)std::min<uint64_t>(prod, kTope);
                    break;
                }
                case ir::IrOp::AND: {
                    /* `p & ~(k-1)` alinea a la fuerza: el resultado es
                     * multiplo de k pase lo que pase con `p`.  Es el idioma de
                     * redondear hacia abajo, y reconocerlo aqui es lo que
                     * permite que la cabeza de un tramo alineado se sepa
                     * alineada. */
                    if (in.operands.size() != 2) break;
                    for (int lado = 0; lado < 2; ++lado) {
                        const ir::IrValueId m = in.operands[lado];
                        if (m >= fn.values.size() || !fn.values[m].is_const)
                            continue;
                        const uint64_t mk = (uint64_t)fn.values[m].const_val;
                        // ~(k-1) tiene los bits bajos a cero: cuantos, es la
                        // alineacion que impone.
                        uint32_t a2 = 1;
                        while (a2 < kTope && (mk & a2) == 0)
                            a2 <<= 1;
                        if ((mk & (a2 - 1)) == 0) nueva = std::max(nueva, a2);
                    }
                    break;
                }
                case ir::IrOp::MOD: {
                    bool break_por_signo = false;
                    /* `x % 2^k` es EXACTAMENTE `x & (2^k - 1)` cuando `x` no es
                     * negativo, y de ahi sale lo que se sabe: el resultado vale
                     * lo mismo que `x` modulo `2^k`.
                     *
                     * Sin esta regla se rompia la cadena del idioma de alinear
                     * hacia arriba -- `x % k`, `k - resto`, `base + eso` --:
                     * el `%` devolvia "no se sabe nada" y todo lo que venia
                     * detras heredaba la ignorancia, aunque la suma y la resta
                     * si supieran propagar restos.  El `AND` con mascara ya
                     * estaba modelado; esta es la misma operacion escrita de la
                     * otra forma, que es como la escribe quien no piensa en
                     * bits.
                     *
                     * Solo con el divisor CONSTANTE y potencia de dos, y solo
                     * si de `x` se conoce un modulo que sea multiplo de el: si
                     * no, el resto del resultado no se puede deducir.  Y solo
                     * sin signo -- con signo, `-1 % 8` vale -1 en esta
                     * aritmetica, y un resto negativo no cabe en el reticulo.
                     */
                    if (in.operands.size() != 2) break;
                    switch (in.type) {
                    case ir::IrType::U8:
                    case ir::IrType::U16:
                    case ir::IrType::U32:
                    case ir::IrType::U64:
                    case ir::IrType::PTR:
                        break; // sin signo: el resto nunca es negativo
                    default: break_por_signo = true;
                    }
                    if (break_por_signo) break;
                    const ir::IrValueId dv = in.operands[1];
                    if (dv >= fn.values.size() || !fn.values[dv].is_const)
                        break;
                    const uint64_t k = (uint64_t)fn.values[dv].const_val;
                    if (k == 0 || (k & (k - 1)) != 0 || k > kTope) break;
                    const uint32_t k32 = (uint32_t)k;
                    const uint32_t mx = f.de(in.operands[0]);
                    if (mx < k32 || (mx % k32) != 0) break;
                    nueva = k32;
                    nuevo_resto = f.resto_de(in.operands[0]) % k32;
                    break;
                }
                case ir::IrOp::PHI: {
                    /* Vale lo que su PEOR rama: cualquiera puede darse.  Una
                     * rama sin ver todavia no baja el valor -- se resuelve en
                     * la vuelta siguiente del punto fijo. */
                    uint32_t peor = kTope;
                    bool alguna = false;
                    for (const auto &pa : in.phi_args) {
                        if (pa.value >= f.de_valor.size()) continue;
                        peor = std::min(peor, f.de(pa.value));
                        alguna = true;
                    }
                    nueva = alguna ? peor : 1u;
                    break;
                }
                default: nueva = 1; break;
                }
                if (nueva < 1) nueva = 1;
                nuevo_resto %= nueva;
                if (f.resto[in.dst] != nuevo_resto) {
                    f.resto[in.dst] = nuevo_resto;
                    cambio = true;
                }
                if (nueva != f.de_valor[in.dst]) {
                    /* Solo a la baja tras la primera vuelta: si subiera, el
                     * punto fijo podria no terminar. */
                    if (vueltas == 1 || nueva < f.de_valor[in.dst]) {
                        f.de_valor[in.dst] = nueva;
                        cambio = true;
                    }
                }
            }
        }
    }
    return f;
}

AlignmentSummaries compute_alignment_summaries(const ir::IrModule &mod,
                                               bool programa_cerrado) {
    AlignmentSummaries out;

    /* Que funciones tienen TODOS sus llamantes a la vista.  Tres cosas los
     * dejan fuera de la vista, y cada una por su motivo:
     *
     *   - la DIRECCION tomada: se la puede llamar por un puntero que sale de
     *     aqui y acaba quien sabe donde;
     *   - ser NATIVA: el cuerpo no es nuestro;
     *   - `main`: la llama el sistema, que no esta en este modulo.
     *
     * Y la cuarta, la que depende de lo que se este construyendo: si esto va a
     * ser una libreria, cualquiera podra llamar a lo PUBLICO desde fuera.  Si
     * va a ser el programa entero, no hay fuera.  El mismo fichero, dos
     * respuestas -- por eso el dato entra como parametro y no se adivina. */
    std::unordered_map<std::string, bool> cerrada;
    for (const ir::IrFunction &fn : mod.functions)
        cerrada[fn.name] = !fn.is_native && fn.name != "main" &&
                           (programa_cerrado || !fn.is_public);
    for (const ir::IrFunction &fn : mod.functions)
        for (const ir::IrBlock &b : fn.blocks)
            for (const ir::IrInstr &in : b.instrs)
                if (in.op == ir::IrOp::LABEL_ADDR && !in.func_name.empty())
                    cerrada[in.func_name] = false;

    // Primera pasada: los hechos de cada funcion sin sembrar (los argumentos
    // que son constantes o reservas ya se conocen sin saber nada de fuera).
    std::unordered_map<std::string, AlignmentFacts> hechos;
    for (const ir::IrFunction &fn : mod.functions)
        hechos.emplace(fn.name, compute_alignment(fn, nullptr, &mod));

    /* Lo que cada funcion garantiza de su retorno, que es lo que permite que
     * el hecho salga de la funcion en vez de morir en ella.
     *
     * Se repite unas pocas veces porque una funcion puede devolver lo que le
     * dio otra: `envoltorio()` que devuelve `reservar()` que devuelve el
     * payload.  En la primera vuelta el retorno de `reservar` aun no se sabe,
     * asi que `envoltorio` tampoco; en la segunda ya si.
     *
     * Se empieza sin saber nada y solo se anade, nunca se quita, asi que
     * pararse antes de tiempo cuesta precision y no correccion -- que es la
     * unica forma de que un tope fijo sea legitimo.  Con recursion mutua
     * simplemente se queda en "no se sabe", que es la respuesta correcta. */
    for (int vuelta = 0; vuelta < 3; ++vuelta) {
        bool cambio = false;
        for (const ir::IrFunction &fn : mod.functions) {
            if (fn.is_native) continue; // sin cuerpo no hay nada que mirar
            const AlignmentFacts &h = hechos[fn.name];
            bool primero = true;
            AlignmentSummaries::Param ret;
            bool alguno = false;
            for (const ir::IrBlock &b : fn.blocks) {
                for (const ir::IrInstr &in : b.instrs) {
                    /* `tailcall` tambien es una salida: lo que devuelve el
                     * destino es lo que devuelve esta funcion.  Mirar solo
                     * `ret` dejaria sin resumen justo a las que delegan, que
                     * son las que mas se encadenan.
                     *
                     * Pero su valor NO esta en los operandos -- ahi van los
                     * ARGUMENTOS --, sino en lo que garantice el destino.
                     * Tomarlo de `operands[0]` seria afirmar la alineacion de
                     * un argumento como si fuera la del resultado. */
                    uint32_t m = 0, r = 0;
                    if (in.op == ir::IrOp::RET) {
                        if (in.operands.empty()) continue;
                        m = h.de(in.operands[0]);
                        r = h.resto_de(in.operands[0]);
                    } else if (in.op == ir::IrOp::TAILCALL) {
                        if (in.func_name.empty()) continue;
                        const auto *rd = out.buscar(in.func_name);
                        if (rd == nullptr || !rd->retorno_valido) continue;
                        m = rd->retorno.modulo;
                        r = rd->retorno.resto;
                    } else {
                        continue;
                    }
                    alguno = true;
                    if (primero) {
                        ret.modulo = m;
                        ret.resto = r;
                        primero = false;
                        continue;
                    }
                    /* La funcion garantiza lo que garantiza su PEOR salida:
                     * cualquiera de ellas puede ser la que se tome. */
                    const uint32_t mc = std::min(ret.modulo, m);
                    if ((ret.resto % mc) != (r % mc)) {
                        ret.modulo = 1;
                        ret.resto = 0;
                    } else {
                        ret.modulo = mc;
                        ret.resto = r % mc;
                    }
                }
            }
            if (!alguno || ret.modulo <= 1) continue;
            AlignmentSummaries::Resumen &res = out.por_funcion[fn.name];
            if (res.retorno_valido && res.retorno.modulo == ret.modulo &&
                res.retorno.resto == ret.resto)
                continue;
            res.retorno = ret;
            res.retorno_valido = true;
            cambio = true;
        }
        if (!cambio) break; // punto fijo: otra vuelta daria lo mismo
        // Rehacer los hechos sabiendo ya lo que devuelven las llamadas.
        for (const ir::IrFunction &fn : mod.functions)
            hechos[fn.name] = compute_alignment(fn, &out, &mod);
    }

    // Encuentro de lo que aporta cada sitio de llamada.
    std::unordered_map<std::string, std::vector<AlignmentSummaries::Param>> acc;
    std::unordered_map<std::string, bool> visto;
    for (const ir::IrFunction &fn : mod.functions) {
        const AlignmentFacts &h = hechos[fn.name];
        for (const ir::IrBlock &b : fn.blocks) {
            for (const ir::IrInstr &in : b.instrs) {
                if (in.op != ir::IrOp::CALL || in.func_name.empty()) continue;
                auto it = cerrada.find(in.func_name);
                if (it == cerrada.end() || !it->second) continue;
                auto &ps = acc[in.func_name];
                if (ps.size() < in.operands.size())
                    ps.resize(in.operands.size());
                const bool primero = !visto[in.func_name];
                visto[in.func_name] = true;
                for (size_t i = 0; i < in.operands.size(); ++i) {
                    const ir::IrValueId a = in.operands[i];
                    const uint32_t m = h.de(a);
                    const uint32_t r = h.resto_de(a);
                    if (primero) {
                        ps[i].modulo = m;
                        ps[i].resto = r;
                        continue;
                    }
                    /* Encuentro: el modulo comun es el menor de los dos, y el
                     * resto solo se conserva si coincide una vez reducido.  Si
                     * dos llamadas dan restos distintos, lo unico cierto es
                     * que no se sabe. */
                    const uint32_t mc = std::min(ps[i].modulo, m);
                    if ((ps[i].resto % mc) != (r % mc)) {
                        ps[i].modulo = 1;
                        ps[i].resto = 0;
                    } else {
                        ps[i].modulo = mc;
                        ps[i].resto = r % mc;
                    }
                }
            }
        }
    }
    /* Y el veredicto por funcion.  La que no esta cerrada no aparece: no se
     * afirma nada de ella.  La cerrada CON llamantes aporta lo que le llega.  Y
     * la cerrada SIN llamantes dice justo eso, que es lo contrario de no saber:
     * se ha visto todo lo que podria llamarla y no habia nada, asi que su
     * cuerpo no se ejecuta nunca. */
    for (const ir::IrFunction &fn : mod.functions) {
        auto ic = cerrada.find(fn.name);
        if (ic == cerrada.end() || !ic->second) continue;
        /* Sobre la entrada que YA hay, no una nueva: el retorno se calculo
         * arriba y vive aqui.  Reemplazar la entrada entera lo borraria, y en
         * silencio -- el analisis seguiria funcionando, solo que sin saber lo
         * que devuelve ninguna funcion. */
        AlignmentSummaries::Resumen &r = out.por_funcion[fn.name];
        auto ia = acc.find(fn.name);
        if (ia == acc.end()) {
            r.universo = Universo::CerradoSinLlamantes;
        } else {
            r.universo = Universo::CerradoConLlamantes;
            r.params = std::move(ia->second);
        }
    }
    return out;
}

} // namespace analysis
