/**
 * @file fingerprint.h
 * @brief Huella computacional por-declaracion: propiedades de recurso y efecto
 *        que el compilador INFIERE del IR y compone interprocedural.
 *
 * Es el "resumen por funcion" del modelo de codegen dirigido por resumenes
 * (ThinLTO-style) Y, a la vez, la base de las anotaciones comprobables
 * (`@pure`,
 * `@alloc(0)`, `@nothrow`, `@stack(N)`, ...): la huella es la VERDAD inferida
 * contra la que se verifica el contrato del usuario.
 *
 * Decidibilidad (regla de soundness): estas propiedades son EXACTAS/sound sobre
 * el IR (contar alloc-sites, sumar ALLOCA, detectar THROW/PANIC, ciclos del
 * callgraph).  La complejidad temporal/espacial (aproximada) vive en el
 * subsistema de coste (@c analyze/bigo.h) y se reporta junto a esta huella.
 *
 * Composicion interprocedural: los totales (`*_total`) agregan la funcion + su
 * cierre transitivo por el callgraph ESTATICO.  Si en ese cierre hay una
 * llamada DINAMICA/externa no resuelta (@c CALLVIRT / @c CALLN a simbolo
 * externo / ...), @c effects_known queda false y los totales de efecto se
 * vuelven CONSERVADORES (no se puede probar la ausencia) -> nunca se afirma
 * `@nothrow`/`@alloc(0)` sin poder demostrarlo.
 */
#ifndef VESTA_ANALYZE_FINGERPRINT_H
#define VESTA_ANALYZE_FINGERPRINT_H

#include "vx/diagnostic.h" // los veredictos salen como diagnosticos del catalogo

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace ir {
struct IrFunction;
struct IrModule;
} // namespace ir

namespace analyze {

/// Sentinela de `stack_bytes_total`: la profundidad de pila NO es acotable
/// (hay recursion en el callgraph, o un callee externo cuyo frame no se ve).
/// `verify` lo trata como inverificable (no se puede PROBAR una cota).
constexpr uint64_t STACK_UNBOUNDED = UINT64_MAX;

/**
 * @struct FunctionFingerprint
 * @brief Propiedades de recurso/efecto de una funcion (locales + compuestas).
 */
struct FunctionFingerprint {
    std::string function; ///< nombre de la funcion.

    // -- Locales (solo esta funcion, sin componer) --------------------------
    uint32_t alloc_sites =
        0; ///< sitios de alloc en heap (GC/raw/newobj/closure-GC).
    uint64_t stack_bytes =
        0;               ///< bytes reservados por ALLOCA (count * sizeof T).
    bool throws = false; ///< THROW/RETHROW propio.
    bool panics = false; ///< PANIC propio.
    bool self_recursive = false; ///< se llama a si misma directamente.
    bool frame_opaque = false;   ///< tiene `asm { }` (INLINE_ASM): su marco de
                               ///< pila REAL no se ve en el IR (los register()
                               ///< + asm no son ALLOCAs).  Para el TOTAL de sus
                               ///< callers se usa su @stack declarado, no el 0
                               ///< medido.
    bool has_dynamic_call =
        false; ///< CALLVIRT/CALLM/CALLCLOSURE/CALLIND (efecto opaco).
    bool pure_local = true; ///< sin efectos de dato observables PROPIOS.
    /**
     * @brief Igual, pero sin contar las llamadas a nativas.
     *
     * Una `CALLN` tumba la pureza LOCAL porque quien la mira sin componer no
     * tiene forma de saber que hace la nativa, y suponer que no hace nada seria
     * aprobar por omision.  Pero al COMPONER si se puede preguntar: si lo
     * declarado dice que solo lee sus argumentos, quien la llama sigue siendo
     * puro.
     *
     * Dos campos y no uno porque responden a dos preguntas distintas: "es pura
     * por si misma, con lo que se sabe aqui" y "lo seria si sus nativas no
     * contaran".  Quien no compone lee la primera -- conservadora -- y no puede
     * equivocarse por descuido.
     */
    bool pure_local_ignoring_natives = true;
    std::vector<std::string>
        calls; ///< callees ESTATICOS (CALL/TAILCALL/CALLN).

    // -- Compuestas (transitivas, tras compose_fingerprints) ----------------
    uint32_t alloc_sites_total =
        0; ///< sitios de alloc alcanzables (SUMA del cierre).
    uint64_t stack_bytes_total =
        0; ///< profundidad de pila peor caso = frame propio
           ///< + MAX de callees; STACK_UNBOUNDED si no acotable.
    bool throws_total = false; ///< la funcion o alguna alcanzable lanza.
    bool panics_total = false; ///< idem panic.
    bool recursive = false;    ///< en un ciclo del callgraph (o self).
    bool effects_known =
        true; ///< false => hay dinamica/externa -> totales conservadores.
    /**
     * @brief QUIEN hace opaco el cierre.  Solo vale con @c !effects_known.
     *
     * Sin esto, "no se pueden demostrar tus efectos" es un callejon: el usuario
     * no sabe a que funcion mirar, y el compilador SI lo sabe -- lo acaba de
     * decidir --.  Se anota donde se decide y no donde se lee, que es la unica
     * forma de que no haya que volver a recorrer el cierre para averiguarlo.
     *
     * Vacio con @c opaque_dynamic puesto: entonces el culpable no es un nombre
     * sino una llamada cuyo destino no se resuelve.
     */
    std::string opaque_callee;
    /// Hay una llamada DINAMICA alcanzable: el destino no se sabe, asi que
    /// tampoco sus efectos.  Se distingue del callee con nombre porque se
    /// arreglan distinto -- uno se declara, el otro hay que resolverlo.
    bool opaque_dynamic = false;
    bool pure =
        false; ///< @pure: sin efectos de dato en TODO el cierre (sound).
};

/**
 * @brief Computa la huella LOCAL de una funcion (sin componer).
 *
 * @param arch Arquitectura de destino del inline asm (@c "x86_64" por defecto).
 *        Selecciona la tabla de efectos con la que se analiza cada bloque
 *        @c asm { }: un mnemonico no reconocido para ese arch se trata de forma
 *        conservadora (rompe la pureza local).
 */
FunctionFingerprint compute_fingerprint(const ir::IrFunction &fn,
                                        const std::string &arch = "x86_64");

/**
 * @brief Huellas locales de todas las funciones del modulo.
 */
std::vector<FunctionFingerprint>
compute_module_fingerprints(const ir::IrModule &mod,
                            const std::string &arch = "x86_64");

struct FunctionContracts; // definido abajo.

/**
 * @brief Compone los totales interprocedurales in-place: llena los campos
 *        `*_total`, `recursive` y `effects_known` recorriendo el callgraph
 *        estatico (cierre transitivo).  Conservador ante llamadas dinamicas
 *        o callees externos no presentes en @p fps.
 *
 * @param contracts opcional.  Si se da, las funciones con marco OPACO
 *        (`frame_opaque`: tienen `asm { }`, su pila no se ve en el IR)
 *        contribuyen al `stack_bytes_total` de sus callers con su @stack
 *        DECLARADO en vez del 0 medido -- asi un wrapper que llama a una
 *        primitiva de asm refleja el marco real de esa primitiva.  El
 *        `stack_bytes` (parcial) medido NO se toca (la verificacion sigue
 *        siendo por cota superior sobre lo medido).
 * @param mod opcional.  Con el, un callee que NO esta en el programa deja de
 *        ser automaticamente opaco: si su importacion DECLARA lo que hace
 *        (@c IrNativeEffects), se aporta lo declarado y el cierre sigue siendo
 *        conocido.
 *
 *        Es la mitad que faltaba de un mecanismo que ya existia: la
 *        declaracion se podia escribir y el motor semantico la aplicaba, pero
 *        ESTE camino -- el de los contratos -- ni la miraba, asi que declarar
 *        no cambiaba nada de lo que el usuario ve.  Un mecanismo que se puede
 *        usar y no se nota es peor que no tenerlo: parece que no funciona.
 */
void compose_fingerprints(
    std::vector<FunctionFingerprint> &fps,
    const std::unordered_map<std::string, FunctionContracts> *contracts =
        nullptr,
    const ir::IrModule *mod = nullptr);

/**
 * @struct FunctionContracts
 * @brief Contratos de huella declarados por el usuario para UNA funcion.
 *
 * Se llevan APARTE del IR (no en @c IrFunction) por DISENO: son metadata
 * puramente de compile-time (modo @c --analyze) que ni el JIT ni el AOT ni la
 * serializacion del IR necesitan; mantener @c IrFunction esbelto evita
 * hincharlo.  Viajan en el @c CompileResult (una instancia, sin serializar) y
 * se verifican por NOMBRE.
 */
struct FunctionContracts {
    bool pure = false;    ///< @pure.
    bool nothrow = false; ///< @nothrow.
    bool nopanic = false; ///< @nopanic.
    // @alloc y @stack tienen DOS dimensiones (como @complexity): parcial (lo
    // propio de la funcion) y total (el cierre / la cadena de callees).  La
    // forma corta `@alloc(N)`/`@stack(N)` es azucar del TOTAL (el peor caso
    // que importa desde fuera).  -1 = esa dimension no se declaro.
    int64_t alloc_partial = -1; ///< @alloc(partial: N).
    int64_t alloc_total = -1;   ///< @alloc(total: N) o `@alloc(N)`.
    int64_t stack_partial = -1; ///< @stack(partial: N).
    int64_t stack_total = -1;   ///< @stack(total: N) o `@stack(N)`.
    bool any() const {
        return pure || nothrow || nopanic || alloc_partial >= 0 ||
               alloc_total >= 0 || stack_partial >= 0 || stack_total >= 0;
    }
};

/**
 * @struct ContractCheck
 * @brief Resultado de verificar UN contrato de huella declarado por el usuario
 *        (@pure/@nothrow/@nopanic/@alloc(N)/@stack(N)) contra la huella
 * inferida.
 */
struct ContractCheck {
    enum Status {
        OK,       ///< probado que se cumple (verde).
        VIOLATED, ///< probado que NO se cumple (rojo, error de compilacion).
        UNVERIFIABLE, ///< no se pudo decidir (efectos desconocidos) -> ni si ni
                      ///< no.
    };
    std::string function;
    std::string contract; ///< "@pure", "@nothrow", "@alloc", ...
    Status status = OK;
    std::string detail; ///< "esperado vs inferido".
};

/**
 * @brief Verifica los contratos de huella declarados en @p mod contra las
 *        huellas @p fps (ya compuestas).  SOUND/ASIMETRICO: solo marca
 *        @c VIOLATED cuando la violacion es DEMOSTRABLE; si los efectos no se
 *        conocen del todo, marca @c UNVERIFIABLE (nunca un falso VIOLATED).
 *        @p fps debe estar alineado con @p mod.functions por nombre.
 */
std::vector<ContractCheck> verify_contracts(
    const std::vector<FunctionFingerprint> &fps,
    const std::unordered_map<std::string, FunctionContracts> &contracts);

/// Lo que salio de mirar los veredictos.
struct ContractReport {
    uint32_t violated = 0;   ///< demostrado que NO se cumple: error.
    uint32_t unverified = 0; ///< no se pudo decidir: aviso, no error.
};

/**
 * @brief Convierte los veredictos en diagnosticos.  UN solo sitio.
 *
 * Antes esto estaba escrito TRES veces -- dos en @c compiler.cpp y una en
 * @c compiler_project.cpp --, y las tres copias hacian lo mismo:
 *
 *     if (ck.status != VIOLATED) continue;
 *
 * O sea que el tercer veredicto -- @c UNVERIFIABLE, "no se puede decidir" -- se
 * DESCARTABA EN SILENCIO.  El resultado es un contrato decorativo: parece
 * comprobado porque el compilador no protesto, y eso es peor que no tenerlo,
 * porque MIENTE CON AUTORIDAD.  Alguien lee `@nothrow` y construye encima.
 *
 * Ademas las tres copias construian el mensaje como prosa espanola dentro del
 * compilador, asi que un contrato incumplido era lo unico del compilador que no
 * se podia leer en otro idioma.  Ahora sale del catalogo, como todo.
 *
 * @param checks Los veredictos.
 * @param file   Fichero al que atribuirlos.
 * @param diags  Donde se depositan.
 * @return Cuantos de cada clase (el llamante decide si aborta).
 */
ContractReport report_contract_checks(const std::vector<ContractCheck> &checks,
                                      const std::string &file,
                                      vx::Diagnostics &diags);

/**
 * @struct TypeFingerprint
 * @brief Huella de un TIPO agregado (struct / clase / enum): propiedades de
 *        layout y de recurso que el compilador INFIERE de sus campos.
 *
 * INVARIANTE DEL LENGUAJE: TODO @c struct tiene layout C-compatible SIEMPRE
 * (orden de campos + alineamiento natural + padding estilo C, sin necesidad de
 * `@repr(C)`).  Por tanto "tener layout C" NO es una propiedad que se contrate
 * (es universal).  Lo que SI varia -- y por eso se contrata -- es si el tipo es
 * @pod: TRIVIALMENTE copiable/pasable a C POR VALOR, es decir sin destructor
 * `~Tipo()` ni campos gestionados (@c unique<T> / @c shared<T> / @c string /
 * referencias de clase).  Un struct con un campo gestionado o un dtor conserva
 * su layout C pero NO es @pod (carril move-only + RAII).
 *
 * Se computa a partir del LAYOUT ya resuelto (tamano, alineamiento, tipos de
 * campo) y de la composicion sobre los CAMPOS: @pod sii todos sus campos son
 * C-representables por valor y no hay destructor; @no_heap sii ningun campo
 * referencia el heap gestionado.  Son propiedades EXACTAS/sound (decidibles del
 * layout), asi que su contrato es DURO (OK / VIOLATED, sin UNVERIFIABLE).
 */
/**
 * @struct FieldPlacement
 * @brief Donde quedo UN campo dentro de su agregado.
 *
 * Es el layout ya resuelto por el comprobador de tipos, no una estimacion:
 * el mismo que usa el generador de codigo para leer y escribir el campo.  Se
 * lleva aqui para que las herramientas -- el editor y el modo de analisis --
 * puedan ensenarlo sin rehacer el calculo, que es como se acaba teniendo dos
 * respuestas distintas a la misma pregunta.
 */
struct FieldPlacement {
    std::string name;
    std::string type_name; ///< tipo legible, ya resuelto.
    uint32_t offset = 0;   ///< desplazamiento en bytes desde el inicio.
    uint32_t size = 0;     ///< tamano del campo en bytes.
    /// Campo de bits: @c bit_width > 0 indica que el campo ocupa @c bit_width
    /// bits a partir de @c bit_offset DENTRO de la palabra de @c size bytes
    /// que empieza en @c offset.  Varios campos comparten esa palabra.
    uint8_t bit_offset = 0;
    uint8_t bit_width = 0;
};

/**
 * @struct VariantPlacement
 * @brief Una variante de un enum, con el valor que le corresponde.
 *
 * @c tag es el indice por orden de declaracion, que es lo que se guarda en
 * memoria.  @c int_value es el valor del enum con base entera (estilo C), que
 * puede no coincidir con el tag cuando el autor lo fija a mano.
 */
struct VariantPlacement {
    std::string name;
    uint32_t tag = 0;
    int64_t int_value = 0;
    uint32_t payload_fields = 0; ///< numero de campos de carga util.
};

struct TypeFingerprint {
    std::string type_name;
    enum Kind { STRUCT, CLASS, ENUM } kind = STRUCT;
    uint64_t size_bytes = 0;  ///< tamano total del tipo (con padding).
    uint32_t align_bytes = 1; ///< alineamiento requerido.
    uint32_t field_count = 0; ///< numero de campos de instancia.
    bool is_pod =
        false; ///< value-type C-representable, sin dtor ni campos gestionados.
    bool no_heap = false; ///< ningun campo referencia el heap gestionado
                          ///< (GC/string/smart-ptr).
    bool has_destructor =
        false; ///< declara `~Tipo()` (o algun campo destructible).
    bool is_reference =
        false; ///< tipo por referencia (clase): vive en el heap por naturaleza.
    bool is_union = false; ///< union C-style: todos los campos en offset 0.
    bool is_overlay =
        false; ///< vista sobre memoria ajena: los offsets son explicitos.
    bool is_polymorphic =
        false; ///< lleva puntero a tabla de metodos al principio.

    /// Disposicion de cada campo de instancia, en orden de declaracion.
    std::vector<FieldPlacement> fields;
    /// Variantes, solo para @c ENUM.
    std::vector<VariantPlacement> variants;
};

/**
 * @struct TypeContracts
 * @brief Contratos de layout/recurso declarados por el usuario sobre un TIPO
 *        (`@pod`, `@no_heap`, `@size(N)`).  Se llevan en el @c CompileResult
 *        (compile-time, sin serializar) y se verifican por NOMBRE de tipo.
 */
struct TypeContracts {
    bool pod = false; ///< @pod: value-type sin recursos gestionados ni dtor.
    bool no_heap = false; ///< @no_heap: ningun campo apunta al heap gestionado.
    int64_t size = -1; ///< @size(N): tamano exacto en bytes; -1 = no declarado.
    bool any() const { return pod || no_heap || size >= 0; }
};

/**
 * @brief Verifica los contratos de TIPO @p contracts contra las huellas de tipo
 *        @p fps.  Todas las propiedades son decidibles del layout -> solo
 *        produce @c OK o @c VIOLATED (nunca @c UNVERIFIABLE).
 */
std::vector<ContractCheck> verify_type_contracts(
    const std::vector<TypeFingerprint> &fps,
    const std::unordered_map<std::string, TypeContracts> &contracts);

} // namespace analyze

#endif // VESTA_ANALYZE_FINGERPRINT_H
