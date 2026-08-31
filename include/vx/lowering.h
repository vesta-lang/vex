/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 *
 * Software libre bajo GPLv2.  La salida del compilador (programas
 * escritos en Vesta) NO queda sujeta a la GPL (excepcion de runtime).
 *
 * Descargo: Autor no responsable por modificaciones.
 */

/**
 * @file lowering.h
 * @brief Pase de bajada AST de Vesta -> ir::IrModule (SSA).
 *
 * Subset cubierto en(intencionalmente reducido para validar el
 * pipeline end-to-end pronto):
 *
 *   - Declaracion de funciones top-level con parametros y retorno.
 *   - Variables locales con inicializador (UNA SOLA asignacion).
 *   - Expresiones aritmeticas, logicas, bitwise, comparacion.
 *   - if/else.
 *   - Llamadas a otras funciones del mismo modulo.
 *   - Recursion permitida.
 *
 * Diferido a hitos posteriores:
 *
 *   - while / for / do-while con estado mutable (requiere phi nodes en
 *     el bloque header, algoritmo de construccion de Braun et al.).
 *   - Asignacion a variables locales (idem: cada nueva asignacion crea
 *     un IrValueId distinto, hay que recolectar phi en bloques merge).
 *   - ++ y -- (variante del anterior).
 *   - Variables globales con estado mutable.
 *
 * Si el AST contiene una construccion no soportada, el lowering emite
 * un diagnostico explicito y aborta.  Esto evita generar IR incorrecto
 * silenciosamente.
 *
 * Decisiones de hardware:
 *   - Scope chain con std::vector<unordered_map>: lookup O(N_scopes)
 *     amortizado, dominado por la cache hot del scope actual.
 *   - Las constantes se rematerializan en cada uso (no se cachean).
 *     El optimizador IR (O1+) hace common subexpression elimination
 *     en la fase posterior, asi que duplicacion aqui es gratuita.
 *   - El lowering recorre el AST UNA sola vez; el type checker ya
 *     dejo el campo result_type relleno, evitando recomputos.
 */

#ifndef VX_LOWERING_H
#define VX_LOWERING_H

#include <functional>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "ir/ssa_ir.h"
#include "vx/asm/asm_lift_reason.h" // AsmMotivoOpaco: POR QUE no se pudo elevar
#include "vx/builtin_names.h" // Builtin: el nombre ya resuelto, no la cadena
#include "vx/ast.h"
#include "vx/diagnostic.h"
#include "vx/type_checker.h"

namespace vx {

// Definido en vx/comptime/comptime_introspect.h.  Se usa por referencia en las
// firmas de materializacion de structs comptime, asi que basta declararlo.
struct ComptimeEvalResult;

/**
 * @class Lowering
 * @brief Convierte un ModuleNode AST en un ir::IrModule SSA.
 *
 * Uso:
 * @code
 *   Lowering low(mod, tc, diags);
 *   ir::IrModule irmod;
 *   if (low.run(irmod, "modname")) { ... usar irmod ... }
 * @endcode
 */
class Lowering {
  public:
    /**
     * @brief Construye el lowering sobre un modulo AST y un diags.
     *
     * @param mod   AST a bajar.  El campo result_type de cada Expr
     *              debe estar relleno (ejecutar TypeChecker antes).
     * @param tc    TypeChecker que ya corrio sobre @p mod; se usa
     *              para consultar StructLayout y resolver tamanos
     *              de variables tipo struct.
     * @param diags Sumidero de errores.
     */
    Lowering(ast::ModuleNode &mod, const TypeChecker &tc, Diagnostics &diags);

    /**
     * @brief Ejecuta el pase y rellena @p out_module.
     *
     * @param out_module Modulo IR de salida.  Se sobreescriben todos
     *                   sus campos.
     * @param module_name Nombre logico del modulo (acaba en @c IrModule::name).
     * @return @c true si no hubo errores; el modulo es valido para emitir.
     */
    bool run(ir::IrModule &out_module, const std::string &module_name);

    /**
     * @brief Habilita instrumentacion para debugging.  Cuando esta
     * activa, el lowering emite @c CALLN sinteticas a
     * @c "vx_trace:enter" al inicio y a @c "vx_trace:exit" antes
     * de cada @c RET de cada funcion del usuario.  La instrumentacion
     * vive en el IR -> todos los backends (bytecode VM, JIT, port C,
     * futuros ports) la heredan automaticamente.
     *
     * @param mode @c "none" (default, sin instrumentacion),
     *             @c "trace" (enter/exit con nombre + depth),
     *             @c "profile" (timing per-funcion).
     */
    void set_instrument_mode(const std::string &mode) {
        instrument_mode_ = mode;
    }

    ///  AOT.2.b: activa el modo POO NATIVA (sin runtime VM).  Cuando
    /// esta activo, el lowering de clases baja a layout C-struct +
    /// new->malloc/alloca + ctor directo, SIN __module_init/registry/GC.
    void set_native_poo(bool on) { native_poo_ = on; }
    /// Bits del target para validar/ensamblar el inline-asm (@Naked / asm{}):
    /// 64 (defecto), 32 o 16.  Lo fija el driver AOT desde --aot-arch.
    void set_asm_target_bits(uint8_t bits) { asm_target_bits_ = bits; }
    /// Ancho del chunk SIMD (bytes) que hornea el matcher del vectorizador en
    /// AOT (16 SSE2 / 32 AVX / 64 AVX512).  Lo fija el driver desde
    /// --float-isa.
    void set_aot_vec_width(uint8_t w) { aot_vec_width_ = w; }
    /// --float-isa auto: chunk DUAL (element-wise 64, reduccion 16) para que un
    /// IR compile a las 3 variantes (multiversion por cpuid en runtime).
    void set_aot_auto_vec(bool on) { aot_auto_vec_ = on; }
    /// Solo-LSP: bajar tambien las funciones @c comptime (no-macro) a IR para
    /// poder inspeccionar su codegen.  Ver @c
    /// CompileOptions::emit_comptime_fns.
    void set_emit_comptime_fns(bool on) { emit_comptime_fns_ = on; }

    /// C-3: registra los nombres de las funciones libres marcadas con
    /// @StringConcat / @StringEq.  Cuando no estan vacios, el lowering
    /// del `+`/`==` entre strings (y de los builtins str_concat/
    /// str_equals) rutea a una CALL a esas funciones en vez del
    /// concat/cmp por defecto.  Aplica en native_poo_ y Full.
    void set_string_op_overrides(const std::string &concat,
                                 const std::string &eq) {
        string_concat_override_ = concat;
        string_eq_override_ = eq;
    }

    /// @SyncImpl: registra los nombres de las funciones Vesta que reemplazan
    /// la primitiva de monitor de `synchronized`.  Cuando NO estan vacios,
    /// @c emit_monitor_op emite un CALL a @p enter / @p exit en LOS 3 MODOS
    /// (interp/JIT/AOT) en vez del opcode MONENTER/MONEXIT (interp/JIT) o
    /// __vx_monenter/monexit (AOT).  El operando es el host_ptr al
    /// ObjectHeader (no el GcHandle): la impl del usuario decide el layout.
    void set_sync_impl_overrides(const std::string &enter,
                                 const std::string &exit) {
        sync_enter_override_ = enter;
        sync_exit_override_ = exit;
    }

    /// CPU dispatch Inc 4: registra el nombre de la fn libre marcada con
    /// @HelperOverride(memcpy).  Cuando NO esta vacio, __vx_memcpy_init
    /// apunta el fp directamente a esta fn (INCONDICIONAL, sin leer el
    /// bitmask de cpuid).  Solo aplica en native_poo_ (AOT).
    void set_memcpy_override(const std::string &fn_name) {
        memcpy_override_ = fn_name;
    }

    /// CPU dispatch Inc 5a: registra el nombre de la fn libre marcada con
    /// @HelperOverride(strcmp).  Cuando NO esta vacio, __vx_strdisp_init
    /// apunta el fp __vx_strcmp_fp a esta fn (INCONDICIONAL).  El default es
    /// __vx_strcmp_base (la impl escalar del compilador).  Solo native_poo_.
    /// Firma esperada: i64(u8*, i64, u8*, i64).
    void set_strcmp_override(const std::string &fn_name) {
        strcmp_override_ = fn_name;
    }

    /// CPU dispatch Inc 5a: registra el nombre de la fn libre marcada con
    /// @HelperOverride(strlen).  Cuando NO esta vacio, __vx_strdisp_init
    /// apunta el fp __vx_strlen_fp a esta fn (INCONDICIONAL).  El default es
    /// __vx_strlen_base.  Solo native_poo_.  Firma esperada: i64(u8*).
    void set_strlen_override(const std::string &fn_name) {
        strlen_override_ = fn_name;
    }

    /// Wrapper publico para que helpers estaticos del modulo (e.g.
    /// @c collect_spawn_captures_in_expr) puedan resolver un nombre
    /// recorriendo todos los scopes activos del lowering.
    /// @return @c IrValueId del binding o @c IR_NO_VALUE si no existe.
    ir::IrValueId spawn_capture_resolve_public(const std::string &name) {
        return spawn_capture_resolve(name);
    }

  private:
    // -----------------------------------------------------------------
    // Helpers de tipo y constante.
    // -----------------------------------------------------------------

    /**
     * @brief Convierte un PrimitiveKind del frontend a ir::IrType.
     */
    static ir::IrType ir_type_from_primitive(PrimitiveKind p) noexcept;

    /**
     * @brief Como se ve un parametro desde el IR.
     *
     * Su tipo, y las dos cosas que el tipo no dice: si lo que lleva es una
     * direccion de memoria del ANFITRION -- que decide si leerlo se emite con
     * la instruccion de memoria del anfitrion o con la de la maquina virtual, y
     * equivocarse ahi da ceros o basura -- y si ademas es un objeto del
     * recolector, que el asignador de registros tiene que seguir cuando una
     * llamada por medio pueda mover el monton.
     */
    /**
     * @struct TypeMemory
     * @brief Lo que un TIPO implica sobre la memoria de un valor suyo.
     *
     * El nucleo comun de @ref type_memory, @ref mark_value_from_type y
     * @ref param_abi, que contestaban lo mismo por separado -- y de los tres
     * sitios que APLICABAN la respuesta a un valor con las mismas siete lineas
     * copiadas.
     *
     * De esto depende que un deref se emita con la instruccion de memoria del
     * anfitrion o con la de la maquina virtual: equivocarse no da un error, da
     * un cero.  Y si ademas es un objeto del recolector, el asignador de
     * registros tiene que seguirlo cuando una llamada por medio pueda mover el
     * monton.
     */
    struct TypeMemory {
        bool is_host_ptr = false;         ///< Direccion de memoria del host.
        bool is_gc_object = false;        ///< Ademas, objeto del recolector.
        bool pointee_is_host_ptr = false; ///< Lo de dentro, tambien (`T**`).
    };

    struct ParamAbi {
        ir::IrType type = ir::IrType::I64; ///< Su tipo en el IR.
        /// De que memoria es (@ref TypeMemory).  Lo contesta el mismo sitio
        /// que para cualquier otro valor, mas lo que es propio de un
        /// parametro: un agregado llega como la direccion de donde esta.
        TypeMemory mem;
    };

    /**
     * @brief Resuelve como se ve @p p desde el IR.
     *
     * Esta regla estaba escrita TRES veces -- para una funcion suelta, para un
     * metodo de clase y para uno de struct -- y las tres no decian lo mismo: la
     * de las funciones sueltas conocia dos casos que las otras dos no.  Que la
     * misma declaracion signifique una cosa u otra segun DONDE se escriba la
     * funcion no es una diferencia defendible: es la convencion de llamada, y
     * quien llama y quien es llamado tienen que estar de acuerdo.
     *
     * La prueba de que dolia esta en los comentarios que quedaron: uno de los
     * tres cuenta un fallo -- un agregado que llegaba a ceros porque se leia
     * con la instruccion equivocada -- que hubo que arreglar en cada copia por
     * separado.
     *
     * NO decide el control del bucle que recorre los parametros: que un
     * variadico crudo se salte entero es cosa de quien recorre.
     *
     * @param p El parametro declarado.
     * @return Su tipo y su naturaleza.
     */
    ParamAbi param_abi(const ast::ParamDecl &p) const;

    /// @brief Un parametro ya declarado en la funcion que se construye.
    struct DeclaredParam {
        /// Su declaracion, o nulo si es el contador oculto de un variadico.
        const ast::ParamDecl *decl;
        ir::IrValueId value; ///< El valor SSA que lo representa.
        ir::IrType type;     ///< Con que tipo quedo declarado.
    };

    /**
     * @brief Declara los parametros de una funcion y los ata a sus nombres.
     *
     * Esto no es solo crear un valor por cada uno: hay que saltarse el `...`
     * pelado -- que no declara nada, sus argumentos van crudos en los registros
     * que diga la convencion --, marcar cada valor con lo que @ref param_abi
     * diga, y anadir al final el CONTADOR OCULTO de un variadico empaquetado,
     * que es lo que `vacount()` lee dentro del cuerpo.
     *
     * Estaba escrito tres veces -- funcion suelta, metodo de clase, metodo de
     * struct -- y solo la primera sabia lo del contador, asi que un variadico
     * declarado en un metodo se aceptaba y luego no habia de donde sacar
     * cuantos eran.
     *
     * @param fn       La funcion que se esta construyendo.
     * @param params   Los parametros declarados.
     * @param bindings Donde apuntar el par (nombre, valor) de cada uno.
     * @return Uno por parametro declarado, en el orden en que quedaron.
     */
    /**
     * @brief Mete en un array los argumentos que sobran y los sustituye por su
     *        direccion y cuantos son.
     *
     * Es lo que hace que `f(1, 2, 3)` llegue a `f(i64... xs)` como un array de
     * tres y un tres.  Estaba dentro de la bajada de una llamada a funcion, asi
     * que una llamada a un METODO variadico no tenia como empaquetar nada.
     *
     * @param arg_ids  Los argumentos ya bajados; queda reescrito.
     * @param fixed    Cuantos son fijos (los de delante del variadico).
     * @param elem_ty  De que tipo es cada uno de los que sobran.
     * @param line     Linea fuente, para la depuracion.
     */
    /**
     * @brief Emite la llamada a una funcion @c @Naked por el despachador.
     *
     * Una @c @Naked no tiene prologo ni epilogo -- su cuerpo es ensamblador
     * puro -- asi que no se llama como a cualquier otra: se llama a un
     * despachador que la localiza por una CLAVE calculada del nombre.
     *
     * La clave la calcula @c jit::fnv1a64_name, la MISMA que usa quien la
     * resuelve.  Estaba escrita a mano aqui, dos veces, con la semilla y el
     * primo copiados y un comentario avisando de que "DEBE coincidir": tres
     * sitios donde cambiar un digito rompe el enlace, y el fallo seria mudo.
     *
     * @param label   Con que nombre quedo registrada.
     * @param e       La llamada.
     * @param ret_ir  El tipo que devuelve.
     * @param out_dst Donde dejar el valor devuelto.
     * @return @c false si algun argumento no se pudo bajar.
     */
    bool emit_naked_dispatch(const std::string &label, ast::CallExpr *e,
                             ir::IrType ret_ir, ir::IrValueId &out_dst);

    /**
     * @brief Cuando se entra a una vuelta del bucle.
     *
     * Un bucle que avanza de W en W solo puede entrar si quedan W elementos
     * ENTEROS: con menos, leerlos de golpe se saldria del array.  Uno que
     * avanza de uno en uno entra mientras quede algo.
     */
    enum class VecLoopGuard {
        WholeStep, ///< `(i + paso) <= N`, para el que avanza a saltos.
        Remaining, ///< `i < N`, para el que recoge lo que sobra.
    };

    /**
     * @struct VecLoopFrame
     * @brief Un bucle contado a medio montar.
     *
     * Los cinco idiomas del vectorizador -- y la reduccion, que ademas lleva
     * uno desenrollado -- construyen todos el mismo bucle: una cabecera con el
     * phi del indice, una condicion, un cuerpo, y una arista de vuelta que
     * avanza el indice.  Escrito a mano son unas cuarenta lineas por bucle, y
     * es donde salen los fallos que no dan error: una arista contada dos veces,
     * o una entrada de phi que apunta al bloque equivocado.
     */
    struct VecLoopFrame {
        ir::IrBlockId hdr = 0;   ///< La cabecera: phi, condicion y salto.
        ir::IrBlockId body = 0;  ///< El cuerpo.
        ir::IrBlockId after = 0; ///< Donde sigue cuando ya no se entra.
        ir::IrValueId phi_idx = ir::IR_NO_VALUE; ///< El indice.
        /// Lo que ademas viaja de una vuelta a la siguiente, en el mismo orden
        /// en que se paso al abrirlo.
        std::vector<ir::IrValueId> phi_carried;
        /// Cuanto avanza el indice, si ya hay un valor que valga en TODOS los
        /// bloques del bucle.  Vacio -> se emite la constante @ref step_imm al
        /// cerrarlo, dentro del cuerpo: un bucle que solo la necesita ahi no
        /// tiene por que arrastrarla desde fuera, y en una cabecera no cabe
        /// nada antes del phi.
        ir::IrValueId step = ir::IR_NO_VALUE;
        uint64_t step_imm = 1;               ///< El paso, cuando no hay valor.
        ir::IrType idx_ty = ir::IrType::I64; ///< El tipo del indice.
    };

    /**
     * @brief Los cinco bloques de un bucle vectorizado y sus dos indices.
     *
     * Vectorizar un bucle no es cambiar una instruccion por otra: es partirlo
     * en DOS.  Uno ancho, que avanza de W en W mientras queden al menos W
     * elementos, y otro de uno en uno para los que sobran al final -- entre
     * cero y W-1, que no se pueden hacer de golpe sin leer fuera del array.
     *
     * Son dos bucles contados encadenados (@ref VecLoopFrame), y esta forma --
     * cinco bloques con esos nombres -- es la que comparten los idiomas que
     * escriben un array.  La reduccion no la usa: la suya lleva ademas uno
     * desenrollado y dos bloques de pegamento, y monta sus bucles con la misma
     * pieza pero en otra figura.
     */
    struct VecSkeleton {
        ir::IrBlockId entry = 0; ///< De donde se viene.
        ir::IrBlockId mhdr = 0;  ///< Cabecera del bucle ancho.
        ir::IrBlockId mbody = 0; ///< Su cuerpo: el idioma, de W en W.
        ir::IrBlockId thdr = 0;  ///< Cabecera del que recoge los que sobran.
        ir::IrBlockId tbody = 0; ///< Su cuerpo: lo mismo, de uno en uno.
        ir::IrBlockId exit = 0;  ///< Donde sigue el programa.
        ir::IrValueId phi_main = ir::IR_NO_VALUE; ///< El indice en el ancho.
        ir::IrValueId phi_tail = ir::IR_NO_VALUE; ///< El indice en el de uno.
        ir::IrValueId v_W = ir::IR_NO_VALUE;      ///< Los carriles, como valor.
        ir::IrType idx_ty = ir::IrType::I64;      ///< El tipo del indice.
        VecLoopFrame main; ///< El bucle que avanza de W en W.
        VecLoopFrame tail; ///< El que recoge de uno en uno lo que sobra.
    };

    /**
     * @brief Abre un bucle contado; al volver se emite en su cuerpo.
     *
     * Los bloques los crea QUIEN LLAMA y se pasan hechos: asi cada idioma les
     * pone su nombre y su orden, que es lo que se lee luego en el volcado del
     * IR.
     *
     * @param f Marco a rellenar.
     * @param hdr Bloque de la cabecera.
     * @param body Bloque del cuerpo.
     * @param after Bloque al que se sale.
     * @param i_init Valor inicial del indice.
     * @param bound Contra que se compara (cuantos elementos hay).
     * @param step Cuanto avanza el indice; @c IR_NO_VALUE para emitir
     *             @p step_imm dentro del cuerpo al cerrarlo.
     * @param step_imm El paso, cuando @p step viene vacio.
     * @param guard Cuando se entra a una vuelta.
     * @param carried_init Valor inicial de cada cosa que viaje entre vueltas.
     * @param ln Linea del fuente.
     * @param from_hint De donde se ENTRA a la cabecera.  Cero = del bloque
     *        actual, y entonces se emite el salto.  Distinto de cero = ya se
     *        llega por una arista que existe (el bucle anterior salio aqui), y
     *        entonces NO se emite salto y el phi toma ese bloque como
     *        predecesor.  Sin esto, encadenar dos bucles emitia un salto de la
     *        cabecera a si misma: un bucle infinito que compila.
     */
    void vec_loop_open(VecLoopFrame &f, ir::IrBlockId hdr, ir::IrBlockId body,
                       ir::IrBlockId after, ir::IrValueId i_init,
                       ir::IrValueId bound, ir::IrValueId step,
                       uint64_t step_imm, VecLoopGuard guard,
                       const std::vector<ir::IrValueId> &carried_init,
                       uint32_t ln, ir::IrBlockId from_hint = 0);

    /**
     * @brief Cierra el cuerpo de un bucle contado y sale a su bloque de salida.
     *
     * @param f El marco.
     * @param carried_next Con que sigue cada valor que viaja, en el mismo
     * orden.
     * @param ln Linea del fuente.
     */
    void vec_loop_close(VecLoopFrame &f,
                        const std::vector<ir::IrValueId> &carried_next,
                        uint32_t ln);

    /// @brief Monta la primera mitad del andamio; deja listo el cuerpo ancho.
    void vec_begin(VecSkeleton &sk, const char *prefijo, ir::IrValueId i_init,
                   ir::IrValueId v_N, uint64_t w, uint32_t ln);

    /// @brief Cierra el cuerpo ancho; deja listo el de uno en uno.
    void vec_to_tail(VecSkeleton &sk, ir::IrValueId v_N, uint32_t ln);

    /// @brief Cierra el cuerpo de uno en uno; deja el programa en la salida.
    void vec_end(VecSkeleton &sk, uint32_t ln);

    /// @brief Emite una operacion binaria en el bloque actual.
    ir::IrValueId vec_bin(ir::IrOp op, ir::IrType ty, ir::IrValueId a,
                          ir::IrValueId b, uint32_t ln);

    /**
     * @brief Que tipo de elemento es, y cuanto ocupa, para vectorizar.
     *
     * Estaba escrita tres veces, una por idioma, y las tres copias NO cubrian
     * lo mismo: la del reparto de escalar se habia quedado sin `f32`, asi que
     * `c[i] = a[i] + k` con flotantes de 32 bits se bajaba de uno en uno.  No
     * era una decision -- la maquina sabe repartir un f32 -- ni se veia: el
     * programa daba el mismo numero.
     *
     * La tabla dice lo que un tipo ES.  Lo que cada idioma puede hacer con el
     * lo dice el idioma, con su motivo al lado: la reduccion, por ejemplo,
     * rechaza los de 1 y 2 bytes porque su acumulador tendria ese ancho y una
     * suma de unos pocos cientos de valores ya se sale.
     *
     * @param k Tipo del elemento.
     * @param out_ty Tipo equivalente del IR.
     * @param out_esz Bytes que ocupa.
     * @param out_fp Si es de coma flotante.
     * @return false si no es un tipo que se pueda vectorizar.
     */
    static bool vec_elem_info(PrimitiveKind k, ir::IrType *out_ty,
                              uint64_t *out_esz, bool *out_fp) noexcept;

    /**
     * @brief Es @p e un `array[i]` que se puede ensanchar?
     *
     * Exige cuatro cosas: que sea un acceso por indice sin nada raro -- ni
     * operador redefinido ni rango --, que el indice sea EL del bucle, que el
     * array viva en memoria del proceso (uno local vive en la pila de la
     * maquina virtual y no se accede igual), y que su tipo de elemento se sepa
     * ensanchar.
     *
     * Y una quinta que no es del acceso sino del idioma, y por eso va aqui: que
     * TODAS las hojas del mismo bucle sean del mismo tipo.  Ninguno de los
     * idiomas convierte, asi que mezclar anchos daria otro numero.
     *
     * Esto estaba escrito tres veces -- una por idioma --, con la quinta regla
     * dicha de tres maneras distintas.  Es la clase de sitio donde un hueco
     * pasa desapercibido: el reparto de escalar en `f32` no funcionaba porque
     * una de las copias de la TABLA DE TIPOS, que se consulta justo aqui, se
     * habia quedado sin ese tipo.
     *
     * @param e Expresion candidata.
     * @param idx_name Nombre del indice del bucle.
     * @param expected Tipo de las hojas ya vistas, o @c COUNT si es la primera;
     *        sale con el de esta.
     * @param out_base Sale con el array.
     * @return false si no es esa forma.
     */
    static bool vec_index_leaf(ast::Expr *e, const std::string &idx_name,
                               PrimitiveKind *expected,
                               ast::IdentExpr **out_base);

    /**
     * @brief Cuantos BYTES avanza de golpe un bucle vectorizado.
     *
     * Tres casos, y el tercero es el que obliga a que esto sea un parametro:
     *
     *   - Nativo con ancho pedido a mano: el que se pidio.
     *   - Nativo en automatico: @p auto_width.  Casi todos los idiomas quieren
     *     el mas ancho y dejan que cada variante lo descomponga, pero la
     *     reduccion no: su acumulador vive en UN registro, no se parte, y las
     *     tres variantes la corren a 128 bits.
     *   - Bytecode: el del objetivo, para que el `.velb` sea portable -- el JIT
     *     descompone despues al ancho de la maquina que lo ejecute.
     *
     * @param auto_width Ancho a usar en el automatico nativo.
     * @return Bytes por vuelta del bucle ancho.
     */
    uint64_t vec_chunk_width(uint64_t auto_width) const noexcept;

    /**
     * @brief Direccion de un elemento: @p base desplazada @p off bytes.
     *
     * La aritmetica de punteros HEREDA la naturaleza de la base, y eso no es un
     * detalle: un array de `malloc` vive en memoria del proceso y uno local
     * vive en la pila de la maquina virtual.  Marcarlo host a ciegas hacia que
     * el acceso saliera con la instruccion equivocada -- leer memoria de la
     * maquina como si fuera del proceso -- y el programa moria al recorrer un
     * array local vectorizado.
     *
     * @param base Puntero de partida.
     * @param off Desplazamiento en BYTES.
     * @param ln Linea del fuente.
     * @return El puntero al elemento.
     */
    ir::IrValueId vec_elem_ptr(ir::IrValueId base, ir::IrValueId off,
                               uint32_t ln);

    /**
     * @brief Lee un elemento de la direccion @p at.
     * @param at Direccion.
     * @param elem_ty Tipo del elemento.
     * @param ln Linea del fuente.
     * @return El valor leido.
     */
    ir::IrValueId vec_load_elem(ir::IrValueId at, ir::IrType elem_ty,
                                uint32_t ln);

    void pack_variadic_args(std::vector<ir::IrValueId> &arg_ids, size_t fixed,
                            ir::IrType elem_ty, uint32_t line);

    std::vector<DeclaredParam>
    declare_params(ir::IrFunction &fn,
                   const std::vector<std::unique_ptr<ast::ParamDecl>> &params,
                   std::vector<std::pair<std::string, ir::IrValueId>> &bindings,
                   size_t reserved_slots = 0);

    /**
     * @brief Cuantos huecos de argumento ocupa esta lista de parametros.
     *
     * Uno por parametro, DOS por un variadico empaquetado -- la direccion del
     * array y cuantos son -- y NINGUNO por el `...` pelado, cuyos argumentos
     * viajan crudos por donde diga la convencion.
     *
     * @param params Los parametros declarados.
     * @return El numero de huecos.
     */
    static size_t param_slot_count(
        const std::vector<std::unique_ptr<ast::ParamDecl>> &params);

    /**
     * @brief Si los metodos de @p class_name se despachan por tabla.
     *
     * Una clase la necesita si HEREDA de otra, si implementa alguna interfaz, o
     * si ALGUIEN LA EXTIENDE -- lo tercero es lo que obliga a mirar el programa
     * entero: `Base b = new Derivada()` tiene que ejecutar el metodo de la
     * derivada, y eso solo se sabe mirando quien hereda de quien.  Sin ninguna
     * de las tres, el metodo se llama directo y no hay tabla que consultar.
     *
     * La regla estaba escrita SEIS veces -- construir el objeto, el destructor
     * al salir de un ambito, el de dentro de un puntero con dueno, liberar en
     * nativo, dos mas -- y cada copia lleva un comentario diciendo que tiene
     * que coincidir con otra ("mismo criterio que __new_", "misma deteccion de
     * needs_vtable").  Seis sitios donde un dia dejaran de coincidir, y lo que
     * se rompe entonces es que un destructor se llame por el tipo ESCRITO en
     * vez de por el que el objeto tiene de verdad.
     *
     * El conjunto de clases de las que alguien hereda se calcula UNA vez y se
     * recuerda: antes cada consulta recorria todas las clases del programa, y
     * las consultas salen dentro de bucles sobre clases y sobre sus campos.
     *
     * Salvo si la clase es FINAL: entonces la tercera pregunta ya tiene
     * respuesta -- nadie puede extenderla -- y no hay programa que mirar.  Ese
     * atajo se apoya en que el comprobador de tipos RECHACE extender una final;
     * sin ese rechazo seria un fallo silencioso, porque saldria con llamada
     * directa una clase que si tiene derivadas.  Las dos cosas entraron a la
     * vez, y hasta entonces `final` en una clase no existia: la palabra clave
     * no parseaba y la anotacion no se aplicaba.
     *
     * @param class_name Nombre de la clase.
     * @return @c true si necesita tabla de metodos.
     */
    bool class_has_vtable(const std::string &class_name) const;

    /**
     * @brief Cuantas ranuras de la tabla de metodos se reservan, en el camino
     *        NATIVO, para el despacho por interfaz.
     *
     * En el camino nativo un objeto tiene UNA tabla y por ella se despachan
     * las dos cosas: los metodos de su clase y los de las interfaces que
     * cumple.  Cada despacho numera por su cuenta -- la clase por su cadena de
     * herencia, la interfaz por el orden en que declara los suyos --, asi que
     * hay que darle a cada uno su tramo o se pisan.
     *
     * Las interfaces van DELANTE, todas seguidas, con el mismo reparto para
     * todo el programa; los metodos de la clase, detras.  Que el reparto sea
     * del programa entero y no de cada clase es lo que hace que una base y su
     * derivada coincidan sin tener que ponerse de acuerdo: si el tramo lo
     * eligiera cada clase, una derivada que cumple una interfaz que su base no
     * cumple correria los metodos heredados y una llamada por el tipo base
     * leeria la ranura equivocada.
     *
     * Vale 0 si el programa no declara ninguna interfaz, y entonces esto no
     * cambia una sola ranura.
     *
     * @return Numero total de ranuras reservadas para interfaces.
     */
    uint32_t native_iface_slot_count() const;

    /**
     * @brief Ranura de un metodo de interfaz en la tabla nativa.
     *
     * @param iface  Nombre de la interfaz.
     * @param midx   Posicion del metodo dentro de la declaracion de la
     * interfaz.
     * @return La ranura, dentro del tramo reservado a esa interfaz.
     */
    uint32_t native_iface_slot(const std::string &iface, uint32_t midx) const;

    /**
     * @brief Ranura de un metodo de clase en la tabla nativa: su indice de
     *        siempre, corrido detras del tramo de las interfaces.
     *
     * @param vtable_index Indice del metodo en la tabla de su clase.
     * @return La ranura.
     */
    uint32_t native_class_slot(uint32_t vtable_index) const {
        return native_iface_slot_count() + vtable_index;
    }

    /**
     * @brief Que clases concretas puede tener de verdad el receptor de un
     *        despacho dinamico, para poder ADIVINARLO y llamar directo.
     *
     * El programa esta entero delante, asi que se sabe quien puede estar al
     * otro lado de un `obj.metodo()`: si son pocos, se compara la clase y se
     * llama directo, y solo si ninguna acierta se despacha como siempre.
     *
     * Se dejan fuera los que llevan aspectos: su camino rapido seria una
     * llamada directa que se saltaria la cadena.  Sus objetos caen al despacho
     * normal, que si la recorre, y los demas siguen adivinandose.
     *
     * @param static_class  Tipo declarado del receptor (clase o interfaz).
     * @param method_name   Metodo que se llama.
     * @param is_interface  Si el tipo declarado es una interfaz.
     * @return Pares (clase concreta, nombre IR del metodo), vacio si son
     *         demasiados o hay algun aspecto sin atribuir.
     */
    std::vector<std::pair<std::string, std::string>>
    spec_devirt_impls(const std::string &static_class,
                      const std::string &method_name, bool is_interface) const;

    /**
     * @brief Emite en @p setup la resolucion del @c ClassInfo* de una clase
     *        por su nombre, y devuelve el valor que lo sostiene.
     *
     * Va a un vector aparte porque su sitio es el bloque de ENTRADA: se
     * resuelve una vez por invocacion y no una por vuelta del bucle.
     *
     * @param setup       Vector donde se acumulan las instrucciones.
     * @param cls_name    Nombre de la clase.
     * @param source_line Linea del fuente a la que atribuirlas.
     * @return El valor con el @c ClassInfo*.
     */
    ir::IrValueId emit_findclass_into(std::vector<ir::IrInstr> &setup,
                                      const std::string &cls_name,
                                      uint32_t source_line);

    /**
     * @brief Mete @p setup al final del bloque de entrada, antes de su
     *        terminador si lo tiene.
     */
    void splice_into_entry_block(std::vector<ir::IrInstr> &setup);

    /// Reparto de tramos por interfaz.  Se calcula una vez, la primera que
    /// alguien pregunta; la jerarquia ya no cambia cuando se llega aqui.
    mutable std::unordered_map<std::string, uint32_t> iface_slot_base_;
    /// Total de ranuras reservadas, o UINT32_MAX mientras no se ha calculado.
    mutable uint32_t iface_slot_total_ = UINT32_MAX;

    /**
     * @brief Las clases de las que alguna otra hereda.
     *
     * Se llena la primera vez que alguien pregunta por una tabla de metodos.
     * Es del bajado entero, no de una funcion, porque la jerarquia ya no cambia
     * cuando se llega aqui: el comprobador de tipos la cerro.
     */
    mutable std::unordered_set<std::string> extended_classes_;
    mutable bool extended_classes_built_ = false;

    /**
     * @brief Genera una instruccion CONST en el bloque actual.
     */
    ir::IrValueId emit_const(ir::IrType t, uint64_t imm, uint32_t source_line);

    /**
     * @name Escribir al exterior, y los literales que se escriben
     *
     * Vivian como lambdas dentro de la bajada de los builtins, y de ahi no
     * podian salir: media docena de sitios los necesitaban y la funcion que los
     * contenia tenia siete mil lineas.  Son metodos porque no capturan nada --
     * solo usan el estado del propio bajador --, asi que el cambio no altera
     * ninguna llamada.
     *
     * Escribir tiene DOS caminos y por eso no es una linea: con el runtime de
     * la maquina virtual delante se llama a su primitiva de salida; en un
     * binario nativo no hay tal cosa, asi que se emiten los bytes por un
     * simbolo que el programador puede redefinir en Vesta.
     * @{
     */

    /// @brief Interna un literal de cadena y devuelve (direccion, longitud).
    std::pair<ir::IrValueId, ir::IrValueId>
    emit_string_lit(ast::StringLitExpr *slit);

    /**
     * @brief Llama a una primitiva de salida por su nombre.
     *
     * Si el programa define una funcion con ese nombre, gana la suya: asi se
     * puede sustituir la salida entera desde Vesta sin tocar el compilador.
     */
    void emit_io_prim(const std::string &prim,
                      const std::vector<ir::IrValueId> &args,
                      uint32_t source_line);

    /**
     * @brief Intenta bajar una llamada como uno de los builtins de imprimir.
     *
     * Imprimir parece una llamada y no lo es: lo que se escribe puede ser un
     * literal, una interpolacion, o un valor de cualquier tipo -- y cada tipo
     * se escribe distinto --, y encima el usuario puede pedir COMO quiere verlo
     * (hexadecimal, binario, alineado a un ancho).  Ese averiguar es el grueso
     * del trabajo; escribir de verdad son cuatro lineas.
     *
     * @return @c true si el nombre era de esta familia y quedo bajado; @c false
     *         si no lo era, para que quien despacha siga probando.
     */
    bool try_lower_print_builtins(ast::CallExpr *e, Builtin b,
                                  ir::IrValueId &out_value);

    /**
     * @brief Intenta bajar una llamada como uno de los builtins que piden algo
     *        al MUNDO: ficheros, memoria del anfitrion, fibras, modulos.
     *
     * Ninguno se resuelve dentro del programa: hay que pedirselo a alguien de
     * fuera y quedarse con lo que devuelva, sabiendo que puede fallar.  Y lo
     * que devuelve es memoria del ANFITRION, no de la maquina virtual, cosa que
     * hay que marcar en el valor o quien lo lea despues acabaria en la memoria
     * equivocada.
     *
     * @return @c true si el nombre era de esta familia y quedo bajado.
     */
    bool try_lower_runtime_builtins(ast::CallExpr *e, Builtin b,
                                    ir::IrValueId &out_value);

    /**
     * @brief Intenta bajar una llamada como uno de los builtins que suponen
     *        que hay ALGUIEN MAS: memoria compartida, atomicos, buzones,
     *        futuros.
     *
     * Lo que los une no es lo que hacen sino con quien: todos existen porque
     * lo que un proceso escribe lo tiene que ver otro, y en el orden correcto.
     * De ahi que `share` no reserve memoria sino que la saque del monton
     * privado, y que un atomico no sume sino que sume SIN dejar ver el estado
     * a medias.
     *
     * @return @c true si el nombre era de esta familia y quedo bajado.
     */
    bool try_lower_concurrent_builtins(ast::CallExpr *e, Builtin b,
                                       ir::IrValueId &out_value);

    /**
     * @brief Intenta bajar una llamada como uno de los builtins de lo que
     *        puede NO estar: `Optional<T>` y `Result<T, E>`.
     *
     * Construirlos, preguntar si hay algo dentro y sacarlo.  Los dos son la
     * misma idea -- un valor que lleva consigo si esta o no --, y ninguno toca
     * el monton: viven en la pila y se devuelven por la direccion que da el
     * llamante, asi que envolver un valor no cuesta una reserva.
     *
     * @return @c true si el nombre era de esta familia y quedo bajado.
     */
    bool try_lower_optional_builtins(ast::CallExpr *e, Builtin b,
                                     ir::IrValueId &out_value);

    /**
     * @brief Intenta bajar una llamada como uno de los builtins de reflexion.
     *
     * Preguntarle al programa por si mismo: la clase por su nombre, el campo o
     * el metodo por el suyo, y llamarlo sin saber cual era hasta ese momento.
     * Es lo contrario del resto, que se decide al compilar.
     *
     * Sale barato porque las clases de Vesta no son metadatos del ejecutable
     * sino objetos que el propio programa construye al arrancar: preguntar por
     * ellas en marcha es mirar donde ya estan.  Y no encarece a quien no la
     * usa: el que conoce el tipo no pasa por aqui.
     *
     * @return @c true si el nombre era de esta familia y quedo bajado.
     */
    bool try_lower_reflect_builtins(ast::CallExpr *e, Builtin b,
                                    ir::IrValueId &out_value);

    /**
     * @brief Intenta bajar una llamada como uno de los builtins de propiedad
     *        y prestamo.
     *
     * Vesta no tiene un recolector que decida cuando se libera: lo decide el
     * codigo, y estos son la manera de decirlo.  Un dueno unico se suelta al
     * salir del ambito; uno compartido se cuenta y lo suelta el ultimo; un
     * prestamo no es dueno de nada.
     *
     * No cuesta nada en ejecucion porque casi todo se decide antes: un
     * prestamo es una direccion, y las reglas de quien puede mirar o escribir
     * se comprueban al compilar.  Quien SUELTA no siempre es el mismo -- el
     * `free` del anfitrion, una funcion en Vesta, una del sistema --, y lo
     * elige el programador al construir.
     *
     * @return @c true si el nombre era de esta familia y quedo bajado.
     */
    bool try_lower_ownership_builtins(ast::CallExpr *e, Builtin b,
                                      ir::IrValueId &out_value);

    /**
     * @brief Intenta bajar una llamada como uno de los builtins de cadena.
     *
     * Medirla, cortarla, unirla, compararla y sacarla al exterior.  Una cadena
     * de Vesta es una secuencia de puntos de codigo que sabe en que
     * codificacion los guarda, asi que medir su longitud y contar sus bytes no
     * son la misma pregunta.
     *
     * Cada uno baja a UNA instruccion de la maquina, no a una llamada: medir
     * es leer un campo ya calculado y cortar da una vista sobre la original
     * sin copiar, de modo que partir una cadena en un bucle no reserva memoria
     * en cada vuelta.
     *
     * @return @c true si el nombre era de esta familia y quedo bajado.
     */
    bool try_lower_string_builtins(ast::CallExpr *e, Builtin b,
                                   ir::IrValueId &out_value);

    /**
     * @brief Intenta bajar una llamada como una operacion matematica.
     *
     * Tres cosas distintas que se escriben igual: numeros reales, enteros, y
     * los BITS del numero.  Las une como viajan los decimales -- la maquina
     * pasa los argumentos en registros de proposito general, asi que un `f64`
     * viaja como sus bits dentro de un entero --.  Las que devuelven un entero
     * NO hacen esa conversion, y confundir los dos casos da valores absurdos.
     *
     * @return @c true si el nombre era de esta familia y quedo bajado.
     */
    bool try_lower_math_builtins(ast::CallExpr *e, Builtin b,
                                 ir::IrValueId &out_value);

    /**
     * @brief Intenta bajar una llamada como uno de los builtins que miran los
     *        TIPOS al compilar.
     *
     * Cuanto mide un tipo, como se alinea, cuantos campos tiene, si uno hereda
     * del otro.  Su respuesta no se calcula: se sabe.  `sizeof<Punto>()` baja
     * a la constante 16, y recorrer los campos de un tipo no monta ningun
     * bucle -- lo da el compilador, y al programa llega el cuerpo repetido --.
     * Junto con los conceptos, es la unica familia cuyo coste en ejecucion es
     * exactamente cero.
     *
     * La contrapartida: todo tiene que saberse aqui.  Preguntar por un tipo EN
     * MARCHA es otra cosa y vive en la familia de reflexion.
     *
     * @return @c true si el nombre era de esta familia y quedo bajado.
     */
    bool try_lower_introspect_builtins(ast::CallExpr *e, Builtin b,
                                       ir::IrValueId &out_value);

    /**
     * @brief Reserva un hueco de @p bytes en el marco actual.
     *
     * Lo que se reserva aqui muere con el marco, asi que es lo correcto para
     * lo que no debe sobrevivir a la funcion.  @p host_memory lo pone en la
     * memoria del ANFITRION en vez de en la de la maquina virtual: es donde un
     * Optional/Result devuelto tiene que estar para que el llamante lo lea
     * bien, y donde va TODO hueco en un binario nativo.
     *
     * @param bytes       Cuanto reservar.
     * @param line        Linea fuente, para la depuracion.
     * @param host_memory Si el hueco va en la memoria del anfitrion.
     * @return El valor SSA con la direccion del hueco.
     */
    ir::IrValueId stack_alloc_buf(uint64_t bytes, uint32_t line,
                                  bool host_memory = false);

    /**
     * @brief Reserva el hueco de un puntero inteligente, en la pila.
     *
     * Siempre en la pila: muere con la funcion, que es cuando toca soltarlo.
     *
     * Habia una segunda via al monton para cuando el puntero acababa en un
     * CAMPO, porque entonces tenia que sobrevivir a quien lo creo.  Ya no hace
     * falta: un campo ES su propia ranura, asi que lo que se guarda en el es el
     * recurso y esta de aqui solo dura lo que la expresion que la construye.
     *
     * @param line Linea fuente, para la depuracion.
     * @return El valor SSA con la direccion del hueco.
     */
    ir::IrValueId unique_slot_buf(uint32_t line);

    /**
     * @brief Suma un desplazamiento a una direccion.
     *
     * El resultado HEREDA de la base si es direccion del anfitrion: una
     * direccion mas ocho sigue apuntando a la misma memoria.  Decir que es del
     * anfitrion cuando la base es de la maquina virtual hace que quien la lea
     * despues emita el acceso equivocado, y eso no da error: lee otra cosa.
     *
     * @param base        La direccion de partida.
     * @param off         Cuanto sumarle.
     * @param source_line Linea fuente, para la depuracion.
     * @return El valor SSA con la direccion resultante.
     */
    ir::IrValueId emit_ptr_add(ir::IrValueId base, ir::IrValueId off,
                               uint32_t source_line);

    /**
     * @brief Igual, con el desplazamiento conocido al compilar.
     *
     * Sumar cero devuelve la base sin emitir nada, para que pedir el campo en
     * el desplazamiento 0 no haya que tratarlo aparte.
     *
     * @param base        La direccion de partida.
     * @param off         Cuanto sumarle, conocido al compilar.
     * @param source_line Linea fuente, para la depuracion.
     * @return El valor SSA resultante, o @p base si @p off es cero.
     */
    ir::IrValueId emit_ptr_add(ir::IrValueId base, uint64_t off,
                               uint32_t source_line);

    /**
     * @brief Suma a una direccion sabiendo que la de salida es del anfitrion.
     *
     * @ref emit_ptr_add hereda la naturaleza de la base, que es lo correcto
     * casi siempre.  Esto es para cuando la base la PERDIO por el camino y aun
     * asi se sabe: tipicamente porque paso por un cambio de tipo a entero --
     * sumar y restar direcciones para elegir una sin bifurcar -- y de ahi sale
     * un numero, que no lleva la marca.
     *
     * Perderla no da un error: da un acceso emitido contra la memoria
     * equivocada, que es peor.  Por eso se dice aqui, en el sitio donde consta.
     *
     * @param base        La direccion de partida.
     * @param off         Cuanto sumarle.
     * @param source_line Linea fuente, para la depuracion.
     * @return El valor SSA resultante, marcado como del anfitrion.
     */
    ir::IrValueId emit_host_ptr_add(ir::IrValueId base, ir::IrValueId off,
                                    uint32_t source_line);

    /**
     * @brief Salta a un bloque, y deja el grafo contado.
     *
     * Emitir el salto es la mitad; la otra es anotar que el bloque de salida
     * va ahi y el de llegada viene de aqui.  Sin eso el codigo generado es
     * correcto pero el GRAFO miente, y quien lo recorra despues decide sobre
     * un mapa equivocado.
     *
     * @param target      El bloque al que saltar.
     * @param source_line Linea fuente, para la depuracion.
     */
    /**
     * @brief Anota que de @p from se puede llegar a @p to, sin emitir nada.
     *
     * Hace falta suelto cuando el salto lo pone otra cosa -- la tabla de un
     * `match`, por ejemplo --.  Es la mitad de @ref emit_br, y la que se
     * olvida.
     *
     * @param from Bloque de salida.
     * @param to   Bloque de llegada.
     */
    void add_cfg_edge(ir::IrBlockId from, ir::IrBlockId to);

    /**
     * @brief Termina la funcion actual sin devolver nada.
     *
     * Marca el bloque como terminado, que es la mitad que se olvida: si el
     * bajador no lo sabe, emite codigo detras del retorno.
     *
     * @param source_line Linea fuente, para la depuracion.
     */
    void emit_ret_void(uint32_t source_line);

    void emit_br(ir::IrBlockId target, uint32_t source_line);

    /**
     * @brief Salta a un bloque DESDE otro que no es el actual.
     *
     * Al construir un bucle, el salto de entrada sale del bloque de ANTES, y
     * para entonces el bajador ya esta emitiendo en la cabecera; al cerrar un
     * condicional, cada rama salta al bloque comun desde donde termino.
     *
     * @param from        Bloque del que sale el salto.
     * @param target      Bloque al que va.
     * @param source_line Linea fuente, para la depuracion.
     */
    void emit_br_from(ir::IrBlockId from, ir::IrBlockId target,
                      uint32_t source_line);

    /**
     * @brief Salta a un bloque o a otro segun @p cond, contando las CUATRO
     *        aristas.
     *
     * Las aristas no son contabilidad: son lo que el analisis de vivacidad
     * camina para saber hasta donde vive un valor.  Sin ellas, un valor que
     * cruza el salto parece muerto al llegar al bloque de destino, y el
     * asignador reutiliza su registro para otra cosa -- lo que en un caso ya
     * costo una direccion basura y un fallo de segmentacion --.  Por eso
     * emitir el salto y apuntarlas es UNA operacion y no dos.
     *
     * @param cond        El valor que decide.
     * @param t_true      Bloque al que ir si no es cero.
     * @param t_false     Bloque al que ir si lo es.
     * @param source_line Linea fuente, para la depuracion.
     */
    void emit_br_cond(ir::IrValueId cond, ir::IrBlockId t_true,
                      ir::IrBlockId t_false, uint32_t source_line);

    /**
     * @brief Igual, pero saliendo del bloque que se diga y no del actual.
     *
     * Hace falta porque un bloque se cierra a menudo DESPUES de haber seguido
     * bajando por otro sitio: la condicion de un bucle, el lado izquierdo de un
     * `&&`, la cadena de comprobaciones de un `catch`.  Cuando llega el momento
     * de poner el salto, el bloque actual ya es otro, y las aristas apuntadas
     * desde el son mentira: el analisis de vivacidad cree que un valor muere
     * donde no muere y el asignador reutiliza su registro.
     *
     * @param from        Bloque del que sale el salto.
     * @param cond        El valor que decide.
     * @param t_true      Bloque al que ir si no es cero.
     * @param t_false     Bloque al que ir si lo es.
     * @param source_line Linea fuente, para la depuracion.
     */
    void emit_br_cond_from(ir::IrBlockId from, ir::IrValueId cond,
                           ir::IrBlockId t_true, ir::IrBlockId t_false,
                           uint32_t source_line);

    /**
     * @brief Lee un qword de una direccion.
     *
     * @param addr        De donde leer.
     * @param source_line Linea fuente, para la depuracion.
     * @return El valor SSA leido.
     */
    /**
     * @brief Lee de una direccion, con el ancho que se pida.
     *
     * El ancho no se deduce: leer ocho bytes donde hay dos arrastra lo de
     * detras, y leer dos donde hay ocho deja el valor a medias.
     *
     * @p host_ptr dice si lo LEIDO es a su vez una direccion del anfitrion, que
     * no es lo mismo que la naturaleza de @p addr.
     *
     * @param addr        De donde leer.
     * @param ty          De que ancho.
     * @param source_line Linea fuente, para la depuracion.
     * @param host_ptr    Si lo leido es una direccion del anfitrion.
     * @return El valor SSA leido.
     */
    ir::IrValueId emit_load_typed(ir::IrValueId addr, ir::IrType ty,
                                  uint32_t source_line, bool host_ptr = false);

    /// @brief Atajo de @ref emit_load_typed para el ancho de ocho bytes.
    ir::IrValueId emit_load_i64(ir::IrValueId addr, uint32_t source_line);

    /**
     * @brief Lee UN byte y lo deja en un valor mas ancho, rellenado con ceros.
     *
     * Lo que separa esto de @ref emit_load_typed es que ahi el ancho de la
     * LECTURA y el del VALOR resultante son el mismo, y aqui no: se leen ocho
     * bits y el valor mide sesenta y cuatro.  Un byte vale de 0 a 255, asi que
     * lo de arriba son ceros y no hay que mirar el signo; tenerlo ya ancho es
     * lo que permite operarlo con el resto sin ir mezclando anchuras.
     *
     * Hacia falta porque esa combinacion no se podia pedir: estaba escrita a
     * mano -- creando la instruccion campo a campo -- en SEIS sitios (recorrer
     * los bytes de una cadena, contar sus puntos de codigo, pasarla a otra
     * codificacion, leer un caracter suelto, dos mas), y construir una
     * instruccion a mano es donde se olvida la linea del fuente o se pone un
     * ancho por otro.
     *
     * @param addr        De donde leer.
     * @param source_line Linea fuente, para la depuracion.
     * @param value_ty    De que ancho es el valor resultante.
     * @return El valor SSA con el byte leido.
     */
    ir::IrValueId emit_load_byte(ir::IrValueId addr, uint32_t source_line,
                                 ir::IrType value_ty = ir::IrType::I64);

    /**
     * @brief Lee de memoria una direccion del anfitrion.
     *
     * Lo guardado son ocho bytes, pero lo leido es un PUNTERO: el valor sale
     * marcado como tal, que es lo que despues decide si un acceso a traves de
     * el va a memoria del anfitrion o de la maquina.  Leerlo como un entero
     * cualquiera pierde esa marca y el acceso siguiente se emite mal.
     *
     * @param addr        De donde leer.
     * @param source_line Linea fuente, para la depuracion.
     * @return El puntero leido, ya marcado.
     */
    ir::IrValueId emit_load_host_ptr(ir::IrValueId addr, uint32_t source_line);

    /**
     * @brief Resuelve por la tabla de metodos cual toca llamar.
     *
     * La tabla esta en los primeros ocho bytes del OBJETO, no en su clase, y
     * eso es lo que hace que una referencia a la base ejecute el metodo de la
     * derivada: quien lo construyo puso ahi la tabla que le tocaba.
     *
     * @param obj          El objeto sobre el que se llama.
     * @param vtable_index La posicion del metodo en la tabla.
     * @param source_line  Linea fuente, para la depuracion.
     * @return El puntero al codigo del metodo.
     */
    ir::IrValueId emit_vtable_method_ptr(ir::IrValueId obj,
                                         uint32_t vtable_index,
                                         uint32_t source_line);

    /**
     * @brief Llama a una funcion de Vesta.
     *
     * Si @p ret es VOID no se crea valor: pedir un hueco para el resultado de
     * algo que no devuelve deja un valor SSA que nadie define.
     *
     * @param name        Nombre de la funcion.
     * @param args        Argumentos, en orden.
     * @param ret         Tipo del resultado, o VOID.
     * @param source_line Linea fuente, para la depuracion.
     * @return El valor SSA del resultado, o IR_NO_VALUE si no devuelve.
     */
    /**
     * @brief Intenta bajar la llamada como constructor de variante de enum.
     *
     * `Color.Red` se escribe como una llamada a un acceso a campo, igual que
     * un metodo, y no lo es: no hay nada que llamar, hay un valor que
     * construir.  Los distingue una marca que dejo el comprobador de tipos.
     *
     * @param e   La llamada.
     * @param out Donde dejar el valor construido.
     * @return @c true si lo era y quedo bajado.
     */
    bool try_lower_enum_variant_ctor(ast::CallExpr *e, ir::IrValueId &out);

    /**
     * @brief Intenta bajar la llamada como `Tipo.default()` de un struct.
     *
     * Dos formas que no hacen lo mismo: con el nombre de un tipo reserva uno
     * nuevo, con una variable resetea el que ya existe.  Y en las dos se pone
     * a cero primero: un struct recien reservado tiene lo que hubiera en la
     * pila, y un campo sin valor por defecto se quedaria con esa basura.
     *
     * @param e   La llamada.
     * @param out Donde dejar la direccion del struct.
     * @return @c true si lo era y quedo bajado.
     */
    bool try_lower_struct_default_ctor(ast::CallExpr *e, ir::IrValueId &out);

    /**
     * @brief Intenta bajar la llamada como funcion de un namespace importado.
     *
     * Forma `lib.funcion(args)`.  El nombre visible no es el que acaba en el
     * binario: cada namespace mangla los suyos, asi que se busca el simbolo y
     * se emite un CALL a su etiqueta manglada.  A que namespace apunta la base
     * lo resolvio el type checker en @c ns_index, porque el nombre por si solo
     * no basta con bases de varios segmentos (`ui.widgets.Boton`).
     *
     * @param e   La llamada.
     * @param out Donde dejar el valor que la llamada produce.
     * @return @c true si el callee era de un namespace y quedo bajado.
     */
    bool try_lower_namespaced_call(ast::CallExpr *e, ir::IrValueId &out);

    /**
     * @brief Intenta bajar la llamada como un metodo sobre un receptor.
     *
     * A donde va `algo.metodo(args)` lo decide el TIPO del receptor, no el
     * nombre: una cadena reescribe a su builtin con el receptor de primer
     * argumento; una clase va al despacho por vtable; un struct, a la llamada
     * directa a su funcion; una coleccion primitiva, a la funcion nativa del
     * plugin.  Aparte quedan los estaticos y la reflexion ergonomica, que se
     * escriben igual pero no son un metodo sobre un valor.
     *
     * @param e   La llamada.
     * @param out Donde dejar el valor que el metodo produce.
     * @return @c true si era un metodo y quedo bajado.
     */
    bool try_lower_method_call(ast::CallExpr *e, ir::IrValueId &out);

    /**
     * @brief Intenta bajar la llamada como un metodo ESTATICO de la clase.
     *
     * `Clase.metodo(args)` no tiene receptor: no hay objeto sobre el que
     * llamar, asi que no se pasa `this` y no hay tabla que consultar -- el
     * destino se sabe al compilar y es una llamada directa.
     *
     * @param e   La llamada.
     * @param fa  Su callee, de donde sale el nombre de la clase.
     * @param out Donde dejar el valor que la llamada produce.
     * @return @c true si era estatica y quedo bajada.
     */
    /**
     * @brief Lee o escribe un campo nombrandolo con una CADENA.
     *
     * `field_get<T>(obj, "x")` parece reflexion y no lo es: el nombre es un
     * literal, asi que el desplazamiento se resuelve AL COMPILAR y se emite el
     * mismo acceso que habria escrito `obj.x`.
     *
     * @param e         La llamada.
     * @param b         Cual de los dos es.
     * @param out_value Donde dejar lo leido; sin valor al escribir.
     * @return @c true si era uno de los dos y quedo bajado.
     */
    /**
     * @brief Recorre los campos o los metodos de un tipo, AL COMPILAR.
     *
     * No es un bucle: el compilador conoce los campos, asi que repite el
     * cuerpo una vez por cada uno con su nombre y su desplazamiento ya
     * puestos.  Al programa llegan N copias, sin contador ni condicion.
     *
     * @param e         La llamada.
     * @param b         Cual de los dos es.
     * @param out_value Donde dejar el resultado, si lo hay.
     * @return @c true si era uno de los dos y quedo bajado.
     */
    bool try_lower_for_each_member(ast::CallExpr *e, Builtin b,
                                   ir::IrValueId &out_value);

    bool try_lower_field_access_by_name(ast::CallExpr *e, Builtin b,

                                        ir::IrValueId &out_value);

    bool try_lower_static_method_call(ast::CallExpr *e,
                                      ast::FieldAccessExpr *fa,
                                      ir::IrValueId &out);

    /**
     * @brief Monta el `try` del modo NATIVO, sin maquina virtual detras.
     *
     * Sin VM no hay pila de marcos de excepcion, asi que el modelo es el de C:
     * se guarda el estado del punto de entrada y lanzar es volver a el.  Ese
     * sitio se ejecuta DOS veces y lo unico que las distingue es lo que
     * devuelve guardar -- cero la primera, distinto de cero al volver --, asi
     * que la bifurcacion no es del programa: es "entro" contra "he vuelto".
     *
     * @param s           El `try` que se esta bajando.
     * @param body_bb     Bloque del cuerpo, al que se entra la primera vez.
     * @param handler_bbs Bloques de los `catch`, en orden.
     */
    void emit_try_frame_native(ast::TryStmt *s, ir::IrBlockId body_bb,
                               const std::vector<ir::IrBlockId> &handler_bbs);

    /**
     * @brief Declara un struct dado por una lista de inicializacion.
     *
     * Cubre `Point p = {1, 2}` y `Point p = {.x=1, .y=2}`: el struct se
     * reserva en memoria del anfitrion y cada campo se escribe en su
     * desplazamiento.  Lo que cambia es de donde sale el valor de cada campo,
     * y que en la forma con nombres un campo puede faltar y tomar entonces el
     * valor por defecto que declare el struct.
     *
     * @param vd       La declaracion.
     * @param sem_type El tipo ya resuelto (alias aplicados).
     * @return @c true si era esta forma y quedo bajada.
     */
    bool try_lower_struct_init_list(ast::VarDeclStmt *vd, const Type &sem_type);

    /**
     * @brief Declara una variable de tipo struct (o enum, mismo camino).
     *
     * Reserva el hueco en memoria del anfitrion -- en los tres modos, porque
     * el callee solo recibe una direccion y no sabria si detras hay pila de la
     * maquina o del anfitrion -- y ata el nombre a esa direccion.  El hueco se
     * pone a cero antes de nada, y si el struct tiene destructor o punteros
     * con dueno se apunta la limpieza del final del ambito.
     *
     * @param vd       La declaracion.
     * @param sem_type El tipo ya resuelto (alias aplicados).
     * @return @c true si era un struct y quedo bajado.
     */
    bool try_lower_struct_var(ast::VarDeclStmt *vd, const Type &sem_type);

    /**
     * @brief Declara una variable de tipo array nativo `T[N]`.
     *
     * Desde el lowering un array es lo mismo que un struct: un hueco contiguo
     * y un nombre atado a su base.  Lo que cambia es de donde salen los bytes
     * iniciales: de un literal de cadena escrito byte a byte (memoria cruda,
     * sin GC), de una lista posicional, o de nada -- reservar y poner a cero.
     *
     * @param vd       La declaracion.
     * @param sem_type El tipo ya resuelto (alias aplicados).
     * @return @c true si era un array y quedo bajado.
     */
    bool try_lower_array_var(ast::VarDeclStmt *vd, const Type &sem_type);

    /**
     * @brief Baja el valor con el que arranca una variable.
     *
     * De aqui sale el valor que se ata al nombre, pero varias formas no dejan
     * un valor que atar: trasladar la propiedad de un puntero con dueno mueve
     * el contenido sin producir nada nuevo, y una funcion que devuelve un
     * agregado lo escribe en el hueco de la variable en vez de devolverlo.
     * Esas terminan la declaracion aqui mismo.
     *
     * Sin inicializador el valor es CERO: una variable con la basura que
     * hubiera en la pila se lee distinto cada vez que se ejecuta.
     *
     * @param vd       La declaracion.
     * @param sem_type El tipo ya resuelto.
     * @param vt       Ese tipo, en el vocabulario del IR.
     * @param v        Donde dejar el valor inicial.
     * @return @c true si la declaracion quedo bajada ENTERA; @c false si lo
     *         unico que falta es atar @p v al nombre.
     */
    /**
     * @brief Declara una variable de la que alguien toma la direccion.
     *
     * Una variable normal es un valor SSA y nada mas.  Pero si en algun sitio
     * aparece `&x` hay que poder dar una direccion, asi que se le reserva su
     * hueco y lo que el ambito guarda es la DIRECCION: cada lectura y cada
     * escritura pasan por memoria.  Se sabe antes de bajar nada porque el
     * recorrido previo del cuerpo lo apunto -- cuando se ve el `&x` ya es
     * tarde, los usos anteriores se habrian bajado como valor --.
     *
     * @param vd       La declaracion.
     * @param sem_type El tipo ya resuelto.
     * @param vt       Ese tipo, en el vocabulario del IR.
     * @return @c true si era una de estas y quedo bajada.
     */
    /**
     * @brief Escribe UN valor interpolado, con la forma que se haya pedido.
     *
     * Lo que hay dentro de un `${...}` puede ser de cualquier tipo, y cada uno
     * se escribe distinto: un entero con signo no es uno sin signo, un
     * flotante no es un puntero, una cadena no es un caracter.  Aqui se
     * averigua cual es y se elige la primitiva que le toca, con las
     * conversiones que haga falta.
     *
     * Se llama a si misma, y no por elegancia: un color de 24 bits se escribe
     * como tres numeros dentro de la misma secuencia, y un struct que sabe
     * decir su nombre se imprime pidiendoselo -- lo que devuelve hay que
     * escribirlo otra vez por aqui --.
     *
     * @param ex       La expresion a escribir.
     * @param fmt_str  Lo que seguia a los dos puntos, o vacio.
     */
    void emit_print_typed_value(ast::Expr *ex, const std::string &fmt_str);

    /**
     * @brief Apunta que nombres visibles LEE una expresion.
     *
     * Va con @ref scan_read_names_stmt, y se llaman entre si porque en este
     * lenguaje una sentencia contiene expresiones y una expresion puede
     * contener sentencias.
     *
     * @param e   Expresion por la que empezar.
     * @param out Donde anñadir los nombres leidos.
     */
    /**
     * @brief Despacha un `match` de muchos casos por un arbol de busqueda.
     *
     * Con pocos casos se comparan uno a uno; con muchos, eso son muchas
     * comparaciones en el peor caso.  El arbol parte por la mitad y baja: el
     * doble de casos cuesta una comparacion mas, no el doble.
     *
     * Se corta en dos casos por hoja porque el arbol ahorra comparaciones
     * pero cada nodo cuesta un bloque y un salto; por debajo de ahi no
     * compensa.
     *
     * @param value       El valor que se despacha.
     * @param cases       Los casos, ORDENADOS por su valor.
     * @param lo,hi       El tramo de @p cases que toca a esta llamada.
     * @param cur         Bloque donde emitir.
     * @param default_bb  A donde ir si no encaja ninguno.
     * @param prefix      Con que empiezan los nombres de los bloques nuevos.
     * @param source_line Linea fuente, para la depuracion.
     */
    void
    emit_case_bst(ir::IrValueId value,
                  const std::vector<std::pair<int64_t, ir::IrBlockId>> &cases,
                  size_t lo, size_t hi, ir::IrBlockId cur,
                  ir::IrBlockId default_bb, const char *prefix,
                  uint32_t source_line);

    void scan_read_names_expr(const ast::Expr *e,
                              std::unordered_set<std::string> &out);

    /**
     * @brief Apunta que nombres visibles LEE una sentencia.
     *
     * Se usa sobre los `catch`: lo que leen tiene que sobrevivir al salto, y
     * eso incluye `this` y los parametros -- que no estan en el ambito mas
     * interno, de ahi que se pregunte por TODOS.
     *
     * @param st  Sentencia por la que empezar.
     * @param out Donde anñadir los nombres leidos.
     */
    void scan_read_names_stmt(const ast::Stmt *st,
                              std::unordered_set<std::string> &out);

    /// @brief @c true si @p name esta atado en ALGUN ambito, no solo el ultimo.
    bool name_visible_in_any_scope(const std::string &name) const;

    bool try_lower_address_taken_var(ast::VarDeclStmt *vd, const Type &sem_type,
                                     ir::IrType vt);

    bool try_lower_var_init(ast::VarDeclStmt *vd, const Type &sem_type,
                            ir::IrType vt, ir::IrValueId &v);

    /**
     * @brief Asigna a un campo: `obj.campo = v`.
     *
     * Dos receptores muy distintos comparten sintaxis.  En una clase el campo
     * puede ser estatico -- y entonces no hay objeto que mirar --, puede ser
     * una propiedad con su metodo de escritura, y con herencia de por medio el
     * desplazamiento sale de la clase que de verdad lo declara.  En un struct
     * es base mas desplazamiento, sin nada que resolver en ejecucion.
     *
     * @param e   La asignacion.
     * @param out Donde dejar el valor asignado.
     * @return @c true si el destino era un campo y quedo bajado.
     */
    bool try_lower_assign_to_field(ast::AssignExpr *e, ir::IrValueId &out);

    /**
     * @brief Asigna a un elemento: `arr[i] = v`.
     *
     * Es escribir en la direccion del elemento, que sale del mismo calculo que
     * leerlo.  Con dos formas que no lo son: una clase o struct puede definir
     * su metodo de escritura por indice, y una coleccion primitiva escribe por
     * su funcion nativa, no por direccion.
     *
     * @param e   La asignacion.
     * @param out Donde dejar el valor asignado.
     * @return @c true si el destino era un indice y quedo bajado.
     */
    bool try_lower_assign_to_index(ast::AssignExpr *e, ir::IrValueId &out);

    /**
     * @brief Asigna a traves de un puntero: `*p = v`.
     *
     * Lo unico que hay que decidir es de que ancho es la escritura -- lo dice
     * el tipo apuntado -- y si va a memoria del anfitrion o de la maquina, que
     * lo dice el propio puntero.
     *
     * @param e   La asignacion.
     * @param out Donde dejar el valor asignado.
     * @return @c true si el destino era un desreferenciado y quedo bajado.
     */
    bool try_lower_assign_to_deref(ast::AssignExpr *e, ir::IrValueId &out);

    /**
     * @brief Reserva el almacenamiento de lo que vive fuera de las funciones.
     *
     * Corre ANTES de bajar ninguna funcion, y el orden no es de comodidad: al
     * bajar `main`, un nombre global sin hueco todavia se lee como no
     * resuelto, y el prologo de `main` decide si llamar al init del modulo
     * mirando si hay algun hueco -- uno que solo USA globales ajenas no
     * tendria ninguno y el init no correria.
     *
     * Cubre las globales propias, las importadas por nombre suelto, las que se
     * usan cualificadas y los campos estaticos de clase.
     */
    void lower_global_storage(ir::IrModule &out_module);

    /**
     * @brief Cablea al arranque lo que el modulo necesite antes de su codigo.
     *
     * Solo en nativo y solo despues de bajarlo TODO: el disparador de cada
     * pieza puede aparecer en cualquier funcion, y `main` se baja la primera.
     * Son tres: la deteccion de lo que sabe hacer el procesador, la copia
     * por-hilo de los `thread_local` con valor inicial, y el arranque del
     * recolector con sus mapas de pila.
     *
     * @param out_module El modulo IR ya bajado, que aqui se retoca.
     */
    void emit_startup_wiring(ir::IrModule &out_module);

    /**
     * @brief Intenta bajar la llamada como INDIRECTA, por puntero a funcion.
     *
     * A donde se salta no se sabe hasta ejecutar, salvo cuando SI se sabe: si
     * el puntero resulta ser una funcion conocida aqui, se emite la llamada
     * directa, que ademas se puede meter en linea despues.
     *
     * @param e   La llamada.
     * @param out Donde dejar el valor que la llamada produce.
     * @return @c true si era indirecta y quedo bajada.
     */
    bool try_lower_indirect_call(ast::CallExpr *e, ir::IrValueId &out);

    /**
     * @brief Intenta EJECUTAR la llamada ahora, si es a una funcion comptime.
     *
     * Si la funcion se declaro comptime y sus argumentos se conocen ya, la
     * llamada no llega al programa: queda su resultado como constante.  Se
     * renuncia si algun argumento no se conoce, y si esto es una macro
     * llamando a otra -- la llamada aun no esta cargada en la maquina
     * comptime y evaluarla daria relleno horneado como constante.
     *
     * @param e   La llamada.
     * @param out Donde dejar la constante resultante.
     * @return @c true si se ejecuto; @c false para bajarla normal.
     */
    bool try_lower_comptime_fn_call(ast::CallExpr *e, ir::IrValueId &out);

    /**
     * @brief Construye un valor con dueno y el soltador de siempre.
     *
     * `unique_box(v)` y `shared_box(v)`: se diferencian en quien lo suelta --
     * el `free` del anfitrion o la cuenta de referencias -- pero construyen
     * igual.  Si el valor se acaba de construir en el sitio se construye YA
     * dentro del bloque del monton, sin copia; la copia queda para cuando lo
     * que se guarda es una variable que ya existia.
     *
     * @param e         La llamada.
     * @param b         Cual de los dos es.
     * @param out_value Donde dejar el valor con dueno.
     * @return Siempre @c true; @c false si la llamada estaba mal escrita.
     */
    bool lower_owner_box(ast::CallExpr *e, Builtin b, ir::IrValueId &out_value);

    /**
     * @brief Construye un valor con dueno eligiendo QUIEN lo suelta.
     *
     * `unique_with(v, soltar)` / `shared_with(v, soltar)`, con cualquier
     * funcion de un argumento.  Es lo que permite poner bajo dueno cosas que
     * no salieron de pedir memoria: un fichero, un descriptor, memoria del
     * sistema.  Aqui no se pide nada: el valor YA es el resultado de haberlo
     * hecho, solo se guarda y se apunta con que soltarlo.
     *
     * @param e         La llamada.
     * @param b         Cual de los dos es.
     * @param out_value Donde dejar el valor con dueno.
     * @return Siempre @c true; @c false si la llamada estaba mal escrita.
     */
    bool lower_owner_box_with(ast::CallExpr *e, Builtin b,
                              ir::IrValueId &out_value);

    /**
     * @brief Traslada la propiedad de un valor: `move(p)`.
     *
     * Deja el origen a CERO, y esa es toda la garantia: al salir del ambito se
     * sueltan los dos, pero el que ya no es dueno tiene un cero y soltar un
     * cero no hace nada.  Copiar sin mas soltaria lo MISMO dos veces.
     *
     * @param e         La llamada.
     * @param out_value Donde dejar el valor que ahora tiene la propiedad.
     * @return Siempre @c true; @c false si la llamada estaba mal escrita.
     */
    bool lower_owner_move(ast::CallExpr *e, ir::IrValueId &out_value);

    /**
     * @brief Presta un valor: `lend(o)` y `lend_mut(o)`.
     *
     * Un prestamo es una direccion y nada mas, asi que los dos emiten lo
     * MISMO: quien puede leer y quien escribir se comprueba al compilar y no
     * deja rastro.  De donde sale la direccion depende de a quien se presta.
     *
     * @param e         La llamada.
     * @param out_value Donde dejar la direccion prestada.
     * @return Siempre @c true; @c false si la llamada estaba mal escrita.
     */
    bool lower_borrow_of(ast::CallExpr *e, Builtin b, ir::IrValueId &out_value);

    /**
     * @brief Avisa de lo que el compilador ve mal en un bloque `asm`.
     *
     * Solo de los que debe ENTENDER: un bloque crudo es cero-analisis por
     * diseno.  Los avisos salen CATALOGADOS -- codigo mas argumentos, nunca
     * una frase hecha --, y hay uno que solo aplica al modelo clasico: donde
     * SI se listan operandos, lo que denuncia no es un fallo sino lo
     * declarado.
     *
     * @param s El bloque.
     */
    void emit_asm_diagnostics(ast::AsmStmt *s);

    /**
     * @brief Comprueba que el cuerpo del bloque `asm` ensambla.
     *
     * Se ensambla ENTERO -- una linea sola no ve la etiqueta a la que otra
     * salta -- y para el OBJETIVO, no para la maquina donde corre el
     * compilador.  Los bytes se tiran: esto es solo la comprobacion.
     *
     * @param s        El bloque.
     * @param body_sub El cuerpo con los sustitutos ya resueltos.
     * @return @c false si no ensambla, con el error ya dado.
     */
    bool validate_asm_syntax(ast::AsmStmt *s, const std::string &body_sub);

    /**
     * @brief Intenta traducir el bloque `asm` a IR en vez de dejarlo opaco.
     *
     * Un bloque que el compilador entiende deja de ser una caja negra: el
     * optimizador lo ve y el asignador reparte sus registros.  Si sale, el
     * bloque NO se emite ademas como opaco.
     *
     * @param s        El bloque.
     * @param asm_name El cuerpo ya normalizado, que identifica al bloque.
     * @return @c true si quedo traducido y no hay que emitir nada mas.
     */
    bool try_lift_asm_block(ast::AsmStmt *s, const std::string &asm_name,
                            AsmMotivoOpaco &motivo_opaco);

    ir::IrValueId emit_call(const std::string &name,
                            std::vector<ir::IrValueId> args, ir::IrType ret,
                            uint32_t source_line);

    /**
     * @brief Llama a una funcion NATIVA -- codigo que no es Vesta.
     *
     * Otra instruccion que @ref emit_call porque el destino es un simbolo de
     * fuera: lo resuelve el cargador, no el enlazador de Vesta.  Quien llama
     * tiene que haber registrado antes su importacion.
     *
     * @param name        Nombre del simbolo, con su biblioteca delante.
     * @param args        Argumentos, en orden.
     * @param ret         Tipo del resultado, o VOID.
     * @param source_line Linea fuente, para la depuracion.
     * @return El valor SSA del resultado, o IR_NO_VALUE si no devuelve.
     */
    ir::IrValueId emit_calln(const std::string &name,
                             std::vector<ir::IrValueId> args, ir::IrType ret,
                             uint32_t source_line);

    /**
     * @brief Llama a una funcion de una biblioteca nativa, y la importa.
     *
     * Llamar a codigo de fuera son SIEMPRE dos cosas: apuntar que el modulo
     * necesita ese simbolo, y emitir la llamada.  Escritas por separado, la
     * primera se olvida -- o se queda atras al copiar la segunda -- y el fallo
     * no sale al compilar sino al enlazar, diciendo que falta un simbolo que
     * en el fuente esta a la vista.
     *
     * Aqui van juntas, y de paso el nombre de la biblioteca se escribe una vez
     * en lugar de dos (una para importar y otra pegada al simbolo).
     *
     * @param lib         La biblioteca (@ref kVestaIoLib y compania).
     * @param fn          El simbolo dentro de ella.
     * @param args        Argumentos, en orden.
     * @param ret         Tipo del resultado, o VOID.
     * @param source_line Linea fuente, para la depuracion.
     * @param effects     Lo que la funcion hace, si se sabe.  Sin esto el
     *                    optimizador ha de suponer lo peor -- que lee y
     *                    escribe cualquier cosa -- y no puede mover nada a su
     *                    alrededor.
     * @return El valor SSA del resultado, o IR_NO_VALUE si no devuelve.
     */
    ir::IrValueId
    emit_native_call(const std::string &lib, const std::string &fn,
                     std::vector<ir::IrValueId> args, ir::IrType ret,
                     uint32_t source_line,
                     const ir::IrNativeEffects *effects = nullptr);

    /**
     * @brief Escribe un qword en una direccion.
     *
     * Los argumentos van como se lee en el fuente -- donde, y que --, no en el
     * orden que la instruccion guarda por dentro.
     *
     * @param addr        Donde escribir.
     * @param val         Que escribir.
     * @param source_line Linea fuente, para la depuracion.
     */
    /**
     * @brief Escribe un valor del ancho que se pida.
     *
     * El ancho no se deduce del valor: escribir ocho bytes donde caben dos
     * pisa lo de detras, y escribir dos donde van ocho deja la mitad de antes.
     *
     * @param addr        Donde escribir.
     * @param val         Que escribir.
     * @param ty          De que ancho.
     * @param source_line Linea fuente, para la depuracion.
     */
    void emit_store_typed(ir::IrValueId addr, ir::IrValueId val, ir::IrType ty,
                          uint32_t source_line);

    /// @brief Atajo de @ref emit_store_typed para el ancho de ocho bytes.
    void emit_store_i64(ir::IrValueId addr, ir::IrValueId val,
                        uint32_t source_line);

    /**
     * @brief Copia @p len bytes, eligiendo COMO segun a donde se compile.
     *
     * En la maquina virtual y en el JIT la copia es una instruccion suya.  En
     * un binario nativo no hay motor detras: se llama a una copia escrita en
     * Vesta, la que el procesador de esa maquina ejecute mas rapido.  Elegir
     * mal no da error -- en nativo deja una copia que nadie implementa --, y
     * por eso la decision esta aqui y no en cada llamante.
     *
     * @param dst         Destino.
     * @param src         Origen.
     * @param len         Cuantos bytes.
     * @param source_line Linea fuente, para la depuracion.
     */
    void emit_memcpy(ir::IrValueId dst, ir::IrValueId src, ir::IrValueId len,
                     uint32_t source_line);

    /**
     * @brief Reserva el hueco de una cadena nativa y lo deja VACIO.
     *
     * Los dos pasos van siempre juntos: un hueco recien reservado tiene lo que
     * hubiera antes en la pila, y leerlo como cadena da una longitud absurda y
     * un puntero a cualquier sitio.  Por eso es un metodo y no dos.
     *
     * @param source_line Linea fuente, para la depuracion.
     * @return El valor SSA con la direccion del hueco.
     */
    ir::IrValueId emit_new_native_str_slot(uint32_t source_line);

    /**
     * @brief La direccion de un dato que ya vive en el ejecutable.
     *
     * Lo que se conoce al compilar -- textos, tablas -- no se construye en
     * marcha: se guarda en el ejecutable y lo unico que hace falta es su
     * direccion.  @p host_ptr dice si es de la memoria del anfitrion, cosa que
     * depende de a donde se compile y no del dato; marcarlo mal hace que quien
     * lo lea emita el acceso contra la otra memoria.
     *
     * @param idx         El sitio del dato, el que dio `intern_static_data`.
     * @param source_line Linea fuente, para la depuracion.
     * @param host_ptr    Si la direccion es de la memoria del anfitrion.
     * @return El valor SSA con la direccion.
     */
    ir::IrValueId emit_str_lit_addr(uint64_t idx, uint32_t source_line,
                                    bool host_ptr = false);

    /**
     * @brief Emite una operacion de dos operandos del IR.
     *
     * No confundir con @ref emit_binop_ir, que traduce un operador del
     * LENGUAJE (con sus reglas de signo y de coma flotante).  Esta emite la
     * instruccion del IR que se le pida, tal cual.
     *
     * @param op          Que operacion.
     * @param a           Primer operando.
     * @param b           Segundo operando.
     * @param t           Tipo del resultado.
     * @param source_line Linea fuente, para la depuracion.
     * @return El valor SSA con el resultado.
     */
    ir::IrValueId emit_ir_binop(ir::IrOp op, ir::IrValueId a, ir::IrValueId b,
                                ir::IrType t, uint32_t source_line);

    /**
     * @brief Emite una operacion del IR con los operandos que sean.
     *
     * La forma general de la que @ref emit_ir_unop y @ref emit_ir_binop son
     * los dos casos comunes: reserva el valor de salida, arma la instruccion y
     * la emite.  Existe porque hay operaciones que no son de uno ni de dos
     * operandos -- buscar un simbolo en una biblioteca toma tres -- y sin ella
     * esas se quedaban escritas a mano por no caber en la forma corta.
     *
     * @param op          Que operacion.
     * @param operands    Sus operandos, en orden.
     * @param t           Tipo del resultado.
     * @param source_line Linea fuente, para la depuracion.
     * @return El valor SSA con el resultado.
     */
    ir::IrValueId emit_ir_op(ir::IrOp op, std::vector<ir::IrValueId> operands,
                             ir::IrType t, uint32_t source_line);

    /**
     * @brief Emite una operacion de UN operando del IR.
     *
     * El caso mas comun es reinterpretar los bits: los mismos ocho bytes
     * leidos como entero o como numero con decimales.  Ahi el tipo del
     * resultado ES la operacion -- no se convierte nada, se cambia con que
     * ojos se mira --, y por eso va explicito.
     *
     * @param op          Que operacion.
     * @param a           El operando.
     * @param t           Tipo del resultado.
     * @param source_line Linea fuente, para la depuracion.
     * @return El valor SSA con el resultado.
     */
    ir::IrValueId emit_ir_unop(ir::IrOp op, ir::IrValueId a, ir::IrType t,
                               uint32_t source_line);

    /// @brief Escribe un texto conocido al compilar.  Vacio no emite nada.
    void emit_print_string_literal(const std::string &text,
                                   uint32_t source_line);
    /** @} */

    /**
     * @brief Vuelca el resultado de una ejecucion comptime como constantes.
     *
     * El valor ES el bloque de memoria que dejo la ejecucion, asi que se copia
     * entero, por palabras, y se escribe en el buffer destino como
     * CONSTANTES.  En el binario no queda ni la llamada ni el codigo que la
     * calculo: solo los valores.
     *
     * NO se recorren los campos a proposito: mirar la estructura obliga a
     * resolver uniones (varias vistas de los mismos bytes), anidamiento y
     * relleno, y nada de eso cambia lo que hay que copiar.
     *
     * Es el unico sitio que hace esta conversion, para que no acabe repartida
     * entre cada llamante con sus propias reglas.
     *
     * @param bytes Resultado en bruto de la ejecucion.
     * @param layout Tipo al que corresponden esos bytes.
     * @param v_dst Buffer destino.
     * @param source_line Linea a la que atribuir las instrucciones.
     * @return false si el tipo contiene una direccion: un puntero calculado al
     *         compilar apunta a memoria del compilador y no se puede
     *         trasladar.
     */
    bool materialize_comptime_bytes(const std::vector<uint8_t> &bytes,
                                    const StructLayout &layout,
                                    ir::IrValueId v_dst, uint32_t source_line);

    /**
     * @brief Emite GETPROC y devuelve el SSA value (PTR al ProcessVM).
     *        Usado por las variantes GC-aware de las colecciones (cada
     *        variante @c *_gc del plugin recibe @c proc como primer arg
     *        para poder invocar @c gc_addref / @c gc_release sobre los
     *        slots que contienen GcHandles).
     */
    ir::IrValueId emit_getproc(uint32_t source_line);

    /**
     * @brief emite la secuencia ALLOCA + GETPROC +
     * CALLN(native_fn) + STRMAKE para convertir un valor primitivo
     * a string (StringObject GcHandle).
     *
     * Usado por interpolacion `${val}` y por los builtins `to_str`,
     * `chr`, `ord` que se aliasan al runtime path.  El @c native_fn
     * (e.g. "vio_int_to_vmbuf", "vstr_chr_to_vmbuf") debe respetar
     * la firma `(proc_ptr, vm_addr, value) -> length`.
     *
     * @param v_val      SSA value del valor primitivo a stringificar.
     * @param native_fn  Nombre de la funcion native en vesta_io.
     * @param source_line Linea para diagnostico.
     * @return GcHandle del StringObject resultante.
     */
    ir::IrValueId stringify_primitive_via_native(ir::IrValueId v_val,
                                                 const char *native_fn,
                                                 uint32_t source_line);

    /**
     * @brief  MC.17.2 -- obtiene (o aloca) el slot @c static_data
     * que materializa un comptime global como memoria runtime para
     * macros lowereados.  Ver @c comptime_global_slots_.
     *
     * @return idx valido o @c UINT64_MAX si el global no es int
     *         (strings/structs no soportados en v1).
     */
    uint64_t get_or_create_comptime_global_slot(const std::string &name);

    /**
     * @brief L2.2: allocate a slot en static_data para una variable
     * global runtime no-const.  El slot guarda el valor (i64-encoded:
     * GcHandle para STRING, valor escalar para i64/u64/etc.).
     *
     * Idempotente: si ya existe slot para @p name lo devuelve.
     * Init: el slot empieza zero-filled; @c __module_init lo inicializa.
     */
    uint64_t get_or_create_runtime_global_slot(const std::string &name,
                                               uint64_t bytes = 8);

    /**
     * @brief Slot del storage de un global IMPORTADO de otro modulo.
     *
     * El consumidor no ve el AST del dep, asi que crea su propio slot con el
     * nombre del dep (`lib__counter`) como clave: el slot lleva ese nombre en
     * @c StaticDataMeta::shared_key y el merge cross-module unifica todas las
     * entries con la misma clave en UNO -- el modulo que define el global y los
     * que lo usan comparten storage.
     *
     * Solo aplica a los globals que NO se inlinean (mutables, y const cuyo
     * valor no se conoce en compile time como un `const string`).
     *
     * @param mangled_label nombre del slot en el modulo que lo define.
     * @param t             tipo declarado (fija el tamano del slot).
     * @return indice del slot en @c static_data.
     */
    uint64_t shared_global_slot_for(const std::string &mangled_label,
                                    const Type &t);

    /**
     * @brief Si @p name es un global importado con storage, garantiza que
     *        @c runtime_global_slots_ lo mapea a su slot compartido.
     *
     * Con el alias registrado, las rutas de lectura/escritura/`&` del ident
     * tratan al global importado igual que a uno propio.  Idempotente.
     *
     * @return true si @p name es (o ya era) un global con slot.
     */
    bool ensure_imported_global_slot(const std::string &name);

    /**
     * @brief Si @p e es `ns.G` sobre un global importado CON storage, devuelve
     *        true y deja en @p out_slot su slot compartido.
     *
     * Falso para el resto (campo de struct/clase, constante inlineable, metodo
     * estatico): esos siguen su ruta normal.
     */
    bool imported_global_slot_of(ast::FieldAccessExpr *e, uint64_t &out_slot);

    /**
     * @brief Reserva el slot de la PLANTILLA de un `thread_local` (TLS).
     *
     * El slot lleva la plantilla por-hilo (bytes de inicializacion estaticos,
     * NO via @c __module_init), marcado @c SD_FLAG_TLS + seccion @c .tdata
     * (SHF_TLS).  El codegen AOT lo emite en una seccion TLS y el acceso usa
     * el thread pointer (fs/gs + TPOFF) en vez de una direccion lineal.
     *
     * @param name   nombre del global.
     * @param bytes  tamano de la variable (>=1).
     * @param init_value valor inicial empaquetado LE (los primeros 8 bytes).
     */
    uint64_t get_or_create_tls_global_slot(const std::string &name,
                                           uint64_t bytes, uint64_t init_value,
                                           uint16_t alignment);

    /**
     * @brief Inserta una conversion de tipo si difiere; identidad si igual.
     *
     * @param is_explicit Si false (por defecto), emite un warning cuando
     *        la conversion es potencialmente perdida (narrowing,
     *        float<->int, etc.).  Las llamadas desde @c lower_cast_expr
     *        pasan true para silenciar el warning porque el usuario
     *        opto explicitamente por el cast.
     */
    ir::IrValueId cast_if_needed(ir::IrValueId v, ir::IrType from,
                                 ir::IrType to, uint32_t source_line,
                                 bool is_explicit = false);
    /**
     * @brief Igual que el anterior pero con el @c SourceLoc completo de la
     *        expresion culpable, para que el warning de conversion apunte a su
     *        COLUMNA real (no al inicio de la linea).  El overload de
     *        @c source_line delega en este con columna 1.
     */
    ir::IrValueId cast_if_needed(ir::IrValueId v, ir::IrType from,
                                 ir::IrType to, const SourceLoc &loc,
                                 bool is_explicit = false);

    // -----------------------------------------------------------------
    // Lowering por categoria.
    // -----------------------------------------------------------------

    void lower_function(ast::FunctionDecl *fd, ir::IrModule &out);

    /**
     * @brief Lowering de funciones marcadas con @Async.
     *
     * Genera DOS funciones IR a partir de la `FunctionDecl @Async`:
     *
     *   1. Wrapper publico con el nombre original (`fd->name`):
     *      - alloca un Future via @c future_alloc()
     *      - spawnea un child con la funcion sintetica `__async_<name>`
     *      - msgsend(child, fut_handle)
     *      - return fut_handle (i64)
     *
     *   2. Spawn helper sintetica `__async_<name>`:
     *      - msgrecv() -> handle del Future en SSA value (`async_fut_id_`)
     *      - body lowered del usuario; cada `return X` se intercepta en
     *        @c lower_return: emite `fulfill(async_fut_id_, X) + hlt`
     *        en lugar de RET.
     *      - Si el body cae naturalmente sin return: emite
     *        `fulfill(async_fut_id_, 0) + hlt` al final.
     *
     * El usuario llama `i64 fut = fn(); i64 r = await fut;` con la
     * misma firma que el wrapper expone.
     */
    void lower_async_function(ast::FunctionDecl *fd, ir::IrModule &out);
    void lower_block(ast::BlockStmt *b);
    void lower_stmt(ast::Stmt *s);
    void lower_var_decl(ast::VarDeclStmt *vd);
    /// Baja un `static T x = init;` local: registra el slot global (gdata)
    /// mangleado por funcion, lo apunta desde @c static_local_slots_ y emite
    /// el init-once (horneado en gdata si el init es constante, o guardado con
    /// un booleano global si es dinamico).
    void lower_static_local(ast::VarDeclStmt *vd, const Type &sem_type);
    void lower_if(ast::IfStmt *s);
    void lower_return(ast::ReturnStmt *s);
    void lower_while(ast::WhileStmt *s);
    /// Auto-vectorizacion (idioma memcpy): si @p s es exactamente el patron
    /// de copia de bytes/elementos `while (i < N) { dst[i] = src[i]; i++; }`
    /// sobre punteros HOST, lo reemplaza por un unico @c MEMCPY (el JIT/AOT lo
    /// bajan a @c rep @c movsb / SIMD; el interprete a un bucle host->host).
    /// Devuelve true si reconocio y bajo el idioma (el llamante debe @c
    /// return); false si no matchea (seguir con el lowering normal del while).
    bool try_lower_memcpy_idiom(ast::WhileStmt *s);
    /// Igual para @c for(T i=init; i<N; i++) dst[i]=src[i]; (la forma canonica
    /// del memcpy).  Cubre el for que DECLARA la var del loop en @c init
    /// (loop-local), evitando el writeback de scope post-loop.
    bool try_lower_memcpy_idiom_for(ast::ForStmt *s);
    /// Auto-vectorizacion aritmetica: @c for(T i=init; i<N; i++) c[i]=a[i] OP
    /// b[i]; con a/b/c punteros f64 HOST y OP in {+,-,*,/}.  Emite un loop
    /// principal que procesa W=2 elementos por iteracion via @c VEC_BINOP
    /// (SIMD packed en JIT/AOT, escalar por lane en interp) + una cola escalar
    /// re-bajando el cuerpo para el resto (N % W).  Devuelve true si matcheo.
    bool try_vectorize_elementwise_for(ast::Stmt *s);
    /// Auto-vectorizacion de DIFUSION ESCALAR (scalar broadcast):
    /// @c for(T i=init; i<N; i++) c[i] = a[i] OP scalar; con @c c/@c a punteros
    /// f64 HOST y @c scalar un valor f64 invariante del loop.  Tambien la forma
    /// conmutativa @c scalar OP a[i] (add/mul) y el compound @c c[i] OP=
    /// scalar. El escalar se difunde a todos los lanes (UNPCKLPD/VBROADCASTSD)
    /// en JIT/ AOT, escalar por lane en interp.  Devuelve true si matcheo.
    bool try_vectorize_scalar_for(ast::Stmt *s);
    /// Auto-vectorizacion UNARIA: @c for(T i=init; i<N; i++) b[i] = OP a[i];
    /// con @c a/@c b punteros f64 HOST y OP in @c -a[i] (fneg), @c sqrt(a[i])
    /// (fsqrt), @c fabs(a[i]) (fabs).  Loop principal W=2 con @c VEC_UNOP (SIMD
    /// packed SQRTPD/XORPD/ANDPD en JIT/AOT, escalar por lane en interp) + cola
    /// escalar.  La copia pura la cubre el memcpy-idiom.  Devuelve true si
    /// match.
    bool try_vectorize_unary_for(ast::Stmt *s);
    /// Auto-vectorizacion de REDUCCION: @c for(T i=init; i<N; i++) acc = acc +
    /// a[i]; con @c acc escalar f64 y @c a puntero f64 HOST.  Usa un acumulador
    /// vectorial de W=2 lanes (slot host 16B) acumulado con @c VEC_BINOP
    /// (acc_slot += a_chunk), reduccion horizontal final + cola escalar.  El
    /// resultado se bindea a @c acc.  Devuelve true si matcheo.
    bool try_vectorize_reduction_for(ast::Stmt *s);
    /// Auto-vectorizacion COMPOUND (cadena lineal multi-op): @c for(...) c[i] =
    /// a[i] OP1 x OP2 y OP3 ... donde cada operando derecho (x, y, ...) es
    /// @c arr[i] (host, mismo tipo) o un escalar invariante f64, y la expresion
    /// es left-leaning `((a OP1 x) OP2 y) ...` (precedencia natural de
    /// @c a[i]*k + b[i]).  Emite el loop principal usando @c c como acumulador:
    /// @c c = a OP1 x ; @c c = c OP2 y ; ... (cadena de @c VEC_BINOP /
    /// @c VEC_BINOP_S por chunk) + cola escalar.  Solo f64/f32.  Cubre el
    /// patron axpy/FMA que los matchers de 1-op no aceptan.  Devuelve true si
    /// matcheo.
    bool try_vectorize_compound_for(ast::Stmt *s);
    /// Valida que @p asg sea exactamente @c dst[idx] = src[idx] con bases
    /// IdentExpr HOST ptr/array de igual tamano de elemento.  Compartido por
    /// las formas while/for.  Rellena las bases y el tamano de elemento.
    bool mc_match_copy_assign(ast::AssignExpr *asg, const std::string &idx_name,
                              ast::IdentExpr **out_dst,
                              ast::IdentExpr **out_src, size_t *out_esz);
    /// Emite el MEMCPY equivalente a la copia en @c current_block_.  @p v_idx
    /// es el SSA del indice inicial (ya resuelto por el llamante: lookup para
    /// el while, lower del init para el for).  Si @p idx_name_for_post no esta
    /// vacio, ademas escribe el idx post-loop = idx_init+count en ese nombre de
    /// scope (solo el while con idx externa lo necesita).  Devuelve false si
    /// @p v_idx no es un entero o si algun lower_expr fallo (defensivo).
    bool mc_emit_copy(ir::IrValueId v_idx, ast::Expr *limit,
                      ast::IdentExpr *dst_base, ast::IdentExpr *src_base,
                      size_t esz, uint32_t ln,
                      const std::string &idx_name_for_post);
    void lower_do_while(ast::DoWhileStmt *s);
    void lower_for(ast::ForStmt *s);
    void lower_try(ast::TryStmt *s);
    void lower_throw(ast::ThrowStmt *s);
    void lower_foreach(ast::ForEachStmt *s);
    void lower_synchronized(ast::SynchronizedStmt *s);
    void
    lower_asm(ast::AsmStmt *s); ///<  AS: baja a IrOp::INLINE_ASM (marker host).

    ir::IrValueId lower_expr(ast::Expr *e);
    ir::IrValueId lower_binary(ast::BinaryExpr *e);
    ir::IrValueId lower_unary(ast::UnaryExpr *e);
    ir::IrValueId lower_call(ast::CallExpr *e);
    ir::IrValueId lower_ident(ast::IdentExpr *e);
    ir::IrValueId lower_string_lit(ast::StringLitExpr *e);
    ir::IrValueId lower_assign(ast::AssignExpr *e);
    ir::IrValueId
    lower_ternary(ast::TernaryExpr *e); ///< A.38: cond ? then : else
    ir::IrValueId lower_field_access(ast::FieldAccessExpr *e);
    ir::IrValueId lower_index(ast::IndexExpr *e);

    /**
     * @brief Lowering de @c spawn @c { @c body @c }.
     *
     * Genera una funcion sintetica de nombre @c __spawn_<N>(void) que
     * contiene el body, terminada con @c hlt (no @c ret) porque los
     * procesos hijo terminan, no retornan.  En el sitio del spawn,
     * emite @c mov @c rN, @c @Absolute("code.__spawn_N") + @c spawn @c rN
     * y captura el PID encoded del hijo (que el opcode deposita en R0).
     *
     * @return SSA value con el PID encoded del hijo (i64).
     */
    ir::IrValueId lower_spawn_expr(ast::SpawnExpr *e);

    /**
     * @brief Genera la funcion sintetica del body de un @c spawn.
     *
     * Compila @p body como funcion top-level con nombre
     * @c __spawn_<N> donde N es @c spawn_func_counter_++.  Termina
     * con @c hlt.  La nueva @c IrFunction se agrega al modulo via
     * @c out_mod_->add_function.
     *
     * @return Nombre de la funcion generada (para usar en @c @Absolute).
     */
    std::string generate_spawn_helper(ast::BlockStmt *body,
                                      const SourceLoc &loc);

    /**
     * @brief Baja `c++` / `c--` sobre un tipo que SOBRECARGA la suma.
     *
     * `c++` es `c += 1`: fabrica ese compound y deja que el type checker lo
     * resuelva (`__iadd__` in-place, o desazucarado a `c = c + 1`).  Va antes
     * que las rutas enteras porque el valor SSA de un struct es su DIRECCION:
     * la ruta entera le sumaba 1 a la direccion del objeto.
     *
     * @param is_inc `++` (true) o `--`; @param is_pre prefijo (true) o
     * postfijo.
     */
    ir::IrValueId lower_overloaded_step(ast::UnaryExpr *e, bool is_inc,
                                        bool is_pre);

    /**
     * @brief lowering de @c rspawn(node) { body }.
     *
     * Genera helper @c __rspawn_<N> con `is_rspawn_body_=true` (cualquier
     * @c return X dentro del body se intercepta -> @c mov r0, X + hlt).
     * En el caller emite la instruccion bytecode @c rspawn r_fn, r_node y
     * captura R0 al SSA value (GcHandle del Future).
     *
     * @return SSA value con el GcHandle del Future (i64).
     */
    ir::IrValueId lower_rspawn_expr(ast::RSpawnExpr *e);

    /**
     * @brief genera la funcion sintetica del body de un @c rspawn.
     *
     * Identico a @c generate_spawn_helper salvo por el flag
     * @c is_rspawn_body_ activado durante el lowering del body.  El name
     * es @c __rspawn_<N>.
     */
    std::string generate_rspawn_helper(ast::BlockStmt *body,
                                       const SourceLoc &loc);

    /**
     * @brief closures: lowering de una @c LambdaExpr inline.
     *
     * Pipeline de tres fases:
     *   1. Genera la funcion sintetica @c __lambda_<N> via
     *      @c generate_lambda_helper, que toma los params declarados
     *      como parametros normales y los captures como prologue
     *      implicito que carga desde @c R14 + offset.
     *   2. Aloca un env block en la pila del caller (@c subsp rsp,
     *      8*nCaptures) y escribe los valores capturados ahi.  Si la
     *      lambda no captura nada (n=0), env_addr = 0 (sentinela).
     *   3. Aloca un slot de 16 bytes para el "function value" tipo
     *      @c fn(T) -> R: `[+0 fn_addr][+8 env_addr]`.  Devuelve el
     *      SSA value con la direccion de ese slot.
     *
     * Coste: con N captures, la creacion de la closure cuesta:
     *   - 1 ALLOCA de @c 8*N bytes (env block)
     *   - N STOREs (un qword por captura)
     *   - 1 ALLOCA de 16 bytes (function value slot)
     *   - 1 RAW_ASM @c mov rN, @c \@Absolute(label)
     *   - 2 STOREs (fn_addr + env_addr en el slot)
     * Total: ~5 + 2N instrucciones bytecode.  Cero allocaciones de
     * heap; cero overhead GC.
     *
     * Limitacion MVP: el env vive en la pila del caller, asi que la
     * closure solo es valida dentro del scope que la creo.  Para
     * closures que escapen (e.g. devolver una closure de una funcion)
     * habra que detectar el escape y promover el env a heap GC.
     *
     * @return SSA value con la direccion del function value (16 bytes).
     */
    ir::IrValueId lower_lambda_expr(ast::LambdaExpr *e);

    /**
     * @brief construye un function value (16 bytes) que
     *        apunta a una funcion top-level con env_addr=0.
     *
     * Mismo layout que @c lower_lambda_expr (slot de 16 bytes en
     * stack: fn_addr en +0, env_addr en +8) pero @c fn_addr es
     * @c @Absolute("code.<fn_name>") y env_addr es la constante 0.
     * Permite pasar funciones declaradas en top-level como argumento
     * a parametros tipados @c fn(...) -> ... sin requerir el wrapping
     * manual a una lambda local.
     *
     * @param fn_name Nombre de la funcion top-level.
     * @param line    Linea fuente para diagnostico.
     * @return SSA value PTR con la direccion del slot de 16 bytes.
     */
    ir::IrValueId emit_topfn_value(const std::string &fn_name, int line);

    /**
     * @brief Promueve un string literal a @c StringObject GC-managed.
     *
     * Emite la secuencia: STR_LIT_ADDR -> SSA value PTR; CONST(len) ->
     * SSA value I64; RAW_ASM "strmake {dst}, {src0}, {src1}" -> SSA
     * value I64 (GcHandle).  El handle se devuelve y puede bindearse
     * a una variable de tipo @c string.  Cero overhead vs el modelo
     * antiguo cuando NO se promueve (literal sigue siendo PTR puro).
     *
     * @param slit  Literal de string sin interpolacion.
     * @return SSA value I64 con el GcHandle del StringObject.
     */
    ir::IrValueId
    lower_string_literal_to_string_object(ast::StringLitExpr *slit);

    /**
     * @brief closures: genera la @c IrFunction sintetica para
     *        el body de una lambda.
     *
     * El helper se llama @c __lambda_<N> donde N es @c lambda_counter_++.
     * Su firma es la de la lambda (mismos params), pero el body lleva
     * un prologue que carga cada captura desde @c [r14 + 8*i] a un
     * SSA value local con el nombre del capture.  De esa forma el
     * resto del body (que el type checker validO referencias a
     * capturas como si fueran locales) puede usar las capturas
     * naturalmente sin distinguirlas de los params.
     *
     * Reusa el mismo patron de save/restore de scope que
     * @c generate_spawn_helper.
     *
     * @return Nombre del helper generado (para @c \@Absolute).
     */
    std::string generate_lambda_helper(ast::LambdaExpr *e);

    /**
     * @brief Overlay F3: sintetiza (una vez) la funcion resolvedora del offset
     *        de bloque de un campo -- `__ovl_resolve_<Struct>_<campo>(self)`.
     *
     * El body es el `@offset { ... }` del campo, lowered con `base` (= @c self)
     * y los campos hermanos ligados como locales; `return <dir>` se vuelve el
     * RET de la funcion.  Reusa TODO el control de flujo (if/else, multiples
     * return) sin ALLOCA-en-bucle; el optimizer puede inlinearla.  Devuelve el
     * nombre; @c generated_overlay_resolvers_ evita duplicados.
     */
    std::string generate_overlay_resolver(const StructLayout &lay,
                                          const StructFieldInfo &fi,
                                          bool is_element = false);
    /// Nombres de resolvedores de overlay ya sintetizados (dedup).
    std::unordered_set<std::string> generated_overlay_resolvers_;
    /// La cadena de aspectos de cada metodo, EN ORDEN, por nombre IR
    /// (`Clase__metodo`).  Se recoge al principio de @c run() porque cada sitio
    /// de llamada la consulta para decidir si puede devirtualizar/especular:
    /// llamar directo a un metodo con aspectos se saltaria su cadena.
    std::unordered_map<std::string, std::vector<ir::IrModule::ChainedAdvice>>
        advice_chains_;
    /// A que llama el `proceed()` de cada `@Around`, por nombre IR: el
    /// siguiente `@Around` de su cadena, o el metodo si es el mas interno.
    /// Vacio para todo lo que no sea un `@Around`.
    std::unordered_map<std::string, std::string> proceed_target_;
    /// Falso si algun aspecto no se pudo atribuir a un metodo concreto; se
    /// vuelve entonces al criterio ancho (ningun sitio se devirtualiza).
    bool all_advices_attributed_ = true;
    /**
     * @brief `extent(v)`: sintetiza `__ovl_extent_<S>(self) -> u64` que computa
     * el SPAN total del layout de la vista con los datos de la instancia
     *        (max(fin de campo) - base).  Cubre escalares (offset const/expr/
     *        block) + arrays de stride CON count; salta arrays sin count y
     *        @element (variable) y resolvers que usan parent<T>().  Devuelve el
     *        nombre de la funcion (dedup via @c generated_overlay_resolvers_).
     */
    std::string generate_overlay_extent(const StructLayout &lay);
    /**
     * @brief F4: baja el puntero de la vista RAIZ de una cadena de accesos
     *        overlay.  Camina @c e por sus bases (FieldAccess/Index) hasta la
     *        expresion que ya no es un acceso a campo/elemento (la vista raiz,
     *        p.ej. `pe` en `pe.Imports[i].name`) y la baja con @c lower_expr.
     *        Es el `root` que se enhebra a un resolver que usa `parent<T>()`.
     */
    ir::IrValueId lower_overlay_root(ast::Expr *e);
    /**
     * @brief Merge SSA N-vias tras un `match` (Braun): inserta PHIs en @c
     * merge_bb para cada variable del scope enclosing que quedo con SSA values
     *        DISTINTOS entre los arms que alcanzan el merge, y rebindea el
     * nombre al PHI.  Sin esto, una variable ASIGNADA (no `return`) dentro de
     * un arm se quedaba con el valor del ULTIMO arm bajado.  @c arm_scopes /
     *        @c arm_preds / @c arm_reaches son paralelos (uno por arm; solo
     * cuentan los que @c arm_reaches[i]==true).  Deja @c scopes_ listo en el
     * merge.
     */
    void emit_match_arm_phis(
        const std::vector<std::unordered_map<std::string, ir::IrValueId>>
            &entry_scopes,
        const std::vector<
            std::vector<std::unordered_map<std::string, ir::IrValueId>>>
            &arm_scopes,
        const std::vector<ir::IrBlockId> &arm_preds,
        const std::vector<char> &arm_reaches, ir::IrBlockId merge_bb,
        uint32_t line);
    /**
     * @brief F5: aplica el swap de endianness `@endian(expr)` a @c value (un
     *        entero de 2/4/8 bytes recien leido/por escribir).  Evalua la expr
     *        de endianness del campo @c fi (con los campos hermanos de @c lay
     *        ligados desde la base de la vista @c base_expr) -> `big`; devuelve
     *        `big ? bswap(value) : value` (select sin ramas; comptime se
     * pliega). Simetrico: sirve para read y para write.
     */
    ir::IrValueId emit_overlay_endian_swap(ast::Expr *base_expr,
                                           const StructLayout &lay,
                                           const StructFieldInfo &fi,
                                           ir::IrValueId value, uint32_t line);

    /**
     * @brief ADTs: lowering de un constructor de variante de
     *        enum (`Color.Green(42)` o `Color.Red`).
     *
     * Estrategia:
     *   1. Aloca un slot en pila del caller con
     *      @c size_bytes = 8 + 8*max_payload_fields del enum.  Igual
     *      que para structs, usamos ALLOCA del IR -> @c subsp rsp, N.
     *   2. STORE i64 del @c tag en offset 0.
     *   3. Para cada payload arg: STORE i64 del valor en offset
     *      @c 8 + 8*i.  El valor se promociona a i64 si es mas
     *      estrecho (uniformidad del slot).
     *   4. Devuelve el SSA value con la direccion del slot (PTR).
     *
     * El call site del lowering reconoce este patron mirando
     * @c FieldAccessExpr::property_kind == 99 (marcado por el type
     * checker).  Para variantes sin payload se entra con
     * @c CallExpr::args vacio o directamente desde un FieldAccessExpr.
     *
     * @param enum_name      Nombre del enum (e.g. "Color").
     * @param variant_name   Nombre de la variante (e.g. "Green").
     * @param args           Args del CallExpr (vacio si sin payload).
     * @param loc            Para diagnosticos / metadata IR.
     * @return SSA value PTR al slot del enum recien construido.
     */
    ir::IrValueId
    lower_enum_constructor(const std::string &enum_name,
                           const std::string &variant_name,
                           const std::vector<std::unique_ptr<ast::Expr>> &args,
                           const SourceLoc &loc);

    /**
     * @brief ADTs: lowering de un @c MatchExpr.
     *
     * Estrategia:
     *   1. Lower del scrutinee -> SSA value PTR al slot del enum.
     *   2. LOAD i64 del tag (offset 0).
     *   3. Construye en stack una jumptable: array de @c uint64
     *      (8 bytes/entry) con la direccion de cada arm en orden de
     *      tag.  Para variantes no cubiertas en el match, la entry
     *      es la direccion del arm @c _ (default) o la de la
     *      siguiente instruccion tras el match (fall-through) si no
     *      hay default.
     *   4. RAW_ASM @c jumptable r_tag, r_table, count -> dispatch O(1).
     *   5. Para cada arm: emite un nuevo IrBlock que (a) lee los
     *      payloads del slot del scrutinee como SSA values nuevos,
     *      (b) los bindea con los nombres del patron, (c) lowers el
     *      body, (d) salta al merge_block.
     *   6. merge_block: continuacion tras el match.
     *
     * MVP simplificado: en lugar de @c jumptable bytecode (que
     * requiere ALLOCA + escritura de la tabla en stack + cuidado
     * con relocations), usamos una cadena de @c cmp + @c jmp.jeq al
     * label de cada arm.  Es O(N) en el numero de variantes pero
     * mas simple y robusto para empezar.  Optimizacion a jumptable
     * 0x27 queda como mejora futura (importante para enums grandes).
     *
     * @return @c IR_NO_VALUE (match es statement-like en MVP).
     */
    ir::IrValueId lower_match_expr(ast::MatchExpr *e);
    /// match sobre ESCALARES (enteros/chars), estilo switch.  Dispatch
    /// eficiente: SWITCH_DENSE (O(1)) si los casos son densos, BST balanceado
    /// (O(log N)) si dispersos, cadena lineal si pocos o con guards.
    /// Statement-like (VOID); el valor se produce con `return` en cada arm.
    ir::IrValueId lower_match_scalar(ast::MatchExpr *e);
    /// match sobre STRINGS.  Hiper-eficiente: computa el hash del scrutinee
    /// (STRHASH) una vez, despacha por los hashes de los literales (calculados
    /// en compile-time, mismo FNV-1a 32-bit que el runtime) via dispatch entero
    /// (BST O(log N) / lineal), y en el candidato hace UN STRCMP de
    /// verificacion (colisiones).  Tipico: 1 hash + 1 strcmp, no N
    /// comparaciones.
    ir::IrValueId lower_match_string(ast::MatchExpr *e);

    /**
     * @brief Lower @c CastExpr `(T) operand`.
     *
     * Casos cubiertos:
     *  - num <-> num (primitivos): delega en @c cast_if_needed.
     *  - PTR <-> PTR (incluyendo @c VirtualPtr<X> <-> @c X*): bitcast,
     *    el valor SSA mantiene el bit-pattern, pero @c is_host_ptr y
     *    @c pointee_is_host_ptr se ajustan al destino para que LOAD
     *    y STORE posteriores emitan @c mov vs @c movh segun la
     *    naturaleza del destino.
     *  - PTR <-> int (i64/u64) y viceversa: BITCAST IR op (preserva
     *    bits sin conversion numerica).
     *  - ARRAY -> PTR: decay (mismo bit-pattern); ARRAY <-> ARRAY:
     *    bitcast con propagacion de @c is_host_ptr.
     */
    ir::IrValueId lower_cast_expr(ast::CastExpr *e);

    // -----------------------------------------------------------------
    // POO: clases, new, this, getfield/setfield/callvirt sobre CLASS.
    // -----------------------------------------------------------------

    /**
     * @brief Compila los metodos de una clase como funciones IR
     *        independientes con nombre @c <Class>__<method> y un
     *        primer parametro implicito @c this de tipo PTR.
     *
     * Ademas registra en out_module la metadata necesaria para que
     * el module init pueda llamar @c defmethod con la direccion del
     * metodo (via label).
     */
    void lower_class_methods(ast::ClassDecl *cd, ir::IrModule &out);

    /**
     * @brief Baja los metodos de un struct a funciones libres.
     *
     * Cada metodo @c m del struct @c sd produce una @c IrFunction
     * @c <Struct>__<metodo> con un primer parametro implicito @c this
     * (PTR a la direccion del buffer del struct, memoria VM por
     * defecto -- @c is_host_ptr=false).  El dispatch en el call site
     * es CALL directo (sin vtable).  Soporta SRET (Optional/Result)
     * con retbuf hidden tras @c this, igual que las funciones libres.
     */
    void lower_struct_methods(ast::StructDecl *sd, ir::IrModule &out);

    /**
     * @brief NS.6-ext: baja los metodos de @c "extension Tipo { ... }" e
     * @c "impl Concept for Tipo { ... }" como funciones libres
     * @c <clave_layout>__<metodo> (dispatch estatico).  Reusa la emision de
     * @c lower_struct_methods via un @c StructDecl temporal; para targets
     * CLASE se activa @c ext_this_is_class_ para ligar @c this como objeto GC.
     */
    void lower_extension_methods(ir::IrModule &out);
    /// NS.6-ext: cuando @c true, @c lower_struct_methods liga @c this como
    /// host_ptr + objeto GC (target de una extension que es una CLASE).
    bool ext_this_is_class_ = false;

    /**
     * @brief Genera el bloque @c __module_init que registra todas las
     *        clases del modulo.  Se invoca al inicio de @c main.
     *
     * Construye la cadena RAW_ASM con la secuencia
     * @c findclass / @c defclass / @c deffield / @c defmethod usando
     * convenciones de registro fijas (r12-r15 reservados).  Los
     * nombres de clase/field/method se registran como bytes estaticos
     * via @c IrModule::intern_static_data.
     */
    std::string build_module_init_asm(ir::IrModule &out_module);

    /**
     * @brief Lower de @c new ClassName(args) -> CALL a la funcion
     *        auxiliar @c __new_<ClassName> generada por el frontend.
     *        Esa funcion encapsula findclass + newobj + callvirt 0.
     */
    ir::IrValueId lower_new_expr(ast::NewExpr *e);

    /**
     * @brief Genera la IrFunction auxiliar @c __new_<Class>(args) para
     *        cada clase declarada en el modulo y la añade a out.
     *        El cuerpo es un bloque RAW_ASM con findclass + newobj +
     *        callvirt 0 (ctor) + return GcHandle.
     */
    void generate_new_helpers(ir::IrModule &out);
    /// Emite, dentro del destructor del contenedor, la liberacion del env
    /// (RAW_ALLOC host) de un campo closure: `env = [this+offset+8]; if (env)
    /// RAW_FREE(env)`.  Modelo de ownership sin GC (el closure-en-campo se
    /// libera con su objeto, como un campo @c unique<T>).
    /// @param this_vid  SSA value del receptor (`this`, host_ptr al objeto).
    /// @param field_offset  Offset del campo closure (inicio del slot 16B).
    /// @param line  Linea fuente para la depuracion.
    void emit_free_closure_env_field(ir::IrValueId this_vid,
                                     uint32_t field_offset, uint32_t line);
    /// Libera el @c unique<T> almacenado en un campo del contenedor al exit del
    /// scope (ownership, sin GC): el campo guarda la direccion del slot Tier 1
    /// (16B [ptr][deleter]); cargamos el slot, y si != 0 dispatchamos el
    /// deleter dinamico (slot+8): deleter==0 -> RAW_FREE(ptr); !=0 -> CALLIND
    /// deleter(ptr).  Ops explicitas (universales en interp/JIT/AOT).
    /// @param this_vid  SSA value del receptor (host_ptr al contenedor).
    /// @param field_offset  Offset del campo @c unique<T> (8B, guarda el slot).
    /// @param line  Linea fuente.
    /// @param deleter  Nombre de quien libera, sacado del TIPO del campo.  Es
    ///                 lo que permite emitir una llamada DIRECTA en vez de
    ///                 leer una direccion de la ranura y saltar a ella.
    void emit_free_unique_field(ir::IrValueId this_vid, uint32_t field_offset,
                                const std::string &deleter, uint32_t line);
    /// Invoca un metodo de struct (`<Struct>__<m>`) sobre un struct que vive en
    /// un campo HOST (p.ej. campo struct de una clase, cuyo payload es host).
    /// Los metodos de struct se compilan asumiendo `this` en memoria VM
    /// (interp/JIT); llamarlos con un `this` host hace que lean `this.campo`
    /// con `mov` (VM) sobre una direccion host -> basura.  En interp/JIT
    /// copiamos el campo a un temporal en VM-stack y llamamos el metodo sobre
    /// el temporal (lee `temp.campo` con VM correcto; los punteros internos son
    /// host y se deref-ean bien).  Valido para metodos que operan sobre los
    /// POINTEES (dtor: free del ptr; copy-hook: ++refcount via el ptr) sin
    /// necesidad de copy-back.  En AOT (native_poo_) el struct ya es host y el
    /// metodo host-this: CALL directo sobre @c field_addr.
    /// @param field_addr  host_ptr a la direccion del campo struct.
    /// @param struct_name  nombre del struct (para el tamano y el label).
    /// @param method_label  label del metodo (`<Struct>__<m>`).
    void emit_struct_method_on_host_field(ir::IrValueId field_addr,
                                          const std::string &struct_name,
                                          const std::string &method_label,
                                          uint32_t line);
    /// Copia memberwise (qword a qword) @p size_bytes desde @p src_addr a
    /// @p dst_addr.  Hereda la naturaleza host/VM de ambas direcciones para
    /// emitir mov/movh correctos.  Usado al copiar un agregado value-type
    /// (struct/array) -- e.g. inicializar un campo struct en un init-list.
    void emit_memberwise_copy(ir::IrValueId dst_addr, ir::IrValueId src_addr,
                              uint64_t size_bytes, uint32_t line);
    /// Rellena con CEROS @p size_bytes a partir de @p addr (STORE 0 en trozos
    /// de 8/4/2/1 bytes, sin desbordar).  Garantiza que todo struct/array en
    /// pila queda zero-inicializado por defecto (seguridad: nada de basura de
    /// la pila en campos no listados en el init).  @p addr es una direccion VM
    /// (ALLOCA); hereda su naturaleza para el STORE.
    void emit_zero_fill(ir::IrValueId addr, uint64_t size_bytes, uint32_t line);
    /// Copia @p size_bytes (redondeado a qword) de un valor ENUM desde
    /// @p src_addr (naturaleza @p src_is_host) al slot @p dst_addr.  Modelo
    /// value-type (mismo que un struct): la variable enum tiene un SLOT
    /// ESTABLE y la construccion/asignacion COPIA sus bytes, en lugar de
    /// repuntar el puntero (que rompia con asignaciones condicionales +
    /// `match` -- PHI de punteros de naturaleza mixta).
    void emit_enum_copy(ir::IrValueId dst_addr, ir::IrValueId src_addr,
                        bool src_is_host, uint64_t size_bytes, uint32_t line);
    /// Tamano del buffer SRET de BUFFER PLANO (enum / Optional / Result) que
    /// devuelve la fn @p callee, o 0 si no devuelve un SRET copiable.  Usado
    /// por el fix nested-SRET de @c lower_call para copiar el retbuf de una
    /// llamada anidada a un slot fresco (y no depender del slot fragil del
    /// productor cuando la presion de registros clobbea su registro).  @p
    /// out_is_host (si no es null) recibe la naturaleza que debe tener el slot
    /// fresco: false (VM-stack) para enum, true (host) para Optional/Result --
    /// debe coincidir con como el callee lee su parametro.
    uint64_t nested_sret_flat_size(const std::string &callee,
                                   bool *out_is_host = nullptr) const;
    /// Emite los valores por defecto de los campos de @p lay (los `u8 a =
    /// 0x10`) sobre el struct ya alocado y zero-inicializado en @p base_addr.
    /// Recurre en campos struct anidados que tengan defaults propios.  Se llama
    /// tras el zero-fill y ANTES del init-list explicito (que sobrescribe lo
    /// que toque).
    /// @p only_non_comptime: emitir SOLO los defaults que NO son
    /// comptime-evaluables (una referencia a funcion, un string).  Se usa
    /// cuando el struct ya se inicializo copiando una imagen construida en
    /// comptime -- que ya lleva los defaults escalares -- y solo faltan los
    /// que necesitan una direccion resuelta en tiempo de enlace.
    /// Transcodifica @p utf8 (la forma canonica de un literal) a @p enc y deja
    /// los bytes en @p out, NUL-terminados en el ancho de la codificacion.
    /// Devuelve false si la codificacion no es plegable en compile-time
    /// (ANSI: depende de la codepage de la maquina donde se EJECUTA) o si el
    /// texto no es representable (un no-ASCII en ENC_ASCII).
    static bool transcode_literal(const std::string &utf8, int enc,
                                  std::vector<uint8_t> &out);

    /// Interna un literal YA transcodificado como blob en memoria HOST y
    /// devuelve un SSA value con su direccion.  Cero coste en runtime: no hay
    /// STRMAKE, ni STRCONV, ni objeto GC.  Deduplica por (texto, encoding).
    ir::IrValueId emit_folded_string_blob(const std::string &utf8, int enc,
                                          uint32_t line);

    /// Literales alcanzables por nombre: `const string p = "x";` deja aqui
    /// (p -> "x") para que `str_cstr(p)` / `str_wstr(p)` se plieguen igual que
    /// con el literal directo.  SOLO `const`: el type checker garantiza que no
    /// se reasigna, asi que no hace falta analisis de mutacion.  Una `string`
    /// mutable no entra: haria falta saber que no se le asigna en ningun punto.
    std::unordered_map<std::string, std::string> const_str_locals_;

    /// Cache del plegado: (texto, encoding) -> indice de slot en static_data.
    std::map<std::pair<std::string, int>, uint64_t> folded_str_blobs_;

    void emit_struct_field_defaults(ir::IrValueId base_addr,
                                    const StructLayout &lay, uint32_t line,
                                    bool only_non_comptime = false);
    /// Rellena los campos de un struct YA alocado en @p base_addr desde el
    /// init-list @p il segun el layout @p lay.  RECURSIVO: un campo de tipo
    /// struct inicializado con un init-list ANIDADO (`{.min = {.x=..,.y=..}}`)
    /// se rellena in-place en la direccion del campo (lower_expr no baja un
    /// InitListExpr como valor).  Un campo struct/array inicializado con una
    /// EXPRESION (otra variable, llamada, ...) usa copia memberwise; un campo
    /// escalar usa STORE.  Comparte la logica del init-list de struct de
    /// @c lower_var_decl para que ambos caminos (top-level y anidado)
    /// coincidan.
    void emit_struct_init_fields(ir::IrValueId base_addr,
                                 const StructLayout &lay, ast::InitListExpr *il,
                                 uint32_t line);
    /// Materializa un struct cuyo valor fue calculado en compile-time.
    /// Cuando una funcion @c comptime devuelve un struct por valor, el
    /// resultado llega como un valor de compile-time con un campo por cada
    /// miembro
    /// (@c ComptimeEvalResult::struct_fields).  Este metodo aloca el buffer del
    /// struct y escribe cada campo con su valor constante (STORE), de forma que
    /// en el binario aparece el struct ya construido, sin llamada en tiempo de
    /// ejecucion.  Los campos de tipo struct se rellenan recursivamente.
    /// Devuelve la direccion del struct materializado.
    ir::IrValueId materialize_comptime_struct(const ComptimeEvalResult &r,
                                              const StructLayout &lay,
                                              uint32_t line);
    /// Rellena, sin alocar, los campos de un struct comptime en @p base_addr.
    /// Auxiliar recursivo de @c materialize_comptime_struct.
    void fill_comptime_struct_into(ir::IrValueId base_addr,
                                   const ComptimeEvalResult &r,
                                   const StructLayout &lay, uint32_t line);

    // --- F1b: constructor `comptime T(expr)` de un struct (literales de tipo
    // usuario).  Definidos en comptime/literal_ctor.cpp para no inflar
    // lowering.cpp (mismo patron que vectorize.cpp). ---

    /// @brief Nombre de la IrFunction de un ctor `comptime` de struct.
    ///
    /// Un ctor comptime se ejecuta en la ComptimeVM, asi que baja con el
    /// prefijo
    /// @c __macro_ (lo identifica como codigo comptime) sobre el mismo esquema
    /// de aridad que el ctor runtime: `__macro_<Struct>__ctor_<aridad>`.
    ///
    /// @param struct_name Nombre del struct.
    /// @param arity       Numero de parametros del constructor.
    /// @return El nombre mangled de la IrFunction del ctor comptime.
    std::string comptime_ctor_ir_name(const std::string &struct_name,
                                      size_t arity) const;

    /// @brief Intenta bajar `T(args)` como constructor `comptime` (F1b).
    ///
    /// Si @p slay tiene un ctor @c comptime cuya aridad casa con @p e, ejecuta
    /// el ctor en la ComptimeVM (@c invoke_struct_macro, convencion SRET donde
    /// el buffer de retorno ES el @c this del ctor) y materializa el struct
    /// como datos constantes (@c materialize_comptime_struct), sin llamada en
    /// runtime. Los tres modos (interp/JIT/AOT) ven el struct ya construido.
    ///
    /// @param e    La expresion de llamada `T(args)`.
    /// @param slay El layout del struct @c T.
    /// @return La direccion del struct materializado, o @c ir::IR_NO_VALUE si
    /// el
    ///         struct no tiene ctor comptime o los argumentos no son
    ///         comptime-evaluables (el caller sigue con el ctor runtime).
    ir::IrValueId try_lower_comptime_ctor_call(ast::CallExpr *e,
                                               const StructLayout &slay);
    /// Ruta B (H1 paso por valor): copia un struct con copy-hook para pasarlo
    /// por valor a una funcion.  Aloca una copia, memcpy del origen, invoca
    /// `copia.__clone__()` y devuelve la direccion de la copia.  El caller debe
    /// emitir el `~dtor` de la copia tras el CALL (la callee no la posee).
    ir::IrValueId emit_struct_arg_copy_clone(ir::IrValueId v_src,
                                             const std::string &struct_name,
                                             uint32_t line);
    /// Ruta B (H3 inc-on-copy): incrementa el refcount del bloque de control de
    /// un `shared<T>` al copiarlo (`b = a`, campo = a, paso por valor).  El
    /// slot guarda el host_ptr al ctrl; refcount en [ctrl+0].  No-op si
    /// ctrl==0.
    void emit_shared_refcount_inc(ir::IrValueId v_slot, uint32_t line);
    /// Ruta B (H3/H5 dec-on-drop): decrementa el refcount y libera (RAW_FREE)
    /// si cae a 0.  Lo usan el cleanup del scope y el dtor del contenedor
    /// (campo shared).  No-op si ctrl==0.
    void emit_shared_refcount_dec(ir::IrValueId v_slot, uint32_t line);
    /// Suelta el recurso que guarda la ranura de un `unique<T>`, dada la
    /// DIRECCION de la ranura: comprobar que no es nula, comprobar que hay algo
    /// dentro, y llamar a quien libera.
    /// @param deleter  Nombre de quien libera (del TIPO).  Vacio = el de por
    ///                 defecto.
    /// @param slot_is_owned  Si la ranura es una reserva aparte que hay que
    ///                 soltar tambien.  Falso para la de un campo, que es un
    ///                 trozo del objeto, y para la de una variable local, que
    ///                 vive en la pila.
    void emit_free_unique_slot(ir::IrValueId slot, const std::string &deleter,
                               uint32_t line, bool slot_is_owned = false);
    /// Genera los thunks Vesta `__cfnthunk_<fn>` para los externs cuya
    /// direccion se tomo como cfn (ver @c extern_cfn_thunks_).
    void generate_extern_cfn_thunks(ir::IrModule &out);
    /// @c true si @p deleter es el liberador de POR DEFECTO.
    ///
    /// Vacio quiere decir "el de por defecto" -- es lo que trae un tipo que no
    /// nombra ninguno --, y el de por defecto es `free`.  Ese criterio se dice
    /// AQUI y en ningun otro sitio: estaba escrito en cinco, y con eso basta
    /// para que uno se quede atras y trate un caso comun como si fuera raro.
    static bool is_default_deleter(const std::string &deleter) {
        return deleter.empty() || deleter == "free";
    }
    /// Devuelve el label a usar para `&fn` / promocion a cfn.  Si @c name es
    /// un extern, registra el thunk y devuelve `__cfnthunk_<fn>`; si no, el
    /// label mangled (o el nombre).
    std::string func_ref_label(const std::string &name,
                               const std::string &mangled);

    /**
     * @brief Genera la IrFunction @c __module_init que registra todas
     *        las clases del modulo via defclass / deffield / defmethod.
     */
    void generate_module_init_function(ir::IrModule &out);

    /**
     * @brief Exporta @c TypeChecker::class_layouts_ al @c IrModule::classes.
     *
     * Convierte el modelo interno del frontend Vesta a la representacion
     * portable del IR.  Cada @c ClassLayout produce un @c ir::IrClass
     * con sus fields/methods/super/interfaces.  Esta info la consumen
     * los transpilers (port-C, port-Java, ...) para emitir POO eficiente
     * sin tener que reconstruir el modelo desde @c __module_init.
     *
     * Clases @c is_runtime_predefined (FatalError, etc.) se omiten:
     * el runtime las define y los transpilers no deben re-emitirlas.
     */
    void export_classes_to_ir(ir::IrModule &out);

    /**
     * @brief Lower de @c this -> primer parametro del metodo en curso.
     */
    ir::IrValueId lower_this_expr(ast::ThisExpr *e);

    /**
     * @brief Lower de @c obj.field (lectura) cuando @c obj es CLASS.
     *        Emite GETFIELD con el offset del ClassLayout.
     */
    ir::IrValueId lower_class_field_load(ast::FieldAccessExpr *e);

    /**
     * @brief Lower de @c obj.field = v cuando @c obj es CLASS.
     *        Emite SETFIELD.
     */
    ir::IrValueId lower_class_field_store(ast::FieldAccessExpr *target,
                                          ir::IrValueId rhs,
                                          const SourceLoc &loc);

    /**
     * @brief Lower de @c obj.method(args) cuando @c obj es CLASS.
     *        Emite CALLVIRT con el indice del metodo en la vtable.
     */
    ir::IrValueId lower_class_method_call(ast::CallExpr *e);

    /**
     * @brief Lower de @c s.method(args) cuando @c s es STRUCT
     *        (value-type).  Emite CALL directo a @c <Struct>__<metodo>
     *        pasando la direccion del struct como primer argumento
     *        (@c this).  Sin vtable: dispatch estatico.  Soporta SRET
     *        (Optional/Result) con retbuf hidden tras @c this.
     */
    ir::IrValueId lower_struct_method_call(ast::CallExpr *e);

    /**
     * @brief @Virtual: emite (una vez, cacheada) la vtable estatica de un
     * struct polimorfico como blob en @c static_data con @c sym_refs a
     * @c <owner>__<metodo> por slot (reloc datos->codigo).  Devuelve el indice
     * del blob en @c static_data.  Modelo AOT: la vtable vive en @c
     * .data.rel.ro.
     */
    uint64_t get_or_emit_struct_vtable(const StructLayout &lay);

    /**
     * @brief @Virtual: inicializa el vptr (offset 0) de un struct polimorfico
     * recien construido en @p struct_addr apuntandolo a su vtable estatica.
     */
    void emit_struct_vptr_init(ir::IrValueId struct_addr,
                               const StructLayout &lay, uint32_t line);

    /// Cache nombre-de-struct -> indice del blob de su vtable en static_data.
    std::unordered_map<std::string, uint64_t> struct_vtable_didx_;

    /**
     * @brief Calcula el puntero al elemento indexado (base + i*sizeof(*base)).
     *
     * Helper compartido por @c lower_index (lectura) y la rama IndexExpr
     * de @c lower_assign (escritura).  Devuelve un IrValueId tipo PTR.
     */
    ir::IrValueId lower_index_addr(ast::IndexExpr *e);

    /**
     * @brief Tamano en bytes del tipo Vesta (consulta layout para STRUCT).
     *
     * @return Tamano del tipo, o 0 si no se puede determinar (e.g. void
     *         o struct desconocido).
     */
    size_t size_of_type(const Type &t) const;

    /**
     * @brief Bytes del buffer de un `Optional<T>` / `Result<V,E>`.
     *
     * El layout es `[+0 i64 flag][+8 payload]`.  Con un payload escalar el
     * total son los 16 bytes de siempre; con un `struct` por valor el payload
     * ocupa su propio tamano (redondeado a 8) en vez de las 8 de un escalar.
     * Sin esto, un `Some(struct)` escribia fuera del payload o guardaba la
     * direccion de un temporal ya muerto.
     *
     * @param t Tipo `OPTIONAL` (o `RESULT`) del que se quiere el buffer.
     * @param base Bytes de cabecera antes del payload (8 en Optional).
     * @return Tamano total del buffer, nunca menor que el clasico de 16.
     */
    size_t optional_buf_bytes(const Type &t, size_t base = 8) const;

    /**
     * @brief Como esta puesto en memoria un `Optional<T>`: atajo al que lo
     *        decide, que es el comprobador de tipos (@c vx::OptionalLayout).
     *
     * @param t Tipo `OPTIONAL`.
     * @return Su disposicion.
     */
    OptionalLayout optional_layout(const Type &t) const;

    /**
     * @struct SretInfo
     * @brief Como devuelve una funcion algo que no cabe en un registro.
     *
     * Tres preguntas que van juntas y que quien llama y quien es llamado
     * tienen que responder IGUAL: si hace falta reservar sitio, cuanto, y si
     * ese sitio vive en memoria del anfitrion.  Si discrepan, el llamado
     * escribe donde el que llama no reservo -- y con el tamano, escribe de
     * mas: fuera del buffer, en el marco ajeno.
     *
     * Estaban contestadas por separado en CUATRO sitios (al registrar la
     * funcion, al bajarla, y en los dos caminos de llamada), y ya habian
     * chocado antes: la nota del bug 248 en @c lower_module cuenta uno de
     * esos choques.  Los dos caminos de llamada, ademas, no listaban lo
     * mismo: el de un metodo estatico se dejaba fuera devolver un lambda y
     * devolver un puntero inteligente, asi que no reservaba nada y el metodo
     * escribia sobre el primer argumento de verdad.
     */
    struct SretInfo {
        bool uses_buffer = false; ///< Quien llama reserva sitio y lo pasa.
        uint64_t bytes = 0;       ///< Cuanto, ya redondeado a palabra.
        bool host_buffer = false; ///< Si vive en memoria del anfitrion.
    };

    /**
     * @brief Responde las tres a la vez, a partir del tipo devuelto.
     *
     * @param ret Tipo que la funcion declara devolver, ya resuelto.
     * @return Que hacer con el retorno.
     */
    SretInfo sret_info(const Type &ret) const;

    /**
     * @brief Lo mismo, para una funcion ya registrada, por su nombre.
     *
     * @param name Nombre de la funcion.
     * @return Lo que se anoto al registrarla; todo a cero si no consta.
     */
    SretInfo sret_info_for(const std::string &name) const;

    /**
     * @brief Anota en un valor SSA lo que su tipo Vesta dice de su memoria.
     *
     * Un `T*` o un `T[]` que no sea `VirtualPtr` apunta a memoria del
     * anfitrion; una referencia a clase, ademas, a un objeto del recolector.
     * De ello depende que un deref se emita con la instruccion de memoria del
     * anfitrion o con la de la maquina virtual: equivocarse no da un error,
     * da un cero o un acceso invalido.
     *
     * La regla estaba escrita en cuatro sitios -- el resultado de una llamada
     * suelta, el de un metodo, el de un metodo de struct y el de un campo --
     * y solo la primera conservaba lo de dentro de un `T**`.  Ninguna cubria
     * leer el valor de un `Optional`, que era la quinta que hacia falta.
     *
     * @param v Valor SSA a anotar.
     * @param t Su tipo Vesta.
     */
    void mark_value_from_type(ir::IrValueId v, const Type &t);

    /**
     * @struct TypeMemory
     * @brief Lo que un TIPO implica sobre la memoria de un valor suyo.
     *
     * El nucleo comun de @ref mark_value_from_type y @ref param_abi, que
     * contestaban lo mismo por separado, y de los tres sitios que APLICABAN la
     * respuesta a un valor con las mismas siete lineas copiadas.
     */
    /**
     * @brief La respuesta, para un tipo.
     *
     * @param t El tipo Vesta.
     * @return Que decir de un valor suyo.
     */
    TypeMemory type_memory(const Type &t) const;

    /**
     * @brief Escribe esa respuesta en un valor de la funcion @p fn.
     *
     * Recibe la funcion en vez de usar la que se esta bajando porque hay
     * quien construye una APARTE -- el envoltorio de una funcion externa, el
     * cuerpo de un lambda -- y necesita la misma regla.
     *
     * @param fn La funcion donde vive el valor.
     * @param v  El valor.
     * @param m  Lo que hay que decir de el.
     */
    void apply_type_memory(ir::IrFunction &fn, ir::IrValueId v,
                           const TypeMemory &m) const;

    /**
     * @brief Hace cumplir un `nonnull`: devuelve el mismo valor, y si es nulo
     *        lanza en el punto donde se escribio.
     *
     * Emite la MISMA operacion que `!!x`.  El pase que quita comprobaciones de
     * nulo demostrables la borra sola cuando el valor no puede ser nulo -- la
     * direccion de algo, un objeto recien creado, una constante distinta de
     * cero --, asi que lo normal es que no cueste nada en ejecucion.
     *
     * @param v    Valor a comprobar.
     * @param line Linea del fuente a la que apuntar si lanza.
     * @return El valor ya comprobado; @p v tal cual si no habia nada que hacer.
     */
    ir::IrValueId enforce_nonnull(ir::IrValueId v, int line);

    /**
     * @brief Elige entre dos valores segun una condicion, calculando cada uno
     *        en su propia rama.
     *
     * Monta los tres bloques -- una rama por lado y el punto donde se juntan --
     * y el PHI que recoge el valor.  Cada lado se calcula DENTRO de su rama,
     * que es lo que lo distingue de un `select`: lo que no se elige no se
     * ejecuta.
     *
     * Es la forma del ternario, y la usan tanto el ternario como
     * `unwrap_or`, que es exactamente eso mismo con la condicion y los lados
     * puestos por el compilador en vez de escritos por el usuario.
     *
     * @param cond     Condicion ya bajada.
     * @param on_true  Calcula el valor de la rama verdadera, dentro de ella.
     * @param on_false Igual para la falsa.  Si difiere de tipo, se convierte.
     * @param tag      Nombre para los bloques (sale en el volcado del IR).
     * @param line     Linea del fuente.
     * @return El valor elegido, o @c IR_NO_VALUE si algun lado no dio ninguno.
     */
    ir::IrValueId
    emit_branching_select(ir::IrValueId cond,
                          const std::function<ir::IrValueId()> &on_true,
                          const std::function<ir::IrValueId()> &on_false,
                          const char *tag, uint32_t line);

    /**
     * @brief ¿Hay algo? -- 1 o 0.
     *
     * Vale igual para un `Optional<T>` y para una referencia nullable, que son
     * la misma pregunta sobre dos formas de guardarla.  Lo usan `isPresent`,
     * `unwrap_or` y `expect`: la respuesta se escribe UNA vez.
     *
     * @param v_arg El valor (direccion del buffer, o el propio puntero).
     * @param at    Su tipo Vesta.
     * @param line  Linea del fuente.
     */
    ir::IrValueId emit_optional_present(ir::IrValueId v_arg, const Type &at,
                                        int line);

    /**
     * @brief El valor que hay dentro.
     *
     * Donde esta lo dice la disposicion (@ref OptionalLayout), no este sitio.
     * Un agregado devuelve su DIRECCION, porque el valor de un agregado es su
     * direccion.
     *
     * @param v_arg   El valor (direccion del buffer, o el propio puntero).
     * @param at      Su tipo Vesta.
     * @param checked Si ademas se AFIRMA que hay algo: si no lo hay, el
     *                proceso muere (ver @ref enforce_nonnull).  Con @c false
     *                no comprueba nada y leer algo que no esta da basura --
     *                es el `unwrap_unchecked`, la renuncia explicita.
     * @param line    Linea del fuente.
     */
    ir::IrValueId emit_optional_value(ir::IrValueId v_arg, const Type &at,
                                      bool checked, int line);

    /**
     * @brief ¿@p t es un `@overlay struct` (una VISTA sobre memoria ajena)?
     *
     * Un overlay comparte @c PrimitiveKind::STRUCT con los structs value-type,
     * pero su semantica de valor es la OPUESTA: el valor de un overlay ES el
     * puntero (8 bytes) al bloque host; no hay payload inline que copiar.  Todo
     * sitio que trate un STRUCT como "buffer inline" (memcpy de @c size_bytes,
     * o "el valor de un elemento es su direccion") debe excluir los overlays y
     * tratarlos como un PTR normal.
     *
     * @return true si @p t es un STRUCT cuyo layout tiene @c is_overlay.
     */
    bool type_is_overlay(const Type &t) const;

    /**
     * @brief Calcula el IrValueId del puntero al campo @c e->field_name.
     *
     * Helper compartido por @c lower_field_access (lectura) y por la
     * rama FieldAccessExpr de @c lower_assign (escritura).  Suma el
     * offset del campo (resuelto via @c TypeChecker::struct_layouts())
     * al puntero base del struct.
     *
     * @return IrValueId de tipo @c PTR apuntando al campo, o
     *         @c IR_NO_VALUE si la base no era un struct valido.
     */
    ir::IrValueId lower_field_addr(ast::FieldAccessExpr *e);

    /**
     * @brief Construye un IrInstr binario en el bloque actual.
     *
     * Helper compartido por lower_binary() y lower_assign() (compound
     * assignments).  Decide el opcode por categoria flotante/integral y
     * con/sin signo, alineando el comportamiento entre asignaciones
     * compuestas y operaciones binarias normales.
     *
     * @param op       Opcode aritmetico/bitwise (mapeado a ADD/FADD/AND/etc.).
     * @param lhs_val  Valor izquierdo (ya bajado).
     * @param rhs_val  Valor derecho (ya bajado).
     * @param common   Tipo comun resultante (ya promovido).
     * @param loc      SourceLoc para anotacion de linea.
     * @return IrValueId del resultado.
     */
    ir::IrValueId emit_binop_ir(ast::BinOp op, ir::IrValueId lhs_val,
                                ir::IrValueId rhs_val, PrimitiveKind common,
                                const SourceLoc &loc);

    /**
     * @brief Si @p name es un builtin (println, print) emite la llamada
     *        FFI correspondiente a vesta_io y devuelve el IrValueId del
     *        retorno (IR_NO_VALUE si la firma es void).
     *
     * Devuelve un valor distinto de "false" mediante un puntero al
     * IrValueId asignado solo cuando se reconocio el builtin; en otro
     * caso devuelve @c std::nullopt.  Los argumentos ya estan en el AST
     * no bajados; el helper se encarga de emitir todo (inclusive la
     * pre-bajada de cada arg y el registro de los datos estaticos / imports).
     *
     * @return IR_NO_VALUE si el builtin coincide y se emitio (caso typico
     *         println/print devuelven void) o un IrValueId valido si en
     *         el futuro hay builtins que devuelven valor.  Devuelve
     *         IR_NO_VALUE - 1 (centinela) si el nombre NO es un builtin
     *         y el caller debe seguir con la ruta normal de CALL.
     */
    bool try_lower_builtin_call(ast::CallExpr *e, ir::IrValueId &out_value);

    // -----------------------------------------------------------------
    // Tabla de simbolos para variables locales y parametros.
    // -----------------------------------------------------------------

    void push_scope();
    void pop_scope();
    void bind(const std::string &name, ir::IrValueId v);
    ir::IrValueId lookup(const std::string &name) const;

    /**
     * @brief Actualiza el valor SSA asociado a @p name en el scope mas
     *        cercano que ya lo tenga definido.
     *
     * Si la variable no existe en ningun scope, ejecuta @c bind() en el
     * scope mas interno como fallback (no deberia ocurrir si el type
     * checker corrio antes; protege en caso de programas malformados).
     *
     * Es la primitiva basica del modelo SSA-construction de Braun:
     * para cada asignacion `x = e` anotamos un nuevo IrValueId como
     * "current value de x" en el scope donde x esta declarada.  Al
     * leer x mas tarde, lookup() devolvera ese ultimo valor.  Los
     * loops insertan PHI nodes en sus bloques header al sellar.
     */
    void update_scope(const std::string &name, ir::IrValueId v);

    /**
     * @brief Recorre el cuerpo de una funcion buscando @c &x donde x es
     *        un IdentExpr local, y rellena @c address_taken_locals_.
     *
     * Se llama una vez al inicio de @c lower_function antes de bajar el
     * body.  El conjunto resultante guia las decisiones de @c lower_var_decl
     * (ALLOCA en lugar de SSA), @c read_local y @c write_local
     * (LOAD/STORE en lugar de scope-update).
     */
    void scan_address_taken(ast::Stmt *s);

    /**
     * @brief Marca como address-taken todo lo que se asigne en @p n.
     *
     * @param n Nodo (el cuerpo de un bucle) por el que mirar.
     */
    void mark_loop_assigned_vars(const ast::Node *n);

    /**
     * @brief Busca en una expresion de quien se toma la direccion.
     *
     * @param e     Expresion por la que empezar.
     * @param depth Cuantas ramas condicionales hay por encima.
     */
    void scan_address_taken_expr(ast::Expr *e, int &depth);

    /**
     * @brief Igual, sobre una sentencia.
     *
     * Lleva la cuenta de ramas condicionales porque de ella depende una
     * decision: una variable que un bucle arrastra solo se promueve cuando el
     * bucle esta DENTRO de una rama -- ahi su hueco no domina la rama hermana
     * y el merge saldria mal --.  A nivel de funcion no hace falta, y hacerlo
     * ademas estropearia la vectorizacion, que espera el contador como valor.
     *
     * @param st    Sentencia por la que empezar.
     * @param depth Cuantas ramas condicionales hay por encima.
     */
    void scan_address_taken_stmt(ast::Stmt *st, int &depth);

    /**
     * @brief Detecta si el body de un `spawn { }` usa primitivas de asincronia
     *        COOPERATIVA (msgrecv/msgsend/fulfill/future_alloc/await).
     *
     * En AOT, `spawn { }` baja por defecto a un HILO REAL del SO
     * (__vx_thread_run).  Pero si el cuerpo usa las primitivas cooperativas
     * (mailbox/future), el spawn es una TAREA COOPERATIVA del scheduler de
     * vx_async (un solo hilo, run-to-completion), no un hilo paralelo: en ese
     * caso se baja a __vx_spawn/__vx_spawn_argv (que devuelven un pid que
     * msgsend/await usan).  Esta distincion refleja el modelo del lenguaje:
     * `spawn { compute }` = paralelismo real; `spawn { msgrecv/fulfill }` =
     * tarea async cooperativa (identico a la semantica del interprete/JIT).
     *
     * @param s Cuerpo del spawn (BlockStmt).
     * @return true si aparece alguna primitiva cooperativa.
     */
    bool spawn_body_uses_coop(ast::Stmt *s);

    /**
     * @brief Lectura de una variable local respetando promocion address-taken.
     *
     * Si @p name esta marcada como address-taken (@c address_taken_locals_),
     * emite un LOAD desde la direccion guardada en scope.  En caso
     * contrario devuelve el IrValueId SSA actual (lookup directo).
     *
     * @param name        Nombre de la variable.
     * @param ir_ty       Tipo IR esperado (para el LOAD; usado solo si
     *                    address-taken).
     * @param source_line Linea fuente para anotar la instruccion.
     * @return IrValueId con el valor leido.  IR_NO_VALUE si la variable
     *         no esta declarada.
     */
    ir::IrValueId read_local(const std::string &name, ir::IrType ir_ty,
                             uint32_t source_line);

    /**
     * @brief Escritura a una variable local respetando promocion address-taken.
     *
     * Si address-taken: emite STORE a la direccion del ALLOCA y deja
     * el value SSA del scope intacto (sigue apuntando a la addr).
     * Si no address-taken: actualiza el scope con el nuevo IrValueId.
     */
    void write_local(const std::string &name, ir::IrValueId v, ir::IrType ir_ty,
                     uint32_t source_line);

    // Helper para reportar features no soportadas por el lowering.
    void unsupported(SourceLoc loc, const char *feature);

    void error_at(SourceLoc loc, std::string msg);

    /**
     * @brief Un builtin usado mal: lo dice, no da valor, y lo da por atendido.
     *
     * Las tres van juntas: el builtin SI era suyo -- el nombre estaba bien, lo
     * que fallo son los argumentos --, asi que contestar que no haria que el
     * despacho siguiera buscando y acabara diciendo que ese nombre no existe.
     * Y dejar el valor sin valor evita un segundo error mas abajo, lejos de lo
     * que el programador escribio mal.
     *
     * @param loc Donde esta el error, para citarlo.
     * @param msg Que le pasa.
     * @param out Donde dejar el resultado: queda sin valor.
     * @return Siempre @c true.
     */
    bool builtin_error(SourceLoc loc, std::string msg, ir::IrValueId &out);

    // -----------------------------------------------------------------
    // Datos.
    // -----------------------------------------------------------------

    ast::ModuleNode &mod_;
    const TypeChecker &tc_;
    Diagnostics &diags_;

  public:
    /// Avisar de cada bloque `asm` que se queda OPACO (no se pudo pasar a IR).
    ///
    /// Un bloque opaco deja de optimizarse y de el solo se sabe lo que diga su
    /// tabla de instrucciones, asi que callarselo hace que todo lo que venga
    /// despues de por bueno un analisis que no llego.  Va aparte mientras el
    /// aviso no sepa NOMBRAR la instruccion en la que se atasco el elevado:
    /// sin ese dato no se puede atender, y un aviso que no se puede atender
    /// solo ensena a ignorar los avisos.
    bool avisar_asm_opaco_ = false;

  private:
    // contadores de @Macros lowered al IR.  Diagnostico
    // para que el desarrollador sepa cuantos @Macros se beneficiaron
    // del lowering y cuantos cayeron al evaluator AST por features
    // todavia no soportadas (introspect, comptime var, etc.).
    uint32_t macro_lowered_count_ = 0;
    uint32_t macro_skipped_count_ = 0;

    /// Force-lower de comptime helpers: nombres (mangled) de las comptime fns
    /// no-macro que un @Macro lowereable referencia (transitivamente) y que por
    /// tanto DEBEN bajarse a runtime (`code.<helper>`) para que el
    /// `__macro_<X>` que las llama resuelva.  Poblado por un pre-pase en @c
    /// run() antes del lowering; consumido por @c lower_function (baja la
    /// comptime fn como fn runtime normal en vez de elidirla).
    std::unordered_set<std::string> comptime_fns_to_force_lower_;

    /// por cada @Macro que el lowering rechazo (usa
    /// builtins comptime-only no aliasables, comptime globals, etc.),
    /// guarda @c (macro_name, reason).  El compiler los propaga al
    /// @c CompileResult y main.cpp los imprime via
    /// @c VESTA_MC_VERBOSE para que el usuario entienda por que
    /// ciertos macros no se benefician del path VM.
    std::vector<std::pair<std::string, std::string>> macro_skip_reasons_;

    /**
     * @brief Que declaracion produjo cada simbolo emitido.
     *
     * Se anota EN el momento de crear el nombre, no despues.  El mangling tiene
     * mas formas de las que parece -- `Clase__metodo`, `Clase__ctor`,
     * `Struct__ctor_<aridad>`, `Struct____dtor`, con prefijo `__macro_` si es
     * comptime -- y quien intente reconstruirlo desde fuera acertara con unas y
     * fallara con otras EN SILENCIO, que es la peor forma de fallar: el mapa
     * sale medio vacio y nadie se entera hasta que hace falta.
     *
     * Cada entrada es `(simbolo, "Tipo::miembro")`.  Lo consume quien vuelca el
     * conocimiento del programa para poder ir de una direccion de ejecucion a
     * la declaracion que la origino.
     */
    std::vector<std::pair<std::string, std::string>> emitted_symbols_;

  public:
    /**
     * @brief El tramo de fuente de una sentencia, dentro de su funcion.
     *
     * Una LINEA no basta: en `return foo(a) / bar(b);` hay tres cosas que
     * pueden fallar y las tres estan en la misma.  Con la columna y la longitud
     * se puede senalar cual.
     */
    struct StmtSpan {
        std::string symbol; ///< funcion en la que esta
        uint32_t line = 0;
        uint32_t column = 0;
        uint32_t length = 0;
    };

  private:
    /// Los tramos de todas las sentencias bajadas, en orden.
    std::vector<StmtSpan> emitted_spans_;
    /**
     * @brief UNICO sitio por el que la bajada emite una instruccion.
     *
     * Antes se llamaba a `append` desde mil sitios y cada uno ponia la linea
     * por su cuenta.  Con eso, cualquier dato nuevo que hubiera que adjuntar a
     * lo emitido -- la columna, de que expresion vino, que ambito estaba vivo
     * -- habia que anadirlo mil veces, y olvidarse en uno dejaba ese caso sin
     * el dato, en silencio.  Pasando todo por aqui, se anade una vez.
     *
     * @param block Bloque destino.
     * @param ins Instruccion.
     */
    void emit(uint32_t block, ir::IrInstr ins) {
        if (!fn_) return;
        // La columna de lo que se esta bajando, si quien la puso no traia ya
        // una mas precisa.
        if (ins.source_column == 0) {
            ins.source_column = pend_stmt_column_;
            // La longitud acompana a la columna: solo vale para el mismo
            // trozo de fuente, y por separado darian un recorte falso.
            if (ins.source_len == 0) ins.source_len = pend_stmt_len_;
        }
        fn_->append(block, std::move(ins));
    }

    /// Columna de la sentencia que se esta bajando, para sellarla en las
    /// instrucciones que emita.  0 = ninguna.
    uint32_t pend_stmt_column_ = 0;

    /// Longitud del mismo trozo de fuente que @c pend_stmt_column_.
    uint32_t pend_stmt_len_ = 0;

    /**
     * @brief Anota el vinculo entre un simbolo y la declaracion que lo produjo.
     * @param symbol Nombre con el que se emite el codigo.
     * @param owner Tipo que declara el miembro.
     * @param member Nombre del miembro tal como se escribio.
     */
    /**
     * @brief Anota el vinculo de una funcion libre, que no tiene propietario.
     * @param symbol Nombre con el que se emite el codigo.
     * @param decl Nombre declarado.
     */
    void note_emitted_function(const std::string &symbol,
                               const std::string &decl) {
        if (symbol.empty() || decl.empty()) return;
        emitted_symbols_.emplace_back(symbol, decl);
    }

    void note_emitted_symbol(const std::string &symbol,
                             const std::string &owner,
                             const std::string &member) {
        if (symbol.empty() || owner.empty() || member.empty()) return;
        emitted_symbols_.emplace_back(symbol, owner + "::" + member);
    }

  public:
    /// @return Que declaracion produjo cada simbolo emitido.
    const std::vector<std::pair<std::string, std::string>> &
    emitted_symbols() const noexcept {
        return emitted_symbols_;
    }

    /// @return El tramo de fuente de cada sentencia bajada.
    const std::vector<StmtSpan> &emitted_spans() const noexcept {
        return emitted_spans_;
    }

    uint32_t macro_lowered_count() const noexcept {
        return macro_lowered_count_;
    }
    uint32_t macro_skipped_count() const noexcept {
        return macro_skipped_count_;
    }
    const std::vector<std::pair<std::string, std::string>> &
    macro_skip_reasons() const noexcept {
        return macro_skip_reasons_;
    }

  private:
    // Nombre del fichero fuente actual (para warnings que solo
    // tienen un source_line).  Se infiere del primer AST node con
    // loc no vacio durante run() y se mantiene durante todo el
    // lowering del modulo.  Si no se puede inferir, queda vacio
    // y los warnings se imprimen sin prefijo de fichero (siguen
    // siendo utiles porque contienen line:col).
    std::string current_file_;

    // Estado por funcion en curso.
    ir::IrModule *out_mod_ =
        nullptr; ///< Modulo IR de salida (para static_data e imports).
    ir::IrFunction *fn_ = nullptr; ///< Funcion en construccion.
    ir::IrBlockId current_block_ =
        ir::IR_NO_BLOCK; ///< Bloque actual donde insertar.
    bool block_terminated_ =
        false; ///< true si current_block_ ya tiene terminador.

    // Tabla de simbolos local: cada scope mapea nombre -> IrValueId.
    std::vector<std::unordered_map<std::string, ir::IrValueId>> scopes_;

    // Para CALL necesitamos saber el tipo de retorno de cada funcion;
    // el type checker ya valido las llamadas, asi que aqui solo
    // mantenemos un cache nombre -> IrType.
    std::unordered_map<std::string, ir::IrType> fn_return_types_;

    /// FFI declarativo: nombre de funcion -> libreria nativa
    /// (e.g. "user32.dll", "kernel32.dll" o "stdlib/native/io/vesta_io").
    /// Se llena en el pase 1 al recorrer @c ExternFnDecl.  Si una entrada
    /// existe para el callee de @c lower_call, emitimos
    /// @c CALLN @Method("<lib>:<name>") con args en R1..RN y registramos
    /// el import via @c out_mod_->register_native_import.  Sin entry,
    /// el flujo normal CALLVM (funcion Vesta local) sigue intacto.
    std::unordered_map<std::string, std::string> extern_lib_by_fn_name_;

    /// Lo que se DEFINIO de cada extern (`in`/`out`/`inout` en sus params),
    /// pasado a las mascaras por argumento de @c ir::IrNativeEffects.  Se llena
    /// en el mismo pase 1 que @c extern_lib_by_fn_name_ y se entrega al
    /// registrar el import en el SITIO DE LLAMADA, no al declararlo: un extern
    /// declarado y nunca llamado no debe meter un import que obligue a resolver
    /// un simbolo que el programa no usa.
    ///
    /// Sin entrada = nadie dijo nada = el analisis supone lo peor, que es lo
    /// unico honesto sobre codigo que no esta en el programa.
    std::unordered_map<std::string, ir::IrNativeEffects>
        extern_effects_by_fn_name_;

    /**
     * @brief Registra el import de una nativa declarada con `extern`, llevando
     *        consigo lo que se DEFINIO de ella.
     * @param out Modulo destino (la llamada directa y el thunk escriben en
     *            modulos distintos).
     * @param lib Libreria.
     * @param fn  Nombre de la funcion nativa.
     *
     * Un solo sitio para las dos vias de llamar a un extern.  Con dos, lo
     * definido valdria o no segun por cual se llegara, que es una diferencia
     * que nadie nota hasta que un contrato se aprueba por un camino y falla
     * por el otro.
     */
    void register_extern_import_(ir::IrModule &out, const std::string &lib,
                                 const std::string &fn);

    /**
     * @brief La direccion de un lvalue, como si se hubiera escrito `&`.
     * @param lvalue La expresion.  El llamante sigue siendo su dueno.
     * @return El valor SSA con la direccion, o @c IR_NO_VALUE si no se pudo.
     *
     * Lo necesita el argumento de un parametro de SALIDA: lo que viaja es la
     * direccion del hueco, y tiene que salir por el MISMO sitio que un `&x`
     * escrito a mano -- si no, se pasaria distinto y eso no da un error, da
     * otra direccion.
     */
    ir::IrValueId lower_addr_of_lvalue(ast::Expr *lvalue);

    /// Externs cuyo `&fn` (o promocion a cfn) se uso como function value.
    /// Para cada uno generamos un thunk Vesta `__cfnthunk_<fn>` que reenvia
    /// al CALLN nativo, asi el cfn es invocable por CALLIND en cualquier
    /// backend (la direccion nativa no se puede llamar por callvmr directo).
    std::unordered_set<std::string> extern_cfn_thunks_;

    /// ADTs: nombre del enum que la funcion retorna (vacio si
    /// no retorna enum declarado).  Se usa en lower_call para
    /// alocar el retbuf con @c enum_layouts_[name].size_bytes y en
    /// lower_function para configurar @c sret_active_/@c sret_buf_size_.
    std::unordered_map<std::string, std::string> fn_ret_enum_name_;

    /// Nombre del STRUCT que la funcion devuelve por valor (vacio si no
    /// devuelve uno).  Igual que @c fn_ret_enum_name_: el caller lo usa para
    /// alocar el retbuf con @c struct_layouts_[name].size_bytes.  Un struct
    /// devuelto por valor es SRET porque su buffer vive en el frame del callee
    /// y muere al RET.
    std::unordered_map<std::string, std::string> fn_ret_struct_name_;

    /// Lo que se decidio sobre el retorno de cada funcion, por su nombre:
    /// si usa buffer, cuanto mide y donde vive (ver @c SretInfo).  Lo escribe
    /// @c register_fn_ret_info y lo leen los caminos de llamada, para que no
    /// vuelvan a deducirlo cada uno por su cuenta.
    std::unordered_map<std::string, SretInfo> fn_sret_;

    /// (gap O cerrado): conjunto de funciones que retornan un
    /// valor de tipo FUNCTION (function value).  Se trata como SRET
    /// con buf_size=16 (mismo layout que el slot de lambda: fn_addr
    /// en +0, env_addr en +8).  El env block apuntado por env_addr
    /// se aloca via RAW_ALLOC (heap) en lugar de ALLOCA (stack)
    /// cuando estamos dentro de una de estas funciones, asi el env
    /// sobrevive al RET y la closure retornada es invocable por el
    /// caller sin use-after-free.
    std::unordered_set<std::string> fn_returns_function_;

    /// Funciones cuyo return type es @c unique<T> o @c shared<T>.
    /// Igual que @c fn_returns_function_ pero con buffer SRET de 8
    /// bytes (slot del smart pointer).  El @c return p en el body
    /// copia los 8 bytes del slot local al retbuf del caller; el
    /// caller bindea la variable receptora directamente al retbuf,
    /// donde ya viven los datos correctos.  Cleanup del local NO
    /// se emite (escape detection lo detecta via "return ident"),
    /// pero el caller registra cleanup sobre el retbuf.
    std::unordered_set<std::string> fn_returns_smartptr_;

    /// Funciones que en @c native_poo_ (AOT Embed/Bare) declaran
    /// devolver `string`.  En native el `string` es VALUE-TYPE de 24
    /// bytes {ptr,len,cap}; un retorno por valor debe usar el ABI SRET
    /// (igual que un struct de 24 bytes): el caller aloca un retbuf de
    /// 24 bytes y lo pasa como primer arg hidden; el callee copia el
    /// value-string al retbuf y transfiere su ownership (no libera en
    /// el callee, lo posee el caller via su RAII).  Sin esto el callee
    /// retornaria en RAX un PTR a su slot local de 24 bytes que muere
    /// al RET -> basura -> segfault.  El path Full/JIT NO usa esto:
    /// ahi `string` es un GcHandle i64 retornado en registro.
    std::unordered_set<std::string> fn_returns_str_value_;

    /// indicador activo durante el lowering del body de una
    /// funcion que retorna FUNCTION.  Disparado en @c lower_function
    /// y consultado por @c lower_lambda_expr para alocar el env
    /// block en heap raw en lugar de stack.  Se restaura al salir.
    bool current_fn_returns_function_ = false;

    /// Activo mientras se baja un lambda-literal que se ALMACENA en un campo /
    /// slot de array / deref (escapa del scope actual a un objeto que puede
    /// sobrevivir al frame).  Disparado por @c lower_assign y consultado por
    /// @c lower_lambda_expr para alocar el env en heap (GC) en lugar de stack.
    bool current_lambda_store_escapes_ = false;

    /// Indica que la funcion actual declara devolver `string` a nivel
    /// fuente.  El IR tipo es I64 (handle a StringObject) por lo que
    /// el flag es necesario para auto-promover en `return "..."` el
    /// literal a StringObject via STRMAKE (mismo patron que
    /// `lower_var_decl` para `string s = "lit"`).  Se restaura al
    /// salir de `lower_function`.
    bool current_fn_returns_string_ = false;

    /// true mientras se baja el body de una funcion que en @c native_poo_
    /// retorna `string` (value-type) por SRET.  El @c lower_return usa este
    /// flag para construir el value-string nativo del `return <expr>` (p.ej.
    /// un literal -> build_native_string_from_literal) ANTES de copiar los
    /// 24 bytes al retbuf.  Sin el, `return "lit"` copiaria los bytes crudos
    /// de static_data en lugar de un {ptr,len,cap}.  Se restaura al salir.
    bool current_fn_sret_str_value_ = false;

    /// true si la funcion actual contiene algun `try { } catch`
    /// statement.  Se rellena con un pre-pase simple en lower_function.
    /// Cuando es true, NO emitimos el cleanup automatico release_handle
    /// para CLASS sin destructor: el bytecode tryenter/throw no preserva
    /// los GP regs, asi que un cleanup que lea un reg con el binding del
    /// local podria leer garbage si el catch handler corrio antes.
    /// Para funciones SIN try el cleanup es seguro y libera handles
    /// deterministicamente al exit del scope.
    bool current_fn_has_try_ = false;
    /// @NoIdiom en la funcion que se esta bajando: los pases que reconocen
    /// idiomas (un bucle de copia -> memcpy) no se aplican dentro.  Sin esto,
    /// el codigo que IMPLEMENTA memcpy se reescribiria a una llamada a si
    /// mismo.
    bool current_fn_no_idiom_ = false;

    /// true si la funcion actual contiene algun loop
    /// (while/for/do-while).  Se rellena con un pre-pase en
    /// lower_function.  Cuando es true, el lower_var_decl marca
    /// AUTOMATICAMENTE como address-taken las vars CLASS / I64-GC
    /// declaradas en el top-level del body (depth scope <= 2).
    ///
    /// Razon: el regalloc puede clobbar el reg de una var GC del
    /// outer scope durante el body del loop (e.g. `newobj r1` reusa
    /// r1 que tenia `owned`).  Address-taken fuerza ALLOCA + STORE/
    /// LOAD por uso, garantizando que el binding sobreviva al loop.
    ///
    /// Esto permite que el cleanup CALL_DTOR / RAW_ASM al RET de la
    /// funcion lea del stack en lugar de un reg potencialmente
    /// corrupto.  Tambien habilita que el cleanup scope-local sea
    /// seguro.
    ///
    /// Coste: 1 STORE inicial + 1 LOAD por uso (~2 instr extra).
    /// Solo aplica a vars CLASS/GC en funciones con loops; el resto
    /// del codigo no tiene overhead.
    bool current_fn_has_loops_ = false;

    /// @c true cuando estamos lowereando el body de
    /// un @Macro.  Se usa para forzar que las VarDecl marcadas
    /// @c is_comptime se bajen como vars runtime regulares (el
    /// macro corre en VM; los locales se computan en cada
    /// invocacion).  Reset al entrar/salir de cada funcion.
    bool current_fn_is_macro_ = false;

    /// cache `name -> static_data_idx` para comptime
    /// globals referenciados por @Macros lowereados.  Cada global
    /// se materializa como un slot de 8 bytes en static_data del
    /// .velb, inicializado con el valor compile-time.  Los macros
    /// leen/escriben via @c STR_LIT_ADDR + LOAD/STORE i64.  El AST
    /// evaluator mantiene su propia copia en
    /// @c TypeChecker::comptime_const_values_ -- son dos espacios
    /// de memoria distintos pero cada pase del two- compile
    /// se mantiene consistente internamente.
    std::unordered_map<std::string, uint64_t> comptime_global_slots_;
    /// L2.2: slots para globales runtime no-const (string/int/etc.)
    std::unordered_map<std::string, uint64_t> runtime_global_slots_;
    /// `static T x = init;` local: duracion estatica (una instancia en gdata,
    /// mangled por funcion) con acceso via el nombre LOCAL.  Se limpia al
    /// empezar cada funcion.  @c lower_ident / @c lower_assign consultan este
    /// mapa ANTES del scope para emitir STR_LIT_ADDR(slot) + LOAD/STORE (o solo
    /// la direccion si es agregado).  El init-once se materializa con un guard
    /// booleano global (otro slot) cuando el init no es un cero constante.
    struct StaticLocalSlot {
        uint64_t slot = 0;                    ///< indice en static_data (gdata)
        ir::IrType ld_type = ir::IrType::I64; ///< ancho del LOAD/STORE
        bool aggregate = false; ///< struct/array -> el valor ES la direccion
    };
    std::unordered_map<std::string, StaticLocalSlot> static_local_slots_;
    /// Nombres (ya mangled) de los globals declarados en ESTE modulo.  Sirve
    /// para no confundir un simbolo de un namespace propio con uno importado:
    /// el storage de los locales lo decide el pre-pase con el tipo delante, y
    /// hay tipos que no llevan slot (p.ej. un global de tipo funcion).
    std::unordered_set<std::string> local_global_names_;

    /// thread_local con init != 0: (slot static_data, valor inicial 8B LE).  El
    /// lowering sintetiza __vx_tls_init (TLS callback del PE) que escribe estos
    /// valores en la copia por-hilo al attach del hilo -- el cargador de
    /// Windows no siempre copia la plantilla del TLS de una .dll a un
    /// consumidor minimal.
    std::vector<std::pair<uint64_t, uint64_t>> tls_nonzero_inits_;

    /// sret en call sites: cache nombre-de-funcion -> PrimitiveKind
    /// del tipo de retorno semantico (antes de la transformacion sret).
    /// Solo nos interesa distinguir OPTIONAL / RESULT del resto, porque
    /// solo esos dos kinds disparan el alocado del retbuf en el caller.
    /// Las claves que NO estan en el mapa o cuyo valor no sea
    /// OPTIONAL/RESULT corresponden a calls "normales" (la firma IR del
    /// callee usa @c fn_return_types_ y el resultado del CALL es el
    /// valor devuelto directamente).
    std::unordered_map<std::string, PrimitiveKind> fn_ret_kind_;

    /**
     * @brief Registra la info de retorno de una funcion top-level (tipo IR,
     *        kind semantico y pertenencia a los conjuntos SRET).
     *
     * Unico punto donde se decide si una funcion usa la convencion SRET
     * (retbuf hidden como primer parametro).  Lo usan TANTO el registro de
     * las funciones LOCALES (a partir del AST) como el de las IMPORTADAS de
     * otro modulo (a partir de la @c FunctionSig del .vxi).  Compartir el
     * criterio es lo que garantiza que caller y callee coincidan: si cada
     * lado dedujera el SRET por su cuenta, una divergencia haria que el
     * callee escribiese en un retbuf que el caller nunca paso.
     *
     * Lo que decide queda anotado en @c fn_sret_ y se consulta con
     * @c sret_info_for, para que quien llama no tenga que volver a deducirlo.
     *
     * @param name     Nombre por el que se invoca la funcion.
     * @param ret      Tipo de retorno YA RESUELTO.  Entero, no solo su
     *                 especie: el tamano de un `Optional` depende de lo que
     *                 envuelva, y quedarse con la especie obligaba a quien
     *                 llamaba a buscarlo por otro lado.
     * @param is_async La fn es @Async: el bytecode devuelve el handle
     *                 i64 del Future, no el tipo logico T.
     */
    void register_fn_ret_info(const std::string &name, const Type &ret,
                              bool is_async);

    /// Variables locales cuya direccion se ha tomado con '&' en alguna
    /// parte de la funcion actual.  Se rellena con scan_address_taken al
    /// inicio de lower_function y se limpia al terminarla.  Las entradas
    /// disparan ALLOCA en lower_var_decl y LOAD/STORE en read/write_local.
    std::unordered_set<std::string> address_taken_locals_;

    /// locales cuyo handle escapa del scope: se devuelven via
    /// @c return id, se asignan a un campo (@c this.x = id, @c obj.x = id,
    /// @c *p = id) o a un slot de array (@c arr[i] = id).  Para esos
    /// locales NO registramos auto-free al exit del scope porque el
    /// caller (o el padre) toma posesion del handle y debera liberarlo
    /// (o el GC lo gestionara via stack scanning conservativo).
    ///
    /// Conservador: si algun uso del local podria escapar segun los
    /// patrones detectados por @c scan_escaping_locals, se marca como
    /// escaping y queda fuera del cleanup automatico.  Falsos positivos
    /// (escape detectado pero no real) producen un leak intencional
    /// que el programador debe liberar via dispose() explicito.
    std::unordered_set<std::string> escaping_locals_;
    /// Locales que se REASIGNAN en algun punto de la funcion (`s = x`, `s +=
    /// x`).  Lo llena el mismo pre-pase que @c escaping_locals_.  Una cadena
    /// inicializada con un literal y que nunca se reasigna no puede llegar a
    /// tener buffer propio, asi que no hace falta liberarla al salir del
    /// ambito -- y sin ese `free` un programa que solo usa cadenas constantes
    /// deja de enlazar el asignador.
    std::unordered_set<std::string> reassigned_locals_;

    /// pre-pase ejecutado al inicio de @c lower_function que
    /// rellena @c escaping_locals_ recorriendo el body.  Reusable como
    /// helper de futuras analizadores de escape mas precisas.
    void scan_escaping_locals(ast::Stmt *body);

    /// @brief Quien puede contener un valor que vino de quien, por asignacion.
    using AliasGraph =
        std::unordered_map<std::string, std::vector<std::string>>;

    /// @brief Marca @p e como escapado, si es un nombre.
    void mark_escaping_if_ident(ast::Expr *e);

    /**
     * @brief @c true si guardar @p e en un campo es COPIARLO, no trasladarlo.
     *
     * Un compartido o un tipo con copia propia se duplican al guardarse: el
     * origen conserva el suyo y lo suelta cuando le toca.  Eso no es un
     * traslado, asi que el origen no escapa.
     */
    bool value_has_copy_hook(ast::Expr *e) const;

    /**
     * @brief Busca en una expresion que locales se escapan de su ambito.
     *
     * @param e     Expresion por la que empezar.
     * @param alias Donde apuntar quien puede contener el valor de quien.
     */
    void scan_escaping_expr(ast::Expr *e, AliasGraph &alias);

    /// @brief Igual, sobre una sentencia.
    void scan_escaping_stmt(ast::Stmt *st, AliasGraph &alias);

    /// Bug D fix: propagar @c is_gc_object a traves de todos los PHI
    /// nodes de la funcion hasta punto fijo.  Llamado al final de cada
    /// lowering de funcion (top-level, class methods, helpers
    /// sintetizados) justo antes de @c IrModule::add_function.
    void propagate_is_gc_object_through_phis(ir::IrFunction &fn);

    /// Limitacion A (cerrada): subset de @c address_taken_locals_ cuyo
    /// contenido es un puntero a memoria HOST (resultado de malloc o
    /// derivado).  Lo registra @c write_local cada vez que el valor
    /// escrito tiene @c is_host_ptr = true.  @c read_local consulta el
    /// set para propagar el bit al SSA value resultante del LOAD; sin
    /// esto, un LOAD de un local address-taken con tipo @c T* siempre
    /// emite @c mov (memoria VM) y corrompe la heap host.
    ///
    /// Es un best-effort sticky: si el local pasa por una asignacion
    /// con @c is_host_ptr = true se queda marcado para siempre.
    /// Asignaciones posteriores con valores VM no lo desmarcan.  En
    /// la practica los locales mantienen su naturaleza host/VM a lo
    /// largo de su vida, asi que esta semantica conservadora basta.
    ///
    /// NO cubre el caso indirecto @c i32** pp = &p; **pp = v.  Para
    /// ese caso haria falta un bit @c pointee_is_host_ptr en
    /// IrValue propagado a traves de @c &x.  Documentado como gap
    /// remanente; requiere acuerdo de diseno antes de implementarse.
    std::unordered_set<std::string> host_bearing_locals_;

    /// Conjunto de clases instanciadas alguna vez via @c new ClassName()
    /// con modificador @c shared (vd->is_shared).  Lo rellena
    /// @c lower_var_decl al detectar el patron.  @c generate_new_helpers
    /// lo consulta para emitir adicionalmente un helper
    /// @c __new_<X>_shared (que internamente usa @c newobjs en lugar de
    /// @c newobj).  Sin esto, una instancia compartida apuntaria al
    /// helper local-only y el child no podria deref el host_ptr.
    std::unordered_set<std::string> classes_used_shared_;

    /// gc<T> opt-in: clases instanciadas como @c gc<Class> -> generar el helper
    /// @c __new_<Class>_gc (aloca con @c vx_gc_alloc + marca is_gc_object, sin
    /// RAII).  El GC (libvesta_gc) colecta lo no alcanzable.
    std::unordered_set<std::string> classes_used_gc_;

    /// true si el modulo registro al menos un finalizador GC (gc<unique>/
    /// gc<shared>/gc<Clase> con recurso interno).  En AOT dispara la inyeccion
    /// de @c vx_gc_finalize_all antes de cada RET de main (cero fuga al exit).
    bool module_has_gc_finalizers_ = false;

    /// Vars locales declaradas con modificador @c shared.  El escape
    /// analyzer de @c spawn las omite del warning "objeto GC local-only
    /// capturado" (declarar @c shared es la solucion sugerida).
    std::unordered_set<std::string> shared_locals_;

    /// Slot stack del @c unique<T>/shared<T> que el caller pasa como
    /// retbuf SRET cuando devuelve smart pointer (signature @c VOID +
    /// retbuf hidden).  Si @c lower_return detecta que el return value
    /// es un @c CallExpr a @c unique_box/shared_box/_with, asigna este
    /// slot al lowering del builtin para que el smart pointer se
    /// construya IN-PLACE en el retbuf sin copia qword-a-qword al final.
    /// @c IR_NO_VALUE = sin in-place SRET (lowering normal).
    ir::IrValueId unique_box_target_slot_ = ir::IR_NO_VALUE;

    /// SSA values de las capturas del spawn body, en el orden en que
    /// fueron resueltas en el caller (sus nombres viven en
    /// @c spawn_captured_names_).  Usado por @c generate_spawn_helper
    /// para propagar @c is_host_ptr / @c is_gc_object a los params del
    /// helper hijo y por el escape analyzer del spawn capture.
    std::vector<ir::IrValueId> spawn_captured_ssa_values_;

    /// Nombres de las capturas del spawn body, paralelo a
    /// @c spawn_captured_ssa_values_.
    std::vector<std::string> spawn_captured_names_;

    /// Wrapper publico para que @c collect_spawn_captures_in_expr (que
    /// vive como helper estatico) pueda resolver un nombre en TODOS
    /// los scopes activos del lowering.  Equivale a @c lookup(name)
    /// pero accesible desde el contexto estatico.
    /// @return @c IrValueId del binding o @c IR_NO_VALUE si no existe.
    ir::IrValueId spawn_capture_resolve(const std::string &name);

    /// Emite la instruccion @c MVTAKE_IR (move-and-take) que copia un
    /// qword desde @c [v_src_addr] a @c [v_dst_addr] y zerifica el
    /// slot fuente en una sola operacion atomica.  Usado por
    /// @c move(p) sobre smart pointers para implementar move-ownership
    /// con la garantia de que la fuente queda invalidada.
    void emit_mvtake(ir::IrValueId v_dst_addr, ir::IrValueId v_src_addr,
                     uint32_t source_line);

    /// Emite GC_SET_FINALIZER %box, imm=kind.  Registra (kind 1/2/3) o
    /// desregistra (kind 0) el finalizador GC de un box con recurso interno.
    /// Para kind==3 (CLASS_DTOR) pasar @p v_dtor_addr con el vaddr del
    /// <Clase>____dtor concreto (dispatch estatico).
    void emit_gc_set_finalizer(ir::IrValueId v_box, uint32_t kind,
                               uint32_t source_line,
                               ir::IrValueId v_dtor_addr = ir::IR_NO_VALUE);

    /// Emite @c IrOp::LABEL_ADDR que se interpreta en el bajado a .vel
    /// como @c @Absolute("code.<label_name>"), produciendo la direccion
    /// absoluta del label resuelta por el linker.  Util para invocar
    /// helpers sintetizados, slots estaticos, etc.
    ir::IrValueId emit_label_addr(const std::string &label_name, uint32_t line);

    /// Construye en stack un @c FindClassParams (name_addr + name_len),
    /// invoca @c IrOp::FINDCLASS y devuelve el SSA value con el
    /// @c ClassInfo* resuelto (host_ptr).  @p name_idx referencia el
    /// slot de strings @c "s_<idx>" emitido previamente.
    ir::IrValueId emit_findclass_by_name(uint64_t name_idx, uint32_t name_len,
                                         uint32_t line);

    /// Emite @c IrOp::GC_HANDLE_FOR_PTR que toma un host_ptr al payload
    /// de un objeto GC y devuelve su @c GcHandle (uint32 zero-extended
    /// a i64).  Util cuando una operacion runtime requiere el handle
    /// (monitor, weak ref, drop) en lugar del puntero directo.
    ir::IrValueId emit_gc_handle_for_ptr(ir::IrValueId v_host_ptr,
                                         uint32_t source_line);

    // Monitor enter/exit.  En native_poo_ (AOT) baja a CALL nativo
    // (__vx_monenter/__vx_monexit, bundle-ado desde stdlib/vx/vx_sync.vx)
    // sobre el host_ptr del objeto; en el resto de tiers emite la IR op
    // MONENTER/MONEXIT (handle) que el runtime/JIT consume.
    void emit_monitor_op(ir::IrValueId v_obj_or_handle, bool enter,
                         uint32_t source_line);

    // --- Helpers de operaciones sobre cadenas (StringObject) ---
    ir::IrValueId emit_strmake(ir::IrValueId v_buf, ir::IrValueId v_len,
                               uint32_t source_line);
    /// Construye un `string` desde un literal (addr+len) eligiendo el repr
    /// segun el tier: value-string nativo (AOT, PURE_NATIVE, SSO) en
    /// native_poo_, o STRMAKE (GcHandle, Full/JIT/interp) en otro caso.  Usado
    /// por los builtins de introspeccion comptime (typename/underlying_of/...)
    /// que antes emitian STRMAKE incondicional -> RUNTIME_DEPENDENT en AOT.
    /// @p known_len = longitud compile-time (>=0) o -1 si solo se sabe en
    /// runtime (el value-string decide SSO/heap con una rama).
    ir::IrValueId emit_string_literal_repr(ir::IrValueId v_addr,
                                           ir::IrValueId v_len,
                                           int64_t known_len,
                                           uint32_t source_line);
    ir::IrValueId emit_strcat(ir::IrValueId v_a, ir::IrValueId v_b,
                              uint32_t source_line);
    ir::IrValueId emit_strraw(ir::IrValueId v_str, uint32_t source_line);
    ir::IrValueId emit_strconv(ir::IrValueId v_str, uint64_t enc_imm,
                               uint32_t source_line);
    ir::IrValueId emit_strgetbytes(ir::IrValueId v_str, uint32_t source_line);

    // --- Vesta Embed Inc 0: string value-type (solo native_poo_) ---
    /// Construye el repr value-string {ptr,len,cap} (24 bytes) en stack
    /// (ALLOCA) desde un literal: aloca buffer en heap (RAW_ALLOC len+1),
    /// copia los bytes del literal + nul final, y escribe los 3 campos
    /// del slot.  Devuelve el PTR al slot de 24 bytes (el "valor" del
    /// string, igual que un struct value-type).  Solo se usa en
    /// @c native_poo_ (AOT Embed/Bare); el path Full usa StringObject GC.
    ir::IrValueId build_native_string_from_literal(ast::StringLitExpr *slit,
                                                   uint32_t source_line);
    /// Vesta Embed: construye un value-string {ptr,len,cap} (24 bytes) en
    /// stack desde un valor @c char en runtime (@p v_char).  Aloca un
    /// buffer de 2 bytes (RAW_ALLOC), escribe el byte del char en
    /// buf[0] + nul en buf[1], y rellena los campos len=1, cap=2.
    /// Devuelve el PTR al slot.  Usado por el cast @c (string)<char>.
    /// Solo en @c native_poo_ (AOT Embed/Bare).
    ir::IrValueId build_native_string_from_char(ir::IrValueId v_char,
                                                uint32_t source_line);
    /// Carga el campo @p byte_off (0=ptr, 8=len, 16=cap) del slot
    /// value-string @p v_slot.  @p as_host marca el resultado como
    /// host_ptr (para el ptr@0 que viene de RAW_ALLOC).
    ir::IrValueId load_native_string_field(ir::IrValueId v_slot,
                                           uint64_t byte_off, bool as_host,
                                           uint32_t source_line);
    /// String Inc 5 (SSO): accesores flag-aware del value-string nativo.
    /// Layout union de 24 bytes con flag en el bit alto (0x80) del byte
    /// [23]:
    ///   HEAP (byte[23]&0x80 != 0): ptr@0 (8B), len@8 (8B), cap en
    ///     bytes[16..22] (56 bits), byte[23] bit alto=1.
    ///   SSO  (byte[23]&0x80 == 0): data en bytes[0..21] (max 22), nul en
    ///     byte[len], len en byte[23] bits bajos (0..22).
    /// @c emit_native_str_is_heap devuelve un I64 (0 o 1) = (byte[23]>>7).
    /// @c emit_native_str_data_ptr devuelve el host_ptr a los bytes: si
    /// HEAP -> LOAD ptr@0; si SSO -> &slot (la data vive inline en
    /// offset 0).  Branchless via mascara (slot + is_heap*(ptr0 - slot)).
    /// @c emit_native_str_len devuelve la longitud: si HEAP -> LOAD len@8;
    /// si SSO -> byte[23]&0x7F.  Branchless.  TODAS las ops de string
    /// usan estos accesores en vez de leer ptr@0/len@8 crudos.
    ir::IrValueId emit_native_str_is_heap(ir::IrValueId v_slot,
                                          uint32_t source_line);
    /// @brief 1 si el buffer detras del puntero es NUESTRO (hay que
    ///        liberarlo), 0 si no.
    ///
    /// Tercer estado del slot: PRESTADO.  Un literal no se copia a memoria
    /// pedida al asignador -- vive en `.rodata`, que para eso esta -- asi que
    /// su slot apunta ahi y NO se libera.  Se marca con el bit 6 de byte[23],
    /// que estaba libre (en modo HEAP los bits 0..6 no se usan: la capacidad
    /// ocupa los bytes 16..22).
    ///
    ///   byte[23] bit 7 = los datos estan detras del puntero (no inline)
    ///   byte[23] bit 6 = prestado: el buffer no es nuestro
    ///
    /// Los accesores de LECTURA siguen mirando solo el bit 7, asi que leer una
    /// vista es exactamente igual de caro que leer un buffer propio.  Este
    /// accesor lo usa unicamente quien libera o quien va a escribir encima.
    ir::IrValueId emit_native_str_is_owned(ir::IrValueId v_slot,
                                           uint32_t source_line);
    /// @brief Deja el value-string en condiciones de que se le ESCRIBA encima.
    ///
    /// Un literal largo no se copia: el slot APUNTA al binario y se marca
    /// prestado, con capacidad 0.  Es lo que hace que un programa que solo
    /// menciona cadenas constantes no arrastre el asignador.  El precio es un
    /// contrato: **quien vaya a escribir copia antes**.
    ///
    /// Este es ese "copia antes", en UN sitio.  Si el slot esta prestado,
    /// reserva un buffer propio, copia los bytes con su nul y reescribe los
    /// campos como propios; si ya era propio o cabe inline, no hace nada.  Un
    /// escritor nuevo debe llamarlo, no volver a escribir la copia.
    ///
    /// Hizo falta porque el contrato estaba escrito y a la vez incumplido:
    /// `s[i] = c` escribia directo, asi que mutar una cadena LARGA nacida de un
    /// literal escribia en memoria de solo lectura y mataba el proceso -- y con
    /// una corta funcionaba, porque esa si se copia al hueco de 24 bytes.  El
    /// comportamiento dependia del LARGO del literal.
    ///
    /// @param v_slot Slot de 24 bytes del value-string.
    /// @param source_line Linea de fuente para el diagnostico.
    void emit_native_str_make_writable(ir::IrValueId v_slot,
                                       uint32_t source_line);
    /// @brief Rellena el slot de 24 bytes como VISTA sobre un buffer ajeno.
    /// @param v_slot Slot destino.
    /// @param v_buf Puntero a los bytes (tipicamente `.rodata`).
    /// @param len Longitud en bytes, sin contar el nul.
    /// @param source_line Linea de fuente para el diagnostico.
    void store_slot_fields_prestado(ir::IrValueId v_slot, ir::IrValueId v_buf,
                                    uint64_t len, uint32_t source_line);
    /// @c emit_native_str_data_ptr / @c emit_native_str_len emiten una CALL a
    /// los helpers @c __vx_strdata / @c __vx_strlen (una sola instruccion por
    /// uso).  La logica branchless (AND-mask heap/SSO) vive en el cuerpo del
    /// helper (@c *_inline), NO inline en cada call site: cada accesor inline
    /// expandia ~10 instrs, y sumar 4 longitudes + 4 punteros en una funcion
    /// reventaba el regalloc SysV (menos callee-saved que Win64) -> resultado
    /// erroneo en ELF.  Mismo patron que @c __vx_strcmp / itoa.  Los helpers
    /// estan en el blacklist del inliner (prefijo @c __vx_str) para no
    /// re-inlinearse.
    ir::IrValueId emit_native_str_data_ptr(ir::IrValueId v_slot,
                                           uint32_t source_line);
    ir::IrValueId emit_native_str_len(ir::IrValueId v_slot,
                                      uint32_t source_line);
    /// Cuerpos branchless de los accesores (emitidos dentro del helper).
    ir::IrValueId emit_native_str_data_ptr_inline(ir::IrValueId v_slot,
                                                  uint32_t source_line);
    ir::IrValueId emit_native_str_len_inline(ir::IrValueId v_slot,
                                             uint32_t source_line);
    /// Construyen (lazy, una vez) los helpers @c __vx_strdata / @c __vx_strlen
    /// y devuelven su nombre.  Firma: @c u8* __vx_strdata(u8* s) /
    /// @c i64 __vx_strlen(u8* s).
    std::string ensure_strdata_helper();
    std::string ensure_strlen_helper();
    /// Vesta Embed Inc 6 (encoding UTF-8): @c .length() cuenta CODE-POINTS (no
    /// bytes; @c .bytes() da los bytes via @c emit_native_str_len).  El helper
    /// @c __vx_str_cplen(u8* p, i64 byte_len) -> i64 recorre los bytes y suma
    /// 1 por cada byte que NO sea continuacion UTF-8 ((b & 0xC0) != 0x80).
    /// Para ASCII coincide con el conteo de bytes (cero cambio en los tests
    /// ASCII existentes).  @c emit_native_str_cplen emite la CALL.
    std::string ensure_str_cplen_helper();
    ir::IrValueId emit_native_str_cplen(ir::IrValueId v_ptr,
                                        ir::IrValueId v_blen,
                                        uint32_t source_line);
    /// Vesta Embed Inc 6: @c .wstr() devuelve un @c u16* NUL-terminado en
    /// UTF-16LE para FFI Win32 @c *W.  El helper
    /// @c __vx_str_to_utf16(u8* p, i64 byte_len) -> u16* aloca un buffer
    /// (@c RAW_ALLOC -> malloc/override), decodifica UTF-8 -> UTF-16 (pares
    /// suplentes para code-points astrales) y lo NUL-termina.  El CALLER es
    /// dueno del buffer (transitorio para FFI; liberar o aceptar la fuga en
    /// uso efimero, como en C).
    std::string ensure_str_to_utf16_helper();
    ir::IrValueId emit_native_str_to_utf16(ir::IrValueId v_ptr,
                                           ir::IrValueId v_blen,
                                           uint32_t source_line);
    /// String Inc 5 (SSO): libera el buffer del value-string SOLO si esta
    /// en modo HEAP (la data SSO es inline, no se libera).  Branchless:
    /// RAW_FREE(ptr0 * is_heap); free(0) es no-op.  Reemplaza el patron
    /// directo RAW_FREE(LOAD ptr@0) en TODOS los sitios de liberacion de
    /// strings nativos (cleanup STRING_FREE + frees de temporales).
    void emit_native_str_free_if_heap(ir::IrValueId v_slot,
                                      uint32_t source_line);
    /// String Inc 5 (SSO): tras un MOVE de @p v_slot (la data ya se copio
    /// al destino), invalida la fuente para evitar doble-free.  Si era
    /// HEAP -> escribe ptr@0=0 (su free posterior sera no-op); si era SSO
    /// -> deja byte[0..7] intacto (es data inline; no hay buffer que
    /// liberar y su free-if-heap ya salta).  Branchless: escribe
    /// ptr@0 = old_ptr0 & (is_heap - 1)  (HEAP: &0 -> 0; SSO: &~0 -> sin
    /// cambio).
    void emit_native_str_invalidate_moved(ir::IrValueId v_slot,
                                          uint32_t source_line);
    /// String Inc 5 (SSO): zero-inicializa los 24 bytes del slot
    /// value-string (3 STORE i64 = 0).  Evita que los accesores
    /// flag-aware lean bytes no inicializados del slot (ptr@0/len@8) en
    /// modo SSO -- valgrind los marcaria como "uninitialised value" aunque
    /// el resultado enmascarado sea correcto.  Llamar tras cada ALLOCA de
    /// 24 bytes de un value-string ANTES de escribir la data.
    void emit_zero_native_str_slot(ir::IrValueId v_slot, uint32_t source_line);
    /// String Inc 5 (SSO): escribe qword2 (bytes 16..23) del slot con UN
    /// STORE i64 entero -- evita el solape parcial i64(cap)+u8(flag) que el
    /// store-forwarding del optimizer mal-resuelve al hacer el move (LOAD
    /// i64 de offset 16).  @c emit_str_meta_sso pone (len << 56): byte[23]=
    /// len, bit alto 0 (SSO), bytes 16..22 = 0.  @c emit_str_meta_heap pone
    /// (cap & 0x00FFFFFFFFFFFFFF) | (0x80 << 56): cap en bytes 16..22 (56b),
    /// byte[23]=0x80 (flag HEAP).  @p v_len_or_cap es un IrValue I64.
    void emit_str_meta_sso(ir::IrValueId v_slot, ir::IrValueId v_len,
                           uint32_t source_line);
    void emit_str_meta_heap(ir::IrValueId v_slot, ir::IrValueId v_cap,
                            uint32_t source_line);
    /// String Inc 5 (SSO): copia los 24 bytes de un value-string de
    /// @p v_src_slot a @p v_dst_slot via MEMCPY (rep movsb) en vez de 3
    /// LOAD/STORE i64.  Evita el store-forwarding del optimizer sobre
    /// qword2 (data inline + byte[23] escritos con stores parciales) que
    /// los i64 LOADs mal-resolvian (perdian la longitud SSO en el move).
    void emit_native_str_move_copy(ir::IrValueId v_dst_slot,
                                   ir::IrValueId v_src_slot,
                                   uint32_t source_line);
    /// String Inc 5 (SSO): rellena el slot value-string @p v_slot (24
    /// bytes ya alocados) a partir de unos bytes recien producidos:
    /// @p v_src_ptr (host_ptr a la fuente) + @p v_len (longitud runtime).
    /// Decide SSO vs HEAP EN RUNTIME via branch: si len <= 22 copia la
    /// data INLINE a bytes[0..len) + nul + byte[23]=len (cero malloc); si
    /// len > 22 hace RAW_ALLOC(len+1), MEMCPY, nul, set ptr@0/len@8/
    /// cap@16 + byte[23] bit alto.  Usado por concat/slice/append/interp
    /// para obtener SSO en resultados runtime cortos.  Solo native_poo_.
    /// @p known_len >= 0 (Tier B str_make): la longitud es constante en
    /// compile-time -> decide SSO/HEAP SIN rama runtime (emite solo el cuerpo
    /// aplicable).  -1 = longitud runtime (rama CMP_GT como antes).
    void build_native_string_finalize(ir::IrValueId v_slot,
                                      ir::IrValueId v_src_ptr,
                                      ir::IrValueId v_len, uint32_t source_line,
                                      int64_t known_len = -1);
    /// str_make optimo (Vesta Embed): COPIA @p v_len bytes de @p v_ptr a un
    /// value-string PROPIO (slot 24B + buffer; RAII lo libera).  Sin GC.
    /// @p known_len >= 0 -> especializa (Tier B sin rama).  Solo native_poo_.
    ir::IrValueId build_native_string_from_buffer(ir::IrValueId v_ptr,
                                                  ir::IrValueId v_len,
                                                  uint32_t source_line,
                                                  int64_t known_len = -1);
    /// Vesta Embed Inc 1: concatena dos value-strings nativos @p v_a y
    /// @p v_b produciendo un NUEVO string owned (slot de 24 bytes en
    /// stack + buffer fresco en heap de total+1 bytes con ambos
    /// contenidos copiados y nul final).  Devuelve el PTR al slot
    /// resultado; el caller registra su STRING_FREE (es owned).  Solo
    /// en @c native_poo_.  @p v_a / @p v_b son PTR a slots value-string;
    /// no se consumen (el concat copia sus bytes).
    ir::IrValueId build_native_string_concat(ir::IrValueId v_a,
                                             ir::IrValueId v_b,
                                             uint32_t source_line);
    /// String Inc 3 (native_poo_): slice `s[a..b]` -> NUEVO string owned
    /// = copia de los bytes [a, b) del value-string @p v_src.  @p v_lo /
    /// @p v_hi son IrValue I64 (limites a y b).  @p inclusive=true para
    /// `s[a..=b]` (longitud b-a+1).  Aloca slot de 24 bytes en stack +
    /// buffer fresco en heap de (len+1) bytes, MEMCPY (rep movsb) de
    /// [src.ptr+a] por len bytes, nul-termina y rellena ptr/len/cap.  El
    /// caller registra su STRING_FREE (es owned).  v1 asume indices
    /// validos (a <= b <= src.len); negativos no soportados.
    ir::IrValueId build_native_string_slice(ir::IrValueId v_src,
                                            ir::IrValueId v_lo,
                                            ir::IrValueId v_hi, bool inclusive,
                                            uint32_t source_line);
    /// String Inc 3 (native_poo_): indexado simple `s[i]` -> el CHAR
    /// (byte) en la posicion @p v_idx del value-string @p v_src.  Carga
    /// el ptr@0 del slot y emite LOAD u8 de [ptr+i].  Devuelve un U8
    /// zero-extended (0-255).  v1 asume i valido (0 <= i < src.len).
    ir::IrValueId build_native_string_index_char(ir::IrValueId v_src,
                                                 ir::IrValueId v_idx,
                                                 uint32_t source_line);
    /// Copia @p v_len bytes desde @p src_base a @p dst_base con un loop de
    /// PALABRA: cuerpo principal de 8 bytes por iteracion (LOAD/STORE i64)
    /// mas un loop de cola para los <8 bytes restantes (LOAD/STORE u8).
    /// ~8x menos iteraciones que el copiado byte-a-byte sin necesitar
    /// registros fijos (rep movsb) -> cero riesgo en el regalloc.  Todas
    /// las ops son PURE_NATIVE (LOAD/STORE/ADD/SUB/CMP/BR) por lo que el
    /// codegen vreg-native (HOST_LEAF) las soporta y el interp/Full siguen
    /// funcionando.  @p src_base / @p dst_base son host_ptr; @p v_len es
    /// un IrValue I64 (>= 0).
    void emit_word_copy_loop(ir::IrValueId dst_base, ir::IrValueId src_base,
                             ir::IrValueId v_len, uint32_t source_line);

    // --- Vesta Embed Inc 2: mutacion += + interpolacion (solo native_poo_) ---
    /// Append in-place de @p v_app_len bytes (en @p v_app_ptr, host) al
    /// value-string cuyo slot {ptr,len,cap} apunta @p v_dst_slot.  Crece
    /// el buffer si la capacidad es insuficiente (RAW_ALLOC nuevo de
    /// new_len+1, MEMCPY de lo viejo, RAW_FREE del viejo, actualiza
    /// ptr@0/cap@16), copia los bytes nuevos al final, actualiza len@8 y
    /// nul-termina.  El slot se muta in-place (es owned mutable); NO
    /// crea slot nuevo.  Usado por `s += t` y por la interpolacion
    /// native.  Solo en @c native_poo_.  @p v_app_ptr / @p v_app_len no
    /// se consumen.
    void build_native_string_append_inplace(ir::IrValueId v_dst_slot,
                                            ir::IrValueId v_app_ptr,
                                            ir::IrValueId v_app_len,
                                            uint32_t source_line);
    /// Vesta Embed Inc 2: construye un value-string owned a partir de un
    /// literal interpolado @p slit ("texto ${a} mas ${b}").  Concatena las
    /// partes literales con cada @c ${expr} convertido a texto INLINE
    /// (string -> bytes directos, char -> 1 byte, int -> itoa decimal por
    /// div/mod, bool -> "true"/"false").  Devuelve el PTR al slot del
    /// value-string resultado (owned; el caller registra STRING_FREE).
    /// Solo en @c native_poo_.
    ir::IrValueId build_native_string_interp(ast::StringLitExpr *slit);
    /// Vesta Embed Inc 2: escribe en @p v_buf (host, >= 24 bytes) la
    /// representacion decimal ASCII de @p v_val (un I64).  @p is_signed
    /// controla el manejo del signo (emite '-' si negativo).  Devuelve el
    /// IrValue I64 con la longitud escrita (sin nul).  itoa INLINE via
    /// loop div/mod por 10 + inversion -- sin helper nativo (AOT bare no
    /// tiene plugin).  Solo en @c native_poo_.
    ir::IrValueId emit_native_itoa_to_buf(ir::IrValueId v_buf,
                                          ir::IrValueId v_val, bool is_signed,
                                          uint32_t source_line);
    /// Vesta Embed Inc 2: garantiza que el helper itoa nativo
    /// @c __vx_itoa_s (signed) / @c __vx_itoa_u (unsigned) este emitido
    /// como funcion IR independiente en @c out_mod_ (una sola vez por
    /// modulo y signedness).  Firma: @c (u8* buf, i64 val) -> i64 len.
    /// El cuerpo es el itoa de @c emit_native_itoa_to_buf, pero como
    /// funcion separada con loops -> el optimizer NO lo foldea cuando el
    /// argumento es una constante (el const-fold mid-expression del itoa
    /// INLINE producia longitudes erroneas).  Por tener varios bloques
    /// (loops) el inliner tampoco lo re-inlinea (is_inlineable exige 1
    /// bloque).  Devuelve el nombre del helper.  Solo en @c native_poo_.
    std::string ensure_itoa_helper(bool is_signed);
    /// Flags: el helper itoa signed/unsigned ya esta emitido en este
    /// modulo (indice 0=unsigned, 1=signed).  Evita duplicar la funcion.
    bool itoa_helper_emitted_[2] = {false, false};
    /// Vesta Embed Inc 2: helper bool->string nativo
    /// @c i64 __vx_btoa(u8* buf, i64 b): escribe "true" (4) o "false"
    /// (5) en @p buf y devuelve la longitud.  Como funcion APARTE con
    /// branch -> evita el const-fold mid-expression del append condicional.
    /// Devuelve el nombre del helper.  Solo en @c native_poo_.
    std::string ensure_btoa_helper();
    bool btoa_helper_emitted_ = false; ///< El helper btoa ya esta emitido.
    /// BUG-3 (`${cp:char}` en construccion native/AOT): helper codepoint ->
    /// UTF-8.  Firma @c i64 __vx_ctoa(u8* buf, i64 cp): escribe la
    /// codificacion UTF-8 (1..4 bytes) del codepoint en @p buf y devuelve la
    /// longitud.  Paridad byte-exacta con @c vio_char_to_vmbuf (interp/JIT).
    /// Solo en @c native_poo_.
    std::string ensure_ctoa_helper();
    bool ctoa_helper_emitted_ = false; ///< El helper ctoa ya esta emitido.
    /// Vesta Embed Inc 4: helper de comparacion lexicografica de strings
    /// value-type nativos.  Firma:
    /// @c i64 __vx_strcmp(u8* pa, i64 la, u8* pb, i64 lb).
    /// Devuelve -1/0/1 (memcmp + tie-break por longitud: a la izquierda
    /// del primer byte distinto decide; si un prefijo coincide, el mas
    /// corto es menor).  Como funcion APARTE con loop -> el optimizer no
    /// foldea la comparacion byte-a-byte mid-expression con operandos
    /// constantes (mismo motivo que itoa/btoa) y el inliner no la re-inlinea
    /// (is_inlineable exige 1 bloque).  Devuelve el nombre.  Solo en
    /// @c native_poo_.
    std::string ensure_strcmp_helper();
    bool strcmp_helper_emitted_ = false;  ///< El helper strcmp ya esta emitido.
    bool strdata_helper_emitted_ = false; ///< El helper __vx_strdata emitido.
    bool strlen_helper_emitted_ = false;  ///< El helper __vx_strlen emitido.
    bool str_cplen_helper_emitted_ =
        false; ///< El helper __vx_str_cplen emitido.
    bool str_to_utf16_helper_emitted_ = false; ///< __vx_str_to_utf16 emitido.

    /// CPU dispatch (cimiento): asegura que existan el global
    /// @c __vx_cpu_features (slot @c static_data de 8 bytes zero-init) y el
    /// helper @c __vx_cpu_init() que ejecuta @c cpuid al arranque y empaqueta
    /// un bitmask de features en ese slot.  Devuelve el indice del slot del
    /// global (para que @c cpu_features() lo lea via STR_LIT_ADDR + LOAD).
    /// Idempotente.  Solo en @c native_poo_ (AOT Bare/Embed): usa INLINE_ASM
    /// que es PURE_NATIVE.  El bitmask: bit0=SSE2 bit1=SSE4.2 bit2=POPCNT
    /// bit3=AVX bit4=AVX2 bit5=BMI1 bit6=BMI2 bit7=AVX512F bit8=ERMS.
    uint64_t ensure_cpu_features_global();
    bool cpu_init_emitted_ = false; ///< El helper __vx_cpu_init ya emitido.
    bool cpu_features_used_ =
        false; ///< Algun cpu_features() se uso -> wirear init en main.
    uint64_t cpu_features_slot_ =
        UINT64_MAX; ///< Slot static_data del global (UINT64_MAX = sin crear).
    bool cpu_dispatch_used_ =
        false; ///< Se uso ALGUN helper multi-versionado (memcpy dispatch) ->
               ///< wirear __vx_cpu_init en main aunque no se llame
               ///< cpu_features() (el init setea los fp).

    /// CPU dispatch (Inc 2): mecanismo de despacho por TABLA DE PUNTEROS.
    /// Asegura el global @c __vx_memcpy_fp (slot @c static_data de 8 bytes,
    /// seccion ".data") + las dos variantes @c __vx_memcpy_base (rep movsb,
    /// segura) y @c __vx_memcpy_avx2 (AVX2 32B + cola byte-a-byte).  El helper
    /// @c __vx_cpu_init setea el fp a la mejor variante segun el bit AVX2.
    /// Devuelve el indice del slot del global @c __vx_memcpy_fp.  Idempotente.
    /// Solo en @c native_poo_ (AOT).  Marca @c cpu_dispatch_used_.
    uint64_t ensure_memcpy_dispatch();
    bool memcpy_helpers_emitted_ =
        false; ///< Las variantes + el global fp ya estan emitidos.
    uint64_t memcpy_fp_slot_ =
        UINT64_MAX; ///< Slot static_data del global __vx_memcpy_fp.

    /// AUTO multiversion (--float-isa auto): si @c main tiene ops VEC_*, lo
    /// renombra a @c __vx_main_body (helper VEC normal que el driver compila
    /// 3x: $sse2/$avx2/$avx512) y sintetiza un @c main fino que (a) corre los
    /// inits y (b) hace @c CALLIND a traves del slot @c __vx_main_body$fp.
    /// Asi "multiversionar main" se reduce a "despachar un helper", sin tratar
    /// el entry como caso especial.  Construye ademas @c __vx_auto_init() que
    /// elige la variante por cpuid (AVX512F bit7 > AVX2 bit4 > SSE2) y la
    /// guarda en el fp.  Idempotente.  Solo @c native_poo_ + @c aot_auto_vec_.
    /// Marca @c cpu_dispatch_used_ + @c auto_dispatch_emitted_ para que
    /// @c run() prepone @c call __vx_auto_init al entry de main.
    void ensure_auto_multiversion(ir::IrModule &out_module);
    bool auto_dispatch_emitted_ =
        false; ///< El main sintetico + fp + __vx_auto_init ya se emitieron.

    /// Emite un memcpy(dst, src, len) DESPACHADO por la tabla de punteros:
    /// LOAD el fp del global + CALLIND.  Solo @c native_poo_.  En interp/JIT/
    /// Full el caller usa MEMCPY inline (rep movsb), sin cambio.
    void emit_memcpy_dispatched(ir::IrValueId dst, ir::IrValueId src,
                                ir::IrValueId len, uint32_t line);

    /// CPU dispatch Inc 5a: despacho de strcmp/strlen via tabla de punteros,
    /// foundation para que una libreria stdlib provea variantes SIMD via
    /// @HelperOverride.  Asegura (idempotente, una sola vez):
    ///   - global @c __vx_strcmp_fp (slot 8 B en ".data").
    ///   - global @c __vx_strlen_fp (slot 8 B en ".data").
    ///   - los helpers BASELINE @c __vx_strcmp_base / @c __vx_strlen_base
    ///     (la impl escalar del compilador; el dispatch los usa por defecto y
    ///     son llamables por nombre desde Vesta para que un override delegue).
    ///   - el helper @c __vx_strdisp_init() que setea ambos fp (override del
    ///     usuario si existe, si no el baseline).  El compilador NO hace cpuid
    ///     aqui: el default es baseline; la SIMD vendra de la lib importada.
    /// Marca @c cpu_dispatch_used_ para que @c run() prepone el init en main.
    /// Solo en @c native_poo_ (AOT).
    void ensure_strdisp();
    bool strdisp_emitted_ =
        false; ///< Los fp + baselines + init ya estan emitidos.
    uint64_t strcmp_fp_slot_ =
        UINT64_MAX; ///< Slot static_data del global __vx_strcmp_fp.
    uint64_t strlen_fp_slot_ =
        UINT64_MAX; ///< Slot static_data del global __vx_strlen_fp.

    /// Emite strcmp(pa, la, pb, lb) -> i64 (-1/0/1) DESPACHADO por la tabla de
    /// punteros (LOAD __vx_strcmp_fp + CALLIND).  Solo @c native_poo_.
    ir::IrValueId emit_strcmp_dispatched(ir::IrValueId pa, ir::IrValueId la,
                                         ir::IrValueId pb, ir::IrValueId lb,
                                         uint32_t source_line);

    // --- Reflexion / meta-OOP /  Z extras ---
    ir::IrValueId emit_findmethod(ir::IrValueId v_params, uint32_t line);
    ir::IrValueId emit_findfield(ir::IrValueId v_params, uint32_t line);
    ir::IrValueId emit_findclass(ir::IrValueId v_params, uint32_t line);
    ir::IrValueId emit_defclass(ir::IrValueId v_params, uint32_t line);
    void emit_deffield(ir::IrValueId v_cls, ir::IrValueId v_params,
                       uint32_t line);
    void emit_defmethod(ir::IrValueId v_cls, ir::IrValueId v_params,
                        uint32_t line);
    void emit_addadvice(ir::IrValueId v_target, ir::IrValueId v_advice,
                        uint64_t kind, uint32_t line);

    // --- GC primitives /  Z atomics ---
    ir::IrValueId emit_gc_allocp(ir::IrValueId v_size, uint32_t line);
    ir::IrValueId emit_gc_promote(ir::IrValueId v_src, uint32_t line);
    ir::IrValueId emit_gc_demote(ir::IrValueId v_src, uint32_t line);
    // wt = ancho del atomico (1/2/4/8 bytes via IrType).  Default I64 (8 bytes)
    // para los builtins Z.8 originales; los genericos pasan el tipo del
    // pointee.
    ir::IrValueId emit_atomic_ld_i64(ir::IrValueId v_addr, uint32_t line,
                                     ir::IrType wt = ir::IrType::I64);
    void emit_atomic_st_i64(ir::IrValueId v_addr, ir::IrValueId v_val,
                            uint32_t line, ir::IrType wt = ir::IrType::I64);
    ir::IrValueId emit_atomic_cas_i64(ir::IrValueId v_addr, ir::IrValueId v_exp,
                                      ir::IrValueId v_des, uint32_t line,
                                      ir::IrType wt = ir::IrType::I64);
    ir::IrValueId emit_atomic_add_i64(ir::IrValueId v_addr,
                                      ir::IrValueId v_delta, uint32_t line,
                                      ir::IrType wt = ir::IrType::I64);

    // --- Static fields + AOP proceed + Async fusion + Intrinsics ---
    ir::IrValueId emit_getstatic(ir::IrValueId v_cls, uint64_t offset,
                                 uint32_t line);
    void emit_setstatic(ir::IrValueId v_cls, ir::IrValueId v_val,
                        uint64_t offset, uint32_t line);
    ir::IrValueId emit_proceed(uint32_t line);
    ir::IrValueId emit_getpid(uint32_t line);
    ir::IrValueId emit_getargc(uint32_t line);
    ir::IrValueId emit_getarg(ir::IrValueId v_idx, uint32_t line);
    void emit_fulfill_hlt(ir::IrValueId v_fut, ir::IrValueId v_val,
                          uint32_t line);

    // --- Lowering helpers para expresiones nuevas ---
    ir::IrValueId lower_try_expr(ast::TryExpr *e);
    ir::IrValueId lower_super_call_expr(ast::SuperCallExpr *e);
    ir::IrValueId lower_super_method_call_expr(ast::SuperMethodCallExpr *e);

    /// Mapa de variables locales tipo `Class` cuyo origen es un
    /// `Class.forName("X")` con literal X.  Permite que el lowering
    /// de `cls.newInstance()` detecte la clase concreta en compile
    /// time y emita `new X()` (que SI llama al constructor via
    /// `__new_<X>` synthetic) en lugar del NEWOBJ raw que no llama
    /// al ctor.  Coste: cero (el helper `__new_<X>` ya existia).
    ///
    /// Llave: nombre del local Class.  Valor: nombre de la clase X
    /// que el local apunta.  Las re-asignaciones desde fuentes no
    /// trackeable (e.g. `cls = otroFn()`) borran la entrada.
    std::unordered_map<std::string, std::string> class_origin_of_local_;

    /// Mapa SSA value -> clase concreta cuando el valor proviene de un
    /// @c new Class() (o cadena MOV/PHI desde ese origen).  Permite
    /// devirtualizar en tiempo de compilacion las llamadas via
    /// interface receiver cuando el tipo concreto es estaticamente
    /// conocido: el dispatch baja a CALLVIRT directo con el vtable_idx
    /// del metodo en la CLASE concreta, sin necesidad del trio
    /// findclass+findmethod+callm runtime.
    ///
    /// Coste: cero runtime; ~50 LOC en el lowering para mantenerlo.
    /// Beneficio: tanto port C como JIT obtienen output devirtualizado
    /// para el caso comun de `Iface x = new Impl(); x.metodo()`.
    ///
    /// Llave: IrValueId.  Valor: nombre de clase concreta.  Vacio = no
    /// se conoce el tipo concreto estatico.
    std::unordered_map<ir::IrValueId, std::string> ssa_concrete_class_;

    /// Modo de instrumentacion: "none", "trace", "profile".  Cuando
    /// no es "none", el lowering envuelve cada funcion usuario con
    /// CALLs a @c vx_trace:enter y @c vx_trace:exit (o equivalente).
    std::string instrument_mode_ = "none";
    ///  AOT.2.b: modo POO nativa (sin runtime VM).  Ver set_native_poo.
    bool native_poo_ = false;
    /// Multihilo AOT: true si esta funcion (o el modulo) uso `spawn { }` que
    /// bajo a un hilo real (__vx_thread_run).  Al lowerar `main` con este flag,
    /// se inyecta CALL __vx_thread_join_all() antes de su RET (join-all
    /// implicito).
    bool vx_thread_used_ = false;
    /// Bits del target para validar el inline-asm (@Naked/asm{}); 64 por
    /// defecto.
    uint8_t asm_target_bits_ = 64;
    /// Ancho del chunk SIMD del vectorizador en AOT (16/32/64 bytes); 16
    /// default.
    uint8_t aot_vec_width_ = 16;
    /// --float-isa auto: chunk dual para multiversion (ver set_aot_auto_vec).
    bool aot_auto_vec_ = false;
    /// Type matching de catch (AOT): por cada clase, su intervalo DFS [lo,hi]
    /// sobre el bosque de herencia.  is-a(A,B) <=> B.lo <= A.lo <= B.hi.  El
    /// throw transporta A.lo; cada catch(B) compara contra [B.lo,B.hi]
    /// (constantes en compile-time).  Vacio fuera de native_poo_.
    std::unordered_map<std::string, std::pair<uint32_t, uint32_t>>
        type_intervals_;
    /// Computa @c type_intervals_ via DFS del bosque de clases (super_name).
    void compute_type_intervals();
    /// Solo-LSP: bajar comptime fns (no-macro) a IR para inspeccion.
    bool emit_comptime_fns_ = false;
    /// C-3: nombres de los override del string built-in (vacios => default).
    std::string string_concat_override_;
    std::string string_eq_override_;
    /// @SyncImpl: nombres de las fns override de monitor enter/exit (vacios
    /// => default por tier).  Ver @c set_sync_impl_overrides.
    std::string sync_enter_override_;
    std::string sync_exit_override_;
    /// CPU dispatch Inc 4: fn libre @HelperOverride(memcpy) (vacio => sin
    /// override; el fp se elige por cpuid en __vx_memcpy_init).
    std::string memcpy_override_;
    /// CPU dispatch Inc 5a: fn libre @HelperOverride(strcmp) / (strlen)
    /// (vacio => sin override; el fp apunta al baseline en __vx_strdisp_init).
    std::string strcmp_override_;
    std::string strlen_override_;

    /// C-3: emite una CALL a una funcion libre override del string
    /// built-in (@StringConcat / @StringEq).  @p lhs / @p rhs son las
    /// expresiones operando; se materializan al repr `string` adecuado
    /// (StringObject handle i64 en Full, PTR a value-string en native).
    /// @p ret_ir es el tipo IR de retorno (I64 para concat, BOOL para eq).
    /// @p negate niega el resultado bool (para `!=` sobre @StringEq).
    /// Devuelve el IrValueId del resultado, o IR_NO_VALUE en error.
    ir::IrValueId emit_string_override_call(const std::string &fn_name,
                                            ast::Expr *lhs, ast::Expr *rhs,
                                            ir::IrType ret_ir, bool negate,
                                            uint32_t source_line);

    /// Helper: emite CALLN sintetica a @c "vx_trace:enter" con
    /// argumento puntero al string literal del nombre de la funcion.
    /// Usa @c out_mod_->intern_static_data para internar el nombre.
    void emit_instrument_enter(const std::string &fn_name, uint32_t line);

    /// Helper: emite CALLN sintetica a @c "vx_trace:exit" con
    /// argumentos (fn_name_ptr, return_value).  Si @c v_ret es
    /// @c IR_NO_VALUE (funcion void), se pasa @c 0.
    void emit_instrument_exit(const std::string &fn_name, ir::IrValueId v_ret,
                              uint32_t line);

    /// Spill slots activos durante el body y catches de un try.
    /// Para cada variable del scope outer que se asigna dentro del try,
    /// reservamos un slot (8 bytes en stack) y mantenemos un STORE
    /// duplicado en cada @c write_local.  El @c throw salta sin pop
    /// pero el slot vive en stack VM mas alla del rsp restore.  En el
    /// merge_bb hacemos LOAD del slot y bindeamos el nombre al SSA
    /// resultante -- asi el valor visible tras el try es siempre el
    /// ultimo escrito (body o catch) sin importar registros corruptos.
    ///
    /// Estructura: name -> SSA value PTR del slot.  Vacio fuera de un
    /// try.  El lower_try lo llena pre-body, lo limpia post-merge.
    std::unordered_map<std::string, ir::IrValueId> try_spill_slots_;

    /// stack de acciones de cleanup activas en el flujo actual.
    /// Cada entrada es codigo RAW_ASM que debe ejecutarse al SALIR del
    /// scope que la registro (sea por flujo normal, return o break).
    /// Lo usa @c synchronized para emitir @c tryleave + @c monexit
    /// cuando el body hace @c return temprano.  Las excepciones NO
    /// pasan por aqui: las maneja el @c tryenter+handler clasico.
    ///
    /// Pila LIFO: el cleanup mas reciente se ejecuta primero (orden
    /// inverso a su registro).  @c emit_cleanups_all() recorre la
    /// pila de tope a fondo, emitiendo cada bloque RAW_ASM en el
    /// bloque actual sin modificar el stack (para que el caller que
    /// abrio el scope haga su pop normal).
    struct CleanupAction {
        /// tipo de accion:
        ///   RAW_ASM: emitir un bloque @c IrOp::RAW_ASM con @c asm_text y
        ///            @c operands.  El regalloc trata el bloque como
        ///            opaco (no preserva regs caller-saved), asi que es
        ///            adecuado solo para cleanups que NO clobreen regs
        ///            de valores vivos del scope (e.g. monexit).
        ///   CALL_DTOR: emitir un @c IrOp::CALLVIRT real que el regalloc
        ///              trata como CALL normal (preserva los regs vivos
        ///              automaticamente).  Necesario para destructores
        ///              de clase y auto-free de colecciones cuando hay
        ///              valor de retorno vivo en el RET (lower_return
        ///              spills regs al stack alrededor del cleanup).
        ///   CALLN_FREE: emitir un @c IrOp::CALLN para liberar una
        ///               coleccion primitiva.  Usa @c func_name para el
        ///               nombre del simbolo nativo y @c needs_proc para
        ///               decidir si emite GETPROC + lo prepende como
        ///               primer argumento (variantes @c *_free_gc del
        ///               plugin de colecciones GC-aware).
        ///               El regalloc trata el CALLN como cualquier call,
        ///               preservando regs caller-saved automaticamente.
        ///   SMARTPTR_FREE: libera un @c unique<T> al exit del scope.
        ///                  Sigue el patron: cargar ptr del slot stack,
        ///                  saltar si es 0 (moved), invocar deleter
        ///                  literal (free, fclose, ~T()).  Para Tier 0
        ///                  el deleter es CALLN a @c free.  Para Tier 1
        ///                  con deleter custom usa el field +8 del slot.
        ///   SHAREDPTR_REL: decremento del refcount de un @c shared<T> al
        ///                  exit del scope.  Si llega a 0 invoca el
        ///                  deleter sobre payload (ctrl_block + 16).
        enum class Kind {
            RAW_ASM,     ///< Cleanup opaco (no preserva regs caller-saved).
            CALL_DTOR,   ///< CALLVIRT real al destructor de la clase.
            STRUCT_DTOR, ///< CALL directo al destructor de un STRUCT value-type
                         ///< (`<Struct>__dtor(addr)`).  Sin vtable: dispatch
                         ///< estatico.  Inlineable (un dtor trivial cuesta ~0
                         ///< tras el inliner).  Se registra solo si el struct
                         ///< tiene `~Struct()` y NO escapa (move-on-return /
                         ///< store suprime el cleanup via escaping_locals_).
            CALLN_FREE, ///< CALLN a libreria nativa (e.g. free de colecciones).
            SMARTPTR_FREE, ///< Liberar @c unique<T> al exit del scope.
            SHAREDPTR_REL, ///< Decrementar refcount de @c shared<T>.
            SYNC_EXIT, ///< Exit de @c synchronized {} : TRYLEAVE + MONEXIT como
                       ///< IR ops.
            NATIVE_FREE, ///<  AOT.2.b: RAW_FREE(obj) de una instancia de
                         ///< clase NATIVA (calloc) al exit del scope (RAII; sin
                         ///< GC). aot_lower lo convierte en call<free>.  Sin
                         ///< dangling.
            STRING_FREE, ///< Vesta Embed Inc 0: liberar el buffer de un
                         ///< string value-type (native_poo_) al exit del
                         ///< scope.  operands[0] = PTR al slot de 24 bytes
                         ///< {ptr,len,cap}.  Emite LOAD ptr@[slot+0] +
                         ///< RAW_FREE(ptr) (aot_lower -> call free; free(0)
                         ///< es no-op tras un move, sin doble-free).
            CLOSURE_ENV_FREE ///< Ownership: liberar el env+slot heap de los
                             ///< campos closure (lambda con captura) de un
                             ///< struct value-type que recibio su valor por
                             ///< move (init desde una call que retorna un
                             ///< struct con closure escapado).  operands[0] =
                             ///< PTR al struct (refresh por refresh_name); @c
                             ///< closure_field_offsets lista los offsets de los
                             ///< campos fn.  Emite, por campo, la misma
                             ///< secuencia que @c emit_free_closure_env_field
                             ///< (null-guard, free env + slot).  Sin GC; un
                             ///< solo free porque el productor suprime su
                             ///< cleanup (move-on-return via escaping_locals_).
        };
        Kind kind = Kind::RAW_ASM;
        // --- Comun ---
        std::vector<ir::IrValueId> operands; ///< valores SSA referenciados
        uint32_t source_line;
        /// si != "", @c emit_cleanups_all hace @c lookup(refresh_name)
        /// y reemplaza @c operands[0] con el SSA value ACTUAL del binding.
        std::string refresh_name;
        // --- RAW_ASM ---
        std::string asm_text; ///< plantilla con {src0..}
        // --- CALL_DTOR ---
        uint32_t dtor_vtable_index = 0;
        // --- NATIVE_FREE (AOT.2.d): dtor polimorfico ---
        /// @c true si la clase estatica tiene vtable y el dtor es virtual:
        /// el cleanup despacha @c ~T() por la vtable de la instancia (LOAD
        /// vtable de obj[0] + LOAD fn[idx] + CALLIND) en vez de un CALL
        /// directo al dtor estatico -> una ref base que posee una instancia
        /// derivada (@c Base b = new Derived()) ejecuta el dtor DERIVADO.
        bool native_dtor_virtual = false;
        // --- SMARTPTR_FREE con inner GC class (e.g. @c unique<Resource>) ---
        /// @c true si el contenido apunta a un objeto GC (no a memoria
        /// RAW_ALLOC).  Cuando se setea, el cleanup invoca el destructor
        /// del inner via @c CALLVIRT (@c inner_dtor_vtable_index) y NO
        /// hace @c RAW_FREE del host_ptr (rompedria el heap GC).
        bool inner_is_gc_class = false;
        /**
         * @brief Si el tipo contenido tiene destructor.
         *
         * Hace falta porque el INDICE no puede decirlo: cero es un indice de
         * tabla perfectamente valido -- el del primer metodo --.  Se uso como
         * "no hay" y el resultado era que una clase cuyo destructor caia el
         * primero perdia su limpieza en silencio.  Y caia el primero justo
         * cuando la clase no declaraba constructor, que es el caso mas comun
         * de todos.
         */
        bool inner_has_dtor = false;
        /// Indice en la vtable del destructor del tipo contenido.  Solo vale
        /// si @c inner_has_dtor; cero es un indice como cualquier otro.
        uint32_t inner_dtor_vtable_index = 0;
        /// Nombre IR del destructor del tipo contenido (@c <Class>____dtor),
        /// para CALL DIRECTO en native_poo (AOT) cuando el inner NO es
        /// polimorfico (tipo estatico == dinamico para @c unique<T>).
        std::string inner_dtor_func_name;
        /// @c true si el inner es polimorfico (tiene vtable): el dtor debe
        /// despacharse por la vtable de la instancia, no por el tipo estatico.
        bool inner_dtor_virtual = false;
        // --- CALLN_FREE / SMARTPTR_FREE / SHAREDPTR_REL ---
        std::string func_name;   ///< "lib:symbol" para CALLN
        bool needs_proc = false; ///< prepend GETPROC
        // --- SMARTPTR_FREE / SHAREDPTR_REL ---
        /// SSA value del PTR al slot del smart pointer (donde vive el ptr).
        /// Usado para LOAD del valor actual y CMP_EQ 0 (skip si moved).
        ir::IrValueId slot_addr = 0;
        /// Nombre del deleter.  Tres formatos:
        ///   "free"                  -> emite IrOp::RAW_FREE directo
        ///                              (deleter por defecto de unique_box).
        ///   "<vesta_fn_name>"       -> emite CALLVM @Method al simbolo
        ///                              Vesta declarado por el usuario.
        ///                              Cero overhead: 1 LOAD + 1 CALLVM.
        ///   "@extern:<lib>:<fn>"    -> emite CALLN al simbolo nativo
        ///                              de la libreria.  El prefijo "@extern:"
        ///                              discrimina extern vs Vesta.
        std::string literal_deleter;
        /// Tamano del slot del smart pointer (8 para Tier 0).
        uint32_t slot_size = 8;
        /// --- CLOSURE_ENV_FREE ---
        /// Offsets (en bytes) de los campos closure (fn con captura) del
        /// struct a liberar al exit del scope.
        std::vector<uint32_t> closure_field_offsets;
    };
    std::vector<CleanupAction> cleanup_stack_;

    /**
     * @brief Bajar un cuerpo en OTRA funcion, y volver donde se estaba.
     *
     * Varias cosas del lenguaje se bajan a una funcion aparte -- el cuerpo de
     * un `spawn`, el de una lambda, el constructor sintetico de una clase --.
     * Para eso hay que apuntar el bajador a la funcion nueva, bajar, y devolver
     * TODO como estaba: en que funcion se emite, en que bloque, si ese bloque
     * ya termino, que nombres son que valores, cuales tienen la direccion
     * tomada, cuales llevan un puntero del anfitrion y que queda por soltar.
     *
     * Siete cosas, y estaban guardadas y restauradas a mano en SEIS sitios.
     * Olvidarse de una no da error: deja al bajador emitiendo en la funcion
     * equivocada, o creyendo que un nombre es otro valor.  De hecho una se
     * olvidaba -- la de los punteros del anfitrion se limpiaba al entrar y no
     * se devolvia al salir --; no se ha conseguido convertir eso en un fallo
     * observable, pero tampoco tenia por que estar ahi.
     *
     * Se construye, se apunta a la funcion hija, se baja, y al cerrarse la
     * llave todo vuelve solo.
     */
    class ChildFunctionScope {
      public:
        /**
         * @brief Guarda el contexto del padre y lo deja limpio para el hijo.
         *
         * @param lo El bajador cuyo contexto se guarda.
         */
        explicit ChildFunctionScope(Lowering &lo);

        /// @brief Devuelve el contexto del padre tal y como estaba.
        ~ChildFunctionScope();

        ChildFunctionScope(const ChildFunctionScope &) = delete;
        ChildFunctionScope &operator=(const ChildFunctionScope &) = delete;

        /**
         * @brief La funcion en la que se estaba emitiendo antes.
         *
         * Hace falta porque alguna de estas bajadas mira valores del padre
         * mientras construye el hijo -- lo que el `spawn` captura, por
         * ejemplo --.
         *
         * @return La funcion del padre.
         */
        ir::IrFunction *parent_fn() const { return fn_; }

      private:
        Lowering &lo_;        ///< A quien se le devuelve el contexto.
        ir::IrFunction *fn_;  ///< En que funcion se emitia.
        ir::IrBlockId block_; ///< En que bloque.
        bool terminated_;     ///< Si ese bloque ya habia terminado.
        std::vector<std::unordered_map<std::string, ir::IrValueId>> scopes_;
        std::unordered_set<std::string> addr_taken_; ///< Con direccion tomada.
        std::unordered_set<std::string>
            host_bearing_;                    ///< Con puntero del host.
        std::vector<CleanupAction> cleanups_; ///< Lo que queda por soltar.

        /**
         * @name Como termina la funcion en la que se estaba
         *
         * COMO se sale de una funcion es propio de ESA funcion: si devuelve un
         * valor grande por un hueco que le presta quien la llama, si es el
         * cuerpo de una asincrona y cada salida resuelve un futuro, si es un
         * proceso que en vez de retornar para.  La hija no hereda nada de eso,
         * y por eso el guarda lo pone a cero al entrar.
         *
         * Estaba fuera del guarda y a mano: tres sitios guardaban el hueco del
         * valor grande, dos guardaban cada uno su bandera, y los demas no
         * guardaban nada.  Con lo cual una lambda escrita dentro del cuerpo de
         * un proceso salia PARANDO EL PROCESO en vez de volviendo a quien la
         * llamo -- son las mismas llaves, pero no es la misma funcion --.
         * @{
         */
        bool sret_active_;           ///< Si devolvia por hueco prestado.
        ir::IrValueId sret_retbuf_;  ///< Cual era ese hueco.
        uint64_t sret_buf_size_;     ///< Cuanto medía.
        bool returns_function_;      ///< Si devolvia una funcion.
        ir::IrValueId async_fut_id_; ///< El futuro que resolvia al salir.
        bool is_rspawn_body_;        ///< Si era un proceso en otro nodo.
        bool is_spawn_body_;         ///< Si era un proceso de aqui.
        /** @} */
    };
    /// Contador para etiquetas unicas en cleanups que emiten labels
    /// (smart pointer cleanups con branches internos).  Cada invocacion
    /// de emit_cleanups consume el siguiente valor; garantiza que dos
    /// cleanups no colisionen en el mismo label dentro de la misma
    /// funcion (caso comun: 2 vars unique<T> en el mismo scope).
    uint32_t cleanup_label_seq_ = 0;
    /// Canal compartido entre @c try_lower_builtin_call (unique_with /
    /// shared_with) y @c lower_var_decl para pasar el nombre del deleter
    /// custom al cleanup pendiente.  Vacio = usar el deleter por
    /// defecto ("free").  Se limpia tras consumirse en lower_var_decl.
    std::string pending_smartptr_deleter_;
    /// Deleter ESTATICO por variable @c unique<T> local.  Permite resolver el
    /// cleanup de un `move(a)` a una llamada DIRECTA al deleter concreto de `a`
    /// (free / <fn_label> / @extern:...) en vez de un dispatch dinamico que lee
    /// el slot+8 en runtime.  Clave = nombre de la variable; valor = mismo
    /// formato que @c CleanupAction::literal_deleter ("free", "<fn>",
    /// "@extern:<lib>:<fn>").  Ausente = deleter desconocido (p.ej. la variable
    /// vino de una factory opaca) -> el move cae a dispatch dinamico.
    std::unordered_map<std::string, std::string> unique_var_deleter_;
    /// Ownership: cuando un @c unique<T> se asigna a un CAMPO (de clase o
    /// struct), su slot Tier 1 (16B [ptr][deleter]) debe vivir en HEAP, no en
    /// stack: el campo guarda la direccion del slot y sobrevive al scope donde
    /// se creo el unique (igual que el env de un closure en un campo).  El dtor
    /// del contenedor libera el inner (via deleter) Y el slot heap.  Lo activa
    /// @c lower_assign antes de bajar el RHS; lo consumen
    /// unique_box/unique_with.

    /// Stack de targets de break/continue para los loops anidados.
    /// Cada vez que entramos a un while/for/do-while se hace push de
    /// {continue_bb, break_bb}; al salir, pop.  BreakStmt emite
    /// `br break_bb` y ContinueStmt emite `br continue_bb` del top.
    ///
    /// continue_bb apunta al header del while (la cond se re-evalua) o
    /// al step_bb del for (ejecuta step y luego cond).  break_bb apunta
    /// al exit_bb del loop.  Vacio fuera de loops (BreakStmt y
    /// ContinueStmt en ese contexto son error de compilacion).
    struct LoopTargets {
        ir::IrBlockId continue_bb;
        ir::IrBlockId break_bb;
        /// Lista de bloques predecesores que saltaron al `continue_bb`
        /// via la sentencia `continue`.  Se rellena cada vez que el
        /// lowering procesa un `ContinueStmt` dentro del loop.  Al
        /// cerrar el loop, lower_while/for itera estos preds para
        /// completar los PHI nodes del header con los SSA values
        /// del scope al momento del continue (sin esto, las
        /// variables modificadas en el body antes del continue
        /// no se propagan correctamente al header del loop).
        std::vector<ir::IrBlockId> continue_preds;
        /// Snapshot del scope (todos los niveles) capturado en el
        /// instante de cada `continue`.  Indice paralelo a
        /// continue_preds.
        std::vector<std::vector<std::unordered_map<std::string, ir::IrValueId>>>
            continue_scopes;
        /// Lista de bloques predecesores que saltaron al `break_bb`
        /// via la sentencia `break`.  Equivalente a continue_preds
        /// pero para el exit_bb.  Sin esto, las variables modificadas
        /// en el body antes del break no se propagan al exit del loop
        /// (bug del PHI del exit con multiples paths que ven distintos
        /// SSA values).
        std::vector<ir::IrBlockId> break_preds;
        /// Snapshot del scope en el instante de cada `break`, paralelo
        /// a break_preds.  Usado por lower_while/for/do-while para
        /// emitir PHIs en el exit_bb cuando hay paths con valores
        /// distintos.
        std::vector<std::vector<std::unordered_map<std::string, ir::IrValueId>>>
            break_scopes;
    };
    std::vector<LoopTargets> loop_targets_;

    /// Mapa global de `goto` labels declaradas en la funcion actual.
    /// Cada `label:` declara un bloque con ese nombre; cada `goto label`
    /// emite BR al bloque resuelto via este mapa.  Se vacia al cerrar
    /// la funcion.  Si una label se usa antes de declararse, se
    /// crea el bloque en el primer goto y se reusa al verla.
    struct GotoEntry {
        ir::IrBlockId block;
        bool declared = false;   // true tras encontrar `label:`
        SourceLoc first_use_loc; // para diagnostico de undefined
    };
    std::unordered_map<std::string, GotoEntry> goto_labels_;

    /// contador monotono para nombrar funciones sinteticas
    /// generadas por @c spawn @c { @c body @c }.  Cada spawn produce
    /// @c __spawn_<N>; reset al inicio del modulo (no por funcion).
    size_t spawn_func_counter_ = 0;

    /// contador para nombres unicos de helpers
    /// @c __lambda_<N>.  Crece junto con cada @c LambdaExpr lowered;
    /// el reseteo es per-modulo (no per-funcion) para garantizar que
    /// dos lambdas distintas en funciones distintas tengan nombres
    /// diferentes.  Reusa @c pending_spawn_helpers_ para encolar los
    /// helpers; el flush a @c out_mod_ pasa al final de @c run().
    size_t lambda_counter_ = 0;

    /// contador per-funcion para nombres unicos de bloques del
    /// operador ternario (@c ter_then_<N> / @c ter_else_<N> /
    /// @c ter_merge_<N>).  Se incrementa por cada @c lower_ternary.
    size_t ternary_counter_ = 0;

    /// stack dinamico de comptime const en lowering.  Usado por
    /// @c lower_comptime_for para bindear el index a su valor const
    /// en cada iteracion del unroll.  @c lower_ident consulta este
    /// stack ANTES de las anotaciones AST -- permite override per-
    /// iteracion del unroll sin re-correr el type checker.
    struct ComptimeLocalEntry {
        bool is_str = false;
        int64_t value = 0;
        std::string str_value;
        ir::IrType ir_t = ir::IrType::I64;
    };
    std::vector<std::unordered_map<std::string, ComptimeLocalEntry>>
        lowering_comptime_scopes_;

    /**
     * @brief emite el cuerpo de un `comptime for` desenrollado.
     *
     * Evalua @c lo y @c hi en compile-time.  Por cada valor de i en
     * [lo, hi) (o [lo, hi] si inclusive), push scope con i->valor,
     * baja el body como stmt normal, pop scope.  Resultado: N copias
     * del body emitidas en secuencia, con i siendo una constante
     * conocida en cada uno (los IdentExpr de i se resuelven via
     * @c lowering_comptime_scopes_).
     */
    void lower_comptime_for(ast::ComptimeForStmt *s);

    /// helpers de spawn pendientes de añadir al modulo.  Las
    /// funciones se acumulan aqui durante el lowering del padre y se
    /// vuelcan a @c out_mod_ al final de @c run() para preservar el
    /// orden de funciones (main primero -> emisor IR la marca como
    /// entry point con @c hlt; spawn helpers despues -> @c ret).
    std::vector<ir::IrFunction> pending_spawn_helpers_;

    /// mapa de nombre de tipo @c @Introspect ->
    /// indice del chunk IntrospectInfo en @c static_data.  Poblado por
    /// @c emit_introspect_info_chunks() al final de @c run(); consultado
    /// por @c lower_call para resolver @c find_type("Name") a un
    /// @c @Absolute("code.s_<idx>") directo (cero overhead cuando el
    /// nombre es literal compile-time).
    std::unordered_map<std::string, uint64_t> introspect_idx_by_name_;

    /**
     * @brief emite chunks IntrospectInfo POD en
     * @c static_data para cada tipo marcado @c @Introspect.
     *
     * Invocado al final de @c run() tras lower_class_methods (que
     * rellena fields/methods).  Itera @c tc_.struct_layouts(),
     * @c class_layouts() y @c enum_layouts(); por cada layout con
     * @c is_introspect=true genera el chunk binario con header (24
     * bytes) + FieldInfo[] + nombres inline.  Indices guardados en
     * @c introspect_idx_by_name_ para resolver @c find_type literal.
     */
    void emit_introspect_info_chunks();

    /// si !=IR_NO_VALUE estamos bajando el body de una
    /// funcion @Async como spawn helper.  El SSA value contiene el
    /// handle del Future (resultado de msgrecv al inicio del helper).
    /// `lower_return` consulta este flag: si esta set, en vez de emitir
    /// RET, emite `fulfill(async_fut_id_, value) + hlt`.  Asi cada
    /// return del body resuelve el future del caller.
    ir::IrValueId async_fut_id_ = ir::IR_NO_VALUE;

    /// si true, estamos lowering el body de un `rspawn(node) { ... }`
    /// helper.  En este caso `lower_return` intercepta `return X` y emite
    /// `mov r0, X + hlt`.  El runtime distribuido captura R0 al detectar
    /// HALT en un proceso con `rspawn_future_id != 0` y envia
    /// VDP_FUTURE_FULFILL al nodo origen con ese valor.  No usa async_fut_id_
    /// porque el future vive en el nodo CALLER, no en el remoto.
    bool is_rspawn_body_ = false;

    /**
     * @brief Cierto mientras se baja el cuerpo de un `spawn { ... }` local.
     *
     * Un cuerpo de spawn NO es una funcion a la que se llame: es por donde
     * EMPIEZA un proceso nuevo, y en su pila no hay ninguna direccion de
     * retorno.  Por eso no termina con un RET sino parando el proceso, que es
     * lo que hace @ref emit_process_body_end.
     *
     * Hacia falta decirlo porque @c lower_return sabia de los otros dos cuerpos
     * que tampoco son funciones -- el de una funcion asincrona y el de un
     * `rspawn` remoto -- y de este no, asi que un `return;` escrito a mano
     * emitia el RET normal y el proceso saltaba a una direccion que nadie habia
     * puesto.  El camino implicito -- llegar al final del bloque sin escribir
     * nada -- si lo hacia bien, asi que el mismo programa terminaba de una
     * forma o de otra segun si el `return` estaba escrito.
     */
    bool is_spawn_body_ = false;

    /**
     * @brief Termina el cuerpo de un proceso: parar, o retornar en nativo.
     *
     * Un proceso de la maquina virtual acaba parando (@c HLT); en un binario
     * nativo el mismo cuerpo ES la funcion de entrada de un hilo del sistema,
     * que se recoge cuando esa funcion retorna.  La regla es una y vive aqui
     * porque la usan los dos finales posibles del cuerpo: llegar al ultimo
     * statement y escribir un `return`.
     *
     * @param line Linea del fuente a la que atribuir la instruccion.
     */
    void emit_process_body_end(uint32_t line);

    /// Emite todos los cleanups activos del @c cleanup_stack_ en orden
    /// inverso (LIFO).  No modifica el stack.  Usado por @c lower_return
    /// para garantizar que las acciones de salida (e.g. monexit) corran
    /// antes del RET.
    void emit_cleanups_all();

    /**
     * @brief Emite los cleanups del rango [start, end) del @c cleanup_stack_
     *        en orden inverso (mas reciente primero).
     *
     * Variante de @c emit_cleanups_all que solo procesa una ventana del
     * stack.  Util para scope-local cleanup desde @c lower_block: el
     * scope recuerda la altura del stack al entrar (start = mark) y al
     * salir emite los cleanups que se registraron en su propio cuerpo
     * (end = stack actual), sin tocar los outer.  Asi un destructor
     * dentro de un loop body se ejecuta al exit de cada iteracion.
     *
     * NO modifica el cleanup_stack_; el caller hace @c resize(start)
     * tras esta llamada para popear las entradas ya emitidas.
     *
     * @param start Indice inicial (inclusive).
     * @param end   Indice final (exclusive); debe ser >= start.
     */
    void emit_cleanups_range(size_t start, size_t end);

    /// sret: si la funcion actual declara devolver Optional<T> o
    /// Result<V,E>, el tipo de retorno se transforma en void y el
    /// caller pasa un buffer hidden (retbuf) como primer argumento.
    /// @c sret_active_ indica si el patron esta en uso, y
    /// @c sret_retbuf_ guarda el SSA value del param hidden.  El
    /// lowering de @c return en estas funciones copia el contenido
    /// del Optional/Result construido al retbuf en vez de devolverlo
    /// como valor.  El de las funciones que NO devuelven Optional/
    /// Result es false / IR_NO_VALUE.
    bool sret_active_ = false;
    ir::IrValueId sret_retbuf_ = ir::IR_NO_VALUE;
    /// Tamano del Optional/Result que se devuelve (16 o 24).  Se
    /// usa para emitir el MEMCPY al retbuf en lower_return.
    uint64_t sret_buf_size_ = 0;

    /// Nombre de la clase contenedora durante el lowering de un metodo
    /// de instancia.  Lo consulta @c lower_class_field_load /
    /// @c lower_class_field_store para resolver offsets cuando el
    /// receptor de @c .field es @c this (caso comun) o cualquier
    /// expresion con tipo CLASS.  Vacio fuera de metodos.
    std::string current_class_lowering_;
};

} // namespace vx

#endif // VX_LOWERING_H
