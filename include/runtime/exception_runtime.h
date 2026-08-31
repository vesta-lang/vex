/**
 * @file exception_runtime.h
 * @brief Sistema de excepciones FatalError capturables desde Vesta.
 *
 * Antes los errores VM "duros" (NPE, div0, illegal opcode,
 * stack overflow, segfault, etc.) escribian @c vm->err_thread =
 * @c THREAD_* y disparaban @c EVT_ERROR -> el proceso moria sin
 * posibilidad de captura desde bytecode.
 *
 * introduce la clase predefinida @c FatalError, registrada en el
 * @c ClassRegistry del Loader publico al crear la VM.  Cualquier opcode
 * que detecte un error duro ahora invoca @c throw_fatal(vm, kind, msg)
 * que:
 *
 *   - Si @c vm->exc_frame_stack es @c nullptr (caso normal: sin try
 *     activo) -> ruta antigua: set @c err_thread + @c EVT_ERROR ->
 *     proceso muere igual que antes.  Cero overhead anadido.
 *
 *   - Si hay un handler activo -> aloca una @c FatalError instance,
 *     llena los campos (kind, pc, message, stack_trace), y delega en
 *     @c do_throw para que la pila de TRYENTER + @c handler_pc lo
 *     atrape igual que cualquier otra excepcion.  El usuario captura
 *     con @c try { ... } catch (FatalError e) { ... } en Vesta.
 *
 * @c FatalError tiene 4 fields ABI fijos (offsets se exponen al
 * lowering del frontend):
 *
 *   ObjectHeader  (24 bytes)
 *   +24  i32  kind         -> codigo @c THREAD_* (NULL_PTR, DIV0, etc.)
 *   +32  u64  pc           -> direccion VM donde ocurrio el error
 *   +40  u64  message_ptr  -> puntero host a string nul-terminado
 *   +48  u64  trace_ptr    -> puntero host a stack trace formateado
 *
 * Usamos un slot estatico por proceso (@c vm->fatal_slot) para evitar
 * alocacion durante el throw -- el GC podria estar en mal estado al
 * momento del error.  Un solo slot basta porque las excepciones no se
 * anidan dentro de un mismo throw (el handler limpia la previa antes
 * de relanzar otra).
 */
#pragma once

#include "loader/oop_types.h"

#include <cstdint>
#include <cstddef>
#include <string>

// Forward declarations para evitar dependencias circulares.
namespace loader {
class Loader;
}
namespace runtime {
class ProcessVM;
}

namespace runtime {

/**
 * @brief Codigos numericos para el campo @c FatalError.kind.
 *
 * Coinciden con @c state_err_thread (@c proceso_runtime.h) para que
 * el usuario pueda comparar facilmente: @c if (e.kind == 1) -> NPE.
 * Documentar en la API de Vesta como constantes.
 */
enum FatalKind : uint32_t {
    FATAL_NULL_POINTER = 1,        ///< deref de puntero null o handle invalido
    FATAL_DIVISION_BY_ZERO = 2,    ///< div / mod entre cero (signed o unsigned)
    FATAL_STACK_OVERFLOW = 3,      ///< RSP supero el limite de pila
    FATAL_STACK_UNDERFLOW = 4,     ///< POP / RET con RSP en frontera
    FATAL_ILLEGAL_INSTRUCTION = 5, ///< opcode invalido o operando malformado
    FATAL_INVALID_SYSCALL = 6,     ///< calln a simbolo no resuelto
    FATAL_SEGMENTATION_FAULT = 7,  ///< acceso a VA fuera de cualquier mapeo
    FATAL_NATIVE_CRASH = 8,        ///< plugin nativo crasheo (SEH/SIGSEGV)
    FATAL_NATIVE_EXCEPTION = 9,    ///< plugin nativo lanzo C++ exception
    FATAL_OUT_OF_MEMORY = 10,      ///< alloc fallo (raw o GC)
    FATAL_USER_ABORT = 11,         ///< builtin Vesta @c panic("...")
};

/**
 * @brief Class info global de @c FatalError.  Inicializada por
 *        @c init_exception_classes() al construir la primera VM.
 *
 * Acceso lock-free tras el init: la inicializacion ocurre antes de
 * que cualquier proceso este corriendo.  En multi-thread la primera
 * VM hace el define_class y las posteriores lo encuentran via
 * @c by_name_ del registry sin re-crear.
 */
extern loader::ClassInfo *g_fatal_error_class;

/**
 * @brief Con que codigo debe salir el proceso tras un fallo sin capturar.
 *
 * Se usan los codigos de siempre y no unos propios: un fallo que en C mata al
 * proceso con SIGFPE tiene que salir con lo mismo aqui.  La convencion es la de
 * cualquier interprete de ordenes -- 128 mas el numero de senal -- asi que una
 * division entre cero sale 136 y un acceso invalido 139, y quien tenga guiones
 * o integracion continua mirando esos numeros no tiene que aprenderse otros.
 * Cabe en los 8 bits que deja un codigo de salida, que es la otra razon.
 *
 * @return El codigo, o 0 si no hubo ningun fallo.
 */
int last_fatal_exit_code();

/**
 * @brief Registra la clase @c FatalError en el ClassRegistry del
 *        loader publico si aun no existe.  Idempotente.
 *
 * Llamado desde el constructor de @c VM tras inicializar el loader
 * privado.  No falla: si el registry ya tiene FatalError simplemente
 * actualiza @c g_fatal_error_class al puntero existente.
 *
 * @param loader Loader publico del manager (donde vive el registry).
 */
void init_exception_classes(loader::Loader &loader);

/**
 * @brief Lanza un @c FatalError capturable desde el opcode actual.
 *
 * Patron de uso desde @c exec_instruction_*.cpp:
 *
 * @code
 *   if (deref_target == 0) {
 *       runtime::throw_fatal(vm, runtime::FATAL_NULL_POINTER,
 *           "deref de puntero null en GETFIELD");
 *       return;
 *   }
 * @endcode
 *
 * Comportamiento:
 *   - Si @c vm->exc_frame_stack != nullptr (handler activo): aloca
 *     o reutiliza el slot @c vm->fatal_slot, llena la instancia
 *     con kind/pc/message + stack trace formateado, e invoca
 *     @c do_throw para que se atrape como excepcion normal.
 *   - Si no hay handler: ruta antigua (set @c err_thread + emit
 *     @c EVT_ERROR).  El proceso muere igual que antes pero la VM
 *     y los demas procesos siguen vivos (que ya era el comportamiento
 *     pre.
 *
 * Coste cuando NO hay handler activo: 1 lectura + 1 branch +
 * 2 stores (fast path).  Cuando SI hay: ~50 ns por la alocacion
 * lazy del slot + memcpy del message.
 *
 * @param vm        Proceso donde se origina el error.
 * @param kind      Codigo @c FatalKind del error.
 * @param message   String C nul-terminado con descripcion legible.
 * @param catchable Si es @c false, NINGUN `catch` lo intercepta: se toma
 *                  siempre la ruta de arriba (mensaje + traza + fin del
 *                  proceso) aunque haya un `try` envolviendo.  Es para los
 *                  fallos que son un BUG del programa y no una condicion que
 *                  el programa pueda encontrarse -- afirmar que algo no es
 *                  nulo y equivocarse --, donde capturar solo sirve para
 *                  seguir corriendo con la suposicion ya rota.  Ademas hace
 *                  que los tres modos coincidan: en nativo no hay
 *                  desenrollado de excepciones, asi que ahi SIEMPRE fue
 *                  fatal, y el mismo programa se comportaba distinto segun
 *                  el modo.
 */
void throw_fatal(ProcessVM *vm, uint32_t kind, const char *message,
                 bool catchable = true);

/**
 * @brief Variante de @c throw_fatal con mensaje formateado tipo printf.
 *
 * Util cuando el mensaje incluye valores dinamicos (offsets, registros,
 * nombres de clase).  Limita a 512 bytes; trunca con "..." si excede.
 */
void throw_fatalf(ProcessVM *vm, uint32_t kind, const char *fmt, ...);

/**
 * @brief Metadata de debug por metodo.  Se rellena durante
 *        @c __module_init via el opcode @c setmethdbg que el frontend
 *        Vesta emite tras cada @c defmethod con la info del .vx source.
 *
 * Layout muy compacto: nombre de archivo (compartido entre todos los
 * metodos del modulo) + linea de inicio del metodo en el source.
 * Suficiente para que el stack trace muestre "(myfile.vx:42)" en
 * cada frame.  Opcionalmente extensible a tabla pc -> line para
 * precision instruction-level (no implementado en MVP).
 */
struct MethodDebug {
    std::string source_file; ///< nombre del .vx source (e.g. "foo.vx")
    uint32_t start_line;     ///< linea 1-based del inicio del metodo
};

/**
 * @brief Registra metadata de debug para un MethodInfo.  Idempotente:
 *        si la entrada ya existe, la sobreescribe.  Llamado por el
 *        opcode @c setmethdbg desde @c __module_init.
 */
void register_method_debug(loader::MethodInfo *method, const char *file,
                           size_t file_len, uint32_t line);

/**
 * @brief Lookup de metadata de debug para un MethodInfo.
 * @return puntero a la entrada, o @c nullptr si no esta registrada.
 */
const MethodDebug *lookup_method_debug(loader::MethodInfo *method);

/**
 * @brief Construye un stack trace estilo Java para el proceso actual.
 *
 * Formato de cada linea: "  at <ClassName>.<methodName>(line:<n>)"
 * cuando la metadata esta disponible; "  at <pc=0xADDR>" como
 * fallback para frames sin metodo (e.g. CALLN nativo).
 *
 * El primer frame siempre es donde ocurrio el error (PC actual);
 * los siguientes recorren @c frame_stack hasta el origen del proceso.
 *
 * El buffer @p out se trunca a @p out_size bytes incluido el nul
 * terminador.  Devuelve la longitud escrita sin contar el nul.
 *
 * @param vm        Proceso a inspeccionar.
 * @param out       Buffer destino.
 * @param out_size  Tamano de @p out (debe ser >= 64 para mensajes utiles).
 * @return          Numero de bytes escritos en @p out (sin nul).
 */
size_t build_stack_trace(ProcessVM *vm, char *out, size_t out_size);

/**
 * @brief Cuenta una excepcion del PROGRAMA que ningun @c catch recogio.
 *
 * No es un fallo del motor -- lanzar es lo que se le pidio --, pero terminar
 * callando es indistinguible de terminar bien: el proceso paraba en seco, sin
 * mensaje, sin la cadena de llamadas y saliendo con codigo CERO.  Un guion o
 * una integracion continua se lo creian.
 *
 * Se llama con la cadena de marcos TODAVIA ENTERA: la traza se saca de ella, y
 * despues ya se puede desmontar.
 *
 * Los fallos del motor (@c FatalError) NO pasan por aqui: los cuenta
 * @c throw_fatal con su propio codigo del catalogo, y hacerlo dos veces
 * imprimiria el mismo fallo dos veces.
 *
 * @param vm         Proceso donde se lanzo.
 * @param class_name Nombre de la clase lanzada; es lo unico que el motor sabe
 *                   de un objeto que es del usuario.
 */
void report_uncaught_exception(ProcessVM *vm, const char *class_name);

// ---------------------------------------------------------------------
// OS-level access violation -> FatalError capturable.
//
// Cuando el bytecode dereferencia un puntero host invalido (el caso
// mas comun: `*null_host_ptr`, deref de un host_ptr stale tras free,
// o aritmetica que sale del bloque malloc'eado), el OS dispara un
// EXCEPTION_ACCESS_VIOLATION (Windows) o SIGSEGV (POSIX).  Sin la
// infraestructura de abajo, la VM entera crashea sin que el `try`
// del usuario lo atrape.
//
// El plan:
//   - install_host_av_handler() registra UN VEH global (Windows) /
//     SIGSEGV handler (POSIX) la primera vez que se llama.  Idempotente.
//   - El scheduler hace setjmp(proc->av_recovery_jmpbuf) antes de
//     cada batch de instrucciones y marca av_recovery_active=true.
//   - Define el thread-local @c g_executing_proc al inicio del batch.
//   - Si ocurre un AV durante la ejecucion: el handler lee el TLS,
//     verifica av_recovery_active y exc_frame_stack, guarda la
//     direccion del AV en proc->pending_av_addr, y dispara longjmp
//     (POSIX directamente; Windows via redireccion de RIP a un stub
//     que llama longjmp).
//   - Tras el longjmp, el scheduler llama throw_fatal con
//     FATAL_SEGMENTATION_FAULT.  El flujo normal de do_throw saltara
//     al handler `catch (FatalError e)` del usuario.
// ---------------------------------------------------------------------

/**
 * @brief Instala el handler global de access violations.  Idempotente
 *        (registra solo la primera llamada via std::once).
 *
 * Se llama desde el constructor de VM, tras init_exception_classes.
 */
void install_host_av_handler() noexcept;

/**
 * @brief Retira el handler global de access violations.
 *
 * Imprescindible cuando la VM se embebe en una libreria dinamica (libvesta) que
 * puede descargarse en caliente (FreeLibrary / dlclose): sin retirarlo, la
 * cadena de manejadores del SO conserva un puntero a codigo ya desmapeado y el
 * cierre del proceso o la siguiente excepcion salta a esa direccion (segfault).
 * Idempotente.  La descarga de libvesta lo invoca desde su destructor de DLL.
 */
void uninstall_host_av_handler() noexcept;

/**
 * @brief Setea (o limpia con nullptr) el ProcessVM cuyo bytecode
 *        esta corriendo en el thread actual.  Lo llama el scheduler
 *        antes y despues de cada batch de instrucciones.
 *
 * El handler de AV consulta este TLS para identificar a quien
 * enviar el longjmp.  Si esta a nullptr cuando ocurre un AV, el
 * handler delega a la cadena de SEH normal (la VM crashea como
 * antes).
 */
void set_current_executing_process(ProcessVM *proc) noexcept;

/**
 * @brief Devuelve el ProcessVM actualmente en ejecucion en este
 *        thread, o nullptr si no hay ninguno.
 */
ProcessVM *get_current_executing_process() noexcept;

#if defined(_WIN32)
/**
 * @brief Indice TLS dedicado (Win64) para que el thunk del JIT
 *        lea @c ProcessVM* directamente desde @c gs:[0x1480+idx*8]
 *        sin llamar a @c get_current_executing_process.  Reserva el
 *        slot via @c TlsAlloc() lazy en la primera invocacion.
 *
 * El offset 0x1480 corresponde a TlsSlots[0] del TEB en Win64.  Si
 * @c TLS_OUT_OF_INDEXES (alocacion fallo), el thunk cae al call.
 * @c TLS_MINIMUM_AVAILABLE = 64 garantiza idx < 64 en la mayoria
 * de procesos (el thunk solo soporta los primeros 64 slots).
 */
unsigned long jit_proc_tls_index() noexcept;
#endif

} // namespace runtime
