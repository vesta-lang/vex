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
 * @file loader.h
 * @brief Loader de ejecutables VELB para VestaVM.
 *
 * El loader es responsable de:
 *  1. Leer y validar el header VELB del archivo binario.
 *  2. Parsear la tabla de espacios de direcciones y la tabla de secciones.
 *  3. Parsear la tabla de importaciones (funciones nativas FFI).
 *  4. Reservar memoria en el @c ArenaManager para cada espacio de direcciones.
 *  5. Copiar el bytecode de cada seccion al rango de memoria reservado.
 *  6. Crear un @c ProcessVM con el PC inicializado y los labels cargados.
 *
 * Macros de error:
 *  - @c LOADER_THROW(kind, msg)          : lanza un @c LoaderError
 * directamente.
 *  - @c LOADER_THROW_AT(kind, msg, rdr)  : incluye el offset del reader en el
 * mensaje.
 *
 * Flujo tipico:
 * @code
 *   runtime::ManageVM mgr;
 *   loader::Loader ldr(mgr);
 *   runtime::ProcessVM *proc = ldr.load_executable(vm_instance,
 * "program.velb"); vm_instance.make_ready(proc->pid);
 * @endcode
 */

#ifndef LOADER_H
#define LOADER_H

#include "runtime/vm_address_space.h"
#include "loader/oop_types.h"
#include "loader/sandbox.h" // loader::Caps + parse_caps + caps_to_string
#include "loader/interp_stackmap.h" // loader::InterpStackmapTable ( E.1)
#include "debug/debug_info.h"
#include "ir/ssa_ir.h"

#include <cstdint> // uint8_t, uint32_t
#include <cstddef> // size_t
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include <memory>

#include "arena/arena_manager.h"
#include "emmit/bytereader.h"
#include "ffi/native_ffi.h"
#include "linker/velb_linker_bytecode.h"
#include "loader/class_registry.h"
#include "runtime/runtime.h"

namespace runtime {
class ManageVM;
}

#define LOADER_THROW(kind, msg) throw loader::LoaderError(kind, msg)
#define LOADER_THROW_AT(kind, msg, reader)                                     \
    throw loader::LoaderError(kind, std::string(msg) + " (offset=" +           \
                                        std::to_string(reader.offset) + ")")

namespace loader {
using namespace Assembly::Bytecode;

enum class ErrorKind {
    TruncatedHeader,
    InvalidFormat,
    InvalidMagic,
    InvalidVersion,
    CorruptedExecutable,
    NotFoundSpacesAddress
};

class LoaderError : public std::exception {
  public:
    LoaderError(ErrorKind kind, std::string msg)
        : kind(kind), message(std::move(msg)) {}

    const char *what() const noexcept override { return message.c_str(); }

    ErrorKind kind;
    std::string message;
};

[[noreturn]]
inline void throw_error(ErrorKind kind, const std::string &msg) {
    throw LoaderError(kind, msg);
}

[[noreturn]]
inline void throw_error_at(ErrorKind kind, const std::string &msg,
                           const ByteReader &reader) {
    throw LoaderError(kind,
                      msg + " (offset=" + std::to_string(reader.offset) + ")");
}

// ClassInfo, MethodInfo, FieldInfo, HandlerException, FrameHeader,
// ObjectHeader, stringx, FieldAccess, FieldKind y constantes
// OBJ_FLAG_*/CLASS_FLAG_*/METHOD_FLAG_* estan definidos en oop_types.h
// (incluido arriba), dentro de namespace loader.

/**
 * @struct Executable
 * @brief Representa un ejecutable VELB completamente enlazado y listo para
 * cargar en la VM.
 *
 * Esta estructura es el resultado final del linker y la entrada principal del
 * loader. Contiene toda la informacion necesaria para:
 *  - reservar espacios de memoria
 *  - copiar secciones ensambladas
 *  - resolver simbolos y labels
 *  - inicializar el PC
 *  - cargar metadatos y relocaciones
 *
 * Es equivalente a un "ELF ejecutable" pero adaptado al formato VELB.
 */
typedef struct Executable {
    /**
     * @brief Identificador del formato del ejecutable.
     *
     * Siempre debe ser `"velb"`. Permite validar que el archivo cargado
     * corresponde al formato correcto.
     */
    std::string format = "velb";

    /**
     * @brief Bloque HOST con el storage de las variables globales (`gdata`).
     *
     * Una variable global es memoria estatica COMPARTIDA: su direccion se toma
     * con `&global` y viaja (a un campo, a un parametro `T*`, a la FFI, a un
     * `lock cmpxchg`), y en el sitio del deref el unico contrato disponible es
     * el del tipo -- y `T*` significa host.  Ademas la memoria de la VM es
     * paginada y de asignacion perezosa, asi que una direccion suya solo vale
     * dentro de su pagina: un `T*` estable a memoria VM no puede existir.
     *
     * Por eso `gdata` no se mapea a `vm_mem`: se copia a este bloque, contiguo
     * y con direccion estable (`unique_ptr` a un array, nunca un `vector`, que
     * al crecer moveria los datos e invalidaria las direcciones ya fijadas).
     *
     * Se aloca UNA vez por modulo y NO se replica por proceso: los actores
     * comparten sus globales (igual que en AOT), y su aislamiento viene de sus
     * locals y su heap, no de aqui.
     */
    /**
     * @brief Bloque HOST donde viven las variables globales.
     *
     * Reservado con alineacion de LINEA DE CACHE, no con `new[]`.
     *
     * `new[]` garantiza la alineacion fundamental -- 16 bytes en x86-64 -- y
     * eso deja sin poder demostrar cualquier exigencia mayor: las
     * instrucciones que EXIGEN direccion alineada (`vmovdqa` pide 32,
     * `vmovdqa64` pide 64) quedaban en "no puedo probarlo" sobre datos que el
     * propio compilador coloca.  Y no era una limitacion del analisis: el
     * dato realmente no tenia esa garantia.
     *
     * Como este bloque lo reservamos NOSOTROS, la garantia la elegimos
     * nosotros.  Con 64 bytes, todo dato en un desplazamiento multiplo de 64
     * queda demostrablemente alineado, y la comprobacion pasa de avisar a
     * verificar.  El coste es unos pocos bytes de mas en UNA reserva por
     * programa.
     *
     * Y SALE DE LA RESERVA DEL ASIGNADOR, de la misma de la que salen los
     * trozos de codigo nativo.  No es un detalle de reparto: el codigo alcanza
     * estos globales con desplazamientos de 32 bits, que cubren +-2 GB, asi que
     * si el bloque cae lejos la referencia no se puede ni emitir.  Saliendo del
     * mismo sitio son vecinos por construccion.  Ver `materialize_gdata_host`.
     */
    /**
     * @brief Suelta @ref gdata_host por la puerta por la que entro.
     *
     * Lleva por que hay DOS puertas y no se pueden confundir: el bloque sale de
     * la reserva del asignador cuando esta puede servirlo -- para que el codigo
     * nativo lo alcance con un desplazamiento de 32 bits -- y de una reserva
     * alineada normal cuando no.  Soltar uno con la funcion del otro no falla
     * al soltarlo: falla despues, en otro sitio.
     *
     * SIN INICIALIZADORES POR DEFECTO en los campos, y no es descuido.  Los de
     * una clase ANIDADA se parsean en el contexto de clase completa de la que
     * la contiene, asi que aqui dentro -- donde `Executable` todavia no esta
     * cerrada -- su constructor por defecto no es utilizable, y entonces
     * `std::unique_ptr` se queda sin el suyo: el error sale en la linea del
     * `typedef struct Executable`, que no es donde esta la causa.  Sin ellos el
     * constructor implicito es trivial, y un `unique_ptr` vacio INICIALIZA POR
     * VALOR el borrador, o sea que los deja en cero -- que es lo que hacian los
     * inicializadores --.  Un borrador con esos ceros no se llega a usar nunca,
     * porque el puntero es nulo.
     */
    struct BorrarAlineado {
        /// Bytes REDONDEADOS de la reserva; los pide la puerta de paginas.
        size_t bytes;
        /// Si salio de la reserva propia (paginas) o de una alineada normal.
        bool de_la_region;
        void operator()(uint8_t *p) const noexcept;
    };
    std::unique_ptr<uint8_t[], BorrarAlineado> gdata_host;
    size_t gdata_size = 0; ///< Bytes de @ref gdata_host.
    uint64_t gdata_va =
        0; ///< VA de la seccion `gdata` (0 = el modulo no tiene).

    /**
     * @brief Version del formato VELB.
     *
     * Permite compatibilidad futura entre versiones del loader y del linker.
     */
    velb_version_format version = 1;

    /**
     * @brief Espacios de direcciones definidos en el ejecutable.
     *
     * Cada `Space` representa un rango de direcciones virtuales:
     *  - `anonymous`
     *  - `stack`
     *  - `heap`
     *  - `data`
     *  - etc.
     *
     * El loader debe reservar memoria para cada uno. Se puede indicar si
     * reservar el rango completo o realizar reserva lazy.
     */
    std::vector<Space> spaces{};

    /**
     * @brief Secciones ensambladas del ejecutable.
     *
     * Cada `Section` contiene bytecode ya resuelto y listo para copiarse
     * en el espacio correspondiente. Equivalente a `.text`, `.data`, `.rodata`
     * en ELF.
     */
    std::vector<Section *> sections{};

    /**
     * @brief Simbolos globales con direccion absoluta.
     *
     * Cada `Label` contiene:
     *  - nombre del simbolo
     *  - direccion absoluta final tras el linking
     *
     * El loader los registra en la tabla de simbolos de la VM.
     */
    std::vector<Label *> labels{};

    /**
     * @brief Bytecode cargado con header y demas datos incluidos.
     *
     */
    std::vector<uint8_t> bytecode{};

    /**
     * Offset al bytecode real dentro del archivo, este campo
     * se puede usar junto a "vector<uint8_t> bytecode" para
     * obtener el bytecode real
     */
    size_t offset_real_bytecode = 0;

    /**
     * @brief Direccion inicial del PC.
     *
     * Determinada por la directiva `@InitPc` o por el linker.
     * El loader debe asignarla al registro PC de la VM.
     */
    uint64_t init_pc = 0;

    /**
     * @brief Cabecera del ejecutable VELB.
     *
     * Contiene informacion adicional como:
     *  - tamano del ejecutable
     *  - checksum
     *  - flags
     *  - version del linker
     *  - punto de entrada
     *
     * Es redundante con algunos campos, pero util para validacion.
     */
    HeaderVELB header{};

    /**
     * @brief Relocaciones aplicadas durante el linking.
     *
     * Normalmente solo se usa para debugging o herramientas de analisis.
     * El ejecutable final ya tiene todas las direcciones resueltas. En teoria,
     * aunque se puede llamar al linker dinamico.
     */
    std::vector<Assembly::Bytecode::Relocation> relocations{};

    /**
     * @brief tabla de relocations leida del .velb tras el link.
     *
     * Cada entry contiene el offset DENTRO del bytecode (no del archivo)
     * y el target_value original.  Permite al loader hacer rebase
     * preciso cuando carga el modulo en una VA distinta de la original
     * (`load_module_dynamic`).  Vacia si el .velb no tiene tabla de
     * relocations (formato viejo o sin relocations resolubles).
     */
    std::vector<entry_relocation_table> velb_relocations{};

    /**
     * @brief Informacion de depuracion bytecode -> source line.
     *
     * Construida cuando el .velb tiene la seccion DVBG (compilado
     * con --vx-debug).  Permite al debugger resolver `b file.vx:42`
     * al offset de bytecode correcto via DebugInfo::lookup_offset_for_line,
     * y mostrar `file:line` del PC actual via DebugInfo::lookup_line.
     * nullptr si el .velb no tiene info de debug (caso comun).
     */
    std::unique_ptr<debug::DebugInfo> debug_info;

    /**
     * @brief Path del archivo .velb desde el filesystem (si fue cargado
     *        dinamicamente via load_module_dynamic).
     *
     * Vacio para el ejecutable principal cargado al inicio.  Usado por
     * `unload_module_dynamic(path)` para localizar el Executable y
     * removerlo del pool sin afectar otros modulos.
     */
    std::string source_path;

    /**
     * @brief Opcion W: funciones IR deserializadas desde la seccion
     *        @c @ir del `.velb` v3.  Llenado por @c parse_velb si
     *        @c header.offset_ir_section != 0; vacio para `.velb` v2
     *        o si la seccion no se pudo parsear.
     *
     * Habilitan auto-JIT ( D.3-C+ del roadmap): cuando una
     * funcion del bytecode se invoca repetidamente (counter >=
     * threshold), el runtime busca su @c IrFunction aqui via nombre
     * (la entrada del map @c ir_lookup) y la pasa a @c JitCompiler.
     * El resultado se asigna a @c MethodInfo::jit_code y futuras
     * invocaciones via @c exec_instr_callvirt despachan directo al
     * codigo nativo.
     */
    std::vector<ir::IrFunction> ir_functions;

    /**
     * @brief Lookup acelerado por nombre (@c IrFunction::name -> indice
     *        en @c ir_functions).  Construido junto con @c ir_functions
     *        durante @c parse_velb para que el dispatch JIT no haga
     *        busqueda lineal en cada invocacion.
     */
    std::unordered_map<std::string, size_t> ir_lookup;

    /**
     * @brief symbol table resuelta del linker.
     *
     * Mapa nombre completo de label (e.g. "code.s_0", "code.s_3") a
     * direccion VM absoluta resuelta por el linker.  Usado por el
     * JIT mini-parser para resolver `@Absolute("code.X")` referencias
     * en raw_asm sin tener que delegar al interp.
     *
     * Layout en el `.velb`: appendeado RIGHT AFTER la seccion @c @ir
     * con magic "VSYM" + version + count + entries.  Backward
     * compatible: archivos sin VSYM tras @ir simplemente dejan este
     * mapa vacio.
     */
    std::unordered_map<std::string, uint64_t> symbol_table;

    /**
     * @brief  E.1: tabla de stackmaps PRECISOS del interprete,
     *        deserializada de la seccion @c VSMP del @c .velb.
     *
     * Vacia si el @c .velb no lleva stackmaps (build sin
     * @c --vx-emit-stackmaps o @c .vel sin safepoints) -> el GC preciso
     * del interprete es no-op y cae al scan conservador.  Consultada por
     * @c gc_heap::scan_interp_roots_precise via el PC de cada frame.
     */
    loader::InterpStackmapTable interp_stackmaps;

    /**
     * @brief Metadatos arbitrarios en formato JSON.
     *
     * Puede incluir:
     *  - autor
     *  - timestamp
     *  - flags de compilacion
     *  - informacion de build
     *  - dependencias
     */
    // Sqlite::json metadata;

    /**
     * @brief Capabilities concedidas a este modulo + whitelists granulares.
     *
     * Default ALL granted + sin whitelists -> @c caps.unrestricted() == true ->
     * cero overhead (los chequeos colapsan a un branch predicho).
     *
     * Configurable por modulo via CLI @c --vx-caps (modulo principal) o
     * por @c loadmodule(path, caps_str) (modulo dinamico).
     */
    loader::Caps caps{};

    // Opciones del linker
    // Assembly::Bytecode::Linker::LinkerOptions options; ///< Opciones usadas
    // para generar este ejecutable
} Executable;

class Loader {
  public:
    /**
     * Tabla de simbolos a funciones nativas.
     */
    ffi::FFI ffi_loader;

    /**
     * Vector de ejecutables cargados alguna vez.
     *
     * Se almacenan como std::unique_ptr<Executable> por varias razones:
     *
     * 1. Evita copias grandes:
     *    Un Executable puede contener tablas, bytecode y estructuras pesadas.
     *    Guardarlo como unique_ptr evita copiar todo_ el objeto al hacer
     * push_back.
     *
     * 2. Estabilidad de direcciones:
     *    Aunque el vector se realoque internamente, los punteros siguen siendo
     * validos. Esto permite devolver referencias a Executable sin riesgo de que
     * queden invalidas.
     *
     * 3. Propiedad clara:
     *    El Loader es el dueno exclusivo de cada Executable.
     *    No hay aliasing, no hay referencias compartidas, no hay riesgo de
     * doble free.
     *
     * 4. Seguridad en multihilo:
     *    Con un mutex protegiendo el vector, las referencias a los Executable
     *    permanecen estables incluso si el vector crece.
     *
     * En resumen: unique_ptr permite almacenar ejecutables grandes de forma
     * eficiente, segura y con direcciones estables, algo que un
     * std::vector<Executable> no garantiza.
     */
    std::vector<std::unique_ptr<Executable>> executables;

    /**
     * @brief Proximo VA libre para asignar a modulos cargados
     * dinamicamente via @c load_module_dynamic.  Empieza en 0x80000000
     * (2 GiB).  Por debajo de eso se reservan las stacks de proceso
     * (esquema en exec_instr_spawn: stack_base = 0x10000000 +
     * (local_pid % 0x1000) * 0x100000 -> hasta 0x10FFF00000 con 4096
     * procesos a 1 MiB cada uno).  Fijar la base de plugins a 2 GiB
     * elimina cualquier solapamiento entre stacks de proceso, code
     * section del caller (en VA 0x0..N) y los plugins cargados
     * dinamicamente.  La carga dinamica solo usa este contador si
     * detecta solapamiento entre la VA original del modulo y otros
     * executables ya cargados.
     */
    uint64_t next_dyn_base = 0x80000000ULL;

    /**
     * @brief  M.sandbox: flag global "hay algun modulo sandboxed".
     *
     * Default @c false (sin sandbox).  Se pone a @c true cuando se aplica
     * un conjunto de caps restringido a algun Executable (via --vx-caps
     * o loadmodule con caps).  Permite que @c check_cap_at_pc retorne de
     * inmediato (1 branch predicho) en el caso comun sin sandbox, en lugar
     * de iterar @c executables en cada CALLN/dlopen/spawn/etc.  Resultado:
     * el sandbox es CERO-overhead cuando no se usa.
     */
    bool sandbox_active = false;

    /**
     * referencia al manager de instancias de VM
     */
    runtime::ManageVM &instance_manager;

    /**
     * Tabla de callbacks de la API expuesta a los plugins nativos.
     * Debe vivir al menos tanto como los modulos cargados que guarden g_api.
     */
    VestaPluginAPI plugin_api;

    explicit Loader(runtime::ManageVM &instance_manager);

    /**
     * @brief Copia el bytecode de TODOS los executables cargados al
     *        @c vm_mem del proceso destino.
     *
     * Replica la copia que hace @c load_executable, pero sobre un proceso
     * que ya existe (caso: hijos creados con @c spawn que comparten codigo
     * pero tienen vm_mem privado vacio).  Para cada Executable iterado en
     * @c executables, recorre sus secciones y emite un
     * @c vm_to_host_memcpy con el rango (address_init, exe->bytecode.size()).
     *
     * Coste O(numero_executables * secciones * tamano_bytecode).  En
     * spawn se llama una sola vez por hijo.
     *
     * @param dest Proceso destino que recibira la copia del codigo.
     * @param parent Proceso padre del que copiar el estado actual de
     *               @c vm_mem (no el bytecode crudo). Si es @c nullptr,
     *               copia desde @c exe->bytecode original. Para spawn
     *               se debe pasar el padre para heredar el state de
     *               @c __module_init (cache slots de @c ClassInfo*, etc.).
     */
    void copy_executables_to(runtime::ProcessVM &dest,
                             runtime::ProcessVM *parent = nullptr);

    /**
     * Permite obtener una cadena de la seccion strings, en base a su offset
     * @param blob contenido de la seccion de cadena que leer.
     * @param offset offset de la cadena a leer.
     * @return cadena encontrada en el offset indicado.
     */
    std::string read_string_at(const std::vector<uint8_t> &blob,
                               uint64_t offset);

    /**
     * Permite obtener un string en base a un offset string a traves de un
     * reader. El reader no se modificara pero indicara los limites de lectura y
     * el contenido del que se puede leer.
     * @param reader reader que usar para obtener un string
     * @param offset offset string que usar para obtener una cadena valida.
     * @return cadena obtenida a traves del offset
     */
    std::string read_string_at(ByteReader &reader, uint64_t offset);

    /**
     * Permite obtener una tabla de cadenas generada de la seccion de la tabla
     * de strings.
     * @param blob contenido entero de la seccion de cadenas a cargar
     * @return tabla de cadenas.
     */
    std::vector<std::string> read_all_strings(const std::vector<uint8_t> &blob);

    void parse_velb_header(Executable &exe, ByteReader &reader);

    void parse_table_spaces(Executable &exe, ByteReader &reader);

    /**
     * Permite buscar a que espacio pertenece una seccion del ejecutable, debe
     * haberse analizado la tabla de espacios de direcciones previamente para
     * poder hacer esto.
     * @param exe datos del ejecutable
     * @param sec seccion que se quiere usar para buscar el espacio de
     * direcciones
     * @return espacio de direcciones al que pertenece la seccion
     */
    Space *find_space_for_section(Executable &exe, const Section &sec);

    /**
     * parsea la tabla de secciones sin modificar el reader. Crea un punto de
     * control del reader.
     * @param exe Datos del ejecutable, debe haberse analizado antes el header,
     * o haberse indicado el offset a la tabla de secciones
     * @param reader reader padre del que realiazar un punto de control
     */
    void parser_table_sections(Executable &exe, ByteReader &reader);

    /**
     * Permite obtener la tabla de importacion del archivo si es que tiene
     */
    void parser_import_table(Executable &exe, ByteReader &reader);

    std::unique_ptr<Executable> parse_velb(std::vector<uint8_t> bytecode);

    /**
     * Permite crear un proceso en una VM cargado su codigo en este proceso.
     * La VM debe haber sido inicializada usando el metodo `start`
     * @param vm instancia virtual inicializada donde crear el nuevo proceso
     * @param path path al ejecutable VELB a ejecutuar.
     * @return devuelve un proceso creado en la maquina virtual dada.
     */
    runtime::ProcessVM *load_executable(runtime::VM &vm, std::string path);

    /**
     * Permite crear un proceso en una VM cargado su codigo en este proceso.
     * La VM debe haber sido inicializada usando el metodo `start`
     * @param vm instancia virtual inicializada donde crear el nuevo proceso
     * @param raw_bytecode_file bytecocde a cargar
     * @return proceso creado en la maquina virtual
     */
    runtime::ProcessVM *load_executable(runtime::VM &vm,
                                        std::vector<uint8_t> raw_bytecode_file);

    /**
     * @brief carga DINAMICA de un .velb adicional en una VM ya corriendo.
     *
     * Diferencias clave con @c load_executable:
     *   - NO crea un proceso nuevo: el modulo se anade al pool de
     *     `executables` y su bytecode se copia al `vm_mem` de TODOS los
     *     procesos vivos para que cualquiera pueda saltar a su codigo.
     *   - Devuelve el `init_pc` del modulo cargado (entry point del main
     *     del nuevo modulo) para que el caller pueda ejecutarlo via
     *     `callvmr` y que el prologo de su `main` invoque `__module_init`
     *     (registrando clases en el ClassRegistry global).
     *
     * El caller tipico es la instruccion bytecode @c loadmod, que reusa
     * la convencion CALLVM (push de return addr + jump al init_pc) para
     * ejecutar el modulo cargado de forma sincrona.
     *
     * @param vm Instancia VM activa donde cargar el modulo.
     * @param raw_bytecode_file Bytes del archivo .velb a cargar.
     * @return @c init_pc (entry point) del modulo cargado, o 0 si el
     *         parse falla o el archivo esta vacio.
     */
    uint64_t load_module_dynamic(runtime::VM &vm,
                                 std::vector<uint8_t> raw_bytecode_file);

    /**
     * @brief  M.sandbox: comprueba si el codigo en @p pc tiene
     *        concedida la capability @p required.
     *
     * Localiza el @c Executable cuya seccion de codigo contiene @p pc y
     * consulta sus @c caps.  Si ese modulo esta sin restringir (default
     * ALL granted) o @p pc no pertenece a ningun modulo sandboxed,
     * devuelve @c true (permitir).  Solo deniega cuando el modulo
     * propietario del @p pc tiene un sandbox activo que NO concede la
     * cap requerida.
     *
     * Fast path: si @c executables esta vacio o ninguno esta restringido
     * el bucle sale en O(N_modulos) con @c caps.unrestricted() (1 branch
     * predicho por modulo) -> coste despreciable cuando no hay sandbox.
     *
     * @param pc       Direccion VM de la instruccion que solicita la cap.
     * @param required Bitmask de @c loader::Caps (p.ej. @c Caps::FFI_CALL).
     * @return @c true si la operacion esta permitida; @c false si el
     *         modulo propietario del @p pc tiene el sandbox y le falta la
     *         cap.
     */
    [[nodiscard]] bool check_cap_at_pc(uint64_t pc,
                                       uint32_t required) const noexcept;

    /**
     * @brief Variante de load_module_dynamic que registra source_path.
     *
     * Equivalente a load_module_dynamic pero ademas asocia el path
     * fuente al Executable resultante para que pueda ser localizado
     * por unload_module_dynamic(path).
     *
     * @param vm                  Instancia VM activa.
     * @param raw_bytecode_file   Bytes del archivo .velb.
     * @param source_path         Path original del archivo (para unload).
     * @return init_pc del modulo cargado, o 0 en error.
     */
    uint64_t
    load_module_dynamic_with_path(runtime::VM &vm,
                                  std::vector<uint8_t> raw_bytecode_file,
                                  const std::string &source_path);

    /**
     * @brief Descarga un modulo previamente cargado dinamicamente.
     *
     * Localiza el Executable cuyo source_path coincide con @p path y lo
     * elimina del pool `executables`.  Si era el ultimo modulo cargado
     * en `next_dyn_base`, retrocede el contador para reutilizar la VA.
     *
     * IMPORTANTE: las clases que el modulo registro en ClassRegistry NO
     * se eliminan automaticamente (los ClassInfo* podrian estar referenciados
     * por instancias vivas).  Si el usuario quiere "reload" debe versionar
     * los nombres de las clases (ExtSyntaxV1 -> ExtSyntaxV2) o aceptar
     * que la 2a load no redefine la clase.  La memoria del bytecode SI
     * se libera (Executable se destruye), reduciendo el footprint.
     *
     * @param vm   Instancia VM cuyos procesos no deben referenciar mas
     *             el bytecode descargado (no se valida; responsabilidad
     *             del llamador).
     * @param path Path al .velb tal como fue pasado a loadmodule().
     * @return true si se encontro y descargo, false si no existe.
     */
    bool unload_module_dynamic(runtime::VM &vm, const std::string &path);

    void resolve_labels(Assembly::Bytecode::Section &section);

    void load_sections(Assembly::Bytecode::Label &label);

    void load_spaces(Assembly::Bytecode::Space &space);

    void build_runtime_context();

    /**
     * Permite obtener el ultimo ejecutable agregado al loader.
     *
     * @warning Esta funcion NO es thread?safe. Debe llamarse bajo el mutex
     * externo.
     *
     * @return referencia al ultimo ejecutable anadido.
     */
    Executable &get_last_instance_unlocked();

    /**
     * Esta es la version thread?safe de get_last_instance_unlocked, usa un
     * mutex interno.
     * @return referencia al ultimo ejecutable anadido.
     */
    Executable &get_last_instance();

    /**
     * Permite crear una instancia de maquina virtual en un manager dado, la
     * instancia no a sido aun inicializada a traves del metodo start, por lo
     * que el usuario debera hacerlo antes de crear un proceso en esta
     * instancia.
     * @param num_schedulers numeros de hilos nativos que puede usar la
     * instancia para ejecutar procesos virtuales.
     * @return instancia no inicializada.
     */
    runtime::VM *create_vm_instance(size_t num_schedulers);

    /**
     * @brief Instancia una clase generica con tipos concretos (monomorphization
     * runtime).
     *
     * Busca en generic_cache_ la clave "ClassName<T1,T2,...>".  Si ya existe,
     * devuelve el ClassInfo* cacheado.  Si no, clona el ClassInfo de @p generic
     * y sustituye los type_params por los tipos concretos proporcionados.
     *
     * @param generic    ClassInfo de la clase generica (CLASS_FLAG_GENERIC).
     * @param type_args  Array de ClassInfo* de tipos concretos.
     * @param count      Numero de tipos (debe coincidir con type_param_count).
     * @return Puntero a la especializacion (cacheada o recien creada).
     */
    loader::ClassInfo *specialize_class(loader::ClassInfo *generic,
                                        loader::ClassInfo **type_args,
                                        size_t count);

    /**
     * @brief Acceso al registro global de clases definidas en runtime.
     *
     * El @c ClassRegistry mantiene la tabla nombre -> ClassInfo* y la
     * propiedad de toda la memoria asociada (FieldInfo[], MethodInfo[],
     * tablas hash de lookup, advices, strings).  Consultar
     * @c class_registry.h para la API de definicion y busqueda.
     */
    ClassRegistry &class_registry() noexcept { return class_registry_; }
    const ClassRegistry &class_registry() const noexcept {
        return class_registry_;
    }

  private:
    /**
     * @brief Registro de clases dinamicas.
     *
     * Vive como miembro del Loader para que su vida coincida con la
     * de la VM.  Las instrucciones VM @c defclass / @c defmethod /
     * @c deffield invocan este registry indirectamente via el VM
     * que conoce su Loader.
     */
    ClassRegistry class_registry_;

    /**
     * Un mutex en el loader para evitar problemas en el
     * caso de usar multihilo
     */
    std::mutex loader_mutex;

    /**
     * @brief Cache de especializaciones de clases genericas.
     *
     * Clave: nombre calificado de la especializacion, e.g. "List<int>".
     * Valor: puntero al ClassInfo clonado para esa especializacion concreta.
     *
     * Protegido por loader_mutex en specialize_class().
     */
    std::unordered_map<std::string, loader::ClassInfo *> generic_cache_;

    /**
     * @brief Almacen de ClassInfo clonados para especializaciones genericas.
     *
     * Los punteros en generic_cache_ apuntan a ClassInfo almacenados aqui.
     * Se usa unique_ptr para la gestion automatica del ciclo de vida.
     */
    std::vector<std::unique_ptr<loader::ClassInfo>> generic_store_;

    /**
     * @brief Almacen de nombres calificados de especializaciones.
     *
     * Cada entrada es el buffer de caracteres del nombre "List<int>" u
     * otro nombre especializado.  Se gestiona con unique_ptr<char[]> para
     * liberar automaticamente al destruir el Loader.
     */
    std::vector<std::unique_ptr<char[]>> generic_store_names_;

    /**
     * @brief Almacen de arrays GenericParam[] clonados para especializaciones.
     *
     * Cada especializacion clona el array de parametros de tipo para poder
     * sustituir concrete sin modificar la plantilla original.
     */
    std::vector<std::unique_ptr<loader::GenericParam[]>> generic_store_params_;

    /**
     * @brief Almacen de arrays FieldInfo[] clonados para especializaciones.
     *
     * Incluye campos de instancia y arrays de argumentos de metodos clonados
     * durante la resolucion de tipos concretos en specialize_class().
     */
    std::vector<std::unique_ptr<loader::FieldInfo[]>> generic_store_fields_;

    /**
     * @brief Almacen de arrays MethodInfo[] clonados para especializaciones.
     *
     * Copia superficial de la tabla de metodos del ClassInfo generico con
     * los tipos de argumentos y retorno ya resueltos a concretos.
     */
    std::vector<std::unique_ptr<loader::MethodInfo[]>> generic_store_methods_;
};
} // namespace loader

#endif
