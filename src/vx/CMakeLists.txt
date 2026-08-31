# ============================================================================
# vx_lib: frontend del lenguaje Vesta (lexer, parser, type checker, lowering,
# facade del compilador).  Diseno aislado segun la decision arquitectonica
# del roadmap: el frontend es una libreria estatica separada que prefigura
# la futura libvesta_rt y permite reutilizarla desde tests, herramientas
# externas o un futuro servicio LSP sin arrastrar todo el binario `vm`.
#
# Dependencias internas:
#  - Ninguna sobre vm/vmcore: el frontend solo conoce ir::IrModule
#    (definido en include/ir/), y consume cabeceras de vx/.  El IR se
#    enlaza desde el ejecutable principal porque sus .cpp se incluyen
#    en el GLOB principal de src/.
#
# Dependencias externas:
#  - Ninguna mas alla de la stdlib de C++17.
# ============================================================================

# ---------------------------------------------------------------------------
# Version de CODEGEN para invalidacion de cache (.vxi / .vxir / .vpc).
#
# vxi_compiler_version_hash() usa VXI_COMPILER_BUILD_ID si esta definido.
# Aqui generamos ese identificador como un hash de las fuentes que afectan la
# SALIDA del compilador.  El header solo se reescribe cuando ese hash cambia:
#   - cambiar lowering/IR/emisores/linker -> nuevo hash -> caches invalidados.
#   - recompilar sin tocar codegen        -> mismo hash -> caches conservados.
# Esto evita el bug de "edite el compilador pero el .vxir viejo se reuso".
#
# El criterio es TODO lo que decide los bytes del artefacto, no solo el
# frontend.  El `.vpc` cachea el `.velb` FINAL, asi que la cadena entera cuenta:
#
#   .vx --[preprocesador]--> .vx --[frontend vx]--> IR --[ir_emitter]--> .vel
#       --[lexer + parser + emmit + linker]--> .velb        (o AOT/JIT/port)
#
# Faltaban los cuatro ultimos: un cambio del LINKER (layout de secciones,
# relocs, @sym) no invalidaba nada y el `.vpc` seguia sirviendo un `.velb`
# emitido por el linker viejo.  Ante la duda, sobre-invalidar: reemitir es
# barato y estas fuentes cambian poco; servir un artefacto stale no lo es.
file(GLOB_RECURSE VX_CODEGEN_SRCS
    ${CMAKE_SOURCE_DIR}/src/vx/*.cpp     ${CMAKE_SOURCE_DIR}/src/vx/*.h
    ${CMAKE_SOURCE_DIR}/include/vx/*.h
    ${CMAKE_SOURCE_DIR}/src/ir/*.cpp      ${CMAKE_SOURCE_DIR}/include/ir/*.h
    ${CMAKE_SOURCE_DIR}/src/emmit/*.cpp   ${CMAKE_SOURCE_DIR}/include/emmit/*.h
    ${CMAKE_SOURCE_DIR}/src/aot/*.c       ${CMAKE_SOURCE_DIR}/src/aot/*.cpp
    ${CMAKE_SOURCE_DIR}/include/aot/*.h
    ${CMAKE_SOURCE_DIR}/src/jit/*.cpp     ${CMAKE_SOURCE_DIR}/include/jit/*.h
    # El allocator central (rbank) + estructuras generales del codegen (RegAlloc,
    # LinearPos, AllocationTimeline...): cambiarlos cambia el codigo emitido -> deben
    # entrar al hash que invalida el cache de codegen.
    ${CMAKE_SOURCE_DIR}/include/codegen/*.h  ${CMAKE_SOURCE_DIR}/src/codegen/*.cpp
    ${CMAKE_SOURCE_DIR}/src/port/transpiler_base.cpp
    ${CMAKE_SOURCE_DIR}/src/port/c/c_backend.cpp
    ${CMAKE_SOURCE_DIR}/src/port/snippet_loader.cpp
    # --- .vel -> .velb: lo que ensambla y enlaza el bytecode final ---
    ${CMAKE_SOURCE_DIR}/src/lexer/*.cpp   ${CMAKE_SOURCE_DIR}/include/lexer/*.h
    ${CMAKE_SOURCE_DIR}/src/parser/*.cpp  ${CMAKE_SOURCE_DIR}/include/parser/*.h
    ${CMAKE_SOURCE_DIR}/src/linker/*.cpp  ${CMAKE_SOURCE_DIR}/include/linker/*.h
    ${CMAKE_SOURCE_DIR}/src/util/assembler_multiprocess.cpp
    ${CMAKE_SOURCE_DIR}/include/util/assembler_multiprocess.h
    # --- preprocesador: corre como primera etapa sobre cada .vx ---
    ${CMAKE_SOURCE_DIR}/preprocessor/src/*.c
    ${CMAKE_SOURCE_DIR}/preprocessor/src/*.cpp
    ${CMAKE_SOURCE_DIR}/preprocessor/include/*.h
)
set(VX_CODEGEN_VERSION_HDR ${CMAKE_CURRENT_BINARY_DIR}/vx_codegen_version.h)
add_custom_command(
    OUTPUT ${VX_CODEGEN_VERSION_HDR}
    COMMAND ${CMAKE_COMMAND}
        -DOUT=${VX_CODEGEN_VERSION_HDR}
        "-DSRCS=${VX_CODEGEN_SRCS}"
        -P ${CMAKE_SOURCE_DIR}/cmake/gen_codegen_version.cmake
    DEPENDS ${VX_CODEGEN_SRCS} ${CMAKE_SOURCE_DIR}/cmake/gen_codegen_version.cmake
    COMMENT "Calculando version de codegen Vesta (invalidacion de cache)"
    VERBATIM
)

add_library(vx_lib STATIC
    ${VX_CODEGEN_VERSION_HDR}
    lexer.cpp
    ast.cpp
    parser.cpp
    # Sistema UNICO de efectos del compilador: modelo (SemanticEffects/
    # MachineEffects/reticulo AbstractLoc + combinadores seq/join), summaries por
    # funcion/modulo, contratos DECLARATIVOS por reglas, y el gestor de analisis
    # de dos niveles (local por nodo + summary por funcion).  Fuente unica para
    # optimizer, scheduler, --analyze, diagramas y LSP.
    ${CMAKE_SOURCE_DIR}/src/analysis/effects/effects.cpp
    ${CMAKE_SOURCE_DIR}/src/analysis/effects/contracts.cpp
    ${CMAKE_SOURCE_DIR}/src/analysis/effects/ir_effects.cpp
    ${CMAKE_SOURCE_DIR}/src/analysis/effects/effect_analysis.cpp
    ${CMAKE_SOURCE_DIR}/src/analysis/effects/effects_report.cpp
    # Hechos IR objetivos (def-use, call-sites, estructura) para la infra de
    # analisis: base compartida que consumen los analisis sin re-recorrer el IR.
    ${CMAKE_SOURCE_DIR}/src/analysis/facts/ir_facts.cpp
    # De cuanto es multiplo un valor: el hecho con el que se pliega una
    # comprobacion de alineacion y se comprueba lo que una instruccion EXIGE.
    ${CMAKE_SOURCE_DIR}/src/analysis/facts/alignment.cpp
    # De que valor del programa habla cada operando de un bloque de asm.  Es el
    # puente entre el texto (donde un operando se llama `$0`) y el IR (donde es
    # un valor), y lo comparten el modelo de efectos, el eliminador de
    # escrituras muertas y la comprobacion de precondiciones.
    ${CMAKE_SOURCE_DIR}/src/analysis/facts/asm_bindings.cpp
    ${CMAKE_SOURCE_DIR}/src/analysis/facts/phys_liveness.cpp
    ${CMAKE_SOURCE_DIR}/src/analysis/memory/points_to.cpp
    ${CMAKE_SOURCE_DIR}/src/analysis/memory/memory_access.cpp
    ${CMAKE_SOURCE_DIR}/src/analysis/escape/escape.cpp
    asm/asm_effects.cpp
    # Resumen de efectos a nivel de bloque de un inline asm (memoria/atomica/
    # call/flags/rama/marco de pila explicito) sobre la tabla plana por
    # instruccion de asm_effects; base del compilador consciente del asm.
    asm/asm_analyze.cpp
    asm/asm_backend.cpp
    # CFG del asm inline (bloques basicos + aristas desde labels/saltos); base
    # del dataflow, los diagnosticos y los diagramas del asm.
    asm/asm_cfg.cpp
    # Diagnosticos estructurales del asm sobre el CFG (codigo muerto, salto no
    # resuelto, bucle sin salida).
    asm/asm_diag.cpp
    # Diagramas del CFG del asm anotados con coste/latencia/cuellos de botella/
    # flags/diagnosticos (mermaid + graphviz), para embeber en los diagramas.
    asm/asm_diagram.cpp
    # Lift de patrones de asm a IR tipado (lock cmpxchg/xadd -> ATOMIC_CAS/ADD):
    # atomicos escritos en asm que bajan al mismo op optimizable que el opcode.
    asm/asm_lift.cpp
    # Emision del IR tipado del lift (separada del reconocimiento, para mantener
    # el lowering minimo).
    asm/asm_lift_emit.cpp
    # Lift de asm opaco sin operandos de registro a ASM_MICRO (barreras/nop/...).
    asm/asm_lift_micro.cpp
    asm/asm_lift_registro.cpp
    # Lift GENERAL de asm inline a IR: dispatcher NEUTRO por ISA + frontend x86.
    # El core neutro (register-file + CFG driver + emisores) vive en el header
    # asm_lift_core.h; cada ISA aporta su lift_<isa> sin tocar el core.
    asm/asm_lift_general.cpp
    asm/asm_lift_x86.cpp
    # Formateador del lenguaje (estandar en doc/VMdoc/Vesta/EstiloYFormato.md).
    #
    # Solo depende del LEXER: ni del parser ni del type checker.  Eso le permite
    # formatear codigo a medio escribir -- el caso normal en un editor -- y deja
    # el modulo listo para extraerlo a una libreria propia el dia que haya quien
    # la aproveche; hoy no la hay, y sacarla ya solo duplicaria la compilacion
    # del lexer sin que nadie gane nada.
    #
    # NO se toca el camino de compilar: la trivia se recupera del texto con los
    # offsets de cada token, asi que el compilador no paga un solo ciclo.
    fmt/trivia.cpp
    fmt/width.cpp
    fmt/annotate.cpp
    fmt/spacing.cpp
    fmt/indent.cpp
    fmt/align.cpp
    fmt/literals.cpp
    fmt/verbatim.cpp
    fmt/rewrite.cpp
    fmt/fmt_driver.cpp
    fmt/fmt_cli.cpp
    fmt/wrap.cpp
    fmt/fmt.cpp
    # Catalogo multi-idioma de diagnosticos (codigo estable VXNNNN -> mensaje por
    # idioma).  La tabla se genera desde catalog/diagnostics.toml con
    # tools/import/gen_diag_catalog.py.  Seleccion de idioma por entorno.
    # Renderizado de diagnosticos en formato maquina (JSON/SARIF) para IDEs/CI.
    diag/diag_format.cpp
    # DB de instrucciones EMBEBIDA (matcher texto->FormID) + tablas generadas
    # por tools/import/gen_cpp_db.py (autocontenido, sin archivos externos).
    # La consumen ASA (asm-aware), el LSP y el optimizer JIT/AOT.
    asm/instr_db.cpp
    gen/instr_db_x86_gen.cpp
    gen/instr_db_arm64_gen.cpp
    gen/instr_db_arm32_gen.cpp
    gen/instr_db_riscv_gen.cpp
    gen/instr_db_x86_cost_gen.cpp
    gen/instr_db_arm64_cost_gen.cpp
    gen/instr_db_arm32_cost_gen.cpp
    gen/instr_db_riscv_cost_gen.cpp
    gen/instr_db_x86_feat_gen.cpp
    gen/instr_db_arm_feat_gen.cpp
    gen/instr_db_riscv_feat_gen.cpp
    # LA lista de nombres que el lenguaje reconoce sin que nadie los declare,
    # y reconocerlos de una vez por busqueda binaria en vez de comparando el
    # nombre contra doscientos literales.  La necesitan el bajador y el
    # comprobador de tipos, que antes tenian cada uno la suya.
    builtin_names.cpp
    type_checker.cpp
    # El `when:` de un contrato: gramatica, atomos y la regla de prioridad
    # entre varios que casan a la vez.  Aparte porque lo necesitan DOS TUs
    # (parser.cpp resuelve los atomos de target, type_checker.cpp los que
    # hablan del parametro de tipo) y tener dos copias del clasificador era
    # justo lo que hacia falta evitar.
    contract_when.cpp
    # Utilidades de clonacion de AST con sustitucion de type-params,
    # extraidas de type_checker.cpp (monolito) para mantenerlo manejable.
    generics/generic_clone.cpp
    # Monomorphizacion de metodos genericos `obj.metodo<U>()` (#4).
    generics/generic_methods.cpp
    # Conceptos / constraints de genericos `<T: Concepto>` / where (#6).
    generics/concepts.cpp
    # Especializacion total + parcial de structs genericos (#7).
    generics/specialization.cpp
    # Fase 0 interop C / ownership: clasificador is_c_representable / is_managed.
    type_classify.cpp
    # Fase 4 interop C: generador de header C publico (vx --emit-header).
    c_header_gen.cpp
    lombok.cpp
    lowering.cpp
    # Bajada de los builtins: las llamadas que el compilador reconoce por su
    # nombre y baja el mismo (imprimir, prestamos, atomicos, cadenas,
    # reflexion, introspeccion comptime, colecciones, concurrencia).  Eran
    # 7425 lineas dentro de lowering.cpp -- el 17% del fichero en UNA funcion.
    lowering/builtins.cpp
    # Escribir al exterior: con el runtime de la VM delante se llama a su
    # primitiva; en un binario nativo se emiten los bytes por un simbolo que el
    # programador puede REDEFINIR en Vesta.
    lowering/io.cpp
    # Imprimir: el builtin mas usado y el que mas trabajo da.  El grueso no es
    # escribir sino AVERIGUAR que se escribe -- cada tipo va distinto -- y con
    # que forma (hexadecimal, binario, alineado).
    lowering/builtins_print.cpp
    # Builtins que piden algo al MUNDO: ficheros, memoria del anfitrion, fibras
    # y modulos cargados en marcha.  Ninguno se resuelve dentro del programa, y
    # lo que devuelven es memoria del ANFITRION -- hay que marcarlo.
    lowering/builtins_runtime.cpp
    # Builtins que suponen que hay ALGUIEN MAS: memoria compartida, atomicos,
    # buzones y futuros.  Existen porque lo que uno escribe lo tiene que ver
    # el otro, y en el orden correcto.
    lowering/builtins_concurrent.cpp
    # Builtins de lo que puede NO estar: Optional y Result.  Construirlos,
    # preguntar y sacar el valor.  Ninguno toca el monton: viven en la pila.
    lowering/builtins_optional.cpp
    # Builtins de reflexion: preguntarle al programa por si mismo.  Sale
    # barato porque las clases son objetos que el propio programa
    # construye al arrancar, no metadatos del ejecutable.
    lowering/builtins_reflect.cpp
    # Builtins de quien es dueno de que y quien lo suelta: punteros con
    # dueno unico o contado, prestamos, y trasladar la propiedad.  Casi
    # todo se decide al compilar y no llega al codigo generado.
    lowering/builtins_ownership.cpp
    # Builtins de cadena: medirla, cortarla, unirla, compararla y sacarla
    # al exterior.  Cada uno baja a UNA instruccion de la maquina; cortar
    # da una vista, no una copia.
    lowering/builtins_string.cpp
    # Operaciones matematicas.  Los numeros con decimales viajan a la
    # nativa como sus BITS dentro de un entero -- la maquina pasa los
    # argumentos en registros de proposito general --; las que devuelven
    # un entero no hacen esa conversion.
    lowering/builtins_math.cpp
    # Builtins que se responden MIRANDO LOS TIPOS al compilar: cuanto mide
    # un tipo, cuantos campos tiene, si uno hereda del otro.  Su respuesta
    # no se calcula, se sabe: bajan a una constante.  Coste en ejecucion
    # exactamente cero.
    lowering/builtins_introspect.cpp
    # Emitir UNA instruccion de la maquina, con su forma exacta.  Son
    # envoltorios de tres lineas, y no sobran: concentran las marcas que
    # viajan con el valor (direccion del anfitrion, objeto del recolector,
    # indice opaco) y que deciden despues que acceso a memoria se emite.
    lowering/instructions.cpp
    # Ensamblador escrito a mano: el mini-ensamblador de bloques `asm` a nivel
    # de datos (literales, db/dw/dd/dq, times, $ y $$, con Keystone para las
    # instrucciones) y la bajada de un `asm { }` dentro de una funcion.
    lowering/asm.cpp
    # Orientacion a objetos: metodos de clase y de struct, ayudantes de
    # construccion (__new_X), la funcion de arranque del modulo que CONSTRUYE
    # las clases antes de main, y la llamada a un metodo.
    lowering/oop.cpp
    # Lo que altera el curso normal de una funcion: try/catch/finally, lanzar,
    # y la seccion protegida por un monitor (que es un try/finally con el
    # desbloqueo dentro).  Comparten el desmontaje del ambito al salir.
    lowering/exceptions.cpp
    # `match`: despachar por la FORMA de un valor.  Cada clase de patron baja
    # distinto (tabla densa de saltos, cadena de comparaciones, comparacion de
    # bytes), y elegir esa forma es el trabajo del fichero.
    lowering/match.cpp
    # Lo que se ejecuta en OTRO sitio: spawn, @Async y el spawn remoto.  Los
    # tres tienen el mismo problema: el cuerpo escrito dentro de la funcion no
    # se ejecuta ahi, hay que sacarlo y averiguar que se lleva consigo.
    lowering/async.cpp
    # Las sentencias: el control de flujo y el retorno.  No producen un valor,
    # producen una FORMA en el grafo de bloques, y se construye ya en SSA.
    lowering/statements.cpp
    # Las expresiones que CALCULAN: operadores, conversiones, condicional.  Un
    # operador no dice por si solo que instruccion sale: depende del tipo, del
    # signo y del ancho de sus operandos.
    lowering/expressions.cpp
    # Las expresiones que NOMBRAN: variable, elemento de array, campo.  Su
    # trabajo no es producir un valor sino resolver DONDE esta, y decidir si
    # quien pregunta necesita la direccion o el contenido.
    lowering/access.cpp
    # Invocar algo: llamadas, construccion de objetos y lambdas.  "Llamar" no
    # es una sola cosa (funcion del modulo, nativa, puntero a funcion, metodo
    # virtual, lambda con entorno, builtin, constructor) y averiguar cual es
    # el trabajo del fichero: cada una tiene su convencion.
    lowering/calls.cpp
    # Declarar una variable y asignarle un valor: donde vive y como llega ahi.
    # Declarar decide SI hace falta sitio, donde (pila de la VM o monton del
    # anfitrion, segun si alguien toma su direccion) y quien lo posee.
    lowering/declarations.cpp
    # Asignar: el destino puede ser variable, campo, elemento, lo apuntado por
    # un puntero, un campo de bits o una propiedad con `set`, y cada uno se
    # escribe distinto.  Si lo asignado POSEE algo, hay que soltar lo que habia.
    lowering/assignment.cpp
    # Las cadenas nativas: una cadena no es un puntero, es una estructura que
    # guarda las cortas DENTRO de si misma y solo pide memoria para las largas,
    # asi que casi ninguna operacion es directa -- hay que mirar antes en cual
    # de las dos formas esta.
    lowering/strings.cpp
    # Construir una cadena: decidir cuanto ocupa, si cabe dentro de la propia
    # estructura o hay que pedir memoria, y dejar sus metadatos coherentes.
    lowering/strings_build.cpp
    # Quien posee cada cosa y que hay que soltar al salir de un ambito.  Vesta
    # libera sin recolector, asi que el desmontaje se emite en cada via de
    # salida -- y solo si el valor no ESCAPO (devuelto, guardado, prestado).
    lowering/ownership.cpp
    # El recorrido de arriba: bajar un modulo entero y bajar una funcion.  Es
    # la parte que ORQUESTA -- que se emite, en que orden, y que hay que
    # generar aunque nadie lo escribiera -- no la que traduce.
    lowering/module.cpp
    # Mover bloques de memoria y elegir COMO segun la maquina que ejecute:
    # copiar no tiene una forma buena sino varias, y cual es la mejor no se
    # sabe al compilar.  Se emiten varias y se pregunta una vez al arrancar.
    lowering/memory_ops.cpp
    # Llegar a un campo: el de un objeto (desplazamiento sabido al compilar) y
    # el de una VISTA sobre bytes ajenos, donde el desplazamiento puede depender
    # de los campos anteriores y el orden de bytes no ser el de esta maquina.
    lowering/fields.cpp
    # Lo que ya se sabe al compilar: se baja su RESULTADO, no su calculo.  Va
    # con la introspeccion porque es lo mismo del otro lado: lo que el programa
    # puede preguntar de un tipo viaja como datos ya escritos en el binario.
    lowering/comptime.cpp
    # Los structs, que NO son clases: un struct es un VALOR -- vive donde se
    # declaro, se copia al pasarlo, muere sin que nadie lo recoja --, asi que
    # su bajada es otra aunque tambien tenga campos y metodos.
    lowering/structs.cpp
    # De los tipos de Vesta a los del IR, y las conversiones entre ellos: el
    # lenguaje tiene mas tipos de los que el IR distingue, y convertir mal no
    # da un error sino un numero distinto.
    lowering/types.cpp
    # Que nombre se refiere a que valor en cada punto: en SSA reasignar no
    # cambia el valor, crea otro, y una variable de la que se toma la direccion
    # deja de vivir en un valor para vivir en memoria.
    lowering/scopes.cpp
    # Auto-vectorizacion de bucles (idiomas memcpy/copy; futuro unroll+SIMD).
    # Metodos de Lowering separados de lowering.cpp para mantenerlos agrupados.
    vectorize.cpp
    borrow_checker.cpp
    compiler.cpp
    compiler_project.cpp
    # Traductor de los tipos de Vesta a entidades de la base de conocimiento de
    # depuracion (vxdbg).  Vive en el frontend porque la correspondencia entre
    # el vocabulario de Vesta y el modelo generico solo la conoce quien declara
    # los tipos; vxdbg no sabe de ningun lenguaje.
    vxdbg_emit.cpp
    # Que se LEE de un texto .vel -- mnemonico, etiqueta, llamada, destino del
    # salto, instruccion fusionada.  Comun a los dos generadores, porque la
    # respuesta no depende del formato en el que luego se dibuje.
    diagram/vel_text_model.cpp
    # Como se LEE una expresion, un tipo, un valor o una instruccion del IR.
    # Tampoco depende del formato en el que se dibuje.
    diagram/diagram_labels.cpp
    diagram/mermaid_diagrams.cpp
    diagram/graphviz_diagrams.cpp
    diagram/html_diagrams.cpp
    # Subsistema de coste Big-O (modo --analyze).  Solo depende de
    # ir::IrModule; vive aqui para que los renderers de diagramas puedan
    # anotar el coste por funcion (--diagram-cost).
    ${CMAKE_SOURCE_DIR}/src/analyze/bigo.cpp
    # Huella computacional por-declaracion (recursos + efectos): base del
    # modelo dirigido por resumenes y de las anotaciones comprobables.
    ${CMAKE_SOURCE_DIR}/src/analyze/fingerprint.cpp
    ${CMAKE_SOURCE_DIR}/src/analyze/asm_report.cpp
    # El asm como dominio del ASA (productor de hechos): vive junto al informe
    # porque comparte la base de datos de instrucciones.
    ${CMAKE_SOURCE_DIR}/src/analyze/asa_asm.cpp
    # La huella como dominio del ASA: la verdad INFERIDA (si lanza, si es pura,
    # cuanto reserva).  Vive aqui porque necesita la maquinaria de efectos.
    ${CMAKE_SOURCE_DIR}/src/analyze/asa_fingerprint.cpp
    # El linter: el primer CONSUMIDOR del ASA.  No analiza -- pregunta a la
    # base de hechos y compara lo demostrado con lo declarado -- y por eso vive
    # al lado de los dominios que consulta, no dentro de ellos.
    ${CMAKE_SOURCE_DIR}/src/analyze/linter.cpp
    ${CMAKE_SOURCE_DIR}/src/analyze/lint_cli.cpp
    # "Compila este IR y damelo listo para ejecutar": la cadena emitir ->
    # ensamblar -> cargar, en UN sitio.  Estaba escrita a mano en el precomputo
    # del arranque y en el camino de las macros; y la necesita ademas la
    # ejecucion comptime perezosa, que es lo que permite quitar el tree-walker.
    comptime/compile_service.cpp
    comptime/comptime_introspect.cpp
    # Recolector del conjunto comptime (P1 fase 1: base del artefacto comptime
    # separado que compilara/ejecutara todo el comptime en la ComptimeVM).
    comptime/comptime_collect.cpp
    # El artefacto comptime por contenido: compila el conjunto una vez y lo
    # reusa via el CAS
    comptime/comptime_artifact.cpp
    # Constructor `comptime T(expr)` de structs: literales de tipo usuario (F1b).
    comptime/literal_ctor.cpp
    # Sistema de modulos.
    module/module_resolver.cpp
    module/module_interop.cpp
    module/namespace_flatten.cpp
    # Indice semantico por-declaracion (hash de contenido + grafo de deps):
    # sustrato de la compilacion incremental granular y distribuida.
    semantic_index.cpp
    # Huella del contenido con SIGNIFICADO de un fuente (tokens, no bytes).
    source_hash.cpp
    # Driver incremental granular: claves Merkle + CAS + plan_rebuild.
    incremental.cpp
    module/vxi_format.cpp
    project_cache.cpp
    velb_signature.cpp
    # comptime_vm.cpp vive en src/runtime/ (depende del runtime VM).
    # Transpiler IR -> codigo fuente (C inicial; Java/JS/etc futuro).
    # Vive aqui porque compiler.cpp lo invoca como ultimo paso opcional.
    # Si en el futuro se quiere usar el transpiler standalone, se extrae
    # a su propia libreria port_lib en CMakeLists del root.
    ${CMAKE_SOURCE_DIR}/src/port/transpiler_base.cpp
    ${CMAKE_SOURCE_DIR}/src/port/c/c_backend.cpp
    # Cargador de snippets compartido (stdlib/port/c) -- backend C + header gen.
    ${CMAKE_SOURCE_DIR}/src/port/snippet_loader.cpp
)

# La libreria expone sus headers desde include/vx/; PUBLIC para que los
# consumidores (vm, tests) los hereden automaticamente al linkear.
target_include_directories(vx_lib PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)
# El header generado con VXI_COMPILER_BUILD_ID es PRIVATE (solo lo usa
# vxi_format.cpp).  Dependencia explicita para que CMake genere el header
# antes de compilar ese TU y lo recompile cuando el header cambie.
target_include_directories(vx_lib PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
# Los codecs de vxdbg comparten un header interno que no forma parte de su API
# publica: se ve desde su propia carpeta y de ningun otro sitio.
target_include_directories(vx_lib PRIVATE ${CMAKE_SOURCE_DIR}/src/vxdbg)
set_source_files_properties(module/vxi_format.cpp PROPERTIES
    OBJECT_DEPENDS ${VX_CODEGEN_VERSION_HDR})

# C++17 minimo (consistente con el resto del proyecto).
target_compile_features(vx_lib PUBLIC cxx_std_17)
# PIC se activa globalmente en el CMakeLists raiz (CMAKE_POSITION_INDEPENDENT_
# CODE ON) para que vx_lib enlace tambien en la libreria compartida embebible
# vesta_ffi (libvesta.so).  No hace falta fijarlo aqui.

# velb_signature.cpp usa OpenSSL EVP_DigestSign / EVP_DigestVerify.
# Enlace centralizado en `vesta_openssl` (estatico/standalone o FireDaemon).
target_link_libraries(vx_lib PRIVATE vesta_openssl)
# El grafo de conocimiento del programa es una libreria aparte: ni es de Vesta
# ni de la maquina, y el runtime tambien lo necesita.
target_link_libraries(vx_lib PUBLIC vxdbg_lib diag_lib)

# Avisos estrictos en builds nuestros para mantener la regla de "no warnings".
if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(vx_lib PRIVATE -Wall -Wextra -Wpedantic)
endif()
