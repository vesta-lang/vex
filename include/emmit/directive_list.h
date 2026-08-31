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
 * @file emmit/directive_list.h
 * @brief Las anotaciones del `.vel`, UNA vez y agrupadas por donde aparecen.
 *
 * De aqui salen el enum, sus nombres y su categoria.  Se incluye definiendo
 * @c VX_DIRECTIVE y cada consumidor decide que hacer con cada linea.  No lleva
 * guarda de inclusion a proposito: se incluye varias veces con macros
 * distintas, igual que @c instr_list.h.
 *
 * ## Por que existe
 *
 * El nombre de cada anotacion vivia repartido en CINCO sitios, todos como
 * cadena suelta:
 *
 *   - `annotation_handlers` (annotations.h), el registro de las de primer
 *     nivel -- y ademas un `unordered_map` estatico EN UNA CABECERA, o sea una
 *     copia por unidad de traduccion.
 *   - las busquedas de hijos en `annotations.cpp` (`"Lib"`, `"Align"`,
 *     `"IniAddress"`, ...).
 *   - las comparaciones del emisor de bytecode (`"Method"`, `"Relative"`,
 *     `"Absolute"`).
 *   - el emisor del IR, que las escribia como literales sin relacion con
 *     ninguna de las anteriores.
 *   - y `AnnKind` en `vel_sink.h`, que iba camino de ser la quinta copia.
 *
 * Eso es lo mismo que ya habia pasado con los mnemonicos, y con el mismo
 * final: dos de las listas divergen y nadie se entera hasta que algo no
 * ensambla.  Aqui la lista es una.
 *
 * ## La categoria es COMO SE ESCRIBE EL ARGUMENTO
 *
 * No "donde aparece": eso no es propiedad de la anotacion.  `@Lib` sale suelta
 * en su linea y tambien dentro de un `@Import { }`, y `@Method` es un bloque en
 * un sitio y el operando de un `calln` en otro.  Lo que SI depende solo de la
 * anotacion, y es lo que el emisor equivoca, es la forma de su argumento:
 *
 *   Quoted   entre comillas:  `@Format("elf")`, `@Name("code")`.
 *   Bare     identificador:   `@Module(mi_modulo)`, `@Export(main)`.
 *   Numeric  numero, en hex:  `@Align(0x1000)`, `@IniAddress(0x0...)`.
 *   Block    abre llaves:     `@Section { ... }`, sin argumento.
 *
 * Escribir `@Module("x")` con comillas, o `@Name(code)` sin ellas, es un error
 * que hoy nadie ve hasta que el ensamblador no entiende el fichero.  Con la
 * forma en la lista, quien emite dice QUE anotacion es y las comillas las pone
 * la lista.
 */

/* --- Bloques: abren llaves y no llevan argumento -------------------------- */
VX_DIRECTIVE(SECTION, "Section", Block)
VX_DIRECTIVE(IMPORT_BLOCK, "Import", Block)

/* --- Argumento entre comillas -------------------------------------------- */
VX_DIRECTIVE(SPACE_ADDRESS, "SpaceAddress", Quoted)
VX_DIRECTIVE(NAME, "Name", Quoted)
VX_DIRECTIVE(FORMAT, "Format", Quoted)
VX_DIRECTIVE(LIB, "Lib", Quoted)
/* ABS_REF / REL_REF y no ABSOLUTE / RELATIVE: los dos nombres obvios son
 * MACROS de `windows.h` (wingdi.h los define para los modos de relleno), y una
 * macro no respeta el ambito de un `enum class` -- el preprocesador sustituye
 * antes de que exista el enum.  El sintoma es un error de sintaxis dentro de
 * esta lista, en la linea de la entrada, sin nada que apunte a windows.h. */
VX_DIRECTIVE(ABS_REF, "Absolute", Quoted)
VX_DIRECTIVE(REL_REF, "Relative", Quoted)
VX_DIRECTIVE(METHOD, "Method", Quoted)

/* --- Argumento identificador, sin comillas ------------------------------- */
VX_DIRECTIVE(MODULE, "Module", Bare)
VX_DIRECTIVE(EXPORT, "Export", Bare)
VX_DIRECTIVE(INIT_PC, "InitPc", Bare)
VX_DIRECTIVE(GENERIC, "Generic", Bare)

/* --- Argumento numerico, en hexadecimal ---------------------------------- */
VX_DIRECTIVE(INI_ADDRESS, "IniAddress", Numeric)
VX_DIRECTIVE(END_ADDRESS, "EndAddress", Numeric)
VX_DIRECTIVE(ALIGN, "Align", Numeric)
