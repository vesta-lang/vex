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
 * @file runtime/vm_block_mem.h
 * @brief Rellenar y copiar BLOQUES de memoria de la maquina, en UN solo sitio.
 *
 * La memoria de la maquina no es contigua: va por paginas, con traduccion y
 * asignacion perezosa.  Una direccion virtual NO es un puntero del proceso, asi
 * que un bloque hay que recorrerlo pagina a pagina y no se puede tratar con la
 * instruccion de bloque del anfitrion.
 *
 * Ese recorrido lo necesitan DOS caminos: la instruccion de la maquina que
 * ejecuta el interprete, y el codigo compilado, que llega aqui por
 * @c vrt_vm_memset / @c vrt_vm_memcpy.  Vive aqui porque los dos tienen que
 * dejar la memoria IGUAL, y dos copias del mismo recorrido es exactamente como
 * empiezan a no dejarla -- ya paso con estas mismas operaciones: el compilado
 * emitia la variante del anfitrion sobre una direccion virtual y escribia en
 * otro sitio, con lo que un programa devolvia CERO compilado y su valor
 * correcto interpretado.
 *
 * PENDIENTE: el movimiento de bytes de cada pagina lo hace todavia la libreria
 * del sistema.  Segun el plan de `std.memory`, lo que mueve memoria tiene que
 * ser la implementacion que el usuario elija -- la misma que use el codigo
 * nativo --, no la del sistema ni una del runtime.  Cuando eso entre, se cambia
 * AQUI y las dos vias lo heredan.
 */

#ifndef VESTA_RUNTIME_VM_BLOCK_MEM_H
#define VESTA_RUNTIME_VM_BLOCK_MEM_H

#include <cstdint>

namespace runtime {

class ProcessVM;

/**
 * @brief Escribe @p len veces el byte @p value desde la direccion @p vaddr.
 *
 * @param vm    Proceso dueno de la memoria.
 * @param vaddr Primer byte, en direcciones de la maquina.
 * @param value Byte que se repite (solo cuentan sus 8 bits bajos).
 * @param len   Cuantos bytes.  Cero no hace nada.
 */
void vm_block_fill(ProcessVM &vm, uint64_t vaddr, uint8_t value, uint64_t len);

/**
 * @brief Copia @p len bytes de @p src a @p dst dentro de la memoria de la
 *        maquina.
 *
 * Admite solape: se comporta como un movimiento, no como una copia hacia
 * delante, porque las dos regiones pueden ser la misma desplazada.
 *
 * @param vm  Proceso dueno de la memoria.
 * @param dst Primer byte del destino, en direcciones de la maquina.
 * @param src Primer byte del origen, en direcciones de la maquina.
 * @param len Cuantos bytes.  Cero, o destino igual a origen, no hace nada.
 */
void vm_block_copy(ProcessVM &vm, uint64_t dst, uint64_t src, uint64_t len);

} // namespace runtime

#endif // VESTA_RUNTIME_VM_BLOCK_MEM_H
