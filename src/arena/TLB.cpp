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
 * @file TLB.cpp
 * @brief Implementacion del Translation Lookaside Buffer (TLB) de VestaVM.
 *
 * Implementa las operaciones del TLB hibrido perezoso de tres niveles:
 * traduccion de direcciones virtuales a punteros del host, invalidacion
 * de entradas, insercion de mapeos y volcado de diagnostico.
 */
#include "arena/TLB.h"

#include "arena/arena.h"

namespace tlb {

/**
 * @brief Garantiza que la posicion @p idx de un vector de TLBEntry exista y
 * tenga el nivel correcto.
 *
 * Si el vector no tiene la capacidad suficiente lo redimensiona.
 * Libera la tabla hija anterior si la entrada ya era un nodo intermedio
 * y la sustituye por una nueva tabla o por datos vacios segun @p lvl.
 *
 * @note Esta funcion pertenece al TLB legado basado en TLBTable/TLBEntry.
 *       El TLB activo (LazyHybridTLB) no la utiliza.
 *
 * @param vec Vector de entradas del nivel actual.
 * @param idx Indice de la entrada que debe existir.
 * @param lvl Nivel que debe tener la entrada tras la llamada.
 * @return    Referencia a la entrada en la posicion @p idx.
 */
inline TLBEntry &ensure_level(std::vector<TLBEntry> &vec, size_t idx,
                              levelEntry lvl) {
    // el vector nunca deberia estar vacio; si ocurre es un error grave
    if (!&vec || vec.capacity() == 0) {
        VGC_CERR << "FATAL: Null vector in ensure_level!" << VGC_ENDL;
        std::abort(); // abortar: estado irrecuperable
    }

    // ampliar el vector si el indice esta fuera del rango actual
    if (idx >= vec.size()) {
        vec.resize(idx + 1, TLBEntry{}); // rellenar con entradas vacias
    }
    TLBEntry &e = vec[idx]; // referencia a la entrada objetivo

    // liberar tabla hija si la entrada ya era un nodo intermedio
    if (e.is_table && e.payload.table) {
        delete e.payload.table; // eliminar la tabla hija anterior
    }

    e.level = lvl;              // asignar el nivel indicado
    e.is_table = (lvl != DATA); // es tabla si no es una hoja de datos

    if (lvl == DATA) {
        e.payload.data =
            TLBEntryData{}; // inicializar datos de traduccion vacios
    } else {
        e.payload.table = new TLBTable(); // crear nueva tabla hija
    }
    return e;
}

/**
 * @brief Vuelca en stdout la descomposicion de una direccion virtual y su ruta
 * en el TLB.
 *
 * Imprime los cuatro campos (PT2, PT1, PT, OFFSET) extraidos de @p vpn_
 * y recorre el arbol hasta el nodo hoja para mostrar su contenido.
 * Util para depuracion en tiempo de ejecucion.
 *
 * @param vpn_ Direccion virtual a inspeccionar.
 */
#if !defined(VESTA_GC_FREESTANDING)
void LazyHybridTLB::dump_tree(uint64_t vpn_) const {
    // encabezado con la direccion completa
    std::cout << "\n=== VPN BREAKDOWN 0x" << std::hex << vpn_ << std::dec
              << " ===" << std::endl;
    std::cout << "FULL:     0x" << std::hex << vpn_ << std::dec << std::endl;

    // mostrar cada campo de la direccion virtual con su anchura en bits
    std::cout << "PT2:      " << GET_PT2(vpn_) << " (24 bits, 0x" << std::hex
              << GET_PT2(vpn_) << std::dec << ")" << std::endl;
    std::cout << "PT1:      " << GET_PT1(vpn_) << " (16 bits, 0x" << std::hex
              << GET_PT1(vpn_) << std::dec << ")" << std::endl;
    std::cout << "PT:       " << GET_PT(vpn_) << " (12 bits, 0x" << std::hex
              << GET_PT(vpn_) << std::dec << ")" << std::endl;
    std::cout << "OFFSET:   " << GET_OFFSET(vpn_) << " (12 bits, 0x" << std::hex
              << GET_OFFSET(vpn_) << std::dec << ")" << std::endl;

    // extraer los indices de cada nivel
    uint32_t pt2 = GET_PT2(vpn_);
    uint16_t pt1 = GET_PT1(vpn_);
    uint16_t pt = GET_PT(vpn_);

    // mostrar la ruta de acceso al arbol
    std::cout << "\nTLB PATH: root[" << pt2 << "] -> pt1[" << pt1 << "] -> pt["
              << pt << "] -> data" << std::endl;

    // recorrer el arbol si los nodos existen
    if (pt2 < root.size() && root[pt2]) {
        const TLBNode &n2 = *root[pt2]; // nodo de nivel PT2
        std::cout << "PT2[" << pt2 << "]: " << (int)n2.type << std::endl;
        if (pt1 < n2.children.size() && n2.children[pt1]) {
            const TLBNode &n1 = *n2.children[pt1]; // nodo de nivel PT1
            std::cout << "PT1[" << pt1 << "]: " << (int)n1.type << std::endl;
            if (pt < n1.children.size() && n1.children[pt]) {
                const TLBNode &data_node = *n2.children[pt1]; // nodo hoja PT
                std::cout << "PT[" << pt << "]: " << (int)data_node.type
                          << std::endl;
                std::cout << "  DATA: " << data_node.data.to_string()
                          << std::endl; // volcar datos de traduccion
            }
        }
    }
}

/**
 * @brief Imprime estadisticas globales del arbol TLB en stdout.
 *
 * Recorre el arbol contabilizando nodos PT2 activos, nodos PT1 activos
 * y el total de ranuras de datos (DATA slots) presentes.
 * Util para evaluar el consumo de memoria del TLB en tiempo de ejecucion.
 */
void LazyHybridTLB::dump_stats() const {
    std::cout << "\n=== LAZYHYBRIDTLB STATS ===" << std::endl;
    std::cout << "Root entries: " << root.size() << std::endl;

    int pt2_active = 0, pt1_active = 0,
        data_entries = 0; // contadores de nodos activos
    for (const auto &n2_ptr : root) {
        if (n2_ptr && n2_ptr->type == PT2) {
            pt2_active++; // contar nodo PT2 activo
            for (const auto &n1_ptr : n2_ptr->children) {
                if (n1_ptr && n1_ptr->type == PT1) {
                    pt1_active++; // contar nodo PT1 activo
                    data_entries +=
                        n1_ptr->children
                            .size(); // sumar ranuras DATA del nivel PT
                }
            }
        }
    }
    // imprimir resumen de nodos y ranuras
    std::cout << "PT2 active: " << pt2_active << ", PT1 active: " << pt1_active
              << ", DATA slots: " << data_entries << std::endl;
}
#endif // !VESTA_GC_FREESTANDING (dump_tree/dump_stats: debug iostream)

/**
 * @brief Registra o actualiza la traduccion de la pagina que contiene @p ptr_.
 *
 * Crea bajo demanda los nodos PT2, PT1 y PT necesarios para llegar al nodo
 * hoja y almacena en el la entrada de datos @p type / @p ptr_mapped.
 *
 * La funcion es idempotente: si los nodos ya existen los reutiliza sin
 * recrearlos, simplemente actualiza la hoja DATA.
 *
 * @param ptr_      Direccion virtual a mapear (se usa la pagina que la
 * contiene).
 * @param type      Tipo de destino (MAPPED_PTR_HOST, MAPPED_PTR_VM,
 * MAPPED_PTR_REMOTE).
 * @param ptr_mapped Union con la direccion real correspondiente al tipo
 * indicado.
 */
void LazyHybridTLB::translate(uint64_t ptr_, vm::type_ptr_mapped type,
                              vm::ptr_mapped ptr_mapped) {
    // descomponer la direccion virtual en sus indices de nivel
    uint32_t pt2 = GET_PT2(ptr_);
    uint16_t pt1 = GET_PT1(ptr_);
    uint16_t pt = GET_PT(ptr_);

    // ampliar el vector raiz si el indice PT2 supera el tamanyo actual
    if (pt2 >= root.size()) {
        root.resize(pt2 + 1); // rellenar con unique_ptr nulos
    }

    // NIVEL 1: crear o reutilizar el nodo PT2
    if (!root[pt2])
        root[pt2] =
            std::make_unique<TLBNode>(); // creacion perezosa del nodo PT2

    TLBNode &pt2_node = *root[pt2];
    pt2_node.type = PT2; // marcar como nodo de nivel PT2

    // NIVEL 2: crear o reutilizar el nodo PT1 dentro del nodo PT2
    if (pt1 >= pt2_node.children.size())
        pt2_node.children.resize(pt1 + 1); // ampliar hijos si es necesario

    if (!pt2_node.children[pt1])
        pt2_node.children[pt1] =
            std::make_unique<TLBNode>(); // creacion perezosa del nodo PT1

    TLBNode &pt1_node = *pt2_node.children[pt1];
    pt1_node.type = PT1; // marcar como nodo de nivel PT1

    // NIVEL 3: crear o reutilizar el nodo hoja PT dentro del nodo PT1
    if (pt >= pt1_node.children.size())
        pt1_node.children.resize(pt + 1); // ampliar hijos si es necesario
    if (!pt1_node.children[pt])
        pt1_node.children[pt] =
            std::make_unique<TLBNode>(); // creacion perezosa del nodo PT

    // almacenar la traduccion en el nodo hoja DATA
    TLBNode &pt_node = *pt1_node.children[pt];
    pt_node.type = DATA; // marcar como hoja de datos
    pt_node.data =
        TLBEntryData{type, ptr_mapped}; // guardar tipo y direccion traducida
}

/**
 * @brief Invalida la entrada TLB de la pagina que contiene @p page_vaddr.
 *
 * Reemplaza la hoja DATA con un mapeo a la direccion virtual cero de tipo
 * MAPPED_PTR_VM.  La pagina quedara como no mapeada hasta que se llame
 * de nuevo a translate().
 *
 * @param page_vaddr Direccion virtual dentro de la pagina a invalidar.
 */
void LazyHybridTLB::clear_tlb_entry(uint64_t page_vaddr) {
    vm::ptr_mapped pm{};
    pm.ptr_vm = vm::vm_map_ptr{0}; // direccion virtual cero como valor invalido
    this->translate(page_vaddr, vm::MAPPED_PTR_VM,
                    pm); // sobreescribir la hoja con el valor invalido
}

/* `get_entry` vive ahora en la CABECERA (`include/arena/TLB.h`), no aqui.
 *
 * Se llama en cada acceso a la memoria de la VM, y estando fuera de linea
 * impedia inlinar tambien sus tres indexaciones de `unique_ptr` y
 * `VirtualMemory::operator[]`, que la llama.  El motivo completo, con las
 * medidas, esta junto a la definicion. */

/**
 * @brief Devuelve el puntero real del host para una direccion virtual de tipo
 * HOST.
 *
 * Combina get_entry() con el acceso al campo ptr_host de la union.
 * Solo funciona para entradas de tipo MAPPED_PTR_HOST; devuelve nullptr
 * si la entrada no existe o es de otro tipo.
 *
 * @param vptr_ Direccion virtual a resolver.
 * @return      Puntero del host correspondiente, o nullptr si la entrada
 *              no existe o no es de tipo MAPPED_PTR_HOST.
 */
void *LazyHybridTLB::get_real_host_ptr_of_vptr(uint64_t vptr_) const {
    const TLBEntryData *entry =
        get_entry(vptr_);                 // buscar la entrada en el arbol
    if (entry == nullptr) return nullptr; // pagina no mapeada

    // rechazar entradas que no apunten a memoria del host
    if (vm::MAPPED_PTR_HOST != entry->type_address) return nullptr;

    return entry->address.ptr_host; // devolver el puntero de host almacenado
}

} // namespace tlb
