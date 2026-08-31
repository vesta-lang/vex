/*
 * VestaVM - Máquina Virtual Distribuida
 *
 * Copyright © 2026 David López.T (DesmonHak) (Castilla y León, ES)
 * Licencia VMProject
 *
 * USO LIBRE NO COMERCIAL con atribución obligatoria.
 * PROHIBIDO lucro sin permiso escrito.
 *
 * Descargo: Autor no responsable por modificaciones.
 */

#include "runtime/manager_runtime.h"
#include <iostream>
#include <pthread.h>
#include <cstdio> // printf

#include "runtime/runtime.h"

#include "../util/mem_stats.h"

int main() {
    runtime::ManageVM manager = runtime::ManageVM(nullptr, 0);

    uint64_t vm1_id = manager.create_vm(1); // ID=1
    uint64_t vm2_id = manager.create_vm(1); // ID=2

    printf("VM Manager %llu tiene %zu maquinas\n", vm1_id, manager.vm_count());

    for (int i = 0; i < manager.vm_count(); i++) {
        if (auto vm = manager.get_vm(i)) {
            std::cout << vm->to_string();
            printf("VMs: %zu | Arenas VM1: %zu\n", manager.vms.size(),
                   vm->manager_mem_public.arenas.size());

        } else {
            printf("VM no encontrada\n");
        }
    }

    manager.print_vm_manager_info();

    manager.destroy_vm(vm1_id);
    bool exists = manager.has_vm(vm1_id); // false
    printf("VM %llu existe: %s\n", vm1_id, exists ? "SI" : "NO");

    print_memory_stats();
    return 0;
}
