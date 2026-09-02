#include "arena/VirtualMemory.h"

int main() {
    vm::ArenaManager arena_mgr;
    tlb::LazyHybridTLB tlb;
    vm::VirtualMemory vm_mem(tlb, arena_mgr);

    // COMO SI FUERA MEMORIA LINEAL
    vm_mem[0x1000] = 0x42; // Auto-crea página 0x1000
    vm_mem[0x2000] = 0xAA; // Auto-crea página 0x2000
    vm_mem[0x1FFF] = 0xFF; // Misma página 0x1000

    vm_mem[0x10000FFF] = 0xFF;

    printf("0x1000: 0x%02x\n", vm_mem[0x1000]);         // 0x42
    printf("0x10000FFF: 0x%02x\n", vm_mem[0x10000FFF]); // 0x42

    uint8_t bytecode[] = {
        0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
    };

    /* READ|WRITE, no READ a secas.
     *
     * `MemPerm::READ` baja a
     * `PAGE_READONLY` en Windows y a `PROT_READ` en
     * Linux, asi que el
     * memset y el memcpy de mas abajo escribian en memoria
     * de SOLO
     * LECTURA y el sistema se llevaba el proceso por delante.  No
     *
     * fallaba el mapeo, que es legitimo: fallaba usarlo para lo contrario de

     * * lo que se habia pedido. */
    vm::vm_map_ptr code =
        vm_mem.map(0x400000, 0x10000, vm::MemPerm::READ | vm::MemPerm::WRITE);
    vm_mem.vm_to_host_memset(0x400000, 0x33, 0x10000);

    const size_t BYTES_PER_LINE = 16;
    size_t count = 0;
    for (int i = 0; i < 0x10000 / 0x100; i++) {
        // Nueva línea cada 16 bytes
        if (count % BYTES_PER_LINE == 0) {
            if (count != 0) std::cout << "\n";
            std::cout << std::setw(8) << std::setfill('0') << std::hex << count
                      << ": ";
        }
        // Imprimir byte en hex, 2 dígitos
        std::cout << std::setw(2) << std::setfill('0') << std::hex
                  << (int)vm_mem[0x400000 + i] << " ";
        count++;
    }
    putchar('\n');

    vm_mem.vm_to_host_memcpy(0x400000, bytecode, sizeof(bytecode));

    tlb::TLBEntryData *tlb_entry = tlb.get_entry(code.raw);
    std::cout << tlb_entry->to_string() << std::endl;

    for (int i = 0; i < 0x10000; i += 0x1000) {
        printf("vptr [0x%p] -> %p\n", (void *)(0x400000 + i),
               tlb.get_real_host_ptr_of_vptr(0x400000 + i));
    }

    tlb.dump_tree(0x1000); // Debug estructura
    return 0;
}
