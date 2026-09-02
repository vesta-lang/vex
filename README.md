<div align="center">
  <img src="./Component 1.svg" width="180" height="180" alt="VestaVM logo" />

# VestaVM

**Una máquina virtual distribuida y un lenguaje moderno, diseñados juntos desde cero.**

[![Licencia](https://img.shields.io/badge/licencia-VMProject-blue.svg)](./LICENSE.md)
[![Estado](https://img.shields.io/badge/estado-interp%20%2B%20JIT%20%2B%20AOT%20nativo-brightgreen.svg)](./doc/ROADMAP.md)
[![Tests](https://img.shields.io/badge/tests-793%2F793%20PASS-brightgreen.svg)](./tests/vx/)
[![AOT](https://img.shields.io/badge/AOT%20nativo-1.65×%20vs%20C%20(geomean)-orange.svg)](./doc/BENCHMARKS.md)
[![JIT](https://img.shields.io/badge/JIT-12×%20vs%20interp%20%2F%20peak%20251×-orange.svg)](./doc/BENCHMARKS.md)
[![Plataformas](https://img.shields.io/badge/plataformas-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](#inicio-r%C3%A1pido)

[**Inicio rápido**](./doc/QUICKSTART.md) · [**El lenguaje Vesta**](./doc/LANGUAGE.md) · [**Arquitectura**](./doc/ARCHITECTURE.md) · [**Benchmarks**](./doc/BENCHMARKS.md) · [**Roadmap**](./doc/ROADMAP.md)

</div>

---

## ¿Qué es VestaVM?

**VestaVM** es una plataforma completa de ejecución de programas que integra tres
componentes diseñados desde cero para trabajar juntos:

1. **[Vesta](./doc/LANGUAGE.md)** — un lenguaje multi-paradigma estáticamente tipado
   con sintaxis C/Java/Python combinada. Soporta clases con herencia/interfaces/AOP,
   genéricos, async/await, pattern matching, borrow checker estilo Rust, smart
   pointers (`unique<T>`/`shared<T>`), FFI nativo declarativo, reflexión runtime,
   y un sistema de **metaprogramación** compile-time potente (`@Macro`, captura
   raw `expr`, introspección zero-overhead, FFI en tiempo de compilación).

2. **Compilador y runtime** — pipeline `Vesta -> SSA IR -> bytecode .velb -> VM`. Más
   de 15 pasadas de optimización SSA, dispatcher threaded computed-goto
   (~313 MIPS sostenidos), GC generacional **preciso y movible** (young+old,
   scan por stackmaps + mark-compact deslizante del OldGen + nursery preciso
   + write-barrier old->young), y un JIT con **asignador de registros real**
   (banco de vregs, spilling, coalescing) que da **12× speedup geomean y hasta
   251×** sobre el intérprete. Además, un **compilador AOT** que produce
   ejecutables nativos **standalone** (PE en Windows y ELF en Linux) sin
   runtime de la VM, con **linker y archivador propios** (`vm --link` /
   `vm --ar`, sin depender de `ld`/`gcc`/`ar` del sistema).

3. **Sistema distribuido nativo (VDP)** — protocolo propio sobre TCP/TLS para
   `rspawn` (spawn remoto), mensajería entre nodos, descubrimiento UDP en LAN,
   y autenticación token/mTLS. La distribución es parte del bytecode, no RPC
   externo.

El proyecto incluye también una shell interactiva (REPL), un lenguaje de scripting
embebido (VestaShellScript `.vsh`), un debugger TCP, y un editor TUI escrito
en el propio Vesta.

---

## Ejemplo: cómo se ve Vesta

```vx
// Pattern matching, smart pointers y borrow checker en 25 lineas.

// Un resultado con dos formas: el valor, o el motivo del fallo.
enum Reparto {
    Ok(i64),
    Err(string)
}

Reparto reparte(i64[] nums, i64 n, i64 divisor)
{
    if (divisor == 0) { return Reparto.Err("division por cero"); }

    // El total vive en el heap: `unique` lo libera al salir del ambito y el
    // borrow checker garantiza que nadie mas lo toca mientras esta prestado.
    unique<i64> total = unique_box(0);
    borrow_mut<i64> vista = lend_mut(total);

    i64 i = 0;
    while (i < n) {
        write_borrow(vista, read_borrow(vista) + nums[i] / divisor);
        i = i + 1;
    }
    return Reparto.Ok(read_borrow(vista));
}

i32 main()
{
    i64[4] datos = {10, 20, 30, 40};

    match reparte(datos, 4, 2) {
        case Ok(suma) => println("suma = ${suma}");
        case Err(msg) => println("error: ${msg}");
    }
    return 0;
}
```

Más ejemplos completos en [`examples_codes_vx/`](./examples_codes_vx/) (420+
programas) y showcase curado en [doc/EXAMPLES.md](./doc/EXAMPLES.md).

---

## Características destacadas

### Lenguaje (Vesta)

- **Multi-paradigma**: imperativo + POO + funcional ligero. Sin envoltura
  `class` obligatoria.
- **Tipado estático con inferencia local** y nullability explícita
  (`Optional<T>`, `Result<V,E>`, `nonnull T`, `T !!name`).
- **POO completa**: clases, herencia simple + interfaces, propiedades get/set,
  modificadores `public`/`private`/`protected`/`static`/`final`, destructores
  RAII.
- **AOP nativo**: `@Aspect` con `@Before`/`@After`/`@Around` y `proceed()`.
- **Reflexión runtime**: `forName`, `getClass`, `getField`, `getMethod`,
  `invoke`, `newInstance`.
- **Genéricos** por monomorphización compile-time + fallback runtime con
  `specialize`. Clases, enums, **structs** (`struct Caja<T>`) y **funciones
  libres** (`R id<T>(...)`) genéricas, con inferencia de tipos (`auto`/CTAD).
- **Async / concurrencia**: `@Async`/`await`/`Future<T>`, `spawn`/`spawn here`/
  `spawn on(N)`/`rspawn`, mailboxes (`msgsend`/`msgrecv`), `synchronized` con
  cleanup automático.
- **Fibras / green threads** cooperativos self-hosted en Vesta (cuerpos de fibra
  en Vesta normal, scheduler cooperativo `yield`/`resume`). Context-switch por
  backend (`swapctx` en intérprete, `fiber_switch` nativo en JIT/AOT) y
  comportamiento **idéntico en los 3 modos** (interp/JIT/AOT, PE y ELF); el JIT
  compila las fibras a nativo sin recaer en el intérprete.
- **Pattern matching** exhaustivo (`match`/`case` con bindings).
- **Smart pointers** zero-overhead: `unique<T>`, `shared<T>` con deleters custom
  para adoptar cualquier recurso del SO.
- **Borrow checker** compile-time estilo Rust con 4 reglas + NLL + reborrow con
  suspend stack + lifetime elision.
- **FFI** declarativo a DLLs (`extern "lib.dll" { fn ...; }`) y runtime
  (`ffi_open`/`ffi_sym`/`ffi_call`).
- **Punteros a función / funciones de primera clase** nativos: `cfn(...)->R`
  (puntero crudo, 8 bytes) distinto del lambda `fn(...)->R` (fat-pointer 16
  bytes), con `&funcion`/`&obj.metodo`; `CALLIND`/`&fn` resuelven a código
  nativo tanto en JIT como en AOT.
- **`synchronized` hookeable** via `@SyncImpl`: el programador sustituye el
  monitor por spinlock, pthread, disable-IRQ (kernel) o lock cooperativo de
  fibras — igual que `@AllocatorOverride`/`@PanicHandler`/`@CustomGC`.
- **Strings** UTF-8/16/32, interpolación `${expr}`, format specifiers
  `${expr:hex:>20}`, triple-quoted. Color de terminal via identificadores
  mágicos (`RED`/`GREEN`/`BOLD`/`RESET`) y **truecolor ANSI 24-bit** con
  `fg_rgb(r,g,b)`/`bg_rgb(r,g,b)` (componentes runtime).
- **Metaprogramación compile-time**: `@Macro` que genera código Vesta inyectable,
  captura raw de expresiones arbitrarias (`asm walk(ptr -> 0x10 -> 0x20)`),
  introspección de tipos sin overhead (`sizeof<T>`, `typename<T>`, `kind<T>`,
  `field_count<T>`, `for_each_field<T>`), FFI en tiempo de compilación que
  invoca DLLs del sistema durante el build y embebe los resultados como
  literales, `static_assert(cond, "msg")` con condiciones comptime-evaluables.

### Runtime y compilador

- **Pipeline SSA completo**: ~15 pasadas (DCE, CSE, copy-prop, const-fold, TCO,
  LICM, DSE+SLF, devirt+inline, load_narrow, list scheduling para ILP).
- **Asignador de registros con banco de vregs** (spilling, coalescing,
  hinting, splitting con recuperación de fragmentación), compartido por JIT
  y AOT.
- **Dispatcher threaded computed-goto** + inline del icache hit path
  (intérprete ~313 MIPS promedio).
- **JIT** con regalloc real y stackmaps precisos para GC: **12× speedup
  geomean** sobre intérprete (mediana 13×, pico **251×** en `vec_axpy`), y
  **6.0× de slowdown geomean frente a C nativo**.
- **AOT nativo**: **43× geomean** sobre intérprete (pico 416×) y solo
  **1.65× más lento que C** en media geométrica — por delante de Go (2.52×)
  y a la par de Rust (1.55×).
- **Auto-vectorizacion**: los bucles elemento a elemento (aritmeticos,
  unarios y de reduccion) y el idioma de copia de bytes bajan a operaciones
  vectoriales de 256 bits, en el JIT y en el binario nativo.  Se apaga con
  `VESTA_NO_VECTORIZE=1`; `tools/verify_vectorize.py` comprueba que no cambia
  ningun resultado del corpus y `tools/bench_vectorize.py` cuanto gana.
- **SIMD como LIBRERIA, no como magia del compilador**: `stdlib/vx/simd_string.vx`
  aporta un `strcmp` vectorizado que un `import` HEREDA (via
  `@HelperOverride`), con auto-despacho SSE2/AVX2 leyendo `cpu_features()`.
  Se lee, se modifica y se sustituye como cualquier otro codigo Vesta.
- **Super-instrucciones**: `cmpjmp`/`cmpjmpu`, `decjnz`, `alu3` (9 variantes
  fusionando `mov+OP`), `loadz`/`loadzh` (zero-extend LOAD), `mvtake`,
  `gcallocp`, `spawnargs`, `fulfillhlt`.
- **GC generacional preciso y movible** Young/Old: scan preciso vía stackmaps
  + **mark-compact** (OldGen deslizante in-place) + nursery preciso +
  write-barrier old->young, funcionando en intérprete, JIT y AOT.
- **Multi-threading** real opcional con scheduler placement (`spawn here`,
  `spawn on(N)`).
- **Profile-Guided Optimization (PGO) foundation**: contadores runtime
  zero-overhead (~1 ciclo cuando inactivo, atomic load + branch
  predicted-not-taken) instrumentan branches condicionales (taken/not_taken
  por PC), tipos observados en call sites virtuales (`callvirt`/`callm`,
  hasta 4 tipos distintos por site + contador de megamorfismo polimórfico),
  y allocations por PC. Volcado a fichero binario `.vprof` al exit del
  proceso, consumible por el JIT (warm-start de funciones hot del run
  anterior) y por el compilador AOT (decisiones especulativas hard-coded
  en el ejecutable nativo).

### Sistema distribuido

- **Protocolo VDP** nativo sobre TCP, opcionalmente cifrado con TLS (mTLS o
  token CRAM SHA-256).
- **Descubrimiento UDP** automático de nodos en LAN.
- **rspawn** transparente: el bytecode envía procesos a nodos remotos como si
  fueran locales; `Future<T>` resuelve cross-node automáticamente.
- **memsync** para sincronización de regiones de memoria entre nodos.

### Herramientas

- **REPL** con TAB completion, historial, búsqueda incremental Ctrl+R, aliases,
  variables de entorno, scripts de inicio (`~/.vestarc`).
- **VestaShellScript (.vsh)** — lenguaje embebido para scripting del REPL.
- **Debugger TCP** con protocolo JSON: breakpoints (por addr o `file.vx:line`),
  step/continue, inspección de registros/memoria/stack, GC stats, source-aware.
- **Diagramas Mermaid** del pipeline: `--diagram-vx/ir/vel/all` para AST, SSA
  IR, bytecode visualizado.
- **Map file de simbolos** opt-in via `--emit-map` (debug; off por defecto
  porque cuesta ~60% del tiempo del linker).
- **Profiler del linker** integrado via `VESTA_LINKER_PROFILE=1` (timing
  fase a fase + bytes emitidos por sección).
- **Ensamblador/desensamblador nativo** integrado (Keystone + Capstone) para
  x86, x86_64, ARM, AArch64.
- **Profile dump** via `--profile [path]` (default: `program.vprof`).
  Alternativa por entorno: `VESTA_PROFILE_DUMP=path`. Genera `.vprof`
  binario al exit con counters de branches, tipos observados en cada
  call site polimórfico, y allocations por PC. Sirve tanto al JIT
  (warm-start) como al pipeline AOT futuro (PGO en ejecutables nativos).

---

## Inicio rápido

```bash
# Clonar (incluye submódulos: Keystone, Capstone, LibPEparse)
git clone --recursive https://github.com/desmonHak/VM.git
cd VM

# Compilar (CMake + GCC/Clang)
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build

# Hola Mundo en Vesta
cat > hola.vx << 'EOF'
i32 main() {
    println("Hola desde Vesta ${1 + 1}!");
    return 0;
}
EOF

./build/vm --vesta hola.vx -o hola
./build/vm --run hola.velb
# -> Hola desde Vesta 2!
```

Guía completa: [**doc/QUICKSTART.md**](./doc/QUICKSTART.md) (5 minutos).

---

## Estado del proyecto

VestaVM tiene el frontend Vesta + intérprete + GC + distribuido completos, un
JIT con asignador de registros real (banco de vregs, sin divergencia frente al
intérprete en todo el corpus) y un **compilador AOT nativo funcional**: `-m aot`
produce ejecutables **standalone** (PE en Windows y ELF en Linux, este último
validado corriendo en WSL) sin runtime de la VM, con linker y archivador
propios (`vm --link`/`vm --ar`, sin `ld`/`gcc`/`ar` del sistema). Los tres
tiers de deployment (Full/Embed/Bare) están en construcción; el path nativo
core — enteros, float, structs, POO no-virtual, FFI e inline-asm — ya genera
binarios que corren. El **GC** es ahora **preciso y movible** (mark-compact +
nursery preciso + write-barrier) en los tres modos. Las **fibras nativas
suspendibles** (green threads cooperativos) funcionan idéntico en interp/JIT/AOT.
Los macros bajan al IR y se ejecutan vía VM con cache persistente y JIT opcional.
**PGO foundation** disponible vía `--profile <path>` que genera `.vprof`
consumible por el JIT (warm-start) y el compilador AOT.

**Suite de tests E2E**: **793 pasos OK / 0 fallidos** sobre 391 casos
(`python tests/vx/e2e_test.py <build-dir>`), cubriendo los 420+ ejemplos del
repo en los tres modos (intérprete, JIT y AOT nativo) más los tests negativos
y positivos del borrow checker.

### Estadísticas clave

La suite de benchmarks abarca **29 workloads multi-lenguaje** con `main.vx`,
`main.c`, `main.cpp`, `main.py`, `Main.java`, `main.go` y `main.rs` cada uno; el
runner es `tools/bench/run_all_benches.py`. Las cifras de abajo provienen de la
corrida completa del **2026-07-25** (11 lenguajes/modos, 29 workloads, 10 runs +
1 warmup por bench, 3 runs en los lentos), sobre Intel Core i7-13700KF (16P/24L,
3.4 GHz base) + 63.8 GB RAM, Windows 10, antivirus desactivado durante la
medicion y sin timeouts. El modo AOT se mide en tres variantes (`sse2`, `avx`,
`auto` con multiversion por CPUID); la columna publicada es `auto`.

| Metrica | Valor |
|---|:---:|
| **Suite e2e Vesta** | 793/793 pasos OK (391 casos, 3 modos) |
| **Interprete: MIPS promedio** | ~313 (threaded computed-goto + super-instr) |
| **AOT vs interprete: geomean / mediana / pico** | **43.4x** / 52.8x / **416x** (`vec_axpy`) |
| **JIT vs interprete: geomean / mediana / pico** | **12.0x** / 13.0x / **251x** (`vec_axpy`) |
| **JIT vs interprete: >=25x / >=10x** | 7/29 / 18/29 benches |
| **AOT vs interprete: >=50x / >=10x** | 16/29 / 26/29 benches |
| **AOT: slowdown geomean vs C nativo** | **1.65x** (mediana 1.48x) |
| **JIT: slowdown geomean vs C nativo** | **5.99x** (mediana 6.33x) |
| **Rust (rustc -O) vs C** | 1.55x |
| **Go (gc) vs C** | 2.52x |
| **C++ (g++ -O2) vs C** | 1.00x (paridad) |
| **HotSpot C2 (Java) vs C** | 10.59x |
| **CPython 3.11 vs C** | 139.95x |
| **AOT: benches ganados** | 29/29 vs Java y Python, 18/29 vs Go, 10/29 vs Rust, 3/29 vs C++ |
| **JIT: benches ganados** | 27/29 vs Java, 28/29 vs Python |

**Top aceleraciones interprete -> AOT nativo** (mediana de 10 runs):

| Benchmark | Interp. | AOT | Aceleracion |
|---|---:|---:|---:|
| `vec_axpy` | 18327 ms | **44.1 ms** | **416x** |
| `intops_jit` | 1208 ms | **5.8 ms** | **207x** |
| `mem_malloc_free` | 647 ms | **4.7 ms** | **139x** |
| `rotops_jit` | 649 ms | **5.2 ms** | **126x** |
| `branch_unpredict` | 3201 ms | **26.2 ms** | **122x** |
| `int_mixed` | 2113 ms | **22.5 ms** | **94x** |
| `state_machine` | 2751 ms | **37.6 ms** | **73x** |
| `mem_struct` | 320 ms | **4.4 ms** | **73x** |

**Top aceleraciones interprete -> JIT**:

| Benchmark | Interp. | JIT | Aceleracion |
|---|---:|---:|---:|
| `vec_axpy` | 18327 ms | **73.0 ms** | **251x** |
| `branch_unpredict` | 3201 ms | **55.0 ms** | **58x** |
| `int_mixed` | 2113 ms | **47.3 ms** | **45x** |
| `state_machine` | 2751 ms | **62.7 ms** | **44x** |
| `intops_jit` | 1208 ms | **32.9 ms** | **37x** |
| `bitops` | 2301 ms | **66.9 ms** | **34x** |
| `obj_accum` | 1754 ms | **67.7 ms** | **26x** |
| `struct_field` | 1220 ms | **49.7 ms** | **25x** |

**Interprete**: ~313 MIPS de media sobre la suite. Dispatcher threaded
computed-goto, super-instrucciones (`alu3`, `loadz`, `cmpjmp`, `decjnz`),
coalescing en el regalloc, `schedule` para ILP y elision por `load_narrow`.

**JIT**: el camino de produccion es el banco de vregs con asignador de
registros real; el selector de slots legacy esta jubilado y una operacion no
cubierta cae al interprete de forma transparente. Los bucles aritmeticos
calientes rinden **25-251x**; la recursion profunda -- caso historicamente
duro para un JIT -- llega a 13x gracias a TAILCALL nativo (`call + ret`
fusionados, sin pool de FrameHeader) y a la llamada auto-recursiva parcheada
directamente a `code_start`, sin trampolin JIT->interprete.

**AOT**: el mismo IR y el mismo asignador que el JIT, pero emitiendo un
ejecutable nativo autonomo. Sin el coste de arranque del JIT ni el del
interprete, el geomean sube a **43x** sobre el interprete y el slowdown
frente a C baja a **1.65x**.

### Comparativa multi-lenguaje (workloads identicos)

Tiempos wall en ms (mediana de 10 runs; i7-13700KF, Windows 10). En cada
fila, **el mas rapido en negrita**:

| Bench | C | C++ | Rust | Go | **Vesta AOT** | Vesta JIT | Java | Python |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `alloc` | 2.8 | **2.8** | 127.3 | 48.5 | 3.1 | 30.6 | 71.6 | 569.4 |
| `array_sum` | 4.5 | 4.8 | **4.0** | 12.1 | 9.2 | 35.4 | 77.8 | 465.0 |
| `bitops` | 26.4 | 26.4 | **21.4** | 33.7 | 38.9 | 66.9 | 94.3 | 7128.3 |
| `branch_unpredict` | **17.7** | 18.0 | 19.9 | 20.5 | 26.2 | 55.0 | 171.9 | 3193.1 |
| `callvirt` | **2.9** | 3.9 | 3.2 | 29.2 | 6.6 | 34.3 | 75.7 | 1771.3 |
| `callvirt_hot` | 10.8 | **4.5** | 11.4 | 12.8 | 4.6 | 32.6 | 70.5 | 724.1 |
| `cmp_fusion` | **2.6** | 2.6 | 3.2 | 14.6 | 12.8 | 52.2 | 74.3 | 1847.4 |
| `fib_recursive` | 6.1 | **6.0** | 7.4 | 12.6 | 13.0 | 38.5 | 77.4 | 244.7 |
| `fp_jit` | 10.7 | 10.8 | **10.0** | 21.6 | 42.6 | 68.7 | 93.0 | 1354.5 |
| `hash_lookup` | **13.3** | 13.6 | 67.2 | 65.3 | 63.4 | 89.3 | 129.1 | 6454.9 |
| `int_mixed` | 47.0 | **18.3** | 18.9 | 20.5 | 22.5 | 47.3 | 86.2 | 10663.8 |
| `intops_jit` | **2.9** | 3.2 | 5.2 | 7.5 | 5.8 | 32.9 | 75.5 | 1068.9 |
| `jit_method` | 3.6 | 3.6 | **3.2** | 11.5 | 8.6 | 35.0 | 75.2 | 1176.9 |
| `mem_class` | **7.7** | 8.4 | 27.9 | 12.3 | 11.1 | 27.8 | 69.7 | 180.3 |
| `mem_malloc_free` | 3.6 | **3.6** | 126.2 | 88.5 | 4.7 | 28.5 | 69.3 | 581.1 |
| `mem_struct` | 3.8 | **2.6** | 53.1 | 19.8 | 4.4 | 29.6 | 71.3 | 438.1 |
| `memcpy_loop` | 5.1 | 5.5 | 5.2 | 21.2 | **4.9** | 30.6 | 97.2 | 3315.1 |
| `nested_loops` | 13.3 | 13.5 | 29.4 | 88.3 | **12.5** | 36.7 | 79.0 | 1567.3 |
| `obj_accum` | 28.2 | 28.2 | **18.2** | 31.8 | 41.5 | 67.7 | 96.0 | 4172.9 |
| `pic_real` | 5.4 | 5.6 | **5.2** | 7.1 | 10.5 | 481.9 | 73.5 | 304.6 |
| `polymorphic` | 8.1 | 8.2 | **8.0** | 12.6 | 22.4 | 50.6 | 77.7 | 1047.3 |
| `quicksort` | **6.9** | 7.4 | 7.9 | 9.1 | 8.4 | 33.5 | 76.7 | 149.5 |
| `rotops_jit` | **3.6** | 4.1 | 15.2 | 6.7 | 5.2 | 30.5 | 73.3 | 1362.2 |
| `state_machine` | 19.0 | 18.6 | **17.2** | 23.6 | 37.6 | 62.7 | 86.5 | 1553.0 |
| `string_hot` | 8.4 | 21.9 | 12.8 | 18.4 | **7.9** | 27.5 | 80.2 | 61.0 |
| `string_workout` | 29.8 | 38.1 | **12.3** | 19.4 | 55.5 | 257.5 | 181.9 | 517.6 |
| `struct_field` | 4.9 | 5.4 | **3.9** | 17.6 | 20.4 | 49.7 | 77.0 | 5060.2 |
| `tight_loop` | 12.6 | 12.4 | **3.0** | 20.9 | 12.8 | 38.2 | 78.7 | 1024.9 |
| `vec_axpy` | **17.5** | 17.5 | 24.6 | 64.5 | 44.1 | 73.0 | 120.6 | 5918.6 |

Vesta AOT gana **29/29** benches a Java y a Python, **18/29** a Go y
**10/29** a Rust; empata o gana a C en 6 (`callvirt_hot`, `int_mixed`,
`memcpy_loop`, `nested_loops`, `string_hot`, `tight_loop`).

Los peores casos del AOT frente a C son `cmp_fusion` (4.9x),
`hash_lookup` (4.8x), `struct_field` (4.1x), `fp_jit` (4.0x) y
`vec_axpy` (2.5x).  Uno de ellos es un hueco conocido del pipeline: la
**desambiguacion de memoria** (sin ella no se pueden hoistear ni fusionar
accesos a campos y tablas hash). La **auto-vectorizacion** YA no es uno de
esos huecos: existe y dispara -- `vec_axpy` baja a operaciones vectoriales de
256 bits --, asi que la distancia que le queda a ese bench frente a gcc tiene
otra causa, todavia sin diagnosticar. El JIT tiene
ademas su propio pendiente -- devirtualizacion especulativa guiada por
perfil, que es de lo que vive `pic_real` -- pero eso es un optimizador de
runtime y no afecta a estos numeros de AOT.

### Visualización gráfica de resultados

El runner genera un dashboard completo en `bench_plots/index.html` con
9 vistas distintas. Las más representativas:

**Resumen geomean vs C** (`08_geomean_summary.png`): media geometrica
del slowdown frente a C nativo por lenguaje. El AOT de Vesta se situa entre
C++/Rust y Go; el JIT queda por delante de HotSpot C2:

![Geomean vs C](./bench_plots/08_geomean_summary.png)

**Heatmap completo** (`02_heatmap.png`): tiempo wall por bench × lenguaje,
colores verde-amarillo-rojo según velocidad relativa:

![Heatmap](./bench_plots/02_heatmap.png)

**Ratio vs C nativo bench-by-bench** (`07_grouped_ratio.png`): ratio
de slowdown contra C para cada bench, agrupado por lenguaje:

![Ratio vs C](./bench_plots/07_grouped_ratio.png)



Vistas adicionales disponibles en `bench_plots/`:
[`00_system_info.png`](./bench_plots/00_system_info.png) (hardware +
toolchains usados),
[`03_radar_profile.png`](./bench_plots/03_radar_profile.png) (perfil
radar por lenguaje),
[`05_scatter_ratio_vs_c.png`](./bench_plots/05_scatter_ratio_vs_c.png)
(scatter de ratio vs C), y
[`06_ranking_lines.png`](./bench_plots/06_ranking_lines.png) (ranking
por bench mostrando consistencia entre lenguajes).  El runner además
genera una gráfica dedicada por cada bench en
`bench_plots/per_bench/` (no commiteadas, regenerar localmente con
`python tools/bench/run_all_benches.py`).

**Roadmap completo** (JIT C2 optimizador con devirtualizacion especulativa
y deoptimizacion, AOT en 3 tiers de deployment):
[doc/ROADMAP.md](./doc/ROADMAP.md).

---

## Comparativa de features

VestaVM no busca competir con runtimes maduros en velocidad bruta o ecosistema,
sino ofrecer un **ecosistema completo y autocontenido** donde lenguaje, runtime,
distribución y herramientas se diseñan juntos. Comparativa de features clave:

| Feature | VestaVM (Vesta) | Java/JVM | Rust | C++ | Python | Go |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| Tipado estático con inferencia local | ✓ | ✓ | ✓ | ✓ | ✗ | ✓ |
| Pattern matching exhaustivo | ✓ | parcial (21+) | ✓ | parcial (C++26) | parcial | ✗ |
| Borrow checker compile-time | ✓ | ✗ | ✓ | ✗ | ✗ | ✗ |
| Smart pointers con deleters custom | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ |
| Reflexión runtime | ✓ | ✓ | parcial | ✗ | ✓ | ✓ |
| AOP nativo (`@Aspect`/proceed) | ✓ | externa (AspectJ) | ✗ | ✗ | externa | ✗ |
| Genéricos por monomorphización | ✓ | ✗ (erasure) | ✓ | ✓ | ✗ | ✓ |
| Async/await + futures | ✓ | ✓ | ✓ | parcial | ✓ | goroutines |
| Spawn distribuido transparente | ✓ | externa (Akka) | externa | ✗ | externa | ✗ |
| Metaprogramación compile-time | ✓ | ✗ | macros | templates | metaclasses | ✗ |
| FFI compile-time (DLLs en build) | ✓ | ✗ | macros build.rs | ✗ | ✗ | ✗ |
| `static_assert` con condiciones runtime-evaluables | ✓ | ✗ | const fn | ✓ | ✗ | ✗ |
| Captura raw de DSL embebido | ✓ (`expr`) | ✗ | `macro_rules!` | macros texto | ✗ | ✗ |
| Format specs en interpolación | ✓ | ✗ | ✓ | parcial (C++20) | ✓ | ✓ |
| Strings UTF-8/16/32 nativos | ✓ | UTF-16 | UTF-8 | varios | varios | UTF-8 |
| GC generacional preciso + movible (mark-compact) | ✓ | ✓ | ✗ | ✗ | refcount+gc | ✓ |
| JIT integrado | ✓ (C1) | ✓ (C1+C2+Graal) | ✗ | ✗ | parcial (PyPy) | ✗ |
| Bytecode portable | ✓ (`.velb`) | ✓ (.class) | ✗ | ✗ | ✓ (.pyc) | ✗ |
| Ejecutables nativos (3 tiers: con runtime / embebido / sin runtime) | funcional (PE+ELF standalone; 3 tiers en progreso) | parcial (GraalVM) | ✓ (no_std) | ✓ (freestanding) | externa | ✓ |
| Profile-Guided Optimization (PGO) | ✓ (foundation `.vprof`) | ✓ | externa (cargo-pgo) | ✓ (GCC/MSVC) | externa | parcial |
| Inline assembly | parcial (`@Asm` whole-function; `asm{}` inline en progreso) | ✗ | ✓ | ✓ | ✗ | parcial |
| REPL interactivo | ✓ | ✓ (JShell) | ✗ | ✗ | ✓ | ✗ |
| Debugger source-aware integrado | ✓ (TCP) | ✓ | ✓ | ✓ | ✓ | ✓ |
| Diagramas Mermaid del pipeline | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Zero deps externas | ✓ | JVM | crates | varios | CPython | runtime Go |

### Donde brilla VestaVM

- **Ecosistema autocontenido**: lenguaje + runtime + JIT + distribución + REPL
  + debugger + visualización en un solo binario ~15 MB sin runtime externo.
- **Distribución como ciudadano de primera**: `rspawn(node) { ... }` + `await`
  cross-node es parte del bytecode, no una librería bolt-on.
- **Metaprogramación end-to-end**: macros con captura raw de DSLs, introspección
  zero-overhead, FFI en tiempo de compilación, todo en el mismo lenguaje.
- **Seguridad de memoria moderna**: borrow checker estilo Rust + smart pointers
  + GC para los casos en los que el borrow checker es demasiado restrictivo.
- **Hand-rolled donde importa**: encoder x86-64 propio para el JIT (10× más
  rápido que Keystone), GC propio, scheduler propio, protocolo distribuido
  propio. Sin "impedance mismatch" entre capas.

### Donde NO brilla (todavía)

- **Madurez del ecosistema**: 0 paquetes públicos vs millones en npm/cargo/maven.
- **Velocidad bruta**: el AOT queda a 1.65× de C en geomean y el JIT a 6.0×;
  el optimizador C2 (devirtualización especulativa, deopt) cerrará parte de
  la brecha restante. La auto-vectorización ya está y dispara.
- **Documentación en inglés**: toda la doc del proyecto está en español ASCII.
- **Plataformas ARM/AArch64**: JIT y AOT emiten x86-64 (y x86-32); el backend
  arm64 está en curso.
- **AOT nativo en construcción**: el path core (int/float/structs/POO
  no-virtual/FFI/inline-asm) ya produce ejecutables PE/ELF standalone, pero
  los tres tiers (Full/Embed/Bare) y features managed sobre AOT siguen en
  desarrollo activo. El JIT cubre el corpus completo; las pocas operaciones no
  soportadas (excepciones polimórficas, spawn/distrib, futures) caen al
  intérprete de forma transparente.

---

## Documentación

### Para empezar

| Documento | Para qué sirve |
|---|---|
| [QUICKSTART](./doc/QUICKSTART.md) | Instalación + primer programa en 5 minutos |
| [LANGUAGE](./doc/LANGUAGE.md) | Visión general del lenguaje Vesta |
| [EXAMPLES](./doc/EXAMPLES.md) | Catálogo curado de ejemplos por tema |
| [ARCHITECTURE](./doc/ARCHITECTURE.md) | Arquitectura interna de la VM |
| [BENCHMARKS](./doc/BENCHMARKS.md) | Performance comparada + metodología |
| [ROADMAP](./doc/ROADMAP.md) | Plan de fases A-H, estado actual |

### Referencia del lenguaje (doc/VMdoc/Vesta/)

| Sintaxis y semántica | Modelo de programación |
|---|---|
| [TiposDatos](./doc/VMdoc/Vesta/TiposDatos.md) | [OOP](./doc/VMdoc/Vesta/OOP.md) |
| [Operadores](./doc/VMdoc/Vesta/Operadores.md) | [Generics](./doc/VMdoc/Vesta/Generics.md) |
| [ControlFlow](./doc/VMdoc/Vesta/ControlFlow.md) | [ReflexionAOP](./doc/VMdoc/Vesta/ReflexionAOP.md) |
| [Strings](./doc/VMdoc/Vesta/Strings.md) | [Metaprogramacion](./doc/VMdoc/Vesta/Metaprogramacion.md) |
| [OptionalResult](./doc/VMdoc/Vesta/OptionalResult.md) | [Colecciones](./doc/VMdoc/Vesta/Colecciones.md) |
| [Closures](./doc/VMdoc/Vesta/Closures.md) | [Excepciones](./doc/VMdoc/Vesta/Excepciones.md) |

| Memoria y seguridad | Concurrencia y FFI |
|---|---|
| [SmartPointers](./doc/VMdoc/Vesta/SmartPointers.md) | [Async](./doc/VMdoc/Vesta/Async.md) |
| [BorrowChecker](./doc/VMdoc/Vesta/BorrowChecker.md) | [Sincronizacion](./doc/VMdoc/Vesta/Sincronizacion.md) |
| | [FFI](./doc/VMdoc/Vesta/FFI.md) |

### Referencia de la VM (doc/VMdoc/)

- [SSA IR](./doc/VMdoc/IR/SSA.md) — formato intermedio + ~15 pasadas de optimización
- [SetInstruccionesVM/](./doc/VMdoc/SetInstruccionesVM/) — 50+ docs por familia
  de opcodes bytecode
- [SUPER_INSTRUCCIONES](./doc/VMdoc/SetInstruccionesVM/SUPER_INSTRUCCIONES.md) —
  opcodes fusionados (alu3, loadz/loadzh, cmpjmp, decjnz, mvtake, etc.)
- [runtime/](./doc/VMdoc/runtime/) — ProcessVM, scheduler, GC, plugins nativos
- [Generics](./doc/VMdoc/Generics/Generics.md), [Debug](./doc/VMdoc/Debug/),
  [Hilos](./doc/VMdoc/Hilos/), [Distribuido](./doc/VMdoc/Distribuido/)

### Herramientas y CLI

- [CLI_REPL](./doc/CLI_REPL.md) — REPL interactivo (edición de línea, historial,
  aliases, scripts)
- [CLI_COMMANDS](./doc/CLI_COMMANDS.md) — referencia completa de comandos
- [CLI_DIST](./doc/CLI_DIST.md) — runtime distribuido desde el REPL
- [CLI_VSH](./doc/CLI_VSH.md) — VestaShellScript (.vsh)

### Proyecto

- [LICENSE](./LICENSE.md) — licencia VMProject
- [CONTRIBUTING](./doc/CONTRIBUTING.md) — cómo contribuir
- [DEPENDENCIES](./doc/DEPENDENCIES.md) — librerías necesarias
- [github_work](./doc/github_work.md) — GitFlow del proyecto

---

## Construir desde código fuente

### Dependencias

| Plataforma | Comando |
|---|---|
| Linux (apt) | `sudo apt install build-essential cmake libssl-dev` |
| Arch Linux | `sudo pacman -S base-devel cmake openssl` |
| macOS | `brew install cmake openssl` |
| Windows | TDM-GCC-64 o MinGW + [precompiled OpenSSL](https://slproweb.com/products/Win32OpenSSL.html) |

Submódulos vendored (Keystone, Capstone, LibPEparse) se clonan automáticamente
con `--recursive`. Cero deps externas adicionales.

### Build

```bash
# Release (recomendado)
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j

# Debug (con símbolos + asserts)
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j

# Windows MinGW
cmake -G "MinGW Makefiles" -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

Si la versión de CMake instalada es ≥ 4.x y falla por las versiones mínimas de
Keystone, añadir `-DCMAKE_POLICY_VERSION_MINIMUM=3.5`.

Detalles completos (Valgrind, ASan, errores comunes, XMake alternativo) en
[doc/QUICKSTART.md](./doc/QUICKSTART.md).

---

## Casos de uso

- **Investigación**: prototipado rápido de runtimes, optimizaciones IR,
  esquemas de GC, JITs y sistemas distribuidos sin pelearse con LLVM.
- **Servicios distribuidos**: ejecutar workloads que cruzan nodos LAN con
  `rspawn` + `Future<T>` sin RPC manual.
- **Aplicaciones embebidas**: la VM compila a un único binario estático ~15 MB,
  sin dependencias dinámicas en Release.
- **DSLs y generación de código**: el sistema de macros `@Macro` + `expr`
  capture permite implementar mini-lenguajes embebidos (parsers, builders,
  pattern matching custom) cuyo código se reduce a literales en compile-time.
- **Aprendizaje de lenguajes**: el código del frontend Vesta (~30K LOC) está
  diseñado para ser legible, con cada feature documentada y comentada
  exhaustivamente en español ASCII.

### Casos de uso: compilación nativa (AOT)

El compilador AOT (`-m aot`) ya produce ejecutables nativos standalone PE/ELF
para el subset core del lenguaje. La arquitectura está preparada para tres
tiers de deployment (en construcción); la **misma fuente** podrá compilar a:

- **Vesta Full** (3-5 MB con runtime linkado dinámicamente) — apps managed
  con todo el lenguaje disponible: GC, async, reflexión, distribución.
  Modelo análogo a Go, Java, C#.
- **Vesta Embed** (500 KB – 1 MB con mini-runtime embebido estáticamente) —
  CLI tools, ETL, scripts standalone. Subset del lenguaje sin reflexión
  ni distribución pero con clases/strings/closures/excepciones. Modelo
  análogo a Rust con std, Swift, OCaml native.
- **Vesta Bare** (50-200 KB sin runtime, solo libc o freestanding) —
  desarrollo de sistemas operativos, drivers de kernel, firmware
  embedded ARM Cortex-M/RISC-V, bootloaders y aplicaciones UEFI,
  hot-path libs distribuidas como `.dll`/`.so` con cero overhead vs
  C++ optimizado. Modelo análogo a Zig minimal, Rust `#![no_std]`,
  C/C++ embedded.

Vesta Bare incluirá mecanismos de extensibilidad para que el programador
implemente lo que falta según su caso de uso: `@AllocatorOverride` para
hookear `kmalloc/kfree` del kernel, `@PanicHandler` para reemplazar el
default `fputs+exit` por halt CPU / reboot / log a UART, `@CustomGC`
para implementaciones especializadas (refcount, region-based, Boehm
conservativo), `@StringImpl` para UTF-8 ligero sin GC, `@SyncImpl` para
spinlocks / IRQ-disable / futex según nivel, `@UnwindImpl` para
`setjmp/longjmp` como alternativa a `.pdata/.eh_frame`. Detalle completo
en el plan AOT del roadmap.

---

## Filosofía del proyecto

VestaVM no busca competir con JVM/CLR/Cranelift en madurez ni con C/Rust en
performance bruta. Su valor está en ser un **ecosistema completo y autocontenido**
donde lenguaje, runtime, distribución y herramientas se diseñan juntos:

- **Decisiones cohesionadas**: el GC sabe del JIT, el JIT sabe del bytecode, el
  bytecode sabe del lenguaje. No hay "impedance mismatch".
- **Hand-rolled cuando importa**: encoder x86-64 propio (10× más rápido que
  Keystone para JIT), object emitter PE/COFF/ELF integrado, linker propio.
  Sin dependencias externas en el path crítico.
- **Documentación binding**: cada feature del lenguaje y cada opcode del
  bytecode tienen doc autoritativa en español. 
  referencia para futuras decisiones).
- **Tests no negociables**: 793/793 pasos e2e antes de cada commit. Cada nueva feature
  ships con su test en `tests/vx/`.

---

## Comunidad

- **Repositorio principal**: [github.com/desmonHak/VM](https://github.com/desmonHak/VM)
- **Documentación Obsidian-friendly**: [github.com/desmonHak/VMdoc](https://github.com/desmonHak/VMdoc)
- **Issues y feature requests**: [GitHub Issues](https://github.com/desmonHak/VM/issues)
- **Cómo contribuir**: [doc/CONTRIBUTING.md](./doc/CONTRIBUTING.md)

---

## Licencia

VestaVM se distribuye bajo la **licencia VMProject**. Lee
[LICENSE.md](./LICENSE.md) para los términos completos.

Submódulos con licencias propias:
- **Keystone** y **Capstone**: BSD 3-Clause.
- **LibPEparse**: ver `libs/SourceCode/LibPEparse/LICENSE`.
- **OpenSSL**: Apache 2.0 / OpenSSL License (según versión).
- **nlohmann/json**: MIT.
- **cxxopts**: MIT.
- **FTXUI**: MIT.

---

<div align="center">

**VestaVM** · una máquina virtual diseñada como ecosistema.

Hecho con C++17, GCC y mucho café por [desmonHak](https://github.com/desmonHak).

</div>
