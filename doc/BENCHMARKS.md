# Benchmarks de VestaVM

Rendimiento del interprete, del JIT y del compilador AOT nativo; metodologia
y comparativas con otros lenguajes y VMs.

---

## Indice

- [Benchmarks de VestaVM](#benchmarks-de-vestavm)
  - [Indice](#indice)
  - [1. TL;DR](#1-tldr)
  - [2. Hardware y metodologia](#2-hardware-y-metodologia)
  - [3. Benchmarks sinteticos del intérprete](#3-benchmarks-sinteticos-del-intérprete)
    - [Benchmarks core (12 incluidos)](#benchmarks-core-12-incluidos)
    - [Benchmarks memoria compartida cross-process](#benchmarks-memoria-compartida-cross-process)
  - [4. Speedup acumulado del sprint 2026-05-17](#4-speedup-acumulado-del-sprint-2026-05-17)
  - [5. JIT y AOT nativo](#5-jit-y-aot-nativo)
  - [6. Pipeline de optimizacion](#6-pipeline-de-optimizacion)
  - [7. Comparativa con otras VMs](#7-comparativa-con-otras-vms)
    - [Estimacion de orden de magnitud](#estimacion-de-orden-de-magnitud)
    - [Comparativa de features](#comparativa-de-features)
  - [8. Como correr los benchmarks](#8-como-correr-los-benchmarks)
    - [Comparar interp vs JIT](#comparar-interp-vs-jit)
  - [9. Profiling y stats](#9-profiling-y-stats)
    - [Stats basicos del intérprete](#stats-basicos-del-intérprete)
    - [Stats con overhead breakdown](#stats-con-overhead-breakdown)
    - [Profiling JIT](#profiling-jit)
    - [Profiling con Valgrind (Linux)](#profiling-con-valgrind-linux)
    - [Profiling con perf (Linux)](#profiling-con-perf-linux)
  - [Roadmap de performance](#roadmap-de-performance)

---

## 1. TL;DR

**Intérprete**:

| Métrica                                  | Antes (baseline)  | Ahora             | Speedup     |
| :--------------------------------------- | :---------------: | :---------------: | :---------: |
| **MIPS promedio** (intérprete)           | ~150              | **~313**          | **2.1×**    |
| **Wall time avg** (10 benches)           | -                 | -                 | **-25..-81%** |
| **bench_polymorphic** (peor caso pre)    | 3660 ms           | **683 ms**        | **-81%**    |
| **bench_struct_field** (LOAD-heavy)      | 3800 ms           | **1994 ms**       | **-48%**    |

**Compilacion nativa** (29 workloads multi-lenguaje, 11 lenguajes/modos,
i7-13700KF + 63.8 GB, Windows 10, mediana de **10 runs** + 1 warmup, AV
desactivado, corrida del 2026-07-25; el modo AOT publicado es `auto`, con
multiversion por CPUID):

| Metrica                                  | AOT nativo    | JIT           |
| :--------------------------------------- | :-----------: | :-----------: |
| **Aceleracion vs interprete (geomean)**  | **43.4x**     | **12.0x**     |
| **Aceleracion vs interprete (mediana)**  | 52.8x         | 13.0x         |
| **Aceleracion pico**                     | **416x** (`vec_axpy`) | **251x** (`vec_axpy`) |
| **Benches con >=50x**                    | 16/29         | 2/29          |
| **Benches con >=10x**                    | 26/29         | 18/29         |
| **Slowdown geomean vs C nativo**         | **1.65x**     | 5.99x         |
| **Slowdown mediana vs C nativo**         | 1.48x         | 6.33x         |

Contexto del slowdown geomean frente a C, mismos 29 workloads:

| Lenguaje / modo             | Slowdown vs C |
| :-------------------------- | :-----------: |
| C++ (g++ -O2)               | 1.00x         |
| Rust (rustc -O)             | 1.55x         |
| **Vesta AOT**               | **1.65x**     |
| Go (gc)                     | 2.52x         |
| **Vesta JIT**               | **5.99x**     |
| Java HotSpot C2             | 10.59x        |
| CPython 3.11                | 139.95x       |

Benches ganados por el AOT: **29/29** contra Java y Python, **18/29** contra
Go, **10/29** contra Rust, **3/29** contra C++. El JIT gana **27/29** a Java y
**28/29** a Python.

Optimizaciones aplicadas (orden cronologico del sprint):
1. `ir_pass_load_narrow` - elide sign-extension redundante
2. INLINE_THRESHOLD 8 -> 12
3. Regalloc coalesce hint con steal-from-active
4. `ir_pass_schedule` - list scheduling para ILP
5. **Threaded computed-goto dispatch** + inline icache hit
6. Super-instrucciones `alu3` (9 variantes)
7. Super-instruccion `loadz/loadzh`



---

## 2. Hardware y metodologia

**Hardware de referencia**:

- CPU: x86-64 moderno (Intel Core / AMD Ryzen reciente)
- RAM: 16+ GB
- OS: Windows 10/11 con MinGW (TDM-GCC-64) o Linux x86-64

**Build configuration**:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

Flags Release: `-O3 -DNDEBUG -march=x86-64 -mtune=native -ffast-math
-fstrict-aliasing -fno-plt -fomit-frame-pointer -fvisibility=hidden
-ffunction-sections -fdata-sections`.

**Metodologia**:

- Cada bench se compila con `vm --vesta bench.vx -o /tmp/b -O2` (opt level 2)
  para interprete y JIT, y con `-m aot` para el ejecutable nativo.
- El runner multi-lenguaje ejecuta **10 runs + 1 warmup** por modo (3 en los
  benches lentos) y reporta la **mediana**, que es lo publicado en el TL;DR.
  Los numeros historicos de secciones posteriores son best-of-3.
- MIPS se calcula como `(profiler_instr_counter / wall_time_ns) * 1000`.
- Sin actividad de fondo del sistema (cerrar navegadores, etc.).

**Variables que afectan los numeros**:

- CPU frequency scaling (especialmente en laptops; mejor con AC plugged).
- Hyperthreading: medir en single-thread (un solo scheduler).
- Termal throttling en runs largos.

---

## 3. Benchmarks sinteticos del intérprete

Ubicacion: [`examples_codes_vx/benchmark/`](../examples_codes_vx/benchmark/).

### Benchmarks core (12 incluidos)

| Bench                | Que mide                                | Iters     | Wall      | MIPS    |
| :------------------- | :-------------------------------------- | :-------: | --------: | ------: |
| `bench_tight_loop`   | ALU pura (muls/adds/xor/and en loop)   | 50M       | 1111 ms   | **358** |
| `bench_array_sum`    | LOAD i32 + ADD (suma de array)         | 10M loads | 374 ms    | 323     |
| `bench_nested_loops` | Loops anidados (1000x1000)             | 1M body   | 30 ms     | 334     |
| `bench_struct_field` | LOAD-STORE-ADD i32 en struct           | 30M       | 1994 ms   | 294     |
| `bench_polymorphic`  | Dispatch polimorfico (3 impls)         | 10M       | 683 ms    | 331     |
| `bench_callvirt`     | CALLVIRT en hot loop (main)            | 30M       | 797 ms    | 339     |
| `bench_callvirt_hot` | CALLVIRT con metodo trivial            | 30M       | 317 ms    | 347     |
| `bench_alloc`        | `new Foo()` con ctor zero-init        | 5M        | 116 ms    | 346     |
| `bench_jit_method`   | Hot loop dentro de metodo virtual      | 30M       | 415 ms    | 359     |
| `bench_fib_recursive`| CALL/RET recursivo (fib 30)            | 2.7M call | 210 ms    | 220     |
| `bench_callvirt_hot.vx` (variante) | Stress test callvirt        | 30M       | 360 ms    | 333     |

**Patrones observables**:

- ALU-heavy: **~350-360 MIPS** (limite del dispatch loop + decode).
- LOAD-heavy: **~290-330 MIPS** (memory deps + zero-extend cost).
- Recursion-heavy: **~200-220 MIPS** (CALL/RET overhead via frame pool).

---

### Benchmarks memoria compartida cross-process

Suite dedicada para validar throughput del `SharedHeap` + monitores cross-scheduler
+ STW GC.  Implementadas como ficheros `bench_shared_*.vx` en
`examples_codes_vx/benchmark/`.

Ejecucion via `bash tests/vx/bench_shared_runner.sh cmake-build-windows`
(corre cada bench en 4 modos: VM single, VM 4-sched, JIT thr=1, JIT 4-sched).

| Bench                           | Que mide                                              | Iters total | VM single  | VM 4-sched | JIT 4-sched |
| :------------------------------ | :---------------------------------------------------- | :---------: | ---------: | ---------: | ----------: |
| `bench_shared_alloc`            | Throughput SharedHeap vs gc_heap local (1M+1M iter)  | 2M          | 1035 ms / 40 MIPS  | 1038 ms / 40 MIPS  | 1034 ms / 40 MIPS  |
| `bench_shared_contention`       | 4 workers concurrent monenter+RMW sobre shared (Counter.add) | 400K | 256 ms / 49 MIPS   | 261 ms     | **64 ms / 177 MIPS** |
| `bench_shared_gc`               | GC mark+sweep latency (100 cy x 1K shared + sweep)   | 100K shared | 64 ms / 35 MIPS    | 64 ms      | 68 ms       |
| `bench_shared_stw_impact`       | STW pause impact (4 CPU-bound workers + 50 GC cycles)| 20M+50      | 429 ms / 327 MIPS  | **121 ms / 1161 MIPS** | 122 ms |

**Verificacion de correctness**:

- `bench_shared_alloc` -> R0 = 0x1e8480 = 2000000 (1M + 1M iter, suma exacta).
- `bench_shared_contention` -> **R0 = 0x61a80 = 400000 exacto** en 3/3 runs
  (post-Z.11 ext; antes perdia ~1.7% por bug de local_pid no-unico cross-sched).
- `bench_shared_gc` -> R0 = 42 (sweep colecta huerfanos correctamente).
- `bench_shared_stw_impact` -> R0 = 42 (workers terminan cuanto el STW corre 50x).

**Patrones observables**:

- `SharedHeap` alloc throughput: ~2-3x mas lento que gc_heap local (1 CAS extra
  + register en SharedHandleTable).  Aceptable y predecible.
- `synchronized` cross-scheduler: 4-sched es **~4x mas rapido** que single-sched
  para CPU-bound workers no-contendentes (`bench_shared_stw_impact`: 327 -> 1161 MIPS).
- JIT 4-sched de contention: **~4x mejor** que VM 4-sched gracias a `lock cmpxchg`
  host inline.
- GC sweep tiene latencia despreciable (~50-200 us por sweep para 1K objetos).

---

## 4. Speedup acumulado del sprint 2026-05-17

Comparado con el baseline ANTES del sprint (pre-2026-05-17):

| Bench                | Pre-sprint | Post-sprint | Δ wall     | MIPS pre -> post |
| :------------------- | ---------: | ----------: | ---------: | --------------: |
| `bench_tight_loop`   | ~2200 ms   | **1111 ms** | **-49%**   | ~150 -> 358      |
| `bench_array_sum`    | ~620 ms    | **374 ms**  | **-40%**   | ~140 -> 323      |
| `bench_nested_loops` | ~46 ms     | **30 ms**   | **-35%**   | ~140 -> 334      |
| `bench_struct_field` | ~3800 ms   | **1994 ms** | **-48%**   | ~120 -> 294      |
| `bench_polymorphic`  | ~3660 ms   | **683 ms**  | **-81%**   | ~80 -> 331       |
| `bench_callvirt`     | ~1400 ms   | **797 ms**  | **-43%**   | ~155 -> 339      |
| `bench_callvirt_hot` | ~500 ms    | **317 ms**  | **-37%**   | ~210 -> 347      |
| `bench_alloc`        | ~155 ms    | **116 ms**  | **-25%**   | ~250 -> 346      |
| `bench_jit_method`   | ~710 ms    | **415 ms**  | **-42%**   | ~210 -> 359      |
| `bench_fib_recursive`| ~290 ms    | **210 ms**  | **-28%**   | ~165 -> 220      |

**Bench ganador del sprint**: `bench_polymorphic`. La combinacion de
INLINE_THRESHOLD bump (8 -> 12) + devirt automatico + LICM + alu3 produjo un
cascade: las tres implementaciones de `Shape.area()` se inlinearon, LICM
hoisteo las computaciones (todas constantes-of-loop) al entry block, y el
body del loop quedo en `add %sum, %precomputed` × 3 ramas. Reduccion 5× en
instrucciones VM ejecutadas.

---

## 5. JIT y AOT nativo

El JIT se activa con `--jit-threshold N` o con `-m jit` (equivale a threshold
1). El compilador AOT se invoca con `-m aot` y produce un ejecutable
autonomo (PE o ELF) que no necesita la VM.

Ambos comparten el mismo IR optimizado y el mismo asignador de registros
(banco de vregs con spilling, coalescing y splitting). El selector de slots
legacy esta **jubilado**: el camino de produccion es el de vregs, y una
operacion no cubierta cae al interprete de forma transparente en vez de a un
segundo backend.

**Aceleracion interprete -> JIT: 12.0x geomean** sobre 29 benchmarks (mediana
de 10 runs). Distribucion:

| Aceleracion    | Benches                       |
| :------------- | :---------------------------: |
| >= 25x         | 7                             |
| 10-25x         | 11                            |
| 5-10x          | 6                             |
| 2-5x           | 0                             |
| 1-2x           | 5                             |
| < 1x           | 0                             |

**Top 5 acelerados por el AOT**:

| Bench | Interp (ms) | AOT (ms) | Aceleracion |
| :---- | ----------: | -------: | ----------: |
| `vec_axpy` | 18327 | **44.1** | **416x** |
| `intops_jit` | 1208 | **5.8** | **207x** |
| `mem_malloc_free` | 647 | **4.7** | **139x** |
| `rotops_jit` | 649 | **5.2** | **126x** |
| `branch_unpredict` | 3201 | **26.2** | **122x** |

**Top 5 acelerados por el JIT**:

| Bench | Interp (ms) | JIT (ms) | Aceleracion |
| :---- | ----------: | -------: | ----------: |
| `vec_axpy` | 18327 | **73.0** | **251x** |
| `branch_unpredict` | 3201 | **55.0** | **58x** |
| `int_mixed` | 2113 | **47.3** | **45x** |
| `state_machine` | 2751 | **62.7** | **44x** |
| `intops_jit` | 1208 | **32.9** | **37x** |

**Donde el JIT acelera menos** (y por que):

| Bench            | Aceleracion | Causa                                                   |
| :--------------- | ----------: | :------------------------------------------------------ |
| `string_hot`  | 1.31x | bench corto (36 ms): el arranque del JIT domina         |
| `mem_class`   | 1.36x | idem (38 ms), mas el coste de allocacion en el GC       |
| `pic_real`    | 1.55x | dispatch polimorfico sin devirtualizacion especulativa  |
| `memcpy_loop` | 1.81x | copia dominada por memoria, poco margen de codegen      |
| `alloc`       | 1.98x | bench corto dominado por el allocador                   |

Casi todos despegan en AOT, que no paga el arranque de la VM ni la
compilacion en caliente: `pic_real` pasa de 1.6x (JIT) a **72x** (AOT),
`alloc` de 2.0x a **20x** y `memcpy_loop` de 1.8x a **11x**. Los dos
benches cortos suben menos (`string_hot` 5x, `mem_class` 3x) porque lo que
les pesa no es el codegen.

**Cobertura**: el corpus completo compila por el camino de vregs sin
divergencia frente al interprete (verificado con `tools/diff_harness.py` en
los tres modos). Lo que queda fuera son operaciones async/distribuidas
(spawn, rspawn, msgsend, future/await) y el desenrollado de excepciones
polimorficas, que caen al interprete sin afectar a los caminos calientes
sincronos.

---

## 5.5. Comparativa multi-lenguaje (Vesta vs C / C++ / Java / Python / Go)

Comparativa empirica contra los principales lenguajes del ecosistema
usando **workloads identicos** implementados en cada uno. Los benchmarks
viven en `examples_codes_vx/benchmark/<bench_name>/` con un fichero
por lenguaje (`main.vx`, `main.c`, `main.cpp`, `main.py`, `Main.java`,
`main.go`).

**Toolchain de comparacion**:

- C: `gcc -O3 -march=native` (TDM-GCC 10.3.0)
- C++: `g++ -O3 -march=native` (TDM-GCC 10.3.0)
- Java: HotSpot 25 (default C2 enabled)
- Python: CPython 3.11 (sin JIT externo)
- Go: toolchain `gc` (compilacion nativa)
- Rust: `rustc -O`
- Vesta AOT: ejecutable nativo (`-m aot`, variante `auto` con multiversion
  por CPUID)
- Vesta JIT: VestaVM con `-m jit`
- Vesta interp: VestaVM intérprete puro (sin JIT)

### Tiempos wall (mediana de 10 runs, ms; 29 workloads multi-lenguaje)

Corrida del 2026-07-25. En cada fila, **el mas rapido en negrita**.

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

### Findings clave

**Slowdown geomean frente a C nativo**: Vesta AOT **1.65x**, C++ 1.00x,
Rust 1.55x, Go 2.52x, Vesta JIT **5.99x**, HotSpot C2 10.59x, CPython 3.11
139.95x.

**El AOT compite con los compiladores nativos.** Queda por delante de Go
(2.52x) y practicamente empatado con Rust (1.55x), y gana **18/29** benches
a Go y **10/29** a Rust. Empata o gana a C en seis (`callvirt_hot`,
`int_mixed`, `memcpy_loop`, `nested_loops`, `string_hot`, `tight_loop`).

**Donde el AOT pierde contra C** son `cmp_fusion` (4.9x), `hash_lookup`
(4.8x), `struct_field` (4.1x), `fp_jit` (4.0x) y `vec_axpy` (2.5x). Los tres
primeros piden **desambiguacion de memoria** (sin ella no se hoistean ni
fusionan accesos a campos y a tablas hash). Los dos ultimos NO piden
auto-vectorizacion: ya la hay y dispara -- comprobado el 2026-09-02, `vec_axpy`
baja a operaciones vectoriales de 256 bits --, asi que lo que les separa de C
queda sin diagnosticar desde que el vectorizador entro. Ninguno de los cinco
depende del C2, que es un optimizador de runtime.

**El JIT vence a HotSpot C2 en 27 de 29 benches** y a CPython en 28 de 29,
pero queda por detras de Go y Rust: la compilacion en caliente paga un
arranque que los benches cortos no llegan a amortizar, y `pic_real` (481 ms)
delata lo que le falta -- devirtualizacion especulativa guiada por perfil.
Ese mismo bench, compilado AOT, baja a 10.5 ms.

**Targets de optimizaciones futuras del JIT**:

- `pic_real` (JIT 482 ms vs AOT 10.5 ms) — el mayor hueco de la tabla:
  dispatch polimorfico sin devirtualizacion especulativa.
- `string_workout` (JIT 258 ms vs Java 182 ms) — sin small-string
  optimization en `StringObject`.
- `fp_jit` (JIT 69 ms vs C 10.7 ms) — el camino float **escalar** del JIT.
  La auto-vectorizacion existe y dispara en AOT; queda ver por que este bench
  no la aprovecha.
- `branch_unpredict` (JIT 55 ms vs C 17.7 ms) — branches genuinamente
  impredecibles; cerrable con branch hints del perfil PGO.

La unica derrota del JIT frente a CPython es precisamente `pic_real`
(481.9 ms vs 304.6 ms), el mismo bench que delata la falta de
devirtualizacion especulativa; en los otros 28 gana. Frente a Java pierde
en `pic_real` y en `string_workout`. Fuera de esos dos casos el peor
resultado de Vesta sigue muy por delante del mejor de Python en bucles
calientes (geomean de CPython: 140x mas lento que C).

### Cierre del gap recursivo (`fib_recursive`)

Originalmente `fib_recursive` era el unico bench donde Vesta JIT perdia
claramente vs Java HotSpot (1.0× speedup sobre interp). Dos optimizaciones
especificas para recursion lo cerraron:

1. **TAILCALL nativo en el JIT**: el opcode IR `TAILCALL` se emite como
   `CALL` + `RET` fusionados directamente en x86-64, sin pasar por el
   FrameHeader pool del runtime. Ahorra ~30 ns por tail call.

2. **Self-recursive call sin trampoline JIT->interp**: cuando una funcion
   JIT-compilada se llama a si misma (`fib(n-1)` desde el body de `fib`),
   antes el JIT iba por el trampoline generico (`vrt_callvm` -> dispatch).
   Ahora el `JitCompiler` parchea el call directamente con la direccion
   `code_start` del mismo bloque de codigo nativo tras la compilacion,
   produciendo un `call rel32` puro a si mismo (~3 ns vs ~30 ns del
   trampoline).

Resultado medido: `fib_recursive` en JIT pasa de 1.0x a **8x** sobre el
interprete (307 ms -> 38.5 ms) y **vence a HotSpot** (38.5 ms vs 77.4 ms).
Compilado AOT baja a 13.0 ms, a 2.1x de C.

**Interprete**: 72x mas lento que C en geomean, lo esperado de un
interprete de bytecode con coste de dispatch. La distancia entre interprete
y codigo nativo en bucles vectorizables (`vec_axpy`: 18327 ms -> 44 ms en
AOT, **416x**) es la que justifica los dos backends.

### Conclusiones

1. **El AOT compite con los compiladores nativos**: 1.65x de slowdown
   geomean frente a C, por delante de Go (2.52x) y a la par de Rust
   (1.55x), ganando 18/29 y 10/29 benches respectivamente.
2. **El JIT bate a HotSpot** — una JVM con 30 anos de optimizacion — en
   27 de 29 benches, con 5.99x vs C frente al 10.59x de HotSpot, pero
   queda por detras de los compiladores nativos: la compilacion en
   caliente cuesta un arranque que los benches cortos no amortizan.
3. **Desambiguacion de memoria**: es el hueco que explica los peores
   casos del AOT (`hash_lookup`, `struct_field`, `cmp_fusion`).
4. **Auto-vectorizacion**: `fp_jit` y `vec_axpy` son donde gcc saca mas
   ventaja; el camino float escalar todavia no se vectoriza.
5. **Devirtualizacion especulativa**: `pic_real` es el peor bench del JIT
   en toda la tabla (482 ms) y el que motiva el optimizador C2.
6. **Strings**: `string_workout` sigue siendo el punto debil (Java gana
   ahi por small-string optimization), implementable en `StringObject` si
   se vuelve critico.

---

## 6. Pipeline de optimizacion

Cada pasada del optimizador SSA contribuye al speedup. Numeros aproximados
medidos en benches sinteticos (variables segun el bench):

| Optimizacion                              | Tipo            | Ganancia tipica |
| :---------------------------------------- | :-------------- | --------------: |
| Dead Code Elimination                     | IR cleanup      | varia           |
| Copy Propagation                          | IR cleanup      | varia           |
| Constant Folding                          | compile-time    | varia           |
| Strength Reduction (mul/div -> shift)      | aritmetica      | varia           |
| LICM (Loop Invariant Code Motion)         | loops           | 0-50% (loops)   |
| Dead Store Elimination + SLF              | memoria         | 5-15%           |
| TCO (Tail Call Optimization)              | recursion       | 0-30% (rec.)    |
| Devirtualization monomorphic              | OOP             | 0-80% (poly)    |
| **Inlining** (threshold 12)               | calls           | 5-30%           |
| CSE (Common Subexpression Elim)           | aritmetica      | 0-15%           |
| **Load Narrow** (elide SEXT)              | i32 loads       | 5-15%           |
| **List Scheduling** (ILP)                 | reordering      | 0-5% interp     |
| **Regalloc coalesce hint**                | regalloc        | **15-30%**      |
| **Threaded computed-goto + icache inline**| scheduler       | **10-20%**      |
| **alu3** super-instr                      | bytecode        | **5-20%**       |
| **loadz** super-instr                     | bytecode        | **5-15%**       |

---

## 7. Comparativa con otras VMs

> **Disclaimer**: comparativas entre VMs distintas son inherentemente injustas
> (diferentes lenguajes, runtimes, GCs, JITs, etc.). Los numeros aqui son
> indicativos, no autoritativos. Para comparativa empirica directa sobre
> workloads identicos, ver la **seccion 5.5 (Comparativa multi-lenguaje)**.

### Estimacion de orden de magnitud

| VM                            | MIPS interp aprox | Notas                                  |
| :---------------------------- | ----------------: | :------------------------------------- |
| **VestaVM** (intérprete)      | ~313              | threaded goto + super-instr            |
| CPython (interpreter)         | ~10-50            | bytecode stack-based, sin JIT          |
| CPython 3.13 (+JIT copy)      | ~30-100           | copy-and-patch JIT experimental        |
| Lua 5.4 (interpreter)         | ~80-200           | register-based, optimizado             |
| LuaJIT (interp mode)          | ~200-400          | computed-goto + register-based         |
| LuaJIT (JIT mode)             | ~1000-3000        | tracing JIT muy maduro                 |
| Ruby YARV                     | ~30-100           | interp + JIT YJIT experimental         |
| OpenJDK Java (interp)         | ~50-150           | template interpreter                   |
| OpenJDK Java (C2 JIT)         | ~2000-10000+      | JIT optimizing maduro 20+ años        |
| V8 JavaScript (Ignition+JIT)  | ~1000-5000+       | tiered JIT + speculative opt           |
| **VestaVM** (JIT)             | ~3000-5000        | regalloc real sobre banco de vregs     |

El intérprete de VestaVM esta en el rango de **LuaJIT en modo interp**, lo
cual es bueno considerando que LuaJIT lleva 15+ anos de optimizacion
especifica. El JIT supera a HotSpot C2 en 27 de los 29 workloads
multi-lenguaje medidos (ver seccion 5.5), y el compilador AOT juega ya en
la liga de los nativos (1.65x vs C). El C2 optimizador planeado apunta al
hueco que queda en dispatch polimorfico.

### Comparativa de features

| Feature                       | Vesta | Lua | Python | Java | JS |
| :---------------------------- | :---: | :-: | :----: | :--: | :-: |
| Multi-paradigma OOP completo  | sí    | -   | sí     | sí   | sí |
| Static types                  | sí    | -   | -      | sí   | TS |
| GC generacional               | sí    | sí  | sí (3.x) | sí | sí |
| Modelo actor nativo           | sí    | -   | -      | -    | -  |
| Smart pointers en lenguaje    | sí    | -   | -      | -    | -  |
| Borrow checker compile-time   | sí    | -   | -      | -    | -  |
| Distribuido nativo            | sí    | -   | -      | -    | -  |
| FFI integrado al lenguaje     | sí    | sí  | (lib)  | JNI  | (lib) |

---

## 8. Como correr los benchmarks

```bash
# Compilar todos los benches en un script
for b in examples_codes_vx/benchmark/bench_*.vx; do
  name=$(basename "$b" .vx)
  ./build/vm --vesta "$b" -o /tmp/$name -O2 > /dev/null
done

# Ejecutar uno especifico con stats
./build/vm --run /tmp/bench_tight_loop.velb --stats

# Best-of-3 para reducir noise
for b in bench_tight_loop bench_array_sum bench_polymorphic; do
  best=999999999
  for i in 1 2 3; do
    out=$(./build/vm --run /tmp/$b.velb --stats 2>&1)
    wall=$(echo "$out" | awk '/Wall time/{print $5}')
    if [ "$wall" -lt "$best" ]; then best=$wall; fi
  done
  echo "$b: best=$best us"
done
```

### Comparar interp vs JIT

```bash
# Interp puro
./build/vm --run /tmp/bench_jit_method.velb --stats

# Con JIT activo
./build/vm --run /tmp/bench_jit_method.velb -m jit --stats

# JIT con stats de compilacion
./build/vm --run /tmp/bench_jit_method.velb -m jit --jit-stats
```

### Comparar contra C / C++ / Java / Python

Los benchmarks multi-lenguaje viven en carpetas con multiples
implementaciones, una por lenguaje:

```text
examples_codes_vx/benchmark/<bench>/
    main.vx      # Vesta
    main.c        # C    (gcc -O3 -march=native)
    main.cpp      # C++  (g++ -O3 -march=native)
    main.py       # Python (CPython 3.11)
    Main.java     # Java (HotSpot 25)
```

Runner Python orquestador:

```bash
# Comparativa completa (todos los lenguajes detectados, todos los benches)
python tools/bench/run_all_benches.py

# Subset de lenguajes
python tools/bench/run_all_benches.py --langs vx_interp,vx_jit,c,java

# Filtrar benches por nombre (regex)
python tools/bench/run_all_benches.py --filter "fib|tight"

# Mediana de N runs (default: 3)
python tools/bench/run_all_benches.py --runs 5

# Saltar benches legacy single-file (solo carpetas multi-lang)
python tools/bench/run_all_benches.py --skip-legacy
```

Salida: tabla coloreada por lenguaje con winner highlighted, speedup
summary vs C como baseline, JSON con resultados, y 9 graficas matplotlib
en `bench_plots/` (si `matplotlib` esta instalado) + reporte HTML
navegable.

### Visualizacion de resultados

El runner genera un dashboard completo en `bench_plots/index.html` con
multiples vistas comparativas:

**Dashboard global** (`01_dashboard.png`): cuatro paneles con wall time
absoluto, ratio vs C nativo, ranking por bench y speedup JIT vs interp.

![Dashboard](../bench_plots/01_dashboard.png)

**Resumen geomean vs C** (`08_geomean_summary.png`): media geometrica
del slowdown vs C por lenguaje.  Vesta JIT compite directamente con
HotSpot C2 y lo supera en promedio.

![Geomean vs C](../bench_plots/08_geomean_summary.png)

**Heatmap por bench × lenguaje** (`02_heatmap.png`): tiempo wall absoluto
en escala logaritmica con codigo de colores verde-amarillo-rojo.

![Heatmap](../bench_plots/02_heatmap.png)

**Boxplot de variabilidad** (`04_boxplot_variability.png`): distribucion
min/p50/p95/max por lenguaje × bench.  Vesta JIT y Vesta interp muestran
varianza muy baja entre runs, demostrando determinismo del dispatcher.

![Variabilidad](../bench_plots/04_boxplot_variability.png)

**Ratio vs C bench-by-bench** (`07_grouped_ratio.png`): slowdown vs C
agrupado por bench para visualizar donde cada lenguaje gana/pierde.

![Grouped ratio](../bench_plots/07_grouped_ratio.png)

Vistas adicionales: `00_system_info.png` (hardware + toolchains),
`03_radar_profile.png` (perfil radar por lenguaje),
`05_scatter_ratio_vs_c.png` (scatter dispersion), `06_ranking_lines.png`
(consistencia de ranking cross-bench), y `per_bench/` con una grafica
dedicada por cada uno de los 29 benches.

### Resiliencia del runner contra flakes

Durante runs largos secuenciales (8-10 min completos) puede ocurrir que
algunos benches den TIMEOUT por causas ambientales:

- **Windows Defender en tiempo real**: tras lanzar el mismo `.exe`
  cientos de veces, el AV escanea el binario antes de cada ejecucion.
  Cada escaneo anade 100-500 ms; ocasionalmente provoca cuarentena
  momentanea de varios segundos.
- **Thermal throttling**: CPUs modernos hacen boost durante ~30s y
  luego bajan a base frequency.  Un bench que normalmente tarda 2s
  puede tardar 4s con clock degradado.
- **Handle exhaustion / page fault storms**: cada `subprocess.run` crea
  ~20 handles del kernel.  Cleanups batch del kernel detienen
  momentaneamente las creaciones de procesos.
- **Carga del sistema durante runs largos**: Windows Update / OneDrive
  sync / telemetria pueden arrancar en background.

El runner mitiga estos flakes con:
- `MAX_ATTEMPTS = 5` reintentos por run individual.
- Backoff exponencial entre reintentos (250 ms, 500 ms, 1 s, 2 s).
- Politica "aceptar lo medido": si 1-2 runs de los 3+1 fallan, los
  validos se usan igual; solo si NINGUN run sale el bench se marca FAIL.

Para evitar timeouts permanentemente en Windows:

- añadir `%TEMP%\vx_bench_multi` y el directorio de `vesta.EXE` como
  exclusiones de Windows Defender.
- Activar el power profile "Alto rendimiento" + AC plugged.
- Cerrar apps pesadas (Chrome, IDE, etc.) durante el bench completo.

---

## 9. Profiling y stats

### Stats basicos del intérprete

```bash
./build/vm --run programa.velb --stats
```

Imprime al final:

```text
Wall time:        1234567 ns  (1234 us, 1 ms)
profiler_instr_counter: 400000000
MIPS:             324.5  (wall time)
```

### Stats con overhead breakdown

```bash
./build/vm --run programa.velb --stats --overhead-breakdown
```

Imprime tambien el desglose de:
- VM construct time (alocacion del ArenaManager, etc.)
- load_executable time (parse del .velb + mmap)
- vm.start time
- wait time (cuanto espero el main thread)
- vm.stop time

Util para detectar overhead del setup vs compute real.

### Profiling JIT

```bash
./build/vm --run programa.velb -m jit --jit-stats --jit-warn
```

Imprime:
- Methods compiled vs unsupported.
- Cada unsupported method con detalle del IR op que falla.
- Code cache usage.

### Profiling con Valgrind (Linux)

```bash
cmake -B build-rwd -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build-rwd -j

valgrind --tool=callgrind ./build-rwd/vm --run programa.velb
callgrind_annotate callgrind.out.*
```

### Profiling con perf (Linux)

```bash
perf record -g ./build/vm --run programa.velb
perf report
```

---

## Roadmap de performance

Ya en produccion: asignador de registros real (banco de vregs con spilling
y coalescing) compartido por JIT y AOT, perfil persistido en `.vprof`,
escape analysis con reemplazo escalar, y ejecutables nativos autonomos
PE/ELF con linker propio.

Lo que queda, por impacto esperado sobre los numeros de arriba:

| Trabajo pendiente                          | Benches que desbloquea            |
| :----------------------------------------- | :-------------------------------- |
| Desambiguacion de memoria                  | `hash_lookup`, `struct_field`, `cmp_fusion` |
| Auto-vectorizacion SSE2/AVX                | `fp_jit`, `vec_axpy`              |
| Devirtualizacion especulativa + deopt      | `pic_real`, `polymorphic`         |
| Dispatch por niveles + OSR                 | benches cortos en JIT             |
| Scheduling de instrucciones consciente del pipeline | transversal              |
| Small-string optimization                  | `string_workout`                  |

Detalles: [doc/ROADMAP.md](./ROADMAP.md).

---

Referencias completas:

- [doc/VMdoc/IR/SSA.md](./VMdoc/IR/SSA.md) seccion 9 para las pasadas de opt.
- [doc/VMdoc/SetInstruccionesVM/SUPER_INSTRUCCIONES.md](./VMdoc/SetInstruccionesVM/SUPER_INSTRUCCIONES.md)
  para los opcodes super-instr.
- [doc/ARCHITECTURE.md](./ARCHITECTURE.md) para el estado actual del JIT y
  del compilador AOT.
