#!/usr/bin/env python3
"""Ancho SIMD del vectorizador en AOT lo fija el TARGET (--float-isa), no el
host de build.  Default = sse2 -> 128b (cross-compile-safe).

Verifica aot/182_vectorize_elementwise compilado a AOT default:
  1. NO contiene ymm/zmm (128b puro; no hereda el AVX2/AVX512 del host).
  2. Corre correcto (180960 & 0xFF = 224).

    wsl python3 tests/aot/vectorize_width_elf_test.py <build_dir>
"""
from aot_harness import AotTest

t = AotTest()
obj = t.wpath("vw.o")
if not t.compile_aot("examples_codes_vx/182_vectorize_elementwise.vx", obj, arch="x86-64"):
    t.fail("FALLO: no se genero el .o")
    t.finish()

# 1. cross-compile-safe: NADA de ymm/zmm en el default (sse2 -> 128b).
#    Se mira SOLO el codigo generado: el objeto entero incluye el
#    despachador de `std.memory`, que lleva las variantes SSE2, AVX2 y
#    AVX-512 a la vez y elige en EJECUCION segun la CPU.  Contarlas aqui
#    decia que un binario sse2 emite AVX-512, que no es lo que pasa.
wide = t.count_lines(t.disasm_generado(obj), r"ymm|zmm")
if wide == 0:
    t.ok("WIDTH: default sse2 = 128b puro (0 ymm/zmm) OK")
else:
    t.fail("WIDTH: FALLO -- %d instrucciones ymm/zmm (deberia ser 128b sse2)" % wide)

# 2. ejecucion correcta.
elf = t.wpath("vw")
if not t.gcc([obj], elf):
    t.fail("FALLO: gcc")
    t.finish()
got = t.run_exit(elf)
if got == 224:
    t.ok("RUN: 182 vectorize-AOT exit=%d OK (180960 & 0xFF)" % got)
else:
    t.fail("RUN: EXIT MISMATCH got=%d exp=224" % got)

t.finish()
