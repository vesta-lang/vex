#!/usr/bin/env python3
"""VX para cvt/cmp/sqrt escalares -> --float-isa avx es LIMPIO end-to-end (sin
mezclar legacy-SSE con VX).  aot/182_vectorize_elementwise --float-isa avx:
  1. 0 ops escalares legacy (addsd/mulsd/cvtsi2sd/cvttsd2si...) -> todo VX.
  2. 0 bytes (bad) -> el encoding VX decodifica bien.
  3. corre = 224 (180960 & 0xFF).

    wsl python3 tests/aot/avx_full_elf_test.py <build_dir>
"""
from aot_harness import AotTest

t = AotTest()
obj = t.wpath("f.o")
if not t.compile_aot("examples_codes_vx/182_vectorize_elementwise.vx", obj, float_isa="avx"):
    t.fail("FALLO: no se genero el .o avx")
    t.finish()

# CERO legacy SSE float escalar (arith + cvt + cmp + sqrt + neg/abs + moves)
# EN EL CODIGO GENERADO.  En el despachador de `std.memory` el SSE legacy
# es obligatorio: su ruta sin AVX corre en CPUs donde VEX no existe.
# \b evita matchear las VX (vmovq/vmovsd... empiezan por 'v').
LEGACY = (r"\baddsd|\bsubsd|\bmulsd|\bdivsd|\baddss|\bsubss|\bmulss|\bdivss|"
          r"\bcvtsi2sd|\bcvttsd2si|\bcvtsi2ss|\bcvttss2si|\bcvtss2sd|\bcvtsd2ss|"
          r"\bucomisd|\bucomiss|\bsqrtsd|\bsqrtss|\bxorps|\bandps|\bmovsd|\bmovss|\bmovq")
dis = t.disasm_generado(obj)
leg = t.count_lines(dis, LEGACY)
bad = t.count_lines(dis, r"\(bad\)")
if leg == 0 and bad == 0:
    t.ok("AVX-FULL: 0 escalar legacy (arith/cvt/cmp/sqrt/neg/moves), 0 bad OK")
else:
    t.fail("AVX-FULL: FALLO legacy=%d bad=%d (esperado 0/0)" % (leg, bad))

elf = t.wpath("f")
if not t.gcc([obj], elf):
    t.fail("FALLO: gcc")
    t.finish()
got = t.run_exit(elf)
if got == 224:
    t.ok("RUN: 182 avx-full exit=%d OK" % got)
else:
    t.fail("RUN: EXIT MISMATCH got=%d exp=224" % got)

t.finish()
