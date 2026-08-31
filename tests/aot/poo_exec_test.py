#!/usr/bin/env python3
"""POO nativa AOT (clases + herencia + override + interfaces + dtor
polimorfico): compila los ejemplos aot/2x a .o, los enlaza y verifica el
EXIT-CODE real de ejecucion.

    wsl python3 tests/aot/poo_exec_test.py <build_dir>
"""
import glob
import os

from aot_harness import AotTest

t = AotTest()
if not t.have("gcc"):
    print("SKIP: gcc no disponible")
    t.rc = 0
    t.finish()

# Runtime minimo para los ejemplos con `extern` (note/get_note del 26).
#
# ACUMULA en vez de sobrescribir: `g = g*10 + x`.  Con un simple `g = x` solo
# sobrevive la ULTIMA anotacion, y entonces "solo corrio ~Animal" y "corrieron
# ~Dog y luego ~Animal" dan el mismo 1 -- que es justo la diferencia que este
# test existe para ver.  Acumulando, la traza de destructores se lee entera:
# 2 = solo ~Dog, 1 = solo ~Animal, 21 = ~Dog y despues ~Animal.
rt_c = t.write("rt.c",
               "static long g_note;\n"
               "void note(long x) { g_note = g_note * 10 + x; }\n"
               "long get_note(void) { return g_note; }\n")
rt_o = t.wpath("rt.o")
t.gcc_c(rt_c, rt_o)


def poo_one(ex, exp, extra=None):
    src = "examples_codes_vx/aot/%s.vx" % ex
    if not os.path.isfile(src):
        print("SKIP %s: no existe" % ex)
        return
    obj = t.wpath("poo.o")
    if not t.compile_aot(src, obj):
        t.fail("FALLO %s: no se genero el .o" % ex)
        return
    elf = t.wpath("poo")
    objs = [obj] + (list(extra) if extra else [])
    if not t.gcc(objs, elf):
        t.fail("FALLO %s: link gcc" % ex)
        return
    got = t.run_exit(elf)
    if got == exp:
        t.ok("OK %s -> exit=%d" % (ex, got))
    else:
        t.fail("FALLO %s -> exit=%d (esperado %d)" % (ex, got, exp))


poo_one("20_class_native", 42)          # clases no-virtuales + devirt de hoja
poo_one("21_devirt_native", 42)
poo_one("22_poly_native", 47)           # polimorfismo via vtable
poo_one("23_interface_native", 42)      # interfaces via vtable
poo_one("26_dtor_polimorfico", 21, [rt_o])  # ~Dog y DESPUES ~Animal (encadenado)

t.finish()
