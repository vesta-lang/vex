#!/usr/bin/env python3
"""Mezclar objetos ELF y COFF en un mismo enlace se rechaza.

# LADO: windows

Por que hace falta comprobarlo
------------------------------
Sabemos leer los dos contenedores, asi que nada impedia fusionarlos: el enlace
salia sin una queja y producia un ejecutable que ARRANCA.  Eso es lo peor que
podia pasar, porque nadie revisa lo que no falla.

Pero el contenedor no es el problema, la ABI si.  Un objeto ELF de x86-64 pasa
los argumentos en rdi/rsi/rdx, usa la zona roja y no reserva espacio de sombra;
uno COFF los pasa en rcx/rdx/r8/r9, reserva 32 bytes de sombra y no tiene zona
roja.  Mientras las dos mitades no se llamen entre si, el binario parece
correcto; en cuanto se llaman, los argumentos se leen de registros donde no
estan y el resultado es un numero equivocado, no un fallo.

De ahi que se compruebe tambien que un enlace LEGITIMO sigue saliendo: una
comprobacion nueva que rechace de mas es tan mala como no tenerla.

    python tests/aot/mixed_format_test.py <build_dir>
"""
import os
import subprocess

from aot_harness import AotTest

t = AotTest()

vx_a = t.write("mfa.vx", "i64 aporta(i64 x) { return x + 1; }\n")
vx_b = t.write("mfb.vx", "i64 main() { return 7; }\n")

o_elf = t.wpath("mfa.o")
o_coff = t.wpath("mfb.obj")
o_coff2 = t.wpath("mfa.obj")

if not t.compile_aot(vx_a, o_elf, emit="obj", fmt="elf"):
    t.fail("FALLO: no se emitio el .o ELF")
    t.finish()
if not t.compile_aot(vx_b, o_coff, emit="obj", fmt="pe"):
    t.fail("FALLO: no se emitio el .obj COFF")
    t.finish()
if not t.compile_aot(vx_a, o_coff2, emit="obj", fmt="pe"):
    t.fail("FALLO: no se emitio el segundo .obj COFF")
    t.finish()

# Que son de verdad de formatos distintos; si no, el test no mide nada.
with open(o_elf, "rb") as f:
    if f.read(4) != b"\x7fELF":
        t.fail("FALLO: el .o no es ELF")
        t.finish()
with open(o_coff, "rb") as f:
    if f.read(2) == b"\x7fE":
        t.fail("FALLO: el .obj parece ELF")
        t.finish()

rc = 0


def enlaza(objetos, destino):
    """Devuelve (se_creo_el_fichero, salida combinada)."""
    p = subprocess.run([t.vm, "--link", *objetos, "-o", destino,
                        "--format", "pe"], capture_output=True, text=True)
    return (os.path.isfile(destino), (p.stdout or "") + (p.stderr or ""))


# --- Mezclado: tiene que fallar, y decir por que -------------------------
mezcla = t.wpath("mezcla.exe")
ok, salida = enlaza([o_elf, o_coff], mezcla)
if ok:
    print("FALLO: se enlazo un ELF con un COFF sin quejarse -- el binario "
          "arranca y las dos mitades usan ABI distintas")
    rc = 1
elif "ELF" not in salida or "COFF" not in salida:
    print("FALLO: fallo, pero el mensaje no dice que se mezclaron formatos: "
          + salida.strip()[:200])
    rc = 1
else:
    print("  la mezcla se rechaza, nombrando los dos formatos")

# --- Homogeneo: tiene que seguir saliendo --------------------------------
bueno = t.wpath("bueno.exe")
ok2, salida2 = enlaza([o_coff2, o_coff], bueno)
if not ok2:
    print("FALLO: el enlace homogeneo dejo de funcionar: "
          + salida2.strip()[:200])
    rc = 1
else:
    ex = t.run_exit(bueno)
    if ex != 7:
        print("FALLO: el binario homogeneo devolvio %d, se esperaba 7" % ex)
        rc = 1
    else:
        print("  el enlace homogeneo sigue saliendo y corre")

if rc:
    t.fail("=== mixed_format_test: FALLOS ===")
t.finish()
