#!/usr/bin/env python3
"""Las tablas de desenrollado de un objeto AJENO sobreviven a nuestro enlace.

# LADO: windows

Que se prueba
-------------
Un objeto compilado por otra herramienta trae sus tablas SEH -- `.pdata`, con
una entrada por funcion, y `.xdata`, con la descripcion de cada marco --, y las
tres direcciones de cada entrada vienen como relocations `ADDR32NB`:
desplazamientos desde la base de la imagen, que solo se pueden escribir cuando
se sabe donde carga.

Nuestro enlazador DESCARTABA esas dos secciones, porque no sabia resolver esa
relocation.  El binario salia y corria; lo que se perdia era el desenrollado de
todo lo que viniera compilado por otro, y eso no se nota hasta que hay una
excepcion que propagar o una pila que recorrer -- o sea, el dia en que hace
falta.

Aqui se comprueba lo contrario: que llegan, que sus direcciones apuntan al
codigo de verdad, y que la tabla resultante cumple lo que el sistema exige de
ella.

Lo del ORDEN es lo menos evidente y lo mas importante.  `.pdata` se consulta por
BISECCION, asi que tiene que estar ordenada por direccion de inicio.  Al enlazar
es la CONCATENACION de las tablas de cada objeto, y pegar dos tablas ordenadas
da una desordenada: el orden final depende de donde acabe el codigo de cada uno,
cosa que ningun objeto sabe por separado.  Una tabla desordenada no falla al
consultarla -- devuelve la entrada equivocada, o ninguna, para una direccion que
si esta --, asi que este es el tipo de fallo que solo aparece revisando los
bytes.

    python tests/aot/pdata_link_test.py <build_dir>
"""
import os
import shutil
import struct
import subprocess

from aot_harness import AotTest

t = AotTest()

CLANG_CL = r"C:\Program Files\LLVM\bin\clang-cl.exe"
if not os.path.isfile(CLANG_CL):
    CLANG_CL = shutil.which("clang-cl") or ""
if not CLANG_CL:
    t.saltar("no hay clang-cl: hace falta un objeto ajeno con .pdata/.xdata")


def leer(path):
    with open(path, "rb") as f:
        return f.read()


def mira_pe(d):
    """Devuelve (base, {seccion: (rva, vsize, raw)}, (exc_rva, exc_size))."""
    lf = struct.unpack_from("<I", d, 0x3C)[0]
    fh = lf + 4
    nsec = struct.unpack_from("<H", d, fh + 2)[0]
    optsz = struct.unpack_from("<H", d, fh + 16)[0]
    opt = fh + 20
    base = struct.unpack_from("<Q", d, opt + 24)[0]
    exc = struct.unpack_from("<II", d, opt + 112 + 3 * 8)
    secs = {}
    for i in range(nsec):
        sh = opt + optsz + i * 40
        nm = d[sh:sh + 8].rstrip(b"\0").decode(errors="replace")
        vsz, rva, rawsz, rawoff = struct.unpack_from("<IIII", d, sh + 8)
        secs[nm] = (rva, vsz, rawoff)
    return base, secs, exc


# --- El objeto ajeno, con marco de verdad ---------------------------------
# Un array local grande obliga a reservar pila, y una funcion con marco es la
# que lleva entrada en .pdata: las hoja sin marco pueden no llevarla, y ese es
# justamente el caso que no probaria nada.
#
# /GS- porque el guardia de pila arrastra el CRT de Microsoft, que no tiene por
# que estar instalado.  Que se resuelva contra el CRT se prueba aparte, en
# msvc_drectve_test.py; aqui estorbaria.
c_src = t.wpath("ajeno.c")
with open(c_src, "w") as f:
    f.write("long long trabaja(long long x) {\n"
            "    volatile long long a[64];\n"
            "    long long s = 0;\n"
            "    for (long long i = 0; i < 64; i++) a[i] = i * x;\n"
            "    for (long long i = 0; i < 64; i++) s += a[i];\n"
            "    return s;\n"
            "}\n")

c_obj = t.wpath("ajeno.obj")
subprocess.run([CLANG_CL, "/c", "/O1", "/GS-", "/Fo:" + c_obj, c_src],
               capture_output=True, text=True)
if not os.path.isfile(c_obj):
    t.fail("FALLO: clang-cl no produjo el objeto")
    t.finish()

# Si el objeto no trae las tablas, el test no mide nada: mejor decirlo.
crudo = leer(c_obj)
if b".pdata" not in crudo or b".xdata" not in crudo:
    t.fail("FALLO: el objeto de clang-cl no trae .pdata/.xdata -- sin eso "
           "este test no prueba lo que dice")
    t.finish()
print("  el objeto ajeno trae .pdata y .xdata")

# --- Un objeto nuestro que aporte main ------------------------------------
vx = t.write("host.vx", "i64 main() { return 7; }\n")
vx_obj = t.wpath("host.obj")
if not t.compile_aot(vx, vx_obj, emit="obj", fmt="pe"):
    t.fail("FALLO: no se emitio el .obj de Vesta")
    t.finish()

exe = t.wpath("mezcla.exe")
if not t.vm_link([c_obj, vx_obj], exe, fmt="pe"):
    t.fail("FALLO: el enlace no produjo ejecutable")
    t.finish()

rc = 0
d = leer(exe)
base, secs, (exc_rva, exc_size) = mira_pe(d)

if ".pdata" not in secs:
    print("FALLO: el binario enlazado perdio .pdata")
    rc = 1
elif ".xdata" not in secs:
    print("FALLO: el binario enlazado perdio .xdata")
    rc = 1
else:
    prva, pvsz, praw = secs[".pdata"]
    xrva, xvsz, _ = secs[".xdata"]
    trva, tvsz, _ = secs[".text"]
    n = exc_size // 12
    print("  enlazado: .pdata=%dB .xdata=%dB, %d entrada(s)"
          % (pvsz, xvsz, n))

    # El directorio tiene que senalar la seccion: sin el, la tabla no existe
    # para el sistema por mucho que este dentro del fichero.
    if exc_rva != prva:
        print("FALLO: el directorio de excepciones apunta a 0x%X y .pdata "
              "esta en 0x%X" % (exc_rva, prva))
        rc = 1
    if n < 1:
        print("FALLO: la tabla quedo vacia")
        rc = 1

    previo = -1
    for k in range(n):
        b, e, u = struct.unpack_from("<III", d, praw + k * 12)
        dentro = trva <= b < trva + tvsz
        unw_ok = xrva <= u < xrva + xvsz
        print("   [%d] begin=0x%05X end=0x%05X unwind=0x%05X %s %s"
              % (k, b, e, u,
                 "codigo-ok" if dentro else "FUERA DE .text",
                 "xdata-ok" if unw_ok else "FUERA DE .xdata"))
        if not dentro:
            print("FALLO: una entrada no apunta al codigo")
            rc = 1
        if not unw_ok:
            print("FALLO: una entrada no apunta a .xdata")
            rc = 1
        if e <= b:
            print("FALLO: una entrada acaba antes de empezar")
            rc = 1
        if b <= previo:
            print("FALLO: la tabla no quedo ordenada (el sistema la busca por "
                  "biseccion)")
            rc = 1
        previo = b

# Las tablas son datos: el programa tiene que comportarse igual.
ex = t.run_exit(exe)
if ex != 7:
    print("FALLO: el binario devolvio %d, se esperaba 7" % ex)
    rc = 1
else:
    print("  el binario corre y devuelve 7")

if rc:
    t.fail("=== pdata_link_test: FALLOS ===")
t.finish()
