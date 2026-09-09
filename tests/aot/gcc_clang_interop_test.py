#!/usr/bin/env python3
"""Objetos COFF de gcc y de clang-cl en el MISMO enlace, llamandose entre si.

# LADO: windows

La pregunta que responde
------------------------
Los dos producen COFF de x86-64, pero no vienen del mismo mundo: gcc trae el de
MinGW y clang-cl el de MSVC.  ¿Se pueden mezclar?

Para C SI, y el motivo es que lo que de verdad tiene que coincidir no es el
contenedor sino la CONVENCION DE LLAMADA, y en Windows x64 los dos usan la
misma: argumentos en rcx/rdx/r8/r9, 32 bytes de espacio de sombra, sin zona
roja.  Es la diferencia con mezclar ELF y COFF, que ahi si cambia la ABI (ver
mixed_format_test.py).

Donde SI se rompen es en lo que este test deliberadamente no toca:

  - C++.  gcc usa la ABI de Itanium (decorado `_Z...`, un layout de vtable, un
    modelo de excepciones) y clang-cl la de Microsoft (`?...`, otro layout).
    No es que interoperen mal: no interoperan.  Clang en modo mingw si va con
    gcc, porque entonces usa la ABI de Itanium.
  - Dos CRT en la misma imagen.  Cada mundo trae el suyo, y acabar con dos
    significa dos monticulos y dos estados de stdio.

Lo que se comprueba, y por que el numero importa
------------------------------------------------
La cadena es Vesta -> gcc -> clang.  El resultado NO es un valor cualquiera:
depende de que el argumento llegue al registro correcto en cada salto.  Si la
convencion no coincidiera, no habria un fallo ruidoso -- saldria otro numero.
De ahi que se compruebe el valor exacto y no solo que el binario arranque.

Y se revisa la tabla de desenrollado fusionada: cada productor aporta la suya,
y tienen que acabar en una sola tabla ordenada, porque el sistema la consulta
por biseccion.

    python tests/aot/gcc_clang_interop_test.py <build_dir>
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
    t.saltar("no hay clang-cl")
if not shutil.which("gcc"):
    t.saltar("no hay gcc del lado de Windows")

# --- Los dos lados, cada uno con marco propio -----------------------------
# El array local fuerza reserva de pila, que es lo que hace que el compilador
# emita .pdata/.xdata: una hoja sin marco puede no llevarlos, y entonces la
# parte de la fusion de tablas no probaria nada.
c_clang = t.wpath("lado_clang.c")
with open(c_clang, "w") as f:
    f.write("long long clang_side(long long x) {\n"
            "    volatile long long a[32];\n"
            "    long long s = 0;\n"
            "    for (long long i = 0; i < 32; i++) a[i] = i * x;\n"
            "    for (long long i = 0; i < 32; i++) s += a[i];\n"
            "    return s;\n"
            "}\n")

c_gcc = t.wpath("lado_gcc.c")
with open(c_gcc, "w") as f:
    f.write("long long clang_side(long long x);\n"
            "long long gcc_side(long long x) {\n"
            "    volatile long long b[32];\n"
            "    long long s = 0;\n"
            "    for (long long i = 0; i < 32; i++) b[i] = i;\n"
            "    for (long long i = 0; i < 32; i++) s += b[i];\n"
            "    return clang_side(x) + s;\n"
            "}\n")

o_clang = t.wpath("lado_clang.obj")
o_gcc = t.wpath("lado_gcc.o")
subprocess.run([CLANG_CL, "/c", "/O1", "/Fo:" + o_clang, c_clang],
               capture_output=True, text=True)
subprocess.run(["gcc", "-O1", "-c", "-o", o_gcc, c_gcc],
               capture_output=True, text=True)
if not os.path.isfile(o_clang) or not os.path.isfile(o_gcc):
    t.fail("FALLO: no se produjeron los dos objetos")
    t.finish()

# Los dos tienen que traer tablas; si no, la parte de la fusion sobra.
for nombre, obj in (("clang", o_clang), ("gcc", o_gcc)):
    with open(obj, "rb") as f:
        crudo = f.read()
    if b".pdata" not in crudo:
        t.fail("FALLO: el objeto de %s no trae .pdata" % nombre)
        t.finish()
print("  los dos objetos traen .pdata")

# --- El programa, que cruza las tres fronteras ----------------------------
vx = t.write("cruce.vx",
             'extern "c" { fn gcc_side(i64 x) -> i64; }\n'
             "i64 main() { return gcc_side(2); }\n")
o_vx = t.wpath("cruce.obj")
if not t.compile_aot(vx, o_vx, emit="obj", fmt="pe"):
    t.fail("FALLO: no se emitio el .obj de Vesta")
    t.finish()

exe = t.wpath("cruce.exe")
p = subprocess.run([t.vm, "--link", o_vx, o_gcc, o_clang, "-o", exe,
                    "--format", "pe"], capture_output=True, text=True)
if not os.path.isfile(exe):
    t.fail("FALLO: no se enlazo: "
           + ((p.stdout or "") + (p.stderr or "")).strip()[:300])
    t.finish()
print("  enlazado: Vesta + gcc + clang-cl")

rc = 0

# clang_side(2) = 2*(0+1+...+31) = 992 ; gcc_side anade (0+...+31) = 496.
#
# Se compara con 1488 entero y no con 1488 % 256: en Windows el codigo de
# salida es de 32 bits y Python lo devuelve tal cual.  Es un shell de tipo Unix
# el que lo recorta a 8 bits, y dar por bueno el valor recortado esconderia la
# mitad alta -- justo donde se veria un resultado equivocado.
ESPERADO = 2 * 496 + 496
ex = t.run_exit(exe)
if ex != ESPERADO:
    print("FALLO: devolvio %d y se esperaba %d -- si la convencion de llamada "
          "no coincidiera, saldria justo esto: otro numero, sin ruido"
          % (ex, ESPERADO))
    rc = 1
else:
    print("  la cadena Vesta -> gcc -> clang da el valor exacto (%d)" % ex)

# --- La tabla de desenrollado fusionada -----------------------------------
with open(exe, "rb") as f:
    d = f.read()
lf = struct.unpack_from("<I", d, 0x3C)[0]
fh = lf + 4
nsec = struct.unpack_from("<H", d, fh + 2)[0]
optsz = struct.unpack_from("<H", d, fh + 16)[0]
opt = fh + 20
exc_rva, exc_size = struct.unpack_from("<II", d, opt + 112 + 3 * 8)
secs = {}
for i in range(nsec):
    sh = opt + optsz + i * 40
    nm = d[sh:sh + 8].rstrip(b"\0").decode(errors="replace")
    vsz, rva, rawsz, rawoff = struct.unpack_from("<IIII", d, sh + 8)
    secs[nm] = (rva, vsz, rawoff)

if ".pdata" not in secs:
    print("FALLO: el binario perdio .pdata")
    rc = 1
else:
    prva, pvsz, praw = secs[".pdata"]
    trva, tvsz, _ = secs[".text"]
    n = exc_size // 12
    print("  .pdata fusionada: %d entrada(s)" % n)
    if exc_rva != prva:
        print("FALLO: el directorio de excepciones no apunta a .pdata")
        rc = 1
    # Al menos una por productor con marco; el CRT puede aportar mas.
    if n < 2:
        print("FALLO: se esperaba al menos una entrada por productor, hay %d"
              % n)
        rc = 1
    previo = -1
    for k in range(n):
        b, e, u = struct.unpack_from("<III", d, praw + k * 12)
        if not (trva <= b < trva + tvsz):
            print("FALLO: la entrada %d no apunta al codigo" % k)
            rc = 1
        if b <= previo:
            print("FALLO: la tabla fusionada no quedo ordenada")
            rc = 1
        previo = b
    if rc == 0:
        print("  ordenada, dentro de .text y anunciada en el directorio")

if rc:
    t.fail("=== gcc_clang_interop_test: FALLOS ===")
t.finish()
