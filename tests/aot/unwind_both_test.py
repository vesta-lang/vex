#!/usr/bin/env python3
"""`--unwind both` describe CADA funcion en las DOS tablas, no una en cada una.

# LADO: windows

Que propiedad se guarda aqui
----------------------------
En Windows conviven dos formatos de desenrollado y cada desenrollador lee UNO:

  - el del sistema (`RtlLookupFunctionEntry`, que es lo que usan el SEH, un
    manejador de fallos y un perfilador que muestrea pilas) lee `.pdata`;
  - los de DWARF (`gdb`, `libunwind`, el runtime de excepciones de MinGW) leen
    `.eh_frame`.

Que un binario lleve las dos secciones NO significa que este cubierto.  Si cada
funcion aparece en una sola, cada desenrollador ve media imagen y el recorrido
de pila se corta justo al entrar en la mitad que no es suya.  Y eso no falla de
forma visible: el binario corre igual, y el problema solo aparece el dia que hay
que sacar una traza.

Asi que lo que se comprueba no es "hay dos secciones", sino que los RANGOS DE
CODIGO que describe cada una son los MISMOS.  Es la unica forma de que las dos
respuestas valgan para toda la imagen.

Se comprueban ademas los otros tres modos, porque el valor de `both` esta en el
contraste: `table` solo pone `.pdata`, `cfi` solo `.eh_frame`, `none` ninguna.
Sin eso, un `both` que hiciera lo mismo que `auto` pasaria el test igual.

    python tests/aot/unwind_both_test.py <build_dir>
"""
import os
import struct

from aot_harness import AotTest

t = AotTest()

FUENTE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "..", "..", "examples_codes_vx", "aot",
                      "22_float_f64_arith.vx")
if not os.path.isfile(FUENTE):
    t.saltar("no esta el ejemplo con varias funciones")


def secciones(d):
    lf = struct.unpack_from("<I", d, 0x3C)[0]
    fh = lf + 4
    nsec = struct.unpack_from("<H", d, fh + 2)[0]
    optsz = struct.unpack_from("<H", d, fh + 16)[0]
    opt = fh + 20
    base = struct.unpack_from("<Q", d, opt + 24)[0]
    exc = struct.unpack_from("<II", d, opt + 112 + 3 * 8)
    out = {}
    for i in range(nsec):
        sh = opt + optsz + i * 40
        nm = d[sh:sh + 8].rstrip(b"\0").decode(errors="replace")
        vsz, rva, rawsz, rawoff = struct.unpack_from("<IIII", d, sh + 8)
        out[nm] = (rva, vsz, rawoff)
    return base, out, exc


def rangos_pdata(d, secs, exc):
    """[(inicio, fin)] de cada RUNTIME_FUNCTION, en RVA."""
    if ".pdata" not in secs:
        return []
    raw = secs[".pdata"][2]
    return [struct.unpack_from("<II", d, raw + k * 12)
            for k in range(exc[1] // 12)]


def rangos_eh_frame(d, base, secs):
    """[(inicio, fin)] de cada FDE, en RVA.

    El nombre llega recortado a ocho caracteres porque es lo que cabe en una
    cabecera de seccion de COFF; se aceptan las dos formas.
    """
    nombre = ".eh_frame" if ".eh_frame" in secs else ".eh_fram"
    if nombre not in secs:
        return []
    rva, vsz, raw = secs[nombre]
    datos = d[raw:raw + vsz]
    va = base + rva
    out = []
    pos = 0
    while pos + 4 <= len(datos):
        length = struct.unpack_from("<I", datos, pos)[0]
        if length == 0:
            break  # terminador
        ident = struct.unpack_from("<I", datos, pos + 4)[0]
        if ident != 0:  # una FDE, no la CIE
            campo = pos + 8
            desp = struct.unpack_from("<i", datos, campo)[0]
            largo = struct.unpack_from("<I", datos, campo + 4)[0]
            ini = va + campo + desp - base
            out.append((ini, ini + largo))
        pos += 4 + length
    return out


def emite(modo):
    """Compila con `--unwind <modo>` y devuelve (ruta, pdata, eh_frame)."""
    exe = t.wpath("unw_%s.exe" % modo)
    if os.path.exists(exe):
        os.remove(exe)
    if not t.compile_aot(FUENTE, exe, emit="exe", fmt="pe",
                         extra=["--unwind", modo]):
        return (None, None, None)
    with open(exe, "rb") as f:
        d = f.read()
    base, secs, exc = secciones(d)
    return (exe, rangos_pdata(d, secs, exc), rangos_eh_frame(d, base, secs))


rc = 0
salidas = {}

for modo in ("none", "table", "cfi", "both"):
    exe, pd, eh = emite(modo)
    if exe is None:
        print("FALLO: no se emitio el binario con --unwind %s" % modo)
        rc = 1
        continue
    print("  --unwind %-5s -> .pdata: %d  .eh_frame: %d"
          % (modo, len(pd), len(eh)))
    salidas[modo] = (pd, eh)

    # Las tablas son DATOS: no pueden cambiar lo que hace el programa.
    salidas.setdefault("_exit", {})[modo] = t.run_exit(exe)

if rc == 0:
    esperado = {"none": (False, False), "table": (True, False),
                "cfi": (False, True), "both": (True, True)}
    for modo, (quiere_pd, quiere_eh) in esperado.items():
        pd, eh = salidas[modo]
        if bool(pd) != quiere_pd:
            print("FALLO: --unwind %s %s .pdata"
                  % (modo, "deberia traer" if quiere_pd else "no deberia traer"))
            rc = 1
        if bool(eh) != quiere_eh:
            print("FALLO: --unwind %s %s .eh_frame"
                  % (modo, "deberia traer" if quiere_eh else "no deberia traer"))
            rc = 1

    # LO QUE IMPORTA: con `both`, los dos describen EL MISMO codigo.
    pd, eh = salidas["both"]
    if sorted(pd) != sorted(eh):
        print("FALLO: con --unwind both las dos tablas describen codigo "
              "distinto -- cada desenrollador veria media imagen")
        print("       .pdata:    %s" % ["0x%X..0x%X" % r for r in sorted(pd)])
        print("       .eh_frame: %s" % ["0x%X..0x%X" % r for r in sorted(eh)])
        rc = 1
    elif not pd:
        print("FALLO: con --unwind both no hay ninguna funcion descrita")
        rc = 1
    else:
        print("  con --unwind both las %d funciones estan en las DOS tablas"
              % len(pd))

    # Y los cuatro modos tienen que dar el mismo resultado.
    codigos = set(salidas["_exit"].values())
    if len(codigos) != 1:
        print("FALLO: los modos no dan el mismo resultado: %s"
              % salidas["_exit"])
        rc = 1
    else:
        print("  los cuatro modos ejecutan igual (%d)" % codigos.pop())

if rc:
    t.fail("=== unwind_both_test: FALLOS ===")
t.finish()
