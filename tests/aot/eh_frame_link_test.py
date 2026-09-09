#!/usr/bin/env python3
"""Valida `.eh_frame` a traves del ENLACE de varios .obj, no de un binario suelto.

# LADO: windows

Por que este test y no basta con el de un ejecutable
----------------------------------------------------
Emitir `.eh_frame` en un solo binario no prueba casi nada: la seccion la escribe
el mismo codigo que decide donde va, asi que cuadra por construccion.  Lo que
hay que comprobar es lo otro, que es donde estan los problemas de verdad:

  1. Que la seccion sobrevive a ir dentro de un .obj RELOCATABLE, donde las
     direcciones de funcion no se pueden escribir todavia y quedan como
     relocations que resuelve el enlazador.
  2. Que al enlazar VARIOS .obj las secciones se concatenan y siguen siendo
     legibles.  `.eh_frame` esta pensada para esto -- cada FDE guarda la
     DISTANCIA hasta su CIE, no un offset absoluto, justamente para que dos
     secciones se puedan pegar sin reescribirlas --, pero que el formato lo
     permita no quiere decir que nuestro emisor y nuestro enlazador lo hagan.
  3. Que las direcciones que quedan dentro apuntan a las funciones de verdad, y
     no a un sitio plausible.  Una FDE con una direccion equivocada no rompe
     nada visible: el binario corre igual y solo falla el dia que hay que
     recorrer la pila.

El test recorre la seccion como la recorreria un lector -- registro a registro,
por su longitud -- y no confia en el tamano de la seccion para saber donde
acaba, que es como se descubre que falta el terminador.

    python tests/aot/eh_frame_link_test.py <build_dir>
"""
import shutil
import struct
import subprocess

from aot_harness import AotTest

t = AotTest()


def leer(path):
    with open(path, "rb") as f:
        return f.read()


def secciones_pe(d):
    """Devuelve {nombre: (rva, vsize, raw_off, raw_size)} de un PE."""
    lf = struct.unpack_from("<I", d, 0x3C)[0]
    if d[lf:lf + 4] != b"PE\0\0":
        return {}
    fh = lf + 4
    nsec = struct.unpack_from("<H", d, fh + 2)[0]
    optsz = struct.unpack_from("<H", d, fh + 16)[0]
    sh0 = fh + 20 + optsz
    out = {}
    for i in range(nsec):
        sh = sh0 + i * 40
        nm = d[sh:sh + 8].rstrip(b"\0").decode(errors="replace")
        vsz, rva, rawsz, rawoff = struct.unpack_from("<IIII", d, sh + 8)
        out[nm] = (rva, vsz, rawoff, rawsz)
    return out


def image_base(d):
    lf = struct.unpack_from("<I", d, 0x3C)[0]
    return struct.unpack_from("<Q", d, lf + 4 + 20 + 24)[0]


def recorre_eh_frame(datos, base_va):
    """Recorre `.eh_frame` como un lector: devuelve (n_cie, [pc de cada FDE]).

    `datos` son los bytes de la seccion y `base_va` la direccion virtual del
    primer byte, que hace falta porque los punteros son relativos a su propia
    posicion.
    """
    n_cie = 0
    pcs = []
    pos = 0
    while pos + 4 <= len(datos):
        length = struct.unpack_from("<I", datos, pos)[0]
        if length == 0:
            break  # terminador: aqui acaba, sin mirar el tamano de la seccion
        if pos + 4 + length > len(datos):
            print("FALLO: un registro de .eh_frame se sale de la seccion")
            return (-1, [])
        ident = struct.unpack_from("<I", datos, pos + 4)[0]
        if ident == 0:
            n_cie += 1
        else:
            campo_pc = pos + 8
            val = struct.unpack_from("<i", datos, campo_pc)[0]
            pcs.append(base_va + campo_pc + val)
        pos += 4 + length
    return (n_cie, pcs)


# --- Dos unidades separadas, cada una con sus funciones -------------------
a_vx = t.write("ehA.vx", """
i64 aporta_a(i64 x) {
	i64 t = 0;
	i64 i = 0;
	while (i < x) { t = t + i * 2; i = i + 1; }
	return t;
}
""")
b_vx = t.write("ehB.vx", """
i64 aporta_b(i64 x) {
	i64 t = 1;
	i64 i = 0;
	while (i < x) { t = t + i; i = i + 1; }
	return t;
}
i64 main() { return 7; }
""")

a_obj, b_obj = t.wpath("ehA.obj"), t.wpath("ehB.obj")
rc = 0

if not t.compile_aot(a_vx, a_obj, emit="obj", fmt="pe",
                     extra=["--unwind", "cfi"]):
    t.fail("FALLO: no se emitio ehA.obj")
    t.finish()
if not t.compile_aot(b_vx, b_obj, emit="obj", fmt="pe",
                     extra=["--unwind", "cfi"]):
    t.fail("FALLO: no se emitio ehB.obj")
    t.finish()

# Cada .obj tiene que traer YA su .eh_frame; si no, no hay nada que enlazar.
for nombre, obj in (("ehA", a_obj), ("ehB", b_obj)):
    # Un .obj de COFF no lleva cabecera opcional, asi que el recorrido de
    # secciones de arriba no le sirve; se busca el nombre en crudo.  Con ocho
    # caracteres, que es lo que cabe en una cabecera de seccion de COFF.
    if b".eh_fram" not in leer(obj):
        print("FALLO: %s.obj no lleva la seccion de CFI" % nombre)
        rc = 1
    else:
        print("  %s.obj: seccion de CFI presente" % nombre)

# --- El enlace, que es lo que se quiere probar ----------------------------
prog = t.wpath("ehlink.exe")
if not t.vm_link([a_obj, b_obj], prog, fmt="pe"):
    print("FALLO: el enlace de los dos .obj no produjo ejecutable")
    t.fail("link")
    t.finish()

d = leer(prog)
secs = secciones_pe(d)

# El nombre llega TRUNCADO, y no es un defecto: una cabecera de seccion de
# COFF reserva ocho bytes para el nombre y ".eh_frame" tiene nueve.  En un
# .obj se puede guardar aparte, en una imagen no.  Se busca por el nombre
# real y por el recortado; si algun dia deja de recortarse, sigue valiendo.
nombre_eh = ".eh_frame" if ".eh_frame" in secs else ".eh_fram"

if nombre_eh not in secs:
    print("FALLO: el ejecutable enlazado perdio la seccion de CFI")
    rc = 1
else:
    rva, vsz, rawoff, rawsz = secs[nombre_eh]
    base = image_base(d)
    datos = d[rawoff:rawoff + min(vsz, rawsz)]
    n_cie, pcs = recorre_eh_frame(datos, base + rva)
    print("  enlazado: .eh_frame de %d bytes, %d CIE, %d FDE"
          % (vsz, n_cie, len(pcs)))

    # DOS CIE es lo que prueba que la fusion salio bien, y es el corazon del
    # test.  Cada objeto aporta su grupo -- CIE propia mas sus FDE -- y un
    # enlazador que no deduplica los pega tal cual; que se sigan viendo las dos
    # significa que el recorrido llego hasta el final de la seccion.  Si el
    # primer grupo llevara un terminador dentro, el lector se pararia en el y
    # aqui se veria UNA.  Asi se descubrio exactamente ese fallo.
    if n_cie < 2:
        print("FALLO: se esperaban 2 CIE (una por objeto), hay %d -- el "
              "recorrido no llego al segundo grupo" % n_cie)
        rc = 1
    # Una FDE por funcion VIVA, que no son todas las escritas: lo que nadie
    # llama se queda fuera al compilar.  De ahi que se pida "al menos dos" y no
    # un numero exacto -- un test que fije el numero se rompe cada vez que
    # cambia el inlining, y no era eso lo que se estaba comprobando.
    if len(pcs) < 2:
        print("FALLO: se esperaban al menos 2 FDE, hay %d" % len(pcs))
        rc = 1

    # Y lo que de verdad importa: que cada direccion caiga DENTRO del codigo.
    trva, tvsz = secs[".text"][0], secs[".text"][1]
    ini, fin = base + trva, base + trva + tvsz
    fuera = [p for p in pcs if not (ini <= p < fin)]
    if fuera:
        print("FALLO: %d FDE apuntan fuera de .text [0x%X,0x%X): %s"
              % (len(fuera), ini, fin, ", ".join("0x%X" % p for p in fuera)))
        rc = 1
    else:
        print("  las %d FDE apuntan dentro de .text [0x%X,0x%X)"
              % (len(pcs), ini, fin))

    # Ninguna repetida: dos FDE con el mismo inicio significa que una reloc se
    # quedo sin resolver y las dos leen el mismo cero.
    if len(set(pcs)) != len(pcs):
        print("FALLO: hay FDE con la misma direccion de inicio (reloc sin "
              "resolver?)")
        rc = 1

# El binario tiene que seguir corriendo: estas tablas son datos, no codigo.
ex = t.run_exit(prog)
if ex != 7:
    print("FALLO: el ejecutable enlazado devolvio %d, se esperaba 7" % ex)
    rc = 1
else:
    print("  el ejecutable enlazado corre y devuelve 7")

# --- Lo mismo en ELF, y leido por una herramienta AJENA -------------------
#
# Se emite ELF desde Windows (el compilador cruza) y se lee con
# `objdump --dwarf=frames`, que decodifica la seccion de verdad.  Contrastar
# contra un lector externo vale mas que contra el nuestro: si nuestro escritor
# y nuestro lector compartieran un error, se validarian entre ellos.
#
# Lo que se vigila aqui es un fallo que YA OCURRIO.  Las FDE se rellenaban a
# cuatro bytes; al enlazar, cada aportacion empieza en un limite de ocho, asi
# que una que acabara en multiplo de cuatro dejaba cuatro ceros de relleno
# detras -- y cuatro ceros SON un registro de longitud cero, o sea un
# terminador.  El resultado era una seccion con un terminador EN MEDIO: un
# lector se paraba ahi y daba por vacio todo lo que aportaran los objetos
# siguientes.  De ahi que no baste con contar FDE: hay que exigir que el
# terminador aparezca UNA vez y al final.
if not shutil.which("objdump"):
    print("  (sin objdump: no se comprueba el lado ELF)")
else:
    a_o, b_o = t.wpath("ehA.o"), t.wpath("ehB.o")
    ok_elf = (t.compile_aot(a_vx, a_o, emit="obj", fmt="elf",
                            extra=["--unwind", "cfi"]) and
              t.compile_aot(b_vx, b_o, emit="obj", fmt="elf",
                            extra=["--unwind", "cfi"]))
    if not ok_elf:
        print("FALLO: no se emitieron los objetos ELF")
        rc = 1
    else:
        elf = t.wpath("ehlink.elf")
        if not t.vm_link([a_o, b_o], elf, fmt="elf"):
            print("FALLO: no se enlazaron los objetos ELF")
            rc = 1
        else:
            p = subprocess.run(["objdump", "--dwarf=frames", elf],
                               capture_output=True, text=True)
            texto = p.stdout or ""
            lineas = [l for l in texto.splitlines()
                      if " CIE" in l or " FDE " in l or "terminator" in l]
            n_cie = sum(1 for l in lineas if l.rstrip().endswith("CIE"))
            n_fde = sum(1 for l in lineas if " FDE " in l)
            n_fin = sum(1 for l in lineas if "terminator" in l)
            print("  ELF: %d CIE, %d FDE, %d terminador(es) segun objdump"
                  % (n_cie, n_fde, n_fin))

            if n_cie < 2 or n_fde < 2:
                print("FALLO: se esperaban al menos 2 CIE y 2 FDE")
                rc = 1
            if n_fin != 1:
                print("FALLO: tiene que haber UN terminador; hay %d.  Mas de "
                      "uno significa relleno leido como fin de seccion" % n_fin)
                rc = 1
            elif lineas and "terminator" not in lineas[-1]:
                print("FALLO: el terminador no es lo ultimo -- lo que venga "
                      "detras es inalcanzable para un lector")
                rc = 1
            # Y que las FDE describan codigo, no la direccion cero.
            for l in lineas:
                if " FDE " in l and "pc=0000000000000000" in l:
                    print("FALLO: una FDE apunta a la direccion cero (reloc "
                          "sin resolver): " + l.strip())
                    rc = 1

if rc:
    t.fail("=== eh_frame_link_test: FALLOS ===")
t.finish()
