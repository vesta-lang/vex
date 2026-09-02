#!/usr/bin/env python3
"""Contrasta `doc/VMdoc/SetInstruccionesVM` con la tabla real de opcodes.

Por que
-------
Esa doc no es material de apoyo: es la ESPECIFICACION del set de instrucciones.
Lo que pasa es que se quedo sin actualizar mientras la tabla seguia creciendo, y
mientras las dos no coincidan no puede ejercer de autoridad -- ni para quien
implementa una instruccion, ni para el desensamblador, ni para un analisis que
necesite saber que toca cada opcode.

Esto saca la lista de en que difieren. Cada linea es algo que reconciliar: o la
doc se quedo vieja, o la tabla se desvio del contrato.

Como lee cada lado
------------------
De la doc, las filas de tabla markdown. Hay dos formatos en uso y los dos
cuentan:

    | `fadd` | 0x00 | 0xF1 | REG | 4 bytes | ...    <- prefijo y opcode aparte
    | `hlt`  | 0x01 | 1 byte | ...                  <- una sola columna

De la tabla, los comentarios `/* 0xNN */` de `decode_table.cpp`, separando la
primaria de la extendida por donde empieza cada array: sin separarlas se compara
un opcode primario con uno extendido y salen discrepancias que no existen.

Uso:
    python tools/doc_vs_tabla.py [--detalle]
"""

import argparse
import collections
import pathlib
import re
import sys

RAIZ = pathlib.Path(__file__).resolve().parent.parent

# | `nombre` | 0xNN [| 0xMM] | ...      (paginas escritas a mano)
# | `nombre` | --- | 0xNN | ...         (tabla generada: `---` = sin prefijo)
#
# La columna de PREFIJO puede ser `0x00` (extendida), `---` (primaria) o no
# existir.  Exigiendo el opcode PEGADO al nombre se perdian las 14 filas
# primarias de la tabla generada: `push`, `pop`, `enter`, `callvm`... salian
# como "sin documentar" estando ahi delante.  Es el cuarto fallo de lectura de
# este comprobador, y por eso sus numeros se miran antes de creerselos.
#
# El nombre NO admite espacios a proposito.  Admitiendolos, las paginas a mano
# --que escriben el operando dentro de las comillas, `push reg`-- colaban 24
# mnemonicos inventados.  El precio es la unica entrada de la tabla que lleva
# espacios, `inc / dec`, que sale como no documentada.
FILA_DOC = re.compile(
    r"\|\s*`([a-z_0-9.]+)`\s*\|\s*(0x[0-9A-Fa-f]{2}|---)\s*"
    r"(?:\|\s*(0x[0-9A-Fa-f]{2})\s*)?\|"
)

# /* 0xNN ... */ { ... "nombre",
#
# El cuerpo del comentario se cruza con DOTALL y no-avaricioso: hay comentarios
# de varias lineas, y otros que llevan un `*` dentro ("dispatch via MethodInfo*").
# Parando en el primer `*` se perdian entradas -- `callm` y `tryleave` salian
# como "documentadas que no existen" cuando estan en la tabla.
ENTRADA_TABLA = re.compile(
    r"/\* (0x[0-9A-Fa-f]{2}).*?\*/\s*\{.*?\"([a-z_0-9 /]*)\"",
    re.DOTALL,
)


def leer_doc():
    """nombre -> {(tabla, opcode)}.  `tabla` es 'primary' o 'extended'."""
    doc = collections.defaultdict(set)
    raiz = RAIZ / "doc" / "VMdoc" / "SetInstruccionesVM"
    if not raiz.is_dir():
        sys.exit(f"no encuentro {raiz}")
    for f in raiz.rglob("*.md"):
        texto = f.read_text(encoding="utf-8", errors="replace")
        for m in FILA_DOC.finditer(texto):
            nombre, pref, b = m.group(1), m.group(2), m.group(3)
            if pref == "---":
                # Tabla generada, fila de la PRIMARIA: el `---` dice que no
                # lleva prefijo, asi que aqui si se sabe de que tabla es.
                if b:
                    doc[nombre].add(("primary", int(b, 16)))
                continue
            a = int(pref, 16)
            if a == 0x00 and b:
                doc[nombre].add(("extended", int(b, 16)))
            else:
                # Una sola columna: la pagina no dice de que tabla es.  Se
                # marca como INDETERMINADA en vez de suponer que es primaria
                # -- suponerlo daba 41 "discrepancias" que solo eran mi
                # lectura, y un numero inventado es peor que no tenerlo.
                doc[nombre].add(("?", a))
    return doc


def leer_tabla():
    """nombre -> {(tabla, opcode)}, separando primaria de extendida."""
    src = (RAIZ / "src" / "runtime" / "decode_table.cpp").read_text(
        encoding="utf-8", errors="replace"
    )
    # Fuera los comentarios `//` ANTES de buscar: alguno lleva una palabra
    # entrecomillada dentro ("halt" en la nota de `tryleave`), y se la comia
    # como si fuera el nombre de la instruccion -- `tryleave` salia como
    # inexistente y aparecia un `halt` que no existe.
    src = re.sub(r"//.*", "", src)  # `.` no cruza lineas: corta hasta el final
    corte = src.index("InstrFormat decode_table_extended")
    real = collections.defaultdict(set)
    for cual, trozo in (("primary", src[:corte]), ("extended", src[corte:])):
        for m in ENTRADA_TABLA.finditer(trozo):
            if m.group(2):
                real[m.group(2)].add((cual, int(m.group(1), 16)))
    return real


def sitios(s):
    return " ".join(("0x%02x" % o) if t == "?" else f"{t[:3]}/0x{o:02x}"
                    for t, o in sorted(s))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--detalle", action="store_true",
                    help="lista entera de las no documentadas")
    args = ap.parse_args()

    doc, real = leer_doc(), leer_tabla()

    # Los `.pd` / `.ps` son alias del ensamblador sobre el mismo opcode, no
    # instrucciones aparte.
    alias = {n for n in doc if "." in n and n.split(".")[0] in doc}

    fantasma = sorted(set(doc) - set(real) - alias)
    sin_doc = sorted(set(real) - set(doc))
    def concuerda(d, r):
        """Con la tabla indeterminada basta que coincida el NUMERO."""
        for td, od in d:
            for tr, orr in r:
                if od == orr and (td == "?" or td == tr):
                    return True
        return False

    movidas = sorted(n for n in set(doc) & set(real) if not concuerda(doc[n], real[n]))

    print(f"doc: {len(doc)} mnemonicos ({len(alias)} alias)   "
          f"tabla: {len(real)} mnemonicos\n")

    print(f"DOCUMENTADAS QUE NO ESTAN EN LA TABLA ({len(fantasma)})")
    print("  o se quitaron de la VM y quedo la pagina, o nunca llegaron:")
    print("   " + " ".join(fantasma) + "\n")

    print(f"EN LA TABLA Y SIN DOCUMENTAR ({len(sin_doc)})")
    lista = sin_doc if args.detalle else sin_doc[:36]
    for i in range(0, len(lista), 10):
        print("   " + " ".join(lista[i:i + 10]))
    if not args.detalle and len(sin_doc) > 36:
        print(f"   ... y {len(sin_doc) - 36} mas (--detalle)")
    print()

    print(f"CON OPCODE DISTINTO ({len(movidas)})")
    for n in movidas:
        print(f"   {n:<16} doc={sitios(doc[n]):<24} tabla={sitios(real[n])}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
