#!/usr/bin/env python3
"""¿Se puede derivar el coste por opcode del binario, sin tocar la VM?

Esto es una PRUEBA DE VIABILIDAD, no el modelo de coste.  Contesta tres
preguntas antes de que nadie escriba una linea en el interprete:

  1. ¿Cuantos handlers distintos hay de verdad?  Las tablas tienen 512
     entradas, pero los punteros `exec`/`decode` se comparten entre opcodes.
     Si `decode` resulta tener ocho funciones en vez de doscientas, la tabla
     de coste de descodificacion es ocho numeros, no doscientos.

  2. ¿Estan esos simbolos en el binario que se envia?  Si el binario va
     stripped, la via de derivar el coste del codigo maquina no existe y hay
     que medir fuera de linea en su lugar.

  3. ¿Cuantos handlers tienen bucles?  Un handler con un bucle dependiente de
     datos -- strings, alloc, el recorrido de vtable -- tiene un coste
     estatico que es solo una COTA INFERIOR.  Saber cuantos son decide si el
     modelo cubre el problema o solo la mitad facil.

No modifica nada.  Solo lee: el fuente de las tablas y, si se le da, un
binario.

    python viabilidad.py
    python viabilidad.py --binario /usr/bin/vesta
"""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

# Una entrada de InstrFormat, tal y como se escribe en `decode_table.cpp`:
#
#     {// add reg, reg
#      "add", Assembly::Bytecode::AddressingMode::REG,
#      Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_add_reg,
#      decode_instr_two_op_reg},
#
# Se parsea el FUENTE y no el binario a proposito: es la unica forma de tener
# los nombres de opcode junto a los simbolos, y ademas funciona con el arbol
# sin compilar.  El comentario `{//...}` puede faltar o llevar cualquier cosa.
ENTRADA = re.compile(
    r'\{\s*(?://[^\n]*\n\s*)?'          # comentario opcional tras la llave
    r'"([^"]*)"\s*,\s*'                 # nombre
    r'Assembly::Bytecode::AddressingMode::(\w+)\s*,\s*'
    r'Assembly::Bytecode::InstrSizeMode::(\w+)\s*,\s*'
    r'(\w+)\s*,\s*'                     # exec  (simbolo o nullptr)
    r'(\w+)\s*\}',                      # decode(simbolo o nullptr)
    re.MULTILINE)


def leer_tabla(texto: str, nombre: str):
    """Las entradas de una de las dos tablas.  [(name, mode, size, exec, dec)]"""
    m = re.search(r'InstrFormat\s+' + nombre + r'\s*\[[^\]]*\]\s*=\s*\{',
                  texto, re.IGNORECASE)
    if not m:
        return []
    # Hasta el cierre de la tabla: la primera linea que empieza por `};`.
    resto = texto[m.end():]
    fin = re.search(r'^\};', resto, re.MULTILINE)
    cuerpo = resto[:fin.start()] if fin else resto
    return [(a, b, c, d, e) for a, b, c, d, e in ENTRADA.findall(cuerpo)]


def simbolos_del_binario(binario: Path):
    """{simbolo: tamano} del binario, o None si no se puede leer.

    Se prueba `nm` y luego `objdump`: en un binario stripped no habra nada, y
    esa es una respuesta valida de la prueba -- significa que la via del
    codigo maquina necesita un build con simbolos.
    """
    for orden in (["nm", "--defined-only", "-S", str(binario)],
                  ["objdump", "-t", str(binario)]):
        if not shutil.which(orden[0]):
            continue
        try:
            r = subprocess.run(orden, capture_output=True, text=True,
                               timeout=120)
        except (OSError, subprocess.SubprocessError):
            continue
        if r.returncode != 0:
            continue
        out = {}
        for linea in r.stdout.splitlines():
            partes = linea.split()
            nombre = ""
            tam = 0
            if orden[0] == "nm":
                # <addr> [<size>] <tipo> <nombre>
                if len(partes) >= 4 and partes[2] in "tT":
                    nombre = partes[3]
                    try:
                        tam = int(partes[1], 16)
                    except ValueError:
                        tam = 0
                elif len(partes) == 3 and partes[1] in "tT":
                    nombre = partes[2]
            else:
                if len(partes) >= 6 and ".text" in linea:
                    nombre = partes[-1]
                    tam = int(partes[-2], 16)
            # En PE el mismo simbolo aparece varias veces con el prefijo de su
            # seccion (`.text$_ZN...`, `.pdata$_ZN...`, `.xdata$_ZN...`).  Esos
            # alias NO valen: `objdump --disassemble=` no los reconoce y
            # devuelve una seccion vacia, que es lo que hacia que casi ningun
            # handler se desensamblara y los pocos que "salian" fueran otra
            # cosa.  Solo el nombre pelado sirve.
            if nombre and "$" not in nombre:
                out[nombre] = tam
        if out:
            return out
    return None


# Una linea de objdump:  "  140d1d380:\t55\tpush   %rbp"
# y en un salto, el destino va al final:  "... \tje     140d1d3f0 <...>"
LINEA_ASM = re.compile(
    r'^\s+([0-9a-f]+):\s+(?:[0-9a-f]{2} )+\s*(\w+)(?:\s+([0-9a-f]+))?')


def desensamblar(binario: Path, simbolo: str):
    """(direccion, mnemonico, destino) de cada instruccion del simbolo."""
    if not shutil.which("objdump"):
        return []
    try:
        r = subprocess.run(
            ["objdump", "-d", "--disassemble=" + simbolo, str(binario)],
            capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return []
    fuera = []
    for linea in r.stdout.splitlines():
        m = LINEA_ASM.match(linea)
        if not m:
            continue
        dst = None
        if m.group(3):
            try:
                dst = int(m.group(3), 16)
            except ValueError:
                dst = None
        fuera.append((int(m.group(1), 16), m.group(2), dst))
    return fuera


def clasificar(instrs):
    """¿Este handler da un coste, una cota, o algo intermedio?

    Tres categorias, y la del medio es la que importa: un salto hacia ADELANTE
    es un `if`, y su coste sigue siendo calculable -- el maximo sobre los
    caminos, o su media ponderada.  Solo un salto hacia ATRAS (un bucle) o una
    llamada a algo no acotado convierten el coste en una cota inferior.
    Meterlos todos en el mismo saco decia que 199 de 210 handlers eran
    inservibles, y no es verdad.
    """
    n_atras = n_adelante = n_call = 0
    for addr, mnem, dst in instrs:
        if mnem in LLAMADAS:
            n_call += 1
        elif mnem in SALTOS and dst is not None:
            if dst <= addr:
                n_atras += 1
            else:
                n_adelante += 1
    if n_atras or n_call:
        return ("cota", n_atras, n_adelante, n_call)
    if n_adelante:
        return ("acotado", n_atras, n_adelante, n_call)
    return ("coste", n_atras, n_adelante, n_call)


# Saltos hacia ATRAS y llamadas: lo que convierte un coste en una cota.
SALTOS = {"jmp", "je", "jne", "jl", "jle", "jg", "jge", "ja", "jae", "jb",
          "jbe", "js", "jns", "jo", "jno", "jp", "jnp", "loop"}
LLAMADAS = {"call", "callq"}


def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--fuente", type=str, default="",
                   help="src/runtime/decode_table.cpp (por defecto se busca "
                        "desde la raiz del proyecto)")
    p.add_argument("--binario", type=str, default="",
                   help="binario con simbolos del que sacar los handlers.  "
                        "Sin esto solo se contestan las preguntas 1 y 3.")
    p.add_argument("--muestras", type=int, default=6,
                   help="cuantos handlers desensamblar como muestra")
    args = p.parse_args()

    raiz = Path(__file__).resolve().parents[2]
    fuente = Path(args.fuente) if args.fuente else (
        raiz / "src" / "runtime" / "decode_table.cpp")
    if not fuente.is_file():
        print("[error] no encuentro %s" % fuente)
        return 1
    texto = fuente.read_text(encoding="utf-8", errors="replace")

    tablas = {n: leer_tabla(texto, n) for n in
              ("decode_table_primary", "decode_table_extended")}
    todas = [e for v in tablas.values() for e in v]
    if not todas:
        print("[error] no pude parsear ninguna entrada.  El formato de "
              "`decode_table.cpp` habra cambiado; hay que ajustar el patron.")
        return 1

    print("VIABILIDAD del modelo de coste por opcode")
    print("  fuente: %s" % fuente)
    print()

    # --- Pregunta 1: cuantos handlers distintos hay -------------------------
    print("1) Cuantos handlers distintos hay de verdad")
    for nombre, entradas in tablas.items():
        vivas = [e for e in entradas if e[3] != "nullptr"]
        print("   %-24s %3d entradas, %3d con exec"
              % (nombre.replace("decode_table_", ""), len(entradas),
                 len(vivas)))
    vivas = [e for e in todas if e[3] != "nullptr"]
    ex = Counter(e[3] for e in vivas)
    de = Counter(e[4] for e in vivas if e[4] != "nullptr")
    print()
    print("   opcodes implementados      %4d" % len(vivas))
    print("   funciones `exec` distintas %4d   (%.1f opcodes por funcion)"
          % (len(ex), len(vivas) / max(1, len(ex))))
    print("   funciones `decode` distintas %2d   (%.1f opcodes por funcion)"
          % (len(de), len(vivas) / max(1, len(de))))
    print()
    print("   Los `decode` mas compartidos -- estos son la tabla de coste de")
    print("   descodificacion, y son los que se pagan en cada fallo de icache:")
    for sim, n in de.most_common(8):
        print("      %-34s %3d opcodes" % (sim, n))

    # --- Modos y tamanos, que es lo que decide el coste de descodificar -----
    print()
    print("   Modos de direccionamiento en uso: %d"
          % len({e[1] for e in vivas}))
    print("   Modos de tamano en uso:           %d   (%s)"
          % (len({e[2] for e in vivas}),
             ", ".join(sorted({e[2] for e in vivas}))))

    if not args.binario:
        print()
        print("2) y 3) necesitan un binario: pasa --binario <ruta>")
        return 0

    # --- Pregunta 2: estan los simbolos en el binario -----------------------
    binario = Path(args.binario)
    if not binario.is_file():
        print("\n[error] no encuentro el binario %s" % binario)
        return 1
    print()
    print("2) Estan los handlers en el binario")
    print("   %s" % binario)
    simbolos = simbolos_del_binario(binario)
    if simbolos is None:
        print("   NO se pudieron leer simbolos (¿sin `nm`/`objdump`, o el "
              "binario esta stripped?).")
        print("   Sin simbolos, la via del codigo maquina no existe: habria "
              "que medir fuera de linea.")
        return 0
    print("   simbolos de codigo leidos: %d" % len(simbolos))

    def buscar(sim):
        """El simbolo real, tolerando el mangling de C++.

        En el fuente el handler es `exec_instr_add_reg`; en el binario es
        `_ZN7runtime18exec_instr_add_regEPNS_9ProcessVMERKNS_12DecodedInstrE`.
        Se busca el nombre como token dentro del manglado -- con su longitud
        delante, que es como Itanium los codifica -- para no casar
        `exec_instr_add` con `exec_instr_add_reg`.
        """
        if sim in simbolos:
            return sim
        token = "%d%s" % (len(sim), sim)     # Itanium: <longitud><nombre>
        candidatos = [s for s in simbolos if token in s]
        if candidatos:
            return min(candidatos, key=len)  # el mas corto = sin envoltorios
        return None

    hallados_ex = {s: buscar(s) for s in ex}
    hallados_de = {s: buscar(s) for s in de}
    n_ex = sum(1 for v in hallados_ex.values() if v)
    n_de = sum(1 for v in hallados_de.values() if v)
    print("   `exec`   encontrados: %d de %d" % (n_ex, len(ex)))
    print("   `decode` encontrados: %d de %d" % (n_de, len(de)))
    if not n_ex:
        print("   Ninguno: el binario no expone estos simbolos.  La via pide "
              "un build sin strip.")
        return 0

    # --- Pregunta 3: cuantos tienen bucles ----------------------------------
    print()
    print("3) Cuantos handlers dan COSTE y cuantos solo una COTA")
    print("   (un salto hacia atras o una llamada = el coste estatico es una")
    print("    cota inferior, no un coste)")
    filas = []
    for grupo, hallados in (("exec", hallados_ex), ("decode", hallados_de)):
        for sim, real in sorted(hallados.items()):
            if not real:
                continue
            instrs = desensamblar(binario, real)
            if not instrs:
                continue
            veredicto, atras, adelante, calls = clasificar(instrs)
            filas.append((grupo, sim, len(instrs), atras, adelante, calls,
                          veredicto))
    if not filas:
        print("   No se pudo desensamblar ninguno (¿falta `objdump`?).")
        return 0

    for grupo in ("exec", "decode"):
        g = [f for f in filas if f[0] == grupo]
        if not g:
            continue
        c = Counter(f[6] for f in g)
        print()
        print("   %-8s %3d handlers:  coste %3d   acotado %3d   cota %3d"
              % (grupo, len(g), c["coste"], c["acotado"], c["cota"]))

    print()
    print("   Muestra de `exec`, del mas simple al mas complejo:")
    ex_filas = sorted((f for f in filas if f[0] == "exec"), key=lambda f: f[2])
    mitad = max(1, args.muestras // 2)
    muestra = ex_filas[:mitad] + ex_filas[-mitad:]
    print("   %-30s %6s %7s %9s %6s  %s"
          % ("handler", "instrs", "atras", "adelante", "calls", "veredicto"))
    for _, sim, n, atras, adelante, calls, ver in muestra:
        print("   %-30s %6d %7d %9d %6d  %s"
              % (sim[:30], n, atras, adelante, calls, ver))
    return 0


if __name__ == "__main__":
    sys.exit(main())
