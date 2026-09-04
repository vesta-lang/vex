#!/usr/bin/env python3
"""Que ficheros del corpus se pueden compilar por su cuenta.

No es lo mismo que "todos los .vx": una carpeta con `main.vx` es UN ejemplo de
varios ficheros, y los demas de dentro NO compilan por separado -- solo a
traves de su main --.  Medirlos uno a uno daria una lista de fallos que no son
fallos.

Lo usan `codegen_size.py` y `runtime_cycles.py`.  Vive aparte para que no
acaben con dos ideas distintas de que es el corpus: por ese hueco ya se colaron
una vez doce ejemplos de varios ficheros que funcionaban y no guardaba nadie.
"""

import os

RAIZ = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EJEMPLOS = os.path.join(RAIZ, "examples_codes_vx")


def entradas(filtro=""):
    """Los ficheros compilables del corpus, ordenados y con nombre unico.

    @param filtro Subcadena; vacia = todos.
    @return lista de (nombre, ruta).  El nombre lleva la carpeta cuando la hay,
            para que dos `main.vx` de carpetas distintas no se pisen en el
            informe.
    """
    fuera = []
    for base, _dirs, ficheros in os.walk(EJEMPLOS):
        vx = sorted(f for f in ficheros if f.endswith(".vx"))
        if not vx:
            continue
        rel = os.path.relpath(base, EJEMPLOS)
        # Una carpeta con `main.vx` es UN ejemplo: sus otros ficheros son
        # partes suyas, no ejemplos sueltos.
        if "main.vx" in vx:
            nombre = rel.replace(os.sep, "_") if rel != "." else "main"
            fuera.append((nombre, os.path.join(base, "main.vx")))
            continue
        for f in vx:
            nombre = os.path.splitext(f)[0]
            if rel != ".":
                nombre = rel.replace(os.sep, "_") + "_" + nombre
            fuera.append((nombre, os.path.join(base, f)))

    if filtro:
        fuera = [(n, p) for n, p in fuera if filtro in n or filtro in p]
    fuera.sort()
    return fuera
