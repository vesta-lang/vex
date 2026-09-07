#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# VestaVM - Maquina Virtual Distribuida
# Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
# Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
#
"""Comprueba que el generador sabe de que cabeceras depende cada objeto.

EL FALLO QUE BUSCA, que no se ve de ninguna otra forma.  Ninja no relee los
ficheros `.d`: los ingiere una vez tras compilar y guarda las dependencias en su
propio registro.  Si en ese momento el fichero no estaba o venia vacio -- una
restauracion de la cache que no lo repuso, por ejemplo --, ninja anota que ese
objeto **no depende de ninguna cabecera**.

A partir de ahi ese objeto no se recompila nunca por un cambio de cabecera.  No
da error, no avisa: enlaza contra codigo viejo.  Y cuando la firma que cambio
esta en una cabecera compartida, lo que sale es un `undefined reference` a una
funcion que existe, en un fichero que no se toco.

Aparecio con cinco objetos en ese estado, y con once mas huerfanos de una
reorganizacion anterior.  Ninguna herramienta lo miraba.

QUE COMPRUEBA, y son dos cosas distintas:

  - Objetos con CERO dependencias registradas cuando su fuente incluye
    cabeceras.  Es el fallo silencioso de arriba.
  - Objetos en disco sin ninguna entrada en el registro.  Suelen ser restos de
    ficheros que se movieron o borraron: no hacen dano, pero estorban al
    diagnostico y crecen solos.

LO QUE NO COMPRUEBA.  Que las dependencias sean CORRECTAS: para eso habria que
preprocesar, y el compilador ya lo hizo.  Aqui se mira que existan, que es donde
esta el agujero.

Uso:
    python tools/check_build_deps.py <build_dir>
    python tools/check_build_deps.py <build_dir> --limpiar-huerfanos

Codigos de salida, y la diferencia entre los dos ultimos importa:

    0   ningun objeto ciego.
    1   HAY objetos ciegos: el binario puede llevar codigo viejo.
    2   NO SE PUDO COMPROBAR (el generador no es Ninja, o no se encontro).

Quien llame a esto tiene que tratar el 2 como "no se sabe" y no como "bien":
son cosas distintas, y confundirlas es justo el error que esta comprobacion
viene a evitar en otro sitio.

Los huerfanos se informan pero nunca fallan: son suciedad, no un riesgo de
correccion.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys

# Extensiones de fuente cuyos objetos DEBEN tener dependencias.  Un objeto de
# un `.c` o `.cpp` que no incluya nada es legitimo; se comprueba leyendo la
# fuente antes de acusar.
FUENTES = (".c", ".cc", ".cpp", ".cxx")


def buscar_ninja(build_dir: str) -> str:
    """Devuelve el ninja que configuro este directorio, o el del PATH.

    Se prefiere el de la cache de CMake porque puede no ser el del PATH -- un
    IDE suele traer el suyo -- y leer el registro de dependencias con otro
    binario no siempre funciona.
    """
    cache = os.path.join(build_dir, "CMakeCache.txt")
    if os.path.isfile(cache):
        with open(cache, "r", encoding="utf-8", errors="replace") as f:
            for linea in f:
                if linea.startswith("CMAKE_MAKE_PROGRAM:"):
                    ruta = linea.split("=", 1)[1].strip()
                    if os.path.isfile(ruta):
                        return ruta
    return "ninja"


def leer_registro(ninja: str, build_dir: str) -> dict[str, int]:
    """Objetos conocidos por el registro, con cuantas dependencias tiene cada uno.

    @return Diccionario ruta -> numero de dependencias.
    """
    try:
        res = subprocess.run([ninja, "-t", "deps"], cwd=build_dir,
                             capture_output=True, text=True, errors="replace")
    except OSError as e:
        print("no se pudo ejecutar '%s': %s" % (ninja, e))
        sys.exit(2)  # no se sabe, que no es lo mismo que estar bien
    if res.returncode != 0:
        print("'%s -t deps' fallo: puede que el generador no sea Ninja." % ninja)
        sys.exit(2)
    salida = res.stdout

    conocidos: dict[str, int] = {}
    for linea in salida.splitlines():
        # Formato: "ruta/al.obj: #deps N, deps mtime M (VALID|STALE)"
        if ": #deps " not in linea:
            continue
        ruta, resto = linea.split(": #deps ", 1)
        try:
            conocidos[ruta.strip()] = int(resto.split(",", 1)[0])
        except ValueError:
            continue
    return conocidos


def objetos_en_disco(build_dir: str) -> list[str]:
    """Rutas relativas de los `.obj` / `.o` que hay bajo el directorio de build."""
    fuera = []
    for raiz, _, ficheros in os.walk(os.path.join(build_dir, "CMakeFiles")):
        for f in ficheros:
            if f.endswith((".obj", ".o")):
                completo = os.path.join(raiz, f)
                fuera.append(os.path.relpath(completo, build_dir).replace("\\", "/"))
    return sorted(fuera)


def fuente_de(objeto: str, raiz_proyecto: str) -> str | None:
    """Adivina la fuente de un objeto por su nombre.

    CMake nombra el objeto como `<lo que sea>.dir/<ruta de la fuente>.obj`, asi
    que la fuente es lo que queda tras el primer `.dir/` quitando la extension
    del objeto.  Devuelve None si el fichero no esta: eso es lo que delata a un
    huerfano.
    """
    marca = ".dir/"
    if marca not in objeto:
        return None
    relativa = objeto.split(marca, 1)[1]
    for ext in (".obj", ".o"):
        if relativa.endswith(ext):
            relativa = relativa[: -len(ext)]
            break
    ruta = os.path.join(raiz_proyecto, relativa)
    return ruta if os.path.isfile(ruta) else None


def incluye_cabeceras(ruta: str) -> bool:
    """true si la fuente tiene algun `#include`.

    Sin esto se acusaria a una unidad legitimamente sin dependencias, que las
    hay -- y una acusacion falsa en una comprobacion que nadie mira de cerca es
    como se aprende a ignorarla.
    """
    try:
        with open(ruta, "r", encoding="utf-8", errors="replace") as f:
            return any(l.lstrip().startswith("#include") for l in f)
    except OSError:
        return False


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("build_dir", help="directorio de build de CMake/Ninja")
    ap.add_argument("--limpiar-huerfanos", action="store_true",
                    help="borra los objetos sin entrada en el registro")
    args = ap.parse_args()

    build_dir = os.path.abspath(args.build_dir)
    if not os.path.isdir(build_dir):
        sys.exit("no es un directorio: %s" % build_dir)
    raiz = os.path.abspath(os.path.join(build_dir, ".."))

    ninja = buscar_ninja(build_dir)
    conocidos = leer_registro(ninja, build_dir)
    en_disco = objetos_en_disco(build_dir)

    ciegos: list[str] = []   # con entrada, pero sin dependencias
    huerfanos: list[str] = []  # sin entrada, y sin fuente

    for obj in en_disco:
        fuente = fuente_de(obj, raiz)
        if obj not in conocidos:
            if fuente is None:
                huerfanos.append(obj)
            else:
                # Tiene fuente y no tiene entrada: nunca se recompilara por
                # cabecera.  Cuenta como ciego, que es lo grave.
                ciegos.append(obj)
            continue
        if conocidos[obj] == 0 and fuente and incluye_cabeceras(fuente):
            ciegos.append(obj)

    print("objetos en disco      : %d" % len(en_disco))
    print("con dependencias      : %d" % sum(1 for o in en_disco
                                             if conocidos.get(o, 0) > 0))
    print("huerfanos (sin fuente): %d" % len(huerfanos))
    print("CIEGOS                : %d" % len(ciegos))

    if huerfanos:
        print("\nHuerfanos -- su fuente ya no existe.  No hacen dano; estorban.")
        for o in huerfanos[:20]:
            print("   %s" % o)
        if len(huerfanos) > 20:
            print("   ... y %d mas" % (len(huerfanos) - 20))
        if args.limpiar_huerfanos:
            for o in huerfanos:
                try:
                    os.remove(os.path.join(build_dir, o))
                except OSError as e:
                    print("   no se pudo borrar %s: %s" % (o, e))
            print("   borrados.")

    if ciegos:
        print("\nCIEGOS -- ningun cambio de cabecera los recompilara.")
        print("Se arregla borrandolos y reconstruyendo; si vuelve a pasar, mirar")
        print("la cache del compilador (modo depend).")
        for o in ciegos:
            print("   %s" % o)
        return 1

    print("\nNinguno ciego: cada objeto sabe de que cabeceras depende.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
