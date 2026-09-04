#!/usr/bin/env python3
"""Cuanto trabaja de verdad cada ejemplo, medido DENTRO del binario.

    python tools/bench/runtime_cycles.py <build> [-o salida.json] [-k patron]
                                         [-j N] [--corridas N]

Sale en el formato que lee `compare_json.py`, asi que comparar dos medidas --
media geometrica, umbral del cinco por ciento -- ya esta hecho:

    python tools/bench/runtime_cycles.py cmake-build-release -o antes.json
    ...cambiar algo...
    python tools/bench/runtime_cycles.py cmake-build-release -o despues.json
    python tools/bench/compare_json.py antes.json despues.json

Por que desde dentro y no cronometrando el proceso.  Medido en esta maquina
sobre un hola mundo:

    arrancar el proceso        ~6.200.000 ciclos
    lo que main hace de verdad        450 ciclos

El arranque es CIEN VECES el programa, asi que desde fuera uno que no hace nada
y uno vectorizado miden lo mismo -- y encima el reloj de pared da +-90% de
dispersion, el de CPU lee cero (resolucion de 15,6 ms) y los ciclos del proceso
+-30%.  Ninguna sirve de red.

Desde dentro si: se lee el contador al entrar y al salir de `main`, y de las
corridas se toma el MINIMO, que es lo que menos recoge del ruido del sistema.
Comprobado en tres rondas independientes: 3890 / 3914 / 3920 ciclos sobre el
mismo binario -- ocho decimas de uno por ciento.

Como se instrumenta sin tocar el ejemplo: se antepone `medidor_ciclos.vx`, que
declara los ganchos.  Vale porque `namespace` como sentencia rige hasta el
siguiente, asi que el medidor y el ejemplo quedan cada uno en el suyo.

Solo x86: el medidor lee `rdtsc`.  Ver su cabecera.
"""

import argparse
import concurrent.futures
import json
import os
import re
import subprocess
import sys

RAIZ = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EJEMPLOS = os.path.join(RAIZ, "examples_codes_vx")
MEDIDOR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "medidor_ciclos.vx")
MARCA = re.compile(r"__CICLOS__\s+(\d+)")


def _medir(vm, fuente, tmp_dir, corridas):
    """Compila el ejemplo con el medidor delante y devuelve el minimo.

    Devuelve None si no compila a nativo o si no llega a imprimir la marca.
    Ninguna de las dos cosas es un fallo de esto -- hay ejemplos que piden
    runtime, y otros que terminan por una via que no pasa por el epilogo de
    `main` --, pero tampoco se pueden dar por medidos: se cuentan aparte.
    """
    nombre = os.path.splitext(os.path.basename(fuente))[0]
    # El fichero combinado se escribe JUNTO al original, no en el temporal:
    # un ejemplo puede importar por ruta relativa, y moverlo de sitio romperia
    # esos imports -- se mediria "no compila" cuando el ejemplo esta bien.
    juntos = os.path.join(os.path.dirname(fuente), "__medido_" + nombre + ".vx")
    binario = os.path.join(tmp_dir, nombre + ".exe")
    try:
        with open(MEDIDOR, "r", encoding="utf-8") as fh:
            cabeza = fh.read()
        with open(fuente, "r", encoding="utf-8") as fh:
            cuerpo = fh.read()
        with open(juntos, "w", encoding="utf-8") as fh:
            fh.write(cabeza + "\n" + cuerpo)
    except OSError:
        return None

    try:
        r = subprocess.run(
            [vm, "-m", "aot", "--vesta", juntos, "--format", "pe", "--emit",
             "exe", "-o", binario],
            capture_output=True, text=True, timeout=300)
    except (subprocess.TimeoutExpired, OSError):
        return None
    ok = (r.returncode == 0 and os.path.exists(binario))
    try:
        os.remove(juntos)
    except OSError:
        pass
    if not ok:
        return None

    mejor = None
    for _ in range(corridas):
        try:
            e = subprocess.run([binario], capture_output=True, text=True,
                               timeout=60)
        except (subprocess.TimeoutExpired, OSError):
            continue
        m = MARCA.search(e.stdout or "")
        if not m:
            continue
        v = int(m.group(1))
        if v > 0 and (mejor is None or v < mejor):
            mejor = v
    if mejor is None:
        return None
    return {"bench": nombre, "vx_ciclos_main": mejor}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("build", help="directorio del build (con vm/vm.exe)")
    ap.add_argument("-o", "--salida", default="runtime_cycles.json")
    ap.add_argument("-k", "--filtro", default="")
    ap.add_argument("-j", "--trabajos", type=int, default=4)
    ap.add_argument("--corridas", type=int, default=40,
                    help="corridas por ejemplo; con 40 el minimo repite dentro "
                         "del uno por ciento")
    args = ap.parse_args()

    vm = os.path.join(RAIZ, args.build, "vm.exe")
    if not os.path.exists(vm):
        vm = os.path.join(RAIZ, args.build, "vm")
    if not os.path.exists(vm):
        print("no encuentro el binario en " + args.build, file=sys.stderr)
        return 2

    fuentes = sorted(
        os.path.join(EJEMPLOS, f) for f in os.listdir(EJEMPLOS)
        if f.endswith(".vx") and (not args.filtro or args.filtro in f))
    if not fuentes:
        print("ningun ejemplo casa con el filtro", file=sys.stderr)
        return 2

    tmp_dir = os.path.join(RAIZ, ".runtime_cycles_tmp")
    os.makedirs(tmp_dir, exist_ok=True)

    filas = []
    with concurrent.futures.ThreadPoolExecutor(args.trabajos) as pool:
        for fila in pool.map(
                lambda f: _medir(vm, f, tmp_dir, args.corridas), fuentes):
            if fila:
                filas.append(fila)

    filas.sort(key=lambda f: f["bench"])
    with open(args.salida, "w", encoding="utf-8") as fh:
        json.dump({"results": filas}, fh, indent=1)

    print("%d medidos, %d sin medida (no compilan a nativo, o no llegan a "
          "salir de main) -> %s"
          % (len(filas), len(fuentes) - len(filas), args.salida))
    return 0


if __name__ == "__main__":
    sys.exit(main())
