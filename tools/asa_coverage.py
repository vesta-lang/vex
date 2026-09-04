#!/usr/bin/env python3
"""asa_coverage.py -- cuanto SABE el ASA del corpus, en un numero comparable.

El problema que resuelve: ningun test detecta que el ASA sepa MENOS que antes.
Los unitarios comprueban casos escritos a mano y la e2e compara la salida del
programa; un analisis que pasa de acotar 5.000 valores a acotar 3.000 no rompe
ninguno de los dos, porque un rango peor casi nunca cambia lo que el programa
imprime.  Solo se nota mucho despues, como codigo mas lento o como una
comprobacion que ya no se puede quitar.

Lo que se mide, por dominio del ASA:

    hechos          lo que el dominio SI pudo afirmar
    miradas         cuantas veces se le pregunto
    sin sacar nada  se miro y no habia nada que decir, o no se supo
    ni miradas      nadie llego a preguntar

Un retroceso se ve como `hechos` bajando o `sin sacar nada` subiendo.  La
cuenta es DETERMINISTA -- son hechos, no tiempos --, asi que dos ejecuciones
del mismo arbol dan lo mismo y la comparacion entre commits significa algo.

Uso:
  python tools/asa_coverage.py [vm_path] [--dir examples_codes_vx]
  python tools/asa_coverage.py --save antes.json
  python tools/asa_coverage.py --baseline antes.json      # y compara
"""
from __future__ import annotations
import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

# "  ranges          670 hechos de   2044 miradas (1374 sin sacar nada, 0 ni
#  miradas), 6591 us"
LINEA_DOMINIO = re.compile(
    r"^\s+(\w+)\s+(\d+)\s+hechos de\s+(\d+)\s+miradas"
    r"\s+\((\d+) sin sacar nada,\s+(\d+) ni miradas\)"
)
# "En total 20219 hechos: 10139 demostrados, 40 inferidos, 10040 sin certeza."
LINEA_TOTAL = re.compile(
    r"^En total (\d+) hechos: (\d+) demostrados, (\d+) inferidos, "
    r"(\d+) sin certeza"
)


def find_vm(explicit: str | None) -> Path:
    # Ruta ABSOLUTA siempre: en Windows una relativa da WinError 2.
    if explicit:
        p = Path(explicit)
        if not p.is_file():
            sys.exit(f"no existe: {p}")
        return p.resolve()
    raiz = Path(__file__).resolve().parent.parent
    for d in ("cmake-build-release", "build", "cmake-build-debug"):
        for nombre in ("vm.exe", "vm"):
            p = raiz / d / nombre
            if p.is_file():
                return p.resolve()
    sys.exit("no encuentro el binario vm; pasalo como primer argumento")


def medir_fichero(vm: Path, fuente: Path, timeout: int) -> dict | None:
    """Corre `vm --asa` sobre un fichero y extrae los contadores.

    Devuelve None si el fichero no compila: un fallo de compilacion no dice
    nada del ASA y contarlo como cero hechos falsearia el total hacia abajo.
    """
    try:
        r = subprocess.run(
            [str(vm), "--asa", str(fuente)],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return None
    if r.returncode != 0:
        return None
    salida = r.stdout + r.stderr
    dominios: dict[str, list[int]] = {}
    total = None
    for linea in salida.splitlines():
        m = LINEA_DOMINIO.match(linea)
        if m:
            dominios[m.group(1)] = [int(m.group(i)) for i in (2, 3, 4, 5)]
            continue
        m = LINEA_TOTAL.match(linea)
        if m:
            total = [int(m.group(i)) for i in (1, 2, 3, 4)]
    if total is None:
        return None
    return {"dominios": dominios, "total": total}


def acumular(destino: dict, parcial: dict) -> None:
    for nombre, v in parcial["dominios"].items():
        acc = destino["dominios"].setdefault(nombre, [0, 0, 0, 0])
        for i in range(4):
            acc[i] += v[i]
    for i in range(4):
        destino["total"][i] += parcial["total"][i]


def imprimir(res: dict) -> None:
    print(f"\n{res['ficheros']} ficheros medidos "
          f"({res['saltados']} no compilan, no cuentan)\n")
    ancho = max((len(n) for n in res["dominios"]), default=8)
    print(f"  {'dominio'.ljust(ancho)}  {'hechos':>9}  {'miradas':>9}  "
          f"{'sin nada':>9}  {'ni miradas':>10}  {'%':>6}")
    for nombre in sorted(res["dominios"],
                         key=lambda n: -res["dominios"][n][0]):
        h, m, s, n = res["dominios"][nombre]
        pct = (100.0 * h / m) if m else 0.0
        print(f"  {nombre.ljust(ancho)}  {h:>9}  {m:>9}  {s:>9}  {n:>10}  "
              f"{pct:>5.1f}%")
    t = res["total"]
    print(f"\n  TOTAL {t[0]} hechos: {t[1]} demostrados, {t[2]} inferidos, "
          f"{t[3]} sin certeza")


def comparar(nuevo: dict, viejo: dict) -> int:
    """Compara con una medida anterior.  Devuelve 1 si algo RETROCEDIO.

    Retroceder es acotar MENOS que antes.  Se marca aparte de "cambio", porque
    subir tambien cambia el numero y eso no es un problema que avisar.
    """
    print("\n--- contra la medida anterior "
          f"({viejo['ficheros']} ficheros, ahora {nuevo['ficheros']})")
    if viejo["ficheros"] != nuevo["ficheros"]:
        print("  OJO: no es el mismo conjunto de ficheros; los totales no son "
              "comparables directamente.")
    peor = False
    todos = set(nuevo["dominios"]) | set(viejo["dominios"])
    for nombre in sorted(todos):
        h_n = nuevo["dominios"].get(nombre, [0, 0, 0, 0])[0]
        h_v = viejo["dominios"].get(nombre, [0, 0, 0, 0])[0]
        if h_n == h_v:
            continue
        d = h_n - h_v
        marca = "  " if d > 0 else "<-"
        if d < 0:
            peor = True
        print(f"  {marca} {nombre:<16} {h_v:>8} -> {h_n:>8}  ({d:+d})")
    d = nuevo["total"][0] - viejo["total"][0]
    print(f"\n  TOTAL {viejo['total'][0]} -> {nuevo['total'][0]} ({d:+d})")
    if peor:
        print("\n  RETROCESO: algun dominio afirma MENOS que antes.")
        return 1
    print("\n  Ningun dominio afirma menos que antes.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("vm", nargs="?", default=None)
    ap.add_argument("--dir", default="examples_codes_vx")
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--limit", type=int, default=0,
                    help="medir solo los N primeros (para iterar rapido)")
    ap.add_argument("--save", default=None, help="guarda la medida en JSON")
    ap.add_argument("--baseline", default=None,
                    help="compara contra una medida guardada")
    args = ap.parse_args()

    vm = find_vm(args.vm)
    raiz = Path(__file__).resolve().parent.parent
    d = Path(args.dir)
    if not d.is_absolute():
        d = raiz / d
    # Solo los .vx sueltos: los de subcarpeta no compilan por separado, solo a
    # traves de su main.vx, y medirlos daria fallos que no son del ASA.
    fuentes = sorted(d.glob("*.vx"))
    if args.limit:
        fuentes = fuentes[: args.limit]
    if not fuentes:
        sys.exit(f"sin ficheros .vx en {d}")

    res = {"dominios": {}, "total": [0, 0, 0, 0], "ficheros": 0,
           "saltados": 0}
    for i, f in enumerate(fuentes, 1):
        print(f"\r[{i}/{len(fuentes)}] {f.name[:50]:<50}", end="",
              file=sys.stderr, flush=True)
        parcial = medir_fichero(vm, f, args.timeout)
        if parcial is None:
            res["saltados"] += 1
            continue
        acumular(res, parcial)
        res["ficheros"] += 1
    print("\r" + " " * 64 + "\r", end="", file=sys.stderr)

    imprimir(res)
    if args.save:
        Path(args.save).write_text(json.dumps(res, indent=1), encoding="utf-8")
        print(f"\nguardado en {args.save}")
    if args.baseline:
        viejo = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
        return comparar(res, viejo)
    return 0


if __name__ == "__main__":
    sys.exit(main())
