#!/usr/bin/env python3
"""Ejecuta el banco entero en el INTERPRETE bajo una sola recogida de VTune.

Que responde
------------
Cuanto cuesta de verdad el DESPACHO del interprete, y en particular sus saltos
indirectos.  Es la pregunta que una cuenta estatica de instrucciones no puede
contestar: un salto indirecto por tabla constante con un indice de dos bits lo
predice bien casi cualquier CPU, asi que su coste real no se deduce de que
exista, hay que medirlo.

Por que el BANCO entero y no un programa
----------------------------------------
Un programa mide un programa.  `104_hot_loop_bench` es un bucle de enteros de
diez millones de vueltas: ejercita `adds` y `cmpjmp` y practicamente nada mas,
asi que su perfil dice como se despachan DOS familias, no como se despacha el
interprete.  El banco tiene familias muy distintas -- reserva de memoria,
recorrido de arrays, operaciones de bits, llamada virtual, coma flotante,
tablas hash, ramas impredecibles --, y solo con todas juntas el reparto del
tiempo significa algo.

Y una sola recogida, no una por programa: finalizar un resultado de VTune cuesta
mucho mas que ejecutar un banco.  VTune sigue a los procesos hijo, asi que
perfilando este guion se perfila el barrido entero.

Se ejecuta EN SERIE a proposito.  En paralelo los programas se pisan la CPU y el
perfil deja de decir cuanto cuesta cada cosa para decir cuanto se espero por un
nucleo libre.

Modo INTERPRETE a proposito
---------------------------
Con `-m vm`.  Sin el, `--run` entra al JIT y lo que se mide es el codigo
compilado, que no tiene el despacho que se quiere medir.

Uso:
    # 1) compilar el banco (una vez)
    python tools/profile_interp.py cmake-build-profile/vm.exe --solo-compilar

    # 2) perfilar la EJECUCION
    vtune -collect uarch-exploration -r F:/vxtmp/vt-interp -- ^
        python tools/profile_interp.py cmake-build-profile/vm.exe

El binario tiene que ser el de `Profile`: Release enlaza con `--strip-all` y sin
simbolos el perfil atribuye el tiempo a direcciones, que no dicen nada.
"""
from __future__ import annotations

import argparse
import csv
import subprocess
import sys
import time
from pathlib import Path

# La raiz del repositorio, deducida de DONDE ESTA este fichero y no del
# directorio desde el que se lance.  Importa mas de lo que parece: perfilar
# eventos de hardware exige una consola de administrador, y esa arranca en otro
# sitio -- las rutas relativas se rompieron ahi, el guion murio al instante y
# VTune recogio 0,115 s de nada dando un informe con aspecto de bueno.
RAIZ = Path(__file__).resolve().parent.parent


def bancos(raiz: Path) -> list:
    """Los programas del banco, cada uno con su fuente principal.

    Hay dos formas en el arbol y las dos cuentan: un `.vx` suelto, y una
    carpeta con su `main.vx` -- los de varios ficheros --.  Coger solo la
    primera dejaria fuera justo los que ejercitan modulos y namespaces.
    """
    fuentes = []
    for p in sorted(raiz.glob("*.vx")):
        fuentes.append(p)
    for d in sorted(x for x in raiz.iterdir() if x.is_dir()):
        main = d / "main.vx"
        if main.exists():
            fuentes.append(main)
    return fuentes


def compilar(vm: Path, fuente: Path, salida: Path, timeout: float) -> int:
    proc = subprocess.Popen(
        [str(vm), "--vesta", str(fuente), "-o", str(salida)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        return proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        return -1


def ejecutar(vm: Path, velb: Path, timeout: float) -> tuple:
    """Ejecuta @p velb en el INTERPRETE y devuelve (pid, codigo, ms).

    Se usa Popen y no run() porque hace falta el PID: al pedirle a VTune el
    informe agrupado por proceso, cada fila es un PID, y sin saber que PID
    ejecuto que banco esa fila no dice nada.
    """
    inicio = time.perf_counter()
    proc = subprocess.Popen(
        [str(vm), "--run", str(velb), "-m", "vm"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pid = proc.pid
    try:
        code = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        code = -1
    return (pid, code, (time.perf_counter() - inicio) * 1000.0)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("vm", type=Path, help="binario a perfilar (usar Profile)")
    # Y el binario tambien: se resuelve contra la raiz si viene relativo.
    ap.add_argument("--bancos", type=Path,
                    default=RAIZ / "examples_codes_vx" / "benchmark",
                    help="carpeta del banco")
    ap.add_argument("--out-dir", type=Path, default=Path("F:/vxtmp/bench-velb"),
                    help="donde dejar los .velb compilados")
    ap.add_argument("--map", type=Path,
                    default=Path("F:/vxtmp/pid_map_interp.csv"),
                    help="CSV con pid,banco,codigo,ms")
    ap.add_argument("--timeout", type=float, default=120.0)
    ap.add_argument("--solo-compilar", action="store_true",
                    help="compilar y salir, para no perfilar la compilacion")
    ap.add_argument("--repetir", type=int, default=1,
                    help="pasadas sobre el banco; mas muestras, menos ruido")
    args = ap.parse_args()

    if not args.vm.is_absolute():
        args.vm = (RAIZ / args.vm).resolve()
    if not args.vm.exists():
        print("no existe el binario: %s" % args.vm, file=sys.stderr)
        return 2

    fuentes = bancos(args.bancos)
    if not fuentes:
        print("sin bancos en %s" % args.bancos, file=sys.stderr)
        return 2
    args.out_dir.mkdir(parents=True, exist_ok=True)

    if args.solo_compilar:
        malos = 0
        for f in fuentes:
            salida = args.out_dir / f.parent.name if f.name == "main.vx" \
                else args.out_dir / f.stem
            code = compilar(args.vm, f, salida, args.timeout)
            if code != 0:
                malos += 1
                print("  no compila: %s (codigo %d)" % (f, code))
        print("%d bancos, %d sin compilar" % (len(fuentes), malos))
        return 0

    filas = []
    inicio = time.perf_counter()
    for _ in range(args.repetir):
        for f in fuentes:
            velb = (args.out_dir / f.parent.name if f.name == "main.vx"
                    else args.out_dir / f.stem).with_suffix(".velb")
            if not velb.exists():
                continue
            pid, code, ms = ejecutar(args.vm, velb, args.timeout)
            filas.append({"pid": pid, "banco": velb.stem, "code": code,
                          "ms": round(ms, 1)})
    total = time.perf_counter() - inicio

    with args.map.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["pid", "banco", "code", "ms"])
        w.writeheader()
        w.writerows(filas)
    malos = len([r for r in filas if r["code"] != 0])
    print("%d ejecuciones en %.1f s, %d con codigo != 0" %
          (len(filas), total, malos))
    print("mapa de PIDs en %s" % args.map)
    return 0


if __name__ == "__main__":
    sys.exit(main())
