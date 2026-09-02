#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# VestaVM - Maquina Virtual Distribuida
# Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
# Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
#
"""A/B de DOS binarios sobre el mismo banco, intercalado y en los dos ordenes.

Por que no basta con cronometrar uno y luego el otro
----------------------------------------------------
El banco tiene +-7% de ruido de por si, asi que dos corridas seguidas no
distinguen el cambio del ruido.  Y hay ademas sesgo de POSICION: el que corre
primero sale peor -- caches frias, el planificador del sistema todavia
colocando --.  Medir A y luego B le regala a B la diferencia entera.

La forma barata de cancelarlo es ALTERNAR QUIEN EMPIEZA entre bancos: el par
va A,B en los pares y B,A en los impares.  Cada binario corre primero en la
mitad de los bancos, asi que el sesgo se cancela igual que repitiendo cada
programa cuatro veces -- y cuesta DOS pases en vez de cuatro.  Con 68 bancos de
dos segundos y medio, eso son seis minutos por ronda en vez de once.

Lo que NO se hace es paralelizar.  Aqui se mide tiempo, y dos programas
peleandose por un nucleo convierten la medida en ruido: es justo la magnitud que
se busca.

Con varias rondas ademas se ve si el signo se mantiene; si cambia entre rondas,
la diferencia es ruido y no hay resultado.

`ab_allocator.py` compara DOS CAMINOS del mismo binario con una puerta; esto
compara DOS BINARIOS, que es lo que hace falta cuando el cambio no se puede
poner detras de una variable -- mover una funcion a la cabecera, por ejemplo --.

Se ejecuta en el INTERPRETE (`-m vm`): con el JIT se mide el codigo compilado,
que no es donde estan los cambios que esto suele comparar.

Uso:
    python tools/ab_binarios.py <A.exe> <B.exe> [--rondas N] [--bancos DIR]
"""
from __future__ import annotations

import argparse
import statistics
import subprocess
import sys
import time
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent


def corre(vm: Path, velb: Path, timeout: float) -> float:
    """Ejecuta @p velb y devuelve los segundos que tardo."""
    inicio = time.perf_counter()
    proc = subprocess.Popen([str(vm), "--run", str(velb), "-m", "vm"],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    return time.perf_counter() - inicio


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("a", type=Path, help="binario A (la linea base)")
    ap.add_argument("b", type=Path, help="binario B (el cambio)")
    ap.add_argument("--bancos", type=Path,
                    default=Path("F:/vxtmp/bench-velb"),
                    help="carpeta con los .velb ya compilados")
    ap.add_argument("--rondas", type=int, default=3)
    ap.add_argument("--timeout", type=float, default=120.0)
    args = ap.parse_args()

    velbs = sorted(args.bancos.glob("*.velb"))
    if not velbs:
        print("sin .velb en %s -- compilalos antes con profile_interp.py "
              "--solo-compilar" % args.bancos, file=sys.stderr)
        return 2
    for x in (args.a, args.b):
        if not x.exists():
            print("no existe: %s" % x, file=sys.stderr)
            return 2

    print("%d bancos, %d rondas, alternando quien empieza\n" %
          (len(velbs), args.rondas))
    por_ronda = []
    for r in range(args.rondas):
        ta = tb = 0.0
        for i, velb in enumerate(velbs):
            # Quien empieza alterna con el banco, y ademas con la ronda: asi
            # ningun banco le toca siempre al mismo, que seria otro sesgo.
            if (i + r) % 2 == 0:
                ta += corre(args.a, velb, args.timeout)
                tb += corre(args.b, velb, args.timeout)
            else:
                tb += corre(args.b, velb, args.timeout)
                ta += corre(args.a, velb, args.timeout)
        delta = 100.0 * (tb - ta) / ta
        por_ronda.append(delta)
        print("  ronda %d:  A %7.2f s   B %7.2f s   %+6.2f%%" %
              (r + 1, ta, tb, delta))

    media = statistics.fmean(por_ronda)
    print("\nmedia de las rondas: %+.2f%%  (negativo = B gana)" % media)
    if len(por_ronda) > 1:
        desv = statistics.pstdev(por_ronda)
        print("desviacion         : %.2f puntos" % desv)
        # El veredicto lo da la CONSISTENCIA, no la media: una media pequena
        # con el signo cambiando entre rondas es ruido, no una mejora chica.
        signos = {d > 0 for d in por_ronda}
        if len(signos) > 1:
            print("\nEl signo CAMBIA entre rondas: la diferencia es ruido, no "
                  "un resultado.")
        elif abs(media) < desv:
            print("\nLa media no llega ni a su propia desviacion: no hay "
                  "resultado.")
        else:
            print("\nEl signo se mantiene en las %d rondas." % len(por_ronda))
    return 0


if __name__ == "__main__":
    sys.exit(main())
