#!/usr/bin/env python3
"""Cada familia de cero, sin cambios, y tras tocar un cuerpo o una interfaz."""
from __future__ import annotations

from ..comun import C, Spinner, _stats_summary, una_medida
from ..contexto import Ctx
from ..familias import familia_modular_vx
from ..informe import barra, cabecera_fase, imprimir_tabla
from ..medida import compila_de_verdad, medir_frio
from ..ordenes import SECUENCIAL, entorno_cache
from ..topologia import mutar, orden_multi


def fase(ctx: Ctx) -> None:
    """Cada familia de cero, sin cambios, y tras tocar un cuerpo o una interfaz."""
    args, vm = ctx.args, ctx.vm
    langs, tamanos, jobs = ctx.langs, ctx.tamanos, ctx.jobs
    base_tmp, dir_cache = ctx.base_tmp, ctx.dir_cache
    entorno_base = ctx.entorno_base
    suelo, resultados = ctx.suelo, ctx.resultados
    # --- 2e. Familia x REGIMEN.  Un numero por familia dice cuanto cuesta;
    # el desglose dice DONDE se va y que parte se puede evitar tras un cambio.
    cabecera_fase("familias-regimen", "Cada familia, por regimen",
                  "La misma familia construida de cero, sin cambios, tras "
                  "tocar un cuerpo y tras tocar una interfaz.  La distancia "
                  "entre cuerpo e interfaz es lo que la frontera de modulo "
                  "esta cortando en esa familia.")
    filas_fr: list[tuple] = []
    _familias_fr = ("genericos", "comptime", "anidamiento", "tipos")
    _spin_fr = Spinner("", color=C.DIM)
    _spin_fr.__enter__()
    for _i_fr, familia in enumerate(_familias_fr):
        _spin_fr.etiqueta(f"familia x regimen  "
                          f"{barra(_i_fr, len(_familias_fr))}  "
                          f"{C.BOLD}{familia}{C.RESET}")
        cuenta = {"genericos": 150, "comptime": 60,
                  "anidamiento": 500, "tipos": 400}[familia]
        for ln in ("vesta", "vesta_aot"):
            if ln not in langs:
                continue
            d = base_tmp / ("fr_%s_%s" % (familia, ln))
            ficheros = familia_modular_vx(familia, cuenta, d)
            if not ficheros:
                continue
            # Eje SECUENCIAL: esta fase compara FAMILIAS de codigo entre si,
            # y el paralelismo anadiria una variable que no es la que mide.
            cmd = orden_multi(ln, ficheros, d / "out", vm, SECUENCIAL,
                              ctx.nucleos)
            if not cmd:
                continue
            env = entorno_cache(ln, dir_cache, entorno_base, SECUENCIAL)
            ok, motivo = compila_de_verdad(ln, cmd, env, d, d / "out",
                                           args.timeout)
            if not ok:
                print(f"  {C.RED}[no compila]{C.RESET} {familia}/{ln}: {motivo}")
                continue
            s_cero = medir_frio(cmd, env, d, args.repes, args.timeout, ln,
                                dir_cache)
            filas_fr.append((ln, "%-12s %-10s de cero" % (familia, ln), s_cero))
            una_medida(cmd, env, args.timeout, d)
            for clase, nombre_caso in ((None, "sin cambios"),
                                       ("cuerpo", "cambia el cuerpo"),
                                       ("interfaz", "cambia la interfaz")):
                serie = []
                fallo_mutacion = False
                for v in range(args.repes):
                    if clase is not None and not mutar(d / "m0.vx", ln, clase, v):
                        # Si el cambio no se puede aplicar, la fila saldria
                        # IDeNTICA a `sin cambios` y se leeria como que el
                        # compilador se lo salto.  Paso de verdad: la mutacion
                        # "cuerpo" buscaba un patron que no existia en estas
                        # familias y las tres filas eran la misma medida.
                        fallo_mutacion = True
                        break
                    t = una_medida(cmd, env, args.timeout, d)
                    if t >= 0:
                        serie.append(t)
                if fallo_mutacion:
                    print(f"  {C.RED}[sin medir]{C.RESET} {familia}/{ln} "
                          f"{nombre_caso}: no se pudo aplicar el cambio")
                    continue
                s_r = _stats_summary(serie) if serie else {}
                filas_fr.append((ln, "%-12s %-10s %s"
                                 % (familia, ln, nombre_caso), s_r))
                resultados["casos"].append({
                    "lang": ln, "fase": "2e", "familia": familia, "regimen": nombre_caso,
                    "cuenta": cuenta, "stats": s_r})
    _spin_fr.__exit__()
    if filas_fr:
        imprimir_tabla(
            "Familia x regimen: donde se va el tiempo y que se puede evitar (ms)",
            filas_fr, suelo,
            "Un numero por familia dice cuanto cuesta compilarla; el desglose "
            "dice donde se va.  `sin cambios` es coste de reutilizar, no "
            "velocidad.  La distancia entre cuerpo e interfaz es lo que la "
            "frontera esta cortando en ESA familia -- y no tiene por que ser "
            "igual en todas.")

