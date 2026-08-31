#!/usr/bin/env python3
"""La misma cantidad de codigo con otra forma de dependencias."""
from __future__ import annotations

from ..comun import C, Spinner, _stats_summary, color_de, una_medida
from ..contexto import Ctx
from ..informe import barra, cabecera_fase, imprimir_tabla
from ..medida import verificar_en_paralelo
from ..ordenes import SECUENCIAL, entorno_cache
from ..topologia import (contar_rehechos, escribir_topologia,
                        huella_artefactos, mutar, orden_multi)


def fase(ctx: Ctx) -> None:
    """La misma cantidad de codigo con otra forma de dependencias."""
    args, vm = ctx.args, ctx.vm
    langs, tamanos, jobs = ctx.langs, ctx.tamanos, ctx.jobs
    base_tmp, dir_cache = ctx.base_tmp, ctx.dir_cache
    entorno_base = ctx.entorno_base
    suelo, resultados = ctx.suelo, ctx.resultados
    # --- 2c. TOPOLOGIA: la misma cantidad de codigo con otra forma de
    # dependencias.  El cambio se hace SIEMPRE en el modulo del que cuelgan los
    # demas (m0), que es el unico sitio desde donde se puede observar si la
    # invalidacion se propaga o se corta.
    cabecera_fase("dependencias", "La forma de las dependencias",
                  "La misma cantidad de codigo con otra FORMA: ancha, en "
                  "cadena y en diamante.  El cambio se hace siempre en el "
                  "modulo del que cuelgan los demas, que es el unico sitio "
                  "desde donde se ve si la invalidacion se propaga o se "
                  "corta.")
    filas_topo: list[tuple] = []
    filas_cuenta: list[tuple] = []
    n_topo = tamanos[-1]
    prep_topo = []
    for forma in ("ancha", "cadena", "diamante"):
        for ln in langs:
            d = base_tmp / ("topo_%s_%s" % (ln, forma))
            ficheros = escribir_topologia(ln, n_topo, args.ficheros, forma, d)
            if not ficheros:
                continue
            # Eje SECUENCIAL: aqui se compara la FORMA del grafo de
            # dependencias, y el paralelismo depende de esa forma -- un
            # grafo ancho paraleliza y uno en cadena no --, asi que
            # dejarlo suelto mezclaria las dos cosas en un solo numero.
            cmd = orden_multi(ln, ficheros, d / "out", vm, SECUENCIAL,
                              ctx.nucleos)
            if not cmd:
                continue
            env = entorno_cache(ln, dir_cache, entorno_base, SECUENCIAL)
            prep_topo.append(((forma, ln), ln, cmd, env, d, d / "out",
                              forma, ficheros))
    with Spinner("verificando las topologias", color=C.DIM):
        vered_topo = verificar_en_paralelo(
            [(c[0], c[1], c[2], c[3], c[4], c[5]) for c in prep_topo],
            jobs, args.timeout)

    with Spinner("", color=C.DIM) as spin:
      for hechos, (clave, ln, cmd, env, d, salida, forma,
                   ficheros) in enumerate(prep_topo):
            spin.etiqueta(f"topologia  {barra(hechos, len(prep_topo))}  "
                          f"{C.BOLD}{forma} / {ln}{C.RESET}")
            ok, motivo = vered_topo.get(clave, (False, "no verificado"))
            if not ok:
                print(f"  {C.RED}[no compila]{C.RESET} topologia {forma}/{ln}: "
                      f"{motivo}")
                continue
            una_medida(cmd, env, args.timeout, d)   # dejarlo construido
            raiz_mod = [f for f in ficheros
                        if f.startswith("m0.") or f.startswith("M0.")]
            for clase, titulo in (("cuerpo", "cuerpo de m0"),
                                  ("interfaz", "interfaz de m0")):
                serie = []
                cuenta = None
                for v in range(args.repes):
                    for f in raiz_mod:
                        mutar(d / f, ln, clase, v)
                    # La primera vuelta se observa ademas por artefactos: que
                    # cambie o no un `.vxi` es un HECHO, mientras que el tiempo
                    # lo ensucian la cache del sistema y la maquina entera.
                    antes = huella_artefactos(d, ln) if v == 0 else {}
                    t = una_medida(cmd, env, args.timeout, d)
                    if v == 0 and antes:
                        cuenta = contar_rehechos(antes,
                                                 huella_artefactos(d, ln))
                    if t >= 0:
                        serie.append(t)
                s_t = _stats_summary(serie) if serie else {}
                filas_topo.append((ln, "%-9s %s  %s" % (forma, ln, titulo), s_t))
                if cuenta is not None:
                    filas_cuenta.append((forma, ln, titulo, cuenta))
                resultados["casos"].append({
                    "lang": ln, "fase": "2c", "topologia": forma, "cambio": clase,
                    "ficheros": len(ficheros), "stats": s_t,
                    "artefactos": ({"rehechos": cuenta[0],
                                    "reutilizados": cuenta[1],
                                    "nuevos": cuenta[2]} if cuenta else None),
                })
    if filas_topo:
        imprimir_tabla(
            "Topologia: donde cuelga cada modulo, y si el cambio se propaga (ms)",
            filas_topo, suelo,
            "El cambio va SIEMPRE en m0, del que cuelgan los demas.  Cambiar su "
            "CUERPO no cambia lo que ofrece, asi que sus dependientes no "
            "deberian rehacerse; cambiar su INTERFAZ obliga a revalidarlos.  La "
            "diferencia entre esas dos filas es lo que la interfaz esta "
            "cortando: si son iguales, no corta nada.")
    if filas_cuenta:
        # La medida FUERTE: no cuanto tardo, sino QUE rehizo.
        print()
        print(f"{C.BOLD}Que artefactos se rehacen, por tipo de cambio{C.RESET}")
        print(f"{C.DIM}  El tiempo lo ensucian la cache del sistema y la "
              f"maquina entera; que un artefacto cambie o no es un hecho.  "
              f"Solo salen las herramientas que dejan artefactos observables: "
              f"una sola invocacion de gcc no deja ninguno, y la cache de Go es "
              f"opaca.{C.RESET}")
        cab3 = (f"{'topologia / cambio':<40}{'rehechos':>10}"
                f"{'reutilizados':>14}{'nuevos':>9}")
        print(f"{C.BOLD}{cab3}{C.RESET}")
        print(f"{C.DIM}  {'':<38}{'(ficheros)':>10}{'(ficheros)':>14}"
              f"{'(ficheros)':>9}{C.RESET}")
        print("-" * len(cab3))
        for forma, ln, titulo, (re_, reu, nue) in filas_cuenta:
            col = C.GREEN if reu > re_ else C.YELLOW
            etq = forma + "  " + ln + "  " + titulo
            print(f"  {color_de(ln)}{etq:<38}{C.RESET}"
                  f"{col}{re_:>10}{C.RESET}{reu:>14}{nue:>9}")
        print("-" * len(cab3))

