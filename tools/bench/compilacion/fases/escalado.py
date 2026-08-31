#!/usr/bin/env python3
"""Como crece el coste con el tamano del programa y con el numero de modulos."""
from __future__ import annotations

from ..comun import C, color_de
from ..contexto import Ctx
from ..generadores import GENERADORES, funciones_para_lineas
from ..multi import escribir_multi
from ..informe import cabecera_fase
from ..medida import compila_de_verdad, medir_caliente, medir_frio
from ..ordenes import SECUENCIAL, entorno_cache, orden_compilar
from ..topologia import orden_multi


def fase(ctx: Ctx) -> None:
    """Como crece el coste con el tamano del programa y con el numero de modulos."""
    args, vm = ctx.args, ctx.vm
    langs, tamanos, jobs = ctx.langs, ctx.tamanos, ctx.jobs
    base_tmp, dir_cache = ctx.base_tmp, ctx.dir_cache
    entorno_base = ctx.entorno_base
    suelo, resultados = ctx.suelo, ctx.resultados
    # --- 2bis. ESCALADO.  Dos curvas, porque preguntan cosas distintas:
    #   por tamano  -- ¿el coste crece con el programa de forma lineal, o hay
    #                  algo superlineal escondido?  Con un solo punto esto es
    #                  invisible, y una superlinealidad se descubre tarde y cara.
    #   por modulos -- a tamano TOTAL constante, repartirlo en mas ficheros mide
    #                  el coste FIJO por modulo: lo que paga un proyecto muy
    #                  dividido solo por estarlo.
    cabecera_fase("escalado", "Escalado",
                  "El coste contra el tamano del programa, y contra el "
                  "numero de modulos a tamano total constante.  Un solo "
                  "punto no distingue lineal de superlineal; esta fase "
                  "va imprimiendo cada fila segun la mide.")
    print()
    print(f"{C.BOLD}Escalado por tamano (un fichero){C.RESET}")
    print(f"{C.DIM}  Si el coste por linea sube con el tamano, hay algo "
          f"superlineal.{C.RESET}")
    cab = (f"{'lenguaje':<12}{'lineas':>9}{'tiempo':>10}{'por kloc':>10}"
           f"{'vs el anterior':>16}")
    print(f"{C.BOLD}{cab}{C.RESET}")
    print(f"{C.DIM}  {'':<10}{'(codigo)':>9}{'(ms)':>10}{'(ms)':>10}"
          f"{'(veces)':>16}{C.RESET}")
    print("-" * len(cab))
    # LINEAS, no funciones.  Sale de `--lineas` en vez de estar fijo aqui: si
    # no, `--grande` anadia el cuarto tamano a las demas fases y esta se
    # quedaba con tres, y las curvas dejaban de apoyarse en la misma base.
    escala = [int(x) for x in args.lineas.split(",") if x.strip()] or \
        [1500, 6000, 24000]
    for ln in langs:
        nombre, gen = GENERADORES[ln]
        previo = None
        for objetivo in escala:
            d = base_tmp / ("esc_%s_%d" % (ln, objetivo))
            d.mkdir(parents=True, exist_ok=True)
            # En LINEAS, no en funciones: si no, cada lenguaje compila una
            # cantidad distinta de codigo y la curva de uno no se puede poner
            # al lado de la del otro.
            texto = gen(funciones_para_lineas(gen, objetivo))
            (d / nombre).write_text(texto, encoding="utf-8")
            lineas = texto.count("\n")
            cmd = orden_compilar(ln, d / nombre, d / "out", vm)
            if not cmd:
                break  # sin camino de compilacion: este lenguaje no participa
            env = entorno_cache(ln, dir_cache, entorno_base)
            ok, motivo = compila_de_verdad(ln, cmd, env, d, d / "out",
                                           args.timeout)
            if not ok:
                print(f"  {C.RED}[no compila]{C.RESET} {ln} {lineas}: {motivo}")
                break
            s = medir_caliente(cmd, env, d, max(3, args.repes // 2),
                               args.timeout)
            if not s:
                break
            piso = (suelo.get(ln) or {}).get("p50") or 0.0
            neto = max(0.001, s["p50"] - piso)
            por_kloc = 1000.0 * neto / max(1, lineas)
            rel = ("%6.2fx" % (neto / previo)) if previo else "     -"
            print(f"  {color_de(ln)}{ln:<10}{C.RESET}{lineas:>9}"
                  f"{s['p50']:>10.0f}{por_kloc:>10.1f}{rel:>16}")
            resultados["casos"].append({
                "lang": ln, "escalado": "tamano", "lineas": lineas,
                "stats": s, "neto": neto})
            previo = neto
    print("-" * len(cab))

    print()
    print(f"{C.BOLD}Escalado por numero de modulos (mismo total){C.RESET}")
    print(f"{C.DIM}  Mismo codigo repartido en mas ficheros: lo que sube es "
          f"el coste FIJO por modulo.{C.RESET}")
    cab2 = f"{'lenguaje':<12}{'modulos':>9}{'ms':>10}{'ms/modulo':>12}"
    print(f"{C.BOLD}{cab2}{C.RESET}")
    print("-" * len(cab2))
    for ln in langs:
        for k in (1, 8, 32, 128):
            d = base_tmp / ("escm_%s_%d" % (ln, k))
            ficheros = escribir_multi(ln, 1024, k, d)
            if not ficheros:
                continue
            # Eje SECUENCIAL, siempre.  Esta fase mide el coste FIJO por
            # modulo, y con cada herramienta usando un numero distinto de
            # hilos ese coste queda dividido por un factor distinto en cada
            # fila: dejaria de ser comparable, que es lo unico que la tabla
            # hace.  Los dos ejes se publican en la fase `proyecto`.
            cmd = orden_multi(ln, ficheros, d / "out", vm, SECUENCIAL,
                              ctx.nucleos)
            if not cmd:
                continue  # sin camino de compilacion: no participa
            env = entorno_cache(ln, dir_cache, entorno_base, SECUENCIAL)
            ok, motivo = compila_de_verdad(ln, cmd, env, d, d / "out",
                                           args.timeout)
            if not ok:
                print(f"  {C.RED}[no compila]{C.RESET} {ln} k={k}: {motivo}")
                continue
            s = medir_frio(cmd, env, d, max(3, args.repes // 2),
                           args.timeout, ln, dir_cache)
            if not s:
                continue
            print(f"  {ln:<10}{len(ficheros):>9}{s['p50']:>10.0f}"
                  f"{s['p50'] / len(ficheros):>12.1f}")
            resultados["casos"].append({
                "lang": ln, "escalado": "modulos", "paralelismo": SECUENCIAL,
                "ficheros": len(ficheros), "stats": s})
    print("-" * len(cab2))

