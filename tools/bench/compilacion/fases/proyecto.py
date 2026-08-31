#!/usr/bin/env python3
"""El mismo codigo repartido en modulos, y que cuesta rehacerlo segun que cambie."""
from __future__ import annotations

from ..comun import C, Spinner, _stats_summary, una_medida
from ..contexto import Ctx
from ..multi import escribir_multi
from ..informe import barra, cabecera_fase, imprimir_tabla
from ..medida import medir_frio, verificar_en_paralelo
from ..ordenes import entorno_cache
from ..topologia import mutar, orden_multi


def fase(ctx: Ctx) -> None:
    """El mismo codigo repartido en modulos, y que cuesta rehacerlo segun que cambie."""
    args, vm = ctx.args, ctx.vm
    langs, tamanos, jobs = ctx.langs, ctx.tamanos, ctx.jobs
    base_tmp, dir_cache = ctx.base_tmp, ctx.dir_cache
    entorno_base = ctx.entorno_base
    suelo, resultados = ctx.suelo, ctx.resultados
    # --- 2b. El MISMO programa repartido en varios ficheros.
    # Se compara contra la fila de un solo fichero del mismo tamano: mismo
    # trabajo, otra forma de presentarselo al compilador.
    cabecera_fase("proyecto", "Un proyecto de varios modulos",
                  "El mismo codigo repartido en varios modulos, y que cuesta "
                  "reconstruirlo segun QUE cambie: nada, un comentario, un "
                  "cuerpo, una interfaz.  La escalera entre esas filas es la "
                  "granularidad de invalidacion del compilador.")
    filas_multi: list[tuple] = []
    filas_inc: list[tuple] = []
    prep_multi = []
    for eje in ctx.ejes:
      for n in tamanos:
        for ln in langs:
            # Un directorio por EJE: los dos escriben objetos y caches en el
            # sitio del caso, y compartirlo dejaria al segundo eje midiendo
            # sobre lo que construyo el primero.
            d = base_tmp / ("multi_%s_%s_%d" % (eje, ln, n))
            ficheros = escribir_multi(ln, n, args.ficheros, d)
            if not ficheros:
                continue
            cmd = orden_multi(ln, ficheros, d / "out", vm, eje, ctx.nucleos)
            if not cmd:
                continue
            env = entorno_cache(ln, dir_cache, entorno_base, eje)
            # El TAMANO va en la etiqueta.  Sin el, dos tamanos distintos daban
            # filas identicas -- `c  21 ficheros` dos veces -- y lo que parecia
            # una tabla eran dos pegadas.  Peor que feo: la comparacion contra
            # la base empareja por etiqueta, asi que las filas de un tamano se
            # dividian entre la referencia del OTRO, y las razones publicadas
            # no significaban nada.
            etiqueta = "%s  %d ficheros, %dk lineas [%s]" % (
                ln, len(ficheros), max(1, round(n / 1000)), eje)
            prep_multi.append(((ln, n, eje), ln, cmd, env, d, d / "out",
                               etiqueta, ficheros, eje))
    with Spinner("verificando los proyectos multi-fichero", color=C.DIM):
        vered_multi = verificar_en_paralelo(
            [(c[0], c[1], c[2], c[3], c[4], c[5]) for c in prep_multi],
            jobs, args.timeout)

    with Spinner("", color=C.DIM) as spin:
      for hechos, (clave, ln, cmd, env, d, salida, etiqueta,
                   ficheros, eje) in enumerate(prep_multi):
            n = clave[1]
            spin.etiqueta(f"multi-fichero  {barra(hechos, len(prep_multi))}  "
                          f"{C.BOLD}{etiqueta}{C.RESET}")
            ok, motivo = vered_multi.get(clave, (False, "no verificado"))
            if not ok:
                print(f"  {C.RED}[no compila]{C.RESET} {etiqueta}: {motivo}")
                continue
            # DE CERO: se vacia la cache de artefactos antes de cada medida.
            #
            # Sin esto la comparacion es tramposa y lo comprobe midiendo: con
            # los `.vxi` calientes, Vesta daba 16 ms -- exactamente su suelo,
            # porque no reconstruia NADA -- mientras gcc recompilaba las 21
            # unidades enteras y daba 867.  "Caliente" no significa lo mismo
            # para quien tiene cache de artefactos que para quien no la tiene,
            # asi que la construccion completa se mide siempre de cero.
            s_cero = medir_frio(cmd, env, d, args.repes, args.timeout, ln,
                                dir_cache)
            filas_multi.append((ln, etiqueta, s_cero))

            # Con el proyecto ya construido, cuanto cuesta volver a
            # construirlo segun QUE haya cambiado.  El orden va de menos a mas
            # profundo, y la escalera entre ellos ES la granularidad de
            # invalidacion del compilador: uno que no distinga dara el mismo
            # numero en las cuatro filas.
            una_medida(cmd, env, args.timeout, d)   # dejarlo todo construido
            modulos = [f for f in ficheros if not f.lower().startswith("main")]
            casos_inc = [
                ("sin cambios", None, []),
                ("1 comentario", "comentario", modulos[:1]),
                ("1 cuerpo", "cuerpo", modulos[:1]),
                ("1 interfaz", "interfaz", modulos[:1]),
                ("mitad de los modulos", "cuerpo",
                 modulos[:max(1, len(modulos) // 2)]),
            ]
            for nombre_caso, clase, objetivos in casos_inc:
                serie = []
                for v in range(args.repes):
                    if clase is not None:
                        for f in objetivos:
                            mutar(d / f, ln, clase, v)
                    t = una_medida(cmd, env, args.timeout, d)
                    if t >= 0:
                        serie.append(t)
                s_i = _stats_summary(serie) if serie else {}
                filas_inc.append((ln, "%s  %s, %dk lineas [%s]" % (
                    ln, nombre_caso, max(1, round(n / 1000)), eje), s_i))
                resultados["casos"].append({
                    "lang": ln, "fase": "2b", "funciones": n, "ficheros": len(ficheros),
                    "regimen": nombre_caso, "stats": s_i, "paralelismo": eje,
                })
            resultados["casos"].append({
                "lang": ln, "fase": "2b", "funciones": n, "ficheros": len(ficheros),
                "regimen": "de cero", "stats": s_cero, "paralelismo": eje,
                # `make -j` es la unica via de paralelizar C aqui.  Si no habia
                # `make`, la orden cayo a la invocacion secuencial y esta fila
                # NO es del eje que dice su etiqueta; queda apuntado para que
                # nadie la lea como tal.
                "paralelizado": not (eje == "maquina" and ln in ("c", "cpp")
                                     and cmd[0] != "make"),
            })
    if filas_multi:
        imprimir_tabla(
            "El MISMO programa repartido en varios ficheros, DE CERO (ms)",
            filas_multi, suelo,
            "Comparar con la tabla de un solo fichero del mismo tamano: mismo "
            "trabajo, otra forma de darselo al compilador.  Se mide de cero "
            "porque 'caliente' no significa lo mismo para quien tiene cache de "
            "artefactos que para quien no la tiene.")
    if filas_inc:
        imprimir_tabla(
            "Reconstruir segun QUE haya cambiado (ms, con las caches puestas)",
            filas_inc, suelo,
            "`sin cambios` NO es un ranking de velocidad de compilacion: es el "
            "coste de REUTILIZAR: lo que tarda en demostrar que lo que ya "
            "tiene sigue valiendo.  Las cuatro filas siguientes van de menos a "
            "mas profundo, y la escalera entre ellas es la granularidad de "
            "invalidacion: quien no distinga dara el mismo numero en todas.")

