#!/usr/bin/env python3
"""Cuantas lineas por segundo digiere cada compilador.

Es la otra forma de leer lo mismo, y no sobra: "tarda 667 ms" solo significa
algo sabiendo de que programa se habla, mientras que "120.000 lineas por
segundo" se compara entre lenguajes y entre tamanos sin mas contexto.  Es
tambien la cifra con la que se estima lo que costara un proyecto que aun no
existe: con las lineas que se esperan, sale el tiempo.

Se publica de dos formas, y la segunda existe porque la primera sola no es
estable:

  por tamano   Lineas entre el tiempo ENTERO, arranque incluido.  Es lo que se
               espera delante del teclado, y no resta nada.  Sube con el
               tamano aunque el compilador vaya igual de rapido, porque el
               arranque es fijo y cada vez pesa menos.

  ajustado     La pendiente de `tiempo = arranque + coste x lineas` sobre
               todos los tamanos.  Separa el arranque SIN medirlo aparte -- es
               la interseccion de la misma recta --, y es la cifra comparable
               entre herramientas.

Por que no se resta el arranque punto a punto, que seria lo obvio: en un
programa pequeno eso es la diferencia de dos numeros grandes.  Rust daba 150 ms
con un arranque de ~145, o sea ~5 ms; el error relativo de esos 5 ms es enorme
y dividir lineas entre ellos lo multiplica.  Asi salio un caudal de 101k
lineas/s que al tamano siguiente se quedaba en 53k -- y el resumen se quedaba
justo con el peor de los dos, porque cogia el maximo.  Con la recta, un error
en un punto se reparte entre todos.
"""
from __future__ import annotations

from ..comun import C, Spinner, color_de
from ..contexto import Ctx
from ..generadores import GENERADORES, funciones_para_lineas
from ..informe import BASE, barra, cabecera_fase
from ..medida import compila_de_verdad, medir_caliente, medir_frio
from ..memoria import formatear as formatear_mem
from ..ordenes import entorno_cache, orden_compilar


def _caudal(lineas: int, ms: float):
    """Lineas por segundo, o None si el tiempo no da para afirmarlo."""
    if ms is None or ms <= 0.5:
        return None
    return lineas * 1000.0 / ms


def recta(puntos: list):
    """Ajusta `ms = arranque + coste_por_linea * lineas` y devuelve los tres.

    ESTA es la forma estable de medir el caudal, y la razon es aritmetica.
    Calcularlo punto a punto obliga a restar el suelo medido aparte, y en un
    programa pequeno eso es la diferencia de dos numeros grandes: rust daba
    150 ms con un arranque de ~145, o sea ~5 ms de neto.  El error relativo de
    esos 5 ms es enorme, y dividir lineas entre ellos lo multiplica -- salia un
    caudal de 101k lineas/s que al tamano siguiente se quedaba en 53k.

    Con la recta no se resta nada: el arranque es la INTERSECCION y el caudal
    la pendiente, los dos salidos del mismo ajuste.  Un error en un punto se
    reparte entre todos en vez de dominar uno.

    Se devuelve tambien R2 -- cuanto del comportamiento explica la recta --
    porque el ajuste siempre da un numero y hay que poder ver si vale: si el
    coste no es lineal, R2 baja y la pendiente deja de significar "coste por
    linea".

    @return (lineas_por_segundo, arranque_ms, r2) o None si no se puede.
    """
    utiles = [(x, y) for x, y in puntos if x > 0 and y > 0]
    if len(utiles) < 2:
        return None
    n = len(utiles)
    mx = sum(x for x, _ in utiles) / n
    my = sum(y for _, y in utiles) / n
    den = sum((x - mx) ** 2 for x, _ in utiles)
    if den <= 0:
        return None
    b = sum((x - mx) * (y - my) for x, y in utiles) / den
    if b <= 0:
        return None  # el tiempo no crece con el tamano: no hay caudal que dar
    a = my - b * mx
    tot = sum((y - my) ** 2 for _, y in utiles)
    res = sum((y - (a + b * x)) ** 2 for x, y in utiles)
    r2 = 1.0 - (res / tot) if tot > 0 else 1.0
    # Una pendiente positiva no basta: tiene que DESTACAR del ruido.  Con la
    # cache caliente, Go devuelve el artefacto ya hecho y tarda lo mismo a los
    # tres tamanos; entre 1.5k y 24k lineas la diferencia era de centesimas de
    # milisegundo, o sea ruido con signo.  La pendiente salia positiva pero
    # minuscula, y `1000/b` la convertia en 595.3M lineas/s -- un numero que
    # parece un resultado espectacular y solo dice que ahi no se compilo nada.
    #
    # El criterio no puede ser el residuo: con tres puntos y dos parametros el
    # ajuste tiene un solo grado de libertad, tres medidas casi identicas
    # quedan casi colineales y el residuo sale minusculo -- daba R2=0.96 para
    # una "tendencia" de cuatro centesimas de milisegundo.
    #
    # Se compara contra lo que se esta midiendo: el tiempo que la recta
    # atribuye al TAMANO a lo largo del rango tiene que ser una parte
    # apreciable del tiempo medido.  Una herramienta que de verdad compila
    # crece con el codigo -- entre 1.5k y 24k lineas hay un factor 16 --, asi
    # que si dieciseis veces mas codigo mueve el reloj menos de un 5%, lo que
    # se esta cronometrando es un coste FIJO y la pendiente es su resto.
    xs = [x for x, _ in utiles]
    ys = [y for _, y in utiles]
    crecimiento = b * (max(xs) - min(xs))    # ms atribuibles al tamano
    ruido = (res / n) ** 0.5                 # dispersion residual, en ms
    if crecimiento <= ruido or crecimiento < 0.05 * max(ys):
        return None
    return (1000.0 / b, a, r2)


def _fmt(v) -> str:
    """El caudal en la unidad que se lea de un vistazo.

    @c None es "no se pudo ajustar", que NO es lo mismo que un caudal
    proximo a cero: decia `~0` y se leia como "este compilador no digiere
    codigo", cuando lo que pasa es que la recta no describe lo medido -- en Go
    con la cache caliente, porque no compila nada.  Se dice `n/d`, igual que
    hace el pico de memoria cuando no se puede medir.
    """
    if v is None:
        return "n/d"
    if v >= 1000000:
        return "%.1fM" % (v / 1000000.0)
    if v >= 1000:
        return "%.0fk" % (v / 1000.0)
    return "%.0f" % v


def fase(ctx: Ctx) -> None:
    """Lineas por segundo de cada compilador, en frio y en caliente."""
    args = ctx.args
    objetivos = [int(x) for x in args.lineas.split(",") if x.strip()]
    cabecera_fase(
        "caudal", "Lineas por segundo",
        "Cuanto codigo digiere cada compilador por segundo.  La tabla de "
        "arriba da el caudal con el arranque DENTRO -- que es lo que se espera "
        "delante del teclado --; la de abajo lo separa ajustando una recta "
        "sobre todos los tamanos, que es la forma estable de medirlo.")

    cab = (f"{'lenguaje':<12}{'lineas':>9}{'caudal frio':>13}"
           f"{'caudal cal':>12}{'mem frio':>11}{'mem cal':>11}"
           f"{'vs ' + BASE:>11}")
    print(f"{C.BOLD}{cab}{C.RESET}")
    print(f"{C.DIM}  {'':<10}{'(codigo)':>9}{'(lin/s)':>13}{'(lin/s)':>12}"
          f"{'(pico)':>11}{'(pico)':>11}{'(frio)':>11}{C.RESET}")
    print("-" * len(cab))
    # Las filas se guardan y se pintan al SALIR del indicador de progreso.
    # Imprimir dentro dejaba la linea a medias del indicador delante de cada
    # fila -- `/ crecimiento [###----] 3/27  vesta ...` pegado a los numeros --
    # y la tabla se volvia ilegible justo en la fase mas larga.
    filas: list = []

    # La base primero, para poder comparar en la misma pasada.
    orden = ([BASE] + [l for l in ctx.langs if l != BASE]
             if BASE in ctx.langs else list(ctx.langs))
    base_bruto: dict = {}
    puntos: dict = {}   # lang -> {"frio": [(lineas, ms)], "caliente": [...]}

    total = max(1, len(ctx.langs) * len(objetivos))
    hechos = 0
    with Spinner("", color=C.DIM) as spin:
        for ln in orden:
            entrada = GENERADORES.get(ln)
            if entrada is None:
                continue
            nombre, gen = entrada
            for objetivo in objetivos:
                spin.etiqueta(f"caudal  {barra(hechos, total)}  "
                              f"{C.BOLD}{ln}{C.RESET} {objetivo} lineas")
                hechos += 1
                d = ctx.base_tmp / ("caud_%s_%d" % (ln, objetivo))
                d.mkdir(parents=True, exist_ok=True)
                texto = gen(funciones_para_lineas(gen, objetivo))
                (d / nombre).write_text(texto, encoding="utf-8")
                lineas = texto.count("\n")
                cmd = orden_compilar(ln, d / nombre, d / "out", ctx.vm)
                if not cmd:
                    continue
                env = entorno_cache(ln, ctx.dir_cache, ctx.entorno_base)
                ok, motivo = compila_de_verdad(ln, cmd, env, d, d / "out",
                                               args.timeout)
                if not ok:
                    filas.append(f"  {C.RED}[no compila]{C.RESET} "
                                 f"{ln} {lineas} lineas: {motivo}")
                    break
                repes = max(3, args.repes // 2)
                s_cal = medir_caliente(cmd, env, d, repes, args.timeout, ln)
                s_frio = medir_frio(cmd, env, d, repes, args.timeout, ln,
                                    ctx.dir_cache)
                if not s_cal or not s_frio:
                    continue
                # Por punto se publica el caudal BRUTO -- lineas entre el
                # tiempo entero --, que no resta nada y por tanto no amplifica
                # ningun error.  El caudal del compilador sin su arranque sale
                # despues, del ajuste sobre todos los tamanos.
                bf = _caudal(lineas, s_frio["p50"])
                bc = _caudal(lineas, s_cal["p50"])
                d_ln = puntos.setdefault(ln, {"frio": [], "caliente": []})
                d_ln["frio"].append((lineas, s_frio["p50"]))
                d_ln["caliente"].append((lineas, s_cal["p50"]))

                if ln == BASE and bf:
                    base_bruto[objetivo] = bf
                b = base_bruto.get(objetivo)
                vs = ("x%.3f" % (bf / b)) if (b and bf) else "-"

                filas.append(f"  {color_de(ln)}{ln:<10}{C.RESET}{lineas:>9}"
                      f"{_fmt(bf):>13}{_fmt(bc):>12}"
                      f"{formatear_mem(s_frio.get('mem_kib')):>11}"
                      f"{formatear_mem(s_cal.get('mem_kib')):>11}{vs:>11}")
                ctx.resultados["casos"].append({
                    "lang": ln, "fase": "caudal", "lineas": lineas,
                    "objetivo": objetivo,
                    "bruto_frio": bf, "bruto_caliente": bc,
                    "ms_frio": s_frio["p50"], "ms_caliente": s_cal["p50"],
                    "mem_frio_kib": s_frio.get("mem_kib"),
                    "mem_cal_kib": s_cal.get("mem_kib")})
    for f in filas:
        print(f)
    print("-" * len(cab))
    print(f"{C.DIM}  bruto = con el arranque del compilador dentro (lo que se "
          f"espera de verdad).  neto = sin el, que es lo comparable entre "
          f"herramientas.\n"
          f"  La distancia entre los dos se estrecha al crecer el programa: "
          f"el arranque es fijo y deja de pesar.  Un `~0` es una medida que no "
          f"se separo del arranque.{C.RESET}")

    # --- El caudal del compilador, del AJUSTE sobre todos los tamanos.
    #
    # Antes esto era el maximo de los caudales por punto, y era lo peor que se
    # podia hacer: el maximo se lo lleva justo el punto mas ruidoso -- el
    # programa mas pequeno, donde el neto es una resta de dos numeros grandes.
    # Rust publicaba 101k lineas/s por esa via y 53k al tamano siguiente.
    ajustes = []
    for ln, d_ln in puntos.items():
        rf = recta(d_ln["frio"])
        rc = recta(d_ln["caliente"])
        if rf or rc:
            ajustes.append((ln, rf, rc))
    if ajustes:
        print()
        print(f"{C.BOLD}Caudal del compilador, ajustado sobre todos los "
              f"tamanos{C.RESET}")
        print(f"{C.DIM}  De la recta `tiempo = arranque + coste x lineas`: la "
              f"pendiente es el caudal y el arranque sale solo, sin restarlo a "
              f"mano.  Es la cifra con la que se estima un proyecto que aun no "
              f"existe.{C.RESET}")
        cab2 = (f"{'lenguaje':<12}{'caudal frio':>13}{'caudal cal':>12}"
                f"{'arranque':>11}{'ajuste':>9}{'100k lineas':>14}")
        print(f"{C.BOLD}{cab2}{C.RESET}")
        print(f"{C.DIM}  {'':<10}{'(lin/s)':>13}{'(lin/s)':>12}{'(ms)':>11}"
              f"{'(R2)':>9}{'(s, en frio)':>14}{C.RESET}")
        print("-" * len(cab2))
        for ln, rf, rc in sorted(ajustes,
                                 key=lambda r: -(r[1][0] if r[1] else 0)):
            cf = rf[0] if rf else None
            cc = rc[0] if rc else None
            arr = rf[1] if rf else (rc[1] if rc else 0)
            r2 = rf[2] if rf else (rc[2] if rc else 0)
            # Con dos tamanos la recta pasa por los dos puntos y R2 vale 1
            # siempre: no dice nada.  Se avisa en vez de enseñar un 1.00 que
            # parece una confirmacion.
            t_r2 = f"{r2:>9.2f}" if len(puntos[ln]["frio"]) > 2 else f"{'n/d':>9}"
            est = ("%.1f" % (100000.0 / cf)) if cf else "-"
            print(f"  {color_de(ln)}{ln:<10}{C.RESET}{_fmt(cf):>13}"
                  f"{_fmt(cc):>12}{arr:>11.0f}{t_r2}{est:>14}")
        print("-" * len(cab2))
        print(f"{C.DIM}  R2 = cuanto del comportamiento explica la recta.  "
              f"Cerca de 1, el coste por linea es constante y la cifra vale; "
              f"si baja, el coste NO es lineal y la pendiente deja de "
              f"significar 'por linea'.  Con solo dos tamanos no se puede "
              f"juzgar: sale `n/d`.{C.RESET}")
        print(f"{C.DIM}  Un caudal `n/d` es que la recta no describe lo "
              f"medido: o el tiempo no crece con el tamano, o lo que crece no "
              f"se separa del ruido.  Pasa cuando la herramienta devuelve un "
              f"artefacto cacheado en vez de compilar, y entonces no hay "
              f"caudal que medir -- no es un caudal de cero.{C.RESET}")
        ctx.resultados["caudal"] = [
            {"lang": ln,
             "lineas_por_segundo": (rf[0] if rf else None),
             "lineas_por_segundo_caliente": (rc[0] if rc else None),
             "arranque_ms": (rf[1] if rf else None),
             "r2": (rf[2] if rf else None)}
            for ln, rf, rc in ajustes]
