#!/usr/bin/env python3
"""Graficas del banco de compilacion, UNA POR FASE.

Antes salia un puñado de figuras que mezclaban fases distintas en los mismos
ejes.  El resultado eran barras de colores sin eje comun ni pregunta detras: si
en una figura conviven el suelo del compilador, un proyecto de veinte modulos y
cuatro familias de codigo, no hay escala que sirva para las tres y no se puede
leer ninguna.

Aqui cada fase produce SUS figuras, con la misma regla que el banco de
ejecucion: **una grafica, una pregunta**.  Mejor ocho imagenes claras que una
sobrecargada.

Anadir graficas a una fase es escribir su funcion y ponerla en `POR_FASE`; las
demas no se enteran.  Si falta matplotlib, todo esto se salta y el banco sigue
publicando sus tablas.
"""
from __future__ import annotations

import sys
from pathlib import Path


# Por que no se pudo dibujar.  Sin esto, faltar matplotlib salia como que no
# se imprimia NADA -- ni una figura ni un aviso -- y parecia que el banco
# simplemente no dibujaba graficas.  Pasa facil al lanzar con `sudo`: root
# suele tener otro Python, sin los paquetes del usuario.
_MOTIVO_SIN_GRAFICAS = ""


def _mpl():
    """matplotlib, o None si no esta.  Las graficas son un extra, no un requisito."""
    global _MOTIVO_SIN_GRAFICAS
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        return plt
    except ImportError as e:
        _MOTIVO_SIN_GRAFICAS = str(e)
        return None


def diagnostico_dependencias() -> str:
    """Una explicacion con la solucion, o "" si no falta nada.

    Se da el interprete EXACTO con el que instalar, no un `pip install` a
    secas: el fallo tipico es tener matplotlib para el usuario y lanzar el
    banco con `sudo`, y ahi un `pip install` sin mas lo instala otra vez donde
    ya estaba.
    """
    if _mpl() is not None:
        return ""
    return ("faltan las librerias de dibujo (%s).  Instalalas para ESTE "
            "interprete:\n           %s -m pip install matplotlib\n"
            "         Si lanzaste el banco con `sudo`, ojo: root suele tener "
            "otro Python distinto del tuyo."
            % (_MOTIVO_SIN_GRAFICAS or "matplotlib", sys.executable))


# Los mismos colores y etiquetas que el banco de ejecucion: las dos tandas se
# leen a menudo juntas, y que C sea azul en una y verde en otra obliga a releer
# la leyenda en cada figura.
try:  # pragma: no cover - solo para reutilizar las tablas si estan
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from plots import LANG_COLORS, LANG_LABELS  # type: ignore # noqa: E402
except Exception:  # noqa: BLE001
    LANG_COLORS, LANG_LABELS = {}, {}


def _col(ln: str) -> str:
    return LANG_COLORS.get(ln, "#888888")


def _lab(ln: str) -> str:
    return LANG_LABELS.get(ln, ln)


def _guardar(plt, fig, destino: Path, nombre: str, hechas: dict) -> None:
    """Cierra y escribe una figura, y la apunta para el resumen final."""
    plt.tight_layout()
    plt.savefig(destino / (nombre + ".png"), dpi=110, bbox_inches="tight")
    plt.close(fig)
    hechas[nombre] = True


def _casos_de(datos: dict, fase: str) -> list:
    return [c for c in datos.get("casos", []) if c.get("fase") == fase]


# ---------------------------------------------------------------------------
#  Fase 1 -- el suelo: lo que cuesta arrancar cada compilador.
# ---------------------------------------------------------------------------

def fase_suelo(datos: dict, destino: Path, hechas: dict) -> None:
    plt = _mpl()
    suelo = datos.get("suelo") or {}
    filas = [(ln, s.get("p50"), s.get("mem_kib")) for ln, s in suelo.items()
             if s.get("p50")]
    if not plt or not filas:
        return
    filas.sort(key=lambda t: t[1])
    # Tiempo y memoria en la misma figura pero en ejes SEPARADOS: son unidades
    # distintas y ponerlas en el mismo eje aplasta una de las dos.
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(13, 5))
    nombres = [_lab(f[0]) for f in filas]
    a1.barh(nombres, [f[1] for f in filas],
            color=[_col(f[0]) for f in filas])
    a1.set_xlabel("ms")
    a1.set_title("Arrancar y no hacer nada (tiempo)")
    a1.grid(axis="x", alpha=0.3)
    mem = [(f[2] or 0) / 1024.0 for f in filas]
    a2.barh(nombres, mem, color=[_col(f[0]) for f in filas])
    a2.set_xlabel("MiB (pico del arbol de procesos)")
    a2.set_title("Arrancar y no hacer nada (memoria)")
    a2.grid(axis="x", alpha=0.3)
    fig.suptitle("Fase 1 -- suelo del compilador\n"
                 "Esto esta DENTRO de cualquier otra medida y por eso se resta",
                 fontsize=12, fontweight="bold")
    _guardar(plt, fig, destino, "f1_suelo", hechas)


# ---------------------------------------------------------------------------
#  Fase 2 -- compilar el programa entero, por tamano.
# ---------------------------------------------------------------------------

def fase_completa(datos: dict, destino: Path, hechas: dict) -> None:
    plt = _mpl()
    casos = _casos_de(datos, "2")
    if not plt or not casos:
        return
    # Por el tamano PEDIDO, no por el conseguido: la normalizacion a lineas
    # se acerca pero no clava, asi que agrupar por lineas reales daba un grupo
    # por lenguaje -- paneles de una sola barra, comparando nada con nada.
    tamanos = sorted({c.get("objetivo") or c["lineas"] for c in casos})

    def _obj(c):
        return c.get("objetivo") or c["lineas"]
    langs = sorted({c["lang"] for c in casos})

    # (a) frio contra caliente, agrupado por tamano.  La pregunta es "cuanto
    # cuesta", y la respuesta son dos numeros por lenguaje, no uno.
    fig, axes = plt.subplots(1, len(tamanos), figsize=(7 * len(tamanos), 5),
                             squeeze=False)
    for i, n in enumerate(tamanos):
        ax = axes[0][i]
        pres = [ln for ln in langs
                if any(c["lang"] == ln and _obj(c) == n for c in casos)]
        xs = list(range(len(pres)))
        f = [next((c["frio"].get("p50") for c in casos
                   if c["lang"] == ln and _obj(c) == n and c.get("frio")),
                  0) for ln in pres]
        cal = [next((c["caliente"].get("p50") for c in casos
                     if c["lang"] == ln and _obj(c) == n
                     and c.get("caliente")), 0) for ln in pres]
        ax.bar([x - 0.2 for x in xs], f, 0.38, label="en frio",
               color=[_col(l) for l in pres])
        ax.bar([x + 0.2 for x in xs], cal, 0.38, label="en caliente",
               color=[_col(l) for l in pres], alpha=0.5)
        ax.set_xticks(xs)
        ax.set_xticklabels([_lab(l) for l in pres], rotation=20, ha="right")
        ax.set_ylabel("ms")
        ax.set_title("~%d lineas" % n)
        ax.grid(axis="y", alpha=0.3)
        ax.legend(fontsize=8)
    fig.suptitle("Fase 2 -- compilar el programa entero",
                 fontsize=12, fontweight="bold")
    _guardar(plt, fig, destino, "f2_completa", hechas)

    # (b) contra la base, que es la lectura que se quiere de un vistazo.
    base = "vesta"
    n = tamanos[-1]
    pares = []
    b = next((c["frio"].get("p50") for c in casos
              if c["lang"] == base and _obj(c) == n and c.get("frio")), 0)
    if b:
        for ln in langs:
            v = next((c["frio"].get("p50") for c in casos
                      if c["lang"] == ln and _obj(c) == n and c.get("frio")),
                     0)
            if v:
                pares.append((v / b, ln))
        pares.sort()
        fig, ax = plt.subplots(figsize=(9, max(3, 0.5 * len(pares) + 2)))
        ax.barh([_lab(p[1]) for p in pares], [p[0] for p in pares],
                color=[_col(p[1]) for p in pares])
        ax.axvline(1.0, color="#444", linestyle=":", linewidth=1.5)
        ax.set_xscale("log")
        ax.set_xlabel("veces respecto a %s (log).  <1 = tarda menos" % base)
        ax.set_title("Fase 2 -- cuanto tarda cada uno comparado con %s\n"
                     "(%d lineas, en frio)" % (base, n),
                     fontsize=11, fontweight="bold")
        ax.grid(axis="x", which="both", alpha=0.3)
        _guardar(plt, fig, destino, "f2_vs_base", hechas)

    # (c) memoria, que es el otro limite y no se deduce del tiempo.
    fig, ax = plt.subplots(figsize=(10, 5))
    hay = False
    for ln in langs:
        pts = sorted((c["lineas"], (c.get("frio") or {}).get("mem_kib"))
                     for c in casos if c["lang"] == ln)
        pts = [(x, y / 1024.0) for x, y in pts if y]
        if not pts:
            continue
        hay = True
        ax.plot([p[0] for p in pts], [p[1] for p in pts], "o-", linewidth=2,
                color=_col(ln), label=_lab(ln))
    if hay:
        ax.set_xlabel("lineas del programa")
        ax.set_ylabel("MiB (pico)")
        ax.set_title("Fase 2 -- memoria maxima al compilar\n"
                     "(es un limite duro: pasarse no hace la compilacion "
                     "lenta, la hace imposible)", fontsize=11,
                     fontweight="bold")
        ax.grid(alpha=0.3)
        ax.legend(fontsize=9)
        _guardar(plt, fig, destino, "f2_memoria", hechas)
    else:
        plt.close(fig)


# ---------------------------------------------------------------------------
#  Fase crecimiento -- como escala, que es lo que un solo tamano no dice.
# ---------------------------------------------------------------------------

def fase_crecimiento(datos: dict, destino: Path, hechas: dict) -> None:
    plt = _mpl()
    casos = _casos_de(datos, "crecimiento")
    if not plt or not casos:
        return
    langs = sorted({c["lang"] for c in casos})

    def _serie(ln: str, clave: str, div: float = 1.0):
        pts = sorted((c["lineas"], c.get(clave)) for c in casos
                     if c["lang"] == ln)
        return [(x, y / div) for x, y in pts if y]

    # (a) tiempo contra lineas, en log-log.  En esos ejes la pendiente ES el
    # exponente, asi que la forma se lee directamente; en escala normal todas
    # las curvas suben y no se distingue una de otra.
    for clave, etiq, nombre in (("neto_frio", "en frio", "fc_tiempo_frio"),
                                ("neto_caliente", "en caliente",
                                 "fc_tiempo_caliente")):
        fig, ax = plt.subplots(figsize=(9, 6))
        hay = False
        for ln in langs:
            pts = _serie(ln, clave)
            if len(pts) < 2:
                continue
            hay = True
            ax.plot([p[0] for p in pts], [p[1] for p in pts], "o-",
                    linewidth=2, color=_col(ln), label=_lab(ln))
        if not hay:
            plt.close(fig)
            continue
        ax.set_xscale("log")
        ax.set_yscale("log")
        ax.set_xlabel("lineas del programa (log)")
        ax.set_ylabel("ms sin el arranque (log)")
        ax.set_title("Crecimiento del TIEMPO %s\n"
                     "(en log-log la pendiente es el exponente: recta a 45 "
                     "grados = lineal)" % etiq, fontsize=11, fontweight="bold")
        ax.grid(alpha=0.3, which="both")
        ax.legend(fontsize=9)
        _guardar(plt, fig, destino, nombre, hechas)

    # (b) lo mismo para la memoria.  Va aparte y no como segunda serie de la
    # figura anterior: son unidades distintas, y superponerlas obligaria a un
    # eje doble que se lee peor que dos imagenes.
    fig, ax = plt.subplots(figsize=(9, 6))
    hay = False
    for ln in langs:
        pts = _serie(ln, "mem_frio_kib", 1024.0)
        if len(pts) < 2:
            continue
        hay = True
        ax.plot([p[0] for p in pts], [p[1] for p in pts], "o-", linewidth=2,
                color=_col(ln), label=_lab(ln))
    if hay:
        ax.set_xscale("log")
        ax.set_yscale("log")
        ax.set_xlabel("lineas del programa (log)")
        ax.set_ylabel("MiB de pico (log)")
        ax.set_title("Crecimiento de la MEMORIA (en frio)\n"
                     "(no tiene por que crecer como el tiempo: se puede tardar "
                     "el doble y pedir cuatro veces mas)",
                     fontsize=11, fontweight="bold")
        ax.grid(alpha=0.3, which="both")
        ax.legend(fontsize=9)
        _guardar(plt, fig, destino, "fc_memoria", hechas)
    else:
        plt.close(fig)

    # (c) los exponentes, que es el resumen de todo lo anterior en una cifra.
    resumen = datos.get("crecimiento") or []
    if resumen:
        fig, ax = plt.subplots(figsize=(max(8, 1.6 * len(resumen)), 5))
        nombres = [r["lang"] for r in resumen]
        xs = list(range(len(nombres)))
        for desp, clave, etiq, alfa in ((-0.26, "k_frio", "tiempo en frio", 1.0),
                                        (0.0, "k_caliente", "tiempo caliente",
                                         0.65),
                                        (0.26, "k_memoria", "memoria", 0.35)):
            ax.bar([x + desp for x in xs],
                   [(r.get(clave) or 0) for r in resumen], 0.25, label=etiq,
                   alpha=alfa, color=[_col(n) for n in nombres])
        ax.axhline(1.0, color="#444", linestyle=":", linewidth=1.5)
        ax.text(len(nombres) - 0.5, 1.03, "lineal", fontsize=8, color="#444",
                ha="right")
        ax.set_xticks(xs)
        ax.set_xticklabels([_lab(n) for n in nombres], rotation=20, ha="right")
        ax.set_ylabel("exponente k de  coste = a * lineas^k")
        ax.set_title("Como escala cada compilador\n"
                     "(1.0 = el doble de codigo cuesta el doble; 2.0 = cuatro "
                     "veces)", fontsize=11, fontweight="bold")
        ax.grid(axis="y", alpha=0.3)
        ax.legend(fontsize=9)
        _guardar(plt, fig, destino, "fc_exponentes", hechas)

    # (d) lo que aporta la cache, y si aguanta al crecer el programa.  No se
    # deduce de las dos curvas por separado sin ir restando a ojo.
    fig, ax = plt.subplots(figsize=(9, 5))
    hay = False
    for ln in langs:
        frio = dict(_serie(ln, "neto_frio"))
        cal = dict(_serie(ln, "neto_caliente"))
        comunes = sorted(set(frio) & set(cal))
        if len(comunes) < 2:
            continue
        hay = True
        ax.plot(comunes, [frio[n] / cal[n] for n in comunes], "o-",
                linewidth=2, color=_col(ln), label=_lab(ln))
    if hay:
        ax.axhline(1.0, color="#444", linestyle=":", linewidth=1.5)
        ax.set_xscale("log")
        ax.set_xlabel("lineas del programa (log)")
        ax.set_ylabel("veces mas rapido con la cache caliente")
        ax.set_title("Cuanto aporta la cache, y si aguanta al crecer\n"
                     "(un fichero suelto no tiene nada que reutilizar: ahi "
                     "1.0 es lo esperado)", fontsize=11, fontweight="bold")
        ax.grid(alpha=0.3, which="both")
        ax.legend(fontsize=9)
        _guardar(plt, fig, destino, "fc_ahorro_cache", hechas)
    else:
        plt.close(fig)

    # (e) el coste POR MIL LINEAS.  La tabla ya publica esta columna pero no
    # habia figura, y es la que responde de un vistazo a "¿el coste por linea
    # es constante?": una linea plana es lineal, una que sube es superlineal.
    # En (a) eso no se ve -- alli todas las curvas suben, porque el programa
    # crece --, y en (c) sale resumido a una sola cifra que no dice DONDE se
    # degrada.
    #
    # Frio y caliente van en dos paneles y no en uno: sus escalas se separan
    # por un orden de magnitud (Vesta esta en ~35 ms/kloc en frio y ~4.5 en
    # caliente) y superponerlos aplasta el panel caliente contra el eje.
    fig, (a_f, a_c) = plt.subplots(1, 2, figsize=(13, 5), sharey=True)
    hay = False
    for eje, clave, titulo in ((a_f, "neto_frio", "en frio"),
                               (a_c, "neto_caliente", "en caliente")):
        for ln in langs:
            pts = [(x, y) for x, y in _serie(ln, clave) if x > 0]
            if len(pts) < 2:
                continue
            hay = True
            eje.plot([p[0] for p in pts],
                     [p[1] / (p[0] / 1000.0) for p in pts], "o-",
                     linewidth=2, color=_col(ln), label=_lab(ln))
        eje.set_xscale("log")
        eje.set_yscale("log")
        eje.set_xlabel("lineas del programa (log)")
        eje.set_title(titulo, fontsize=10)
        eje.grid(alpha=0.3, which="both")
    if hay:
        a_f.set_ylabel("ms por cada mil lineas, sin el arranque (log)")
        for eje in (a_f, a_c):     # el panel que tenga curvas (ver la gemela)
            if eje.get_legend_handles_labels()[0]:
                eje.legend(fontsize=9)
                break
        fig.suptitle("Coste por mil lineas\n"
                     "(plana = el coste por linea no cambia con el tamano; "
                     "si sube, la curva no es lineal)",
                     fontsize=11, fontweight="bold")
        _guardar(plt, fig, destino, "fc_coste_por_kloc", hechas)
    else:
        plt.close(fig)

    # (f) lo mismo para la memoria: MiB por cada mil lineas.  Una base fija
    # grande -- el propio compilador cargado -- hace que esta curva BAJE
    # aunque la memoria crezca, y eso es informacion: dice cuanto de lo que
    # pide es coste de arranque y cuanto es el programa.
    fig, ax = plt.subplots(figsize=(9, 5))
    hay = False
    for ln in langs:
        pts = [(x, y) for x, y in _serie(ln, "mem_frio_kib", 1024.0) if x > 0]
        if len(pts) < 2:
            continue
        hay = True
        ax.plot([p[0] for p in pts], [p[1] / (p[0] / 1000.0) for p in pts],
                "o-", linewidth=2, color=_col(ln), label=_lab(ln))
    if hay:
        ax.set_xscale("log")
        ax.set_yscale("log")
        ax.set_xlabel("lineas del programa (log)")
        ax.set_ylabel("MiB de pico por cada mil lineas (log)")
        ax.set_title("Memoria por mil lineas (en frio)\n"
                     "(baja cuando la mayor parte del pico es el compilador "
                     "cargado y no el programa)",
                     fontsize=11, fontweight="bold")
        ax.grid(alpha=0.3, which="both")
        ax.legend(fontsize=9)
        _guardar(plt, fig, destino, "fc_memoria_por_kloc", hechas)
    else:
        plt.close(fig)


# ---------------------------------------------------------------------------
#  Fases con RaGIMENES: 2b (que cambio) y 2e (familia x regimen).
# ---------------------------------------------------------------------------

def _barras_por_regimen(datos: dict, fase: str, campo: str, orden: list,
                        titulo: str, nota: str, nombre: str,
                        destino: Path, hechas: dict) -> None:
    """Un grupo de barras por regimen, con una barra por lenguaje.

    Es la forma de esta pregunta -- que se evita segun QUE haya cambiado --, y
    lo que se mira es la ESCALERA entre grupos: un compilador que no distinga
    un comentario de una interfaz dara la misma altura en todos.
    """
    plt = _mpl()
    casos = _casos_de(datos, fase)
    if not plt or not casos:
        return
    regs = [r for r in orden if any(c.get(campo) == r for c in casos)]
    langs = sorted({c["lang"] for c in casos})
    if not regs or not langs:
        return
    fig, ax = plt.subplots(figsize=(max(10, 1.5 * len(regs) * len(langs)), 5.5))
    ancho = 0.8 / len(langs)
    for j, ln in enumerate(langs):
        alturas = []
        for r in regs:
            vs = [(c.get("stats") or {}).get("p50") for c in casos
                  if c["lang"] == ln and c.get(campo) == r]
            vs = [v for v in vs if v]
            # La mediana entre tamanos: si la fase midio el mismo regimen en
            # varios, la barra tiene que resumirlos, no quedarse con el primero.
            alturas.append(sorted(vs)[len(vs) // 2] if vs else 0)
        ax.bar([i + (j - len(langs) / 2 + 0.5) * ancho
                for i in range(len(regs))], alturas, ancho,
               label=_lab(ln), color=_col(ln))
    ax.set_xticks(range(len(regs)))
    ax.set_xticklabels(regs, rotation=15, ha="right")
    ax.set_ylabel("ms")
    ax.set_yscale("log")
    ax.set_title(titulo + "\n" + nota, fontsize=11, fontweight="bold")
    ax.grid(axis="y", which="both", alpha=0.3)
    ax.legend(fontsize=8, ncol=2)
    _guardar(plt, fig, destino, nombre, hechas)


def fase_proyecto(datos: dict, destino: Path, hechas: dict) -> None:
    _barras_por_regimen(
        datos, "2b", "regimen",
        ["de cero", "sin cambios", "1 comentario", "1 cuerpo", "1 interfaz",
         "mitad de los modulos"],
        "Fase 2b -- que cuesta reconstruir segun QUE haya cambiado",
        "Lo que importa es la ESCALERA: quien no distinga un comentario de "
        "una interfaz dara la misma altura en todos (escala log)",
        "f2b_regimenes", destino, hechas)


def fase_regimen(datos: dict, destino: Path, hechas: dict) -> None:
    """2e: lo mismo, pero abierto por FAMILIA de codigo."""
    plt = _mpl()
    casos = _casos_de(datos, "2e")
    if not plt or not casos:
        return
    familias = sorted({c.get("familia") for c in casos if c.get("familia")})
    regs = ["de cero", "sin cambios", "cambia el cuerpo", "cambia la interfaz"]
    regs = [r for r in regs if any(c.get("regimen") == r for c in casos)]
    if not familias or not regs:
        return
    # Un panel por familia.  En una sola figura, cuatro familias x cuatro
    # regimenes x N lenguajes son barras sin eje comun -- que es justo lo que
    # hacia ilegible la version anterior.
    fig, axes = plt.subplots(1, len(familias),
                             figsize=(5.2 * len(familias), 5), squeeze=False,
                             sharey=True)
    langs = sorted({c["lang"] for c in casos})
    for i, fam in enumerate(familias):
        ax = axes[0][i]
        ancho = 0.8 / max(1, len(langs))
        for j, ln in enumerate(langs):
            alturas = []
            for r in regs:
                v = next(((c.get("stats") or {}).get("p50") for c in casos
                          if c["lang"] == ln and c.get("familia") == fam
                          and c.get("regimen") == r), 0)
                alturas.append(v or 0)
            ax.bar([k + (j - len(langs) / 2 + 0.5) * ancho
                    for k in range(len(regs))], alturas, ancho,
                   label=_lab(ln) if i == 0 else None, color=_col(ln))
        ax.set_xticks(range(len(regs)))
        ax.set_xticklabels(regs, rotation=20, ha="right", fontsize=8)
        ax.set_title(fam)
        ax.set_yscale("log")
        ax.grid(axis="y", which="both", alpha=0.3)
    axes[0][0].set_ylabel("ms (log)")
    fig.legend(fontsize=8, ncol=4, loc="upper center")
    fig.suptitle("Fase 2e -- cada familia de codigo, por regimen\n"
                 "La distancia entre cuerpo e interfaz es lo que la frontera "
                 "corta EN ESA familia", fontsize=12, fontweight="bold", y=1.06)
    _guardar(plt, fig, destino, "f2e_familia_regimen", hechas)


# ---------------------------------------------------------------------------
#  Fase 2c -- la forma de las dependencias.
# ---------------------------------------------------------------------------

def fase_topologia(datos: dict, destino: Path, hechas: dict) -> None:
    plt = _mpl()
    casos = _casos_de(datos, "2c")
    if not plt or not casos:
        return
    formas = sorted({c.get("topologia") for c in casos if c.get("topologia")})
    langs = sorted({c["lang"] for c in casos})
    if not formas or not langs:
        return
    fig, ax = plt.subplots(figsize=(max(9, 2.2 * len(formas)), 5.5))
    ancho = 0.8 / max(1, len(langs))
    for j, ln in enumerate(langs):
        alturas = []
        for f in formas:
            vs = [(c.get("stats") or {}).get("p50") for c in casos
                  if c["lang"] == ln and c.get("topologia") == f]
            vs = [v for v in vs if v]
            alturas.append(sorted(vs)[len(vs) // 2] if vs else 0)
        ax.bar([i + (j - len(langs) / 2 + 0.5) * ancho
                for i in range(len(formas))], alturas, ancho,
               label=_lab(ln), color=_col(ln))
    ax.set_xticks(range(len(formas)))
    ax.set_xticklabels(formas)
    ax.set_ylabel("ms")
    ax.set_title("Fase 2c -- la MISMA cantidad de codigo con otra forma de "
                 "dependencias\n(el cambio se hace siempre en el modulo del "
                 "que cuelgan los demas)", fontsize=11, fontweight="bold")
    ax.grid(axis="y", alpha=0.3)
    ax.legend(fontsize=8, ncol=2)
    _guardar(plt, fig, destino, "f2c_topologia", hechas)


# ---------------------------------------------------------------------------
#  Fase 2d -- que codigo, no cuanto.
# ---------------------------------------------------------------------------

def fase_familias(datos: dict, destino: Path, hechas: dict) -> None:
    plt = _mpl()
    casos = _casos_de(datos, "2d")
    if not plt or not casos:
        return
    familias = sorted({c.get("familia") for c in casos if c.get("familia")})
    langs = sorted({c["lang"] for c in casos})
    if not familias or not langs:
        return
    fig, ax = plt.subplots(figsize=(max(9, 2.2 * len(familias)), 5.5))
    ancho = 0.8 / max(1, len(langs))
    for j, ln in enumerate(langs):
        alturas = []
        for fam in familias:
            v = next(((c.get("stats") or {}).get("p50") for c in casos
                      if c["lang"] == ln and c.get("familia") == fam), 0)
            alturas.append(v or 0)
        ax.bar([i + (j - len(langs) / 2 + 0.5) * ancho
                for i in range(len(familias))], alturas, ancho,
               label=_lab(ln), color=_col(ln))
    ax.set_xticks(range(len(familias)))
    ax.set_xticklabels(familias, rotation=15, ha="right")
    ax.set_ylabel("ms")
    ax.set_title("Fase 2d -- QUE codigo se compila, no cuanto\n"
                 "Mil lineas de genericos y mil de aritmetica plana no cuestan "
                 "lo mismo: pegan en partes distintas del compilador",
                 fontsize=11, fontweight="bold")
    ax.grid(axis="y", alpha=0.3)
    ax.legend(fontsize=8, ncol=2)
    _guardar(plt, fig, destino, "f2d_familias", hechas)


# ---------------------------------------------------------------------------
#  Fase 3 -- lo que tarda en salir el diagnostico.
# ---------------------------------------------------------------------------

def fase_realimentacion(datos: dict, destino: Path, hechas: dict) -> None:
    plt = _mpl()
    filas = datos.get("realimentacion") or []
    filas = [f for f in filas if (f.get("stats") or {}).get("p50")]
    if not plt or not filas:
        return
    filas.sort(key=lambda f: f["stats"]["p50"])
    fig, ax = plt.subplots(figsize=(9, max(3, 0.5 * len(filas) + 2)))
    ax.barh([f.get("etiqueta") or f["lang"] for f in filas],
            [f["stats"]["p50"] for f in filas],
            color=[_col(f["lang"]) for f in filas])
    # La marca de los 100 ms no es decorativa: por encima, la respuesta deja de
    # sentirse inmediata mientras se edita, que es para lo que sirve esto.
    ax.axvline(100, color="#444", linestyle=":", linewidth=1.5)
    ax.text(105, -0.4, "100 ms", fontsize=8, color="#444")
    ax.set_xlabel("ms")
    ax.set_title("Fase 3 -- cuanto tarda en decirte si tu codigo esta bien\n"
                 "Solo analizar y diagnosticar: no genera codigo ni enlaza",
                 fontsize=11, fontweight="bold")
    ax.grid(axis="x", alpha=0.3)
    _guardar(plt, fig, destino, "f3_realimentacion", hechas)


# ---------------------------------------------------------------------------
#  Fase caudal -- lineas por segundo.
# ---------------------------------------------------------------------------

def fase_caudal(datos: dict, destino: Path, hechas: dict) -> None:
    plt = _mpl()
    casos = _casos_de(datos, "caudal")
    if not plt or not casos:
        return
    langs = sorted({c["lang"] for c in casos})

    # (a) el caudal contra el tamano.  Lo que se mira es si BAJA: un caudal que
    # cae al crecer el programa es la misma noticia que un exponente por encima
    # de 1, dicha en las unidades en las que se piensa.
    fig, ax = plt.subplots(figsize=(10, 6))
    hay = False
    for ln in langs:
        for clave, estilo, alfa in (("bruto_frio", "o-", 1.0),
                                    ("bruto_caliente", "s--", 0.55)):
            pts = sorted((c["lineas"], c.get(clave)) for c in casos
                         if c["lang"] == ln)
            pts = [(x, y) for x, y in pts if y]
            if len(pts) < 2:
                continue
            hay = True
            ax.plot([p[0] for p in pts], [p[1] for p in pts], estilo,
                    linewidth=2, color=_col(ln), alpha=alfa,
                    label="%s (%s)" % (
                        _lab(ln),
                        "frio" if clave.endswith("frio") else "caliente"))
    if hay:
        ax.set_xscale("log")
        ax.set_xlabel("lineas del programa (log)")
        ax.set_ylabel("lineas compiladas por segundo")
        ax.set_title("Caudal de cada compilador\n"
                     "(plano = escala bien; si BAJA al crecer, hay algo "
                     "superlineal)", fontsize=11, fontweight="bold")
        ax.grid(alpha=0.3, which="both")
        ax.legend(fontsize=8, ncol=2)
        _guardar(plt, fig, destino, "fq_caudal", hechas)
    else:
        plt.close(fig)

    # (b) el mejor de cada uno, que es la cifra con la que se estima un
    # proyecto futuro.
    mejor = datos.get("caudal") or []
    if mejor:
        mejor = sorted(mejor, key=lambda r: r["lineas_por_segundo"])
        fig, ax = plt.subplots(figsize=(9, max(3, 0.5 * len(mejor) + 2)))
        ax.barh([_lab(r["lang"]) for r in mejor],
                [r["lineas_por_segundo"] for r in mejor],
                color=[_col(r["lang"]) for r in mejor])
        for i, r in enumerate(mejor):
            ax.text(r["lineas_por_segundo"], i,
                    "  100k lineas en %.1f s" % (100000.0 / r["lineas_por_segundo"]),
                    va="center", fontsize=8, color="#444")
        ax.set_xlabel("lineas por segundo (neto, en frio)")
        ax.set_title("Cuanto codigo digiere cada compilador\n"
                     "(con esto se estima lo que costara un proyecto que aun "
                     "no existe)", fontsize=11, fontweight="bold")
        ax.grid(axis="x", alpha=0.3)
        _guardar(plt, fig, destino, "fq_mejor_caudal", hechas)


# ---------------------------------------------------------------------------
#  Las mismas curvas de crecimiento, pero con el programa REPARTIDO.
#
#  El monolitico mide una sola cosa: digerir codigo.  Un proyecto real ademas
#  abre y resuelve cada unidad, cruza sus interfaces y enlaza, y ese coste no
#  aparece en un fichero suelto por grande que sea.  Publicar solo la curva
#  monolitica y llamarla "compilar" describe un caso que nadie tiene.
#
#  Se lee de la fase `proyecto`, que reparte el MISMO programa en un numero
#  fijo de ficheros y lo mide a varios tamanos.  Sus dos regimenes extremos
#  son el equivalente exacto del par frio/caliente del monolitico:
#      "de cero"      reconstruccion completa sin cache  -> frio
#      "sin cambios"  todo construido y nada tocado      -> caliente
# ---------------------------------------------------------------------------

def _suelo_de(datos: dict, ln: str, frio: bool) -> float:
    """El arranque que toca restar, o 0 si no se midio esa fase."""
    clave = "suelo_frio" if frio else "suelo"
    return float(((datos.get(clave) or {}).get(ln) or {}).get("p50") or 0.0)


def fase_crecimiento_multi(datos: dict, destino: Path, hechas: dict) -> None:
    """Crecimiento, coste por kloc, memoria y cache, con el programa repartido."""
    plt = _mpl()
    casos = [c for c in _casos_de(datos, "2b") if c.get("funciones")]
    if not plt or not casos:
        return
    langs = sorted({c["lang"] for c in casos})

    def _serie(ln: str, regimen: str, campo: str = "p50", div: float = 1.0,
               neto: bool = False):
        """(lineas, valor) de un lenguaje en un regimen, ordenado."""
        out = []
        for c in casos:
            if c["lang"] != ln or c.get("regimen") != regimen:
                continue
            v = (c.get("stats") or {}).get(campo)
            if not v:
                continue
            if neto:
                v = max(0.001, v - _suelo_de(datos, ln, regimen == "de cero"))
            out.append((c["funciones"], v / div))
        return sorted(out)

    n_fich = max((c.get("ficheros") or 0) for c in casos)
    marca = " (%d ficheros)" % n_fich if n_fich else ""

    # (a) tiempo contra lineas, log-log, en los dos regimenes.
    for regimen, etiq, nombre in (("de cero", "en frio", "fm_tiempo_frio"),
                                  ("sin cambios", "en caliente",
                                   "fm_tiempo_caliente")):
        fig, ax = plt.subplots(figsize=(9, 6))
        hay = False
        for ln in langs:
            pts = _serie(ln, regimen, neto=True)
            if len(pts) < 2:
                continue
            hay = True
            ax.plot([p[0] for p in pts], [p[1] for p in pts], "o-",
                    linewidth=2, color=_col(ln), label=_lab(ln))
        if not hay:
            plt.close(fig)
            continue
        ax.set_xscale("log")
        ax.set_yscale("log")
        ax.set_xlabel("lineas del programa (log)")
        ax.set_ylabel("ms sin el arranque (log)")
        ax.set_title("Crecimiento del TIEMPO %s, REPARTIDO%s\n"
                     "(comparar con la misma figura monolitica: la distancia "
                     "entre las dos es el coste de repartirlo)"
                     % (etiq, marca), fontsize=11, fontweight="bold")
        ax.grid(alpha=0.3, which="both")
        ax.legend(fontsize=9)
        _guardar(plt, fig, destino, nombre, hechas)

    # (b) coste por mil lineas, que es donde se ve si repartir cambia la FORMA
    # de la curva o solo la desplaza hacia arriba.
    fig, (a_f, a_c) = plt.subplots(1, 2, figsize=(13, 5), sharey=True)
    hay = False
    for eje, regimen, titulo in ((a_f, "de cero", "en frio"),
                                 (a_c, "sin cambios", "en caliente")):
        for ln in langs:
            pts = [(x, y) for x, y in _serie(ln, regimen, neto=True) if x > 0]
            if len(pts) < 2:
                continue
            hay = True
            eje.plot([p[0] for p in pts],
                     [p[1] / (p[0] / 1000.0) for p in pts], "o-",
                     linewidth=2, color=_col(ln), label=_lab(ln))
        eje.set_xscale("log")
        eje.set_yscale("log")
        eje.set_xlabel("lineas del programa (log)")
        eje.set_title(titulo, fontsize=10)
        eje.grid(alpha=0.3, which="both")
    if hay:
        a_f.set_ylabel("ms por cada mil lineas, sin el arranque (log)")
        # La leyenda va en el panel que TENGA curvas: `hay` puede venir de uno
        # solo -- si una tanda trae el regimen caliente y no el frio, pedirla
        # en el vacio suelta un aviso de matplotlib y deja la figura sin
        # leyenda.
        for eje in (a_f, a_c):
            if eje.get_legend_handles_labels()[0]:
                eje.legend(fontsize=9)
                break
        fig.suptitle("Coste por mil lineas, REPARTIDO%s\n"
                     "(si sube respecto al monolitico, lo que se paga es "
                     "tener modulos, no tener codigo)" % marca,
                     fontsize=11, fontweight="bold")
        _guardar(plt, fig, destino, "fm_coste_por_kloc", hechas)
    else:
        plt.close(fig)

    # (c) memoria.  Solo en frio: los regimenes incrementales se cronometran
    # con `una_medida`, que no mide el pico, y publicar un hueco como si fuera
    # un dato seria peor que no publicarlo.
    for campo, ylab, nombre, porkloc in (
            ("mem_kib", "MiB de pico (log)", "fm_memoria", False),
            ("mem_kib", "MiB de pico por cada mil lineas (log)",
             "fm_memoria_por_kloc", True)):
        fig, ax = plt.subplots(figsize=(9, 5))
        hay = False
        for ln in langs:
            pts = [(x, y) for x, y in
                   _serie(ln, "de cero", campo, 1024.0) if x > 0]
            if len(pts) < 2:
                continue
            hay = True
            ys = [(y / (x / 1000.0) if porkloc else y) for x, y in pts]
            ax.plot([p[0] for p in pts], ys, "o-", linewidth=2,
                    color=_col(ln), label=_lab(ln))
        if not hay:
            plt.close(fig)
            continue
        ax.set_xscale("log")
        ax.set_yscale("log")
        ax.set_xlabel("lineas del programa (log)")
        ax.set_ylabel(ylab)
        ax.set_title("Memoria%s en frio, REPARTIDO%s"
                     % (" por mil lineas" if porkloc else "", marca),
                     fontsize=11, fontweight="bold")
        ax.grid(alpha=0.3, which="both")
        ax.legend(fontsize=9)
        _guardar(plt, fig, destino, nombre, hechas)

    # (d) lo que aporta la cache.  Aqui SI hay algo que reutilizar -- es la
    # diferencia con el fichero suelto, donde un 1.0x es lo esperado --, asi
    # que esta figura dice mas que su gemela monolitica.
    fig, ax = plt.subplots(figsize=(9, 5))
    hay = False
    for ln in langs:
        frio = dict(_serie(ln, "de cero"))
        cal = dict(_serie(ln, "sin cambios"))
        comunes = sorted(set(frio) & set(cal))
        if len(comunes) < 2:
            continue
        hay = True
        ax.plot(comunes, [frio[n] / cal[n] for n in comunes], "o-",
                linewidth=2, color=_col(ln), label=_lab(ln))
    if hay:
        ax.axhline(1.0, color="#444", linestyle=":", linewidth=1.5)
        ax.set_xscale("log")
        ax.set_xlabel("lineas del programa (log)")
        ax.set_ylabel("veces mas rapido sin tocar nada")
        ax.set_title("Cuanto aporta la cache con el programa REPARTIDO%s\n"
                     "(reconstruir de cero frente a no haber tocado nada)"
                     % marca, fontsize=11, fontweight="bold")
        ax.grid(alpha=0.3, which="both")
        ax.legend(fontsize=9)
        _guardar(plt, fig, destino, "fm_ahorro_cache", hechas)
    else:
        plt.close(fig)


# ---------------------------------------------------------------------------
#  El modelo de DOS variables.
#
#  Un proyecto no se describe con su numero de lineas: tambien importa en
#  cuantos modulos esta, y las dos cosas se pagan por separado.
#
#      t(n, k) = arranque + coste_linea * n + coste_modulo * k
#
#  El banco ya mide las dos pendientes, pero en fases distintas y sin
#  cruzarlas:
#      `proyecto`  varia n con k FIJO   -> da coste_linea
#      `escalado`  varia k con n FIJO   -> da coste_modulo
#  Cada una por separado responde media pregunta, y las dos juntas responden
#  la que se hace de verdad: "mi proyecto tiene 80k lineas en 400 ficheros,
#  ¿cuanto tarda?".  Sin el termino por modulo, un compilador con coste fijo
#  por unidad alto parece barato mientras se le midan proyectos de 20
#  ficheros.
# ---------------------------------------------------------------------------

def fase_modelo_dos_variables(datos: dict, destino: Path, hechas: dict) -> None:
    """Coste por linea y coste por modulo, juntos, y lo que predicen."""
    plt = _mpl()
    if not plt:
        return
    casos = datos.get("casos") or []
    # coste_linea: de `proyecto` de cero, que varia n con k fijo.
    por_linea, k_fijo = {}, {}
    for c in casos:
        if c.get("fase") != "2b" or c.get("regimen") != "de cero":
            continue
        v = (c.get("stats") or {}).get("p50")
        if c.get("funciones") and v:
            por_linea.setdefault(c["lang"], []).append((c["funciones"], v))
            k_fijo[c["lang"]] = c.get("ficheros") or 0
    # coste_modulo: de `escalado` por modulos, que varia k con n fijo.
    por_modulo = {}
    for c in casos:
        if c.get("escalado") != "modulos":
            continue
        v = (c.get("stats") or {}).get("p50")
        if c.get("ficheros") and v:
            por_modulo.setdefault(c["lang"], []).append((c["ficheros"], v))

    # Es la UNICA figura que necesita dos fases a la vez.  Si solo corrio una,
    # no sale -- y sin decirlo pareceria que el banco no sabe hacerla, cuando
    # lo que pasa es que le falta la mitad de los datos.
    if bool(por_linea) != bool(por_modulo):
        falta = "escalado" if por_linea else "proyecto"
        print("[aviso] el modelo de dos variables necesita las fases "
              "`proyecto` (coste por linea) y `escalado` (coste por modulo); "
              "falta `%s`, asi que no se dibuja." % falta)
        return

    modelos = {}
    for ln in sorted(set(por_linea) & set(por_modulo)):
        ml = _recta_af(sorted(por_linea[ln]))
        mm = _recta_af(sorted(por_modulo[ln]))
        if not ml or not mm:
            continue
        # El arranque sale del ajuste por lineas; el termino por modulo se
        # toma solo como PENDIENTE, porque su interseccion ya incluye las
        # 1024 lineas fijas de esa fase y sumarla contaria ese coste dos
        # veces.
        modelos[ln] = {"arranque": ml[0], "por_linea": ml[1],
                       "por_modulo": mm[1], "k_medido": k_fijo.get(ln, 0),
                       "r2_linea": ml[2], "r2_modulo": mm[2]}
    if len(modelos) < 2:
        return

    # (a) las dos pendientes juntas, en barras enfrentadas.  Es lo que ninguna
    # tabla ensena hoy: quien es barato por linea puede ser caro por modulo.
    langs = sorted(modelos)
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(12, 5))
    xs = list(range(len(langs)))
    a1.bar(xs, [modelos[l]["por_linea"] * 1000 for l in langs],
           color=[_col(l) for l in langs])
    a1.set_xticks(xs)
    a1.set_xticklabels([_lab(l) for l in langs], rotation=20, ha="right",
                       fontsize=9)
    a1.set_ylabel("ms por cada mil lineas")
    a1.set_title("Lo que cuesta el CODIGO", fontsize=10, fontweight="bold")
    a1.grid(axis="y", alpha=0.3)
    a2.bar(xs, [modelos[l]["por_modulo"] for l in langs],
           color=[_col(l) for l in langs])
    a2.set_xticks(xs)
    a2.set_xticklabels([_lab(l) for l in langs], rotation=20, ha="right",
                       fontsize=9)
    a2.set_ylabel("ms por cada modulo")
    a2.set_title("Lo que cuesta REPARTIRLO", fontsize=10, fontweight="bold")
    a2.grid(axis="y", alpha=0.3)
    fig.suptitle("Las dos mitades del coste, por separado\n"
                 "(un proyecto muy dividido paga la derecha aunque no crezca "
                 "de tamano)", fontsize=11, fontweight="bold")
    _guardar(plt, fig, destino, "fd_dos_pendientes", hechas)

    # (b) lo que el modelo predice para proyectos REALES: mismas lineas,
    # distinto reparto.  Aqui es donde el termino por modulo cambia el orden
    # entre lenguajes, que es justo lo que un solo eje no puede ensenar.
    fig, ax = plt.subplots(figsize=(10, 5.5))
    ks = [10, 50, 200, 800]
    n_ref = 80000
    ancho = 0.8 / max(1, len(langs))
    for i, ln in enumerate(langs):
        m = modelos[ln]
        ys = [(m["arranque"] + m["por_linea"] * n_ref + m["por_modulo"] * k)
              / 1000.0 for k in ks]
        ax.bar([x + i * ancho for x in range(len(ks))], ys, ancho,
               color=_col(ln), label=_lab(ln))
    ax.set_xticks([x + 0.4 - ancho / 2 for x in range(len(ks))])
    ax.set_xticklabels(["%d modulos" % k for k in ks])
    ax.set_ylabel("segundos que predice el modelo")
    ax.set_title("Un proyecto de %s lineas, repartido de varias formas\n"
                 "(PREDICCION del modelo, no medida: el reparto sale de una "
                 "fase y el tamano de otra)" % _fmt_lineas(n_ref),
                 fontsize=11, fontweight="bold")
    ax.grid(axis="y", alpha=0.3)
    ax.legend(fontsize=9)
    _guardar(plt, fig, destino, "fd_prediccion_proyecto", hechas)


# ---------------------------------------------------------------------------
#  Lo incremental, contra el TAMANO del proyecto.
#
#  La fase `proyecto` ya mide que cuesta tocar un comentario, un cuerpo o una
#  interfaz, pero solo publicaba esas cifras a un tamano cada vez.  La
#  pregunta que decide si un proyecto grande es usable no es cuanto cuesta
#  tocar una interfaz, es si ESE coste crece con el proyecto:
#
#      si tocar una interfaz cuesta lo mismo con 6k lineas que con 100k, la
#      invalidacion es proporcional a lo TOCADO y el proyecto puede crecer;
#      si crece con el total, es proporcional al PROYECTO, y eso se sufre
#      mucho antes que cualquier cifra de compilacion completa.
#
#  Una curva plana aqui vale mas que ser rapido de cero.
# ---------------------------------------------------------------------------

_REGIMENES = ("sin cambios", "1 comentario", "1 cuerpo", "1 interfaz",
              "mitad de los modulos")
_REG_ESTILO = {"sin cambios": (":", 1.4), "1 comentario": ("-.", 1.6),
               "1 cuerpo": ("--", 1.8), "1 interfaz": ("-", 2.4),
               "mitad de los modulos": ("-", 1.4)}


def fase_incremental(datos: dict, destino: Path, hechas: dict) -> None:
    """Como cambia el coste de reconstruir al crecer el proyecto."""
    plt = _mpl()
    casos = [c for c in _casos_de(datos, "2b") if c.get("funciones")]
    if not plt or not casos:
        return
    # Un solo eje de paralelismo: mezclar el secuencial con el de la maquina
    # en la misma curva daria saltos que parecen del compilador y son del
    # numero de hilos.  Se prefiere el secuencial, que es el comparable.
    ejes = {c.get("paralelismo") for c in casos}
    eje = "secuencial" if "secuencial" in ejes else (
        sorted(x for x in ejes if x)[0] if any(ejes) else None)
    if eje:
        casos = [c for c in casos if c.get("paralelismo") == eje]
    langs = sorted({c["lang"] for c in casos})
    presentes = [r for r in _REGIMENES
                 if any(c.get("regimen") == r for c in casos)]
    if not presentes or not langs:
        return

    def _serie(ln, regimen):
        out = []
        for c in casos:
            if c["lang"] != ln or c.get("regimen") != regimen:
                continue
            v = (c.get("stats") or {}).get("p50")
            if v:
                out.append((c["funciones"], v))
        return sorted(out)

    # (a) una rejilla: un panel por lenguaje, una curva por regimen.  Asi se
    # compara DENTRO de un lenguaje (que regimen cuesta mas) y ENTRE ellos
    # (quien tiene las curvas mas planas) sin dos figuras distintas.
    cols = min(3, len(langs))
    filas = (len(langs) + cols - 1) // cols
    fig, ejes_g = plt.subplots(filas, cols, figsize=(5.2 * cols, 4.2 * filas),
                               squeeze=False, sharex=True, sharey=True)
    hay = False
    for i, ln in enumerate(langs):
        ax = ejes_g[i // cols][i % cols]
        for reg in presentes:
            pts = _serie(ln, reg)
            if len(pts) < 2:
                continue
            hay = True
            estilo, grosor = _REG_ESTILO.get(reg, ("-", 1.8))
            ax.plot([p[0] for p in pts], [p[1] for p in pts], estilo,
                    marker="o", markersize=4, linewidth=grosor, label=reg)
        ax.set_xscale("log")
        ax.set_yscale("log")
        ax.set_title(_lab(ln), fontsize=10, color=_col(ln),
                     fontweight="bold")
        ax.grid(alpha=0.3, which="both")
    for j in range(len(langs), filas * cols):
        ejes_g[j // cols][j % cols].axis("off")
    if hay:
        ejes_g[0][0].legend(fontsize=8)
        for c in range(cols):
            ejes_g[filas - 1][c].set_xlabel("lineas del proyecto (log)")
        for f in range(filas):
            ejes_g[f][0].set_ylabel("ms de reconstruccion (log)")
        fig.suptitle("Que cuesta reconstruir, segun crece el proyecto"
                     "%s\n(plana = el coste depende de lo TOCADO;  si sube, "
                     "depende del PROYECTO)"
                     % ("  --  eje %s" % eje if eje else ""),
                     fontsize=12, fontweight="bold")
        _guardar(plt, fig, destino, "fi_regimenes", hechas)
    else:
        plt.close(fig)

    # (b) el resumen en una figura: lo que cuesta tocar una interfaz frente a
    # no tocar nada.  Es la razon que de verdad se sufre -- "he cambiado una
    # linea, ¿por que tarda tanto?" -- y si sube con el tamano, el compilador
    # esta invalidando de mas.
    if "1 interfaz" not in presentes or "sin cambios" not in presentes:
        return
    fig, ax = plt.subplots(figsize=(9, 5.5))
    hay = False
    for ln in langs:
        base = dict(_serie(ln, "sin cambios"))
        toca = dict(_serie(ln, "1 interfaz"))
        comunes = sorted(set(base) & set(toca))
        if len(comunes) < 2:
            continue
        hay = True
        ax.plot(comunes, [toca[n] / base[n] for n in comunes], "o-",
                linewidth=2.2, color=_col(ln), label=_lab(ln))
    if hay:
        ax.axhline(1.0, color="#444", linestyle=":", linewidth=1.5)
        ax.set_xscale("log")
        ax.set_xlabel("lineas del proyecto (log)")
        ax.set_ylabel("veces mas que no tocar nada")
        ax.set_title("Lo que cuesta tocar UNA interfaz%s\n"
                     "(si la linea sube, la invalidacion crece con el "
                     "proyecto y no con el cambio)"
                     % ("  --  eje %s" % eje if eje else ""),
                     fontsize=11, fontweight="bold")
        ax.grid(alpha=0.3, which="both")
        ax.legend(fontsize=9)
        _guardar(plt, fig, destino, "fi_interfaz_vs_nada", hechas)
    else:
        plt.close(fig)


# ---------------------------------------------------------------------------
#  Cruces: con cuanto codigo un lenguaje adelanta a otro.
#
#  Un compilador se describe con dos numeros que tiran en sentidos opuestos:
#  lo que cuesta ARRANCAR (fijo, se paga igual con diez lineas que con cien
#  mil) y lo que cuesta cada LINEA.  Quien arranca antes gana en los programas
#  pequenos; quien cuesta menos por linea acaba ganando si el programa crece
#  bastante.  La pregunta util no es "quien es mas rapido" sino "a partir de
#  cuantas lineas", y esa cifra no esta en ninguna tabla: hay que sacarla de
#  los dos numeros a la vez.
#
#  Con `t(n) = arranque + coste * n` para cada uno, A adelanta a B donde
#
#      arranque_A + coste_A * n  <  arranque_B + coste_B * n
#      (arranque_A - arranque_B) <  (coste_B - coste_A) * n
#
#  y de ahi salen los cuatro casos, incluidos los dos que no son un numero:
#  que A gane SIEMPRE (arranca antes y ademas crece mas despacio) y que no
#  gane NUNCA (arranca despues y encima crece mas deprisa).
# ---------------------------------------------------------------------------

def _recta_af(pts: list):
    """Ajusta `y = a + b*x` por minimos cuadrados.  Devuelve (a, b, r2).

    Sobre el valor TOTAL, no sobre el neto: aqui el arranque no es algo que
    haya que quitar, es la mitad de la respuesta -- es lo que hace que un
    compilador gane en los programas pequenos.  Sale como interseccion del
    mismo ajuste del que sale la pendiente, sin restarlo a mano.
    """
    utiles = [(x, y) for x, y in pts if x > 0 and y is not None and y > 0]
    if len(utiles) < 2:
        return None
    n = len(utiles)
    mx = sum(x for x, _ in utiles) / n
    my = sum(y for _, y in utiles) / n
    den = sum((x - mx) ** 2 for x, _ in utiles)
    if den <= 0:
        return None
    b = sum((x - mx) * (y - my) for x, y in utiles) / den
    a = my - b * mx
    tot = sum((y - my) ** 2 for _, y in utiles)
    res = sum((y - (a + b * x)) ** 2 for x, y in utiles)
    r2 = 1.0 - (res / tot) if tot > 0 else 1.0
    return (a, b, r2)


def _cruce(ma, mb):
    """¿Con cuanto codigo adelanta A a B?  Devuelve (estado, lineas).

    Estados, y por que hacen falta los cuatro:
      "siempre"  A gana desde la primera linea y no lo pierde.
      "desde"    A pierde al principio y gana a partir de esas lineas.
      "hasta"    A gana al principio y lo pierde a partir de esas lineas.
      "nunca"    A no gana en ningun tamano.
    Las lineas valen None en "siempre" y "nunca": ahi no hay cruce que dar, y
    devolver un cero o un infinito se leeria como si lo hubiera.
    """
    a_a, b_a, _ = ma
    a_b, b_b, _ = mb
    den = b_b - b_a
    # Pendientes iguales: las rectas son paralelas y no se cortan nunca.  Quien
    # arranca antes gana en todos los tamanos, y el que no, en ninguno.
    if abs(den) <= 1e-12 * max(abs(b_a), abs(b_b), 1e-12):
        return ("siempre", None) if a_a < a_b else ("nunca", None)
    n = (a_a - a_b) / den
    if den > 0:                       # A crece mas despacio: gana de n en adelante
        return ("siempre", None) if n <= 0 else ("desde", n)
    return ("nunca", None) if n <= 0 else ("hasta", n)   # A crece mas deprisa


def _fmt_lineas(n: float) -> str:
    """Un tamano de programa en la unidad que se lea de un vistazo."""
    if n >= 1e6:
        return "%.1fM" % (n / 1e6)
    if n >= 1e3:
        return "%.0fk" % (n / 1e3)
    return "%.0f" % n


_CRUCE_COLOR = {"siempre": "#2e7d32", "desde": "#a5d6a7",
                "hasta": "#ffcc80", "nunca": "#ef9a9a"}


def _matriz_cruces(plt, modelos: dict, medido_max: float, titulo: str,
                   unidad: str, nombre: str, destino: Path,
                   hechas: dict) -> None:
    """La tabla de quien adelanta a quien, y con cuanto codigo."""
    langs = sorted(modelos)
    if len(langs) < 2:
        return
    k = len(langs)
    fig, ax = plt.subplots(figsize=(1.55 * k + 3.2, 1.15 * k + 2.8))
    for i, la in enumerate(langs):
        for j, lb in enumerate(langs):
            y = k - 1 - i
            if i == j:
                ax.add_patch(plt.Rectangle((j, y), 1, 1, facecolor="#eeeeee",
                                           edgecolor="white", linewidth=2))
                continue
            estado, n = _cruce(modelos[la], modelos[lb])
            ax.add_patch(plt.Rectangle((j, y), 1, 1,
                                       facecolor=_CRUCE_COLOR[estado],
                                       edgecolor="white", linewidth=2))
            if n is None:
                txt, sub = estado, ""
            else:
                txt = _fmt_lineas(n)
                # Un cruce mas alla de lo medido es EXTRAPOLACION, y se dice.
                # La recta se ajusto con tres tamanos; que la prediccion caiga
                # fuera de ese rango no la invalida, pero cambia lo que se
                # puede afirmar con ella.
                sub = ("%s\n(extrapolado)" % estado if n > medido_max
                       else estado)
            ax.text(j + 0.5, y + 0.58, txt, ha="center", va="center",
                    fontsize=11, fontweight="bold", color="#212121")
            if sub:
                ax.text(j + 0.5, y + 0.26, sub, ha="center", va="center",
                        fontsize=7, color="#424242")
    ax.set_xlim(0, k)
    ax.set_ylim(0, k)
    ax.set_xticks([j + 0.5 for j in range(k)])
    ax.set_yticks([k - 1 - i + 0.5 for i in range(k)])
    ax.set_xticklabels([_lab(x) for x in langs], rotation=20, ha="right",
                       fontsize=9)
    ax.set_yticklabels([_lab(x) for x in langs], fontsize=9)
    ax.set_xlabel("...adelanta a este", fontsize=9)
    ax.set_ylabel("este lenguaje...", fontsize=9)
    for lado in ("top", "right", "bottom", "left"):
        ax.spines[lado].set_visible(False)
    ax.tick_params(length=0)
    ax.set_title("%s\n(cada celda son LINEAS de codigo; lo que se compara son "
                 "%s)" % (titulo, unidad), fontsize=11, fontweight="bold")
    manijas = [plt.Rectangle((0, 0), 1, 1, facecolor=_CRUCE_COLOR[e])
               for e in ("siempre", "desde", "hasta", "nunca")]
    ax.legend(manijas,
              ["gana en todos los tamanos",
               "gana a partir de ese tamano",
               "gana solo por debajo de ese tamano",
               "no gana en ningun tamano"],
              loc="upper center", bbox_to_anchor=(0.5, -0.13), ncol=2,
              fontsize=8, frameon=False)
    _guardar(plt, fig, destino, nombre, hechas)


def _modelo_lineas(plt, modelos: dict, medido_max: float, titulo: str,
                   ylab: str, nombre: str, destino: Path,
                   hechas: dict, nota: str = "") -> None:
    """Las rectas ajustadas, prolongadas, con los cruces marcados.

    La matriz da la cifra; esto da la forma -- se ve de un vistazo quien
    arranca antes, quien crece mas despacio y donde se cortan.  El tramo
    medido va solido y el prolongado a rayas, porque no valen lo mismo.
    """
    if len(modelos) < 2:
        return
    langs = sorted(modelos)
    cruces = []
    for i, la in enumerate(langs):
        for lb in langs[i + 1:]:
            estado, n = _cruce(modelos[la], modelos[lb])
            if n is not None:
                cruces.append(n)
    # Hasta el ultimo cruce con margen, o diez veces lo medido si no hay
    # ninguno.  Sin tope la figura la marcaria un cruce a diez millones de
    # lineas y el rango util quedaria aplastado contra el eje.
    tope = min(max(cruces) * 1.3, medido_max * 200.0) if cruces else medido_max * 10.0
    tope = max(tope, medido_max * 1.5)
    fig, ax = plt.subplots(figsize=(10, 6))
    for ln in langs:
        a, b, r2 = modelos[ln]
        ax.plot([0, medido_max], [a, a + b * medido_max], "-", linewidth=2.2,
                color=_col(ln), label="%s  (R2 %.2f)" % (_lab(ln), r2))
        ax.plot([medido_max, tope], [a + b * medido_max, a + b * tope], "--",
                linewidth=1.6, color=_col(ln), alpha=0.75)
    for i, la in enumerate(langs):
        for lb in langs[i + 1:]:
            estado, n = _cruce(modelos[la], modelos[lb])
            if n is None or n > tope:
                continue
            a, b, _ = modelos[la]
            ax.plot([n], [a + b * n], "o", markersize=7, color="#212121",
                    markerfacecolor="white", markeredgewidth=1.6, zorder=5)
    ax.axvline(medido_max, color="#666", linestyle=":", linewidth=1.4)
    ax.text(medido_max, ax.get_ylim()[1], " fin de lo medido ", fontsize=8,
            color="#666", va="top")
    ax.set_xlabel("lineas del programa")
    ax.set_ylabel(ylab)
    ax.set_title("%s\n(solido = medido; a rayas = prolongado; los puntos son "
                 "los cruces)" % titulo, fontsize=11, fontweight="bold")
    ax.grid(alpha=0.3)
    ax.legend(fontsize=9)
    # El aviso va al pie y no pegado al eje: como etiqueta del eje Y crecia
    # hasta salirse de la figura y dejaba la unidad ilegible, que es
    # justamente lo que el eje tiene que decir.
    if nota:
        fig.text(0.5, -0.02, nota, ha="center", fontsize=8, color="#8a6d3b")
    _guardar(plt, fig, destino, nombre, hechas)


def fase_cruces(datos: dict, destino: Path, hechas: dict) -> None:
    """Con cuanto codigo adelanta cada lenguaje a cada otro, y en memoria.

    Se hace DOS veces, y no es lo mismo:

      monolitico  un solo fichero, de la fase `crecimiento`.  Mide el coste
                  de digerir codigo y nada mas.
      por modulos el mismo programa repartido, de la fase `proyecto`.  Ahi
                  aparece lo que el monolitico no puede ver: abrir y resolver
                  cada unidad, la interfaz entre ellas, el enlazado.

    Publicar solo el primero y llamarlo "compilar" seria quedarse con el caso
    que ningun proyecto real tiene.  Van en figuras separadas porque el cruce
    puede caer en sitios MUY distintos: un compilador con coste fijo por
    modulo alto puede ganar en monolitico y perder repartido al mismo tamano.
    """
    plt = _mpl()
    if not plt:
        return

    def _dibuja(casos, x_de, ejes, sufijo, regimen):
        langs = sorted({c["lang"] for c in casos})
        for saca, titulo, unidad, ylab, n_matriz, n_modelo in ejes:
            modelos, medido, minimo_pts = {}, 0.0, 99
            for ln in langs:
                pts = sorted((x_de(c), saca(c)) for c in casos
                             if c["lang"] == ln and x_de(c) and saca(c))
                m = _recta_af(pts)
                if m is None:
                    continue
                modelos[ln] = m
                medido = max(medido, max(x for x, _ in pts))
                minimo_pts = min(minimo_pts, len(pts))
            if len(modelos) < 2 or medido <= 0:
                continue
            # Con dos tamanos la recta pasa por los dos puntos y el R2 vale 1
            # siempre: no dice nada.  Mismo aviso que da la fase de caudal.
            aviso = ("" if minimo_pts > 2 else
                     "Ajustado con solo %d tamanos: la recta pasa por los "
                     "puntos, asi que su R2 vale 1 siempre y no se puede "
                     "juzgar.  Con --tamanos se piden mas." % minimo_pts)
            _matriz_cruces(plt, modelos, medido, titulo + regimen, unidad,
                           n_matriz + sufijo, destino, hechas)
            _modelo_lineas(plt, modelos, medido, titulo + regimen, ylab,
                           n_modelo + sufijo, destino, hechas, aviso)

    # --- Monolitico: un fichero.  `crecimiento` guarda las lineas REALES.
    mono = _casos_de(datos, "crecimiento")
    if mono:
        _dibuja(mono, lambda c: c.get("lineas"), (
            (lambda c: (c.get("frio") or {}).get("p50"),
             "Con cuanto codigo se adelanta a los demas, EN FRIO",
             "milisegundos", "ms totales, con el arranque dentro",
             "cruces_tiempo_frio", "cruces_modelo_frio"),
            (lambda c: (c.get("caliente") or {}).get("p50"),
             "Con cuanto codigo se adelanta a los demas, EN CALIENTE",
             "milisegundos", "ms totales, con el arranque dentro",
             "cruces_tiempo_caliente", "cruces_modelo_caliente"),
            (lambda c: (c.get("mem_frio_kib") or 0) / 1024.0,
             "Con cuanto codigo pide menos MEMORIA que los demas (en frio)",
             "MiB de pico", "MiB de pico",
             "cruces_memoria", "cruces_modelo_memoria"),
        ), "", "\nun solo fichero")

    # --- Por modulos: el mismo codigo repartido, reconstruido DE CERO.  Los
    # otros regimenes de esa fase (tocar un cuerpo, tocar una interfaz) miden
    # reconstruccion incremental, que es otra pregunta y no se mezcla aqui.
    # El campo se llama `funciones` por historia pero lleva el tamano pedido
    # en LINEAS, que es lo que documenta `--tamanos`.
    multi = [c for c in _casos_de(datos, "2b")
             if c.get("regimen") == "de cero"]
    if multi:
        _dibuja(multi, lambda c: c.get("funciones"), (
            (lambda c: (c.get("stats") or {}).get("p50"),
             "Con cuanto codigo se adelanta a los demas, EN FRIO",
             "milisegundos", "ms totales, con el arranque dentro",
             "cruces_tiempo_frio", "cruces_modelo_frio"),
            (lambda c: ((c.get("stats") or {}).get("mem_kib") or 0) / 1024.0,
             "Con cuanto codigo pide menos MEMORIA que los demas (en frio)",
             "MiB de pico", "MiB de pico",
             "cruces_memoria", "cruces_modelo_memoria"),
        ), "_multi", "\nrepartido en modulos")


# ---------------------------------------------------------------------------
#  Registro: que dibuja cada fase.  Anadir una es poner su funcion aqui.
# ---------------------------------------------------------------------------

POR_FASE = [
    ("1", fase_suelo),
    ("2", fase_completa),
    ("2b", fase_proyecto),
    ("2c", fase_topologia),
    ("2d", fase_familias),
    ("2e", fase_regimen),
    ("3", fase_realimentacion),
    ("crecimiento", fase_crecimiento),
    ("crecimiento-multi", fase_crecimiento_multi),
    ("incremental", fase_incremental),
    ("dos-variables", fase_modelo_dos_variables),
    ("cruces", fase_cruces),
    ("caudal", fase_caudal),
]


def dibujar(datos: dict, destino: Path) -> dict:
    """Todas las graficas que los datos permitan, en @p destino.

    Cada fase escribe las suyas y ninguna depende de las demas: una tanda de
    una sola fase produce sus figuras y ya, sin huecos ni ejes vacios.
    """
    # Se lanza en vez de devolver {} porque el llamante solo imprimia cuando
    # habia figuras: sin matplotlib no salia NI UNA LINEA -- ni figura ni
    # aviso -- y parecia que el banco simplemente no dibujaba.  Su `except` ya
    # existe para esto y publica el motivo.
    motivo = diagnostico_dependencias()
    if motivo:
        raise RuntimeError(motivo)
    destino.mkdir(parents=True, exist_ok=True)
    hechas: dict = {}
    for _id, fn in POR_FASE:
        try:
            fn(datos, destino, hechas)
        except Exception as e:  # noqa: BLE001
            # Una figura que falla no puede llevarse por delante las demas ni
            # la tanda: el banco ya midio, y eso es lo que no se puede perder.
            print("[aviso] grafica de la fase %s: %s" % (_id, e))
    return hechas
