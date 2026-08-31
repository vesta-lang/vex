"""plots.py -- generador de visualizaciones para el benchmark suite.

Cada `plot_*` function genera UNA grafica enfocada en una pregunta
especifica.  Todas dependen de matplotlib + numpy.  Si el caller no
tiene matplotlib, las funciones retornan @c False y el caller cae al
output de texto.

Filosofia: una grafica = una pregunta.  Mejor 8 imagenes claras que 1
imagen sobrecargada.
"""
from __future__ import annotations
import math
import statistics
import sys
from pathlib import Path
from typing import Optional

# Colores fijos por lenguaje para consistencia visual cross-plot.
LANG_COLORS = {
    "vx_interp":   "#ff7f0e",  # naranja
    "vx_jit":      "#2ca02c",  # verde
    # 3 modos AOT con colores DISTINTOS (antes caian al gris fallback "#888"
    # -> indistinguibles en los diagramas).
    "vx_aot_sse2": "#8c564b",  # marron
    "vx_aot_avx":  "#e377c2",  # rosa
    "vx_aot_auto": "#bcbd22",  # oliva
    # El banco de COMPILACION nombra a Vesta de otra forma (`vesta` para el
    # camino que para en el `.velb` y `vesta_aot` para el nativo), asi que sus
    # claves no estaban aqui y las DOS caian al gris fallback: en cada figura
    # de ese banco las dos curvas de Vesta salian del mismo color, que es
    # justo lo que estaba mal.  Se les da el verde del JIT y el marron del
    # AOT para que las dos tandas se lean juntas sin volver a la leyenda.
    "vesta":        "#2ca02c",  # verde, como vx_jit
    "vesta_aot":    "#8c564b",  # marron, como vx_aot_sse2
    "c":            "#1f77b4",  # azul
    "cpp":          "#9467bd",  # violeta
    "python":       "#17becf",  # cyan
    "java":         "#d62728",  # rojo
    "nim":          "#e6b800",  # amarillo Nim
    "go":           "#007d9c",  # teal Go (distinto del cyan de python)
    "rust":         "#CE422B",  # naranja de marca Rust (distinto del gris fallback)
}

# Labels formateados.
LANG_LABELS = {
    "vx_interp":   "Vesta-lang interp",
    "vx_jit":      "Vesta-lang JIT",
    "vx_aot_sse2": "Vesta-lang AOT sse2",
    "vx_aot_avx":  "Vesta-lang AOT avx2",
    "vx_aot_auto": "Vesta-lang AOT auto",
    "vesta":        "Vesta (a .velb)",
    "vesta_aot":    "Vesta (AOT nativo)",
    "c":            "C (gcc -O3)",
    "cpp":          "C++ (g++ -O3)",
    "python":       "Python",
    "java":         "Java",
    "nim":          "Nim (-d:release)",
    "go":           "Go (gc)",
    "rust":         "Rust (rustc -O)",
}


# Por que no se pudieron dibujar las graficas.  Lo rellena `_try_import` y lo
# lee `generate_all`: sin esto, faltar una libreria salia como doce `FAIL`
# seguidos sin decir de que, y se buscaba el error en las graficas cuando el
# problema era el interprete.  Pasa facil al lanzar con `sudo`: root suele
# tener otro Python, sin los paquetes del usuario.
_MOTIVO_SIN_GRAFICAS = ""


def _try_import():
    """Intenta importar matplotlib + numpy.  Returns (mpl, plt, np) o None."""
    global _MOTIVO_SIN_GRAFICAS
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
        return matplotlib, plt, np
    except ImportError as e:
        _MOTIVO_SIN_GRAFICAS = str(e)
        return None


def diagnostico_dependencias() -> str:
    """Una explicacion con la solucion, o "" si no falta nada.

    Se da el interprete EXACTO con el que hay que instalar, no un `pip install`
    a secas: el fallo tipico es tener matplotlib para el usuario y lanzar el
    banco con `sudo`, y ahi un `pip install` sin mas lo instala otra vez donde
    ya estaba.
    """
    if _try_import() is not None:
        return ""
    return ("faltan las librerias de dibujo (%s).  Instalalas para ESTE "
            "interprete:\n           %s -m pip install matplotlib numpy\n"
            "         Si lanzaste el banco con `sudo`, ojo: root suele tener "
            "otro Python distinto del tuyo." % (
                _MOTIVO_SIN_GRAFICAS or "matplotlib / numpy",
                sys.executable))


def valor(r: dict, lang: str) -> Optional[float]:
    """El tiempo utilizable de @p lang en la fila @p r, o None.

    Un solo sitio donde se decide que es utilizable, porque si cada grafica lo
    decide por su cuenta acaban dibujando poblaciones distintas del mismo dato.

    Se descartan las medidas marcadas como que NO se separan del arranque del
    proceso.  La tabla las ensena con un `~` -- son lo que se midio -- pero
    aqui no valen: al ser casi cero, cualquier razon calculada con ellas
    explota.  El radar se quedo plano justo por eso: bastaba una celda de 0.05
    ms para que el "normalizado al mas rapido" mandara a todos al centro.
    """
    if lang in (r.get("_bajo_suelo") or {}):
        return None
    v = r.get(lang)
    return v if (v is not None and v > 0) else None


def _filter_valid(rows: list[dict], lang: str) -> tuple[list[str], list[float]]:
    """Extrae (nombres, valores) utilizables para un lenguaje."""
    names, vals = [], []
    for r in rows:
        v = valor(r, lang)
        if v is not None:
            names.append(r["bench"])
            vals.append(v)
    return names, vals


# =============================================================================
# Plot 1: dashboard general (1 PNG con 4 paneles resumiendo todo)
# =============================================================================

def plot_dashboard(rows: list[dict], langs: list[str], out_path: Path) -> bool:
    deps = _try_import()
    if not deps:
        return False
    _, plt, np = deps

    fig = plt.figure(figsize=(18, 12))
    gs = fig.add_gridspec(2, 2, hspace=0.32, wspace=0.25)

    # 1.1 Wall time absoluto por bench (log scale).
    ax1 = fig.add_subplot(gs[0, 0])
    _plot_wall_time(ax1, rows, langs)

    # 1.2 Ratio vs C.
    ax2 = fig.add_subplot(gs[0, 1])
    _plot_ratio_vs_c(ax2, rows, langs)

    # 1.3 Ranking (orden ordinal por bench).
    ax3 = fig.add_subplot(gs[1, 0])
    _plot_ranking_heatmap(ax3, rows, langs)

    # 1.4 Speedup Vesta-lang JIT vs interp.
    ax4 = fig.add_subplot(gs[1, 1])
    _plot_vx_speedup(ax4, rows)

    fig.suptitle("VestaVM benchmark suite -- dashboard",
                 fontsize=15, fontweight="bold", y=0.995)
    plt.savefig(out_path, dpi=110, bbox_inches="tight")
    plt.close(fig)
    return True


def _plot_wall_time(ax, rows, langs):
    n_benches = len(rows)
    n_langs = len(langs)
    bar_h = 0.8 / max(1, n_langs)
    y_pos = list(range(n_benches))
    for i, ln in enumerate(langs):
        times = []
        for r in rows:
            v = valor(r, ln)
            times.append(v if (v is not None and v > 0) else float("nan"))
        offset = (i - n_langs / 2 + 0.5) * bar_h
        ax.barh([y + offset for y in y_pos], times, bar_h,
                label=LANG_LABELS.get(ln, ln),
                color=LANG_COLORS.get(ln, "#888"))
    ax.set_yticks(y_pos)
    ax.set_yticklabels([r["bench"] for r in rows], fontsize=9)
    ax.set_xscale("log")
    ax.set_xlabel("Wall time (ms, log scale)")
    ax.set_title("(a) Wall time absoluto por lenguaje")
    ax.legend(loc="lower right", fontsize=8)
    ax.grid(axis="x", which="both", alpha=0.3)


def _plot_ratio_vs_c(ax, rows, langs):
    """Barras: ratio de cada lenguaje vs C (mas alto = mas lento)."""
    if "c" not in langs:
        ax.text(0.5, 0.5, "C no disponible como baseline",
                ha="center", va="center", transform=ax.transAxes)
        return
    n_benches = len(rows)
    other_langs = [ln for ln in langs if ln != "c"]
    bar_h = 0.8 / max(1, len(other_langs))
    y_pos = list(range(n_benches))
    for i, ln in enumerate(other_langs):
        ratios = []
        for r in rows:
            t_c = valor(r, "c")
            t_l = valor(r, ln)
            if t_c is None or t_c <= 0 or t_l is None or t_l <= 0:
                ratios.append(float("nan"))
            else:
                ratios.append(t_l / t_c)
        offset = (i - len(other_langs) / 2 + 0.5) * bar_h
        ax.barh([y + offset for y in y_pos], ratios, bar_h,
                label=LANG_LABELS.get(ln, ln),
                color=LANG_COLORS.get(ln, "#888"))
    ax.axvline(x=1.0, color="grey", linestyle="--", alpha=0.5,
               label="1x (paridad con C)")
    ax.axvline(x=10.0, color="orange", linestyle=":", alpha=0.5,
               label="10x mas lento")
    ax.set_yticks(y_pos)
    ax.set_yticklabels([r["bench"] for r in rows], fontsize=9)
    ax.set_xscale("log")
    ax.set_xlabel("Ratio vs C (mas alto = mas lento)")
    ax.set_title("(b) Comparativa vs C nativo")
    ax.legend(loc="lower right", fontsize=8)
    ax.grid(axis="x", which="both", alpha=0.3)


def _plot_ranking_heatmap(ax, rows, langs):
    """Heatmap de ranking ordinal (1=ganador, N=perdedor) por bench."""
    deps = _try_import()
    if not deps:
        return
    _, plt, np = deps
    n_benches = len(rows)
    n_langs = len(langs)
    matrix = np.full((n_benches, n_langs), np.nan)
    for i, r in enumerate(rows):
        vals_with_idx = []
        for j, ln in enumerate(langs):
            v = valor(r, ln)
            if v is not None and v > 0:
                vals_with_idx.append((v, j))
        vals_with_idx.sort()
        for rank, (_, j) in enumerate(vals_with_idx, 1):
            matrix[i, j] = rank
    im = ax.imshow(matrix, cmap="RdYlGn_r", aspect="auto", vmin=1, vmax=n_langs)
    ax.set_xticks(range(n_langs))
    ax.set_xticklabels([LANG_LABELS.get(ln, ln) for ln in langs],
                       rotation=30, ha="right", fontsize=9)
    ax.set_yticks(range(n_benches))
    ax.set_yticklabels([r["bench"] for r in rows], fontsize=9)
    ax.set_title("(c) Ranking por bench (1 = mas rapido)")
    # Anotaciones con el rank.
    for i in range(n_benches):
        for j in range(n_langs):
            if not math.isnan(matrix[i, j]):
                txt = f"{int(matrix[i, j])}"
                ax.text(j, i, txt, ha="center", va="center",
                        fontsize=10, fontweight="bold",
                        color="white" if matrix[i, j] >= n_langs - 1 else "black")
    plt.colorbar(im, ax=ax, label="Ranking (1=mejor)", fraction=0.04)


def _plot_vx_speedup(ax, rows):
    """Barras del speedup Vesta-lang JIT vs Vesta-lang interp para cada bench."""
    names, speedups = [], []
    for r in rows:
        ti = r.get("vx_interp")
        tj = r.get("vx_jit")
        if ti and ti > 0 and tj and tj > 0:
            names.append(r["bench"])
            speedups.append(ti / tj)
    y_pos = list(range(len(names)))
    colors = ["#2ca02c" if s >= 10 else
              "#1f77b4" if s >= 2 else
              "#ff7f0e" if s >= 1 else "#d62728" for s in speedups]
    ax.barh(y_pos, speedups, color=colors)
    ax.set_yticks(y_pos)
    ax.set_yticklabels(names, fontsize=9)
    ax.set_xlabel("Speedup (interp_ms / JIT_ms)")
    ax.set_title("(d) Vesta-lang JIT vs Vesta-lang interp")
    ax.axvline(x=1.0, color="grey", linestyle="--", alpha=0.5)
    ax.axvline(x=10.0, color="green", linestyle=":", alpha=0.5)
    for i, sp in enumerate(speedups):
        ax.text(sp, i, f" {sp:.1f}x", va="center", fontsize=8)
    ax.grid(axis="x", alpha=0.3)


# =============================================================================
# Plot 2: heatmap puro (matriz bench x lang con log wall time)
# =============================================================================

def plot_heatmap(rows: list[dict], langs: list[str], out_path: Path) -> bool:
    deps = _try_import()
    if not deps:
        return False
    _, plt, np = deps
    n_benches = len(rows)
    n_langs = len(langs)
    # Matriz log10(ms).
    matrix = np.full((n_benches, n_langs), np.nan)
    for i, r in enumerate(rows):
        for j, ln in enumerate(langs):
            v = valor(r, ln)
            if v is not None and v > 0:
                matrix[i, j] = math.log10(v)

    fig, ax = plt.subplots(figsize=(11, max(5, n_benches * 0.5)))
    im = ax.imshow(matrix, cmap="RdYlGn_r", aspect="auto")
    ax.set_xticks(range(n_langs))
    ax.set_xticklabels([LANG_LABELS.get(ln, ln) for ln in langs],
                       rotation=30, ha="right", fontsize=10)
    ax.set_yticks(range(n_benches))
    ax.set_yticklabels([r["bench"] for r in rows], fontsize=10)
    ax.set_title("Heatmap: wall time (ms, log10).  Verde = rapido, rojo = lento")
    # Annotations.
    for i in range(n_benches):
        for j in range(n_langs):
            if not math.isnan(matrix[i, j]):
                ms = 10 ** matrix[i, j]
                txt = f"{ms:.0f}" if ms >= 10 else f"{ms:.1f}"
                ax.text(j, i, f"{txt}ms", ha="center", va="center",
                        fontsize=9, color="black")
    cb = plt.colorbar(im, ax=ax, label="log10(wall time ms)")
    plt.tight_layout()
    plt.savefig(out_path, dpi=110, bbox_inches="tight")
    plt.close(fig)
    return True


# =============================================================================
# Plot 3: radar / spider chart por lenguaje
# =============================================================================

def plot_radar(rows: list[dict], langs: list[str], out_path: Path) -> bool:
    """Radar chart: cada lenguaje tiene un poligono que muestra su 'perfil'
    a traves de los benches.  Eje = bench, distancia al centro = log de
    wall time invertido (mas grande el area = mejor).
    """
    deps = _try_import()
    if not deps:
        return False
    _, plt, np = deps
    n_benches = len(rows)
    if n_benches < 3:
        return False
    # Cerrar el poligono con el primer punto al final.
    angles = np.linspace(0, 2 * np.pi, n_benches, endpoint=False).tolist()
    angles += [angles[0]]
    bench_names = [r["bench"] for r in rows]

    fig, ax = plt.subplots(figsize=(12, 11),
                            subplot_kw={"projection": "polar"})
    # Para cada lenguaje: 1/wall_time normalizado a [0, 1].
    max_inv = 0.0
    inv_data = {}
    for ln in langs:
        invs = []
        for r in rows:
            v = valor(r, ln)
            invs.append(1.0 / v if (v is not None and v > 0) else 0.0)
        inv_data[ln] = invs
        max_inv = max(max_inv, max(invs) if invs else 0.0)
    if max_inv <= 0:
        return False
    for ln in langs:
        invs = inv_data[ln]
        norm = [x / max_inv for x in invs]
        norm += [norm[0]]
        ax.plot(angles, norm, "o-", linewidth=2,
                label=LANG_LABELS.get(ln, ln),
                color=LANG_COLORS.get(ln, "#888"))
        ax.fill(angles, norm, alpha=0.10,
                color=LANG_COLORS.get(ln, "#888"))
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(bench_names, fontsize=10)
    ax.set_yticks([0.2, 0.4, 0.6, 0.8, 1.0])
    ax.set_yticklabels(["20%", "40%", "60%", "80%", "100%"], fontsize=8)
    ax.set_ylim(0, 1.05)
    ax.set_title("Perfil de rendimiento por lenguaje\n"
                 "(area mayor = mejor; normalizado al mas rapido)",
                 fontsize=12, pad=20)
    ax.legend(loc="upper right", bbox_to_anchor=(1.3, 1.1), fontsize=9)
    plt.tight_layout()
    plt.savefig(out_path, dpi=110, bbox_inches="tight")
    plt.close(fig)
    return True


# =============================================================================
# Plot 4: box plot de runs individuales por bench
# =============================================================================

def plot_boxplot_variability(rows: list[dict], langs: list[str],
                              out_path: Path) -> bool:
    """Para cada bench, muestra los runs individuales como box plot.
    Permite ver variabilidad / outliers entre corridas."""
    deps = _try_import()
    if not deps:
        return False
    _, plt, np = deps

    # Filtrar benches con runs disponibles.
    valid_benches = [r for r in rows if r.get("_runs")]
    if not valid_benches:
        return False
    n = len(valid_benches)
    cols = min(3, n)
    rows_n = (n + cols - 1) // cols

    fig, axes = plt.subplots(rows_n, cols, figsize=(6 * cols, 4.5 * rows_n),
                              squeeze=False)
    for k, r in enumerate(valid_benches):
        ax = axes[k // cols][k % cols]
        data = []
        labels = []
        colors = []
        for ln in langs:
            runs = r.get("_runs", {}).get(ln, [])
            if runs:
                data.append(runs)
                labels.append(LANG_LABELS.get(ln, ln))
                colors.append(LANG_COLORS.get(ln, "#888"))
        if not data:
            ax.set_visible(False)
            continue
        bp = ax.boxplot(data, labels=labels, patch_artist=True,
                         widths=0.6, showmeans=True)
        for patch, c in zip(bp["boxes"], colors):
            patch.set_facecolor(c)
            patch.set_alpha(0.6)
        ax.set_yscale("log")
        ax.set_title(r["bench"], fontweight="bold")
        ax.set_ylabel("Wall time (ms, log)")
        ax.tick_params(axis="x", rotation=30, labelsize=8)
        ax.grid(axis="y", which="both", alpha=0.3)
    # Ocultar subplots sobrantes.
    for k in range(n, rows_n * cols):
        axes[k // cols][k % cols].set_visible(False)

    fig.suptitle("Variabilidad de runs individuales por bench\n"
                 "(box = IQR, linea = mediana, triangulo = media, "
                 "puntos = outliers)",
                 fontsize=13, y=1.005)
    plt.tight_layout()
    plt.savefig(out_path, dpi=110, bbox_inches="tight")
    plt.close(fig)
    return True


# =============================================================================
# Plot 5: per-bench (un PNG por bench con detalle individual)
# =============================================================================

def _resumen(runs: list[float]) -> Optional[dict]:
    """p50 / cuartiles / MAD de una serie de medidas.

    Duplica a proposito lo minimo del resumen del corredor: las graficas se
    generan tambien desde un JSON antiguo, y depender de la version del
    corredor para dibujar un dato que ya esta guardado seria acoplarlas sin
    necesidad."""
    if not runs:
        return None
    s = sorted(runs)
    n = len(s)

    def pct(q):
        if n == 1:
            return s[0]
        i = q * (n - 1)
        lo = int(i)
        hi = min(lo + 1, n - 1)
        return s[lo] + (s[hi] - s[lo]) * (i - lo)

    p50 = statistics.median(s)
    return {"p50": p50, "q1": pct(0.25), "q3": pct(0.75),
            "mad": statistics.median([abs(x - p50) for x in s]),
            "min": s[0], "max": s[-1]}


def plot_per_bench(rows: list[dict], langs: list[str],
                    out_dir: Path, suelo: Optional[dict] = None) -> int:
    """Genera 1 PNG por bench con barras horizontales + valores.
    Retorna numero de plots generados."""
    deps = _try_import()
    if not deps:
        return 0
    _, plt, np = deps
    out_dir.mkdir(parents=True, exist_ok=True)
    suelo = suelo or {}
    count = 0
    for r in rows:
        valid = [(ln, valor(r, ln)) for ln in langs
                 if valor(r, ln) is not None]
        if len(valid) < 2:
            continue
        valid.sort(key=lambda x: x[1])
        names = [LANG_LABELS.get(ln, ln) for ln, _ in valid]
        vals = [v for _, v in valid]
        colors = [LANG_COLORS.get(ln, "#888") for ln, _ in valid]
        fastest = vals[0]
        ratios = [v / fastest for v in vals]

        # Dispersion real de cada barra y suelo del lenguaje.  Una barra sin
        # esto invita a leer como diferencia lo que puede ser la maquina.
        corridas = r.get("_runs", {}) or {}
        err_lo, err_hi, pisos = [], [], []
        for ln, v in valid:
            st = _resumen(corridas.get(ln) or [])
            # La dispersion se calcula sobre las muestras CRUDAS y se aplica
            # como desplazamiento: restar el suelo mueve el centro, no cambia lo
            # que la medida se movia.
            err_lo.append(max(0.0, st["p50"] - st["q1"]) if st else 0.0)
            err_hi.append(max(0.0, st["q3"] - st["p50"]) if st else 0.0)
            pisos.append((suelo.get(ln) or {}).get("p50") or 0.0)

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, max(3, len(valid) * 0.55)))
        # Panel 1: tiempo absoluto.
        bars = ax1.barh(names, vals, color=colors, alpha=0.85,
                        xerr=[err_lo, err_hi], capsize=3,
                        error_kw={"ecolor": "#333", "elinewidth": 1.2})
        # La barra de color es el tiempo del CoDIGO; el arranque del lenguaje va
        # APILADO detras, en gris.  El total es lo que marcaria un cronometro
        # por fuera, asi que el grafico dice las dos cosas a la vez: cuanto vale
        # el codigo, y cuanto hay que pagar solo por echar a andar el proceso.
        if any(p > 0 for p in pisos):
            ax1.barh(names, pisos, left=vals, color="#000000", alpha=0.25,
                     label="arranque del lenguaje")
            ax1.legend(loc="lower right", fontsize=8)
        ax1.set_xscale("log")
        ax1.set_xlabel("ms (log): color = codigo, gris = arranque.  "
                       "Barra de error = IQR de las muestras")
        ax1.set_title(f"{r['bench']} -- tiempo absoluto")
        for bar, v, ln in zip(bars, vals, [x[0] for x in valid]):
            st = _resumen(corridas.get(ln) or [])
            etiqueta = f" {v:.1f} ms"
            if st and st["p50"] > 0:
                etiqueta += f"  +-{100.0 * st['mad'] / st['p50']:.0f}%"
            ax1.text(v, bar.get_y() + bar.get_height() / 2,
                     etiqueta, va="center", fontsize=9)
        ax1.grid(axis="x", which="both", alpha=0.3)

        # Panel 2: ratio vs el mas rapido (slowdown).
        bars2 = ax2.barh(names, ratios, color=colors, alpha=0.85)
        ax2.set_xlabel(f"Slowdown vs {names[0]} (1x = mas rapido)")
        ax2.set_title(f"{r['bench']} -- relativo")
        ax2.axvline(x=1.0, color="grey", linestyle="--", alpha=0.5)
        for bar, ratio in zip(bars2, ratios):
            ax2.text(ratio, bar.get_y() + bar.get_height() / 2,
                     f" {ratio:.2f}x", va="center", fontsize=9)
        ax2.grid(axis="x", alpha=0.3)

        plt.tight_layout()
        plt.savefig(out_dir / f"{r['bench']}.png", dpi=100,
                    bbox_inches="tight")
        plt.close(fig)
        count += 1
    return count


# =============================================================================
# Plot 6: scatter ratio vs C en eje X, langs en Y (dispersion)
# =============================================================================

def plot_scatter_ratio(rows: list[dict], langs: list[str],
                        out_path: Path) -> bool:
    """Scatter: cada punto es (ratio_vs_C, lang) -- ver dispersion entre
    benches por lenguaje."""
    deps = _try_import()
    if not deps:
        return False
    _, plt, np = deps
    if "c" not in langs:
        return False
    other_langs = [ln for ln in langs if ln != "c"]
    fig, ax = plt.subplots(figsize=(14, 7))
    for i, ln in enumerate(other_langs):
        ratios = []
        names_ok = []
        for r in rows:
            tc = valor(r, "c")
            tl = valor(r, ln)
            if tc and tc > 0 and tl and tl > 0:
                ratios.append(tl / tc)
                names_ok.append(r["bench"])
        if not ratios:
            continue
        y = [i] * len(ratios)
        ax.scatter(ratios, y, s=120,
                   color=LANG_COLORS.get(ln, "#888"),
                   alpha=0.75, edgecolors="black", linewidth=0.5,
                   label=LANG_LABELS.get(ln, ln))
        # Anotaciones por punto.
        for r_val, name in zip(ratios, names_ok):
            ax.annotate(name, (r_val, i),
                         xytext=(0, 8), textcoords="offset points",
                         fontsize=7, ha="center", alpha=0.8)
    ax.axvline(x=1.0, color="grey", linestyle="--", alpha=0.5,
                label="1x (paridad C)")
    ax.axvline(x=10.0, color="orange", linestyle=":", alpha=0.5,
                label="10x")
    ax.set_xscale("log")
    ax.set_yticks(range(len(other_langs)))
    ax.set_yticklabels([LANG_LABELS.get(ln, ln) for ln in other_langs])
    ax.set_xlabel("Ratio vs C (log scale)")
    ax.set_title("Dispersion de slowdown vs C por bench y lenguaje\n"
                 "Cada punto es un bench.  Cuanto mas a la izq = mejor.")
    ax.legend(loc="lower right", fontsize=9)
    ax.grid(axis="x", which="both", alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_path, dpi=110, bbox_inches="tight")
    plt.close(fig)
    return True


# =============================================================================
# Plot 7: line chart de ranking (mostrar el orden de cada lang por bench)
# =============================================================================

def plot_ranking_lines(rows: list[dict], langs: list[str],
                        out_path: Path) -> bool:
    """Line chart con rank ordinal de cada lang en cada bench.  Permite
    ver consistencia de cada lang (lineas mas planas = mas consistente)."""
    deps = _try_import()
    if not deps:
        return False
    _, plt, np = deps
    n_benches = len(rows)
    if n_benches < 2:
        return False
    fig, ax = plt.subplots(figsize=(14, 7))
    # Para cada bench, calcular ranks.
    rank_data = {ln: [] for ln in langs}
    for r in rows:
        items = [(ln, valor(r, ln)) for ln in langs
                 if valor(r, ln) is not None]
        items.sort(key=lambda x: x[1])
        ranks = {ln: i + 1 for i, (ln, _) in enumerate(items)}
        for ln in langs:
            rank_data[ln].append(ranks.get(ln))
    x = list(range(n_benches))
    for ln in langs:
        ys = rank_data[ln]
        # NaN para faltantes para que el plot tenga gaps.
        ys_plot = [y if y is not None else float("nan") for y in ys]
        ax.plot(x, ys_plot, "o-", linewidth=2.5, markersize=10,
                label=LANG_LABELS.get(ln, ln),
                color=LANG_COLORS.get(ln, "#888"))
    ax.set_xticks(x)
    ax.set_xticklabels([r["bench"] for r in rows],
                       rotation=30, ha="right", fontsize=9)
    ax.set_yticks(range(1, len(langs) + 1))
    ax.set_ylabel("Ranking (1 = mas rapido)")
    ax.set_title("Ranking por bench: que lenguaje gana donde\n"
                 "(lineas mas planas = mas consistente)")
    ax.invert_yaxis()  # 1 arriba
    ax.legend(loc="lower right", fontsize=9, ncol=2)
    ax.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_path, dpi=110, bbox_inches="tight")
    plt.close(fig)

    # Y ADEMAS, sin quitar nada de lo anterior, dos cosas que el puesto solo no
    # puede decir.  Se emiten aparte porque son otra pregunta, no otra forma de
    # dibujar la misma.
    _plot_ranking_desglose(rows, langs, rank_data,
                           out_path.with_name(out_path.stem + "_desglose"
                                              + out_path.suffix))
    return True


def _plot_ranking_desglose(rows, langs, rank_data, out_path) -> bool:
    """El puesto de cada lenguaje, uno por panel, y CUANTO vale ese puesto.

    Once lineas superpuestas se leen mal, pero adelgazar el grafico tirando
    lenguajes seria cambiar el problema por otro peor.  Aqui se dibuja lo mismo
    una vez por lenguaje -- el suyo resaltado, los demas en gris de fondo -- asi
    que no se pierde ni una medida y cada linea se puede seguir.

    El color del punto anade lo que un puesto NO dice: la DISTANCIA al primero.
    Ser segundo puede ser quedarse a un 2% o a diez veces, y en un ranking
    ordinal las dos cosas se ven igual.
    """
    deps = _try_import()
    if not deps:
        return False
    _, plt, _np = deps
    n = len(rows)
    presentes = [ln for ln in langs if any(v is not None for v in rank_data[ln])]
    if not presentes:
        return False

    # Distancia al ganador de cada bench, por lenguaje (ratio, 1.0 = gana).
    ratios = {ln: [] for ln in presentes}
    for r in rows:
        vals = [r.get(l) for l in presentes
                if r.get(l) is not None and r.get(l, -1) > 0]
        mejor = min(vals) if vals else None
        for ln in presentes:
            v = valor(r, ln)
            ratios[ln].append((v / mejor) if (v and mejor and v > 0) else None)

    cols = 3
    filas = (len(presentes) + cols - 1) // cols
    fig, axes = plt.subplots(filas, cols, figsize=(6.2 * cols, 2.9 * filas),
                             sharex=True, sharey=True)
    axes = list(axes.flatten()) if hasattr(axes, "flatten") else [axes]
    x = list(range(n))
    for i, ln in enumerate(presentes):
        ax = axes[i]
        # Los demas, de fondo: el contexto no se quita, se atenua.
        for otro in presentes:
            if otro == ln:
                continue
            ys = [y if y is not None else float("nan")
                  for y in rank_data[otro]]
            ax.plot(x, ys, "-", linewidth=0.8, color="#cccccc", zorder=1)
        ys = [y if y is not None else float("nan") for y in rank_data[ln]]
        ax.plot(x, ys, "-", linewidth=2.0, zorder=2,
                color=LANG_COLORS.get(ln, "#888"))
        # Cada punto coloreado por su distancia al ganador.
        for xi, (y, rt) in enumerate(zip(ys, ratios[ln])):
            if y != y or rt is None:  # NaN
                continue
            if rt <= 1.05:
                c, s = "#1a9850", 46      # empata con el mejor
            elif rt <= 2.0:
                c, s = "#fdae61", 38      # mismo orden de magnitud
            elif rt <= 10.0:
                c, s = "#d73027", 30
            else:
                c, s = "#7a0177", 24      # otra liga
            ax.scatter([xi], [y], s=s, color=c, zorder=3,
                       edgecolors="white", linewidths=0.6)
        ax.set_title(LANG_LABELS.get(ln, ln), fontsize=10)
        ax.grid(alpha=0.25)
        ax.set_yticks(range(1, len(presentes) + 1))
    for j in range(len(presentes), len(axes)):
        axes[j].set_visible(False)
    if axes:
        axes[0].invert_yaxis()
    # Los nombres de los benches van en todo panel que no tenga otro DEBAJO.
    # Ponerlos solo en la ultima fila deja sin etiquetar los de la penultima
    # cuando la ultima esta incompleta, y esos paneles se vuelven ilegibles.
    for i in range(len(presentes)):
        if i + cols < len(presentes):
            continue
        axes[i].set_xticks(x)
        axes[i].set_xticklabels([r["bench"] for r in rows], rotation=90,
                                fontsize=6)
        axes[i].tick_params(labelbottom=True)

    fig.suptitle("Ranking por lenguaje -- el MISMO dato del 06, una linea por "
                 "panel para poder seguirla.\n"
                 "El color del punto dice cuanto vale el puesto: "
                 "verde = a menos del 5% del mejor,  naranja = hasta 2x,  "
                 "rojo = hasta 10x,  morado = mas de 10x",
                 fontsize=11)
    plt.tight_layout(rect=(0, 0, 1, 0.94))
    plt.savefig(out_path, dpi=110, bbox_inches="tight")
    plt.close(fig)
    return True


# =============================================================================
# Plot 8: barras agrupadas (ratio vs C, una grafica por bench)
# =============================================================================

def plot_grouped_ratio(rows: list[dict], langs: list[str],
                        out_path: Path) -> bool:
    """Bar chart agrupado: x=bench, grupos de barras = lenguajes,
    altura = ratio vs C."""
    deps = _try_import()
    if not deps:
        return False
    _, plt, np = deps
    if "c" not in langs:
        return False
    other_langs = [ln for ln in langs if ln != "c"]
    n_benches = len(rows)
    n_other = len(other_langs)
    bar_w = 0.8 / max(1, n_other)
    x = np.arange(n_benches)
    fig, ax = plt.subplots(figsize=(max(12, n_benches * 1.5), 7))
    for i, ln in enumerate(other_langs):
        ratios = []
        for r in rows:
            tc = valor(r, "c")
            tl = valor(r, ln)
            if tc and tc > 0 and tl and tl > 0:
                ratios.append(tl / tc)
            else:
                ratios.append(float("nan"))
        offset = (i - n_other / 2 + 0.5) * bar_w
        bars = ax.bar(x + offset, ratios, bar_w,
                       label=LANG_LABELS.get(ln, ln),
                       color=LANG_COLORS.get(ln, "#888"),
                       alpha=0.85)
        # Anotaciones.
        for bar, ratio in zip(bars, ratios):
            if not math.isnan(ratio):
                ax.text(bar.get_x() + bar.get_width() / 2,
                        ratio * 1.05, f"{ratio:.1f}",
                        ha="center", fontsize=7, rotation=0)
    ax.axhline(y=1.0, color="grey", linestyle="--", alpha=0.5,
                label="1x = paridad C")
    ax.set_yscale("log")
    ax.set_xticks(x)
    ax.set_xticklabels([r["bench"] for r in rows],
                       rotation=30, ha="right")
    ax.set_ylabel("Ratio vs C (log)")
    ax.set_title("Slowdown vs C por bench (cada grupo = un bench)")
    ax.legend(loc="upper left", fontsize=9, ncol=2)
    ax.grid(axis="y", which="both", alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_path, dpi=110, bbox_inches="tight")
    plt.close(fig)
    return True


# =============================================================================
# Plot 9: cumulative geometric mean -- "geomean slowdown" per lang
# =============================================================================

def plot_geomean_summary(rows: list[dict], langs: list[str],
                          out_path: Path) -> bool:
    """Bar chart simple con la media geometrica del ratio vs C de cada
    lenguaje a traves de todos los benches.  La media geometrica es
    la metrica correcta para ratios (no la aritmetica).
    """
    deps = _try_import()
    if not deps:
        return False
    _, plt, np = deps
    if "c" not in langs:
        return False
    other_langs = [ln for ln in langs if ln != "c"]
    geomeans = []
    for ln in other_langs:
        ratios = []
        for r in rows:
            tc = valor(r, "c")
            tl = valor(r, ln)
            if tc and tc > 0 and tl and tl > 0:
                ratios.append(tl / tc)
        if not ratios:
            geomeans.append(float("nan"))
        else:
            # Media geometrica = exp(mean(log(x)))
            geomeans.append(math.exp(sum(math.log(r) for r in ratios)
                                       / len(ratios)))
    fig, ax = plt.subplots(figsize=(12, 6))
    # Ordenar por geomean (mejor primero).
    pairs = sorted(zip(other_langs, geomeans),
                    key=lambda p: p[1] if not math.isnan(p[1]) else float("inf"))
    labels = [LANG_LABELS.get(p[0], p[0]) for p in pairs]
    vals = [p[1] for p in pairs]
    colors = [LANG_COLORS.get(p[0], "#888") for p in pairs]
    bars = ax.bar(labels, vals, color=colors, alpha=0.85,
                   edgecolor="black")
    ax.axhline(y=1.0, color="grey", linestyle="--", alpha=0.5,
                label="1x = paridad C")
    ax.set_yscale("log")
    ax.set_ylabel("Geomean slowdown vs C (log)")
    ax.set_title("Resumen global: media geometrica de slowdown vs C\n"
                 "Mas bajo = lenguaje mas rapido en promedio")
    for bar, v in zip(bars, vals):
        if not math.isnan(v):
            ax.text(bar.get_x() + bar.get_width() / 2, v,
                    f"{v:.2f}x", ha="center", va="bottom",
                    fontsize=12, fontweight="bold")
    ax.legend(fontsize=10)
    ax.grid(axis="y", which="both", alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_path, dpi=120, bbox_inches="tight")
    plt.close(fig)
    return True


# =============================================================================
# Plot 10: system info (hardware + versiones de compiladores)
# =============================================================================

def plot_system_info(sys_info: dict, out_path: Path) -> bool:
    """Imagen con info del sistema en el que se corrio el bench.

    Critico para reproducibilidad: incluye CPU, RAM, OS, y version
    EXACTA de cada compilador/runtime usado.

    @param sys_info dict con keys: 'hardware', 'os', 'tooling', 'date'.
    """
    deps = _try_import()
    if not deps:
        return False
    _, plt, _ = deps

    fig, ax = plt.subplots(figsize=(14, 9))
    ax.axis("off")

    # Titulo.
    ax.text(0.5, 0.97, "VestaVM Benchmark Suite -- System Info",
            fontsize=18, fontweight="bold", ha="center",
            transform=ax.transAxes)
    ax.text(0.5, 0.935,
            f"Reporte generado: {sys_info.get('date', '?')}",
            fontsize=10, ha="center", style="italic",
            transform=ax.transAxes, color="#666")

    # Linea separadora.
    ax.axhline(y=0.91, color="black", linewidth=0.5,
                xmin=0.05, xmax=0.95)

    # Seccion 1: Hardware.
    y = 0.86
    ax.text(0.05, y, "[1] HARDWARE", fontsize=13,
            fontweight="bold", color="#1f77b4",
            transform=ax.transAxes)
    y -= 0.04
    hw = sys_info.get("hardware", {})
    hw_items = [
        ("CPU",         hw.get("cpu_model", "?")),
        ("Arquitectura", hw.get("arch", "?")),
        ("Cores (logical/physical)",
            f"{hw.get('cpu_logical', '?')} / {hw.get('cpu_physical', '?')}"),
        ("Frecuencia CPU", hw.get("cpu_freq_mhz", "?")),
        ("RAM total",   hw.get("ram_gb", "?")),
    ]
    for key, val in hw_items:
        ax.text(0.07, y, f"{key}:", fontsize=10, fontweight="bold",
                transform=ax.transAxes)
        ax.text(0.35, y, str(val), fontsize=10,
                transform=ax.transAxes, family="monospace")
        y -= 0.032

    # Seccion 2: OS.
    y -= 0.015
    ax.text(0.05, y, "[2] SISTEMA OPERATIVO", fontsize=13,
            fontweight="bold", color="#2ca02c",
            transform=ax.transAxes)
    y -= 0.04
    os_info = sys_info.get("os", {})
    os_items = [
        ("Plataforma", os_info.get("platform", "?")),
        ("Version", os_info.get("version", "?")),
        ("Kernel/Release", os_info.get("release", "?")),
    ]
    for key, val in os_items:
        ax.text(0.07, y, f"{key}:", fontsize=10, fontweight="bold",
                transform=ax.transAxes)
        ax.text(0.35, y, str(val), fontsize=10,
                transform=ax.transAxes, family="monospace")
        y -= 0.032

    # Seccion 3: Toolchain / runtime versions.
    y -= 0.015
    ax.text(0.05, y, "[3] COMPILADORES / RUNTIMES",
            fontsize=13, fontweight="bold", color="#d62728",
            transform=ax.transAxes)
    y -= 0.04
    tooling = sys_info.get("tooling", {})
    for lang_name, info in tooling.items():
        if not info.get("available"):
            ax.text(0.07, y, f"{lang_name}:",
                    fontsize=10, fontweight="bold",
                    transform=ax.transAxes, color="#888")
            ax.text(0.35, y, "NO DISPONIBLE", fontsize=10,
                    transform=ax.transAxes, family="monospace",
                    color="#888")
        else:
            ax.text(0.07, y, f"{lang_name}:",
                    fontsize=10, fontweight="bold",
                    transform=ax.transAxes)
            version = info.get("version", "?")
            if len(version) > 80:
                version = version[:77] + "..."
            ax.text(0.35, y, version, fontsize=9,
                    transform=ax.transAxes, family="monospace",
                    color="#333")
            # Path en una sub-linea.
            path = info.get("path", "")
            if path:
                y -= 0.024
                if len(path) > 90:
                    path = "..." + path[-87:]
                ax.text(0.35, y, path, fontsize=8,
                        transform=ax.transAxes, family="monospace",
                        color="#888")
        y -= 0.032

    # Footer.
    ax.text(0.5, 0.02,
            "Estos parametros condicionan los tiempos.  Para comparar "
            "vs otro PC verifica que coincidan.",
            fontsize=9, ha="center", style="italic",
            transform=ax.transAxes, color="#666")

    plt.savefig(out_path, dpi=110, bbox_inches="tight")
    plt.close(fig)
    return True


# =============================================================================
# Generador maestro: produce TODAS las graficas en un directorio
# =============================================================================

def plot_ruido(rows: list[dict], langs: list[str], out_path: Path,
               suelo: Optional[dict] = None) -> bool:
    """Cuanto ruido tiene cada medida, y de donde sale.

    Dos paneles, porque son dos preguntas:

      - izquierda: de que lenguaje fiarse.  La dispersion de su MAD relativa a
        lo largo de todos los benches, no un promedio: si un lenguaje es
        estable en 25 benches y salvaje en 3, un solo numero lo esconde.
      - derecha: POR QUE.  El ruido relativo contra lo que dura la medida.  Lo
        que se ve es que las medidas cortas son las ruidosas -- y la linea del
        suelo dice hasta donde eso es inevitable, porque por debajo de ella se
        esta midiendo el arranque del proceso y no el programa.
    """
    deps = _try_import()
    if not deps:
        return False
    _, plt, np = deps
    suelo = suelo or {}

    por_lang: dict[str, list[float]] = {}
    puntos: list[tuple[float, float, str]] = []  # (p50, mad_pct, lang)
    # Ruido de CADA celda (bench, lenguaje).  Es el dato de grano fino: un
    # promedio por lenguaje dice de cuanto fiarse en general, pero no en cual de
    # las 29 medidas hay que desconfiar, que es lo que hace falta para leer una
    # fila concreta de la tabla.
    celdas: dict[tuple[int, str], float] = {}
    for i, r in enumerate(rows):
        corridas = r.get("_runs", {}) or {}
        for ln in langs:
            st = _resumen(corridas.get(ln) or [])
            if not st or st["p50"] <= 0:
                continue
            mad_pct = 100.0 * st["mad"] / st["p50"]
            por_lang.setdefault(ln, []).append(mad_pct)
            puntos.append((st["p50"], mad_pct, ln))
            celdas[(i, ln)] = mad_pct
    if not por_lang:
        return False

    presentes = [ln for ln in langs if ln in por_lang]
    fig = plt.figure(figsize=(max(16, 0.55 * len(rows) + 8),
                              7 + 0.42 * len(presentes)))
    gs = fig.add_gridspec(2, 2, height_ratios=[1.15, 1.0], hspace=0.42,
                          wspace=0.18)
    ax0 = fig.add_subplot(gs[0, :])
    ax1 = fig.add_subplot(gs[1, 0])
    ax2 = fig.add_subplot(gs[1, 1])

    # --- Panel de arriba: el ruido, celda a celda ---------------------------
    matriz = [[celdas.get((i, ln), float("nan")) for i in range(len(rows))]
              for ln in presentes]
    im = ax0.imshow(matriz, aspect="auto", cmap="RdYlGn_r", vmin=0.0,
                    vmax=max(10.0, min(25.0, max(
                        (v for fila in matriz for v in fila
                         if v == v), default=10.0))))
    ax0.set_xticks(range(len(rows)))
    ax0.set_xticklabels([r["bench"] for r in rows], rotation=90, fontsize=7)
    ax0.set_yticks(range(len(presentes)))
    ax0.set_yticklabels([LANG_LABELS.get(ln, ln) for ln in presentes],
                        fontsize=8)
    for y, fila in enumerate(matriz):
        for x_, v in enumerate(fila):
            if v != v:
                continue
            ax0.text(x_, y, f"{v:.0f}", ha="center", va="center", fontsize=5.5,
                     color=("white" if v > 12.0 else "black"))
    ax0.set_title("Ruido de CADA medida (MAD relativa, %) -- "
                  "cuanto se mueve ese bench en ese lenguaje")
    fig.colorbar(im, ax=ax0, fraction=0.018, pad=0.01, label="MAD relativa (%)")

    orden = sorted(por_lang, key=lambda ln: statistics.median(por_lang[ln]))
    datos = [por_lang[ln] for ln in orden]
    bp = ax1.boxplot(datos, vert=False, patch_artist=True,
                     labels=[LANG_LABELS.get(ln, ln) for ln in orden])
    for caja, ln in zip(bp["boxes"], orden):
        caja.set_facecolor(LANG_COLORS.get(ln, "#888"))
        caja.set_alpha(0.75)
    ax1.set_xlabel("MAD relativa (%) -- una marca por benchmark")
    ax1.set_title("Ruido por lenguaje (mas a la izquierda = mas repetible)")
    ax1.grid(axis="x", alpha=0.3)

    for ln in orden:
        xs = [p for p, _, l in puntos if l == ln]
        ys = [m for _, m, l in puntos if l == ln]
        ax2.scatter(xs, ys, s=34, alpha=0.8, label=LANG_LABELS.get(ln, ln),
                    color=LANG_COLORS.get(ln, "#888"))
    ax2.set_xscale("log")
    ax2.set_xlabel("Duracion de la medida (ms, log).  "
                   "Los triangulos marcan el suelo de cada lenguaje")
    ax2.set_ylabel("MAD relativa (%)")
    ax2.set_title("El ruido vive en las medidas cortas")
    ax2.grid(alpha=0.3)
    if suelo:
        # El suelo de CADA lenguaje, en su color y al pie del eje.  Sombrear una
        # franja comun diria que toda medida corta es dudosa, y eso solo vale
        # para el lenguaje que mas tarda en arrancar: un binario nativo mide
        # bien a 3 ms y la JVM no.  Atribuir el limite a quien es corrige eso.
        y0 = ax2.get_ylim()[0]
        for ln in orden:
            piso = (suelo.get(ln) or {}).get("p50")
            if not piso:
                continue
            ax2.plot([piso], [y0], marker="^", markersize=9, clip_on=False,
                     color=LANG_COLORS.get(ln, "#888"),
                     markeredgecolor="black", markeredgewidth=0.5)
        minimo = min((s.get("p50") or 0.0) for s in suelo.values() if s)
        if minimo > 0:
            # Por debajo del suelo MAS BAJO no mide nadie: ahi no hay programa
            # que medir, solo arranque.
            ax2.axvspan(ax2.get_xlim()[0], minimo, color="grey", alpha=0.10)
    ax2.legend(fontsize=7, ncol=2, loc="upper right", framealpha=0.9)

    plt.tight_layout()
    plt.savefig(out_path, dpi=110, bbox_inches="tight")
    plt.close(fig)
    return True


def plot_suelo(suelo: dict, langs: list[str], out_path: Path) -> bool:
    """Lo que tarda cada lenguaje en ejecutar un programa que no hace nada.

    Es el minimo por debajo del cual ninguna medida de ese lenguaje puede
    bajar, y esta dentro de todas ellas.
    """
    deps = _try_import()
    if not deps or not suelo:
        return False
    _, plt, _np = deps
    orden = sorted((ln for ln in langs if ln in suelo),
                   key=lambda ln: suelo[ln]["p50"])
    if not orden:
        return False
    vals = [suelo[ln]["p50"] for ln in orden]
    errs = [suelo[ln].get("mad", 0.0) for ln in orden]
    fig, ax = plt.subplots(figsize=(11, max(3, len(orden) * 0.45)))
    ax.barh([LANG_LABELS.get(ln, ln) for ln in orden], vals,
            xerr=errs, capsize=3,
            color=[LANG_COLORS.get(ln, "#888") for ln in orden], alpha=0.85)
    for i, v in enumerate(vals):
        ax.text(v, i, f" {v:.1f} ms", va="center", fontsize=9)
    ax.set_xscale("log")
    ax.set_xlabel("ms (log) -- arrancar el proceso y levantar su runtime")
    ax.set_title("Suelo de cada lenguaje: esta DENTRO de cada medida")
    ax.grid(axis="x", which="both", alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_path, dpi=110, bbox_inches="tight")
    plt.close(fig)
    return True


def plot_compilacion(datos: dict, out_dir: Path) -> dict:
    """Graficas del banco de COMPILACION, a partir de su JSON.

    Dos preguntas que en tabla se leen mal y en curva se ven de golpe:

      (a) ¿el coste por linea se mantiene al crecer el programa?  Una tabla de
          seis filas obliga a comparar numeros a ojo; la curva ensena la forma,
          que es lo que distingue lineal de superlineal.

      (b) ¿cuanto trabajo se evita segun QUE haya cambiado?  Las cuatro barras
          juntas dicen de un vistazo si un compilador distingue un cambio de
          cuerpo de uno de interfaz, o si le da igual.
    """
    deps = _try_import()
    if not deps:
        return {}
    _, plt, _np = deps
    out_dir.mkdir(parents=True, exist_ok=True)
    hechas: dict = {}
    casos = datos.get("casos", [])
    suelo = datos.get("suelo", {})

    # --- (a) escalado: ms por kilo-linea contra el tamano ------------------
    escal: dict[str, list[tuple[float, float]]] = {}
    for c in casos:
        if c.get("escalado") != "tamano" or not c.get("stats"):
            continue
        lineas = c.get("lineas") or 0
        if lineas <= 0:
            continue
        neto = c.get("neto")
        if neto is None:
            piso = (suelo.get(c["lang"]) or {}).get("p50") or 0.0
            neto = max(0.001, c["stats"]["p50"] - piso)
        escal.setdefault(c["lang"], []).append((lineas, 1000.0 * neto / lineas))
    if escal:
        fig, ax = plt.subplots(figsize=(10, 6))
        for ln, pares in escal.items():
            pares.sort()
            ax.plot([p[0] for p in pares], [p[1] for p in pares], "o-",
                    linewidth=2, label=LANG_LABELS.get(ln, ln),
                    color=LANG_COLORS.get(ln, "#888"))
        ax.set_xscale("log")
        ax.set_xlabel("lineas del programa (log)")
        ax.set_ylabel("ms por cada mil lineas")
        ax.set_title("Coste por linea segun el tamano\n"
                     "(plano = lineal; si sube, hay algo superlineal)")
        ax.grid(alpha=0.3, which="both")
        ax.legend(fontsize=9)
        plt.tight_layout()
        p = out_dir / "c1_escalado.png"
        plt.savefig(p, dpi=110, bbox_inches="tight")
        plt.close(fig)
        hechas["c1_escalado"] = True

    # --- (a2) crecimiento: tiempo contra lineas, en frio Y en caliente -----
    #
    # Va en escala doblemente logaritmica a proposito.  Si el tiempo sigue
    # t = a * n^k, en log-log es una RECTA cuya pendiente es k, asi que la
    # forma de la curva se lee directamente: paralela a la diagonal = lineal,
    # mas inclinada = superlineal.  En escala normal todas se ven "curvas
    # hacia arriba" y no se distingue una de otra.
    crec: dict = {}
    for c in casos:
        if c.get("fase") != "crecimiento":
            continue
        n = c.get("lineas") or 0
        if n <= 0:
            continue
        d = crec.setdefault(c["lang"], {"frio": [], "caliente": []})
        if c.get("neto_frio"):
            d["frio"].append((n, c["neto_frio"]))
        if c.get("neto_caliente"):
            d["caliente"].append((n, c["neto_caliente"]))
    if crec:
        fig, ax = plt.subplots(figsize=(10, 6))
        for ln, d in crec.items():
            col = LANG_COLORS.get(ln, "#888")
            for regimen, estilo in (("frio", "o-"), ("caliente", "s--")):
                pares = sorted(d[regimen])
                if len(pares) < 2:
                    continue
                ax.plot([p[0] for p in pares], [p[1] for p in pares], estilo,
                        linewidth=2, color=col, alpha=1.0 if regimen == "frio"
                        else 0.55,
                        label="%s (%s)" % (LANG_LABELS.get(ln, ln), regimen))
        ax.set_xscale("log")
        ax.set_yscale("log")
        ax.set_xlabel("lineas del programa (log)")
        ax.set_ylabel("ms sin el arranque (log)")
        ax.set_title("Como crece el tiempo de compilar con el codigo\n"
                     "(en log-log la pendiente ES el exponente: paralela a la "
                     "diagonal = lineal)")
        ax.grid(alpha=0.3, which="both")
        ax.legend(fontsize=8, ncol=2)
        plt.tight_layout()
        p = out_dir / "c1b_crecimiento.png"
        plt.savefig(p, dpi=110, bbox_inches="tight")
        plt.close(fig)
        hechas["c1b_crecimiento"] = True

        # --- (a3) el exponente de cada uno, en barras.  Es el resumen de la
        # curva de arriba: una sola cifra por lenguaje y regimen, con la linea
        # del 1.0 marcada porque es la frontera entre "escala" y "no escala".
        resumen = datos.get("crecimiento") or []
        if resumen:
            fig, ax = plt.subplots(figsize=(max(8, 1.3 * len(resumen)), 5))
            nombres = [r["lang"] for r in resumen]
            xs = list(range(len(nombres)))
            ancho = 0.38
            ax.bar([x - ancho / 2 for x in xs],
                   [r.get("k_frio") or 0 for r in resumen], ancho,
                   label="en frio",
                   color=[LANG_COLORS.get(n, "#888") for n in nombres])
            ax.bar([x + ancho / 2 for x in xs],
                   [r.get("k_caliente") or 0 for r in resumen], ancho,
                   label="en caliente", alpha=0.55,
                   color=[LANG_COLORS.get(n, "#888") for n in nombres])
            ax.axhline(1.0, color="#444", linestyle=":", linewidth=1.5)
            ax.text(len(nombres) - 0.5, 1.02, "lineal", fontsize=8,
                    color="#444", ha="right")
            ax.set_xticks(xs)
            ax.set_xticklabels([LANG_LABELS.get(n, n) for n in nombres],
                               rotation=20, ha="right")
            ax.set_ylabel("exponente k de t = a * n^k")
            ax.set_title("Como escala cada compilador\n"
                         "(1.0 = el doble de codigo, el doble de tiempo; "
                         "2.0 = cuatro veces)")
            ax.grid(alpha=0.3, axis="y")
            ax.legend(fontsize=9)
            plt.tight_layout()
            p = out_dir / "c1c_exponente.png"
            plt.savefig(p, dpi=110, bbox_inches="tight")
            plt.close(fig)
            hechas["c1c_exponente"] = True

        # --- (a4) lo que aporta la cache, contra el tamano.  Interesa porque
        # no es constante: hay herramientas cuyo ahorro se diluye al crecer el
        # programa, y eso no se ve en ninguna de las dos curvas por separado.
        fig, ax = plt.subplots(figsize=(10, 5))
        alguna = False
        for ln, d in crec.items():
            frio = dict(d["frio"])
            cal = dict(d["caliente"])
            comunes = sorted(set(frio) & set(cal))
            if len(comunes) < 2:
                continue
            alguna = True
            ax.plot(comunes, [frio[n] / cal[n] for n in comunes], "o-",
                    linewidth=2, color=LANG_COLORS.get(ln, "#888"),
                    label=LANG_LABELS.get(ln, ln))
        if alguna:
            ax.axhline(1.0, color="#444", linestyle=":", linewidth=1.5)
            ax.text(0.99, 1.02, "la cache no aporta nada", fontsize=8,
                    color="#444", ha="right", transform=ax.get_yaxis_transform())
            ax.set_xscale("log")
            ax.set_xlabel("lineas del programa (log)")
            ax.set_ylabel("veces mas rapido con la cache caliente")
            ax.set_title("Cuanto aporta la cache, y si aguanta al crecer\n"
                         "(un fichero suelto no tiene nada que reutilizar: "
                         "ahi el valor 1.0 es lo esperado)")
            ax.grid(alpha=0.3, which="both")
            ax.legend(fontsize=9)
            plt.tight_layout()
            p = out_dir / "c1d_ahorro_cache.png"
            plt.savefig(p, dpi=110, bbox_inches="tight")
            hechas["c1d_ahorro_cache"] = True
        plt.close(fig)

    # --- (b) que se evita segun que cambie ---------------------------------
    orden_reg = ["de cero", "sin cambios", "1 comentario", "1 cuerpo",
                 "1 interfaz", "mitad de los modulos"]
    reg: dict[str, dict[str, float]] = {}
    for c in casos:
        r = c.get("regimen")
        if not r or not c.get("stats"):
            continue
        reg.setdefault(c["lang"], {})[r] = c["stats"]["p50"]
    if reg:
        presentes = [r for r in orden_reg
                     if any(r in v for v in reg.values())]
        fig, ax = plt.subplots(figsize=(max(9, 1.6 * len(reg) * len(presentes)), 6))
        ancho = 0.8 / max(1, len(presentes))
        x = list(range(len(reg)))
        langs_reg = list(reg.keys())
        for i, r in enumerate(presentes):
            vals = [reg[ln].get(r, float("nan")) for ln in langs_reg]
            ax.bar([xi + (i - len(presentes) / 2 + 0.5) * ancho for xi in x],
                   vals, ancho, label=r)
        ax.set_xticks(x)
        ax.set_xticklabels([LANG_LABELS.get(ln, ln) for ln in langs_reg],
                           rotation=15, ha="right")
        ax.set_ylabel("ms")
        ax.set_yscale("log")
        ax.set_title("Cuanto cuesta reconstruir, segun QUE haya cambiado\n"
                     "(barras iguales = ese compilador no distingue)")
        ax.grid(axis="y", alpha=0.3, which="both")
        ax.legend(fontsize=9)
        plt.tight_layout()
        p = out_dir / "c2_regimenes.png"
        plt.savefig(p, dpi=110, bbox_inches="tight")
        plt.close(fig)
        hechas["c2_regimenes"] = True
    return hechas


def generate_all(rows: list[dict], langs: list[str], plot_dir: Path,
                 sys_info: Optional[dict] = None,
                 suelo: Optional[dict] = None) -> dict:
    """Genera todas las graficas en @c plot_dir .  Retorna dict con
    {nombre_plot: bool_ok} para que el caller reporte que se genero.
    """
    # Si faltan las dependencias fallan TODAS por la misma razon.  Se dice una
    # vez y con la solucion, en vez de doce `FAIL` que no explican nada y que
    # ademas invitan a buscar el error en el sitio equivocado.
    motivo = diagnostico_dependencias()
    if motivo:
        return {"(ninguna) " + motivo: False}
    plot_dir.mkdir(parents=True, exist_ok=True)
    results = {}
    # System info PRIMERO (00 prefix).  Es el contexto de todo lo demas.
    if sys_info is not None:
        results["00_system_info"] = plot_system_info(
            sys_info, plot_dir / "00_system_info.png")
    results["01_dashboard"] = plot_dashboard(
        rows, langs, plot_dir / "01_dashboard.png")
    results["02_heatmap"] = plot_heatmap(
        rows, langs, plot_dir / "02_heatmap.png")
    results["03_radar"] = plot_radar(
        rows, langs, plot_dir / "03_radar_profile.png")
    results["04_boxplot_variability"] = plot_boxplot_variability(
        rows, langs, plot_dir / "04_boxplot_variability.png")
    results["05_scatter_ratio"] = plot_scatter_ratio(
        rows, langs, plot_dir / "05_scatter_ratio_vs_c.png")
    results["06_ranking_lines"] = plot_ranking_lines(
        rows, langs, plot_dir / "06_ranking_lines.png")
    results["07_grouped_ratio"] = plot_grouped_ratio(
        rows, langs, plot_dir / "07_grouped_ratio.png")
    results["08_geomean"] = plot_geomean_summary(
        rows, langs, plot_dir / "08_geomean_summary.png")
    results["09_ruido"] = plot_ruido(
        rows, langs, plot_dir / "09_ruido.png", suelo)
    # El suelo solo se puede dibujar si se midio.  Un JSON anterior a que
    # existiera no lo trae, y eso no es un fallo de la grafica: decir FAIL
    # invitaria a buscar un error donde solo falta un dato.
    if suelo:
        results["10_suelo"] = plot_suelo(
            suelo, langs, plot_dir / "10_suelo.png")
    # Per-bench: subdir.
    per_bench_dir = plot_dir / "per_bench"
    count = plot_per_bench(rows, langs, per_bench_dir, suelo)
    results[f"per_bench ({count} archivos)"] = count > 0
    return results
