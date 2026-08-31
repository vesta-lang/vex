#!/usr/bin/env python3
"""Sube (o baja) el trabajo de los benchmarks, igual en todos los lenguajes.

Por que hace falta
------------------
El arnes mide WALL TIME EXTERNO, que incluye arrancar el proceso.  Ese arranque
va de 0.2 ms (un ELF nativo) a 32 ms (la VM de Vesta o la JVM), y un benchmark
cuyo trabajo dura menos que eso no se puede medir: quitado el arranque, lo que
queda cabe dentro del ruido.  En la ultima tanda eran 30 de 357 medidas, y once
de ellas del JIT -- o sea que la columna del JIT se apoyaba en muy pocos casos.

La regla practica: el trabajo tiene que durar al menos diez veces el arranque
del lenguaje mas lento que participe.  Con la VM en ~32 ms, eso son ~320 ms.

Como lo hace, y que NO hace
---------------------------
Un benchmark solo se toca si sus variantes estan de acuerdo: se busca el mismo
literal numerico grande en TODAS ellas y se multiplica en todas por el mismo
factor.  Si las variantes no coinciden -- o hay varios candidatos, o el trabajo
no es un numero (`fib(32)` no lo es) -- NO se adivina: se salta y se dice, para
que esa se mire a mano.

Es deliberado que no sepa nada de cada benchmark en particular.  Un script que
"arregla" 33 benchmarks con reglas especiales para cada uno es un script que
nadie vuelve a leer, y basta que una regla este mal para meter un sesgo en la
tabla sin que se note.

Uso
---
    python escalar_workload.py                 # en seco: dice que haria
    python escalar_workload.py --factor 8      # en seco, con otro factor
    python escalar_workload.py --factor 8 --aplicar
    python escalar_workload.py --factor 0.125 --aplicar    # deshacer un x8
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# Ficheros de cada lenguaje dentro de la carpeta de un bench.
FUENTES = ("main.vx", "main.c", "main.cpp", "main.py", "Main.java",
           "main.go", "main.rs")

# Solo se consideran literales de este tamano para arriba.  Por debajo son
# constantes del programa (tamanos de array, semillas, mascaras), no el mando
# del trabajo, y multiplicarlas cambiaria lo que el benchmark MIDE en vez de
# cuanto dura.
MINIMO = 100_000

# Un entero, con o sin separadores `_` (Vesta, Rust, Java y Python los
# admiten; C, C++ y Go en estos ficheros no los usan).  Se exige que no venga
# pegado a otro digito, letra, `.` o `_` para no partir un decimal, un
# identificador ni un literal mas largo.
NUMERO = re.compile(r"(?<![\w.])(\d[\d_]*)(?![\w.])")


def literales(texto: str) -> dict[int, int]:
    """Los literales >= MINIMO del fichero, y cuantas veces sale cada uno."""
    out: dict[int, int] = {}
    for m in NUMERO.finditer(texto):
        crudo = m.group(1)
        if crudo.endswith("_"):
            continue
        try:
            v = int(crudo.replace("_", ""))
        except ValueError:
            continue
        if v >= MINIMO:
            out[v] = out.get(v, 0) + 1
    return out


def con_separadores(v: int, como: str) -> str:
    """Formatea @p v imitando el estilo del literal @p como que sustituye.

    Si el original llevaba `_`, el nuevo tambien: cambiar `50_000_000` por
    `400000000` compila igual pero deja el fichero peor de lo que estaba, y
    estos ficheros se leen.
    """
    if "_" not in como:
        return str(v)
    s = str(v)
    partes = []
    while len(s) > 3:
        partes.append(s[-3:])
        s = s[:-3]
    partes.append(s)
    return "_".join(reversed(partes))


def sustituir(texto: str, viejo: int, nuevo: int) -> tuple[str, int]:
    """Cambia todas las apariciones de @p viejo por @p nuevo.  (texto, cuantas)"""
    n = 0

    def rep(m):
        nonlocal n
        crudo = m.group(1)
        if crudo.endswith("_"):
            return crudo
        try:
            if int(crudo.replace("_", "")) != viejo:
                return crudo
        except ValueError:
            return crudo
        n += 1
        return con_separadores(nuevo, crudo)

    return NUMERO.sub(rep, texto), n


def analizar(carpeta: Path) -> tuple[int | None, list[str], str]:
    """Que literal escalar en este bench.  (valor, ficheros, motivo si no).

    El literal tiene que estar en TODAS las variantes y ser el UNICO candidato
    comun.  Con dos candidatos comunes no se elige por tamano ni por orden: se
    dice que hay dos y se deja para una persona.
    """
    presentes = [f for f in FUENTES if (carpeta / f).is_file()]
    if not presentes:
        return (None, [], "sin fuentes")
    comunes: set[int] | None = None
    for f in presentes:
        try:
            texto = (carpeta / f).read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            return (None, [], "no se pudo leer %s: %s" % (f, e))
        vals = set(literales(texto))
        comunes = vals if comunes is None else (comunes & vals)
    if not comunes:
        return (None, presentes,
                "ningun literal >= %s comun a las %d variantes"
                % (f"{MINIMO:,}", len(presentes)))
    if len(comunes) > 1:
        return (None, presentes,
                "hay %d candidatos comunes (%s): elegir uno es adivinar"
                % (len(comunes), ", ".join(f"{v:,}" for v in sorted(comunes))))
    return (comunes.pop(), presentes, "")


def factores_desde_json(ruta: Path, objetivo: float, tope: float) -> dict:
    """Factor por benchmark, sacado de una tanda anterior.

    Dos condiciones a la vez, y tiran en sentidos opuestos:
      - el lenguaje MAS RAPIDO tiene que llegar a @p objetivo, o su medida
        sigue sin separarse del arranque;
      - el MAS LENTO no debe pasar de @p tope, o arreglar una columna
        convierte la tanda en horas.

    Cuando las dos no caben, el benchmark NO se puede arreglar escalando: su
    reparto entre lenguajes es demasiado ancho.  Se dice, en vez de elegir una
    de las dos y publicar el resultado como si nada -- `alloc_large` va de 6 ms
    en AOT a 18 s en Go, y no hay factor que deje a los dos bien.

    @return {bench: (factor, aviso)}.  factor None = no se puede.
    """
    datos = json.loads(ruta.read_text(encoding="utf-8"))
    langs = datos.get("active_langs") or []
    out: dict = {}
    for fila in datos.get("results") or []:
        nombre = fila.get("bench")
        if not nombre:
            continue
        tiempos = [fila[l] for l in langs
                   if isinstance(fila.get(l), (int, float)) and fila[l] > 0]
        if len(tiempos) < 2:
            continue
        t_min, t_max = min(tiempos), max(tiempos)
        necesita = objetivo / t_min          # para que el rapido se mida
        permite = tope / t_max               # para que el lento no se dispare
        if necesita <= 1.0:
            out[nombre] = (1.0, "ya se mide")
        elif necesita <= permite:
            out[nombre] = (necesita, "")
        else:
            out[nombre] = (
                None,
                "no cabe: el mas rapido (%.1f ms) necesita x%.0f y el mas "
                "lento (%.0f ms) solo admite x%.1f" % (
                    t_min, necesita, t_max, permite))
    return out


def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dir", type=str, default="",
                   help="carpeta de los benchmarks (por defecto, la del "
                        "proyecto: examples_codes_vx/benchmark)")
    p.add_argument("--factor", type=float, default=10.0,
                   help="por cuanto multiplicar el trabajo (default 10)")
    p.add_argument("--aplicar", action="store_true",
                   help="escribir los cambios.  Sin esto solo se dice que "
                        "se haria, que es lo que se quiere la primera vez.")
    p.add_argument("--bench", type=str, default="",
                   help="solo estos benchmarks, separados por comas")
    p.add_argument("--desde-json", type=str, default="",
                   help="calcular un factor POR BENCHMARK a partir de una "
                        "tanda anterior (bench_results.json), en vez de "
                        "aplicar el mismo a todos.  Es lo que hay que usar: "
                        "un factor unico o deja cortos los benchmarks "
                        "rapidos o dispara los lentos.")
    p.add_argument("--objetivo-min", type=float, default=300.0,
                   help="ms que deberia tardar el lenguaje MAS RAPIDO tras "
                        "escalar (default 300).  Por debajo de ~10 veces el "
                        "arranque de la VM (~32 ms) la medida no se separa "
                        "del ruido.")
    p.add_argument("--tope-max", type=float, default=20000.0,
                   help="ms que NO deberia pasar el lenguaje mas lento tras "
                        "escalar (default 20000).  Es lo que impide que "
                        "arreglar una columna convierta la tanda en horas.")
    args = p.parse_args()

    if args.dir:
        raiz = Path(args.dir)
    else:
        aqui = Path(__file__).resolve()
        raiz = aqui.parents[2] / "examples_codes_vx" / "benchmark"
    if not raiz.is_dir():
        print("[error] no encuentro los benchmarks en %s" % raiz)
        return 1
    if args.factor <= 0:
        print("[error] el factor tiene que ser positivo")
        return 1

    pedidos = {b.strip() for b in args.bench.split(",") if b.strip()}
    carpetas = [d for d in sorted(raiz.iterdir())
                if d.is_dir() and d.name != "out"
                and (not pedidos or d.name in pedidos)]

    print("Escalar el trabajo de los benchmarks   factor x%g   %s"
          % (args.factor, "APLICANDO" if args.aplicar else "en seco"))
    print("  %s" % raiz)
    print()
    cab = "%-24s %14s %14s  %-7s %s" % ("bench", "ahora", "quedaria",
                                          "factor", "ficheros")
    print(cab)
    print("-" * len(cab))

    por_bench: dict = {}
    if args.desde_json:
        pj = Path(args.desde_json)
        if not pj.is_file():
            print("[error] no encuentro %s" % pj)
            return 1
        por_bench = factores_desde_json(pj, args.objetivo_min, args.tope_max)
        print("  factores por benchmark desde %s" % pj.name)
        print("  objetivo: el mas rapido >= %.0f ms;  tope: el mas lento "
              "<= %.0f ms" % (args.objetivo_min, args.tope_max))
        print()

    tocados, saltados = 0, []
    for d in carpetas:
        valor, presentes, motivo = analizar(d)
        if valor is None:
            saltados.append((d.name, motivo))
            continue
        factor = args.factor
        if por_bench:
            if d.name not in por_bench:
                saltados.append((d.name, "no sale en el JSON de referencia"))
                continue
            factor, aviso = por_bench[d.name]
            if factor is None:
                saltados.append((d.name, aviso))
                continue
            if aviso == "ya se mide":
                saltados.append((d.name, "ya se mide bien: no hace falta"))
                continue
        nuevo = int(round(valor * factor))
        if nuevo == valor:
            saltados.append((d.name, "el factor no lo cambia"))
            continue
        cambios = []
        for f in presentes:
            ruta = d / f
            texto = ruta.read_text(encoding="utf-8", errors="replace")
            salida, n = sustituir(texto, valor, nuevo)
            if n:
                cambios.append((ruta, salida, n))
        if len(cambios) != len(presentes):
            saltados.append((d.name, "el literal no se pudo sustituir en "
                                     "todas las variantes"))
            continue
        print("%-24s %14s %14s  x%-6.1f %s" % (
            d.name, f"{valor:,}", f"{nuevo:,}", factor,
            " ".join(r.name for r, _, _ in cambios)))
        if args.aplicar:
            for ruta, salida, _ in cambios:
                ruta.write_text(salida, encoding="utf-8")
        tocados += 1

    print("-" * len(cab))
    print("%d benchmark(s) %s." % (tocados,
                                   "escalados" if args.aplicar else
                                   "se escalarian"))
    if saltados:
        print()
        print("Sin tocar (%d) -- estos hay que mirarlos a mano:" % len(saltados))
        for nombre, motivo in saltados:
            print("  %-24s %s" % (nombre, motivo))
    if not args.aplicar and tocados:
        print()
        print("Nada escrito.  Anade --aplicar cuando el listado te cuadre.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
