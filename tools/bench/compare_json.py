#!/usr/bin/env python3
"""Compara dos ficheros de resultados de `run_all_benches.py`.

Uso:  python tools/bench/compare_json.py referencia.json actual.json [modos...]

Imprime, por modo, la media geometrica de actual/referencia (menor es mejor) y
los benches que se salen del ruido.  Se mide asi -- y no por la media
aritmetica -- porque los tiempos van de milisegundos a decenas de segundos y la
aritmetica la dominarian los lentos.
"""

import json
import sys
import textwrap

RUIDO = 0.05  # +-5%: por debajo de eso no se distingue del ruido de la maquina.


def cargar(ruta):
    """Devuelve {(caso, modo): milisegundos} a partir de un fichero.

    Entiende los DOS bancos.  El de ejecucion (`run_all_benches.py`) trae
    `results` con columnas `vx_*`; el de compilacion (`compile_bench.py`) trae
    `casos`, que es otra forma entera.  Antes solo se leia el primero, asi que
    los tiempos de COMPILACION no tenian forma de compararse entre tandas: se
    podia medir una regresion y no verla.  Con la cache por hash y los builds
    reproducibles, eso deberia ser un test de CI.
    """
    datos = json.load(open(ruta, encoding="utf-8"))
    if "results" in datos:
        return _cargar_ejecucion(datos)
    if "casos" in datos:
        return _cargar_compilacion(datos)
    raise SystemExit("no reconozco el formato de %s: no trae ni `results` "
                     "(banco de ejecucion) ni `casos` (banco de "
                     "compilacion)." % ruta)


# Centinelas que el arnes de ejecucion escribe en lugar de un tiempo.  Cada uno
# es una causa DISTINTA y hasta ahora salian los cinco como "sin medir", que no
# se puede accionar: un compilador roto se leia igual que un bench lento.
CENTINELAS = {
    -1.0: "planton (timeout)",
    -2.0: "no compila",
    -3.0: "murio al ejecutar",
    -4.0: "no arranca",
    -5.0: "no le dieron turno",
}


def _cargar_ejecucion(datos):
    tabla, motivos = {}, {}
    for f in datos["results"]:
        nombre = f.get("bench")
        # Estas dos las publica el arnes con su explicacion; aqui solo hay que
        # no perderla.  `bajo_suelo` es una medida REAL que no supera el
        # arranque, y `censurado` es una cota inferior por haber tocado el
        # tope: ninguna de las dos se puede meter en una razon, pero decir
        # "sin medir" de ellas es falso.
        bajo = f.get("bajo_suelo") or {}
        censurado = f.get("censurado") or {}
        for clave, valor in f.items():
            if not clave.startswith("vx_") or not isinstance(valor,
                                                             (int, float)):
                continue
            tabla[(nombre, clave)] = valor
            # (motivo, detalle): el motivo AGRUPA -- tiene que ser el mismo
            # texto para todos los que caen por lo mismo -- y el detalle es lo
            # que cambia bench a bench.  Metiendo los numeros en el motivo,
            # cada uno formaba su propio grupo y la lista volvia a ser plana.
            if clave in censurado:
                motivos[(nombre, clave)] = ("censurada (es una cota inferior)",
                                            "")
            elif clave in bajo:
                d = bajo[clave]
                motivos[(nombre, clave)] = (
                    "no supera el arranque",
                    "%.2f ms sobre %.2f de suelo" % (d.get("bruto", 0.0),
                                                     d.get("suelo", 0.0)))
            elif valor in CENTINELAS:
                motivos[(nombre, clave)] = (CENTINELAS[valor], "")
            elif valor <= 0:
                motivos[(nombre, clave)] = ("valor no positivo",
                                            "%.3f" % valor)
    return tabla, motivos


def _cargar_compilacion(datos):
    """Un caso del banco de compilacion -> una fila comparable.

    La CLAVE tiene que identificar el mismo caso en dos tandas distintas, y
    por eso lleva todo lo que lo distingue: lenguaje, fase, tamano, numero de
    ficheros, regimen y eje de paralelismo.  Si se dejara fuera cualquiera de
    ellos, dos casos distintos colapsarian en la misma clave y la comparacion
    restaria peras de manzanas -- que es el mismo fallo que la fase de
    proyecto ya arreglo una vez en sus etiquetas.
    """
    tabla, motivos = {}, {}
    for c in datos.get("casos", []):
        lang = c.get("lang")
        if not lang:
            continue
        fase = c.get("fase") or ("escalado-" + c["escalado"]
                                 if c.get("escalado") else "?")
        partes = [fase]
        for campo in ("lineas", "funciones", "objetivo", "ficheros",
                      "regimen", "paralelismo"):
            if c.get(campo) not in (None, ""):
                partes.append("%s=%s" % (campo, c[campo]))
        nombre = " ".join(partes)
        # Cada caso guarda sus medidas de una forma segun la fase.  Se cogen
        # todas las que haya, cada una como su propio "modo": frio y caliente
        # son numeros distintos y una regresion puede estar solo en uno.
        for modo, valor in (("frio", _p50(c.get("frio"))),
                            ("caliente", _p50(c.get("caliente"))),
                            ("ms", _p50(c.get("stats"))),
                            ("neto_frio", c.get("neto_frio")),
                            ("neto_caliente", c.get("neto_caliente")),
                            ("ms_frio", c.get("ms_frio")),
                            ("ms_caliente", c.get("ms_caliente"))):
            clave = (nombre + "  [" + lang + "]", modo)
            if isinstance(valor, (int, float)) and valor > 0:
                tabla[clave] = float(valor)
            elif isinstance(valor, (int, float)):
                tabla[clave] = float(valor)
                motivos[clave] = (CENTINELAS.get(float(valor),
                                                 "valor no positivo"),
                                  "" if float(valor) in CENTINELAS
                                  else "%.3f" % valor)
    return tabla, motivos


def _p50(d):
    return d.get("p50") if isinstance(d, dict) else None


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    ref, mot_ref = cargar(sys.argv[1])
    act, mot_act = cargar(sys.argv[2])
    modos = sys.argv[3:] or sorted({m for _, m in act})
    for modo in modos:
        razones, fuera = [], []
        # Descartado -> por que.  Antes era una lista de nombres a secas y
        # todas las causas se leian igual: 21 de 33 benchmarks "sin medir" sin
        # forma de saber si el problema era el compilador, la maquina o el
        # propio arnes.
        descartados: dict[str, list[str]] = {}

        def descartar(nombre, motivo, detalle=""):
            etiqueta = f"{nombre} ({detalle})" if detalle else nombre
            descartados.setdefault(motivo, []).append(etiqueta)

        for (nombre, m), valor in act.items():
            if m != modo:
                continue
            previo = ref.get((nombre, m))
            if previo is None:
                descartar(nombre, "no esta en la referencia")
                continue
            # Cada lado puede estar descartado por su cuenta y por causas
            # distintas; se dice la del lado que falla, empezando por el nuevo.
            marca = mot_act.get((nombre, m)) or mot_ref.get((nombre, m))
            if marca is not None:
                descartar(nombre, marca[0], marca[1])
                continue
            if previo <= 0 or valor <= 0:
                descartar(nombre, "valor no positivo sin motivo declarado")
                continue
            razon = valor / previo
            razones.append(razon)
            if abs(razon - 1.0) > RUIDO:
                fuera.append((razon, nombre))
        if not razones:
            print(f"{modo:14s} sin datos comparables")
            for motivo, nombres in sorted(descartados.items()):
                print(f"                {len(nombres):3d} x {motivo}: "
                      f"{', '.join(sorted(nombres))}")
            continue
        geo = 1.0
        for r in razones:
            geo *= r
        geo **= 1.0 / len(razones)
        print(f"{modo:14s} geomean {geo:.4f}   ({len(razones)} benches)")
        for razon, nombre in sorted(fuera, reverse=True):
            marca = "peor" if razon > 1.0 else "mejor"
            print(f"                {nombre:20s} {razon:6.3f}x  {marca}")
        # El recuento primero: "12 de 33 comparados" es la linea que dice si
        # fiarse del geomean de arriba.  Sin ella, una media sobre un tercio de
        # la suite se lee igual que una sobre la suite entera.
        total = len(razones) + sum(len(v) for v in descartados.values())
        if descartados:
            print(f"                comparados {len(razones)} de {total}; "
                  f"fuera {total - len(razones)}:")
            for motivo, nombres in sorted(descartados.items()):
                print(f"                  {len(nombres):3d} x {motivo}:")
                print(textwrap.fill(", ".join(sorted(nombres)), width=96,
                                    initial_indent=" " * 22,
                                    subsequent_indent=" " * 22))
    return 0


if __name__ == "__main__":
    sys.exit(main())
