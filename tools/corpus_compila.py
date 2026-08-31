#!/usr/bin/env python3
"""Compila todo el corpus y avisa de lo que NO termina bien.

Es la primera puerta al tocar el compilador, y va antes que comparar
diagnosticos o bytes.  Motivo, aprendido caro: un cambio en el analisis de
rangos hizo que `255_mutex.vx` cascara con violacion de segmento, y la
comparacion de diagnosticos lo enseño como "difieren dos ejemplos" -- un
sintoma confuso, al final de una vuelta de varios minutos.  Mirar solo el
CoDIGO DE SALIDA lo dice en el primer minuto y sin ambiguedad: `rc=139` no se
confunde con nada.

Lo que comprueba es deliberadamente poco: que el proceso termine con cero y
deje artefacto.  No mira que dice ni que emite -- para eso estan la suite e2e y
la comparacion de `.velb` --, porque una puerta que tarda es una puerta que se
salta.

Los ejemplos que deben fallar A PROPOSITO (los negativos del comprobador de
limites y del borrow checker) salen aparte y no cuentan como fallo: lo que
importa de ellos es que fallen COMPILANDO, no que se lleven el compilador por
delante.

Uso:
    python tools/corpus_compila.py cmake-build-release/vm.exe
    python tools/corpus_compila.py vm.exe --antes otra/vm.exe   # comparar dos
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# Los avisos y errores que interesa comparar.  Se filtran aqui y no fuera para
# que el barrido devuelva ya lo comparable: el resto de la salida lleva rutas
# temporales que cambian en cada vuelta.
_DIAG = re.compile(r"(VX\d{4}|VXA\d{3})")


def compilar(vm: Path, fuente: Path, salida: Path, timeout: float) -> tuple:
    """(codigo, diagnosticos) de compilar @p fuente.  -1 si se paso del tiempo.

    Se devuelven las dos cosas de UNA pasada.  Antes eran dos barridos -- uno
    para codigos y otro para diagnosticos -- o sea el doble de compilaciones
    para responder a dos preguntas sobre el mismo trabajo.
    """
    try:
        r = subprocess.run([str(vm), "--vesta", str(fuente), "-o", str(salida)],
                           capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return (-1, [])
    txt = (r.stderr or b"").decode("utf-8", "replace") +           (r.stdout or b"").decode("utf-8", "replace")
    diags = sorted(l.strip() for l in txt.splitlines() if _DIAG.search(l))
    return (r.returncode, diags)


def barrer(vm: Path, fuentes: list, timeout: float, jobs: int) -> dict:
    """{nombre: (codigo, diagnosticos)} de compilar cada fuente, EN PARALELO.

    Compilar cada fuente es un proceso independiente, asi que repartirlas no
    cambia ningun resultado -- al contrario que MEDIR, que jamas se paraleliza
    porque entonces se mide la carga de la maquina.  Aqui no se cronometra
    nada: se comprueba.  Y secuencial, un barrido de 469 son varios minutos --
    una comprobacion que cuesta minutos es una comprobacion que se salta, que
    es exactamente como se colaron dos cambios malos en un solo dia.

    Cada trabajo escribe en SU directorio: con uno compartido, dos
    compilaciones a la vez se pisan el artefacto y el veredicto seria del
    ultimo en llegar.
    """
    out: dict = {}
    hechas = [0]
    with tempfile.TemporaryDirectory() as tmp:
        def uno(par):
            i, f = par
            d = Path(tmp) / ("j%d" % i)
            d.mkdir(parents=True, exist_ok=True)
            # La clave es la RUTA, no el nombre: los bancos de pruebas traen
            # una carpeta por banco y dentro todos se llaman `main.vx`, asi que
            # por nombre se pisan unos a otros y solo se veria el ultimo -- lo
            # que hace desaparecer de la cuenta a casi todos sin decir nada.
            return (str(f), compilar(vm, f, d / "out", timeout))

        with ThreadPoolExecutor(max_workers=jobs) as ex:
            for fut in as_completed([ex.submit(uno, x)
                                     for x in enumerate(fuentes)]):
                nombre, res = fut.result()
                out[nombre] = res
                hechas[0] += 1
                print("\r  %d/%d" % (hechas[0], len(fuentes)),
                      end="", file=sys.stderr, flush=True)
    print("\r" + " " * 30 + "\r", end="", file=sys.stderr)
    return out


def clasificar(rc: int) -> str:
    """Que significa ese codigo, en palabras.

    Se distingue CAER de fallar: un compilador que rechaza un programa hace su
    trabajo; uno que se cae con una senal tiene un fallo dentro.
    """
    if rc == 0:
        return "ok"
    if rc == 1:
        return "rechaza el programa"
    if rc == -1:
        return "se paso del tiempo"
    if rc == 139 or rc == -11:
        return "VIOLACION DE SEGMENTO"
    if rc in (134, -6, 0xC0000409):
        # 0xC0000409 es el fallo-rapido de Windows, que es como sale un
        # `abort()`.  Un negativo que rechaza el programa abortando no es una
        # caida del compilador, asi que se nombra por lo que es.
        return "abortado (rechazo o panico)"
    if rc == 136 or rc == -8:
        return "excepcion aritmetica"
    return "codigo %d" % rc


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("vm", help="binario a comprobar")
    p.add_argument("--antes", default="",
                   help="otro binario con el que comparar: solo se listan los "
                        "que CAMBIAN de veredicto, que es lo que interesa al "
                        "tocar el compilador.")
    p.add_argument("--corpus", default="examples_codes_vx")
    p.add_argument("--timeout", type=float, default=10.0,
                   help="limite por compilacion.  10 s: ningun ejemplo del "
                        "corpus tarda tanto, asi que pasarse ES el sintoma -- "
                        "y un limite generoso solo hace que un cuelgue tarde "
                        "en verse.")
    p.add_argument("-j", "--jobs", type=int, default=0,
                   help="compilaciones en paralelo (default: nucleos - 2).  "
                        "Se puede porque aqui no se cronometra nada: se "
                        "comprueba, y cada compilacion es un proceso aparte.")
    args = p.parse_args()

    vm = Path(args.vm)
    if not vm.is_file():
        print("[error] no encuentro %s" % vm)
        return 2
    raiz = Path(args.corpus)
    # Los ejemplos del nivel de arriba, mas los BENCHMARKS.
    #
    # Los benchmarks tambien tienen que compilar, y no se comprobaban: solo se
    # tocaban al medir, que es algo que se hace de vez en cuando y no en cada
    # cambio.  Asi que un cambio del compilador podia dejarlos rotos y no se
    # sabia hasta la siguiente medicion.
    #
    # Vienen en dos formas -- un fichero suelto, o una carpeta por banco con su
    # `main.vx` al lado de las versiones en otros lenguajes -- y las dos son
    # autonomas.  El resto de subcarpetas del corpus NO se meten: son modulos
    # de varios ficheros que no compilan por separado a proposito, y contarlos
    # daria fallos que no lo son.
    fuentes = sorted(raiz.glob("*.vx"))
    fuentes += sorted((raiz / "benchmark").glob("*.vx"))
    fuentes += sorted((raiz / "benchmark").glob("*/main.vx"))
    if not fuentes:
        print("[error] no hay fuentes en %s" % args.corpus)
        return 2

    jobs = args.jobs if args.jobs > 0 else max(1, (os.cpu_count() or 4) - 2)
    print("compilando %d ejemplos con %s (%d a la vez)"
          % (len(fuentes), vm, jobs))
    ahora = barrer(vm, fuentes, args.timeout, jobs)

    if args.antes:
        antes = barrer(Path(args.antes), fuentes, args.timeout, jobs)
        # DOS comparaciones, y en este orden.  Que el compilador no se caiga es
        # la primera puerta, pero NO basta: un cambio la paso limpiamente
        # mientras silenciaba 29 avisos en `255_mutex` -- de 29 a 0.  Un
        # compilador que enmudece pasa cualquier puerta que solo mire si
        # termino bien.
        rc_dist = sorted(n for n in ahora
                         if antes.get(n, (None, None))[0] != ahora[n][0])
        dg_dist = sorted(n for n in ahora
                         if n not in rc_dist
                         and antes.get(n, (None, None))[1] != ahora[n][1])
        if not rc_dist and not dg_dist:
            print("[ok] ni un veredicto ni un diagnostico cambian "
                  "(%d comprobados)" % len(fuentes))
            return 0
        if rc_dist:
            print("[CAMBIA COMO TERMINA] %d:" % len(rc_dist))
            for n in rc_dist:
                print("  %-42s %s -> %s" % (n, clasificar(antes[n][0]),
                                            clasificar(ahora[n][0])))
        if dg_dist:
            print("[CAMBIAN LOS DIAGNOSTICOS] %d:" % len(dg_dist))
            for n in dg_dist:
                print("  %-42s %d -> %d avisos"
                      % (n, len(antes[n][1]), len(ahora[n][1])))
        return 1

    # Sin comparacion: lo que importa es que NADIE se caiga.  Rechazar un
    # programa es trabajo hecho; caerse es un fallo del compilador.
    caidas = {n: v[0] for n, v in ahora.items()
              if v[0] not in (0, 1) or v[0] == -1}
    rechazos = sum(1 for v in ahora.values() if v[0] == 1)
    print("  %d compilan, %d rechazados (esperable en los negativos), "
          "%d se CAEN" % (sum(1 for v in ahora.values() if v[0] == 0),
                          rechazos, len(caidas)))
    for n, rc in sorted(caidas.items()):
        print("  %-42s %s" % (n, clasificar(rc)))
    return 1 if caidas else 0


if __name__ == "__main__":
    sys.exit(main())
