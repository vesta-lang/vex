#!/usr/bin/env python3
"""Ordenes de compilacion, y donde guarda su cache cada herramienta.

Lo segundo es tan importante como lo primero: si "en frio" se mide sin vaciar
la cache de quien la tenga, se compara el primer arranque de unos con el
enesimo de otros.  Cada herramienta la guarda en un sitio distinto, asi que
"frio" hay que definirlo una vez por herramienta o no significa nada.
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import Optional

from .comun import ELEGIDO

# ---------------------------------------------------------------------------
#  Los DOS ejes de paralelismo.  No es una eleccion entre ellos: son dos
#  preguntas distintas y las dos se publican.
#
#    secuencial  cada herramienta con un solo hilo.  Mide la EFICIENCIA del
#                compilador: cuanto trabajo hace por unidad de trabajo.
#    maquina     cada herramienta como la usaria un proyecto de verdad --
#                Vesta con su paralelismo automatico, `make -j`, `go build`
#                con sus paquetes en paralelo.  Mide lo que SUFRE el usuario.
#
#  La distancia entre los dos es cuanto aprovecha cada herramienta la maquina,
#  que es un resultado por si mismo y antes no aparecia en ningun sitio.
#  Publicar solo el segundo y llamarlo "tiempo de compilacion" comparaba ocho
#  hilos contra uno sin decirlo.
# ---------------------------------------------------------------------------

SECUENCIAL = "secuencial"
MAQUINA = "maquina"
PARALELISMO = (SECUENCIAL, MAQUINA)


def orden_compilar(lang: str, fuente: Path, salida: Path, vm: Path) -> list[str]:
    """Compilacion COMPLETA hasta binario ejecutable."""
    if lang == "c":
        return [ELEGIDO["c"], "-O2", "-std=c11", str(fuente), "-o", str(salida)]
    if lang == "cpp":
        return [ELEGIDO["cpp"], "-O2", "-std=c++17", str(fuente), "-o", str(salida)]
    if lang == "rust":
        # `-C incremental` es la cache de rustc.  Sin ella, este banco medía
        # a Rust SIN cache y publicaba su aporte como 1.00x -- que se leia
        # como "Rust no cachea" cuando lo que pasaba es que no se le habia
        # dado donde.  El `CARGO_HOME` que se redirigia no pintaba nada: aqui
        # se invoca `rustc` a pelo y cargo no llega a correr.
        # Medido con 5954 lineas: sin el flag, frio y caliente dan lo mismo
        # (236 y 267 ms); con el, 277 en frio y 175-187 en caliente.
        # Va bajo el directorio del caso, como el `--nimcache` de Nim y por el
        # mismo motivo: si viviera en el sitio de siempre, "en frio" no seria
        # frio.
        return ["rustc", "-O", "-C",
                "incremental=" + str(salida.parent / "rustc-inc"),
                str(fuente), "-o", str(salida)]
    if lang == "go":
        return ["go", "build", "-o", str(salida), str(fuente)]
    if lang == "java":
        return ["javac", "-d", str(salida.parent / "clases"), str(fuente)]
    if lang == "nim":
        # `-d:release` para que sea comparable con el `-O2` de los demas.
        # `--nimcache` dentro del directorio del caso: Nim guarda el C que
        # genera, y si esa cache viviera en el sitio de siempre, "en frio" no
        # seria frio -- que es exactamente el error que este modulo evita.
        # `--hints:off` porque su salida normal es muy verbosa y aqui no se
        # lee.
        return ["nim", "c", "-d:release", "--hints:off",
                "--nimcache:" + str(salida.parent / "nimcache"),
                "-o:" + str(salida), str(fuente)]
    if lang == "vesta":
        return [str(vm), "--vesta", str(fuente), "-o", str(salida)]
    if lang == "vesta_aot":
        # El camino NATIVO: sigue hasta MachineIR, asignacion de registros,
        # codificacion y enlazado propio.  No cuesta lo mismo que parar en el
        # `.velb`, y publicarlos juntos daria un numero que no es ninguno.
        fmt = "pe" if sys.platform == "win32" else "elf"
        return [str(vm), "-m", "aot", "--vx", str(fuente), "-o",
                str(salida) + ".exe", "--emit", "exe", "--format", fmt]
    return []


def orden_comprobar(lang: str, fuente: Path, salida: Path,
                    vm: Path) -> Optional[list[str]]:
    """Solo COMPROBAR: analizar y diagnosticar, sin generar codigo ni enlazar.

    Es lo que hay detras de "cuanto tardo en ver el error".  No todos lo
    ofrecen, y el que no lo tenga se queda fuera de ese eje en vez de
    compararse contra algo que no es lo mismo.
    """
    if lang == "c":
        return [ELEGIDO["c"], "-fsyntax-only", "-std=c11", str(fuente)]
    if lang == "cpp":
        return [ELEGIDO["cpp"], "-fsyntax-only", "-std=c++17", str(fuente)]
    if lang == "rust":
        # Tambien aqui su cache.  Esta fase mide en CALIENTE, y sin el flag
        # rustc no se calienta nunca mientras Vesta si reaprovecha la suya:
        # seria comparar el enesimo intento de uno con el primero del otro.
        # Medido con 5954 lineas: 144 ms sin el flag, 93-102 con el.
        # Directorio APARTE del de `orden_compilar`: comparten el del caso, y
        # si compartieran tambien la cache, "cuanto tardo en ver el error"
        # podria salir caliente por una compilacion completa anterior --
        # contaminacion entre dos fases que miden cosas distintas.
        return ["rustc", "--emit=metadata", "-C",
                "incremental=" + str(salida.parent / "rustc-inc-chk"),
                "-o", str(salida) + ".rmeta", str(fuente)]
    if lang == "python":
        return [sys.executable, "-m", "py_compile", str(fuente)]
    if lang == "vesta":
        # Sin `--vesta ... -o` no hay etapa de check separada todavia; lo mas
        # cercano es volcar el IR sin emitir binario.  Queda anotado como
        # aproximacion en vez de presentarse como equivalente exacto.
        return [str(vm), "--vx-emit-only", "--vesta", str(fuente), "-o",
                str(salida)]
    # go y java no tienen un modo "solo comprobar" separado de compilar.
    return None


def entorno_cache(lang: str, dir_cache: Path, base: dict,
                  paralelo: str = "") -> dict:
    """Entorno con la cache de @p lang apuntando a @p dir_cache.

    Redirigir la cache es lo unico que permite decir "en frio" con propiedad:
    borrar un directorio del repositorio deja frio a Vesta y calientes a Go y
    Rust, y la comparacion resultante mide el estado de la maquina, no los
    compiladores.

    @p paralelo elige el EJE (ver `PARALELISMO`).  En `secuencial` se le pide a
    cada herramienta que use un solo hilo; en `maquina` se la deja hacer lo que
    haria en un uso normal.  Sin esto, la fase multi-modulo comparaba Vesta
    -- que por defecto reparte los modulos de un mismo nivel topologico hasta
    en 8 hilos -- contra una sola invocacion secuencial de gcc, y el lector
    supone recursos iguales.
    """
    e = dict(base)
    dir_cache.mkdir(parents=True, exist_ok=True)
    if paralelo == SECUENCIAL:
        # `VX_PARALLEL_COMPILE=1` fuerza secuencial en el compilador Vesta
        # (0 o ausente = auto, hasta 8 hilos).  Es su propia valvula de
        # diagnostico, documentada en src/vx/compiler_project.cpp.
        e["VX_PARALLEL_COMPILE"] = "1"
    elif paralelo == MAQUINA:
        e.pop("VX_PARALLEL_COMPILE", None)   # auto
    if lang == "go":
        e["GOCACHE"] = str(dir_cache / "go")
    elif lang == "rust":
        # Se conserva por si algun dia se compila via cargo, pero HOY no hace
        # nada: el banco invoca `rustc` directamente y cargo no llega a
        # correr.  La cache que rustc si usa es la de `-C incremental`, que va
        # en la propia orden (ver `orden_compilar`) porque es un argumento y no
        # una variable de entorno.
        e["CARGO_HOME"] = str(dir_cache / "cargo")
    elif lang == "vesta":
        # El compilador Vesta cachea en el arbol: `.cache/` junto al proyecto y
        # los `.vxi`/`.vxir` al lado de cada fuente.  No hay variable que lo
        # mueva, asi que en frio se BORRAN (ver `enfriar`).
        pass
    return e


def enfriar(lang: str, dir_trabajo: Path, dir_cache: Path) -> None:
    """Deja a @p lang sin ninguna cache antes de una medida en frio."""
    for sub in (dir_cache / "go", dir_cache / "cargo"):
        shutil.rmtree(sub, ignore_errors=True)
    if lang == "nim":
        # Nim guarda el C que genera, y de ahi para adelante no vuelve a
        # generarlo ni a compilarlo.  Sin borrarlo, "en frio" era caliente
        # desde la segunda medida: se vio en el banco -- 1484 lineas y 5900
        # daban el MISMO tiempo, que es imposible si de verdad estuviera
        # compilando las dos.
        shutil.rmtree(dir_trabajo / "nimcache", ignore_errors=True)
    if lang == "rust":
        # La cache incremental de rustc, que `orden_compilar` puso aqui.  Sin
        # borrarla, la segunda medida "en frio" ya seria caliente -- el mismo
        # fallo que se arreglo en Nim.
        shutil.rmtree(dir_trabajo / "rustc-inc", ignore_errors=True)
        shutil.rmtree(dir_trabajo / "rustc-inc-chk", ignore_errors=True)
    if lang in ("vesta", "vesta_aot"):
        shutil.rmtree(dir_trabajo / ".cache", ignore_errors=True)
        shutil.rmtree(dir_trabajo / ".vx_cache", ignore_errors=True)
        for p in list(dir_trabajo.glob("*.vxi")) + list(dir_trabajo.glob("*.vxir")):
            try:
                p.unlink()
            except OSError:
                pass


