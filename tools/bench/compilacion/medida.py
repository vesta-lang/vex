#!/usr/bin/env python3
"""Como se toma una medida, y como se comprueba que valga algo.

Dos cosas que no hay que mezclar: comprobar que una orden COMPILA de verdad
(un compilador que falla deprisa daria el mejor tiempo del banco) y cronometrar
la que ya se sabe buena.  Lo primero se paraleliza; lo segundo jamas, porque
entonces se mediria la carga de la maquina.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .comun import _stats_summary, serie_asentada, una_medida
from .memoria import pico_memoria
from .ordenes import enfriar
def compila_de_verdad(lang: str, cmd: list[str], env: dict, cwd: Path,
                      salida: Path, timeout: float) -> tuple[bool, str]:
    """Esta orden COMPILA, o solo falla deprisa?

    Sin esta comprobacion el modulo cronometra fallos y los publica como
    tiempos.  Paso de verdad: el generador nombraba las funciones `f0..f199` y
    en Vesta `f32` y `f64` son palabras reservadas, asi que la compilacion
    moria en el parser -- y 26 ms de error entraban en la tabla como el mejor
    tiempo de compilacion de la tanda.

    Se exige lo mismo que se le exigiria a cualquiera: codigo de salida cero Y
    un artefacto en disco.  Cualquiera de las dos por separado se deja enganar.
    """
    # Orden vacia: el lenguaje no tiene camino de compilacion (`python` genera
    # fuente y tiene modo de comprobacion, pero no compila a binario, asi que
    # `orden_compilar` devuelve []).  Se responde como cualquier otro caso que
    # no compila.  Antes esto llegaba a `subprocess.run([])`, que revienta con
    # `IndexError` -- no con `OSError`, que es lo unico que se recogia -- y
    # tumbaba la tanda entera en la primera fase que no llevara la guarda.
    if not cmd:
        return (False, "sin orden de compilacion para este lenguaje")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, cwd=str(cwd),
                           env=env, timeout=timeout)
    except subprocess.TimeoutExpired:
        return (False, "se paso del tiempo limite")
    except OSError as e:
        # No llego ni a arrancar: ejecutable ausente o directorio invalido.  Se
        # devuelve como caso que no compila, no como excepcion que tumba la
        # tanda entera.
        return (False, "no se pudo lanzar: %s" % e)
    if r.returncode != 0:
        primera = (r.stderr or r.stdout or "").strip().splitlines()
        return (False, primera[0] if primera else "codigo de salida != 0")
    # El artefacto: cada herramienta lo deja con un nombre distinto.
    candidatos = [salida, salida.with_suffix(".exe"), salida.with_suffix(".velb"),
                  salida.parent / "clases"]
    if any(c.exists() for c in candidatos):
        return (True, "")
    # Diagnostico que no cuesta nada y ahorra media hora: si el proceso salio
    # con cero pero no dejo nada, lo mas probable es que haya escrito los
    # errores sin cambiar el codigo de salida.
    primera = (r.stdout or r.stderr or "").strip().splitlines()
    return (False, "no genero artefacto"
            + (": " + primera[0] if primera else ""))


def verificar_en_paralelo(casos: list, jobs: int, timeout: float) -> dict:
    """Comprueba EN PARALELO que cada caso compila.  Devuelve clave -> (ok, motivo).

    Se paraleliza esto y NO las mediciones, y la distincion es la que sostiene
    todo el modulo: compilar para comprobar que el caso es valido no se
    cronometra, asi que da igual que ocho compiladores se peleen por la CPU.
    Cronometrar mientras otros siete compilan daria un numero que mide la carga
    de la maquina, no el compilador.

    Quien venga luego a "optimizar" el bucle de medidas metiendolas aqui estara
    haciendo el benchmark mas rapido y mas falso a la vez.
    """
    resultados: dict = {}
    if not casos:
        return resultados
    with ThreadPoolExecutor(max_workers=max(1, jobs)) as ex:
        futuros = {
            ex.submit(compila_de_verdad, lang, cmd, env, cwd, salida, timeout):
                clave
            for (clave, lang, cmd, env, cwd, salida) in casos
        }
        for f in as_completed(futuros):
            clave = futuros[f]
            try:
                resultados[clave] = f.result()
            except Exception as e:  # noqa: BLE001
                resultados[clave] = (False, str(e))
    return resultados


def repeticiones(args, muestra_ms: float) -> int:
    """Cuantas veces medir, segun lo que tarde una medida.

    Repetir cinco veces algo que tarda cinco segundos son veinticinco segundos
    para afinar un numero que ya se conoce con una precision de sobra: la
    dispersion se publica, asi que si tres medidas no bastan se ve en la MAD y
    se sube a mano.  Lo que no se hace es recortar en las medidas rapidas, que
    son las que de verdad necesitan repeticion.
    """
    if muestra_ms >= 5000.0:
        return max(2, args.repes // 2)
    if muestra_ms >= 1000.0:
        return max(3, args.repes - 1)
    return args.repes


def _calentar(cmd, env, cwd, timeout) -> int:
    """Descarta ejecuciones hasta que la serie deja de bajar (mismo criterio
    que el arnes de ejecucion: no es un numero fijo, se decide midiendo)."""
    traza: list[float] = []
    gastado = 0.0
    while len(traza) < 12 and not serie_asentada(traza) and gastado < 20000.0:
        ms = una_medida(cmd, env, timeout, cwd)
        if ms < 0:
            break
        traza.append(ms)
        gastado += ms
    return len(traza)


def fases_internas(cmd, env, cwd, timeout) -> dict:
    """El reparto por fases que el propio compilador publica.

    El tiempo total dice CUANTO tarda; esto dice EN QUE.  Sin ello, un banco
    que compara lenguajes solo puede senalar que vamos peor en algun tamano,
    no donde se va ese tiempo -- y "hacemos trabajo de mas en codigo sencillo"
    no se arregla sin saber en que fase.

    En una pasada APARTE, por el mismo motivo que la memoria: capturar la
    salida cuesta, y lo que se publica como tiempo tiene que ser el del
    compilador, no el del que lo mira.  Una basta: el reparto no depende del
    estado de la maquina.

    Solo Vesta lo emite; para el resto de lenguajes no hay equivalente y se
    devuelve vacio en vez de inventar uno.
    """
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, cwd=str(cwd),
                           env=env, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return {}
    for linea in (r.stdout or "").splitlines():
        if not linea.startswith("__VESTA_TIMES_FRONTEND__"):
            continue
        try:
            d = json.loads(linea.split(" ", 1)[1])
        except (ValueError, IndexError):
            return {}
        # Solo el reparto por fases.  El detalle por pase tambien viene, pero
        # son decenas de entradas por medida y ahogarian el JSON; para eso esta
        # la salida del compilador a pelo.
        return {k: v for k, v in d.items() if k.endswith("_us")}
    return {}


def medir_caliente(cmd, env, cwd, repes, timeout, lang: str = "") -> dict:
    """Serie con las caches CALIENTES: se calienta y luego se mide.

    @p lang solo sirve para saber si pedir el reparto por fases; es opcional
    para no obligar a tocar a quien no lo necesita.
    """
    _calentar(cmd, env, cwd, timeout)
    muestras = [una_medida(cmd, env, timeout, cwd) for _ in range(repes)]
    muestras = [m for m in muestras if m >= 0]
    if not muestras:
        return {}
    s = _stats_summary(muestras)
    # La memoria se mide en una pasada APARTE, no dentro de las que cronometran.
    # Meterla en las mismas contaminaria el tiempo: seguir el consumo cuesta, y
    # lo que se publica como tiempo tiene que ser el del compilador, no el del
    # que lo mira.  Una pasada basta porque el pico apenas varia entre corridas
    # -- lo que se reserva depende del programa, no del estado de la maquina.
    s["mem_kib"] = pico_memoria(cmd, env, cwd, timeout)
    if lang.startswith("vesta"):
        s["fases_us"] = fases_internas(cmd, env, cwd, timeout)
    return s


def medir_frio(cmd, env, cwd, repes, timeout, lang, dir_cache) -> dict:
    """Serie EN FRIO: se vacia la cache antes de CADA medida.

    No se calienta: calentar seria justo lo contrario de lo que se quiere.  A
    cambio, estas medidas son las mas ruidosas del modulo -- cada una paga
    ademas la paginacion del compilador -- y por eso se publica su dispersion.
    """
    muestras = []
    for _ in range(repes):
        enfriar(lang, cwd, dir_cache)
        ms = una_medida(cmd, env, timeout, cwd)
        if ms >= 0:
            muestras.append(ms)
    if not muestras:
        return {}
    s = _stats_summary(muestras)
    # Tambien en frio, y con la cache vaciada justo antes: sin cache hay que
    # rehacer trabajo que en caliente se lee ya hecho, y eso puede pedir mas
    # memoria.  Publicar solo el pico en caliente ocultaria precisamente el
    # caso que decide si una compilacion cabe en la maquina.
    enfriar(lang, cwd, dir_cache)
    s["mem_kib"] = pico_memoria(cmd, env, cwd, timeout)
    if lang.startswith("vesta"):
        enfriar(lang, cwd, dir_cache)
        s["fases_us"] = fases_internas(cmd, env, cwd, timeout)
    return s


