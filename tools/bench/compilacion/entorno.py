#!/usr/bin/env python3
"""De que maquina salieron estos numeros.

Un banco cuyo resultado es un JSON guardado tiene que decir DONDE se midio, o
ese fichero deja de ser comparable con el siguiente.  Sin esto, una tanda hecha
en WSL sobre un disco de Windows y otra hecha en ext4 nativo producen ficheros
indistinguibles, y la unica forma de saber cual es cual es acordarse.

El caso que motiva el modulo es real: en una tanda sobre `/mnt/f` -- o sea
DrvFs, el puente de WSL hacia el disco de Windows -- TODOS los tiempos que no
eran de Vesta cayeron en la rejilla `14 + k*50 ms`.  Cuatro compiladores
distintos aterrizando en los mismos multiplos no es comportamiento de
compilador, es del entorno; pero con el JSON de entonces no habia forma de
demostrarlo despues, porque no guardaba ni el sistema de ficheros ni si aquello
era WSL.  Ahora si.

Nada de lo que se recoge aqui cuesta tiempo de medida: se toma una vez al
arrancar, antes de la primera fase.
"""
from __future__ import annotations

import os
import platform
import shutil
import sys
from pathlib import Path


def _sistema_de_ficheros(ruta: Path) -> str:
    """Tipo del sistema de ficheros donde vive @p ruta, o "" si no se sabe.

    Es el dato que mas cambia los numeros y el que nadie apunta.  Compilar
    sobre DrvFs (`/mnt/c`, `/mnt/f`) desde WSL paga un sobrecoste por cada
    `open` y cada `stat` que no existe en un ext4 nativo, y como los
    compiladores tocan miles de ficheros, eso se ve en el reloj.  Publicar un
    tiempo sin decir sobre que se midio invita a compararlo con otro que no es
    comparable.
    """
    try:
        objetivo = str(Path(ruta).resolve())
    except OSError:
        return ""
    # /proc/mounts es lo unico que da el TIPO; `os.statvfs` da tamanos y
    # opciones pero no dice si esto es ext4, 9p o drvfs.
    try:
        with open("/proc/mounts", encoding="utf-8", errors="replace") as fh:
            lineas = fh.readlines()
    except OSError:
        return ""
    mejor, tipo = "", ""
    for linea in lineas:
        partes = linea.split()
        if len(partes) < 3:
            continue
        punto, clase = partes[1], partes[2]
        # El punto de montaje mas LARGO que sea prefijo: `/mnt/f` gana a `/`.
        if (objetivo == punto or objetivo.startswith(punto.rstrip("/") + "/")) \
                and len(punto) > len(mejor):
            mejor, tipo = punto, clase
    return tipo


def _es_wsl() -> tuple[bool, str]:
    """¿Corre esto dentro de WSL?  Devuelve (si, version del kernel)."""
    try:
        with open("/proc/version", encoding="utf-8", errors="replace") as fh:
            v = fh.read().strip()
    except OSError:
        return (False, "")
    return ("microsoft" in v.lower(), v)


def _modelo_de_cpu() -> str:
    """El modelo de CPU, que decide mas que el numero de nucleos."""
    try:
        with open("/proc/cpuinfo", encoding="utf-8", errors="replace") as fh:
            for linea in fh:
                if linea.lower().startswith("model name"):
                    return linea.split(":", 1)[1].strip()
    except OSError:
        pass
    # Fuera de Linux `platform.processor()` es lo que hay; en algunos sistemas
    # devuelve vacio, y un vacio se publica como vacio en vez de inventarlo.
    return platform.processor() or ""


def recoger(vm: Path, raiz: Path, base_tmp: Path, herramienta: dict,
            version_de) -> dict:
    """Todo lo que hace falta para volver a leer esta tanda dentro de un ano.

    @param vm           binario de Vesta que se va a medir.
    @param raiz         raiz del proyecto (para el commit).
    @param base_tmp     donde se generan las fuentes: es SU sistema de
                        ficheros el que pagan las medidas, no el del repo.
    @param herramienta  lenguaje -> ejecutable, tal y como lo eligio el CLI.
    @param version_de   funcion que saca la version de un ejecutable.
    """
    es_wsl, kernel = _es_wsl()
    # El hardware y el SO los recoge ya el arnes de ejecucion, y con mas
    # detalle del que tenia sentido reescribir aqui (RAM, frecuencia, nucleos
    # fisicos, por plataforma).  Se le pasa un toolchain vacio porque sus
    # versiones de compilador vienen en otra forma; las de aqui se anaden
    # abajo.  Duplicar esa funcion daria dos definiciones de "que maquina es
    # esta" que podrian separarse, que es lo mismo que evita `comun.py`.
    try:
        from run_all_benches import capture_system_info  # noqa: E402
        base = capture_system_info(vm, {}) or {}
    except Exception:  # noqa: BLE001
        base = {}
    datos = {
        "hardware": base.get("hardware") or base,
        "so": {
            "sistema": platform.system(),
            "version": platform.release(),
            "maquina": platform.machine(),
            "wsl": es_wsl,
            "kernel": kernel,
        },
        "cpu": {
            "modelo": _modelo_de_cpu(),
            "nucleos_logicos": os.cpu_count() or 0,
        },
        "python": sys.version.split()[0],
        "sistema_de_ficheros": {
            # Los dos, porque pueden ser distintos y el que manda es el de las
            # fuentes: el repo puede estar en ext4 y el TEMP en otra cosa.
            "fuentes": _sistema_de_ficheros(base_tmp),
            "proyecto": _sistema_de_ficheros(raiz),
        },
        "rutas": {"vm": str(vm), "fuentes": str(base_tmp)},
        "herramientas": {},
    }
    # Las versiones EXACTAS de cada compilador medido.  El arranque
    # interactivo ya las ensena para elegir y luego las tiraba; sin ellas, dos
    # tandas separadas por una actualizacion del sistema parecen la misma
    # medida hecha dos veces.
    for lang, exe in sorted(herramienta.items()):
        if not exe:
            continue
        ruta = shutil.which(exe) or (exe if Path(exe).is_file() else "")
        if not ruta:
            continue
        # Go no entiende `--version`: responde "flag provided but not
        # defined" y eso acababa GUARDADO como si fuera su version.  Un dato
        # mal recogido es peor que no tenerlo, porque nadie lo revisa.
        orden = ([ruta, "version"] if lang == "go"
                 else [ruta, "--version"])
        datos["herramientas"][lang] = {
            "ruta": ruta,
            "version": (version_de(orden) or "").strip(),
        }
    datos["herramientas"]["vesta"] = {
        "ruta": str(vm),
        "version": (version_de([str(vm), "--version"]) or "").strip(),
    }
    commit = _commit(raiz)
    if commit:
        datos["commit"] = commit
    return datos


def _commit(raiz: Path) -> str:
    """El commit del arbol medido, leido de `.git` sin invocar a git.

    Se lee el fichero en vez de lanzar `git rev-parse` porque esto corre antes
    de la primera medida y no merece la pena arrancar un proceso; y si no hay
    `.git`, no hay commit y ya, que es una respuesta valida.
    """
    try:
        cabeza = (raiz / ".git" / "HEAD").read_text(encoding="utf-8").strip()
    except OSError:
        return ""
    if not cabeza.startswith("ref:"):
        return cabeza          # HEAD suelto: ya es el hash
    ref = cabeza.split(":", 1)[1].strip()
    try:
        return (raiz / ".git" / ref).read_text(encoding="utf-8").strip()
    except OSError:
        pass
    # Referencia empaquetada: vive en `packed-refs` y no como fichero suelto.
    try:
        for linea in (raiz / ".git" / "packed-refs").read_text(
                encoding="utf-8").splitlines():
            if linea.startswith("#"):
                continue
            partes = linea.split()
            if len(partes) == 2 and partes[1] == ref:
                return partes[0]
    except OSError:
        pass
    return ""


def resumen(datos: dict) -> str:
    """Una linea para el terminal: lo que hay que ver sin abrir el JSON."""
    so = datos.get("so", {})
    fs = (datos.get("sistema_de_ficheros") or {}).get("fuentes") or "?"
    cpu = (datos.get("cpu") or {})
    partes = ["%s %s" % (so.get("sistema", "?"), so.get("maquina", "")),
              "%d nucleos" % (cpu.get("nucleos_logicos") or 0),
              "fuentes en %s" % fs]
    if so.get("wsl"):
        partes.append("WSL")
    return "  |  ".join(p for p in partes if p)
