#!/usr/bin/env python3
"""Cuanta memoria llega a usar un compilador.

Es la otra mitad del coste, y la que decide si algo se puede compilar en una
maquina concreta.  Un compilador que tarda la mitad pero pide cuatro veces mas
memoria no es mas barato: es mas caro en cuanto el proyecto crece o la maquina
es modesta.  Y es un limite DURO -- pasarse no hace la compilacion lenta, la
hace imposible --, mientras que tardar mas solo se sufre.

Lo que se mide es el PICO, no lo que hay al final: un compilador puede acabar
con poco residente despues de haber pedido gigabytes a mitad de camino, y lo
que hace fracasar la compilacion es el maximo.

Medirlo bien tiene una trampa que hay que nombrar: varias herramientas lanzan
OTROS procesos.  Nim genera C y llama a un compilador de C; Go y Java lanzan
sus propios ayudantes.  Mirar solo el proceso que se invoca da un numero que no
tiene nada que ver con lo que la maquina llego a reservar.  Por eso aqui se
mide el ARBOL entero:

  Windows   El proceso se mete en un Job Object y despues se consulta
            `PeakJobMemoryUsed`, que es exactamente "lo maximo que llegaron a
            usar a la vez todos los procesos del grupo".  Los hijos que cree el
            proceso heredan el grupo, asi que el compilador de C que lanza Nim
            cuenta.

  POSIX     `os.wait4` devuelve el consumo de ESE hijo -- y de los suyos que ya
            hubiera esperado -- en `ru_maxrss`.  Se usa `fork` + `exec` en vez
            de `subprocess` porque este ultimo se queda con el hijo y entonces
            ya no se puede preguntar por el.

Si en una plataforma no se puede medir, se devuelve None y quien lo publique
enseña un hueco.  Un cero seria mentira: no es que no gastara memoria, es que
no se supo.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional


def _pico_windows(cmd: list, env: dict, cwd: Path,
                  timeout: float) -> Optional[int]:
    """Pico del arbol de procesos, en KiB, via Job Object."""
    import ctypes
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [("ReadOperationCount", ctypes.c_ulonglong),
                    ("WriteOperationCount", ctypes.c_ulonglong),
                    ("OtherOperationCount", ctypes.c_ulonglong),
                    ("ReadTransferCount", ctypes.c_ulonglong),
                    ("WriteTransferCount", ctypes.c_ulonglong),
                    ("OtherTransferCount", ctypes.c_ulonglong)]

    class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong),
                    ("PerJobUserTimeLimit", ctypes.c_longlong),
                    ("LimitFlags", wintypes.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.POINTER(ctypes.c_ulong)),
                    ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD)]

    class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [("BasicLimitInformation",
                     JOBOBJECT_BASIC_LIMIT_INFORMATION),
                    ("IoInfo", IO_COUNTERS),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t)]

    JobObjectExtendedLimitInformation = 9

    job = k32.CreateJobObjectW(None, None)
    if not job:
        return None
    try:
        p = subprocess.Popen(cmd, env=env, cwd=str(cwd),
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        # Se mete en el grupo nada mas crearlo.  Queda una rendija -- lo que
        # tarda el proceso en arrancar -- en la que sus primeras reservas no se
        # cuentan; es despreciable frente a lo que pide un compilador
        # trabajando, y a cambio no hace falta crearlo suspendido, que en
        # Python obliga a manejar el hilo principal a mano.
        try:
            k32.AssignProcessToJobObject(job, int(p._handle))
        except Exception:  # noqa: BLE001
            pass
        try:
            p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
            return None
        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        devuelto = wintypes.DWORD(0)
        ok = k32.QueryInformationJobObject(
            job, JobObjectExtendedLimitInformation, ctypes.byref(info),
            ctypes.sizeof(info), ctypes.byref(devuelto))
        if not ok:
            return None
        return int(info.PeakJobMemoryUsed) // 1024
    finally:
        k32.CloseHandle(job)


def _pico_posix(cmd: list, env: dict, cwd: Path,
                timeout: float) -> Optional[int]:
    """Pico del hijo, en KiB, via `os.wait4`, sin pasar de @p timeout.

    El @p timeout se respeta de verdad: antes se llamaba a `os.wait4(pid, 0)`,
    que bloquea SIN LiMITE, asi que un compilador colgado colgaba la tanda
    entera -- y solo en POSIX, porque el camino de Windows si lo respetaba via
    el Job Object.  Se espera con @c WNOHANG hasta la fecha limite y, pasada,
    se mata al hijo y se recoge para no dejar un zombi.

    Sondear aqui no contamina nada: esta pasada NO cronometra -- el tiempo se
    mide en su propia serie, aparte y por el mismo motivo -- asi que lo que
    cuesta mirar cada dos milisegundos da igual.
    """
    if not cmd:
        return None
    try:
        pid = os.fork()
    except OSError:
        return None
    if pid == 0:  # hijo
        try:
            os.chdir(str(cwd))
            nulo = os.open(os.devnull, os.O_WRONLY)
            os.dup2(nulo, 1)
            os.dup2(nulo, 2)
            os.execvpe(cmd[0], list(cmd), env)
        except Exception:  # noqa: BLE001
            os._exit(127)
    fin = time.monotonic() + max(0.0, timeout)
    estado, uso = None, None
    while True:
        hijo, est, us = os.wait4(pid, os.WNOHANG)
        if hijo == pid:
            estado, uso = est, us
            break
        if time.monotonic() >= fin:
            # Se pasó del limite: se mata y se recoge.  No se devuelve un pico
            # a medias, que se leeria como una medida buena de un caso que no
            # llego a terminar.
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
            try:
                os.wait4(pid, 0)
            except OSError:
                pass
            return None
        time.sleep(0.002)
    if estado != 0:
        return None
    # En Linux `ru_maxrss` viene en KiB; en macOS, en bytes.
    bruto = int(uso.ru_maxrss)
    return bruto // 1024 if sys.platform == "darwin" else bruto


def pico_memoria(cmd: list, env: dict, cwd: Path,
                 timeout: float) -> Optional[int]:
    """Memoria maxima que llego a usar @p cmd (y sus hijos), en KiB.

    None cuando no se pudo medir: en esta plataforma no hay forma, o el proceso
    fallo.  Quien lo publique debe enseñar un hueco, no un cero.
    """
    try:
        if sys.platform == "win32":
            return _pico_windows(cmd, env, cwd, timeout)
        return _pico_posix(cmd, env, cwd, timeout)
    except Exception:  # noqa: BLE001
        return None


def formatear(kib: Optional[int]) -> str:
    """La cifra en la unidad que se lea de un vistazo, o un guion si no la hay."""
    if not kib:
        return "-"
    if kib < 1024:
        return "%d KiB" % kib
    if kib < 1024 * 1024:
        return "%.0f MiB" % (kib / 1024.0)
    return "%.2f GiB" % (kib / (1024.0 * 1024.0))


def tamano_arbol(d: Path) -> int:
    """Bytes que ocupa @p d con todo lo que hay dentro.

    Sirve para dos cosas que el banco contaba a medias: lo que ocupa el
    artefacto producido y lo que ocupa la cache que lo acelera.  Una cache que
    ahorra dieciocho veces y ocupa dos gigas es una decision, no una ventaja, y
    hasta ahora solo se publicaba la mitad buena.
    """
    if not d.exists():
        return 0
    if d.is_file():
        try:
            return d.stat().st_size
        except OSError:
            return 0
    total = 0
    for hijo in d.rglob("*"):
        try:
            if hijo.is_file():
                total += hijo.stat().st_size
        except OSError:
            pass   # desaparecio mientras se recorria: no vale la pena morir
    return total


def formatear_bytes(n: int) -> str:
    """Bytes en la unidad que se lea de un vistazo, o un guion si no hay."""
    if not n:
        return "-"
    if n < 1024:
        return "%d B" % n
    if n < 1024 * 1024:
        return "%.0f KiB" % (n / 1024.0)
    if n < 1024 * 1024 * 1024:
        return "%.1f MiB" % (n / (1024.0 * 1024.0))
    return "%.2f GiB" % (n / (1024.0 * 1024.0 * 1024.0))
