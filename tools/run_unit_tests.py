#!/usr/bin/env python3
"""run_unit_tests.py -- ejecuta los binarios de test unitario y resume.

Cada `.cpp` de `tests/` produce un ejecutable propio; el proyecto no usa ctest,
asi que sin esto no hay forma de correrlos todos de una vez.  Y sin forma de
correrlos, no se corren: asi es como un test dejo de compilar al cambiar la
firma de una funcion y siguio roto sin que nadie se enterara.

Un test se considera PASS si termina con codigo 0.  Los que se cuelgan se matan
al llegar al tiempo limite y cuentan como TIMEOUT, no como fallo silencioso.

TOPE DE MEMORIA
---------------
Cada test corre con un techo de memoria y se MATA al pasarlo (cuenta como
MEMORIA, aparte de FAIL).  No es precaucion generica: aqui se prueban el
recolector y el asignador, y un fallo suyo no se queda quieto -- pide memoria
sin parar --.  Con solo el limite de tiempo, un test asi tenia dos minutos para
llenar la RAM de la maquina, y ademas se corren VARIOS a la vez.

Lo pone el nucleo, no un vigilante: `RLIMIT_AS` en POSIX y un Job Object en
Windows.  Asi el proceso muere aunque este dentro de un bucle que no devuelve
el control.

Uso:
    python tools/run_unit_tests.py [build_dir] [-k patron] [--timeout N] [-j N]
                                   [--mem-mb N]
"""

import argparse
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def say(text):
    """@brief Imprime sin morir por lo que no quepa en la consola.

    La salida de un test puede traer color ANSI y caracteres que la consola de
    Windows no sabe representar.  Sin esto, el resumen entero se pierde por un
    byte de un test: el informe reventaba justo donde iba a decir que fallo.
    """
    enc = getattr(sys.stdout, "encoding", None) or "utf-8"
    sys.stdout.write(text.encode(enc, "replace").decode(enc, "replace") + "\n")


def collect(build_dir, pattern):
    """@brief Reune los ejecutables de test del directorio de build.

    @param build_dir Directorio de compilacion.
    @param pattern   Subcadena que debe contener el nombre, o None.
    @return Lista de rutas, ordenada.
    """
    found = []
    for dirpath, _dirnames, filenames in os.walk(build_dir):
        for name in filenames:
            if not name.startswith("test_"):
                continue
            if not name.endswith(".exe") and "." in name:
                continue
            if pattern and pattern not in name:
                continue
            found.append(os.path.join(dirpath, name))
    return sorted(found)


def _parece_sin_memoria(rc, salida):
    """Si el proceso murio por el techo de memoria y no por un fallo suyo.

    No hay una senal unica que lo diga: en POSIX una reserva que pasa de
    `RLIMIT_AS` devuelve NULL y el programa suele abortar (SIGABRT) o morir por
    `std::bad_alloc`; en Windows el Job Object lo mata con un codigo propio.  Se
    mira lo que hay: el codigo y lo que dejo dicho.
    """
    if rc in (-6, 134):  # SIGABRT: el clasico de un alloc que devuelve NULL
        return True
    if os.name == "nt" and (rc & 0xFFFFFFFF) in (0xC0000017, 0x1F):
        return True      # STATUS_NO_MEMORY, o el codigo del job
    marcas = ("bad_alloc", "out of memory", "Cannot allocate memory",
              "memoria agotada", "OUT_OF_MEMORY")
    return any(m in salida for m in marcas)


def _limitador_posix(mem_bytes):
    """El techo de memoria del hijo, puesto por el NUCLEO (RLIMIT_AS).

    Se aplica en el proceso hijo justo antes de ejecutar, asi que vale aunque
    el test no vuelva a ceder el control: la reserva que pase del tope FALLA y
    el proceso se cae, en vez de seguir pidiendo hasta agotar la maquina.
    """
    import resource

    def poner():
        resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))

    return poner


def _job_windows(mem_bytes):
    """Un Job Object con techo de memoria, o None si no se pudo crear.

    Es el equivalente de Windows a `RLIMIT_AS`: el sistema mata el proceso al
    pasarse.  Se le pone tambien el cierre-mata-todo, para que un test que deje
    hijos no se los deje sueltos si el lanzador termina.
    """
    if os.name != "nt":
        return None
    try:
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

        class BASIC(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong),
                        ("PerJobUserTimeLimit", ctypes.c_longlong),
                        ("LimitFlags", wintypes.DWORD),
                        ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t),
                        ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.POINTER(ctypes.c_ulong)),
                        ("PriorityClass", wintypes.DWORD),
                        ("SchedulingClass", wintypes.DWORD)]

        class EXTENDED(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", BASIC),
                        ("IoInfo", IO_COUNTERS),
                        ("ProcessMemoryLimit", ctypes.c_size_t),
                        ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t),
                        ("PeakJobMemoryUsed", ctypes.c_size_t)]

        JOB_MEM = 0x00000100          # LIMIT_PROCESS_MEMORY
        JOB_KILL_ON_CLOSE = 0x00002000
        EXTENDED_CLASS = 9            # JobObjectExtendedLimitInformation

        job = k32.CreateJobObjectW(None, None)
        if not job:
            return None
        info = EXTENDED()
        info.BasicLimitInformation.LimitFlags = JOB_MEM | JOB_KILL_ON_CLOSE
        info.ProcessMemoryLimit = mem_bytes
        if not k32.SetInformationJobObject(job, EXTENDED_CLASS,
                                           ctypes.byref(info),
                                           ctypes.sizeof(info)):
            k32.CloseHandle(job)
            return None
        return (k32, job)
    except Exception:
        return None


def run_one(path, timeout, mem_mb):
    """@brief Ejecuta un test con techo de tiempo y de MEMORIA.
    @return (nombre, estado, salida) con estado en PASS/FAIL/TIMEOUT/MEMORIA.
    """
    name = os.path.basename(path)
    mem_bytes = mem_mb * 1024 * 1024 if mem_mb > 0 else 0
    kw = {}
    trabajo = None
    if mem_bytes:
        if os.name != "nt":
            kw["preexec_fn"] = _limitador_posix(mem_bytes)
        else:
            trabajo = _job_windows(mem_bytes)
    try:
        p = subprocess.Popen([path], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, cwd=ROOT, **kw)
        if trabajo:
            # Se mete en el job recien creado.  Hay una rendija entre arrancar y
            # asignar, pero un test no reserva gigabytes en ese hueco: primero
            # tiene que cargarse e inicializarse.
            k32, job = trabajo
            import ctypes
            h = ctypes.c_void_p(int(p._handle))
            k32.AssignProcessToJobObject(job, h)
        try:
            out_b, err_b = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            p.communicate()
            return (name, "TIMEOUT", "")
    except OSError as e:
        return (name, "FAIL", str(e))
    finally:
        if trabajo:
            trabajo[0].CloseHandle(trabajo[1])
    out = (out_b or b"").decode("utf-8", "replace")
    err = (err_b or b"").decode("utf-8", "replace")
    if p.returncode == 0:
        return (name, "PASS", out + err)
    # Al sistema matar un proceso por pasarse de memoria no sale un fallo del
    # test: sale un codigo de salida raro.  Se distingue para que el resumen no
    # diga "falla" cuando lo que paso es que se comio el techo -- son dos cosas
    # que se arreglan de forma distinta.
    salida = out + err
    if _parece_sin_memoria(p.returncode, salida):
        return (name, "MEMORIA", salida)
    return (name, "FAIL", salida)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build_dir", nargs="?", default="cmake-build-release")
    parser.add_argument("-k", dest="pattern", help="filtra por nombre")
    parser.add_argument("--timeout", type=int, default=120, help="segundos por test")
    parser.add_argument("--mem-mb", type=int, default=2048,
                        dest="mem_mb",
                        help="techo de memoria por test en MiB "
                             "(0 = sin techo).  Aqui se prueban el "
                             "recolector y el asignador: un fallo suyo "
                             "pide memoria sin parar y con solo el "
                             "limite de tiempo se lleva la RAM de la "
                             "maquina")
    parser.add_argument("-j", type=int, default=max(1, (os.cpu_count() or 4) // 2))
    args = parser.parse_args()

    build_dir = args.build_dir
    if not os.path.isabs(build_dir):
        build_dir = os.path.join(ROOT, build_dir)
    tests = collect(build_dir, args.pattern)
    if not tests:
        print("no se encontro ningun ejecutable de test en " + build_dir)
        return 2

    with ThreadPoolExecutor(max_workers=args.j) as pool:
        results = list(pool.map(
            lambda t: run_one(t, args.timeout, args.mem_mb), tests))

    bad = [r for r in results if r[1] != "PASS"]
    for name, state, out in bad:
        say("== {} [{}]".format(name, state))
        # Las ultimas lineas son donde el test dice que fallo; el resto es ruido.
        tail = [l for l in out.splitlines() if l.strip()][-12:]
        for line in tail:
            say("   " + line[:160])

    print(
        "\n=== tests unitarios: {} OK, {} fallidos de {}".format(
            len(results) - len(bad), len(bad), len(results)
        )
    )
    if bad:
        print("   " + ", ".join(n for n, _s, _o in bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
