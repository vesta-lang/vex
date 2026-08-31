#!/usr/bin/env python3
"""run_all_benches.py -- benchmark suite multi-lenguaje VestaVM.

Sprint bench-multilang (2026-06-02):
- Descubre benches en @c examples_codes_vx/benchmark/<bench_name>/ con
  multiples implementaciones (main.vx, main.c, main.cpp, main.py,
  Main.java).
- Detecta compiladores/runtimes disponibles (gcc, g++, javac+java,
  python, vesta).
- Compila + ejecuta cada implementacion midiendo wall time (mediana de
  N runs).
- Reporta tabla agrupada por bench con todos los lenguajes lado a lado.
- Genera grafica matplotlib comparativa + JSON con todos los datos.
- Tambien soporta el layout legacy @c benchmark/*.vx (un fichero
  Vesta-lang sin carpeta) ejecutando solo en Vesta-lang interp + JIT.

Modos de ejecucion del Vesta-lang:
- @b interp: VESTA_JIT_THRESHOLD=UINT32_MAX (forzado; el default del vm es 1500), 100% interp.
- @b jit: VESTA_JIT_THRESHOLD=1, fuerza JIT en el primer call.
- @b aot: compila el .vx a un .exe nativo standalone (-m aot --emit exe) y
  mide el wall time de la ejecucion nativa.  Solo cubre el subset nativo
  del lenguaje; los benches no soportados quedan N/A en esa columna.

Output:
- Tabla coloreada en terminal con spinner live + timer.
- @c bench_results.json con datos crudos.
- @c bench_results.png con grafica comparativa (matplotlib opcional).

Uso:
  python tools/bench/run_all_benches.py                  # auto-detect + prompt
  python tools/bench/run_all_benches.py /path/al/vm.exe  # binary fijo
  python tools/bench/run_all_benches.py --langs vx,c    # subset lenguajes
  python tools/bench/run_all_benches.py --filter fib     # subset benches
"""
from __future__ import annotations
import argparse
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional


# Benches legacy (single-file .vx) excluidos del modo multi-lenguaje.
LEGACY_SKIP_PATTERN = re.compile(
    r"^(bench_macro_|bench_shared_|bench_native_callback|"
    r"100_reflection|get_time|test_vptr_loop)"
)

# Numero de runs medidos.  Los lenguajes NO interpretados (nativos / JIT) son
# rapidos y muy sensibles al ruido del scheduler del SO -> se miden muchas veces
# y se toma la mediana.  Los INTERPRETADOS (Python, interprete Vesta puro) son
# lentos: 10 runs dispararian el tiempo total del harness sin ganar precision
# relativa -> se miden pocas veces.
RUNS_FAST = 10  # c/cpp/go/rust/java/vx_jit/vx_aot_* (no interpretados)
RUNS_SLOW = 3   # python, vx_interp (interpretados/lentos)
RUNS_PER_MODE = RUNS_FAST  # default de --runs (compat)
# Lenguajes interpretados/lentos: se miden con RUNS_SLOW.
INTERPRETED_LANGS = frozenset({"python", "vx_interp"})
BENCH_TIMEOUT = 60.0   # tope por caso.  Lo que pase de aqui NO se pierde:
                       # se apunta como ">tope" (cota inferior) en vez de
                       # como TIMEOUT, que tiraba la celda entera.  60 s
                       # mantiene la tanda en horas y no en dias.


# =============================================================================
# Colores ANSI
# =============================================================================

class C:
    _enabled = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    RESET = "\033[0m" if _enabled else ""
    BOLD = "\033[1m" if _enabled else ""
    DIM = "\033[2m" if _enabled else ""
    RED = "\033[31m" if _enabled else ""
    GREEN = "\033[32m" if _enabled else ""
    YELLOW = "\033[33m" if _enabled else ""
    BLUE = "\033[34m" if _enabled else ""
    MAGENTA = "\033[35m" if _enabled else ""
    CYAN = "\033[36m" if _enabled else ""
    GREY = "\033[90m" if _enabled else ""
    # Colores 256 extendidos para desambiguar los 3 modos AOT (los 6 colores
    # base ya estan usados por interp/jit/c/cpp/python/java).
    ORANGE = "\033[38;5;208m" if _enabled else ""  # naranja
    VIOLET = "\033[38;5;99m" if _enabled else ""   # violeta azulado
    PINK = "\033[38;5;213m" if _enabled else ""    # rosa
    # Teal/turquesa brillante (aquamarine 43, ~#00d7af) para Go.  Distinto de
    # CYAN (36, python), BLUE (34, c) y GREEN (32, jit): tira a verde-cian pero
    # con hue propio y brillante, inequivoco frente al resto de la paleta.
    TEAL = "\033[38;5;43m" if _enabled else ""
    # Naranja-rojizo (202, ~#ff5f00) para Rust, cercano al naranja de marca
    # #CE422B.  Distinto del ORANGE (208, aot_sse2) y del rojo (31, java).
    RUST = "\033[38;5;202m" if _enabled else ""

    @classmethod
    def enable_windows_ansi(cls):
        if sys.platform == "win32":
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            except Exception:
                pass


# =============================================================================
# Modos AOT por backend de punto flotante (--float-isa)
# =============================================================================
# Cada modo compila el bench a un .exe nativo standalone con un backend SIMD
# distinto.  Sirve para comparar el efecto del ancho vectorial:
#   - sse2 : 128b, baseline; corre en CUALQUIER x86-64 (cross-compile-safe).
#   - avx  : AVX2 256b; mas rapido en bucles vectorizables, requiere AVX2 en HW.
#   - auto : multiversion por cpuid (sse2/avx2/avx512 en el binario; elige la
#            variante optima del host en runtime).  Lo mejor de ambos mundos.
# lang_name -> valor de --float-isa.
VX_AOT_MODES: dict[str, str] = {
    "vx_aot_sse2": "sse2",
    "vx_aot_avx":  "avx",
    "vx_aot_auto": "auto",
}
# Todos los lenguajes "Vesta-lang" (comparten la variante .vx; difieren en como se
# compila/ejecuta).  Usado en los dispatch de compile + run.
VX_LANGS = ("vx_interp", "vx_jit", *VX_AOT_MODES.keys())


def info(msg: str) -> None:
    print(f"{C.CYAN}[info]{C.RESET} {msg}")


def warn(msg: str) -> None:
    print(f"{C.YELLOW}[warn]{C.RESET} {msg}")


def err(msg: str) -> None:
    print(f"{C.RED}[error]{C.RESET} {msg}", file=sys.stderr)


def ok(msg: str) -> None:
    print(f"{C.GREEN}[ok]{C.RESET} {msg}")


# =============================================================================
# Resolver project root + binario vm
# =============================================================================

def find_project_root(start: Path) -> Path:
    cur = start.resolve()
    while True:
        if (cur / "CMakeLists.txt").is_file() and (cur / "examples_codes_vx").is_dir():
            return cur
        if cur.parent == cur:
            err("no encuentro project root (CMakeLists.txt + examples_codes_vx/)")
            sys.exit(1)
        cur = cur.parent


def find_vm_candidates(project_root: Path) -> list[tuple[str, Path]]:
    candidates: list[tuple[str, Path]] = []
    seen: set[Path] = set()
    # Las construcciones OPTIMIZADAS primero: la primera es la opcion por
    # defecto, y medir una construccion de depuracion da numeros que no
    # significan nada -- justo lo que preguntar pretende evitar.  Las de
    # depuracion siguen apareciendo en la lista para quien las quiera a
    # proposito, pero al final.
    build_patterns = [
        "cmake-build-release", "cmake-build-windows-release",
        "cmake-build-windows", "build-release", "build", "out",
        "cmake-build-debug", "cmake-build-windows-debug", "build-debug",
    ]
    for sub in build_patterns:
        for name in ("vm.exe", "vm"):
            cand = project_root / sub / name
            if cand.is_file():
                resolved = cand.resolve()
                if resolved not in seen:
                    seen.add(resolved)
                    candidates.append((f"build local ({sub})", cand))
                break
    for tool_name in ("vm", "vesta"):
        path_bin = shutil.which(tool_name)
        if path_bin:
            resolved = Path(path_bin).resolve()
            if resolved not in seen:
                seen.add(resolved)
                candidates.append((f"PATH ({tool_name})", Path(path_bin)))
    return candidates


def prompt_choose_vm(candidates: list[tuple[str, Path]]) -> Path:
    if not candidates:
        err("no encontre ningun binario vm/vesta")
        sys.exit(1)
    if len(candidates) == 1:
        desc, path = candidates[0]
        info(f"unico binario: {C.BOLD}{path}{C.RESET} ({desc})")
        return path
    if not sys.stdin.isatty():
        desc, path = candidates[0]
        warn(f"stdin no es TTY -- default a [0]: {desc} {C.DIM}{path}{C.RESET}")
        return path
    print()
    info(f"{C.BOLD}Encontre {len(candidates)} binarios vesta:{C.RESET}")
    for i, (desc, path) in enumerate(candidates):
        print(f"  {C.GREEN}[{i}]{C.RESET} {desc:<28} {C.DIM}{path}{C.RESET}")
    while True:
        try:
            choice = input(f"{C.CYAN}Elige [0-{len(candidates)-1}] "
                           f"(default 0): {C.RESET}").strip()
        except EOFError:
            # No hay nadie al otro lado (lanzado desde un arnes, con la
            # entrada cerrada o redirigida).  Eso no es un motivo para no
            # medir: se toma el defecto y se avisa de cual fue.  Antes moria
            # aqui, asi que el banco no se podia automatizar sin pasar la
            # ruta a mano.
            print()
            desc, path = candidates[0]
            warn(f"sin respuesta -- default a [0]: {desc} "
                 f"{C.DIM}{path}{C.RESET}")
            return path
        except KeyboardInterrupt:
            # Esto SI es una decision: alguien lo ha cortado a proposito.
            print()
            sys.exit(1)
        if not choice:
            return candidates[0][1]
        if choice.isdigit() and 0 <= int(choice) < len(candidates):
            return candidates[int(choice)][1]
        warn(f"opcion invalida: {choice!r}")


def _directorios_extra() -> list[Path]:
    """Directorios EXTRA donde buscar herramientas, dichos por quien los tiene.

    Que algo este instalado y que este en el PATH son dos cosas distintas, y el
    arnes no deberia quedarse ciego ante la primera porque falle la segunda.
    Pero tampoco vale ponerse a adivinar rutas ni a barrer unidades: eso solo
    funciona en el equipo donde se escribio.  Aqui se lee lo que el usuario
    declare en VESTA_BENCH_BIN, y para un compilador concreto estan --cc y
    --cxx.
    """
    dirs: list[Path] = []
    for extra in os.environ.get("VESTA_BENCH_BIN", "").split(os.pathsep):
        if extra.strip():
            dirs.append(Path(extra.strip()))
    return [d for d in dirs if d.is_dir()]


def buscar_fuera_del_path(nombre: str) -> str:
    """Busca @p nombre en los directorios declarados.  Ruta absoluta o ""."""
    sufijos = [".exe", ""] if sys.platform == "win32" else [""]
    for d in _directorios_extra():
        for suf in sufijos:
            cand = d / (nombre + suf)
            if cand.is_file():
                return str(cand)
    return ""


_ENTORNO_MSVC: Optional[dict] = None


def entorno_msvc() -> dict:
    """Variables que MSVC necesita (LIB, INCLUDE, PATH), descubiertas solas.

    Tener Visual Studio instalado y tener su entorno PUESTO son dos cosas
    distintas: `LIB` e `INCLUDE` los exporta el "Developer Command Prompt", no
    una terminal cualquiera.  Sin ellas, el enlazador no encuentra
    `kernel32.lib` aunque este en el disco -- y eso es lo que hacia fallar a
    rustc aqui, no el enlazador.

    Se descubre preguntando, no adivinando: `vswhere.exe` (cuya ubicacion SI la
    fija Microsoft) dice donde esta instalado, y `vcvars64.bat` dice que
    variables hacen falta.  Funciona con Visual en `C:` o en `U:`, que es donde
    esta en este equipo.
    """
    global _ENTORNO_MSVC
    if _ENTORNO_MSVC is not None:
        return _ENTORNO_MSVC
    _ENTORNO_MSVC = {}
    if sys.platform != "win32":
        return _ENTORNO_MSVC
    pf = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    vswhere = Path(pf) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    if not vswhere.is_file():
        return _ENTORNO_MSVC
    try:
        r = subprocess.run([str(vswhere), "-latest", "-property",
                            "installationPath"],
                           capture_output=True, text=True, timeout=30)
        raiz = (r.stdout or "").strip().splitlines()
        if not raiz:
            return _ENTORNO_MSVC
        vcvars = (Path(raiz[0].strip()) / "VC" / "Auxiliary" / "Build"
                  / "vcvarsall.bat")
        if not vcvars.is_file():
            return _ENTORNO_MSVC
        # Se lanza desde un .bat intermedio en vez de encadenar en la linea de
        # `cmd`: el encadenado se come las comillas de la ruta y el script no
        # llega a ejecutarse -- que era lo que hacia parecer que no estaba.
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".bat", delete=False,
                                          encoding="utf-8", newline="\r\n") as f:
            f.write('@echo off\ncall "%s" x64 >nul\nset\n' % str(vcvars))
            puente = f.name
        try:
            r2 = subprocess.run(["cmd", "/c", puente], capture_output=True,
                                text=True, timeout=180)
            for linea in (r2.stdout or "").splitlines():
                if "=" in linea:
                    k, v = linea.split("=", 1)
                    # La clave se guarda en MAYUSCULAS a proposito: `cmd`
                    # imprime `Path=` y `os.environ` usa `PATH=`, asi que
                    # mezclarlas tal cual dejaba DOS entradas distintas en el
                    # entorno del hijo y ganaba la vieja -- el compilador seguia
                    # viendo el PATH de antes y todo esto no servia de nada.
                    if k.upper() in ("LIB", "INCLUDE", "LIBPATH", "PATH",
                                     "WINDOWSSDKDIR", "VCTOOLSINSTALLDIR"):
                        _ENTORNO_MSVC[k.upper()] = v
        finally:
            try:
                os.unlink(puente)
            except OSError:
                pass
        # Si no salio `LIB`, el entorno no se preparo: sin ella el enlazador no
        # encuentra `kernel32.lib` por mucho que Visual este instalado.  Se
        # avisa una vez, porque si no el fallo aparece mas tarde disfrazado de
        # "este lenguaje no compila" sin decir de que.
        if "LIB" not in {k.upper() for k in _ENTORNO_MSVC}:
            warn("Visual Studio esta instalado pero su entorno no se pudo "
                 "preparar (vcvarsall no exporto LIB).  Lo que dependa del "
                 "enlazador de MSVC no compilara.")
            _ENTORNO_MSVC = {}
    except Exception:  # noqa: BLE001
        pass
    return _ENTORNO_MSVC


def entorno_para_compilar(base: Optional[dict] = None) -> dict:
    """Entorno para lanzar un compilador, con lo de MSVC ya dentro si lo hay."""
    e = dict(base or os.environ)
    e.update(entorno_msvc())
    return e


def buscar_compiladores(nombres: list[str]) -> list[tuple[str, str]]:
    """Compiladores instalados de entre @p nombres, con su ruta.

    Existe porque tener gcc y clang a la vez es lo normal, y coger a ciegas el
    primero del PATH tiene dos problemas: generan codigo bastante distinto, y la
    tabla acabaria diciendo "C (gcc -O3)" con clang por debajo.  Un numero mal
    etiquetado es peor que no tenerlo.
    """
    out: list[tuple[str, str]] = []
    vistos: set[str] = set()
    for n in nombres:
        p = shutil.which(n) or buscar_fuera_del_path(n)
        if not p:
            continue
        # Se descarta por VERSION, no por ruta.  En Windows `c++.exe` es una
        # copia de `g++.exe` del mismo TDM-GCC -- ficheros distintos, mismo
        # compilador -- y preguntar entre los dos es ruido que ademas dejaria
        # colgada una corrida automatica.  La version los identifica.
        ver = get_tool_version([p, "--version"]) or ""
        # La version empieza por el nombre del propio ejecutable ("g++.EXE
        # (tdm64-1) 10.3.0"), asi que hay que quitarlo antes de comparar o dos
        # copias del mismo compilador seguirian pareciendo distintas.
        clave = ver.lower().replace(Path(p).name.lower(), "").strip()
        if not clave:
            clave = str(Path(p).resolve()).lower()
        if clave in vistos:
            continue
        vistos.add(clave)
        out.append((n, p))
    return out


def elegir_compilador(lenguaje: str, candidatos: list[tuple[str, str]],
                      forzado: str = "",
                      preguntar: bool = True) -> tuple[str, str]:
    """Devuelve (nombre, ruta) del compilador a usar para @p lenguaje.

    Con uno solo, se usa sin preguntar.  Con varios y terminal interactiva, se
    pregunta -- igual que ya se hace con el binario de la maquina virtual.  Sin
    terminal (un script, la integracion continua) se coge el primero y se DICE
    cual, para que quede en el registro de la corrida.
    """
    if forzado:
        return (Path(forzado).stem, forzado)
    if not candidatos:
        return ("", "")
    if len(candidatos) == 1:
        return candidatos[0]
    if not preguntar:
        return candidatos[0]
    if not sys.stdin.isatty():
        n, p = candidatos[0]
        warn(f"{lenguaje}: hay {len(candidatos)} compiladores y stdin no es "
             f"TTY -- se usa {C.BOLD}{n}{C.RESET} ({p})")
        return candidatos[0]
    print()
    info(f"{C.BOLD}{lenguaje}: encontre {len(candidatos)} compiladores{C.RESET}")
    for i, (n, p) in enumerate(candidatos):
        ver = get_tool_version([p, "--version"])
        print(f"  {C.GREEN}[{i}]{C.RESET} {n:<10} {C.DIM}{p}{C.RESET}")
        if ver:
            print(f"      {C.DIM}{ver}{C.RESET}")
    while True:
        try:
            elec = input(f"{C.CYAN}Elige [0-{len(candidatos)-1}] "
                         f"(default 0): {C.RESET}").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(1)
        if not elec:
            return candidatos[0]
        if elec.isdigit() and 0 <= int(elec) < len(candidatos):
            return candidatos[int(elec)]
        warn(f"opcion invalida: {elec!r}")


# =============================================================================
# Detector de toolchain por lenguaje
# =============================================================================

@dataclass
class Toolchain:
    """Configuracion de toolchain por lenguaje."""
    name: str             # vx_interp, vx_jit, c, cpp, python, java
    label: str            # texto visible
    color: str            # ANSI color para tablas
    available: bool       # True si el compilador/runtime esta instalado
    why_unavailable: str = ""


def get_tool_version(cmd: list[str], timeout: float = 5.0) -> str:
    """Ejecuta cmd y retorna la primera linea no vacia del stdout/stderr.
    Util para `gcc --version`, `python --version`, etc."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout)
        out = (r.stdout + "\n" + r.stderr).strip()
        for line in out.splitlines():
            line = line.strip()
            if line:
                return line[:120]
    except Exception:
        pass
    return "(version no detectada)"


def capture_system_info(vm_bin: Path, tc: dict) -> dict:
    """Captura hardware + OS + versiones de todos los compiladores
    usados.  Critico para reproducibilidad cross-machine.

    Sin deps externas (no usa psutil).  Para info detallada de CPU
    en Windows usa @c wmic; en Linux @c /proc/cpuinfo; en macOS
    @c sysctl.  Si nada esta disponible, fallback a @c platform.
    """
    import datetime
    import platform

    info_d: dict = {}

    # ---- Hardware ----
    hw: dict = {
        "arch": platform.machine(),
        "cpu_logical": os.cpu_count() or "?",
    }
    # CPU model + freq + cores fisicos + RAM segun plataforma.
    if sys.platform == "win32":
        try:
            r = subprocess.run(
                ["wmic", "cpu", "get", "Name,MaxClockSpeed,NumberOfCores", "/value"],
                capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                line = line.strip()
                if not line or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                if k == "Name":
                    hw["cpu_model"] = v.strip()
                elif k == "MaxClockSpeed":
                    hw["cpu_freq_mhz"] = f"{v.strip()} MHz"
                elif k == "NumberOfCores":
                    hw["cpu_physical"] = v.strip()
        except Exception:
            pass
        try:
            r = subprocess.run(
                ["wmic", "ComputerSystem", "get", "TotalPhysicalMemory", "/value"],
                capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                if line.startswith("TotalPhysicalMemory="):
                    bytes_v = int(line.split("=", 1)[1].strip())
                    hw["ram_gb"] = f"{bytes_v / (1024**3):.1f} GB"
        except Exception:
            pass
    elif sys.platform.startswith("linux"):
        try:
            with open("/proc/cpuinfo") as f:
                cpu_data = f.read()
            for line in cpu_data.splitlines():
                if line.startswith("model name") and "cpu_model" not in hw:
                    hw["cpu_model"] = line.split(":", 1)[1].strip()
                elif line.startswith("cpu MHz") and "cpu_freq_mhz" not in hw:
                    hw["cpu_freq_mhz"] = f"{float(line.split(':', 1)[1].strip()):.0f} MHz"
            hw["cpu_physical"] = str(cpu_data.count("processor"))
        except Exception:
            pass
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        kb = int(line.split()[1])
                        hw["ram_gb"] = f"{kb / (1024**2):.1f} GB"
                        break
        except Exception:
            pass
    elif sys.platform == "darwin":
        try:
            for k, key, fmt in (
                ("machdep.cpu.brand_string", "cpu_model", lambda v: v),
                ("hw.physicalcpu", "cpu_physical", lambda v: v),
                ("hw.cpufrequency_max",  "cpu_freq_mhz",
                    lambda v: f"{int(v) // 1_000_000} MHz"),
                ("hw.memsize", "ram_gb",
                    lambda v: f"{int(v) / (1024**3):.1f} GB"),
            ):
                r = subprocess.run(["sysctl", "-n", k],
                                    capture_output=True, text=True, timeout=2)
                if r.returncode == 0:
                    hw[key] = fmt(r.stdout.strip())
        except Exception:
            pass

    # Fallback: platform.processor() puede traer string.
    if "cpu_model" not in hw:
        hw["cpu_model"] = platform.processor() or "(desconocido)"
    info_d["hardware"] = hw

    # ---- OS ----
    info_d["os"] = {
        "platform": f"{platform.system()} {platform.release()}",
        "version": platform.version(),
        "release": platform.release(),
    }

    # ---- Toolchains ----
    tooling: dict = {}
    # Vesta-lang
    if vm_bin.is_file():
        vx_ver = get_tool_version([str(vm_bin), "--version"])
        tooling["Vesta-lang VM"] = {
            "available": True,
            "version": vx_ver,
            "path": str(vm_bin),
        }
    else:
        tooling["Vesta-lang VM"] = {"available": False}
    # gcc
    if tc.get("c") and tc["c"].available:
        tooling["C (gcc)"] = {
            "available": True,
            "version": get_tool_version([tc["c"].path, "--version"]),
            "path": tc["c"].path,
        }
    else:
        tooling["C (gcc)"] = {"available": False}
    # g++
    if tc.get("cpp") and tc["cpp"].available:
        tooling["C++ (g++)"] = {
            "available": True,
            "version": get_tool_version([tc["cpp"].path, "--version"]),
            "path": tc["cpp"].path,
        }
    else:
        tooling["C++ (g++)"] = {"available": False}
    # python
    if tc.get("python") and tc["python"].available:
        tooling["Python"] = {
            "available": True,
            "version": get_tool_version([tc["python"].path, "--version"]),
            "path": tc["python"].path,
        }
    else:
        tooling["Python"] = {"available": False}
    # java + javac
    if tc.get("java") and tc["java"].available:
        tooling["Java (javac)"] = {
            "available": True,
            "version": get_tool_version([tc["java"].path_javac, "--version"]),
            "path": tc["java"].path_javac,
        }
        tooling["Java (java)"] = {
            "available": True,
            "version": get_tool_version([tc["java"].path_java, "--version"]),
            "path": tc["java"].path_java,
        }
    else:
        tooling["Java"] = {"available": False}
    # go (usa `go version`, sin dashes).
    if tc.get("go") and tc["go"].available:
        tooling["Go (gc)"] = {
            "available": True,
            "version": get_tool_version([tc["go"].path, "version"]),
            "path": tc["go"].path,
        }
    else:
        tooling["Go (gc)"] = {"available": False}
    # rust (usa `rustc --version`).
    if tc.get("rust") and tc["rust"].available:
        tooling["Rust (rustc -O)"] = {
            "available": True,
            "version": get_tool_version([tc["rust"].path, "--version"]),
            "path": tc["rust"].path,
        }
    else:
        tooling["Rust (rustc -O)"] = {"available": False}
    info_d["tooling"] = tooling

    # ---- Fecha del reporte ----
    info_d["date"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return info_d


def print_system_banner(sys_info: dict) -> None:
    """Sprint bench-hwinfo (2026-06-02): banner expandido con hardware +
    OS + versiones de toolchains.  Permite comparar runs cross-maquina
    y dejar trazabilidad en el output de consola (no solo en el JSON).
    """
    hw = sys_info.get("hardware", {})
    os_ = sys_info.get("os", {})
    tools = sys_info.get("tooling", {})
    date = sys_info.get("date", "?")

    line_w = 78
    print()
    print(C.BOLD + "=" * line_w + C.RESET)
    print(f"{C.BOLD}  Sistema  {C.RESET}{C.DIM}{date}{C.RESET}")
    print(C.BOLD + "-" * line_w + C.RESET)

    def kv(k: str, v: str, color: str = C.BOLD) -> None:
        print(f"  {k:<14} {color}{v}{C.RESET}")

    kv("CPU",
       f"{hw.get('cpu_model', '?')} "
       f"({hw.get('cpu_physical', '?')} fisicos / "
       f"{hw.get('cpu_logical', '?')} logicos @ "
       f"{hw.get('cpu_freq_mhz', '?')})")
    kv("RAM",  hw.get("ram_gb", "?"))
    kv("Arch", hw.get("arch", "?"))
    kv("OS",   f"{os_.get('platform', '?')} ({os_.get('version', '?')})")

    if tools:
        print(C.BOLD + "-" * line_w + C.RESET)
        print(f"  {C.BOLD}Toolchains{C.RESET}")
        for name, t in tools.items():
            if t.get("available"):
                ver = t.get("version", "?")
                # Primera linea solamente (las versiones a veces son
                # multi-linea; e.g. gcc --version imprime banner+copyright).
                ver_short = (ver.splitlines() or ["?"])[0][:64]
                print(f"  {name:<14} {C.GREEN}{ver_short}{C.RESET}")
            else:
                print(f"  {name:<14} {C.RED}no disponible{C.RESET}")
    print(C.BOLD + "=" * line_w + C.RESET)


# =============================================================================
# Sprint bench-categories: agrupacion por dominio + geomean por categoria
# =============================================================================

# Inferencia automatica por el nombre del bench.  Cada bench cae en UNA
# categoria principal; cuando hay overlap (e.g. callvirt_hot mide tanto
# OOP como branch) prevalece la mas representativa del workload dominante.
BENCH_CATEGORIES: dict[str, str] = {
    # Floating-point heavy.
    "fp_jit":            "fp",
    # Integer arithmetic / counter loops.
    "tight_loop":        "int",
    "int_mixed":         "int",
    "cmp_fusion":        "int",
    "jit_method":        "int",
    "fib_recursive":     "int",
    "nested_loops":      "int",
    "intops_jit":        "int",
    "rotops_jit":        "bit",
    "bitops":            "bit",
    # Memory: allocation throughput.
    "alloc":             "alloc",
    "mem_class":         "alloc",
    "mem_malloc_free":   "alloc",
    "mem_struct":        "alloc",
    # Memory bandwidth.
    "memcpy_loop":       "mem",
    "array_sum":         "mem",
    # Branch-heavy / unpredictable control flow.
    "branch_unpredict":  "branch",
    "state_machine":     "branch",
    "quicksort":         "branch",
    # Hash / lookup tables.
    "hash_lookup":       "hash",
    # OOP: virtual dispatch + heap classes.
    "callvirt":          "oop",
    "callvirt_hot":      "oop",
    "polymorphic":       "oop",
    "pic_real":          "oop",
    "struct_field":      "oop",
    # String operations.
    "string_hot":        "string",
    "string_workout":    "string",
}


def bench_category(name: str) -> str:
    """Devuelve la categoria del bench, o 'misc' si no esta tagged."""
    return BENCH_CATEGORIES.get(name, "misc")


def print_category_summary(rows: list[dict], active_langs: list[str],
                            tc: dict[str, Toolchain],
                            baseline: str = "c") -> None:
    """Sprint bench-categories: geomean slowdown vs baseline POR categoria.

    Pemite identificar areas debiles del JIT (e.g. "FP: 7x, OOP: 3x,
    Branch: 12x").  Para cada categoria: geomean del ratio bench_lang /
    bench_baseline sobre todos los benches de esa categoria que tienen
    ambos valores positivos.
    """
    if not rows:
        return

    # Agrupar benches por categoria.
    cats: dict[str, list[dict]] = {}
    for row in rows:
        cats.setdefault(bench_category(row["bench"]), []).append(row)

    # Para cada (categoria, lang): geomean slowdown vs baseline.
    import math
    print()
    print(f"{C.BOLD}Geomean slowdown vs {tc[baseline].label} por categoria"
          f"{C.RESET}")
    print(f"{C.DIM}  (mas bajo = mejor; <1.0 = mas rapido que {baseline}){C.RESET}")
    print()

    header_cols = [f"{'CATEGORIA':<12}{'N':>4}"]
    for ln in active_langs:
        if ln == baseline:
            continue
        header_cols.append(f"{tc[ln].label:>16}")
    print(f"{C.BOLD}{' '.join(header_cols)}{C.RESET}")
    print("-" * (12 + 4 + 17 * (len(active_langs) - 1)))

    for cat in sorted(cats.keys()):
        rows_in_cat = cats[cat]
        cols = [f"{cat:<12}{len(rows_in_cat):>4}"]
        for ln in active_langs:
            if ln == baseline:
                continue
            ratios = []
            for r in rows_in_cat:
                v_ln = r.get(ln)
                v_base = r.get(baseline)
                dudosas = no_agregables(r)
                # Fuera de la media lo que no se distingue del arranque: una
                # media geometrica de razones inventadas es una cifra
                # inventada, y encima con aspecto de resumen fiable.
                if (v_ln is None or v_base is None
                        or v_ln <= 0 or v_base <= 0
                        or ln in dudosas or baseline in dudosas):
                    continue
                ratios.append(v_ln / v_base)
            if not ratios:
                cols.append(f"{C.GREY}{'N/A':>16}{C.RESET}")
                continue
            # Geomean.
            log_sum = sum(math.log(r) for r in ratios)
            geo = math.exp(log_sum / len(ratios))
            # Color: <1.5x = verde, <3x = amarillo, >=3x = rojo.
            if geo < 1.5:
                col = C.GREEN
            elif geo < 3.0:
                col = C.YELLOW
            else:
                col = C.RED
            cols.append(f"{col}{geo:>15.2f}x{C.RESET}")
        print(" ".join(cols))
    print("-" * (12 + 4 + 17 * (len(active_langs) - 1)))


def detect_toolchains(vm_bin: Path, cc_forzado: str = "",
                      cxx_forzado: str = "",
                      pedidos: Optional[set] = None) -> dict[str, Toolchain]:
    tc: dict[str, Toolchain] = {}

    tc["vx_interp"] = Toolchain(
        "vx_interp", "Vesta-lang interp", C.YELLOW,
        available=vm_bin.is_file(),
        why_unavailable="" if vm_bin.is_file() else "vm binary missing"
    )
    tc["vx_jit"] = Toolchain(
        "vx_jit", "Vesta-lang JIT", C.GREEN,
        available=vm_bin.is_file(),
        why_unavailable="" if vm_bin.is_file() else "vm binary missing"
    )
    # Sprint bench-aot (2026-06-17): modo AOT nativo.  Compila cada bench
    # a un .exe nativo standalone (-m aot --emit exe) y mide su wall time.
    # El AOT solo cubre un SUBSET del lenguaje (enteros/structs/funciones/
    # control de flujo; sin GC/strings-managed/print/async), asi que
    # muchos benches caen a N/A cuando el compile nativo falla.
    #
    # Sprint bench-aot-isa (2026-06-26): tres modos por backend SIMD
    # (--float-isa) para ver el efecto del ancho vectorial lado a lado:
    #   sse2 (128b baseline), avx (AVX2 256b), auto (multiversion cpuid).
    _aot_labels = {
        "vx_aot_sse2": "Vesta-lang AOT sse2",
        "vx_aot_avx":  "Vesta-lang AOT avx2",
        "vx_aot_auto": "Vesta-lang AOT auto",
    }
    # Colores distintos de los 6 base (interp=amarillo, jit=verde, c=azul,
    # cpp=magenta, python=cian, java=rojo) para que el trio AOT se diferencie.
    _aot_colors = {
        "vx_aot_sse2": C.ORANGE,
        "vx_aot_avx":  C.VIOLET,
        "vx_aot_auto": C.PINK,
    }
    for _ln in VX_AOT_MODES:
        tc[_ln] = Toolchain(
            _ln, _aot_labels[_ln], _aot_colors[_ln],
            available=vm_bin.is_file(),
            why_unavailable="" if vm_bin.is_file() else "vm binary missing"
        )

    # La ETIQUETA lleva el compilador que se eligio de verdad.  Poner "gcc" con
    # clang por debajo daria un numero mal atribuido, que es peor que no tenerlo.
    # Solo se pregunta por lo que se va a usar: con `--langs c` no tiene
    # sentido interrumpir para elegir el compilador de C++, y ademas dejaba
    # bloqueada una corrida que no lo necesitaba.
    def _preguntar(l: str) -> bool:
        return pedidos is None or l in pedidos

    nombre_c, ruta_c = elegir_compilador(
        "C", buscar_compiladores(["gcc", "clang", "cc"]), cc_forzado,
        preguntar=_preguntar("c"))
    tc["c"] = Toolchain(
        "c", "C (%s -O3)" % (nombre_c or "gcc"), C.BLUE,
        available=bool(ruta_c),
        why_unavailable="" if ruta_c else "ni gcc ni clang en el PATH"
    )
    tc["c"].path = ruta_c

    nombre_cpp, ruta_cpp = elegir_compilador(
        "C++", buscar_compiladores(["g++", "clang++", "c++"]), cxx_forzado,
        preguntar=_preguntar("cpp"))
    tc["cpp"] = Toolchain(
        "cpp", "C++ (%s -O3)" % (nombre_cpp or "g++"), C.MAGENTA,
        available=bool(ruta_cpp),
        why_unavailable="" if ruta_cpp else "ni g++ ni clang++ en el PATH"
    )
    tc["cpp"].path = ruta_cpp

    py = shutil.which("python") or shutil.which("python3")
    tc["python"] = Toolchain(
        "python", "Python (CPython)", C.CYAN,
        available=py is not None,
        why_unavailable="" if py else "python not in PATH"
    )
    tc["python"].path = py if py else ""

    javac = shutil.which("javac")
    java = shutil.which("java")
    tc["java"] = Toolchain(
        "java", "Java (HotSpot)", C.RED,
        available=javac is not None and java is not None,
        why_unavailable="" if (javac and java) else "javac/java not in PATH"
    )
    tc["java"].path_javac = javac if javac else ""
    tc["java"].path_java = java if java else ""

    go = shutil.which("go")
    tc["go"] = Toolchain(
        "go", "Go (gc)", C.TEAL,
        available=go is not None,
        why_unavailable="" if go else "go not in PATH"
    )
    tc["go"].path = go if go else ""

    # Rust (rustc directo, sin cargo): compila cada bench a un exe nativo con
    # optimizacion agresiva (-O -C target-cpu=native), analogo a C/C++/Go.  Es
    # la referencia de "codigo optimo" de LLVM: mismo backend que Clang -O3.
    rustc = shutil.which("rustc")
    tc["rust"] = Toolchain(
        "rust", "Rust (rustc -O)", C.RUST,
        available=rustc is not None,
        why_unavailable="" if rustc else "rustc not in PATH"
    )
    tc["rust"].path = rustc if rustc else ""

    return tc


# =============================================================================
# Bench discovery
# =============================================================================

@dataclass
class BenchVariant:
    """Una implementacion de un bench en un lenguaje especifico."""
    lang: str             # vx, c, cpp, python, java
    src_path: Path
    bench_name: str       # nombre del bench (ej. tight_loop)


@dataclass
class Bench:
    """Un benchmark con todas sus variantes en distintos lenguajes."""
    name: str
    variants: dict[str, BenchVariant] = field(default_factory=dict)
    is_legacy: bool = False  # True si es un .vx single-file old style


def discover_benches(bench_dir: Path) -> list[Bench]:
    benches: list[Bench] = []
    # 1. Carpetas multi-lenguaje.
    multilang_names: set[str] = set()
    for d in sorted(bench_dir.iterdir()):
        if not d.is_dir() or d.name == "out":
            continue
        b = Bench(name=d.name)
        candidates = {
            "vx":    d / "main.vx",
            "c":      d / "main.c",
            "cpp":    d / "main.cpp",
            "python": d / "main.py",
            "java":   d / "Main.java",
            "go":     d / "main.go",
            "rust":   d / "main.rs",
        }
        for lang, p in candidates.items():
            if p.is_file():
                b.variants[lang] = BenchVariant(lang=lang, src_path=p,
                                                 bench_name=b.name)
        if b.variants:
            benches.append(b)
            multilang_names.add(d.name)
    # 2. Single-file legacy (.vx) -- solo Vesta-lang.
    # Sprint string-perf-6 (2026-06-02): skip de duplicados.  Si el .vx
    # legacy tiene contrapartida multi-lenguaje (e.g. bench_array_sum.vx
    # vs carpeta array_sum/), saltar el legacy para evitar filas dobles
    # en la tabla de resultados.  El nombre logico del legacy se deriva
    # quitando el prefijo "bench_" si existe.
    for f in sorted(bench_dir.glob("*.vx")):
        if LEGACY_SKIP_PATTERN.match(f.stem):
            continue
        logical = f.stem
        if logical.startswith("bench_"):
            logical = logical[len("bench_"):]
        # Tambien aceptar sufijos comunes que el multi-lang no usa.
        # bench_bitops_jit -> bitops, bench_intops_jit -> int_mixed (no
        # 1:1 pero el caso bitops_jit -> bitops es directo).  Eliminamos
        # el sufijo "_jit" para que esos legacy se colapsen con el dir.
        logical_no_jit = logical[:-len("_jit")] if logical.endswith("_jit") else logical
        if logical in multilang_names or logical_no_jit in multilang_names:
            continue
        b = Bench(name=f.stem, is_legacy=True)
        b.variants["vx"] = BenchVariant(lang="vx", src_path=f,
                                          bench_name=b.name)
        benches.append(b)
    return benches


# =============================================================================
# Spinner con timer
# =============================================================================

class Spinner:
    FRAMES = ["|", "/", "-", "\\"]

    def __init__(self, label: str, color: str = ""):
        self.label = label
        self.color = color
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._start = 0.0
        # Sin terminal no hay nada que animar: reescribir la linea y borrarla
        # solo tiene sentido sobre una consola.  Redirigido a un fichero, cada
        # cuadro se queda escrito y el resultado son miles de lineas de basura
        # entre las tablas.
        self._activo = sys.stdout.isatty()

    def etiqueta(self, label: str, color: Optional[str] = None) -> None:
        """Cambia el texto SIN parar el spinner.

        Existe para no abrir y cerrar un spinner por cada ejecucion medida: el
        hilo escribe a stdout cada 80 ms, y arrancarlo y pararlo justo antes y
        despues de lanzar el proceso mete su propio trabajo dentro de la
        ventana que se esta midiendo.  Uno solo por fase, y solo cambia el
        rotulo.
        """
        self.label = label
        if color is not None:
            self.color = color

    def _run(self):
        i = 0
        while not self._stop.is_set():
            elapsed = (time.perf_counter() - self._start) * 1000.0
            frame = self.FRAMES[i % len(self.FRAMES)]
            sys.stdout.write(
                f"\r{self.color}{frame}{C.RESET} {self.label} "
                f"{C.DIM}({elapsed:7.1f} ms){C.RESET}\033[K"
            )
            sys.stdout.flush()
            i += 1
            time.sleep(0.08)

    def __enter__(self):
        self._start = time.perf_counter()
        if not self._activo:
            return self
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_):
        self._stop.set()
        if not self._activo:
            return
        if self._thread:
            self._thread.join(timeout=0.5)
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()


# =============================================================================
# Ejecucion / compilacion por lenguaje
# =============================================================================

# Una medida que no se pudo tomar porque el proceso NO LLEGO A ARRANCAR.  Es
# negativa como el -1 de planton -- todos los `ms >= 0` de siempre la
# descartan igual -- pero se distingue de el, porque el planton puede ser un
# mal momento de la maquina y esto no cambia por reintentarlo.
# -4 y no -2: el -2 ya estaba cogido por "no compila", y compartir el valor
# hacia que un binario que no se puede lanzar saliera en la tabla como si el
# compilador hubiera fallado -- mandando a mirar el sitio equivocado.
NO_ARRANCA = -4.0

# Por que no arranco el ultimo intento.  Lo pone `run_timed` y lo lee
# `una_medida`, que es la que sabe si el caso se pudo recuperar: avisar en el
# sitio donde se detecta daria un "no se pudo lanzar" de algo que se lanza
# bien un milisegundo despues.  Vale un global porque las medidas son
# SECUENCIALES por diseno -- ver `verificar_en_paralelo`, que paraleliza las
# comprobaciones justamente para no tener que paralelizar estas.
_MOTIVO_NO_ARRANCA = ""

# Los binarios a los que hubo que ponerles el bit de ejecucion.  Se acumulan
# en vez de avisar cada vez: son 3 modos AOT x 33 benches, y un aviso por cada
# uno son 99 lineas repetidas que entierran cualquier problema de verdad.  Se
# explica UNA vez y se resume al final.
_SIN_PERMISO: list[str] = []

# ¿La ultima medida se corto por el tope de tiempo?  Lo pone `run_timed` y lo
# lee el bucle que junta las muestras, que es quien puede marcar la fila.
# Mismo patron y mismo motivo que `_MOTIVO_NO_ARRANCA`: las medidas son
# secuenciales por diseno.
_ULTIMA_CENSURADA = False

# El proceso arranco pero se MURIO por una senal (SIGILL, SIGSEGV...).  No es
# una medida: es un programa que no llego a hacer su trabajo, y publicarlo lo
# convertiria en el mas rapido de la tabla.
MURIO = -3.0

# Ni un solo intento: a ese par (bench, lenguaje) no le toco turno en ninguna
# ronda.  No es un fallo del lenguaje ni del programa, y llamarlo `TIMEOUT`
# -- que es lo que pasaba -- acusa de lento a quien ni llego a correr.
SIN_TURNO = -5.0

# Celdas que se quedaron sin muestras y sin un motivo reconocible.  Existen
# porque la alternativa era la de antes: llamarlas `TIMEOUT` y dar por bueno
# un diagnostico que nadie comprobo.  Si esta lista sale con algo, hay un
# camino en el arnes que su propio codigo no explica.
_SIN_EXPLICACION: list = []

# TODO lo que le pasa a un caso durante la corrida: no compila, no arranca,
# revienta.  Se acumula y se cuenta al FINAL, no segun ocurre.
#
# El motivo es de lectura, no de estilo: durante la tanda lo que se mira es la
# linea de cada bench -- una por fila, alineada, comparable de un vistazo -- y
# un aviso en medio la parte en dos.  Con 17 casos rotos, la salida en vivo
# eran mas avisos que resultados y no se veia el banco.  La celda ya dice
# `MURIO` en su sitio: quien mira en vivo no pierde nada, y quien quiere el
# porque lo tiene entero y agrupado al terminar.
_INCIDENCIAS: list = []


def apuntar_incidencia(caso: str, motivo: str) -> None:
    """Guarda una incidencia para el resumen final.  NO imprime."""
    _INCIDENCIAS.append((caso, motivo))


def resumen_incidencias() -> None:
    """Que le paso a cada caso que no dio medida, agrupado por motivo."""
    if not _INCIDENCIAS:
        return
    print()
    warn("%d caso(s) no dieron medida:" % len(_INCIDENCIAS))
    # Agrupado por motivo: diecisiete lineas identicas de SIGSEGV no informan
    # mas que una que diga cuales.
    por: dict = {}
    for caso, motivo in _INCIDENCIAS:
        por.setdefault(motivo, []).append(caso)
    for motivo, casos in sorted(por.items(), key=lambda kv: -len(kv[1])):
        print("        %s%s%s  (%d)" % (C.BOLD, motivo, C.RESET, len(casos)))
        print("          " + ", ".join(sorted(casos)))


def resumen_sin_explicacion() -> None:
    """Celdas vacias cuyo motivo el arnes no supo dar.  Deberia salir vacio."""
    if not _SIN_EXPLICACION:
        return
    print()
    warn("%d celda(s) se quedaron sin muestras y el arnes no sabe por que.  Esto es un fallo DEL BANCO, no de lo medido: revisalo antes de fiarte de esa fila." % len(_SIN_EXPLICACION))
    for bench, ln, motivo in _SIN_EXPLICACION:
        print("        %s/%s: %s" % (bench, ln, motivo))

_MUERTES: list[tuple[str, int, float]] = []

# Nombres de las senales que importan aqui.  No se usa `signal.Signals` porque
# en Windows no estan todas y esto tiene que poder imprimirse igual.
_SENALES = {4: "SIGILL (instruccion ilegal)", 6: "SIGABRT", 8: "SIGFPE",
            9: "SIGKILL", 11: "SIGSEGV (fallo de memoria)", 15: "SIGTERM"}


# Marcas de "esto reventó" que NO se ven en el codigo de salida.  Un runtime
# que atrapa su propia senal -- Vesta captura el acceso invalido a memoria y lo
# convierte en `fatal error`, que es una FEATURE suya -- sale con un codigo
# normal, y para el arnes eso era una ejecucion buena.  Medido: 23 de 35
# benchmarks reventaban bajo el JIT y entraban en la tabla como medidas
# validas de ~32 ms, que es justo lo que tarda arrancar la VM.
_MARCAS_FATALES = ("fatal error", "Stack trace (Vesta)", "panic:",
                   "Segmentation fault", "AddressSanitizer",
                   "Traceback (most recent call last)", "Exception in thread")


def verificar_ejecucion(cmd: list, env: dict | None, cwd, timeout: float):
    """¿Este caso EJECUTA de verdad, o solo falla deprisa?  (ok, motivo).

    Una pasada aparte, con la salida capturada, ANTES de cronometrar nada.  Es
    la gemela de `compila_de_verdad` del banco de compilacion, y existe por lo
    mismo que ella: sin comprobarlo, se cronometran fallos y se publican como
    tiempos -- y un programa que revienta al arrancar sale como el mas rapido.
    Aqui faltaba, y por eso paso desapercibido durante toda la campana.
    """
    if not cmd:
        return (False, "sin orden")

    def _lanzar():
        return subprocess.run(cmd, capture_output=True, env=env,
                              cwd=str(cwd) if cwd else None, timeout=timeout)

    try:
        p = _lanzar()
    except subprocess.TimeoutExpired:
        return (True, "")     # lento no es roto: de eso se ocupa la censura
    except OSError as e:
        # Falta el bit de ejecucion: es lo mismo que `una_medida` ya sabe
        # arreglar, y esta comprobacion corre ANTES que ella.  Sin repetirlo
        # aqui, un binario recuperable quedaba marcado como que no ejecuta --
        # acusando al programa de un problema del fichero.
        if not (cmd and asegurar_ejecutable(cmd[0])):
            return (False, "no se pudo lanzar: %s" % e)
        try:
            p = _lanzar()
        except subprocess.TimeoutExpired:
            return (True, "")
        except OSError as e2:
            return (False, "no se pudo lanzar: %s" % e2)
    if p.returncode is not None and p.returncode < 0:
        return (False, "murio con %s"
                % _SENALES.get(-p.returncode, "senal %d" % -p.returncode))
    texto = (p.stderr or b"").decode("utf-8", "replace")
    for marca in _MARCAS_FATALES:
        if marca in texto:
            primera = texto.strip().splitlines()
            return (False, primera[0][:90] if primera else marca)
    return (True, "")


def _registrar_muerte(cmd, senal: int, ms: float) -> None:
    """Apunta un proceso que murio, y lo dice la primera vez."""
    # No imprime.  `verificar_ejecucion` ya coge estos casos ANTES de medir y
    # los apunta con su motivo, asi que un aviso aqui seria el segundo del
    # mismo problema y encima en medio de la corrida.  Se guarda para el
    # resumen y ya.
    nombre = Path(str(cmd[0])).name if cmd else "?"
    _MUERTES.append((nombre, senal, ms))


def resumen_muertes() -> None:
    """Que binarios se murieron, agrupados por senal.  Una vez, al final."""
    if not _MUERTES:
        return
    print()
    warn("%d ejecucion(es) murieron por una senal y quedaron fuera de la "
         "tabla." % len(_MUERTES))
    por: dict = {}
    for nombre, senal, _ in _MUERTES:
        por.setdefault(_SENALES.get(senal, "senal %d" % senal),
                       set()).add(nombre)
    for senal, quienes in sorted(por.items()):
        print("        %s: %s" % (senal, ", ".join(sorted(quienes))))


def no_agregables(row: dict) -> set:
    """Lenguajes de esta fila cuyo numero NO puede entrar en razones ni medias.

    Son dos casos opuestos y por eso se juntan aqui en vez de en cada sitio:
      - por abajo, lo que no se separa del arranque del proceso;
      - por arriba, lo que se corto en el tope y solo es una cota inferior.
    Los dos se ENSENAN en la tabla -- son lo que se midio -- y los dos
    envenenan un cociente: uno por dividir entre casi cero y el otro por
    dividir entre un numero que no es el de verdad.
    """
    return set(row.get("_bajo_suelo") or {}) | set(row.get("_censurado") or {})


def asegurar_ejecutable(ruta) -> bool:
    """Le pone el bit de ejecucion a @p ruta si le faltaba.  ¿Se arreglo algo?

    El banco no deberia tener que hacer esto: un compilador que emite un
    ejecutable tiene que dejarlo ejecutable.  Se hace igualmente porque
    depender de que la otra parte acierte SIEMPRE es lo que convierte un
    despiste en media hora de tanda perdida:

      - el compilador puede fallar al poner el bit (umask raro, un sistema de
        ficheros que no los soporta, permisos del directorio) y su aviso no
        para el build;
      - el binario que se mide puede ser uno INSTALADO, mas viejo que el
        arreglo -- que es exactamente el caso que destapo esto: `vesta` de
        `/usr/bin` no llevaba el fix del toolchain;
      - y el mismo problema podria venir de cualquier otra herramienta.

    Solo devuelve True si de verdad cambio el permiso, para que el llamante
    reintente unicamente cuando el reintento tiene sentido.  En Windows no hay
    bit que poner y devuelve False sin tocar nada.
    """
    if os.name != "posix":
        return False
    try:
        p = Path(ruta)
        if not p.is_file() or os.access(str(p), os.X_OK):
            return False
        modo = p.stat().st_mode
        # El bit de ejecucion donde ya haya lectura: 0644 -> 0755, 0600 -> 0700.
        nuevo = modo | ((modo & 0o444) >> 2)
        if nuevo == modo:
            return False
        os.chmod(str(p), nuevo)
        if not os.access(str(p), os.X_OK):
            return False
        # NO se avisa aqui.  Esto se arreglo y el programa corrio, asi que
        # interrumpir la tanda con un aviso cuenta un problema que ya no
        # existe -- y encima pisa la linea de progreso.  Se cuenta y se
        # resume al final, que es donde se lee sin estorbar (ver
        # `resumen_permisos`).
        _SIN_PERMISO.append(p.name)
        return True
    except OSError:
        return False


def resumen_permisos() -> None:
    """Cuantos binarios hubo que arreglar, y de quien eran.  Una linea."""
    if not _SIN_PERMISO:
        return
    print()
    warn("%d ejecutable(s) venian sin permiso de ejecucion y se lo puse para "
         "poder medirlos.  El banco no deberia tener que hacer esto: es un "
         "fallo de quien los emite." % len(_SIN_PERMISO))
    # Los sufijos dicen QUIEN los genero mejor que la lista entera de nombres.
    familias: dict[str, int] = {}
    for n in _SIN_PERMISO:
        clave = n.rsplit("_", 1)[-1] if "_" in n else n
        familias[clave] = familias.get(clave, 0) + 1
    print("        por variante: " + ", ".join(
        "%s x%d" % (k, v) for k, v in sorted(familias.items())))


def run_timed(cmd: list[str], env: dict | None = None,
              timeout: float = 60.0, cwd: Optional[Path] = None) -> float:
    """Wall time external (incluye fork + startup del runtime).

    Para C/C++/Python/Java el overhead del fork+startup es bajo (<5ms en
    binarios optimizados; Python ~30ms; Java ~50-80ms por JVM init).  Para
    Vesta-lang la VM tiene ~28ms de overhead de boot que distorsiona benches
    cortos -- usar @c run_timed_vx en su lugar."""
    global _ULTIMA_CENSURADA
    _ULTIMA_CENSURADA = False
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=env, timeout=timeout, cwd=str(cwd) if cwd else None, check=False,
        )
    except subprocess.TimeoutExpired:
        # CENSURA, no perdida.  Antes se devolvia -1 y la celda salia
        # `TIMEOUT`: se tiraba la unica informacion que habia -- que ese caso
        # tarda MAS que el tope -- y con ella la fila entera.  Ahora se
        # devuelve el tope y se marca.  Es una COTA INFERIOR y como tal se
        # trata: se ensena con `>`, y queda fuera de razones y medias igual
        # que las medidas que no se separan del arranque.
        _ULTIMA_CENSURADA = True
        return timeout * 1000.0
    except OSError as e:
        # El proceso no llego a arrancar: ejecutable que no esta, sin permiso
        # de ejecucion, directorio de trabajo invalido, ruta mal formada.
        # Antes esto tumbaba la tanda ENTERA -- media hora de medidas perdida
        # porque un caso de treinta no pudo lanzarse --.  Se trata como lo que
        # es: ese caso no da medida, y se dice cual y por que.
        #
        # Se devuelve NO_ARRANCA y no el -1 de planton porque son cosas
        # distintas: un planton puede ser la maquina teniendo un mal momento y
        # merece reintento; esto es determinista y reintentarlo son cinco
        # esperas por medida para llegar al mismo sitio.  Con un binario sin
        # el bit de ejecucion, el banco parecia colgado.
        #
        # NO se avisa aqui: `una_medida` puede arreglar el caso del permiso y
        # volver a lanzar, y entonces este aviso seria falso -- decia "no se
        # pudo lanzar" de algo que se lanzo un milisegundo despues.  Se deja
        # el motivo apuntado y avisa quien sepa como acabo la cosa.
        global _MOTIVO_NO_ARRANCA
        _MOTIVO_NO_ARRANCA = "%s: %s" % (" ".join(map(str, cmd[:2])), e)
        return NO_ARRANCA
    ms = (time.perf_counter() - t0) * 1000.0
    # ¿Termino, o se MURIO?  Hasta ahora el resultado de `subprocess.run` ni se
    # recogia, asi que un binario que revienta al arrancar entraba en la tabla
    # como la medida mas rapida del banco.  Es exactamente el fallo que el
    # banco de COMPILACION ya evita con `compila_de_verdad` ("un compilador que
    # falla deprisa daria el mejor tiempo"); aqui no habia equivalente.
    #
    # Solo cuentan las muertes por SENAL (returncode < 0 en POSIX).  Un codigo
    # de salida distinto de cero es NORMAL en este corpus: varios benchmarks
    # devuelven el resultado del calculo como exit-code -- `tight_loop` acaba
    # con `return (int32_t)(acc & 0xFFFFFFFF)` -- y rechazarlos por eso tiraria
    # medidas buenas.
    if proc.returncode is not None and proc.returncode < 0:
        _registrar_muerte(cmd, -proc.returncode, ms)
        return MURIO
    return ms


# Sprint bench-walltime (2026-06-02): patron de parseo para extraer el
# Wall time interno reportado por @c --stats.  Forma del output:
#   "Wall time:     2895000 ns  (2895 us, 2 ms)"
_VX_WALL_RE = re.compile(r"Wall time:\s+(\d+)\s+ns")


def run_timed_vx(cmd: list[str], env: dict | None,
                   timeout: float, cwd: Optional[Path]) -> float:
    """Wall time INTERNO del scheduler (excluye VM init overhead).

    Ejecuta el binario Vesta-lang con @c --stats, captura stdout, y extrae la
    linea "Wall time: N ns".  Si no se encuentra (Vesta-lang < esta version),
    fallback a wall externo via @c run_timed.

    Cualquier @c --stats / @c --jit-stats que el usuario ya tenga en
    @c cmd se preserva (no se duplica)."""
    global _ULTIMA_CENSURADA
    _ULTIMA_CENSURADA = False
    cmd_with_stats = list(cmd)
    if "--stats" not in cmd_with_stats:
        cmd_with_stats.append("--stats")
    try:
        proc = subprocess.run(
            cmd_with_stats, capture_output=True, text=True,
            env=env, timeout=timeout, cwd=str(cwd) if cwd else None, check=False,
        )
    except subprocess.TimeoutExpired:
        # Mismo trato que en `run_timed`: se corta en el tope y se marca como
        # cota, en vez de perder la celda.  (`global` ya declarado arriba.)
        _ULTIMA_CENSURADA = True
        return timeout * 1000.0
    except OSError as e:
        # Mismo blindaje que en `run_timed`: si el proceso no arranca, ese caso
        # se queda sin medida y el resto de la tanda sigue.  Se apunta el
        # motivo y avisa `una_medida`, que es quien sabe si se pudo recuperar.
        global _MOTIVO_NO_ARRANCA
        _MOTIVO_NO_ARRANCA = "%s: %s" % (" ".join(map(str, cmd[:2])), e)
        return NO_ARRANCA
    m = _VX_WALL_RE.search(proc.stdout or "")
    if not m:
        m = _VX_WALL_RE.search(proc.stderr or "")
    if not m:
        # Fallback a wall externo si el binario no soporta --stats.
        return run_timed(cmd, env=env, timeout=timeout, cwd=cwd)
    ns = int(m.group(1))
    return ns / 1_000_000.0  # ns -> ms


def median_runs(cmd: list[str], env: dict | None, runs: int,
                 timeout: float, cwd: Optional[Path] = None) -> float:
    times = []
    for _ in range(runs):
        ms = run_timed(cmd, env=env, timeout=timeout, cwd=cwd)
        if ms < 0:
            return -1.0
        times.append(ms)
    return statistics.median(times)


def all_runs(cmd: list[str], env: dict | None, runs: int,
             timeout: float, cwd: Optional[Path] = None,
             warmup: int = 0, use_vx_walltime: bool = False) -> list[float]:
    """Devuelve los runs MEDIDOS (excluye los primeros @c warmup runs).

    Para JIT/JVM el primer run paga compile-fresh y no es representativo
    del steady-state.  Estandar de la industria: descartar W warmups.

    Total runs ejecutados: warmup + runs.  Retorna solo los runs reales
    (longitud == @c runs).  Devuelve lista vacia si cualquier run falla.

    @param use_vx_walltime  Si true, ejecuta con @c --stats y extrae el
    Wall time interno (sin VM init overhead).  Solo para langs Vesta-lang.

    Resiliencia contra flakes ambientales:
    - @c MAX_ATTEMPTS=5 reintentos por run individual antes de fallar.
    - Backoff exponencial entre reintentos (250ms, 500ms, 1s, 2s).
    - Si un TIMEOUT ocurre tras el primer run exitoso, no abortar todo
      el bench: skipear ese run y continuar con los demas (devolver lo
      medido si al menos 1 run salio).  Solo abortar si NINGUN run sale.

    Causas tipicas de flake en Windows:
    - AV scan / Windows Defender bloqueando momentaneamente el .exe.
    - Carga del sistema durante el run (otros procesos, telemetria).
    - Handle/file lock contention al lanzar muchos subprocess rapido.
    """
    total = max(0, warmup) + runs
    times = []
    timer = run_timed_vx if use_vx_walltime else run_timed
    MAX_ATTEMPTS = 5
    BACKOFF_MS = [0, 250, 500, 1000, 2000]
    for i in range(total):
        ms = -1.0
        for attempt in range(MAX_ATTEMPTS):
            if attempt > 0:
                time.sleep(BACKOFF_MS[attempt] / 1000.0)
            ms = timer(cmd, env=env, timeout=timeout, cwd=cwd)
            if ms >= 0:
                break
        if ms < 0:
            # Run individual fallo tras 5 reintentos.  En lugar de
            # abortar todo el bench (lo que tira hasta 4 runs validos
            # por culpa de 1 flake), continuamos: aceptamos perder 1
            # run si los demas estan bien.  Solo si TODOS fallan
            # devolvemos lista vacia.
            continue
        if i >= warmup:
            times.append(ms)
    return times


def una_medida(cmd: list[str], env: dict | None, timeout: float,
               cwd: Optional[Path], use_vx_walltime: bool = False,
               intentos: int = 5) -> float:
    """UNA ejecucion medida, con reintentos ante un flake del entorno.

    Misma resiliencia que @c all_runs (antivirus, contencion de handles, carga
    puntual), pero para una sola medida: es la pieza que necesitan tanto el
    calentamiento como la medicion por rondas.
    """
    espera_ms = [0, 250, 500, 1000, 2000]
    timer = run_timed_vx if use_vx_walltime else run_timed
    for intento in range(max(1, intentos)):
        if intento > 0:
            time.sleep(espera_ms[min(intento, len(espera_ms) - 1)] / 1000.0)
        ms = timer(cmd, env=env, timeout=timeout, cwd=cwd)
        if ms >= 0:
            return ms
        # Que no arranque no se reintenta a ciegas: no es un flake del
        # entorno, es que ese binario no se puede ejecutar, y cinco intentos
        # con esperas llegan al mismo sitio tres segundos y medio mas tarde.
        # Multiplicado por cada medida de cada ronda, el banco parecia colgado
        # -- se vio con un ejecutable AOT al que le faltaba el bit de
        # ejecucion.
        #
        # La UNICA causa que si se puede arreglar desde aqui es esa, la del
        # permiso.  Se intenta una vez: si se arreglo, se reintenta; si no,
        # se corta ya.
        if ms == MURIO:
            return MURIO   # determinista: reintentar da lo mismo
        if ms == NO_ARRANCA:
            # El motivo se lee AHORA, antes de relanzar: el relanzamiento lo
            # sobreescribe, y avisar despues con el de antes cuenta una
            # historia falsa.  Paso de verdad: un binario sin permiso se
            # arreglaba, se relanzaba, moria con SIGSEGV -- y se publicaba
            # "no se pudo lanzar: Permission denied" de algo que si se lanzo.
            motivo = _MOTIVO_NO_ARRANCA or str(cmd[:1])
            # 1) La causa que se puede arreglar aqui: el bit de ejecucion.
            if cmd and asegurar_ejecutable(cmd[0]):
                ms = timer(cmd, env=env, timeout=timeout, cwd=cwd)
                if ms >= 0:
                    return ms      # recuperado: ni una linea de ruido
                if ms == MURIO:
                    return ms      # arranco y murio: ya se reporto solo
            # 2) Y si no era el permiso, SE REINTENTA.  En Windows un fallo al
            # lanzar es a menudo pasajero -- el antivirus mirando el .exe, o
            # contencion de handles al abrir muchos procesos seguidos -- y el
            # arnes ya tenia reintentos con espera justo para eso.  Al hacer
            # `NO_ARRANCA` no-reintentable para no perder tres segundos con un
            # binario sin permiso, me lleve por delante esa resiliencia: en
            # Windows aparecian fallos sueltos, uno por fila y en lenguajes
            # distintos, que es la firma de un problema pasajero.
            #
            # Se reintenta solo esto: `MURIO` es determinista y el permiso ya
            # se ha probado arriba.
            if intento < max(1, intentos) - 1:
                continue
            apuntar_incidencia(str(cmd[0]) if cmd else "?",
                               "no se pudo lanzar tras %d intentos: %s"
                               % (max(1, intentos), motivo))
            return NO_ARRANCA
    return -1.0


# Topes del calentamiento.  El primero acota los casos patologicos; el segundo
# es el que manda de verdad: en un bench que tarda segundos, la paginacion del
# binario es ruido de fondo y seguir calentando son minutos tirados.
CALENTAMIENTO_MAX = 12
CALENTAMIENTO_PRESUPUESTO_MS = 20000.0


def serie_asentada(traza: list[float]) -> bool:
    """¿Ha dejado de BAJAR esta serie de medidas?

    La primera ejecucion de un programa es sistematicamente mas lenta que las
    siguientes, y no por el programa: el sistema tiene que paginar el binario y
    todo lo que arrastra.  Cuanto mas grande es el runtime, mas dura la caida --
    medido en esta maquina, un `.exe` de C se asienta en 2 ejecuciones y la JVM
    tarda 7.  Descartar un numero FIJO falla por los dos lados: sobra para C y
    se queda corto para Java, que entraba a la tabla con la mitad de sus
    muestras todavia frias.

    El criterio NO es que la serie sea plana.  Una medida de 2 ms nunca lo es --
    su ruido relativo es grande de por si -- y exigirselo condenaria a los
    benches cortos a calentar siempre hasta el tope.  Lo que se comprueba es que
    haya dejado de DESCENDER: la mediana de las tres ultimas contra la de las
    tres anteriores, y sigue calentando mientras caiga mas de un 10%.  Asi el
    umbral se ajusta solo al nivel de ruido de cada medida.

    Efecto lateral util: si algo perturba la maquina justo ahora, la serie no se
    asienta y se sigue calentando; la perturbacion se queda en lo descartado.
    """
    if len(traza) < 6:
        return False  # aun no hay dos ventanas que comparar
    previas = statistics.median(traza[-6:-3])
    ultimas = statistics.median(traza[-3:])
    if previas <= 0:
        return True
    # El umbral se escala con el ruido de la PROPIA serie.  Un 10% fijo lo
    # cruza por puro azar una medida de 2 ms -- que se mueve un 5% sin que pase
    # nada -- y entonces un lenguaje rapido nunca se daba por asentado y
    # arrastraba a todos los demas hasta el tope de rondas.  Pedir que la caida
    # supere tres veces su propia dispersion distingue una tendencia de un
    # vaiven.
    p50 = statistics.median(traza)
    mad_rel = (statistics.median([abs(x - p50) for x in traza]) / p50
               if p50 > 0 else 0.0)
    umbral = min(0.5, max(0.10, 3.0 * mad_rel))
    return ultimas >= previas * (1.0 - umbral)


# Por que no compilo cada (bench, lenguaje).  Sin esto, un compilador roto se
# publica como un lenguaje lento: el arnes marcaba "TIMEOUT" tanto cuando el
# programa tardaba demasiado como cuando ni siquiera habia programa que
# ejecutar, y ademas mandaba el error del compilador a /dev/null.  Paso de
# verdad: `rustc` no podia enlazar en este equipo -- el `link.exe` de GNU
# coreutils tapaba al de MSVC en el PATH -- y la tabla lo enseno como TIMEOUT.
ERRORES_COMPILACION: dict[tuple[str, str], str] = {}


def _anotar_fallo(bench: str, lang: str, r) -> None:
    """Guarda la primera linea del error, que casi siempre basta."""
    txt = ""
    if r is not None:
        txt = (getattr(r, "stderr", "") or getattr(r, "stdout", "") or "")
        if isinstance(txt, bytes):
            txt = txt.decode("utf-8", "replace")
    lineas = [l.strip() for l in txt.strip().splitlines() if l.strip()]
    if not lineas:
        ERRORES_COMPILACION[(bench, lang)] = "sin mensaje del compilador"
        return
    # La primera linea suele ser generica ("linking with `link.exe` failed") y
    # la util viene mas abajo ("could not open 'kernel32.lib'").  Se prefiere
    # la ULTIMA que mencione un error concreto; si no hay, la primera.
    ruido = ("aborting due to", "returned an unexpected error",
             "some arguments are omitted", "may need to install",
             "for more information", "error generated", "errors generated",
             "linker command failed")
    concretas = [l for l in lineas
                 if ("error" in l.lower() or "no such" in l.lower())
                 and not any(r in l.lower() for r in ruido)]
    # De las concretas, la PRIMERA: en un compilador, el primer error es la
    # causa y los siguientes suelen ser su consecuencia.  Antes se cogia la
    # ultima y salia "1 error generated", que no dice nada -- el util era
    # "static assertion failed: STL1000: Unexpected compiler version".
    if concretas:
        ERRORES_COMPILACION[(bench, lang)] = concretas[0][:200]
        return
    if not concretas:
        # Sin una linea de error concreta, la mas informativa suele ser una
        # `note:` corta; las largas son el volcado de la orden completa, que no
        # dice nada que no se sepa ya.
        concretas = [l for l in lineas[1:]
                     if l.startswith("= note:") and len(l) < 200
                     and not any(r in l.lower() for r in ruido)]
    ERRORES_COMPILACION[(bench, lang)] = (
        (concretas[-1] if concretas else lineas[0])[:200])


# Compilers: cada uno devuelve (cmd_to_run, work_cwd, normalize_factor).
# normalize_factor: multiplicar wall time medido por este factor para
# obtener el equivalente "100% workload".  Util cuando Python reduce
# iteraciones para no tardar horas.

def compile_c(variant: BenchVariant, work_dir: Path,
              tc: Toolchain) -> Optional[tuple[list[str], Path, float]]:
    out = work_dir / f"{variant.bench_name}_c.exe"
    # `-lm` solo fuera de Windows.  Aqui la matematica va dentro del propio
    # CRT: MinGW tolera la bandera sin mas, pero clang con objetivo MSVC se
    # pone a buscar `m.lib`, que no existe, y muere con LNK1181.  El sintoma
    # era desconcertante -- un fichero vacio compilaba y el benchmark no --
    # porque la bandera no depende del codigo sino del compilador elegido.
    extra = ["-lm"] if sys.platform != "win32" else []
    r = subprocess.run(
        [tc.path, "-O3", "-std=c11", "-march=native",
         str(variant.src_path), "-o", str(out)] + extra,
        capture_output=True, text=True, timeout=60.0,
        env=entorno_para_compilar(),
    )
    if r.returncode != 0 or not out.is_file():
        _anotar_fallo(variant.bench_name, variant.lang, r)
        return None
    return ([str(out)], work_dir, 1.0)


def compile_cpp(variant: BenchVariant, work_dir: Path,
                tc: Toolchain) -> Optional[tuple[list[str], Path, float]]:
    out = work_dir / f"{variant.bench_name}_cpp.exe"
    r = subprocess.run(
        [tc.path, "-O3", "-std=c++17", "-march=native",
         str(variant.src_path), "-o", str(out)],
        capture_output=True, text=True, timeout=60.0,
        env=entorno_para_compilar(),
    )
    if r.returncode != 0 or not out.is_file():
        _anotar_fallo(variant.bench_name, variant.lang, r)
        return None
    return ([str(out)], work_dir, 1.0)


def compile_python(variant: BenchVariant, work_dir: Path,
                   tc: Toolchain) -> Optional[tuple[list[str], Path, float]]:
    # Python no requiere compilacion.  Factor 10 para memcpy_loop (que
    # reduce a 10 iter para no tardar horas).
    factor = 10.0 if variant.bench_name == "memcpy_loop" else 1.0
    return ([tc.path, str(variant.src_path)], variant.src_path.parent, factor)


def compile_java(variant: BenchVariant, work_dir: Path,
                 tc: Toolchain) -> Optional[tuple[list[str], Path, float]]:
    # Compilar Main.java -> Main.class en un dir dedicado por bench.
    bench_work = work_dir / f"{variant.bench_name}_java"
    bench_work.mkdir(exist_ok=True)
    r = subprocess.run(
        [tc.path_javac, "-d", str(bench_work), str(variant.src_path)],
        capture_output=True, text=True, timeout=60.0,
        env=entorno_para_compilar(),
    )
    if r.returncode != 0:
        _anotar_fallo(variant.bench_name, variant.lang, r)
        return None
    return ([tc.path_java, "-cp", str(bench_work), "Main"], bench_work, 1.0)


def compile_go(variant: BenchVariant, work_dir: Path,
               tc: Toolchain) -> Optional[tuple[list[str], Path, float]]:
    # Go compila a un exe nativo (el compilador gc optimiza por defecto; no se
    # pasan flags de optimizacion ni se usa gccgo).  Se ejecuta como binario
    # nativo igual que C, midiendo su wall time.
    suffix = ".exe" if sys.platform == "win32" else ""
    out = work_dir / f"{variant.bench_name}_go{suffix}"
    r = subprocess.run(
        [tc.path, "build", "-o", str(out), str(variant.src_path)],
        capture_output=True, text=True, timeout=120.0,
        env=entorno_para_compilar(),
        cwd=str(variant.src_path.parent),
    )
    if r.returncode != 0 or not out.is_file():
        _anotar_fallo(variant.bench_name, variant.lang, r)
        return None
    return ([str(out)], work_dir, 1.0)


def compile_rust(variant: BenchVariant, work_dir: Path,
                 tc: Toolchain) -> Optional[tuple[list[str], Path, float]]:
    # Rust compila a un exe nativo con optimizacion agresiva: -O (opt-level 2)
    # + target-cpu=native (habilita AVX/SSE del host, igual que gcc -march=native).
    # Es la referencia de codigo optimo de LLVM.  Se ejecuta como binario nativo
    # (su exit-code es el return de main), midiendo su wall time igual que C/Go.
    suffix = ".exe" if sys.platform == "win32" else ""
    out = work_dir / f"{variant.bench_name}_rust{suffix}"
    r = subprocess.run(
        [tc.path, "-O", "-C", "target-cpu=native", "-C", "opt-level=3",
         str(variant.src_path), "-o", str(out)],
        capture_output=True, text=True, timeout=120.0,
        env=entorno_para_compilar(),
    )
    if r.returncode != 0 or not out.is_file():
        _anotar_fallo(variant.bench_name, variant.lang, r)
        return None
    return ([str(out)], work_dir, 1.0)


def compile_vx(variant: BenchVariant, work_dir: Path,
                vm_bin: Path) -> Optional[tuple[list[str], Path, float]]:
    velb_stem = work_dir / f"{variant.bench_name}_vx"
    r = subprocess.run(
        [str(vm_bin), "--vx", str(variant.src_path), "-o", str(velb_stem)],
        capture_output=True, text=True, timeout=60.0,
        env=entorno_para_compilar(),
    )
    velb = Path(str(velb_stem) + ".velb")
    if r.returncode != 0 or not velb.is_file():
        _anotar_fallo(variant.bench_name, variant.lang, r)
        return None
    return ([str(vm_bin), "--run", str(velb)], work_dir, 1.0)


def compile_vx_aot(variant: BenchVariant, work_dir: Path,
                    vm_bin: Path,
                    float_isa: str = "sse2"
                    ) -> Optional[tuple[list[str], Path, float]]:
    """Compila el .vx a un ejecutable nativo standalone via el driver AOT.

    @p float_isa elige el backend SIMD (--float-isa): "sse2" (128b, baseline),
    "avx" (AVX2 256b) o "auto" (multiversion por cpuid).  Cada modo produce un
    binario distinto (nombre de salida sufijado por la ISA) para no colisionar
    en la compilacion paralela.

    En Windows emite un PE (--format pe); en POSIX un ELF (--format elf).
    El AOT solo soporta un subset del lenguaje, por lo que para muchos
    benches el compile falla (returncode != 0 o no se genera el .exe).
    En ese caso devolvemos None y el bench queda como N/A en la columna
    AOT (no entra en el geomean).

    El comando de ejecucion es simplemente el .exe nativo (su exit-code
    es el return de main); medimos su wall time como cualquier otro lang.
    """
    fmt = "pe" if sys.platform == "win32" else "elf"
    suffix = ".exe" if sys.platform == "win32" else ""
    out = work_dir / f"{variant.bench_name}_aot_{float_isa}{suffix}"
    # Limpiar un binario previo para no medir uno viejo si el compile falla.
    try:
        if out.exists():
            out.unlink()
    except OSError:
        pass
    try:
        r = subprocess.run(
            [str(vm_bin), "-m", "aot", "--vx", str(variant.src_path),
             "-o", str(out), "--emit", "exe", "--format", fmt,
             "--float-isa", float_isa],
            capture_output=True, text=True, timeout=60.0,
        env=entorno_para_compilar(),
        )
    except subprocess.TimeoutExpired:
        return None
    # N/A si el compile fallo o el ejecutable nativo no se materializo.
    if r.returncode != 0 or not out.is_file():
        _anotar_fallo(variant.bench_name, variant.lang, r)
        return None
    return ([str(out)], work_dir, 1.0)


# =============================================================================
# Reporte: tabla + grafica matplotlib
# =============================================================================

def colored_time(ms: float, color: str) -> str:
    if ms < 0:
        return f"{C.RED}TIMEOUT{C.RESET}"
    return f"{color}{ms:>10.1f}{C.RESET}"


def _percentil(ordenados: list[float], q: float) -> float:
    """Percentil @p q (0..1) con interpolacion lineal sobre @p ordenados."""
    n = len(ordenados)
    if n == 1:
        return ordenados[0]
    idx = q * (n - 1)
    lo = int(idx)
    hi = min(lo + 1, n - 1)
    return ordenados[lo] + (ordenados[hi] - ordenados[lo]) * (idx - lo)


def _stats_summary(runs: list[float]) -> dict:
    """Resumen de una serie de medidas, en ms.

    La ESTIMACION es la MEDIANA, no la media.  Diez ejecuciones no dan por si
    solas un numero mas fiable: dan una muestra, y basta una interferencia del
    sistema para que la media deje de describir lo que el programa tarda en
    condiciones normales.  Con 10,10,11,10,10,10,11,10,10,48 la media dice 13
    -- un tiempo que no ocurrio nunca -- y la mediana dice 10, que es lo que
    pasa casi siempre.

    Ese 48 no se esconde: es lo que miden la MAD y el IQR, que son las medidas
    de dispersion que corresponden a una mediana (la desviacion tipica arrastra
    el mismo problema que la media).  La media se conserva como dato
    SECUNDARIO, porque compararla con la mediana es justo lo que delata que
    hubo un valor atipico.
    """
    if not runs:
        return {}
    sorted_r = sorted(runs)
    n = len(sorted_r)
    p50 = statistics.median(sorted_r)
    q1 = _percentil(sorted_r, 0.25)
    q3 = _percentil(sorted_r, 0.75)
    # MAD: mediana de las desviaciones absolutas respecto a la mediana.  Un
    # atipico mueve la MAD mucho menos que la desviacion tipica, que es
    # precisamente lo que se quiere de una medida de dispersion robusta.
    mad = statistics.median([abs(x - p50) for x in sorted_r])
    media = statistics.fmean(sorted_r)
    return {
        "min": sorted_r[0],
        "q1": q1,
        "p50": p50,
        "q3": q3,
        "p95": _percentil(sorted_r, 0.95),
        "max": sorted_r[-1],
        "iqr": q3 - q1,
        "mad": mad,
        # Dispersion RELATIVA: lo unico comparable entre un bench de 4 ms y uno
        # de 900 ms.  Es el "cuanto ruido tiene esto" de cada fila.
        "mad_pct": (100.0 * mad / p50) if p50 > 0 else 0.0,
        "iqr_pct": (100.0 * (q3 - q1) / p50) if p50 > 0 else 0.0,
        "mean": media,
        # Cuanto se separa la media de la mediana, en %.  Grande = hay cola.
        "sesgo_pct": (100.0 * (media - p50) / p50) if p50 > 0 else 0.0,
        "stddev": (statistics.stdev(sorted_r) if n >= 2 else 0.0),
        "n": n,
    }


def _color_ruido(mad_pct: float) -> str:
    """Color segun cuanto ruido tiene una medida (no es un juicio: es una guia
    de lectura -- por encima de cierto punto el numero ya no distingue)."""
    if mad_pct < 2.0:
        return C.GREEN
    if mad_pct < 5.0:
        return C.YELLOW
    return C.RED


# Programa que no hace NADA, por lenguaje.  Lo que tarda en ejecutarse es el
# suelo de ese lenguaje en esta maquina: arrancar el proceso, cargar el binario
# y levantar su runtime.  Ese tiempo esta DENTRO de cada medida de la tabla
# principal, y en un bench de 4 ms puede ser la mayor parte.
FUENTES_VACIAS: dict[str, tuple[str, str]] = {
    # lang -> (nombre de fichero, fuente)
    "c": ("suelo.c", "int main(void) { return 0; }\n"),
    "cpp": ("suelo.cpp", "int main() { return 0; }\n"),
    "python": ("suelo.py", "pass\n"),
    "java": ("Main.java",
             "public class Main { public static void main(String[] a) {} }\n"),
    "go": ("suelo.go", "package main\n\nfunc main() {}\n"),
    "rust": ("suelo.rs", "fn main() {}\n"),
    "vx": ("suelo.vx", "i32 main(string[] args) { return 0; }\n"),
}


def usa_eje_interno(ln: str, fair: bool) -> bool:
    """Si las medidas de @p ln salen del reloj INTERNO (@c --stats).

    En modo FAIR (el de por defecto) NADIE lo usa: todos se miden por wall
    externo, arranque incluido, que es lo que paga quien ejecuta el programa.
    En @c --unfair los Vesta-lang vuelven al reloj de dentro.

    Vive aqui, en UN sitio, porque la medida y el suelo que se le resta tienen
    que estar en el mismo eje.  Estaba escrito solo en el plan de ejecucion, el
    suelo no se enteraba, y restar un arranque a una medida que ya venia sin
    arranque daba tiempos negativos.
    """
    return (not fair) and ln in ("vx_interp", "vx_jit")


def medir_suelo(active_langs: list[str], work_dir: Path,
                compilar_para, runs: int, timeout: float,
                eje_interno: Callable[[str], bool] | None = None) -> dict:
    """Cuanto tarda cada lenguaje en NO hacer nada.

    Es lo que cuesta arrancar el proceso y levantar el runtime, y esta dentro de
    cada medida.  Va de 2 ms en C a 67 ms en Java, asi que en un bench de 4 ms
    el numero hablaba mas del sistema operativo que del codigo generado.
    Descontarlo es lo que convierte la tabla en una medida de la CALIDAD DEL
    CoDIGO en vez de una carrera de arranques.

    Se mide con el mismo camino de compilacion y el mismo calentamiento que un
    bench: un suelo obtenido de otra manera no seria el suelo de estas medidas.

    @param eje_interno  Dice, por lenguaje, si sus medidas van a salir del reloj
        INTERNO (@c --stats) en vez del wall externo.  El suelo tiene que
        medirse en el MISMO eje que lo que se le va a restar: en @c --unfair
        los Vesta-lang se miden por dentro -- sin arranque -- y se les restaba
        un suelo medido por fuera -- con arranque --, asi que el neto salia
        NEGATIVO.  `compare_json.py` los descartaba entonces como "sin medir",
        21 de 33 benchmarks, sin decir por que.  Medido en su eje, el suelo de
        un programa vacio por dentro es casi cero, que es justo lo que debe
        descontarse cuando el arranque ya no esta en la medida.
    """
    suelo: dict[str, dict] = {}
    base = work_dir / "_suelo"
    base.mkdir(parents=True, exist_ok=True)
    for ln in active_langs:
        clave = "vx" if ln in VX_LANGS else ln
        pareja = FUENTES_VACIAS.get(clave)
        if pareja is None:
            continue
        nombre, fuente = pareja
        # Java exige que el fichero se llame como la clase; el resto no, pero
        # se les da un directorio propio igualmente para no pisarse.
        dir_ln = base / ln
        dir_ln.mkdir(exist_ok=True)
        src = dir_ln / nombre
        try:
            src.write_text(fuente, encoding="utf-8")
        except OSError:
            continue
        variant = BenchVariant(lang=clave, src_path=src,
                               bench_name=f"suelo_{ln}")
        try:
            res = compilar_para(ln, variant)
        except Exception:  # noqa: BLE001
            res = None
        if res is None:
            continue
        cmd, cwd, _factor = res
        # Mismo calentamiento adaptativo que un bench: si el suelo se midiera en
        # frio seria mayor que el arranque que de verdad pagan las medidas, y
        # descontarlo se comeria trabajo real del programa.
        vx_wt = bool(eje_interno(ln)) if eje_interno is not None else False
        traza: list[float] = []
        gastado = 0.0
        while (len(traza) < CALENTAMIENTO_MAX
               and not serie_asentada(traza)
               and gastado < CALENTAMIENTO_PRESUPUESTO_MS):
            ms = una_medida(cmd, None, timeout, cwd, use_vx_walltime=vx_wt)
            if ms < 0:
                break
            traza.append(ms)
            gastado += ms
        muestras = [una_medida(cmd, None, timeout, cwd, use_vx_walltime=vx_wt)
                    for _ in range(runs)]
        muestras = [m for m in muestras if m >= 0]
        if muestras:
            suelo[ln] = _stats_summary(muestras)
    return suelo


def print_suelo_table(suelo: dict, active_langs: list[str],
                      tc: dict[str, Toolchain]) -> None:
    """Publica el suelo medido, ordenado."""
    if not suelo:
        return
    print()
    print(f"{C.BOLD}Suelo del lenguaje (ms) -- lo que tarda un programa que "
          f"no hace nada{C.RESET}")
    print(f"{C.DIM}  Esta DENTRO de cada medida de la tabla principal.  En un "
          f"bench corto puede ser casi todo el numero.{C.RESET}")
    orden = sorted((ln for ln in active_langs if ln in suelo),
                   key=lambda ln: suelo[ln]["p50"])
    if not orden:
        return
    peor = suelo[orden[-1]]["p50"] or 1.0
    for ln in orden:
        s = suelo[ln]
        barra = ascii_bar(s["p50"], peor, width=24, color=tc[ln].color)
        print(f"  {tc[ln].color}{tc[ln].label:<22}{C.RESET}"
              f"{s['p50']:>8.1f}  +-{s['mad']:>5.2f}  {barra}")


def print_verbose_stats_table(rows: list[dict], active_langs: list[str],
                                tc: dict[str, Toolchain],
                                suelo: Optional[dict] = None) -> None:
    """Estimacion + dispersion por (bench, lang).

    La columna que manda es @c p50 (la estimacion).  A su lado va la MAD, que
    dice cuanto se mueve; y detras la MEDIA, que solo sirve para comparar: si se
    separa de la mediana, hubo cola.

    Si se midio el suelo del lenguaje (arranque del proceso + init del runtime),
    aparece tambien el tiempo NETO: lo que queda al descontarlo.  En un bench de
    4 ms con 3 ms de arranque, el numero de la tabla principal habla mas del
    sistema operativo que del programa.
    """
    print()
    tiene_suelo = bool(suelo)
    cab = (f"{'Estimacion y ruido (ms)':<32}{'p50':>9}{'MAD':>8}{'MAD%':>8}"
           f"{'IQR':>8}{'media':>9}{'min':>8}{'max':>8}")
    if tiene_suelo:
        cab += f"{'neto':>9}"
    print(f"{C.BOLD}{cab}{C.RESET}")
    print(f"{C.DIM}  p50 = estimacion   MAD = dispersion robusta   "
          f"media = dato secundario (si difiere del p50, hubo atipico)"
          f"{C.RESET}")
    print("-" * (len(cab) + 2))
    for row in rows:
        runs_map = row.get("_runs", {})
        for ln in active_langs:
            rs = runs_map.get(ln)
            if not rs:
                continue
            s = _stats_summary(rs)
            if not s:
                continue
            label = f"  {row['bench']}/{ln}"
            color = tc[ln].color
            cr = _color_ruido(s["mad_pct"])
            linea = (f"{color}{label:<32}{C.RESET}"
                     f"{s['p50']:>9.1f}{s['mad']:>8.2f}"
                     f"{cr}{s['mad_pct']:>7.1f}%{C.RESET}"
                     f"{s['iqr']:>8.2f}{s['mean']:>9.1f}"
                     f"{s['min']:>8.1f}{s['max']:>8.1f}")
            if tiene_suelo:
                piso = (suelo.get(ln) or {}).get("p50")
                if piso is None:
                    linea += f"{'-':>9}"
                else:
                    neto = s["p50"] - piso
                    # Un neto <= 0 no es un error de medida que haya que
                    # esconder: dice que el bench no se distingue del arranque.
                    linea += (f"{C.DIM}{'~0':>9}{C.RESET}" if neto <= 0.0
                              else f"{neto:>9.1f}")
            print(linea)
    print("-" * (len(cab) + 2))


def print_dos_ejes(rows: list[dict], active_langs: list[str], tc: dict,
                   suelo: dict) -> None:
    """Los dos ejes de Vesta, uno al lado del otro.

    externo   lo que tarda el proceso entero, arranque de la VM incluido.  Es
              lo que espera quien ejecuta el programa, y lo unico comparable
              contra un binario nativo o contra Python.
    interno   lo que tarda el codigo dentro de la VM, sin el arranque.  Es lo
              unico que se puede medir cuando el bench dura menos que el
              propio arranque.

    Ninguno de los dos sobra, y por eso se publican juntos: el externo dice
    QUE se paga y el interno dice DONDE se va.  La resta entre ambos es el
    arranque, que hasta ahora no aparecia en ningun sitio -- habia que elegir
    con `--fair` cual de los dos numeros ver, y elegir uno escondia el otro.
    """
    vx = [ln for ln in active_langs if ln.startswith("vx_")]
    filas = [(r, {ln: (r.get("_interno") or {}).get(ln) for ln in vx})
             for r in rows]
    filas = [(r, d) for r, d in filas if any(v for v in d.values())]
    if not filas or not vx:
        return
    print()
    print(f"{C.BOLD}Los dos ejes: con el arranque dentro y sin el{C.RESET}")
    print(f"{C.DIM}  `externo` es lo que tarda el proceso -- lo que se paga de "
          f"verdad --; `interno` es el codigo sin el arranque de la VM, que es "
          f"lo unico medible cuando el bench dura menos que arrancar.  La "
          f"diferencia entre los dos ES el arranque.{C.RESET}")
    cab = f"{'BENCH':<22}" + "".join(
        f"{tc[ln].label[:11]:>13}{'':>11}" for ln in vx)
    print(f"{C.BOLD}{cab}{C.RESET}")
    print(f"{C.DIM}  {'':<20}" + "".join(f"{'externo':>13}{'interno':>11}"
                                         for ln in vx) + f"{C.RESET}")
    print("-" * len(cab))
    for r, dat in filas:
        cols = [f"{r['bench']:<22}"]
        for ln in vx:
            bruto = (r.get("_bruto") or {}).get(ln)
            interno = dat.get(ln)
            cols.append(f"{bruto:>13.1f}" if bruto else f"{'-':>13}")
            cols.append(f"{interno:>11.1f}" if interno else f"{'-':>11}")
        print("".join(cols))
    print("-" * len(cab))
    # El arranque, que es la resta, en una linea por lenguaje.
    for ln in vx:
        pares = [((r.get("_bruto") or {}).get(ln), (r.get("_interno") or {}).get(ln))
                 for r, _ in filas]
        pares = [(b, i) for b, i in pares if b and i and b > i]
        if not pares:
            continue
        dif = statistics.median([b - i for b, i in pares])
        piso = (suelo.get(ln) or {}).get("p50")
        extra = ("  (el suelo medido aparte dice %.1f ms)" % piso) if piso else ""
        print(f"{C.DIM}  {tc[ln].label:<22} arranque implicito: "
              f"{dif:.1f} ms{extra}{C.RESET}")


def print_censurados_table(rows: list[dict], tc: dict) -> None:
    """Que celdas se cortaron en el tope, y que significa su numero.

    Es la gemela por arriba de `print_bajo_suelo_table`.  Las dos dicen lo
    mismo con signo contrario: aqui hay un numero que se ensena y que NO se
    puede usar en un cociente.  Antes estas celdas salian como `TIMEOUT` y no
    tenian tabla porque no tenian numero; ahora lo tienen -- una cota -- y hay
    que decir de que cota se trata.
    """
    casos = [(r["bench"], ln, d)
             for r in rows
             for ln, d in (r.get("_censurado") or {}).items()]
    if not casos:
        return
    print()
    print(f"{C.BOLD}Cortados por el tope: {len(casos)} casos{C.RESET}")
    print(f"{C.DIM}  Estos tardan MAS de lo que dice su numero: es una cota "
          f"inferior, no una medida.  Salen del cuadro por lo mismo que los de "
          f"abajo -- un cociente con una cota no es un cociente -- pero se "
          f"publican, porque saber que algo pasa del tope es informacion y un "
          f"hueco no lo es.{C.RESET}")
    for bench, ln, d in sorted(casos):
        etiqueta = tc[ln].label if ln in tc else ln
        print(f"    {bench}/{etiqueta:<22} >{d.get('tope_ms', 0) / 1000.0:.0f} s"
              f"   ({d.get('cortadas', 0)} de {d.get('muestras', 0)} "
              f"ejecuciones se cortaron)")


def print_bajo_suelo_table(rows: list[dict], active_langs: list[str],
                           tc: dict[str, Toolchain]) -> None:
    """Medidas que no se distinguen del arranque del proceso.

    No es un fallo del lenguaje ni del arnes: es que el bench hace tan poco
    trabajo que, descontado el arranque, no queda nada por encima del ruido.
    Sale con nombre y apellidos porque la conclusion es accionable -- ese bench
    necesita mas trabajo por ejecucion -- y porque callarlo lo dejaria como un
    hueco en la tabla indistinguible de "este lenguaje no lo soporta".
    """
    casos = []
    for row in rows:
        for ln, d in (row.get("_bajo_suelo") or {}).items():
            casos.append((row["bench"], ln, d))
    if not casos:
        return
    print()
    print(f"{C.BOLD}{C.YELLOW}No medible por encima del arranque: "
          f"{len(casos)} casos{C.RESET}")
    print(f"{C.DIM}  El bench hace tan poco que, quitado el arranque del "
          f"proceso, lo que queda cabe dentro del ruido.  Salen de la tabla: "
          f"un numero casi cero produce ratios sin sentido.{C.RESET}")
    casos.sort(key=lambda t: (t[0], t[1]))
    for bench, ln, d in casos[:25]:
        color = tc[ln].color if ln in tc else ""
        print(f"    {color}{bench + '/' + ln:<30}{C.RESET}"
              f"medido {d['bruto']:>7.2f} ms   arranque {d['suelo']:>7.2f} ms"
              f"   queda {d['neto']:>7.2f} ms  (ruido +-{d['margen']:.2f})")
    if len(casos) > 25:
        print(f"    {C.DIM}... y {len(casos) - 25} mas{C.RESET}")


def print_calentamiento_table(rows: list[dict], active_langs: list[str],
                              tc: dict[str, Toolchain]) -> None:
    """Cuantas ejecuciones hubo que descartar antes de que la serie se asentara.

    Es una decision del arnes que cambia los numeros publicados, asi que se
    ensena en vez de quedarse dentro.  Ademas mide algo real por si misma: lo
    que tarda un lenguaje en entrar en regimen dice cuanto arrastra al arrancar.
    """
    por_lang: dict[str, list[int]] = {}
    for row in rows:
        for ln, n in (row.get("_calentamientos") or {}).items():
            por_lang.setdefault(ln, []).append(n)
    if not por_lang or all(not v or max(v) == 0 for v in por_lang.values()):
        return
    print()
    print(f"{C.BOLD}Calentamiento: ejecuciones descartadas hasta que la serie "
          f"deja de bajar{C.RESET}")
    print(f"{C.DIM}  No es un parametro fijo: se decide midiendo, y por eso "
          f"difiere entre lenguajes.{C.RESET}")
    orden = sorted(por_lang, key=lambda ln: -statistics.median(por_lang[ln]))
    for ln in orden:
        v = por_lang[ln]
        if ln not in tc:
            continue
        print(f"  {tc[ln].color}{tc[ln].label:<22}{C.RESET}"
              f"mediana {statistics.median(v):>4.1f}   "
              f"min..max {min(v)}..{max(v)}")


def print_samples_table(rows: list[dict], active_langs: list[str],
                        tc: dict[str, Toolchain]) -> None:
    """TODAS las muestras, una fila por lenguaje.

    Un resumen es una interpretacion; las muestras son el dato.  Verlas en fila
    es lo unico que deja ver de un vistazo la forma de la serie -- si es plana,
    si sube, si hay un salto suelto --, y eso ningun estadistico lo dice.  La
    mediana va marcada con `*` para poder situarla entre las demas.
    """
    print()
    print(f"{C.BOLD}Muestras individuales (ms) -- una fila por lenguaje{C.RESET}")
    print(f"{C.DIM}  `*` la muestra mas cercana a la mediana; "
          f"`!` las que se apartan de ella mas de 3 sigmas estimadas "
          f"desde la MAD{C.RESET}")
    for row in rows:
        runs_map = row.get("_runs", {})
        hay = [ln for ln in active_langs if runs_map.get(ln)]
        if not hay:
            continue
        print(f"\n  {C.BOLD}{row['bench']}{C.RESET}")
        for ln in hay:
            rs = runs_map[ln]
            s = _stats_summary(rs)
            # Umbral de atipico: 3 sigmas, con la sigma estimada a partir de la
            # MAD (x1.4826, que es lo que la iguala a la desviacion tipica en
            # una normal).  Usar la MAD cruda marcaba como atipica cualquier
            # variacion normal de una serie apretada.  Con MAD 0 (serie
            # constante) no se marca nada: no hay escala con la que medir.
            umbral = 3.0 * 1.4826 * s["mad"] if s["mad"] > 0 else float("inf")
            # La mediana de una muestra par no es ninguna de las medidas: se
            # marca la que MENOS se aparta de ella, y solo esa.
            i_p50 = min(range(len(rs)), key=lambda i: abs(rs[i] - s["p50"]))
            piezas = []
            for i, x in enumerate(rs):
                if i == i_p50:
                    sufijo, col = "*", C.BOLD
                elif abs(x - s["p50"]) > umbral:
                    sufijo, col = "!", C.RED
                else:
                    sufijo, col = " ", ""
                fin = C.RESET if col else ""
                piezas.append(f"{col}{x:8.1f}{sufijo}{fin}")
            print(f"    {tc[ln].color}{ln:<14}{C.RESET}" + "".join(piezas))


def print_noise_ranking(rows: list[dict], active_langs: list[str],
                        tc: dict[str, Toolchain]) -> None:
    """Cuanto ruido tiene cada lenguaje, y donde esta el peor.

    Dos vistas, porque responden a cosas distintas: la primera dice de que
    lenguaje se puede uno fiar en esta maquina, y la segunda senala las medidas
    concretas que hay que mirar con lupa antes de sacar conclusiones de ellas.
    """
    # 1. Por lenguaje: la mediana de su ruido a lo largo de todos los benches.
    por_lang: dict[str, list[float]] = {}
    peores: list[tuple[float, str, str, dict]] = []
    for row in rows:
        runs_map = row.get("_runs", {})
        for ln in active_langs:
            rs = runs_map.get(ln)
            if not rs:
                continue
            s = _stats_summary(rs)
            por_lang.setdefault(ln, []).append(s["mad_pct"])
            peores.append((s["mad_pct"], row["bench"], ln, s))
    if not por_lang:
        return

    print()
    print(f"{C.BOLD}Ruido por lenguaje (MAD relativa, mediana sobre los "
          f"benches){C.RESET}")
    print(f"{C.DIM}  mas bajo = medida mas repetible.  No dice nada de lo "
          f"rapido que es: dice de cuanto fiarse del numero.{C.RESET}")
    orden = sorted(por_lang.items(), key=lambda kv: statistics.median(kv[1]))
    peor = max(statistics.median(v) for v in por_lang.values()) or 1.0
    for pos, (ln, vals) in enumerate(orden, 1):
        m = statistics.median(vals)
        alto = max(vals)
        barra = ascii_bar(m, peor, width=24, color=_color_ruido(m))
        print(f"  {pos:>2}. {tc[ln].color}{tc[ln].label:<22}{C.RESET}"
              f"{m:>6.1f}%  {barra}  (peor bench: {alto:.1f}%)")

    # 2. Las medidas concretas mas ruidosas.
    peores.sort(key=lambda t: -t[0])
    con_ruido = [p for p in peores if p[0] >= 5.0]
    print()
    if not con_ruido:
        print(f"{C.GREEN}  Ninguna medida pasa del 5% de MAD relativa: la "
              f"corrida entera es estable.{C.RESET}")
        return
    print(f"{C.BOLD}Medidas mas ruidosas (MAD relativa >= 5%): "
          f"{len(con_ruido)} de {len(peores)}{C.RESET}")
    print(f"{C.DIM}  De estas, una diferencia menor que su propio ruido no es "
          f"una diferencia.{C.RESET}")
    for mad_pct, bench, ln, s in con_ruido[:15]:
        print(f"    {tc[ln].color}{bench + '/' + ln:<30}{C.RESET}"
              f"p50={s['p50']:>8.1f}  "
              f"{_color_ruido(mad_pct)}MAD={mad_pct:>5.1f}%{C.RESET}  "
              f"min..max = {s['min']:.1f}..{s['max']:.1f}  "
              f"media-p50 = {s['sesgo_pct']:+.1f}%")
    if len(con_ruido) > 15:
        print(f"    {C.DIM}... y {len(con_ruido) - 15} mas{C.RESET}")


def print_baseline_comparison(rows: list[dict], active_langs: list[str],
                                tc: dict[str, Toolchain],
                                baseline_path: str,
                                threshold_pct: float) -> None:
    """Compara cada (bench, lang) vs el JSON baseline.

    Reporta delta porcentual:
      - >= +threshold% -> regresion (rojo).
      - <= -threshold% -> mejora    (verde).
      - dentro del threshold -> neutro (gris).
    """
    print()
    try:
        with open(baseline_path, encoding="utf-8") as f:
            base_data = json.load(f)
    except Exception as e:  # noqa: BLE001
        warn(f"baseline no se pudo leer ({baseline_path}): {e}")
        return

    base_results = {r["bench"]: r for r in base_data.get("results", [])}
    print(f"{C.BOLD}Comparacion vs baseline "
          f"({baseline_path}){C.RESET}")
    print(f"{C.DIM}umbral regresion/mejora: +/-{threshold_pct:.1f}%{C.RESET}")
    print()

    header_cols = [f"{'BENCHMARK':<22}"]
    for ln in active_langs:
        header_cols.append(f"{tc[ln].label:>14}")
    print(f"{C.BOLD}{' '.join(header_cols)}{C.RESET}")
    print("-" * (22 + 15 * len(active_langs)))

    n_regress = 0
    n_improve = 0
    n_neutral = 0
    for row in rows:
        cols = [f"{row['bench']:<22}"]
        base_row = base_results.get(row["bench"], {})
        for ln in active_langs:
            cur = row.get(ln)
            prev = base_row.get(ln)
            if (cur is None or cur < 0 or prev is None
                    or (isinstance(prev, (int, float)) and prev < 0)):
                cols.append(f"{C.GREY}{'-':>14}{C.RESET}")
                continue
            delta = (cur - prev) * 100.0 / prev if prev > 0 else 0.0
            if delta >= threshold_pct:
                col = C.RED
                n_regress += 1
            elif delta <= -threshold_pct:
                col = C.GREEN
                n_improve += 1
            else:
                col = C.GREY
                n_neutral += 1
            # El formato +13.1f ya emite signo (+/-); no duplicar.
            cols.append(f"{col}{delta:>+13.1f}%{C.RESET}")
        print(" ".join(cols))
    print("-" * (22 + 15 * len(active_langs)))
    print(f"  {C.RED}regresiones (>=+{threshold_pct:.0f}%): "
          f"{n_regress}{C.RESET}   "
          f"{C.GREEN}mejoras (<=-{threshold_pct:.0f}%): "
          f"{n_improve}{C.RESET}   "
          f"{C.GREY}neutros: {n_neutral}{C.RESET}")


def print_results_table(rows: list[dict], tc: dict[str, Toolchain],
                         active_langs: list[str]) -> None:
    """Tabla: filas=benches, columnas=lenguajes con el tiempo del CODIGO."""
    # Cabecera.
    header_cols = [f"{'BENCHMARK':<22}"]
    for ln in active_langs:
        label = tc[ln].label
        header_cols.append(f"{label:>14}")
    header = " ".join(header_cols)
    print()
    # Decir QUE hay en la tabla, porque no es el numero obvio: es el medido
    # menos el arranque del lenguaje.  Sin esta linea, quien compare con un
    # cronometro por fuera vera otra cosa y pensara que el arnes miente.
    if any(row.get("_suelo_descontado") for row in rows):
        print(f"{C.DIM}ms de CoDIGO: al tiempo medido se le ha restado el "
              f"arranque del lenguaje (ver 'Suelo').  Un `~` delante marca las "
              f"medidas que no llegan a separarse de ese arranque: se ensenan, "
              f"pero no entran en las razones ni en las medias.{C.RESET}")
    print(f"{C.BOLD}{header}{C.RESET}")
    print("-" * len(header))

    for row in rows:
        cols = [f"{row['bench']:<22}"]
        dudosas = no_agregables(row)
        # El ganador se busca solo entre las medidas que SI se distinguen del
        # arranque.  Sin ese filtro, ganaria el que menos se distingue.
        valid_times = {k: row[k] for k in active_langs
                       if k in row and row[k] is not None and row[k] >= 0
                       and k not in dudosas}
        min_time = min(valid_times.values()) if valid_times else None
        for ln in active_langs:
            t = row.get(ln)
            if t is None:
                cols.append(f"{C.GREY}{'N/A':>14}{C.RESET}")
            elif t == SIN_TURNO and ln not in dudosas:
                cols.append(f"{C.GREY}{'SIN TURNO':>14}{C.RESET}")
            elif t == NO_ARRANCA and ln not in dudosas:
                # Ni compilo mal ni tardo: no se pudo ni lanzar (falta el
                # binario, o el permiso no se pudo arreglar).
                cols.append(f"{C.RED}{'NO ARRANCA':>14}{C.RESET}")
            elif t == MURIO and ln not in dudosas:
                # Compilo y arranco; se murio a mitad.  Antes caia en la rama
                # de abajo y salia `NO COMPILA`, que manda a mirar el
                # compilador cuando el problema esta en el programa.
                cols.append(f"{C.RED}{'MURIO':>14}{C.RESET}")
            elif t <= -2 and ln not in dudosas:
                cols.append(f"{C.RED}{'NO COMPILA':>14}{C.RESET}")
            elif t < 0 and ln not in dudosas:
                cols.append(f"{C.RED}{'TIMEOUT':>14}{C.RESET}")
            elif ln in dudosas:
                # Se muestra el numero -- es lo que se midio -- con la marca de
                # que no se sostiene por si solo.  Dos marcas distintas porque
                # son problemas OPUESTOS y el lector tiene que poder verlo:
                #   `~`  demasiado rapido: no se separa del arranque.
                #   `>`  demasiado lento: se corto en el tope, es una cota.
                if ln in (row.get("_censurado") or {}):
                    texto = f">{t:.0f}"
                else:
                    texto = f"~{t:.1f}" if t > 0 else "~0"
                cols.append(f"{C.YELLOW}{texto:>14}{C.RESET}")
            else:
                color = C.BOLD + C.GREEN if t == min_time else tc[ln].color
                cols.append(f"{color}{t:>14.1f}{C.RESET}")
        print(" ".join(cols))
    print("-" * len(header))


def ascii_bar(value: float, max_value: float, width: int = 30,
              color: str = "") -> str:
    """Barra ASCII proporcional."""
    if max_value <= 0:
        return ""
    fill = int(width * value / max_value)
    fill = max(0, min(width, fill))
    return f"{color}{'#' * fill}{C.DIM}{'.' * (width - fill)}{C.RESET}"


def print_ascii_charts(rows: list[dict], active_langs: list[str],
                        tc: dict[str, Toolchain]) -> None:
    """Imprime los charts ASCII en consola: 3 visualizaciones rapidas
    sin necesidad de abrir el PNG."""
    print()
    print(f"{C.BOLD}=== ASCII charts (vista rapida en consola) =={C.RESET}")

    # Chart 1: wall time por bench (lenguaje mas rapido como baseline).
    print()
    print(f"{C.BOLD}(1) Wall time relativo por bench (lang mas rapido = 100%){C.RESET}")
    for r in rows:
        # El MISMO filtro que la tabla: fuera las medidas que no se separan
        # del arranque del proceso.  Sin el, esta grafica cogia como "ganador"
        # justamente el numero que la tabla ya habia declarado no medible --
        # un `vx_jit` de 0.0 ms -- y escalaba a los demas contra el, con
        # resultados como "Python 172089.66x".  El mismo informe excluia un
        # valor en una pagina y montaba su titular sobre el en la siguiente.
        dudosas = no_agregables(r)
        valid = [(ln, r[ln]) for ln in active_langs
                 if r.get(ln) is not None and r.get(ln, -1) > 0
                 and ln not in dudosas]
        if len(valid) < 2:
            continue
        valid.sort(key=lambda x: x[1])
        fastest_t = valid[0][1]
        max_t = valid[-1][1]
        print(f"\n  {C.BOLD}{r['bench']}{C.RESET}")
        for ln, v in valid:
            ratio = v / fastest_t
            bar = ascii_bar(v, max_t, width=30,
                            color=tc[ln].color)
            mark = f"{C.GREEN}<-- ganador{C.RESET}" if ratio == 1.0 else ""
            label = LANG_LABELS_PLAIN.get(ln, ln)
            print(f"    {label:<16} {bar} {v:>9.1f} ms  ({ratio:>5.2f}x) {mark}")

    # Chart 2: speedup Vesta-lang JIT vs Vesta-lang interp por bench.
    print()
    print(f"{C.BOLD}(2) Speedup Vesta-lang JIT vs Vesta-lang interp{C.RESET}")
    vx_data = []
    for r in rows:
        ti = r.get("vx_interp")
        tj = r.get("vx_jit")
        if ti and ti > 0 and tj and tj > 0:
            vx_data.append((r["bench"], ti / tj))
    if vx_data:
        vx_data.sort(key=lambda x: x[1], reverse=True)
        max_sp = vx_data[0][1]
        for name, sp in vx_data:
            color = (C.GREEN if sp >= 10 else
                     C.CYAN if sp >= 2 else
                     C.YELLOW if sp >= 1 else C.RED)
            bar = ascii_bar(sp, max_sp, width=35, color=color)
            print(f"  {name:<18} {bar} {color}{sp:>7.2f}x{C.RESET}")

    # Chart 3: geomean slowdown vs C por lenguaje.
    if "c" in active_langs:
        print()
        print(f"{C.BOLD}(3) Geomean slowdown vs C por lenguaje (mas bajo = mejor){C.RESET}")
        geomeans = []
        for ln in active_langs:
            if ln == "c":
                continue
            ratios = []
            for r in rows:
                tc_v = r.get("c")
                tl = r.get(ln)
                if tc_v and tc_v > 0 and tl and tl > 0:
                    ratios.append(tl / tc_v)
            if ratios:
                import math
                gm = math.exp(sum(math.log(x) for x in ratios) / len(ratios))
                geomeans.append((ln, gm))
        geomeans.sort(key=lambda x: x[1])
        if geomeans:
            max_gm = geomeans[-1][1]
            for ln, gm in geomeans:
                color = (C.GREEN if gm < 2 else
                         C.YELLOW if gm < 5 else
                         C.CYAN if gm < 20 else C.RED)
                bar = ascii_bar(gm, max_gm, width=35, color=color)
                label = LANG_LABELS_PLAIN.get(ln, ln)
                print(f"  {label:<18} {bar} {color}{gm:>7.2f}x{C.RESET}")


# Labels sin codigos ANSI para padding consistente.
LANG_LABELS_PLAIN = {
    "vx_interp":   "Vesta-lang interp",
    "vx_jit":      "Vesta-lang JIT",
    "vx_aot_sse2": "Vesta-lang AOT sse2",
    "vx_aot_avx":  "Vesta-lang AOT avx2",
    "vx_aot_auto": "Vesta-lang AOT auto",
    "c":            "C (gcc -O3)",
    "cpp":          "C++ (g++ -O3)",
    "python":       "Python",
    "java":         "Java",
    "go":           "Go (gc)",
    "rust":         "Rust (rustc -O)",
}


def print_speedup_summary(rows: list[dict], active_langs: list[str],
                           baseline: str = "c") -> None:
    """Compara cada lenguaje contra C (baseline = mas rapido tipicamente)."""
    if baseline not in active_langs:
        return
    print()
    print(f"{C.BOLD}Speedup vs {baseline.upper()} (mas alto = peor){C.RESET}")
    print(f"{C.DIM}(C es el baseline porque tipicamente es el mas rapido){C.RESET}")
    print()
    header = f"{'BENCH':<22}"
    for ln in active_langs:
        if ln == baseline:
            continue
        header += f"{ln+' vs '+baseline:>20}"
    print(f"{C.BOLD}{header}{C.RESET}")
    saltadas = 0
    for row in rows:
        cols = [f"{row['bench']:<22}"]
        dudosas = no_agregables(row)
        baseline_t = row.get(baseline)
        # Una razon exige que los DOS terminos se sostengan.  Si el baseline no
        # se distingue del arranque, dividir por el da un numero inventado.
        if (baseline_t is None or baseline_t <= 0 or baseline in dudosas):
            if baseline in dudosas:
                saltadas += 1
            for ln in active_langs:
                if ln == baseline:
                    continue
                cols.append(f"{'-':>20}")
        else:
            for ln in active_langs:
                if ln == baseline:
                    continue
                t = row.get(ln)
                if t is None or t < 0 or ln in dudosas:
                    if ln in dudosas:
                        saltadas += 1
                    cols.append(f"{'-':>20}")
                else:
                    ratio = t / baseline_t
                    if ratio < 2:
                        clr = C.GREEN
                    elif ratio < 5:
                        clr = C.YELLOW
                    elif ratio < 20:
                        clr = C.CYAN
                    else:
                        clr = C.RED
                    text = f"{ratio:>14.2f}x"
                    pad = 20 - len(text)
                    cols.append(f"{' '*pad}{clr}{text}{C.RESET}")
        print(" ".join(cols))
    if saltadas:
        # Decir lo que se dejo fuera.  Una tabla con huecos y sin explicacion
        # se lee como si no hubiera pasado nada.
        print(f"{C.DIM}  ({saltadas} razones sin calcular: alguno de los dos "
              f"terminos no se distingue del arranque del proceso){C.RESET}")


def save_matplotlib(rows: list[dict], active_langs: list[str],
                     tc: dict[str, Toolchain], out_path: Path) -> bool:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        return False

    # Filtrar benches que tienen al menos 2 lenguajes con datos validos.
    valid_rows = []
    for row in rows:
        cnt = sum(1 for ln in active_langs
                  if row.get(ln) is not None and row.get(ln, -1) >= 0)
        if cnt >= 2:
            valid_rows.append(row)
    if not valid_rows:
        return False

    # Map lenguaje -> color matplotlib.
    lang_color = {
        "vx_interp":   "#ff7f0e",
        "vx_jit":      "#2ca02c",
        "vx_aot_sse2": "#8c564b",
        "vx_aot_avx":  "#e377c2",
        "vx_aot_auto": "#7f7f7f",
        "c":            "#1f77b4",
        "cpp":          "#9467bd",
        "python":       "#17becf",
        "java":         "#d62728",
        "go":           "#007d9c",
        "rust":         "#CE422B",
    }

    n_benches = len(valid_rows)
    n_langs = len(active_langs)
    bar_h = 0.8 / n_langs
    y_pos = np.arange(n_benches)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(18, max(6, n_benches * 0.7)))

    # Panel 1: tiempo absoluto (log scale).
    for i, ln in enumerate(active_langs):
        times = [row.get(ln) for row in valid_rows]
        # Sustituir None/-1 por NaN para que no se grafiquen.
        plot_times = [t if (t is not None and t >= 0) else float("nan") for t in times]
        offset = (i - n_langs / 2 + 0.5) * bar_h
        ax1.barh(y_pos + offset, plot_times, bar_h,
                 label=tc[ln].label, color=lang_color.get(ln, "#888"))
    ax1.set_yticks(y_pos)
    ax1.set_yticklabels([r["bench"] for r in valid_rows], fontsize=10)
    ax1.set_xscale("log")
    ax1.set_xlabel("Wall time (ms, log scale)")
    ax1.set_title("Wall time absoluto por lenguaje")
    ax1.legend(loc="lower right", fontsize=9)
    ax1.grid(axis="x", which="both", alpha=0.3)

    # Panel 2: ratio vs C (cuanto mas lento es cada lenguaje vs C).
    baseline = "c"
    if baseline in active_langs:
        for i, ln in enumerate(active_langs):
            if ln == baseline:
                continue
            ratios = []
            for row in valid_rows:
                tb = row.get(baseline)
                tl = row.get(ln)
                if tb is None or tb <= 0 or tl is None or tl < 0:
                    ratios.append(float("nan"))
                else:
                    ratios.append(tl / tb)
            offset = (i - n_langs / 2 + 0.5) * bar_h
            ax2.barh(y_pos + offset, ratios, bar_h,
                     label=tc[ln].label, color=lang_color.get(ln, "#888"))
        ax2.axvline(x=1.0, color="grey", linestyle="--", alpha=0.5,
                    label="1x (paridad con C)")
        ax2.axvline(x=10.0, color="orange", linestyle=":", alpha=0.5,
                    label="10x mas lento")
        ax2.set_yticks(y_pos)
        ax2.set_yticklabels([r["bench"] for r in valid_rows], fontsize=10)
        ax2.set_xscale("log")
        ax2.set_xlabel("Ratio vs C (mas alto = mas lento)")
        ax2.set_title("Comparativa vs C (baseline)")
        ax2.legend(loc="lower right", fontsize=9)
        ax2.grid(axis="x", which="both", alpha=0.3)

    plt.tight_layout()
    plt.savefig(out_path, dpi=110, bbox_inches="tight")
    plt.close(fig)
    return True


# =============================================================================
# Sprint bench-html (2026-06-02): reporte HTML autocontenido
# =============================================================================

def _html_escape(s: str) -> str:
    """Escape minimo para HTML."""
    return (s.replace("&", "&amp;")
             .replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;"))


def generate_html_report(rows: list[dict], active_langs: list[str],
                          tc: dict[str, "Toolchain"],
                          sys_info: dict, plot_dir: Path,
                          json_path: Path,
                          baseline_path: str = "",
                          threshold_pct: float = 10.0) -> Path:
    """Genera @c bench_plots/index.html con sistema info + tabla de
    resultados + tabla de categorias + plots embebidos.

    El HTML referencia los PNG por ruta relativa, asi que abrir
    @c bench_plots/index.html en cualquier navegador funciona stand-alone.

    Si @c baseline_path apunta a un JSON valido, se incluye una tabla
    extra con deltas vs baseline coloreados.
    """
    import datetime
    import math
    out_path = plot_dir / "index.html"
    hw = sys_info.get("hardware", {})
    os_info = sys_info.get("os", {})
    tooling = sys_info.get("tooling", {})
    timestamp = sys_info.get("date") or datetime.datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S")

    # CSS minimalista.
    css = """
    body { font-family: -apple-system,Segoe UI,Roboto,sans-serif; max-width:1280px;
           margin:24px auto; padding:0 20px; color:#1f2328; }
    h1 { border-bottom:2px solid #d0d7de; padding-bottom:8px; }
    h2 { margin-top:32px; border-bottom:1px solid #d0d7de; padding-bottom:4px; }
    dl.sysinfo { display:grid; grid-template-columns:160px 1fr; gap:4px 12px; }
    dl.sysinfo dt { font-weight:600; color:#57606a; }
    table { border-collapse:collapse; width:100%; margin:8px 0 24px;
            font-variant-numeric:tabular-nums; font-size:13px; }
    th,td { padding:6px 10px; border-bottom:1px solid #eaecef; text-align:right; }
    th:first-child,td:first-child { text-align:left; font-weight:500; }
    th { background:#f6f8fa; font-weight:600; }
    tr:hover { background:#f8f9fb; }
    .winner { font-weight:700; color:#1a7f37; }
    .timeout { color:#cf222e; }
    .na { color:#8c959f; }
    /* Medidas que se ensenan pero no entran en razones ni medias: `~` no se
       separa del arranque, `>` se corto en el tope.  En ambar, no en rojo:
       no son un fallo, son un numero que no se sostiene solo. */
    .dudosa { color:#9a6700; }
    .cat-good { color:#1a7f37; font-weight:600; }
    .cat-mid { color:#bf8700; font-weight:600; }
    .cat-bad { color:#cf222e; font-weight:600; }
    .delta-regress { color:#cf222e; font-weight:600; }
    .delta-improve { color:#1a7f37; font-weight:600; }
    .delta-neutral { color:#8c959f; }
    img.plot { max-width:100%; height:auto; border:1px solid #d0d7de;
               border-radius:6px; margin:12px 0; }
    .meta { color:#6e7681; font-size:12px; margin-top:24px;
             padding-top:12px; border-top:1px solid #eaecef; }
    .grid-plots { display:grid; grid-template-columns:repeat(auto-fit,
                  minmax(400px,1fr)); gap:16px; }
    """

    html: list[str] = []
    html.append("<!doctype html>")
    html.append('<html lang="es"><head>')
    html.append('<meta charset="utf-8">')
    html.append("<title>VestaVM Benchmark Report</title>")
    html.append(f"<style>{css}</style>")
    html.append("</head><body>")
    html.append(f"<h1>VestaVM Benchmark Report</h1>")
    html.append(f'<p class="meta">Generado {_html_escape(timestamp)} '
                f'&middot; JSON: <code>{_html_escape(str(json_path))}</code></p>')

    # ---- System info ----
    html.append("<h2>Sistema</h2>")
    html.append('<dl class="sysinfo">')
    cpu_line = (f"{hw.get('cpu_model','?')} "
                f"({hw.get('cpu_physical','?')} fisicos / "
                f"{hw.get('cpu_logical','?')} logicos @ "
                f"{hw.get('cpu_freq_mhz','?')})")
    html.append(f"<dt>CPU</dt><dd>{_html_escape(cpu_line)}</dd>")
    html.append(f"<dt>RAM</dt><dd>{_html_escape(str(hw.get('ram_gb','?')))}</dd>")
    html.append(f"<dt>Arch</dt><dd>{_html_escape(str(hw.get('arch','?')))}</dd>")
    html.append(f"<dt>OS</dt><dd>{_html_escape(os_info.get('platform','?'))} "
                f"({_html_escape(os_info.get('version','?'))})</dd>")
    html.append("</dl>")

    if tooling:
        html.append("<h2>Toolchains</h2>")
        html.append('<dl class="sysinfo">')
        for name, t in tooling.items():
            if t.get("available"):
                ver = (t.get("version") or "").splitlines()
                ver_short = (ver[0] if ver else "?")[:80]
                html.append(f"<dt>{_html_escape(name)}</dt>"
                            f"<dd>{_html_escape(ver_short)}</dd>")
            else:
                html.append(f"<dt>{_html_escape(name)}</dt>"
                            f"<dd class='na'>no disponible</dd>")
        html.append("</dl>")

    # ---- Tabla principal de resultados ----
    html.append("<h2>Resultados (ms, mediana)</h2>")
    html.append("<table>")
    head = ["<th>Benchmark</th>"]
    for ln in active_langs:
        head.append(f"<th>{_html_escape(tc[ln].label)}</th>")
    html.append("<thead><tr>" + "".join(head) + "</tr></thead>")
    html.append("<tbody>")
    for row in rows:
        # El MISMO filtro que la consola.  El HTML se publica y se comparte, y
        # que ensene como buena una cifra que la tabla del terminal marco es
        # peor que no publicarlo: sobrevive al terminal donde estaba el aviso.
        dudosas = no_agregables(row)
        valid_times = {k: row[k] for k in active_langs
                       if k in row and row[k] is not None and row[k] >= 0
                       and k not in dudosas}
        min_time = min(valid_times.values()) if valid_times else None
        cols = [f"<td>{_html_escape(row['bench'])}</td>"]
        for ln in active_langs:
            t = row.get(ln)
            if t is None:
                cols.append('<td class="na">N/A</td>')
            elif ln in dudosas and t is not None and t >= 0:
                # Se ensena con su marca, igual que en la consola: `>` es una
                # cota por arriba (se corto en el tope) y `~` una por abajo
                # (no se separa del arranque).
                if ln in (row.get("_censurado") or {}):
                    texto, titulo = ">%.0f" % t, "se corto en el tope: cota inferior"
                else:
                    texto, titulo = "~%.1f" % t, "no se separa del arranque del proceso"
                cols.append('<td class="dudosa" title="%s">%s</td>'
                            % (titulo, texto))
            elif t < 0:
                # Los mismos cuatro estados que la consola.  El HTML se
                # comparte y sobrevive al terminal, asi que es el sitio donde
                # menos puede permitirse decir `TIMEOUT` de un crash.
                estado = ("SIN TURNO" if t == SIN_TURNO else
                          "NO ARRANCA" if t == NO_ARRANCA else
                          "MURIO" if t == MURIO else
                          "NO COMPILA" if t <= -2 else "TIMEOUT")
                cols.append('<td class="timeout">%s</td>' % estado)
            else:
                cls = ' class="winner"' if t == min_time else ""
                cols.append(f'<td{cls}>{t:.1f}</td>')
        html.append("<tr>" + "".join(cols) + "</tr>")
    html.append("</tbody></table>")

    # ---- Tabla de categorias ----
    cats: dict[str, list[dict]] = {}
    for row in rows:
        cats.setdefault(bench_category(row["bench"]), []).append(row)
    if cats and "c" in active_langs:
        html.append("<h2>Geomean slowdown vs C por categoria</h2>")
        html.append('<p class="meta">Verde &lt;1.5x &middot; Amarillo '
                    "&lt;3x &middot; Rojo &ge;3x</p>")
        html.append("<table>")
        head = ["<th>Categoria</th><th>N</th>"]
        for ln in active_langs:
            if ln == "c":
                continue
            head.append(f"<th>{_html_escape(tc[ln].label)}</th>")
        html.append("<thead><tr>" + "".join(head) + "</tr></thead>")
        html.append("<tbody>")
        for cat in sorted(cats.keys()):
            rs = cats[cat]
            cols = [f"<td>{_html_escape(cat)}</td><td>{len(rs)}</td>"]
            for ln in active_langs:
                if ln == "c":
                    continue
                ratios = []
                for r in rs:
                    v_ln = r.get(ln); v_c = r.get("c")
                    if (v_ln is None or v_c is None
                            or v_ln <= 0 or v_c <= 0):
                        continue
                    ratios.append(v_ln / v_c)
                if not ratios:
                    cols.append('<td class="na">N/A</td>')
                    continue
                log_sum = sum(math.log(x) for x in ratios)
                geo = math.exp(log_sum / len(ratios))
                cls = ("cat-good" if geo < 1.5
                       else "cat-mid" if geo < 3.0
                       else "cat-bad")
                cols.append(f'<td class="{cls}">{geo:.2f}x</td>')
            html.append("<tr>" + "".join(cols) + "</tr>")
        html.append("</tbody></table>")

    # ---- Comparacion vs baseline ----
    if baseline_path:
        try:
            with open(baseline_path, encoding="utf-8") as f:
                base_data = json.load(f)
            base_map = {r["bench"]: r for r in base_data.get("results", [])}
            html.append(f"<h2>Comparacion vs baseline</h2>")
            html.append(f'<p class="meta">Baseline: '
                        f'<code>{_html_escape(baseline_path)}</code> '
                        f'&middot; Umbral: &plusmn;{threshold_pct:.1f}%</p>')
            html.append("<table>")
            head = ["<th>Benchmark</th>"]
            for ln in active_langs:
                head.append(f"<th>{_html_escape(tc[ln].label)}</th>")
            html.append("<thead><tr>" + "".join(head) + "</tr></thead>")
            html.append("<tbody>")
            n_r = n_i = n_n = 0
            for row in rows:
                base_row = base_map.get(row["bench"], {})
                cols = [f"<td>{_html_escape(row['bench'])}</td>"]
                for ln in active_langs:
                    cur = row.get(ln); prev = base_row.get(ln)
                    if (cur is None or cur < 0 or prev is None
                            or (isinstance(prev, (int, float)) and prev < 0)):
                        cols.append('<td class="na">-</td>')
                        continue
                    delta = (cur - prev) * 100.0 / prev if prev > 0 else 0.0
                    if delta >= threshold_pct:
                        cls = "delta-regress"; n_r += 1
                    elif delta <= -threshold_pct:
                        cls = "delta-improve"; n_i += 1
                    else:
                        cls = "delta-neutral"; n_n += 1
                    cols.append(f'<td class="{cls}">{delta:+.1f}%</td>')
                html.append("<tr>" + "".join(cols) + "</tr>")
            html.append("</tbody></table>")
            html.append(f'<p class="meta">'
                        f'<span class="delta-regress">regresiones: {n_r}</span> '
                        f'&middot; <span class="delta-improve">mejoras: {n_i}</span> '
                        f'&middot; <span class="delta-neutral">neutros: {n_n}</span>'
                        f'</p>')
        except Exception as e:  # noqa: BLE001
            html.append(f"<p>baseline error: {_html_escape(str(e))}</p>")

    # ---- Plots embebidos ----
    html.append("<h2>Graficas</h2>")
    # Listar PNG ordenados (los numericos primero por prefijo "NN_").
    pngs = sorted(plot_dir.glob("*.png"))
    if pngs:
        html.append('<div class="grid-plots">')
        for png in pngs:
            rel = png.name  # ya estan en el mismo dir.
            stem = png.stem
            html.append(f'<div><h3>{_html_escape(stem)}</h3>'
                        f'<img class="plot" src="{_html_escape(rel)}" '
                        f'alt="{_html_escape(stem)}"></div>')
        html.append("</div>")
        # per_bench/ tambien.
        per_bench_dir = plot_dir / "per_bench"
        if per_bench_dir.is_dir():
            pb_pngs = sorted(per_bench_dir.glob("*.png"))
            if pb_pngs:
                html.append("<h2>Per-bench</h2>")
                html.append('<div class="grid-plots">')
                for png in pb_pngs:
                    rel = "per_bench/" + png.name
                    html.append(f'<div><h3>{_html_escape(png.stem)}</h3>'
                                f'<img class="plot" src="{_html_escape(rel)}" '
                                f'alt="{_html_escape(png.stem)}"></div>')
                html.append("</div>")
    else:
        html.append('<p class="na">No hay PNG en este directorio.</p>')

    html.append("</body></html>")
    out_path.write_text("\n".join(html), encoding="utf-8")
    return out_path


# =============================================================================
# Sprint bench-from-json: re-render desde JSON sin re-medir
# =============================================================================

def rerender_from_json(json_path: Path, project_root: Path,
                        no_plot: bool, no_html: bool,
                        verbose_stats: bool,
                        baseline_path: str, threshold_pct: float) -> int:
    """Carga un bench_results.json previo y re-genera tabla consola +
    plots + HTML.  Util para tweakear el reporte sin re-medir."""
    print()
    info(f"re-renderizando desde JSON: {C.BOLD}{json_path}{C.RESET}")
    try:
        with open(json_path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:  # noqa: BLE001
        err(f"no pude leer JSON: {e}")
        return 1

    active_langs = data.get("active_langs", [])
    sys_info = data.get("system_info", {})

    # Reconstruir rows con shape esperado.
    rows: list[dict] = []
    for r in data.get("results", []):
        row = {k: v for k, v in r.items() if k != "runs_individual"}
        # Para reusar las funciones que usan _runs:
        row["_runs"] = r.get("runs_individual", {})
        row["_calentamientos"] = r.get("calentamientos", {})
        row["_bruto"] = r.get("bruto", {})
        row["_bajo_suelo"] = r.get("bajo_suelo", {})
        # Las dos que se anadieron con los dos ejes.  Se restauran aqui o el
        # re-render publicaria como buenas unas cifras que la tanda original
        # habia marcado, y sin el eje interno la tabla de los dos ejes saldria
        # vacia al re-renderizar.
        row["_censurado"] = r.get("censurado", {})
        row["_interno"] = r.get("interno", {})
        row["_suelo_descontado"] = bool(data.get("suelo"))
        rows.append(row)

    # Toolchains: solo necesitamos los labels.  Construir un mock minimal.
    class _MockTc:
        def __init__(self, name, label, color):
            self.name = name; self.label = label; self.color = color
            self.available = True
    LABELS = {
        "vx_interp":   ("Vesta-lang interp",   C.YELLOW),
        "vx_jit":      ("Vesta-lang JIT",      C.GREEN),
        "vx_aot_sse2": ("Vesta-lang AOT sse2", C.ORANGE),
        "vx_aot_avx":  ("Vesta-lang AOT avx2", C.VIOLET),
        "vx_aot_auto": ("Vesta-lang-lang AOT auto", C.PINK),
        "c":            ("C (gcc -O3)",  C.BLUE),
        "cpp":          ("C++ (g++ -O3)", C.MAGENTA),
        "python":       ("Python (CPython)", C.CYAN),
        "java":         ("Java (HotSpot)", C.RED),
        "go":           ("Go (gc)", C.TEAL),
        "rust":         ("Rust (rustc -O)", C.RUST),
    }
    tc = {ln: _MockTc(ln, *LABELS.get(ln, (ln, C.RESET))) for ln in active_langs}

    # Banner.
    if sys_info:
        print_system_banner(sys_info)

    # Tabla principal.
    print_results_table(rows, tc, active_langs)
    print_speedup_summary(rows, active_langs, baseline="c")
    if "c" in active_langs:
        print_category_summary(rows, active_langs, tc, baseline="c")
    suelo = data.get("suelo", {})
    print_suelo_table(suelo, active_langs, tc)
    print_calentamiento_table(rows, active_langs, tc)
    print_dos_ejes(rows, active_langs, tc, suelo)
    print_censurados_table(rows, tc)
    print_bajo_suelo_table(rows, active_langs, tc)
    if verbose_stats:
        print_verbose_stats_table(rows, active_langs, tc, suelo)
        print_samples_table(rows, active_langs, tc)
    # El ruido se publica SIEMPRE, no solo con --verbose-stats: sin saber
    # cuanto se mueve una medida, la tabla principal invita a leer como
    # diferencia lo que puede ser la maquina.
    print_noise_ranking(rows, active_langs, tc)
    if baseline_path:
        print_baseline_comparison(rows, active_langs, tc,
                                   baseline_path, threshold_pct)

    # Plots.  Solo el JSON de REFERENCIA escribe en el directorio de
    # referencia.  Es el mismo agujero que ya se tapo para el JSON, y aqui
    # seguia abierto: re-renderizar una corrida de dos benches dejaba
    # `bench_plots/` con dos benches, sin avisar, y las graficas versionadas de
    # la tanda completa desaparecian.  La regla no es adivinar si el JSON esta
    # completo -- eso no se puede saber mirandolo -- sino que quien no es la
    # referencia no la toca.
    referencia = project_root / "bench_results.json"
    es_referencia = json_path.resolve() == referencia.resolve()
    plot_dir = (project_root / "bench_plots" if es_referencia
                else project_root / f"bench_plots_{json_path.stem}")
    if not es_referencia:
        info(f"el JSON no es la referencia: las graficas van a "
             f"{plot_dir.name}/ para no pisar las de la tanda completa.")
    if not no_plot:
        try:
            from . import plots
        except (ImportError, ValueError):
            sys.path.insert(0, str(Path(__file__).parent))
            import plots  # type: ignore
        try:
            results = plots.generate_all(rows, active_langs, plot_dir,
                                          sys_info=sys_info, suelo=suelo)
            print()
            info(f"plots: {plot_dir}")
            for name, success in results.items():
                marker = (f"{C.GREEN}OK{C.RESET}" if success
                          else f"{C.RED}FAIL{C.RESET}")
                print(f"  {marker}  {name}")
        except Exception as e:  # noqa: BLE001
            warn(f"plots error: {e}")

    # HTML.
    if not no_html:
        try:
            html_path = generate_html_report(
                rows, active_langs, tc, sys_info, plot_dir,
                json_path, baseline_path, threshold_pct)
            ok(f"HTML: {C.BOLD}{html_path}{C.RESET}")
        except Exception as e:  # noqa: BLE001
            warn(f"HTML error: {e}")

    return 0


# =============================================================================
# Main
# =============================================================================

def main() -> int:
    C.enable_windows_ansi()

    parser = argparse.ArgumentParser(
        description="Benchmark suite multi-lenguaje VestaVM",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("vm_path", nargs="?")
    parser.add_argument(
        "--langs", type=str,
        default="vx_interp,vx_jit,vx_aot_sse2,vx_aot_avx,vx_aot_auto,"
                "c,cpp,python,java,go,rust",
        help=("lista CSV de lenguajes/modos a ejecutar.  Validos: "
              "vx_interp (interp puro), vx_jit (JIT), "
              "vx_aot_sse2 (AOT nativo 128b), vx_aot_avx (AOT AVX2 256b), "
              "vx_aot_auto (AOT multiversion cpuid), "
              "c (gcc -O3), cpp (g++ -O3), python, java, go (Go gc), "
              "rust (rustc -O -C target-cpu=native).  "
              "Ej: --langs vx_jit,vx_aot_auto,c,rust"))
    parser.add_argument("--cc", type=str, default="",
                        help="compilador de C a usar (ruta o nombre).  Sin "
                             "esto: si hay varios instalados se pregunta, y "
                             "si no hay terminal se coge el primero y se dice "
                             "cual.")
    parser.add_argument("--cxx", type=str, default="",
                        help="compilador de C++ a usar (ruta o nombre).")
    parser.add_argument("--filter", type=str, default="",
                        help="Regex para filtrar benches por nombre")
    parser.add_argument("--runs", type=int, default=RUNS_FAST,
                        help=("Runs medidos para lenguajes NO interpretados "
                              "(nativos/JIT), rapidos y ruidosos (default %d)."
                              % RUNS_FAST))
    parser.add_argument("--runs-slow", type=int, default=RUNS_SLOW,
                        help=("Runs medidos para lenguajes INTERPRETADOS "
                              "(python, vx_interp), lentos (default %d)."
                              % RUNS_SLOW))
    parser.add_argument("--timeout", type=float, default=BENCH_TIMEOUT,
                        help="tope de segundos por MEDIDA (default %g).  Lo "
                             "que se pase se anota como cota inferior "
                             "(`>tope`), se ensena en la tabla y se deja "
                             "fuera de razones y medias." % BENCH_TIMEOUT)
    parser.add_argument("--no-plot", action="store_true")
    parser.add_argument("--out-json", type=str, default="bench_results.json")
    parser.add_argument("--out-plot", type=str, default="bench_results.png")
    parser.add_argument("--skip-legacy", action="store_true",
                        help="No correr benches legacy single-file .vx")
    parser.add_argument("--compile-jobs", type=int, default=0,
                        help=("Paralelismo de compilacion (default: os.cpu_count()).  "
                              "Las EJECUCIONES siguen secuenciales para no contaminar "
                              "las mediciones de tiempo."))
    parser.add_argument("--warmup", type=int, default=1,
                        help=("Calentamiento ADAPTATIVO (default: activo).  El "
                              "arnes descarta ejecuciones hasta que la serie "
                              "deja de bajar, que es distinto en cada lenguaje "
                              "(un .exe de C se estabiliza en 2, la JVM en 7).  "
                              "Con 0 se desactiva: se mide EN FRIO a proposito."))
    parser.add_argument("--baseline", type=str, default="",
                        help=("Path a un bench_results.json previo para comparar.  "
                              "Imprime delta porcentual por bench y marca "
                              "regresiones/mejoras segun --threshold."))
    parser.add_argument("--threshold", type=float, default=10.0,
                        help=("Umbral porcentual para marcar regresion/mejora vs "
                              "baseline (default 10).  Solo afecta la coloracion."))
    parser.add_argument("--verbose-stats", action="store_true",
                        help=("Imprime min/p50/p95/max/stddev por bench (no solo "
                              "mediana).  Default false; activable para diagnostico."))
    parser.add_argument("--from-json", type=str, default="",
                        help=("Path a un bench_results.json previo.  Skip compile "
                              "+ run; solo re-genera tabla/plots/HTML desde los "
                              "datos guardados.  Util para re-renderizar tras "
                              "cambiar el codigo de reporte sin re-medir."))
    parser.add_argument("--no-html", action="store_true",
                        help="No generar bench_plots/index.html")
    # Sprint bench-fair (2026-06-03): measurement methodology.
    parser.add_argument("--fair", action="store_true", default=True,
                        help=("FAIR MODE (default): mide wall externo para "
                              "TODOS los lenguajes (incluye fork + runtime "
                              "init).  Es la metrica honesta -- 'cuanto tarda "
                              "el usuario al invocar el programa'.  Vesta-lang paga "
                              "sus ~30ms de VM init igual que Python/Java pagan "
                              "su startup.  Benches cortos quedan dominados "
                              "por init y se ve realmente el coste."))
    parser.add_argument("--unfair", dest="fair", action="store_false",
                        help=("UNFAIR MODE (legacy): mide wall externo para "
                              "C/C++/Python/Java pero wall INTERNO (--stats) "
                              "para Vesta-lang.  Sobreestima Vesta-lang en benches cortos "
                              "porque excluye sus ~30ms de VM init.  Util "
                              "solo para diagnostico del scheduler interno."))
    args = parser.parse_args()

    project_root = find_project_root(Path(__file__).parent)
    info(f"project root: {C.BOLD}{project_root}{C.RESET}")
    if args.fair:
        info(f"measurement: {C.BOLD}{C.CYAN}FAIR{C.RESET} (wall externo "
             f"para TODOS los lenguajes; incluye fork + runtime init).  "
             f"Vesta-lang paga sus ~30ms de VM init igual que Python ~15ms / Java ~80ms.")
    else:
        info(f"measurement: {C.BOLD}{C.YELLOW}UNFAIR (legacy){C.RESET} "
             f"-- Vesta-lang usa Wall time interno --stats (sin VM init); otros "
             f"langs usan wall externo.  Sobreestima Vesta-lang en benches cortos.")

    # Sprint bench-from-json: short-circuit del flujo normal cuando el
    # usuario solo quiere re-renderizar reportes desde un JSON previo.
    if args.from_json:
        json_path = Path(args.from_json)
        if not json_path.is_absolute():
            json_path = project_root / json_path
        if not json_path.is_file():
            err(f"from-json: archivo no existe: {json_path}")
            return 1
        return rerender_from_json(
            json_path, project_root,
            no_plot=args.no_plot, no_html=args.no_html,
            verbose_stats=args.verbose_stats,
            baseline_path=args.baseline,
            threshold_pct=args.threshold)

    # Resolver el binario vm.
    if args.vm_path:
        vm = Path(args.vm_path)
        if not vm.is_file():
            err(f"binario no existe: {vm}")
            return 1
    else:
        candidates = find_vm_candidates(project_root)
        vm = prompt_choose_vm(candidates)
    ok(f"usando vm: {C.BOLD}{vm}{C.RESET}")

    # Detectar toolchains.
    _pedidos = {l.strip() for l in args.langs.split(",") if l.strip()} or None
    tc = detect_toolchains(vm, args.cc, args.cxx, _pedidos)
    print()
    info(f"{C.BOLD}Toolchains detectados:{C.RESET}")
    for name, t in tc.items():
        if t.available:
            print(f"  {C.GREEN}OK{C.RESET}  {t.color}{t.label}{C.RESET}")
        else:
            print(f"  {C.RED}--{C.RESET}  {C.DIM}{t.label}{C.RESET} "
                  f"({t.why_unavailable})")

    # Capturar info del sistema (CPU/RAM/OS + versiones).
    print()
    with Spinner("capturando info del sistema...", color=C.CYAN):
        sys_info = capture_system_info(vm, tc)
    # Sprint bench-hwinfo: banner expandido con hardware + toolchains.
    print_system_banner(sys_info)

    # Filtrar lenguajes activos.
    requested = [ln.strip() for ln in args.langs.split(",") if ln.strip()]
    # Avisar de nombres no reconocidos (typo o nombre viejo como "vx_aot").
    unknown = [ln for ln in requested if ln not in tc]
    if unknown:
        warn(f"lenguaje(s) no reconocido(s): {', '.join(unknown)}")
        info(f"validos: {', '.join(tc.keys())}")
    # Avisar de los reconocidos pero no disponibles (toolchain ausente).
    for ln in requested:
        if ln in tc and not tc[ln].available:
            warn(f"{ln} no disponible: {tc[ln].why_unavailable or 'desconocido'}")
    active_langs = [ln for ln in requested if ln in tc and tc[ln].available]
    if not active_langs:
        err("ningun lenguaje disponible/solicitado")
        return 1

    # Descubrir benches.
    bench_dir = project_root / "examples_codes_vx" / "benchmark"
    benches = discover_benches(bench_dir)
    if args.skip_legacy:
        benches = [b for b in benches if not b.is_legacy]
    if args.filter:
        pat = re.compile(args.filter)
        benches = [b for b in benches if pat.search(b.name)]
    if not benches:
        err("ningun bench encontrado")
        return 1
    multi = sum(1 for b in benches if not b.is_legacy)
    legacy = sum(1 for b in benches if b.is_legacy)
    info(f"benches: {C.BOLD}{len(benches)}{C.RESET} "
         f"({multi} multi-lenguaje, {legacy} legacy single-vx)")

    # Las librerias de dibujo se comprueban ANTES de medir.  Esta tanda dura
    # veinte minutos largos; descubrir al final que no hay graficas obliga a
    # repetirla entera.  Aqui se esta a tiempo de cortar, instalar y relanzar.
    if not args.no_plot:
        try:
            from . import plots  # cuando se invoca como modulo
        except (ImportError, ValueError):
            sys.path.insert(0, str(Path(__file__).parent))
            import plots  # type: ignore
        falta = plots.diagnostico_dependencias()
        if falta:
            warn(falta)
            print(f"{C.DIM}         La tanda sigue y el JSON se escribe igual; "
                  f"lo unico que no habra son las graficas.  Con `--no-plot` "
                  f"este aviso no sale.{C.RESET}")

    work_dir = Path(os.environ.get("TEMP", "/tmp")) / "vx_bench_multi"
    work_dir.mkdir(parents=True, exist_ok=True)

    # -------------------------------------------------------------------
    # Sprint bench-parallel (2026-06-02): pre-compile en paralelo.
    #
    # Antes el flujo era: por cada (bench, lang) hacer compile + run.  Los
    # compiles son IO-heavy (subprocess de gcc/g++/javac/vm.exe) y se
    # serializaban -> dominaban el tiempo total cuando se cubren todos
    # los lenguajes.  Ahora ejecutamos TODOS los compiles en paralelo via
    # ThreadPoolExecutor (workers = --compile-jobs, default cpu_count()).
    #
    # Las EJECUCIONES (mediciones reales) siguen secuenciales por diseno:
    # paralelizarlas contaminaria las mediciones (CPU compartida entre
    # benches -> tiempo wallclock no representativo).
    # -------------------------------------------------------------------
    n_compile_jobs = args.compile_jobs if args.compile_jobs > 0 else (os.cpu_count() or 4)

    # Build worklist de (bench_idx, bench, lang, variant).
    compile_tasks: list[tuple[int, Bench, str, BenchVariant]] = []
    for idx, b in enumerate(benches, 1):
        for ln in active_langs:
            variant: Optional[BenchVariant] = None
            if ln in VX_LANGS:
                variant = b.variants.get("vx")
            else:
                variant = b.variants.get(ln)
            if variant is None:
                continue
            compile_tasks.append((idx, b, ln, variant))

    def compilar_para(ln: str, variant: BenchVariant):
        """Compila @p variant para el lenguaje @p ln.

        Existe para que el suelo del lenguaje (@c medir_suelo) recorra
        EXACTAMENTE el mismo camino que un bench: mismos compiladores, mismas
        banderas, misma forma de lanzarlo.  Un suelo medido de otra manera no
        seria el suelo de estas medidas.
        """
        if ln in ("vx_interp", "vx_jit"):
            return compile_vx(variant, work_dir, vm)
        if ln in VX_AOT_MODES:
            return compile_vx_aot(variant, work_dir, vm,
                                  float_isa=VX_AOT_MODES[ln])
        if ln in ("c", "cpp", "python", "java", "go", "rust"):
            return {
                "c": compile_c, "cpp": compile_cpp, "python": compile_python,
                "java": compile_java, "go": compile_go, "rust": compile_rust,
            }[ln](variant, work_dir, tc[ln])
        return None

    def compile_one(task):
        idx, b, ln, variant = task
        try:
            if ln in ("vx_interp", "vx_jit"):
                return (idx, b.name, ln, compile_vx(variant, work_dir, vm), None)
            elif ln in VX_AOT_MODES:
                return (idx, b.name, ln,
                        compile_vx_aot(variant, work_dir, vm,
                                        float_isa=VX_AOT_MODES[ln]), None)
            elif ln == "c":
                return (idx, b.name, ln, compile_c(variant, work_dir, tc["c"]), None)
            elif ln == "cpp":
                return (idx, b.name, ln, compile_cpp(variant, work_dir, tc["cpp"]), None)
            elif ln == "python":
                return (idx, b.name, ln, compile_python(variant, work_dir, tc["python"]), None)
            elif ln == "java":
                return (idx, b.name, ln, compile_java(variant, work_dir, tc["java"]), None)
            elif ln == "go":
                return (idx, b.name, ln, compile_go(variant, work_dir, tc["go"]), None)
            elif ln == "rust":
                return (idx, b.name, ln, compile_rust(variant, work_dir, tc["rust"]), None)
            else:
                return (idx, b.name, ln, None, "unknown lang")
        except Exception as e:  # noqa: BLE001
            return (idx, b.name, ln, None, str(e))

    print()
    info(f"compilando en paralelo: {C.BOLD}{len(compile_tasks)}{C.RESET} targets"
         f" ({C.BOLD}{n_compile_jobs}{C.RESET} workers)")
    compiled_map: dict[tuple[str, str], Optional[tuple]] = {}
    compile_errors: dict[tuple[str, str], str] = {}

    import concurrent.futures as _futures
    compile_t0 = time.perf_counter()
    with Spinner("compilando todo", color=C.MAGENTA):
        with _futures.ThreadPoolExecutor(max_workers=n_compile_jobs) as pool:
            futures = [pool.submit(compile_one, t) for t in compile_tasks]
            for fut in _futures.as_completed(futures):
                idx, bname, ln, compiled, err = fut.result()
                compiled_map[(bname, ln)] = compiled
                if err is not None:
                    compile_errors[(bname, ln)] = err
    compile_elapsed = time.perf_counter() - compile_t0
    info(f"compile total: {C.BOLD}{compile_elapsed:.2f}s{C.RESET}")
    if compile_errors:
        for (bname, ln), err in compile_errors.items():
            apuntar_incidencia(f"{bname}/{ln}",
                               "fallo al compilar: %s" % err)

    # -------------------------------------------------------------------
    #   SUELO de cada lenguaje.  Se mide ANTES de los benches porque es
    #   lo que se va a descontar de cada medida: la tabla tiene que hablar del
    #   codigo, no de cuanto tarda el sistema operativo en levantar un proceso.
    # -------------------------------------------------------------------
    print()
    with Spinner("midiendo el suelo de cada lenguaje", color=C.DIM):
        suelo = medir_suelo(active_langs, work_dir, compilar_para,
                            runs=max(5, args.runs), timeout=args.timeout,
                            eje_interno=lambda ln: usa_eje_interno(ln,
                                                                   args.fair))
    print_suelo_table(suelo, active_langs, tc)

    # -------------------------------------------------------------------
    #   EJECUCIONES (secuencial; mediciones no contaminadas).
    # -------------------------------------------------------------------
    print()
    rows: list[dict] = []
    started_at = time.perf_counter()

    for idx, b in enumerate(benches, 1):
        row: dict = {"bench": b.name, "is_legacy": b.is_legacy}

        # --- 1. Preparar el plan de este bench --------------------------------
        plan: dict[str, dict] = {}
        for ln in active_langs:
            variant: Optional[BenchVariant] = None
            if ln in VX_LANGS:
                variant = b.variants.get("vx")
            else:
                variant = b.variants.get(ln)
            if variant is None:
                row[ln] = None
                continue

            compiled = compiled_map.get((b.name, ln))
            if compiled is None:
                # Para AOT, un compile fallido significa "bench no soportado
                # por el subset nativo" -> N/A (gris), no FAIL (rojo).  Asi
                # no entra en el geomean ni se confunde con un crash real.
                #
                # Para el resto, -2 significa NO COMPILA y -1 fallo al
                # EJECUTAR.  Antes las dos cosas eran -1 y salian como
                # "TIMEOUT", que hacia pasar un compilador roto por un lenguaje
                # lento -- y con el error mandado a /dev/null no habia forma de
                # saberlo.
                row[ln] = None if ln in VX_AOT_MODES else -2.0
                motivo = ERRORES_COMPILACION.get((b.name, ln))
                if motivo and ln not in VX_AOT_MODES:
                    apuntar_incidencia(f"{b.name}/{ln}",
                                       "no compila: %s" % motivo)
                continue
            cmd, cwd, factor = compiled

            # Env: forzar el threshold explicito por modo.  El DEFAULT del vm
            # ahora es JIT (threshold=1500), asi que vx_interp debe forzar
            # UINT32_MAX para medir interp puro (sin esto la columna interp
            # seria JIT-para-metodos-hot y la comparacion no tendria sentido).
            env = os.environ.copy()
            if ln == "vx_jit":
                env["VESTA_JIT_THRESHOLD"] = "1"
            elif ln == "vx_interp":
                env["VESTA_JIT_THRESHOLD"] = "4294967295"

            # Los no interpretados se miden mas veces (rapidos + ruidosos); los
            # interpretados pocas (lentos).  --runs / --runs-slow lo overridean.
            # ANTES de cronometrar: ¿esto ejecuta?  Una pasada con la salida
            # capturada.  Sin ella se cronometraban crashes y salian como
            # medidas -- 23 de 35 benchmarks bajo el JIT, todos a ~32 ms, que
            # es lo que tarda arrancar la VM antes de reventar.
            ok_ej, motivo_ej = verificar_ejecucion(cmd, env, cwd, args.timeout)
            if not ok_ej:
                row[ln] = MURIO
                _MUERTES.append((f"{b.name}/{ln}", 0, 0.0))
                apuntar_incidencia(f"{b.name}/{ln}", motivo_ej)
                continue
            plan[ln] = {
                "cmd": cmd, "cwd": cwd, "factor": factor, "env": env,
                "n": args.runs_slow if ln in INTERPRETED_LANGS else args.runs,
                # Sprint bench-fair (2026-06-03): por default mode FAIR usa
                # wall externo para TODOS los lenguajes (incluye fork +
                # runtime init).  Mode --unfair restaura el legacy (Vesta-lang
                # usa --stats interno, otros wall externo).
                "vx_wt": usa_eje_interno(ln, args.fair),
                "muestras": [],
            }

        # --- 2. Calentar EN RONDAS, el mismo regimen en el que se va a medir --
        #
        # Calentar cada lenguaje por separado y medir intercalando NO funciona,
        # y esta medido: entre dos ejecuciones de Java corren los otros diez y
        # le desalojan las paginas, asi que llegaba a la medicion tan frio como
        # al principio y sus muestras seguian cayendo (307 -> 86 ms dentro de
        # las rondas ya medidas).  El estado que se alcanza calentando solo vale
        # si se alcanza en las mismas condiciones en las que luego se mide.
        #
        # Por eso el calentamiento ejecuta el CICLO COMPLETO -- todos los
        # lenguajes, aunque alguno ya se haya asentado -- y se repite hasta que
        # ninguno sigue bajando.  Que un lenguaje asentado deje de correr
        # cambiaria la composicion del ciclo, y con ella el regimen que los
        # demas estan intentando alcanzar.
        orden = list(plan.keys())
        calentamientos: dict[str, int] = {ln: 0 for ln in orden}
        if args.warmup != 0 and orden:
            trazas: dict[str, list[float]] = {ln: [] for ln in orden}
            gastado_ms = 0.0
            with Spinner(f"[{idx}/{len(benches)}] {b.name} | calentando",
                         color=C.DIM) as sp:
                for ronda_w in range(CALENTAMIENTO_MAX):
                    giro = (orden[ronda_w % len(orden):]
                            + orden[:ronda_w % len(orden)])
                    for ln in giro:
                        p = plan[ln]
                        sp.etiqueta(f"[{idx}/{len(benches)}] {b.name} | "
                                    f"calentando ronda {ronda_w + 1} | "
                                    f"{tc[ln].label}", tc[ln].color)
                        ms = una_medida(p["cmd"], p["env"], args.timeout,
                                        p["cwd"], p["vx_wt"])
                        if ms >= 0:
                            trazas[ln].append(ms)
                            gastado_ms += ms
                    if all(serie_asentada(trazas[ln]) for ln in orden):
                        break
                    if gastado_ms >= CALENTAMIENTO_PRESUPUESTO_MS:
                        # En un bench que tarda segundos, la paginacion es
                        # ruido de fondo y seguir calentando son minutos
                        # tirados.
                        break
            for ln in orden:
                calentamientos[ln] = len(trazas[ln])

        # --- 3. Medir INTERCALANDO: una ejecucion de cada uno por ronda -------
        # Las diez muestras de un lenguaje ya no se toman seguidas en el
        # tiempo.  Antes, si la maquina se alteraba durante ese minuto -- un
        # antivirus, el turbo decayendo, otro proceso -- la alteracion caia
        # entera sobre el lenguaje que tocaba y se leia como que ESE lenguaje
        # era lento.  Repartidas, una perturbacion afecta a una muestra de cada
        # uno y la mediana se la come.
        #
        # El orden ROTA cada ronda para que ninguno sea siempre el primero (el
        # primero de una ronda paga el cambio de contexto de los demas).  Se
        # rota en vez de barajar para que la corrida siga siendo reproducible.
        max_rondas = max((p["n"] for p in plan.values()), default=0)
        # Los lenguajes lentos toman menos muestras (3 frente a 10).  Si las
        # gastaran en las tres primeras rondas, el ciclo se aligeraria a partir
        # de la cuarta y los rapidos pasarian a medirse en otro entorno a mitad
        # de camino -- el mismo error que arreglar el calentamiento, otra vez.
        # Sus muestras se reparten a lo largo de todas las rondas.
        for p in plan.values():
            n = max(1, p["n"])
            p["rondas"] = {round(i * (max_rondas - 1) / max(1, n - 1))
                           for i in range(n)} if n > 1 else {0}
        with Spinner(f"[{idx}/{len(benches)}] {b.name} | midiendo",
                     color=C.DIM) as sp:
            for ronda in range(max_rondas):
                giro = (orden[ronda % len(orden):] + orden[:ronda % len(orden)]
                        if orden else [])
                for ln in giro:
                    p = plan[ln]
                    if len(p["muestras"]) >= p["n"]:
                        continue  # este ya tiene todas las suyas
                    if ronda not in p["rondas"]:
                        continue  # no le toca en esta vuelta
                    sp.etiqueta(f"[{idx}/{len(benches)}] {b.name} | ronda "
                                f"{ronda + 1}/{max_rondas} | {tc[ln].label}",
                                tc[ln].color)
                    ms = una_medida(p["cmd"], p["env"], args.timeout,
                                    p["cwd"], p["vx_wt"])
                    if ms >= 0:
                        p["muestras"].append(ms)
                        # Una muestra cortada por el tope entra igual -- es lo
                        # que se sabe de ese caso -- pero deja constancia, para
                        # que luego no se use como si fuera un tiempo medido.
                        if _ULTIMA_CENSURADA:
                            p["censuradas"] = p.get("censuradas", 0) + 1
                    else:
                        # Se apunta el MOTIVO de quedarse sin muestras.  Sin
                        # esto, una fila sin muestras salia siempre como
                        # `TIMEOUT` -- daba igual lo que hubiera pasado -- y
                        # mandaba a buscar un problema de lentitud donde podia
                        # haber un crash, un binario que no arranca, o un
                        # lenguaje al que ni le toco el turno.
                        p["ultimo_fallo"] = ms
                        if ms == MURIO:
                            p["muerto"] = True

        for ln, p in plan.items():
            if not p["muestras"]:
                # Sin muestras.  El motivo se ARRASTRA desde el intento que
                # fallo en vez de asumir uno: con la censura activa un planton
                # de verdad ya no llega aqui -- se apunta como `>tope` y SI da
                # muestra --, asi que un `-1` a estas alturas significaba
                # "no lo se" y se publicaba como TIMEOUT, que es afirmar algo
                # que nadie comprobo.
                ultimo = p.get("ultimo_fallo")
                if ultimo in (MURIO, NO_ARRANCA):
                    row[ln] = ultimo
                elif ultimo is None:
                    # Ni un solo intento.  Leyendo el planificador esto NO
                    # deberia poder pasar -- `orden` es el plan entero y la
                    # ronda 0 siempre esta en `p["rondas"]` --, asi que si
                    # aparece es que el planificador hace algo que su codigo
                    # no dice.  Se marca aparte justamente para eso: para que
                    # se vea en vez de confundirse con un planton.
                    row[ln] = SIN_TURNO
                    _SIN_EXPLICACION.append((b.name, ln, "ni un intento"))
                else:
                    # Un negativo que no es ninguno de los conocidos.  Se
                    # publica el valor crudo en el resumen: inventarle una
                    # etiqueta es lo que hacia que todo saliera `TIMEOUT`.
                    row[ln] = -1.0
                    _SIN_EXPLICACION.append(
                        (b.name, ln, "valor %.1f sin estado conocido" % ultimo))
                row.setdefault("_runs", {})[ln] = []
                continue
            # Normalizar (Python memcpy_loop reduce iters).
            normalized = [t * p["factor"] for t in p["muestras"]]
            bruto = statistics.median(normalized)
            row.setdefault("_runs", {})[ln] = normalized
            row.setdefault("_bruto", {})[ln] = bruto
            # Cortada por el tope: lo que se publica es una COTA INFERIOR.  Se
            # marca antes de descontar el suelo, porque el neto de una cota
            # sigue siendo una cota y hay que decirlo igual.
            if p.get("censuradas"):
                row.setdefault("_censurado", {})[ln] = {
                    "muestras": len(normalized),
                    "cortadas": p["censuradas"],
                    "tope_ms": args.timeout * 1000.0,
                }
            # --- El SEGUNDO eje: el wall time INTERNO de la VM.
            #
            # El externo (la serie de arriba) es el que manda y no se toca: es
            # lo que tarda el codigo de verdad, arranque incluido, y es lo
            # comparable contra los demas lenguajes.  Pero con la VM tardando
            # ~32 ms en arrancar, ese arranque se come benchmarks enteros: once
            # medidas del JIT no se separaban de el.
            #
            # El interno se saca de UNA pasada aparte con `--stats`, no de la
            # serie: capturar la salida cuesta, y meterlo en las ejecuciones
            # cronometradas ensuciaria el numero que se publica.  Una basta
            # porque este numero no tiene el ruido del sistema operativo --
            # mismo criterio que la memoria, que tambien va en su propia
            # pasada y por lo mismo.
            if ln.startswith("vx_") and not p.get("vx_wt"):
                interno = run_timed_vx(p["cmd"], p["env"], args.timeout,
                                       p["cwd"])
                if interno >= 0 and not _ULTIMA_CENSURADA:
                    row.setdefault("_interno", {})[ln] = interno * p["factor"]
            # Lo que se publica es el tiempo del CoDIGO: al bruto se le quita el
            # suelo del lenguaje, que es lo que cuesta arrancar el proceso y no
            # dice nada de lo que el compilador genero.  Sin descontarlo,
            # `alloc/c` "tardaba" 2.2 ms de los cuales 2.3 eran el arranque: la
            # tabla comparaba sistemas operativos.
            s_piso = suelo.get(ln) or {}
            piso = s_piso.get("p50")
            if piso is None:
                row[ln] = bruto
                continue
            neto = bruto - piso
            # Un neto que no supera el ruido de las dos medidas que lo forman no
            # es un tiempo pequeno: es que este bench NO MIDE NADA por encima
            # del arranque en este lenguaje.  Publicarlo daria un numero
            # minusculo del que saldrian ratios absurdos (dividir por casi cero
            # convierte a cualquiera en infinitamente rapido).  Se retira del
            # cuadro y se dice aparte, con su nombre: la conclusion util es que
            # ese bench necesita mas trabajo por ejecucion, no que un lenguaje
            # sea magico.
            s_med = _stats_summary(normalized)
            margen = 3.0 * (s_med.get("mad", 0.0) + s_piso.get("mad", 0.0))
            row[ln] = neto
            if neto <= margen:
                # Se marca, NO se borra.  La medida existe y se ensena; lo que
                # no se puede es meterla en una razon (dividir por casi cero
                # convierte a cualquiera en infinitamente rapido) ni en una
                # media geometrica.  Queda fuera de los agregados, dentro de la
                # tabla, y con su motivo al pie.
                row.setdefault("_bajo_suelo", {})[ln] = {
                    "bruto": bruto, "suelo": piso, "neto": neto,
                    "margen": margen,
                }
        row["_calentamientos"] = calentamientos
        row["_suelo_descontado"] = bool(suelo)

        rows.append(row)

        # Imprimir fila parcial.
        # Cada columna usa ANCHO FIJO para que las etiquetas (vx_jit=, c=, ...)
        # queden alineadas verticalmente en todas las filas.  El padding se
        # aplica sobre el texto VISIBLE (sin contar los codigos de color ANSI),
        # por eso se construye primero la celda en crudo y se pad-ea con ljust
        # antes de envolverla en color.
        line = f"  [{idx:>3}/{len(benches)}] {C.BOLD}{b.name:<22}{C.RESET}"
        for ln in active_langs:
            v = row.get(ln)
            # Ancho fijo de la columna: etiqueta (p.ej. "vx_interp=") mas hasta
            # 6 digitos de ms y el sufijo "ms".  Caben N/A, FAIL y TIMEOUT.
            col_w = len(ln) + 1 + 6 + 2  # "<ln>=" + 6 digitos + "ms"
            # Los mismos cuatro estados que la tabla final, y por el mismo
            # motivo: son cosas distintas y mandan a mirar sitios distintos.
            # Esta linea se lee EN VIVO, asi que es la primera -- y a veces la
            # unica -- que alguien ve; que aqui dijera `NO COMPILA` de un
            # binario que compilo bien y luego reventó mandaba a revisar el
            # compilador en vez del programa.
            if v is None:
                text, color = "N/A", C.GREY
            elif v == SIN_TURNO:
                text, color = "SIN TURNO", C.GREY
            elif v == NO_ARRANCA:
                text, color = "NO ARRANCA", C.RED
            elif v == MURIO:
                text, color = "MURIO", C.RED
            elif v <= -2:
                text, color = "NO COMPILA", C.RED
            elif v < 0:
                text, color = "TIMEOUT", C.RED
            else:
                text, color = f"{ln}={v:.0f}ms", tc[ln].color
            # Pad-ear el texto visible a ancho fijo y luego aplicar color.
            line += f"  {color}{text.ljust(col_w)}{C.RESET}"
        print(line)

    elapsed = time.perf_counter() - started_at
    print()
    info(f"tiempo total bench suite: {C.BOLD}{elapsed:.1f} s{C.RESET}")

    # Tabla completa.
    print_results_table(rows, tc, active_langs)
    print_speedup_summary(rows, active_langs, baseline="c")

    # Sprint bench-categories: geomean slowdown vs C por categoria.
    if "c" in active_langs:
        print_category_summary(rows, active_langs, tc, baseline="c")

    print_calentamiento_table(rows, active_langs, tc)
    print_dos_ejes(rows, active_langs, tc, suelo)
    print_censurados_table(rows, tc)
    print_bajo_suelo_table(rows, active_langs, tc)

    if args.verbose_stats:
        print_verbose_stats_table(rows, active_langs, tc, suelo)
        print_samples_table(rows, active_langs, tc)
    # Siempre: cuanto ruido tiene cada medida y cada lenguaje.
    print_noise_ranking(rows, active_langs, tc)

    # Sprint bench-baseline (2026-06-02): comparacion vs JSON previo.
    if args.baseline:
        print_baseline_comparison(rows, active_langs, tc,
                                   args.baseline, args.threshold)

    # ASCII charts en consola para vista rapida.
    print_ascii_charts(rows, active_langs, tc)

    # JSON con runs individuales para post-analisis.
    json_path = (project_root / args.out_json
                 if not os.path.isabs(args.out_json) else Path(args.out_json))
    # Una corrida PARCIAL no puede pisar la referencia: el fichero por defecto
    # esta versionado con la tanda completa (todos los benches x todos los
    # lenguajes), y sobreescribirlo con un subconjunto se lleva por delante el
    # resto sin avisar -- y la siguiente comparacion se hace sobre menos casos
    # creyendo que estan todos.  Cuando se ha filtrado, el resultado va a un
    # fichero aparte salvo que se pida el destino a mano.
    parcial = bool(args.filter) or bool(args.langs)
    if parcial and args.out_json == parser.get_default("out_json"):
        json_path = json_path.with_name(json_path.stem + "_parcial" +
                                        json_path.suffix)
        print(f"[info] corrida parcial: los resultados van a "
              f"{json_path.name} para no pisar la referencia completa.  "
              f"Usa --out-json si quieres otro destino.")
    serializable_rows = []
    for r in rows:
        new_r = {k: v for k, v in r.items() if not k.startswith("_")}
        new_r["runs_individual"] = r.get("_runs", {})
        # Cuantas ejecuciones hizo falta descartar en cada uno.  Es parte de
        # como se obtuvo el numero: sin esto, dos corridas con criterios de
        # calentamiento distintos parecen comparables y no lo son.
        new_r["calentamientos"] = r.get("_calentamientos", {})
        # El BRUTO (con arranque) no se tira: es el dato medido, y el neto es
        # una derivada suya.  Quien quiera comparar contra una corrida anterior
        # -- o contra otra herramienta que no descuente nada -- lo necesita.
        new_r["bruto"] = r.get("_bruto", {})
        new_r["bajo_suelo"] = r.get("_bajo_suelo", {})
        # Las dos marcas que dicen que un numero NO se puede meter en una
        # razon.  Sin guardarlas, el JSON publica la cifra desnuda y quien lo
        # lea despues -- `compare_json`, las graficas, un re-render -- la usa
        # como si fuera una medida limpia: el aviso vivia solo en la consola de
        # aquella tanda.
        new_r["censurado"] = r.get("_censurado", {})
        # El SEGUNDO eje: el codigo sin el arranque de la VM.  Es la mitad del
        # trabajo de esta version; dejarlo fuera del JSON lo reduciria a una
        # tabla bonita que se pierde al cerrar el terminal.
        new_r["interno"] = r.get("_interno", {})
        # Sprint bench-categories: tag de categoria por bench.
        new_r["category"] = bench_category(r["bench"])
        # Sprint bench-stats: incluir summary por lang en el JSON para
        # que herramientas externas no tengan que reprocesar los runs.
        stats_per_lang = {}
        for ln, rs in r.get("_runs", {}).items():
            if rs:
                stats_per_lang[ln] = _stats_summary(rs)
        new_r["stats"] = stats_per_lang
        serializable_rows.append(new_r)
    json_data = {
        "vm_binary": str(vm),
        "project_root": str(project_root),
        "runs_per_mode": args.runs,       # no interpretados
        "runs_per_mode_slow": args.runs_slow,  # interpretados (python, vx_interp)
        # El calentamiento ya no es un numero fijo: se decide midiendo, y el
        # que se aplico a cada par (bench, lenguaje) va en su propia fila.
        # Aqui solo consta si estaba activo.
        "warmup_adaptativo": args.warmup != 0,
        "medicion": "rondas intercaladas",
        "active_langs": active_langs,
        "elapsed_total_s": elapsed,
        "system_info": sys_info,
        # El suelo de cada lenguaje en ESTA maquina y ESTA corrida.  Va en el
        # JSON porque sin el los tiempos de otra maquina no son comparables:
        # una diferencia de 2 ms entre dos equipos puede ser solo su arranque.
        "suelo": suelo,
        "results": serializable_rows,
    }
    try:
        json_path.write_text(json.dumps(json_data, indent=2))
        print()
        ok(f"JSON: {C.BOLD}{json_path}{C.RESET}")
    except Exception as e:
        warn(f"no pude escribir JSON: {e}")

    # Matplotlib: generar TODAS las graficas en un directorio.
    # Con una corrida parcial las graficas van aparte por lo mismo que el JSON:
    # `bench_plots/` esta versionado con la tanda completa y unas graficas de
    # tres benches no la representan.
    if not args.no_plot:
        plot_dir = project_root / ("bench_plots_parcial" if parcial
                                   else "bench_plots")
        try:
            from . import plots  # cuando se invoca como modulo
        except (ImportError, ValueError):
            # Fallback: import directo cuando se corre como script.
            sys.path.insert(0, str(Path(__file__).parent))
            import plots  # type: ignore
        try:
            results = plots.generate_all(rows, active_langs, plot_dir,
                                          sys_info=sys_info, suelo=suelo)
            print()
            info(f"{C.BOLD}Graficas generadas en {plot_dir}/:{C.RESET}")
            for name, success in results.items():
                marker = (f"{C.GREEN}OK{C.RESET}" if success
                          else f"{C.RED}FAIL{C.RESET}")
                print(f"  {marker}  {name}")
        except Exception as e:
            warn(f"error generando plots: {e}")

    # Sprint bench-html: reporte HTML autocontenido con todo el contexto.
    if not args.no_html and not args.no_plot:
        plot_dir = project_root / ("bench_plots_parcial" if parcial
                                   else "bench_plots")
        try:
            html_path = generate_html_report(
                rows, active_langs, tc, sys_info, plot_dir,
                json_path, args.baseline, args.threshold)
            print()
            ok(f"HTML: {C.BOLD}{html_path}{C.RESET}")
        except Exception as e:  # noqa: BLE001
            warn(f"HTML error: {e}")

    # Al final y no por el camino: durante la tanda hay barras de progreso y
    # una linea por bench, y un aviso ahi dentro se pierde entre las medidas.
    resumen_incidencias()
    resumen_permisos()
    resumen_muertes()
    resumen_sin_explicacion()
    return 0


if __name__ == "__main__":
    sys.exit(main())
