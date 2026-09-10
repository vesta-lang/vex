#!/usr/bin/env python3
"""diff_harness.py -- red de seguridad diferencial interp vs JIT para VestaVM.

Sprint JIT-hardening (Fase 0).  Corre cada @c .vx del corpus en los 3 modos
de ejecucion y clasifica cada programa comparando contra el INTERPRETE como
oraculo.  Convierte bugs latentes del JIT (corrupcion silenciosa, divergencia
interp!=jit, crashes) en un backlog conocido ANTES de tocar el codegen.

Modos de ejecucion:
  - interp     : -m vm  (VESTA_JIT_THRESHOLD=UINT32_MAX), 100% interprete (oraculo).
  - jit-vreg   : -m jit (threshold=1), path por defecto (regalloc vreg).
  - jit-slots  : VESTA_JIT_VREGS=0 -m jit, path selector (slots).

Clasificacion por programa (el interp es el oraculo de correccion):
  OK         los 3 modos exit 0 y mismo R0.
  DIVERGE    interp da R0 pero algun JIT da R0 distinto  -> BUG del JIT.
  CRASH      interp da R0 (exit 0) pero algun JIT exit != 0 -> BUG del JIT.
  TIMEOUT    algun modo excede el timeout.
  NOCOMPILA  el .velb no se genero (puede ser test negativo esperado).
  NORUN      ningun modo produce R0 (no-ejecutable: modulo sin main, falta input...).
  NODET      en lista de no-deterministas conocidos (se reporta aparte, no es bug).

Salida: tabla clasificada en consola + diff_baseline.json con el detalle.

Uso:
  python tools/diff_harness.py [vm.exe] [--filter X] [--timeout S]
                               [--no-benchmarks] [--out diff_baseline.json]
"""
from __future__ import annotations
import argparse
import concurrent.futures as cf
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

R00_RE = re.compile(r"R00=0x([0-9a-fA-F]+)")

# Programas con R0 legitimamente no-determinista (punteros host, timestamps,
# direcciones GC) -> interp!=jit es esperado, NO un bug.  Se reportan aparte.
NODET = {
    "bug3_struct",            # puntero host en R0
    "160_macro_walk_pchase",  # macro: ERR en interp por diseno
    # 282: lee el PEB REAL de Windows via inline asm `mov rax, gs:[0x60]`.
    # El JIT/default(threshold 1500)/AOT lo compilan a nativo -> PEB real (42).
    # El oraculo interp PURO (-m vm, sin JIT) usa el trampolin vrt:inline_asm_exec
    # y, con el get_peb INLINEADO en main dentro de este programa overlay-heavy,
    # devuelve 0 -> "sin PEB" -> 1.  No es un bug del codegen JIT (el JIT acierta);
    # es una limitacion del trampolin interp para asm inlineado con segmento gs:.
    "282_overlay_peb",
    # asm_stack_manip: el asm hace `mov rcx, rsp` y retorna (sp>0x1000)?42:0.
    # El JIT/default/AOT lo compilan a nativo -> rsp real del host (>0x1000) -> 42.
    # El oraculo interp PURO usa el trampolin vrt:inline_asm_exec y el rsp que
    # lee no se propaga de vuelta al register("rcx") de salida -> sp=0 -> 0.  El
    # codegen JIT acierta; es la misma limitacion del trampolin interp que 282
    # (asm que inspecciona estado real de pila/segmento).  Ortogonal a coalescing.
    "asm_stack_manip",
}

# Programas que necesitan setup externo (loadmodule de un .velb concreto,
# argv, stdin) y no corren standalone en este harness.  No son bugs del JIT.
SKIP = {
    "49_loadmodule_caller",   # requiere _test_plugin.velb en el FS
}


class C:
    _on = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    R = "\033[0m" if _on else ""
    BOLD = "\033[1m" if _on else ""
    RED = "\033[31m" if _on else ""
    GRN = "\033[32m" if _on else ""
    YEL = "\033[33m" if _on else ""
    CYN = "\033[36m" if _on else ""
    DIM = "\033[2m" if _on else ""


def find_vm(arg: str | None, root: Path) -> Path | None:
    if arg and Path(arg).is_file():
        return Path(arg)
    for c in ("cmake-build-release/vm.exe", "cmake-build-release/vm",
              "build/vm.exe", "build/vm", "vm.exe", "vm"):
        p = root / c
        if p.is_file():
            return p
    return None


def discover(root: Path, want_bench: bool):
    """Devuelve [(name, path)] del corpus."""
    items = []
    for p in sorted((root / "examples_codes_vx").glob("*.vx")):
        items.append((p.stem, p))
    if want_bench:
        for d in sorted((root / "examples_codes_vx" / "benchmark").iterdir()):
            mv = d / "main.vx"
            if mv.is_file():
                items.append((d.name, mv))
    return items


def run_mode(vm: Path, velb: Path, mode: str, timeout: float, tmp: Path):
    """Corre el .velb en un modo.  Devuelve (status, r0) donde status es
    'ok'|'crash'|'timeout'|'norun' y r0 es la cadena hex (o None)."""
    env = dict(os.environ)
    cmd = [str(vm), "--run", str(velb), "--stats", "--schedulers", "1"]
    if mode == "interp":
        cmd += ["-m", "vm"]
    elif mode == "jit-vreg":
        cmd += ["-m", "jit"]
    elif mode == "jit-slots":
        cmd += ["-m", "jit"]
        env["VESTA_JIT_VREGS"] = "0"
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, env=env, cwd=str(tmp), check=False)
    except subprocess.TimeoutExpired:
        return "timeout", None
    out = (r.stdout or "") + (r.stderr or "")
    m = R00_RE.search(out)
    r0 = m.group(1).lstrip("0") or "0" if m else None
    if r.returncode != 0:
        # exit != 0: crash si ademas no hay R0 limpio; igual lo marcamos crash.
        return "crash", r0
    if r0 is None:
        return "norun", None
    return "ok", r0


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("vm_path", nargs="?")
    ap.add_argument("--filter", default="")
    ap.add_argument("--timeout", type=float, default=60.0)
    ap.add_argument("--no-benchmarks", action="store_true")
    ap.add_argument("--out", default="diff_baseline.json")
    ap.add_argument("--jobs", "-j", type=int, default=0,
                    help="programas en paralelo (0 = auto = cpu_count)")
    args = ap.parse_args()

    vm = find_vm(args.vm_path, root)
    if not vm:
        print(f"{C.RED}[error]{C.R} no se encontro vm.exe (pasa la ruta)")
        return 1
    print(f"{C.CYN}[info]{C.R} vm: {vm}")

    # En el cajon de transitorios de la cache, no en un `tmp/` colgando de la
    # raiz del repositorio.  @see include/util/cache_paths.h
    tmp = root / ".cache" / "tmp" / "diff_harness"
    tmp.mkdir(parents=True, exist_ok=True)

    corpus = discover(root, not args.no_benchmarks)
    if args.filter:
        corpus = [(n, p) for (n, p) in corpus if args.filter in n]
    print(f"{C.CYN}[info]{C.R} corpus: {len(corpus)} programas, 3 modos, "
          f"timeout {args.timeout:.0f}s\n")

    cats = {k: [] for k in
            ("OK", "XFAIL", "VREG_HANG", "DIVERGE", "CRASH", "XPASS", "SLOTS_BUG",
             "NO_ORACLE", "NOCOMPILA", "NODET", "SKIP")}
    detail = []
    t0 = time.time()

    # Procesa UN programa (compile + 3 modos + clasificacion).  Independiente
    # por programa (velb unico), asi que es paralelizable con hilos: los
    # subprocess sueltan el GIL.  Devuelve un `rec` con su `cat`.
    def process_one(name: str, path: Path) -> dict:
        if name in SKIP:
            return {"name": name, "cat": "SKIP"}
        # Tests negativos (compile-must-fail): marcados con `@expect-compile-fail`.
        # NO deben producir .velb -- el fallo de compilacion es el resultado
        # ESPERADO (XFAIL, verde).  Si compilan (producen .velb) es una regresion
        # del checker (XPASS, bug).  Sin el marcador, un fallo de compilacion sigue
        # siendo NOCOMPILA (problema real a investigar).
        try:
            src = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            src = ""
        expect_fail = "@expect-compile-fail" in src
        velb = tmp / (name + ".velb")
        try:
            cr = subprocess.run([str(vm), "--vx", str(path), "-o", str(tmp / name)],
                                capture_output=True, text=True, timeout=120, check=False)
        except subprocess.TimeoutExpired:
            return {"name": name, "cat": "NOCOMPILA", "note": "compile timeout"}
        if cr.returncode != 0 or not velb.is_file():
            if expect_fail:
                return {"name": name, "cat": "XFAIL"}  # fallo de compilacion esperado
            return {"name": name, "cat": "NOCOMPILA"}
        if expect_fail:
            # El negativo COMPILO -> el checker dejo de atrapar el error.
            return {"name": name, "cat": "XPASS",
                    "note": "negativo marcado @expect-compile-fail pero compilo"}

        res = {}
        for mode in ("interp", "jit-vreg", "jit-slots"):
            res[mode] = run_mode(vm, velb, mode, args.timeout, tmp)
        st = {m: res[m][0] for m in res}
        r0 = {m: res[m][1] for m in res}
        rec = {"name": name, "interp": res["interp"], "jit-vreg": res["jit-vreg"],
               "jit-slots": res["jit-slots"]}

        # Clasificar (interp = oraculo).  interp!=ok -> sin oraculo; vreg
        # timeout/crash/diverge = BUG de produccion; slots = legacy.
        if st["interp"] != "ok":
            cat = "NO_ORACLE"
        elif st["jit-vreg"] == "timeout":
            cat = "VREG_HANG"
        elif st["jit-vreg"] == "crash":
            cat = "CRASH"
        elif r0["jit-vreg"] != r0["interp"]:
            cat = "DIVERGE"
        elif st["jit-slots"] in ("timeout", "crash") or \
                r0["jit-slots"] != r0["interp"]:
            cat = "SLOTS_BUG"
        else:
            cat = "OK"
        if name in NODET and cat in ("DIVERGE", "CRASH", "VREG_HANG"):
            cat = "NODET"
        rec["cat"] = cat
        return rec

    njobs = args.jobs if args.jobs > 0 else (os.cpu_count() or 4)
    njobs = max(1, njobs)
    print(f"{C.CYN}[info]{C.R} paralelismo: {njobs} jobs")
    done = 0
    total = len(corpus)
    if njobs == 1:
        recs = [process_one(n, p) for (n, p) in corpus]
    else:
        recs = [None] * total
        with cf.ThreadPoolExecutor(max_workers=njobs) as ex:
            futs = {ex.submit(process_one, n, p): i
                    for i, (n, p) in enumerate(corpus)}
            for fut in cf.as_completed(futs):
                i = futs[fut]
                recs[i] = fut.result()
                done += 1
                sys.stdout.write(f"\r{C.DIM}[{done}/{total}]{C.R}   ")
                sys.stdout.flush()

    # Agregar resultados en orden de corpus.
    for rec in recs:
        cat = rec["cat"]
        cats[cat].append(rec["name"])
        if cat not in ("OK", "SKIP"):
            detail.append(rec)

    sys.stdout.write("\r" + " " * 60 + "\r")
    elapsed = time.time() - t0

    # Resumen.
    print(f"{C.BOLD}=== diff_harness: baseline ({elapsed:.0f}s) ==={C.R}")
    order = [("OK", C.GRN), ("XFAIL", C.GRN), ("VREG_HANG", C.RED),
             ("DIVERGE", C.RED), ("CRASH", C.RED), ("XPASS", C.RED),
             ("SLOTS_BUG", C.YEL), ("NO_ORACLE", C.DIM),
             ("NOCOMPILA", C.DIM), ("NODET", C.DIM), ("SKIP", C.DIM)]
    for k, col in order:
        print(f"  {col}{k:10s}{C.R} {len(cats[k]):3d}")

    # Los bugs reales del path de PRODUCCION (vreg): VREG_HANG + DIVERGE + CRASH.
    # SLOTS_BUG es la ruta legacy en jubilacion (backlog conocido) -> no falla.
    bug_cats = ("VREG_HANG", "DIVERGE", "CRASH")
    bugs = sum((cats[c] for c in bug_cats), [])
    if bugs:
        print(f"\n{C.RED}{C.BOLD}BUGS DEL JIT (path vreg de produccion):{C.R}")
        for rec in detail:
            if rec["cat"] in bug_cats:
                iv = rec.get("interp"); vg = rec.get("jit-vreg"); sl = rec.get("jit-slots")
                print(f"  {C.RED}{rec['cat']:9s}{C.R} {rec['name']:32s} "
                      f"interp={iv} vreg={vg} slots={sl}")
    else:
        print(f"\n{C.GRN}{C.BOLD}Sin bugs del path vreg (VREG_HANG/DIVERGE/CRASH).{C.R}")
    if cats["SLOTS_BUG"]:
        print(f"{C.YEL}[nota]{C.R} SLOTS_BUG (legacy en jubilacion): "
              f"{', '.join(cats['SLOTS_BUG'])}")
    if cats["XPASS"]:
        # Regresion del CHECKER: un test negativo (@expect-compile-fail) compilo.
        print(f"\n{C.RED}{C.BOLD}XPASS (regresion del checker -- negativos que "
              f"YA NO fallan):{C.R}")
        for n in cats["XPASS"]:
            print(f"  {C.RED}XPASS{C.R} {n}")
    if cats["XFAIL"]:
        print(f"{C.GRN}[ok]{C.R} XFAIL ({len(cats['XFAIL'])} negativos que fallan "
              f"la compilacion como se espera).")

    out = root / args.out
    out.write_text(json.dumps({"vm": str(vm), "elapsed_s": elapsed,
        "summary": {k: len(v) for k, v in cats.items()},
        "categories": cats, "detail": detail}, indent=2), encoding="utf-8")
    print(f"\n{C.CYN}[ok]{C.R} baseline: {out}")
    # Exit code = bugs del path de produccion + XPASS (negativos que regresaron)
    # -> usable como gate de CI / bisect.  Antes SIEMPRE retornaba 0.
    return 1 if (bugs or cats["XPASS"]) else 0


if __name__ == "__main__":
    sys.exit(main())
