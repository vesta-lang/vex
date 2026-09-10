#!/usr/bin/env python3
"""jit_coverage.py -- mide la cobertura del path JIT-vreg y los gaps.

Sprint JIT-hardening (Fase 2).  Corre cada .vx del corpus en modo jit
(threshold=1) con los flags de debug del vreg, y agrega:
  - cuantos metodos compilan por VREG (path por defecto, limpio).
  - cuantos CAEN al selector (slots) y por QUE op del IR.

Reporta cobertura % + histograma de ops-gap ordenado por frecuencia, para
priorizar que op portar al vreg primero (cada una elimina dependencia del
selector buggy y mete mas codigo en el path limpio).

Uso:
  python tools/jit_coverage.py [vm.exe] [--filter X] [--timeout S] [--no-benchmarks]
"""
from __future__ import annotations
import argparse, os, re, subprocess, sys, time
from pathlib import Path
from collections import Counter

VREG_OK_RE  = re.compile(r"\[jit-vreg\] (?:eager )?compilado")
VREG_SEL_RE = re.compile(r"\[vreg-sel\] '([^']+)' no soportada: op (\w+)")

def find_vm(arg, root):
    if arg and Path(arg).is_file(): return Path(arg)
    for c in ("cmake-build-release/vm.exe", "build/vm.exe", "vm.exe"):
        if (root / c).is_file(): return root / c
    return None

def discover(root, want_bench):
    items = [(p.stem, p) for p in sorted((root/"examples_codes_vx").glob("*.vx"))]
    if want_bench:
        for d in sorted((root/"examples_codes_vx"/"benchmark").iterdir()):
            if (d/"main.vx").is_file(): items.append((d.name, d/"main.vx"))
    return items

def main():
    root = Path(__file__).resolve().parents[1]
    ap = argparse.ArgumentParser()
    ap.add_argument("vm_path", nargs="?")
    ap.add_argument("--filter", default="")
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--no-benchmarks", action="store_true")
    args = ap.parse_args()
    vm = find_vm(args.vm_path, root)
    if not vm: print("[error] no vm.exe"); return 1
    # El mismo cajon de transitorios que usa `diff_harness.py`, dentro de la
    # cache.  @see include/util/cache_paths.h
    tmp = root/".cache"/"tmp"/"diff_harness"; tmp.mkdir(parents=True, exist_ok=True)
    corpus = discover(root, not args.no_benchmarks)
    if args.filter: corpus = [(n,p) for (n,p) in corpus if args.filter in n]
    print(f"[info] vm: {vm}\n[info] corpus: {len(corpus)} programas\n")

    vreg_ok = 0           # metodos compilados por vreg
    sel_fallback = 0      # metodos caidos al selector
    op_hist = Counter()   # op -> cuantos metodos tumba
    per_op_methods = {}   # op -> set(method) (para no contar duplicados)
    env = dict(os.environ)
    env.update(VESTA_JIT_THRESHOLD="1", VESTA_JIT_WARN_UNSUPPORTED="1",
               VESTA_JIT_VREGS_DEBUG="1", NO_COLOR="1")
    t0 = time.time()
    for i,(name,path) in enumerate(corpus,1):
        sys.stdout.write(f"\r[{i}/{len(corpus)}] {name[:38]:38s}"); sys.stdout.flush()
        velb = tmp/(name+".velb")
        if not velb.is_file():
            cr = subprocess.run([str(vm),"--vx",str(path),"-o",str(tmp/name)],
                                capture_output=True, text=True, timeout=120, check=False)
            if cr.returncode!=0 or not velb.is_file(): continue
        try:
            r = subprocess.run([str(vm),"--run",str(velb),"-m","jit","--schedulers","1"],
                               capture_output=True, text=True, timeout=args.timeout,
                               env=env, cwd=str(tmp), check=False)
        except subprocess.TimeoutExpired:
            r = None
        out = ((r.stdout or "")+(r.stderr or "")) if r else ""
        vreg_ok += len(VREG_OK_RE.findall(out))
        for m in VREG_SEL_RE.finditer(out):
            meth, op = m.group(1), m.group(2)
            sel_fallback += 1
            op_hist[op] += 1
            per_op_methods.setdefault(op, set()).add(f"{name}:{meth}")
    sys.stdout.write("\r"+" "*55+"\r")

    total = vreg_ok + sel_fallback
    cov = 100.0*vreg_ok/total if total else 0.0
    print(f"=== cobertura JIT-vreg ({time.time()-t0:.0f}s) ===")
    print(f"  metodos compilados por VREG : {vreg_ok}")
    print(f"  metodos caidos al SELECTOR  : {sel_fallback}")
    print(f"  COBERTURA VREG              : {cov:.1f}%  ({vreg_ok}/{total})")
    print(f"\n=== gaps: ops que tumban el vreg (por frecuencia) ===")
    for op,n in op_hist.most_common():
        print(f"  {op:16s} {n:4d} metodos")
    return 0

if __name__ == "__main__":
    sys.exit(main())
