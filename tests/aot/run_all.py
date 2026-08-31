#!/usr/bin/env python3
"""Corre TODOS los tests de `tests/aot/` y resume.

Por que existe
--------------
Sin esto habia 29 guiones que solo se lanzaban a mano, uno a uno, con la ruta
del build detras.  El resultado previsible: **nadie sabia como estaban**.  Al
correrlos por primera vez en tanda, 15 de 26 fallaban -- y entre ellos habia
fallos REALES del producto que llevaban meses ahi (el enlazador escribia un
ejecutable sin permiso de ejecucion; el guion de enlazado no compilaba; mutar
una cadena larga mataba el proceso).

Los dos LADOS
-------------
No todos se lanzan igual, y no es un descuido: unos prueban el objetivo PE con
herramientas de Windows, otros el ELF con las de Linux, y un par prueban los
dos y llaman a `wsl` para la mitad de alla.  Cada test declara su lado con un
comentario `# LADO: windows` en su cabecera; sin el, se asume Linux/WSL, que es
la mayoria.

Este lanzador NO cruza de lado: corre los que tocan donde esta y SALTA los
otros diciendolo.  Saltar no es aprobar -- se cuentan aparte -- porque un rojo
permanente que se aprende a ignorar se lleva por delante a los rojos de verdad.

Uso
---
    # desde WSL (los de ELF)
    wsl python3 tests/aot/run_all.py /root/.cache/vesta/linux-build

    # desde Windows (los de PE, y los de dos lados)
    python tests/aot/run_all.py cmake-build-release

Salida 0 si ninguno FALLA (los saltados no cuentan).
"""
import os
import re
import subprocess
import sys

AQUI = os.path.dirname(os.path.abspath(__file__))
# 77 = "no aplica aqui", el convenio de saltar que usan automake y otros.
RC_SALTADO = 77


def lado_de(ruta):
    """El lado que el test declara en su cabecera.  Por defecto, Linux/WSL."""
    with open(ruta, encoding="utf-8", errors="replace") as fh:
        cab = fh.read(4096)
    m = re.search(r"^#\s*LADO:\s*(\w+)", cab, re.M)
    return (m.group(1).lower() if m else "wsl")


def lado_actual():
    return "windows" if os.name == "nt" else "wsl"


# Lo que hace que una linea sea LA del fallo.  Sin esto se cogia la ultima
# linea util, y como estos tests van imprimiendo cada paso, el resumen acababa
# dando como motivo del fallo una linea que decia "OK" -- que es peor que no
# decir nada, porque manda a mirar donde no es.
_SENAL_FALLO = re.compile(
    r"FALLO|FALLA|FAIL|ERROR|error:|MISMATCH|Traceback|no se genero|"
    r"no compila|Exception|assert", re.I)


def motivo_del_fallo(p):
    """La linea que explica POR QUE fallo, no la ultima que se imprimio."""
    lineas = [l.strip() for l in
              ((p.stdout or "") + "\n" + (p.stderr or "")).splitlines()
              if l.strip()]
    for l in reversed(lineas):
        # Una linea que ademas dice OK no es la del fallo, por mucho que
        # contenga la palabra: `VALGRIND 53 OK (0 leaks, 0 errores...)` trae
        # "errores" y es justo el paso que SI paso.
        if _SENAL_FALLO.search(l) and not re.search(r"\bOK\b", l):
            return l if len(l) <= 200 else l[:197] + "..."
    return lineas[-1] if lineas else "rc=%d sin salida" % p.returncode


def main():
    if len(sys.argv) < 2:
        print("uso: run_all.py <build_dir> [-k patron]")
        return 2
    build = sys.argv[1]
    filtro = None
    if "-k" in sys.argv:
        i = sys.argv.index("-k")
        if i + 1 < len(sys.argv):
            filtro = sys.argv[i + 1]

    aqui = lado_actual()
    tests = sorted(f for f in os.listdir(AQUI) if f.endswith("_test.py"))
    if filtro:
        tests = [f for f in tests if filtro in f]

    ok, fallidos, saltados = [], [], []
    for f in tests:
        ruta = os.path.join(AQUI, f)
        nombre = f[:-3]
        if lado_de(ruta) != aqui:
            saltados.append((nombre, "es del lado '%s' y estamos en '%s'"
                             % (lado_de(ruta), aqui)))
            continue
        try:
            p = subprocess.run([sys.executable, ruta, build], timeout=600,
                               capture_output=True, text=True,
                               errors="replace")
        except subprocess.TimeoutExpired:
            fallidos.append((nombre, "TIMEOUT (600 s)"))
            continue
        if p.returncode == RC_SALTADO:
            motivo = ""
            for ln in (p.stdout or "").splitlines():
                if ln.startswith("SALTADO"):
                    motivo = ln.split(":", 1)[-1].strip()
                    break
            saltados.append((nombre, motivo or "el propio test lo dice"))
        elif p.returncode == 0:
            ok.append(nombre)
        else:
            fallidos.append((nombre, motivo_del_fallo(p)))

    print("=== tests/aot en '%s': %d OK, %d fallidos, %d saltados"
          % (aqui, len(ok), len(fallidos), len(saltados)))
    for n, m in fallidos:
        print("  FALLA   %-32s %s" % (n, m))
    for n, m in saltados:
        print("  salta   %-32s %s" % (n, m))
    return 1 if fallidos else 0


if __name__ == "__main__":
    sys.exit(main())
