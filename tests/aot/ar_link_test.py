#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
 AOT.5 -- validacion del "pull" perezoso de archivos estaticos .a por el
linker propio (vm --link), sin ld/gcc para el enlace final.

Escenario (PE, corre nativo en Windows):
  1. kern.vx declara `extern "rt" { fn rt_value() -> i64; }` y main() lo llama.
  2. rt.c (compilado con gcc -c -> COFF .obj) define rt_value().
  3. Se archiva rt.obj en una libreria estatica librt.a (con 'ar rcs').
  4. `vm --link kern.obj librt.a -o prog.exe` debe EXTRAER rt.obj del .a
     (resolviendo rt_value) y producir un .exe que retorna 42.

Valida el parser AR + el pull perezoso aislados (rt.obj es autocontenido, no
necesita libc -> no depende del Increment 2 de imports).

Uso:  python tests/aot/ar_link_test.py <build_dir>
"""
import os
import subprocess
import sys
import tempfile

# LADO: windows  (prueba el objetivo PE con herramientas de Windows)
#
# El gcc/ar se BUSCAN.  Aqui habia la ruta de una maquina concreta, y en
# cualquier otro equipo eso no era un fallo del compilador sino un fichero
# que no esta -- pero salia como si Vesta estuviera rota.
from aot_harness import AotTest
GCC = AotTest.buscar_gcc_windows()
AR = (os.path.join(os.path.dirname(GCC), "ar.exe")
      if GCC else None)


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def main():
    if len(sys.argv) < 2:
        print("uso: ar_link_test.py <build_dir>")
        return 2
    build = os.path.abspath(sys.argv[1])
    vm = os.path.join(build, "vm.exe")
    if not os.path.exists(vm):
        vm = os.path.join(build, "vm")
    if not os.path.exists(vm):
        print(f"no se encuentra vm en {build}")
        return 2

    if not GCC or not os.path.isfile(GCC):
        print("SALTADO: no hay gcc del lado de Windows (este test prueba "
              "el objetivo PE con herramientas de Windows)")
        return 77

    work = tempfile.mkdtemp(prefix="ar_link_")
    rc = 0

    kern = os.path.join(work, "kern.vx")
    with open(kern, "w") as f:
        f.write('extern "rt" { fn rt_value() -> i64; }\n'
                'i64 main() { return rt_value() + 2; }\n')

    rtc = os.path.join(work, "rt.c")
    with open(rtc, "w") as f:
        f.write("long long rt_value(void) { return 40; }\n")

    kern_obj = os.path.join(work, "kern.obj")
    rt_obj = os.path.join(work, "rt.obj")
    lib_a = os.path.join(work, "librt.a")
    prog = os.path.join(work, "prog.exe")

    # 1. kern.vx -> kern.obj (COFF PE)
    r = run([vm, "--vx", kern, "-m", "aot", "--emit", "obj",
             "--format", "pe", "-o", kern_obj])
    if not os.path.exists(kern_obj):
        print("FALLO: no se genero kern.obj")
        print(r.stdout, r.stderr)
        return 1

    # 2. rt.c -> rt.obj (COFF) via gcc
    r = run([GCC, "-c", "-fno-pic", rtc, "-o", rt_obj])
    if not os.path.exists(rt_obj):
        print("FALLO: gcc no genero rt.obj")
        print(r.stdout, r.stderr)
        return 1

    # 3. archivar rt.obj en librt.a
    r = run([AR, "rcs", lib_a, rt_obj])
    if not os.path.exists(lib_a):
        print("FALLO: ar no genero librt.a")
        print(r.stdout, r.stderr)
        return 1

    # 4. vm --link kern.obj librt.a -> prog.exe (pull de rt.obj del .a)
    r = run([vm, "--link", kern_obj, lib_a, "-o", prog, "--format", "pe"])
    if not os.path.exists(prog):
        print("FALLO: el linker no genero prog.exe (pull del .a fallido?)")
        print("stdout:", r.stdout)
        print("stderr:", r.stderr)
        return 1

    # 5. ejecutar -> debe retornar 42
    r = run([prog])
    if r.returncode == 42:
        print("AR-LINK PE (pull de .a): exit=42 OK")
    else:
        print(f"AR-LINK PE: EXIT MISMATCH got={r.returncode} exp=42")
        rc = 1

    # Negativo: sin el .a, el simbolo rt_value debe quedar sin resolver.
    prog2 = os.path.join(work, "prog_noa.exe")
    r = run([vm, "--link", kern_obj, "-o", prog2, "--format", "pe"])
    if os.path.exists(prog2):
        print("AR-LINK negativo: ADVERTENCIA, enlazo sin el .a (rt_value deberia "
              "faltar)")
    else:
        print("AR-LINK negativo (sin .a -> simbolo no resuelto): OK")

    return rc


if __name__ == "__main__":
    sys.exit(main())
