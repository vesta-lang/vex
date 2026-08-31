#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
 AOT.5 -- archivador propio (vm --ar) + enlace contra nuestras propias
librerias (.a creadas por nosotros y .dll emitidas por nosotros), sin ar/ld/gcc
para crear/usar la libreria.

Dos escenarios (PE, nativo Windows):
  A) NUESTRA .a:  vm --ar libfoo.a foo.obj  -> luego vm --link main.obj libfoo.a
     -> .exe que llama a foo (pull perezoso del miembro).
  B) NUESTRA .dll: vm --emit shared -> libbar.dll  -> luego
     vm --link main.obj libbar.dll -> .exe que importa de bar.dll por IAT.

Uso:  python tests/aot/ar_create_dll_test.py <build_dir>
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


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def main():
    if len(sys.argv) < 2:
        print("uso: ar_create_dll_test.py <build_dir>")
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

    work = tempfile.mkdtemp(prefix="ar_dll_")
    rc = 0

    # --- A) nuestra .a -----------------------------------------------------
    with open(os.path.join(work, "foo.c"), "w") as f:
        f.write("long long foo_value(void) { return 40; }\n")
    foo_obj = os.path.join(work, "foo.obj")
    run([GCC, "-c", os.path.join(work, "foo.c"), "-o", foo_obj])
    lib_a = os.path.join(work, "libfoo.a")
    # crear la .a con NUESTRO archivador
    r = run([vm, "--ar", lib_a, foo_obj])
    if not os.path.exists(lib_a):
        print("FALLO: vm --ar no creo libfoo.a")
        print(r.stdout, r.stderr)
        return 1
    with open(os.path.join(work, "mainA.vx"), "w") as f:
        f.write('extern "foo" { fn foo_value() -> i64; }\n'
                'i64 main() { return foo_value() + 2; }\n')
    mainA_obj = os.path.join(work, "mainA.obj")
    run([vm, "--vx", os.path.join(work, "mainA.vx"), "-m", "aot",
         "--emit", "obj", "--format", "pe", "-o", mainA_obj])
    progA = os.path.join(work, "progA.exe")
    run([vm, "--link", mainA_obj, lib_a, "-o", progA, "--format", "pe"])
    if os.path.exists(progA) and run([progA]).returncode == 42:
        print("AR-CREATE (nuestra .a): exit=42 OK")
    else:
        print("AR-CREATE: FALLO")
        rc = 1

    # --- B) nuestra .dll ---------------------------------------------------
    with open(os.path.join(work, "bar.vx"), "w") as f:
        f.write("i64 bar_value() { return 40; }\n")
    bar_dll = os.path.join(work, "bar.dll")
    run([vm, "--vx", os.path.join(work, "bar.vx"), "-m", "aot",
         "--emit", "shared", "--format", "pe", "-o", bar_dll])
    if not os.path.exists(bar_dll):
        print("FALLO: no se emitio bar.dll")
        return 1
    with open(os.path.join(work, "mainB.vx"), "w") as f:
        f.write('extern "bar.dll" { fn bar_value() -> i64; }\n'
                'i64 main() { return bar_value() + 2; }\n')
    mainB_obj = os.path.join(work, "mainB.obj")
    run([vm, "--vx", os.path.join(work, "mainB.vx"), "-m", "aot",
         "--emit", "obj", "--format", "pe", "-o", mainB_obj])
    progB = os.path.join(work, "progB.exe")
    run([vm, "--link", mainB_obj, bar_dll, "-o", progB, "--format", "pe"])
    # la .dll debe estar junto al exe para ejecutar
    if os.path.exists(progB) and run([progB], cwd=work).returncode == 42:
        print("DLL-LINK (nuestra .dll): exit=42 OK")
    else:
        print("DLL-LINK: FALLO")
        rc = 1

    return rc


if __name__ == "__main__":
    sys.exit(main())
