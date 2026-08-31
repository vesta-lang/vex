#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
 AOT.5 / gc<T> -- enlace standalone de un programa con GC opt-in usando
NUESTRO linker (vm --link), sin g++/ld externos.

Escenario (PE, nativo Windows):
  1. Un .vx usa gc<Box> (GC opt-in) -> el .obj referencia vx_gc_alloc_ptr /
     vx_gc_register_aot_stackmaps (definidos en libvesta_gc.a, libc-only).
  2. `vm --link prog.obj libvesta_gc.a -o prog.exe` debe:
       - extraer del .a solo los miembros necesarios (pull perezoso),
       - hacer COMDAT-folding de los inline/plantillas de C++ (operator new...),
       - resolver los simbolos libc/Win32 restantes como imports
         (ucrtbase.dll + kernel32.dll, autodetectando el CRT),
     produciendo un .exe que crea el objeto GC y retorna su campo (42).

Valida la cadena completa: parser AR + pull + COMDAT + imports IAT + CRT
autodetectado, sin g++/ld.

Uso:  python tests/aot/gc_link_test.py <build_dir>

# LADO: windows
#
# El escenario es PE de arriba abajo: `.obj`, `.exe`, y los simbolos de
# libc resueltos como IMPORTS de ucrtbase.dll/kernel32.dll.  Lanzado en
# Linux fallaba con una lista larguisima de simbolos sin resolver --
# memcpy, malloc, write, mmap... todos de libc -- que parecia una
# limitacion del enlazador y era estar del lado equivocado: alli lo
# equivalente no son imports por IAT sino enlace dinamico contra
# libc.so.6, que es otro mecanismo.
"""
import os
import subprocess
import sys
import tempfile


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def main():
    if len(sys.argv) < 2:
        print("uso: gc_link_test.py <build_dir>")
        return 2
    build = os.path.abspath(sys.argv[1])
    vm = os.path.join(build, "vm.exe")
    if not os.path.exists(vm):
        vm = os.path.join(build, "vm")
    lib = os.path.join(build, "libvesta_gc.a")
    if not os.path.exists(vm) or not os.path.exists(lib):
        print(f"falta vm o libvesta_gc.a en {build}")
        return 2

    work = tempfile.mkdtemp(prefix="gc_link_")
    src = os.path.join(work, "gc.vx")
    with open(src, "w") as f:
        f.write("class Box { i64 v; Box(i64 x) { this.v = x; } }\n"
                "i64 main() { gc<Box> b = new Box(42); return b.v; }\n")

    obj = os.path.join(work, "gc.obj")
    exe = os.path.join(work, "gc.exe")

    r = run([vm, "--vx", src, "-m", "aot", "--emit", "obj",
             "--format", "pe", "-o", obj])
    if not os.path.exists(obj):
        print("FALLO: no se genero gc.obj")
        print(r.stdout, r.stderr)
        return 1

    r = run([vm, "--link", obj, lib, "-o", exe, "--format", "pe"])
    if not os.path.exists(exe):
        print("FALLO: el linker no genero gc.exe")
        print("stdout:", r.stdout)
        print("stderr:", r.stderr)
        return 1

    r = run([exe])
    rc = 0
    if r.returncode == 42:
        print("GC-LINK PE (gc<T> + libvesta_gc.a, sin g++): exit=42 OK")
    else:
        print(f"GC-LINK PE: EXIT MISMATCH got={r.returncode} exp=42")
        rc = 1

    # Increment 3: --emit exe DIRECTO debe auto-enlazar libvesta_gc.a.
    auto = os.path.join(work, "gc_auto.exe")
    run([vm, "--vx", src, "-m", "aot", "--emit", "exe", "--format", "pe",
         "-o", auto])
    if os.path.exists(auto) and run([auto]).returncode == 42:
        print("GC-AUTOLINK PE (--emit exe, libvesta_gc.a automatica): exit=42 OK")
    else:
        print("GC-AUTOLINK PE: FALLO (auto-link de libvesta_gc.a)")
        rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
