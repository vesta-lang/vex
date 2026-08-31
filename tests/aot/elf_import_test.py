#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Resolucion de imports en ELF: el enlazador propio (vm --link) produce un
ejecutable de Linux que llama a libc, leyendo de libc.so.6 que simbolos exporta
(tabla dinamica) para resolver los imports por GOT/DT_NEEDED, sin ld/gcc.

Como el binario es ELF, se compila y ejecuta a traves de WSL (Linux).  En
Windows, libc.so.6 no esta en el sistema de archivos local, asi que se copia a
una ruta accesible y se pasa explicitamente como entrada al enlazador.

Escenario: un .vx llama a toupper() de libc; toupper(97) = 'A' = 65.

Uso:  python tests/aot/elf_import_test.py <build_dir>
"""
import os
import shutil
import subprocess
import sys


# LADO: windows  (prueba los DOS objetivos: el PE aqui, el ELF via WSL)
#
# `wsl` solo existe DESDE Windows.  Lanzado desde dentro de WSL este test
# moria con "No such file or directory: 'wsl'", que parecia un fallo suyo y
# era estar del lado equivocado.  Ahora se dice y se salta.
HAY_WSL = shutil.which("wsl") is not None


def wsl(cmd):
    return subprocess.run(["wsl", "bash", "-c", cmd], capture_output=True,
                          text=True)


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def main():
    if len(sys.argv) < 2:
        print("uso: elf_import_test.py <build_dir>")
        return 2
    if not HAY_WSL:
        print("SALTADO: no hay `wsl`.  Este test se lanza DESDE Windows y usa "
              "WSL para la mitad de Linux; desde dentro de WSL no aplica.")
        return 77

    build = os.path.abspath(sys.argv[1])
    vm = os.path.join(build, "vm.exe")
    if not os.path.exists(vm):
        vm = os.path.join(build, "vm")
    repo = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

    # WSL disponible?
    if wsl("echo ok").stdout.strip().splitlines()[-1:] != ["ok"]:
        print("ELF-IMPORT: WSL no disponible, omitido")
        return 0

    work = os.path.join(repo, "_elf_imp_test")
    os.makedirs(work, exist_ok=True)
    wm = "/mnt/" + repo[0].lower() + repo[1:].replace("\\", "/").replace(
        ":", "") + "/_elf_imp_test"
    try:
        # copiar libc.so.6 a una ruta accesible desde Windows
        wsl(f"cp $(ls /usr/lib/x86_64-linux-gnu/libc.so.6 "
            f"/lib/x86_64-linux-gnu/libc.so.6 2>/dev/null | head -1) "
            f"{wm}/libc.so.6")
        libc = os.path.join(work, "libc.so.6")
        if not os.path.exists(libc):
            print("ELF-IMPORT: no se encontro libc.so.6 en WSL, omitido")
            return 0

        with open(os.path.join(work, "m.vx"), "w") as f:
            f.write('extern "libc.so.6" { fn toupper(i32 c) -> i32; }\n'
                    'i64 main() { return (i64)toupper(97); }\n')
        obj = os.path.join(work, "m.o")
        prog = os.path.join(work, "p")
        run([vm, "--vx", os.path.join(work, "m.vx"), "-m", "aot",
             "--emit", "obj", "--format", "elf", "-o", obj])
        run([vm, "--link", obj, libc, "-o", prog, "--format", "elf"])
        if not os.path.exists(prog):
            print("ELF-IMPORT: el enlazador no genero el ejecutable")
            return 1
        rc = wsl(f"cd {wm} && chmod +x p && ./p").returncode
        if rc == 65:
            print("ELF-IMPORT (libc via dynsym, vm --link): exit=65 OK")
            return 0
        print(f"ELF-IMPORT: EXIT MISMATCH got={rc} exp=65")
        return 1
    finally:
        import shutil
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
