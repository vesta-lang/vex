#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
La BASE DE LA IMAGEN, resuelta por NUESTRO enlazador y por la via del GOT.

`__ImageBase` (PE) y `__executable_start` (ELF) no los define ningun fichero
fuente: los publica el ENLAZADOR, y su valor es el primer byte de la imagen
cargada.  `link.exe` y `ld` los sintetizan; el nuestro no, y el modo de fallar
era de los caros: no lo define ningun objeto y no lo exporta ninguna DLL, asi
que salia como "simbolo no resuelto" a varias capas del sitio que lo pedia.

Con un archivo `.a` por medio ni siquiera hacia falta LLAMAR a la funcion que lo
menciona: la unidad de enlace es el OBJETO entero, asi que traerse cualquier
otra cosa de ese fichero se traia tambien la referencia.

Este test cubre la via del GOT, que es la que emite CUALQUIER compilador al
generar codigo independiente de posicion -- o sea, la que decide si un objeto
AJENO enlaza con nosotros --.  La via directa ya la ejercitan los casos de
`gc<T>` en AOT.

Y no se conforma con que la base no sea nula: la DESREFERENCIA y comprueba que
ahi estan los cuatro bytes de la cabecera ELF.  Una base equivocada tambien es
distinta de cero, asi que mirar solo eso dejaria pasar el fallo.

Uso:  python tests/aot/imagebase_got_test.py <build_dir>
"""
import os
import shutil
import subprocess
import sys

# LADO: windows  (prueba los DOS lados: enlaza el ELF AQUI -- nuestro enlazador
# produce ELF desde Windows -- y lo EJECUTA via WSL)
#
# `wsl` solo existe DESDE Windows; lanzado desde dentro de WSL este test moriria
# por no encontrarlo, que parece un fallo suyo y no lo es.
HAY_WSL = shutil.which("wsl") is not None

FUENTE = r"""
extern char __executable_start[];

/* En funcion aparte: si el compilador ve la comprobacion entera la resuelve al
 * compilar y no llega a emitir el acceso por GOT, que es justo lo que hay que
 * ejercitar. */
const void *base_del_modulo(void) { return __executable_start; }

int main(void) {
    const unsigned char *b = (const unsigned char *)base_del_modulo();
    if (b == 0) return 1;                       /* no se resolvio */
    if (b[0] != 0x7F || b[1] != 'E' || b[2] != 'L' || b[3] != 'F')
        return 2;                               /* se resolvio, pero MAL */
    return 42;
}
"""


def wsl(cmd):
    return subprocess.run(["wsl", "bash", "-c", cmd], capture_output=True,
                          text=True)


def main():
    if len(sys.argv) < 2:
        print("uso: imagebase_got_test.py <build_dir>")
        return 2
    build = os.path.abspath(sys.argv[1])
    vm = os.path.join(build, "vm.exe")
    if not os.path.exists(vm):
        vm = os.path.join(build, "vm")
    if not os.path.exists(vm):
        print("no se encuentra vm en %s" % build)
        return 2

    if not HAY_WSL:
        print("SALTADO: no hay `wsl`.  Este test se lanza DESDE Windows: "
              "compila el objeto ELF y ejecuta el binario alli")
        return 77

    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    work = os.path.join(repo, "_imagebase_got_test")
    os.makedirs(work, exist_ok=True)
    # La MISMA carpeta vista desde los dos lados: el enlazador es de Windows y
    # el compilador y el binario son de Linux.
    wm = "/mnt/" + repo[0].lower() + repo[1:].replace("\\", "/").replace(
        ":", "") + "/_imagebase_got_test"

    try:
        with open(os.path.join(work, "prog.c"), "w") as f:
            f.write(FUENTE)

        if wsl("command -v gcc").returncode != 0:
            print("SALTADO: sin gcc en WSL no se puede producir el objeto ELF "
                  "con la reubicacion GOT que este test necesita")
            return 77

        # -fPIC es lo que manda el acceso por GOT; -O0, que no lo pliegue.
        r = wsl(f"cd {wm} && gcc -fPIC -O0 -c prog.c -o prog.o")
        if r.returncode != 0:
            print("FALLO: gcc no pudo compilar el objeto\n%s" % r.stderr)
            return 1

        # Que la reubicacion sea de VERDAD por GOT.  Sin esto el test podria
        # pasar sin haber probado nada, que es la peor clase de verde.
        r = wsl(f"cd {wm} && readelf -r prog.o")
        if r.returncode == 0 and "GOTP" not in r.stdout:
            print("FALLO: el objeto no lleva reubicacion GOT sobre "
                  "__executable_start; el test no probaria nada")
            return 1

        obj = os.path.join(work, "prog.o")
        exe = os.path.join(work, "prog")
        r = subprocess.run([vm, "--link", obj, "--format", "elf", "-o", exe],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print("FALLO: nuestro enlazador no resolvio __executable_start "
                  "por GOT\n%s%s" % (r.stdout, r.stderr))
            return 1

        rc = wsl(f"cd {wm} && chmod +x prog && ./prog").returncode
        if rc == 1:
            print("FALLO: la base salio NULA")
            return 1
        if rc == 2:
            print("FALLO: la base se resolvio, pero no apunta al inicio de la "
                  "imagen (no hay cabecera ELF ahi)")
            return 1
        if rc != 42:
            print("FALLO: codigo de salida %d, se esperaba 42" % rc)
            return 1

        print("OK: __executable_start por GOT -> la base apunta al magic ELF")
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
