#!/usr/bin/env python3
"""Harness compartido para los tests AOT-ELF de Vesta (portados de bash a Python).

Cada test AOT sigue el mismo patron: compilar un `.vx` a objeto nativo con
`vesta -m aot`, enlazarlo con gcc, ejecutar el binario y verificar el
exit-code; opcionalmente valgrind (0 leaks) u objdump (grep de mnemonicos).

Se corre bajo Linux/WSL (necesita gcc/objdump/valgrind + poder ejecutar el
ELF resultante):

    wsl python3 tests/aot/<test>.py <build_dir>

El `vesta`/`vm[.exe]` del build resuelve rutas RELATIVAS a su cwd, por eso el
harness hace chdir a la raiz del repo y pasa rutas relativas.  Solo stdlib.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile


class AotTest:
    """Contexto de un test AOT: localiza el binario, crea un tmpdir y acumula rc."""

    def __init__(self):
        if len(sys.argv) < 2:
            sys.exit("uso: python %s <build_dir>" % os.path.basename(sys.argv[0]))
        self.build = sys.argv[1]
        # Raiz del repo = dos niveles por encima de este fichero.
        self.root = os.path.abspath(
            os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "..", ".."))
        os.chdir(self.root)
        # Preferir el binario nativo Linux; caer al .exe (invocable desde WSL).
        self.vm = os.path.join(self.build, "vm")
        if not (os.path.isfile(self.vm) and os.access(self.vm, os.X_OK)):
            self.vm = os.path.join(self.build, "vm.exe")
        self.work = tempfile.mkdtemp()
        self.rc = 0

    # --- reporte ---------------------------------------------------------
    def ok(self, msg):
        print(msg)

    def fail(self, msg):
        print(msg)
        self.rc = 1

    def wpath(self, name):
        """Ruta dentro del tmpdir de trabajo."""
        return os.path.join(self.work, name)

    def finish(self):
        shutil.rmtree(self.work, ignore_errors=True)
        sys.exit(self.rc)

    # --- pasos -----------------------------------------------------------
    def compile_aot(self, vx, out, fmt="elf", emit="obj", arch=None,
                    float_isa=None, bin_base=None, extra=None):
        """Compila @p vx a @p out con `vesta -m aot`.  Devuelve True si existe out.

        Con fmt=None se omite --format (p.ej. `--emit bin`).  bin_base fija la
        base de carga del binario plano.
        """
        # El vm.exe de Windows (invocado desde WSL) NO puede escribir al tmpdir
        # de WSL (/tmp); emite primero a un temporal bajo el build (accesible a
        # ambos mundos) y luego se copia a `out`.  En entorno uniforme (vm
        # nativo) el copy es un no-op equivalente.
        stage = os.path.join(self.build, "_aot_stage_" + os.path.basename(out))
        cmd = [self.vm, "--vesta", vx, "-m", "aot", "--emit", emit]
        if fmt:
            cmd += ["--format", fmt]
        if arch:
            cmd += ["--aot-arch", arch]
        if float_isa:
            cmd += ["--float-isa", float_isa]
        if bin_base:
            cmd += ["--bin-base", bin_base]
        if extra:
            cmd += list(extra)
        cmd += ["-o", stage]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if os.path.isfile(stage):
            shutil.copy(stage, out)
            try:
                os.remove(stage)
            except OSError:
                pass
        return os.path.isfile(out)

    def gcc(self, objs, out, flags=("-no-pie",)):
        """Enlaza @p objs (lista) en @p out con gcc.  Devuelve True si exito."""
        cmd = ["gcc", *flags, "-o", out, *objs]
        return subprocess.run(cmd, stderr=subprocess.DEVNULL).returncode == 0

    def gcc_c(self, csrc, out_o, flags=("-O2",)):
        """Compila un .c a .o (para harness/runtime en C)."""
        cmd = ["gcc", "-c", *flags, "-o", out_o, csrc]
        return subprocess.run(cmd, stderr=subprocess.DEVNULL).returncode == 0

    def vm_link(self, objs, out, fmt="elf", entry=None, link_script=None):
        """Enlaza @p objs con el linker propio (`vesta --link`).  True si exec."""
        cmd = [self.vm, "--link", *objs, "-o", out, "--format", fmt]
        if entry:
            cmd += ["--entry", entry]
        if link_script:
            cmd += ["--link-script", link_script]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return os.path.isfile(out) and os.access(out, os.X_OK)

    def readelf(self, flags, f):
        """Devuelve la salida de `readelf <flags> <f>` (texto)."""
        return subprocess.run(["readelf", *flags, f], capture_output=True,
                              text=True).stdout

    def run_exit(self, elf, args=()):
        """Ejecuta el binario y devuelve su exit-code."""
        return subprocess.run([elf, *args], stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL).returncode

    def expect_exit(self, elf, want, label):
        """Ejecuta y compara el exit-code; reporta OK/FALLO."""
        got = self.run_exit(elf)
        if got == want:
            self.ok("%s: run exit=%d OK" % (label, got))
        else:
            self.fail("%s: EXIT MISMATCH got=%d exp=%d" % (label, got, want))
        return got

    def valgrind(self, elf, label, errcode=88):
        """Valgrind con --error-exitcode=errcode.  Reporta OK/FALLO por leaks."""
        vg = subprocess.run(
            ["valgrind", "--error-exitcode=%d" % errcode, "--leak-check=full",
             "--errors-for-leak-kinds=all", "-q", elf],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
        if vg == errcode:
            self.fail("  VALGRIND %s FALLO (errores/leaks)" % label)
        else:
            self.ok("  VALGRIND %s OK (0 leaks, 0 errores; prog exit=%d)" % (label, vg))

    def disasm(self, f, intel=False):
        """Devuelve el desensamblado de @p f (texto)."""
        cmd = ["objdump", "-d"] + (["-M", "intel"] if intel else []) + [f]
        return subprocess.run(cmd, capture_output=True, text=True).stdout

    # Rutinas que llevan A PROPOSITO varias versiones del mismo codigo, una por
    # familia de instrucciones, y eligen en EJECUCION segun lo que diga la CPU.
    # Ver `std.memory`: el despachador comprueba los rasgos y salta a la variante
    # SSE2, AVX2 o AVX-512 que toque.
    MULTIVERSION = ("std__memory__",)

    def disasm_generado(self, f, intel=False):
        """El desensamblado SOLO del codigo que genero el compilador.

        Cualquier comprobacion sobre QUE instrucciones se emiten tiene que mirar
        aqui, no al objeto entero.  Un programa que toque memoria arrastra el
        despachador de `std.memory`, que contiene TODAS las variantes -- SSE2,
        AVX2 y AVX-512 a la vez -- porque la eleccion es en ejecucion.  Contarlas
        como si fueran codigo generado dice que un binario `--float-isa sse2`
        emite AVX-512, que es falso: lo emite la stdlib, guardado tras una
        comprobacion de CPU, y no se ejecuta donde no se puede.

        Por lo mismo, en la ruta sin AVX de esas rutinas el SSE es legacy A LA
        FUERZA: en una CPU sin AVX no existe la codificacion VEX.
        """
        out = []
        incluir = True
        for ln in self.disasm(f, intel).splitlines(True):
            if ln and ln[0].isalnum() and " <" in ln and ln.rstrip().endswith(">:"):
                nombre = ln.split("<", 1)[1]
                incluir = not any(m in nombre for m in self.MULTIVERSION)
            if incluir:
                out.append(ln)
        return "".join(out)

    def symbols(self, f):
        """Devuelve la tabla de simbolos (`objdump -t`) como texto."""
        return subprocess.run(["objdump", "-t", f], capture_output=True,
                              text=True).stdout

    @staticmethod
    def count_lines(text, pattern):
        """Cuenta LINEAS que casan @p pattern (semantica de `grep -c`), case-insensitive."""
        rx = re.compile(pattern, re.I)
        return sum(1 for ln in text.splitlines() if rx.search(ln))

    @staticmethod
    def have(tool):
        return shutil.which(tool) is not None

    def write(self, name, content):
        """Escribe un fichero auxiliar (.vx/.c) en el tmpdir."""
        p = self.wpath(name)
        with open(p, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)
        return p
