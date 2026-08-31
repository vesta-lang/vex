#!/usr/bin/env python3
"""Suite end-to-end del compilador Vesta (port fiel de test_vx_e2e.sh).

Compila los ejemplos de examples_codes_vx/ con el binario `vm` construido por
CMake y verifica el resultado de ejecucion de cada uno (R00 del interprete,
exit-code del binario nativo en AOT, contenido del output, bytes emitidos...).

    python3 tests/vx/e2e_test.py <build_dir> [-j N] [-k filtro] [--keep]

`build_dir` debe contener vm.exe (Windows MinGW) o vm (Linux).  Sale con codigo
0 si todo pasa; != 0 si algun caso falla.

    -j N      casos en paralelo (0 = automatico, por defecto)
    -k TXT    ejecutar solo los casos cuyo tag contenga TXT (diagnostico)
    --keep    no borrar el directorio temporal al terminar

Convencion del proyecto: los scripts de automatizacion van en Python (no .sh).

Diferencias deliberadas respecto del .sh original (documentadas):

  * El .sh era fail-fast (`set -e` + `exit 1` en el primer fallo).  Aqui se
    ejecutan TODOS los casos y se reporta el conjunto de fallos al final, que
    es lo que hacen el resto de tests Python del repo (init_overlay_test.py) y
    lo que permite ver de un vistazo cuanto esta roto.  Un caso que falla no
    aborta los demas.

  * Los casos se ejecutan en PARALELO (ThreadPoolExecutor).  El arranque de
    `vm` cuesta ~55 ms fijos y hay >300 pasos, asi que el grueso del tiempo es
    lanzar procesos.  Cada caso escribe en su propio directorio temporal para
    no pisarse.  La salida se recolecta y se imprime en el orden de la lista,
    de modo que el resultado es determinista pese al paralelismo.

  * Los pocos casos que tocan estado GLOBAL (la ruta fija
    <raiz>/_test_plugin.velb de loadmodule) se marcan `serial=True` y se
    ejecutan en solitario, fuera del pool.

Los valores esperados son los del .sh original y NO se han reinterpretado.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

# ---------------------------------------------------------------------------
# Infraestructura
# ---------------------------------------------------------------------------

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "..", ".."))
VX_DIR = os.path.join(ROOT, "examples_codes_vx")

# Formato del objeto AOT segun el host: PE en Windows/Msys, ELF en el resto.
AOT_FMT = "pe" if sys.platform.startswith("win") else "elf"

VM_EXE = None      # se rellena en main()
TMP_ROOT = None    # se rellena en main()


class CaseFail(Exception):
    """Un paso del caso ha fallado; aborta el caso (no la suite)."""


class Ctx:
    """Contexto de un caso: directorio propio, log de pasos y helpers.

    Cada caso recibe un Ctx con su propio directorio temporal, de modo que dos
    casos en hilos distintos jamas comparten ficheros de salida.
    """

    def __init__(self, tag):
        self.tag = tag
        self.dir = os.path.join(TMP_ROOT, tag)
        os.makedirs(self.dir, exist_ok=True)
        self.lines = []   # ("OK"|"SKIP"|"FAIL", texto)
        self.n_ok = 0

    # -- reporte --------------------------------------------------------
    def ok(self, msg):
        self.lines.append(("OK", msg))
        self.n_ok += 1

    def skip(self, msg):
        self.lines.append(("SKIP", msg))

    def warn(self, msg):
        """El caso pasa, pero no comprueba lo que dice comprobar.

        Un caso que no puede fallar da un OK que enganya y se pudre en silencio:
        mejor que lo diga en voz alta cada vez que se ejecuta.
        """
        self.lines.append(("WARN", msg))

    def fail(self, msg, detail=""):
        """Marca el fallo y aborta el caso (equivalente al `exit 1` del .sh)."""
        self.lines.append(("FAIL", msg))
        if detail:
            self.lines.append(("DETAIL", detail.rstrip()))
        raise CaseFail(msg)

    # -- rutas ----------------------------------------------------------
    def path(self, name):
        return os.path.join(self.dir, name)

    def src(self, name):
        """Ruta a un ejemplo de examples_codes_vx (acepta subdirectorios)."""
        return os.path.join(VX_DIR, name)

    # -- ejecucion ------------------------------------------------------
    def run(self, args, cwd=None, env=None, timeout=600):
        """Ejecuta un comando y devuelve (returncode, stdout+stderr).

        El .sh redirige siempre `>log 2>&1`, es decir combina ambos flujos; se
        replica juntando stdout y stderr en una sola cadena.
        """
        try:
            p = subprocess.run(args, cwd=cwd, env=env, timeout=timeout,
                               capture_output=True, text=True,
                               errors="replace")
        except subprocess.TimeoutExpired:
            return 124, "TIMEOUT tras %ds: %s" % (timeout, " ".join(map(str, args)))
        return p.returncode, (p.stdout or "") + (p.stderr or "")

    # -- pasos de alto nivel --------------------------------------------
    def compile_vx(self, src, out, extra=None, must_succeed=True, cwd=None,
                   env=None):
        """Compila un .vx a .velb.  Devuelve (rc, log).  `src` es absoluto.

        `env` permite pasar variables de entorno (p.ej. {"VESTA_NO_CTPE": "1"}
        para verificar codegen que el precomputo CTPE optimizaria al plegar main).
        """
        args = [VM_EXE, "--vesta", src]
        if extra:
            args += [str(a) for a in extra]
        args += ["-o", self.path(out)]
        full_env = None
        if env:
            full_env = os.environ.copy()
            full_env.update({k: str(v) for k, v in env.items()})
        rc, log = self.run(args, cwd=cwd, env=full_env)
        if must_succeed and not os.path.exists(self.path(out + ".velb")):
            # Con el CoDIGO DE SALIDA.  Sin el, una compilacion que no deja
            # binario es indistinguible de una que CASCA: se vieron fallos con
            # el registro completamente vacio, que no eran errores de
            # compilacion sino caidas del proceso, y el mensaje no lo decia.
            # En Windows el codigo negativo ES el motivo (0xC0000005 = acceso
            # invalido, 0xC00000FD = desbordamiento de pila).
            extra_rc = " (rc=%d / 0x%08X)" % (rc, rc & 0xFFFFFFFF)
            self.fail("compilacion de %s no produjo .velb%s"
                      % (os.path.basename(src), extra_rc), log)
        return rc, log

    def run_velb(self, out, schedulers=None, stats=True, mode=None, cwd=None,
                 extra=None, env=None):
        args = [VM_EXE]
        if mode:
            args += ["-m", mode]
        args += ["--run", self.path(out + ".velb")]
        if schedulers is not None:
            args += ["--schedulers", str(schedulers)]
        if stats:
            args += ["--stats"]
        if extra:
            args += [str(a) for a in extra]
        return self.run(args, cwd=cwd, env=env)


def bash_hex_to_int(h):
    """Replica `$((0x...))` de bash: aritmetica con signo de 64 bits.

    bash evalua en 64 bits con signo, de modo que 0xffffffffffffffff -> -1.
    """
    return wrap64(int(h, 16))


def wrap64(v):
    """Envuelve un entero a 64 bits con signo (semantica aritmetica de bash)."""
    v &= (2 ** 64 - 1)
    if v >= 2 ** 63:
        v -= 2 ** 64
    return v


def bash_arith(text):
    """Replica `$((x))` sobre un literal decimal o `0x...` (con envoltura)."""
    text = text.strip()
    base = 16 if text.lower().startswith("0x") else 10
    return wrap64(int(text, base))


def exit_code(rc):
    """Replica `$?` de un shell POSIX: el codigo de salida son 8 bits.

    En POSIX el propio SO trunca, pero en Windows `subprocess` devuelve el
    valor de 32 bits completo; el .sh corria bajo MSYS y veia el truncado (de
    ahi los valores `N mod 256` que espera).  Truncar aqui hace que el port se
    comporte igual en ambas plataformas.
    """
    return rc & 0xFF


def bre_to_py(pat):
    """Traduce un patron BRE de `grep` (sin -E) a una regex de Python.

    En BRE los metacaracteres `( ) { } + ? |` son LITERALES; solo `. * [ ] ^ $`
    son especiales.  Los patrones del .sh se escribieron para `grep -q`, asi que
    sin esta traduccion algo como `prestamo(s) shared activo(s)` se
    interpretaria como grupos de captura y dejaria de casar.
    """
    out = []
    i = 0
    while i < len(pat):
        c = pat[i]
        if c == "\\" and i + 1 < len(pat):
            out.append(pat[i:i + 2])
            i += 2
            continue
        out.append("\\" + c if c in "(){}+?|" else c)
        i += 1
    return "".join(out)


R00_RE = re.compile(r"R00=0x([0-9a-fA-F]+)")
LASTERR_RE = re.compile(r"LastErr=([0-9]+)")


def get_r00(log):
    """Extrae el primer R00=0x... del log (equivale a grep -oE | head -1)."""
    m = R00_RE.search(log)
    return bash_hex_to_int(m.group(1)) if m else None


def get_r00_hex(log):
    """Devuelve el R00 como texto hex tal cual lo imprime la VM."""
    m = R00_RE.search(log)
    return "0x" + m.group(1) if m else None


def check_lasterr(ctx, log, label):
    """Replica: si aparece LastErr y != 0 -> FAIL.  Si no aparece, se ignora."""
    m = LASTERR_RE.search(log)
    if m and m.group(1) != "0":
        ctx.fail("%s: LastErr == %s" % (label, m.group(1)), log)


def read_text(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def read_bytes(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        return b""


# ---------------------------------------------------------------------------
# Helpers equivalentes a los del .sh
# ---------------------------------------------------------------------------

def h_verify_r0(ctx, label, src, expected, out=None, schedulers=1,
                lasterr=False, extra=None):
    """Equivalente de `verify_r0`: compila, ejecuta y compara R00.

    `schedulers=1` reproduce el helper verify_r0 del .sh.  Los bloques inline
    antiguos no pasaban --schedulers; esos casos llaman con schedulers=None.
    """
    out = out or ctx.tag
    ctx.compile_vx(ctx.src(src), out, extra=extra)
    ctx.ok("compilacion %s -> .velb" % src)
    _, log = ctx.run_velb(out, schedulers=schedulers)
    got = get_r00(log)
    if got != expected:
        ctx.fail("%s: R00 == %s, se esperaba %d" % (label, got, expected), log)
    if lasterr:
        check_lasterr(ctx, log, label)
    ctx.ok("%s -> R0 = %d" % (label, expected))
    return log


def h_verify_compile_fails(ctx, label, src, pattern):
    """Equivalente de `verify_compile_fails`: la compilacion debe fallar."""
    out = ctx.tag
    _, log = ctx.compile_vx(ctx.src(src), out, must_succeed=False)
    if os.path.exists(ctx.path(out + ".velb")):
        ctx.fail("%s: la compilacion produjo .velb pero deberia fallar" % label,
                 log)
    if not re.search(bre_to_py(pattern), log):
        ctx.fail("%s: el mensaje de error no contiene '%s'" % (label, pattern),
                 log)
    ctx.ok("%s (compile error con mensaje correcto)" % label)


def h_verify_const_reject(ctx, label, body):
    """Equivalente de `verify_const_reject`: genera un main() y exige error."""
    tag = ctx.tag
    vx = ctx.path(tag + ".vx")
    with open(vx, "w", encoding="utf-8") as f:
        f.write("void main() {\n%s\n}\n" % body)
    _, log = ctx.run([VM_EXE, "--vesta", vx, "-o", ctx.path(tag)])
    if os.path.exists(ctx.path(tag + ".velb")):
        ctx.fail("const-neg '%s': la compilacion debio fallar pero produjo .velb"
                 % label, log)
    if not re.search("const", log, re.IGNORECASE):
        ctx.fail("const-neg '%s': no se reporto el error de const" % label, log)
    ctx.ok("const rechaza '%s'" % label)


def h_verify_3modes(ctx, label, src, expected, out=None):
    """Equivalente de `verify_naked_3modes`: mismo R0 en -m vm, -m jit y -m aot.

    En AOT el valor observado es el exit-code del ejecutable nativo.
    """
    out = out or ctx.tag
    ctx.compile_vx(ctx.src(src), out)

    _, log = ctx.run_velb(out, schedulers=1, mode="vm")
    got = get_r00(log)
    if got != expected:
        ctx.fail("%s (-m vm): R00 == %s, se esperaba %d" % (label, got, expected),
                 log)
    ctx.ok("%s (-m vm) -> R0 = %d" % (label, expected))

    _, log = ctx.run_velb(out, schedulers=1, mode="jit")
    got = get_r00(log)
    if got != expected:
        ctx.fail("%s (-m jit): R00 == %s, se esperaba %d" % (label, got, expected),
                 log)
    ctx.ok("%s (-m jit) -> R0 = %d" % (label, expected))

    exe = aot_build(ctx, ctx.src(src), out + "_aot", label + " (-m aot)")
    rc, _ = ctx.run([exe])
    rc = exit_code(rc)
    if rc != expected:
        ctx.fail("%s (-m aot): exit == %d, se esperaba %d" % (label, rc, expected))
    ctx.ok("%s (-m aot) -> exit = %d" % (label, expected))


def h_verify_3modes_agree(ctx, label, src, out=None):
    """Los tres modos dan LO MISMO, sea lo que sea.

    Para un programa cuyo resultado no se escribe a mano: un banco de pruebas
    devuelve una suma de control que depende de su trabajo, y fijarla aqui seria
    copiar un numero que nadie ha comprobado.  Lo que SI se puede afirmar es que
    interpretarlo, compilarlo al vuelo y compilarlo a nativo tienen que coincidir
    -- y eso es justo lo que se rompe cuando el codigo generado se desvia --.

    El INTERPRETE es el oraculo: es el mas simple y el que menos transformaciones
    aplica.  En nativo solo se puede comparar el byte bajo, que es todo lo que un
    codigo de salida puede llevar.
    """
    out = out or ctx.tag
    ctx.compile_vx(ctx.src(src), out)

    _, log = ctx.run_velb(out, schedulers=1, mode="vm")
    ref = get_r00(log)
    if ref is None:
        ctx.fail("%s (-m vm): no devolvio nada" % label, log)
        return
    ctx.ok("%s (-m vm) -> R0 = %s (oraculo)" % (label, ref))

    _, log = ctx.run_velb(out, schedulers=1, mode="jit")
    got = get_r00(log)
    if got != ref:
        ctx.fail("%s: el jit no coincide con el interprete: %s vs %s"
                 % (label, got, ref), log)
        return
    ctx.ok("%s (-m jit) coincide" % label)

    exe = aot_build(ctx, ctx.src(src), out + "_aot", label + " (-m aot)")
    rc, _ = ctx.run([exe])
    rc = exit_code(rc)
    # Solo el byte bajo: es lo que cabe en un codigo de salida.
    if rc != (int(ref) & 0xFF):
        ctx.fail("%s: el nativo no coincide con el interprete: %d vs %d "
                 "(byte bajo)" % (label, rc, int(ref) & 0xFF))
        return
    ctx.ok("%s (-m aot) coincide" % label)


def h_verify_aot_only(ctx, label, src, expected, out=None):
    """Un programa que SOLO tiene sentido en nativo: se compila y se ejecuta.

    Hay ejemplos escritos para el binario y no para la maquina virtual -- hilos
    del sistema operativo, el planificador M:N de fibras, exclusion mutua entre
    hilos de verdad --.  Pedirles que corran en el interprete no prueba que
    esten rotos: prueba que se les pidio algo que no es lo suyo.  Aqui se les
    pide lo que si son, y el binario nativo devuelve el `return` del programa
    como codigo de salida.
    """
    out = out or ctx.tag
    exe = aot_build(ctx, ctx.src(src), out + "_aot", label)
    rc_raw, _ = ctx.run([exe])
    # Mismo cuidado que en la red diferencial: un binario que CASCA no
    # "devuelve" un valor.  Enmascarar a 8 bits convierte un 0xC0000005 en un
    # inocente "exit == 5" y manda a buscar un error de calculo donde lo que hay
    # es un cuelgue.
    if rc_raw < 0 or (rc_raw & 0xC0000000) == 0xC0000000:
        ctx.fail("%s: el binario AOT CASCO (codigo 0x%X)" %
                 (label, rc_raw & 0xFFFFFFFF),
                 getattr(ctx, "last_aot_log", ""))
        return
    rc = exit_code(rc_raw)
    if rc != expected:
        ctx.fail("%s (-m aot): exit == %d, se esperaba %d" %
                 (label, rc, expected), getattr(ctx, "last_aot_log", ""))
        return
    ctx.ok("%s (-m aot) -> exit = %d" % (label, expected))


def h_diff3(ctx, label, src, out=None, aot=True):
    """Red de seguridad diferencial (Pilar 1): el INTERP es el ORACULO; jit y aot
    deben COINCIDIR con el.  No hay valor esperado fijo -- basta con que los tres
    modos den el MISMO R0.  Cualquier divergencia (un backend distinto de otro)
    ROMPE el build: es la garantia 'falla todo o nada' contra desincronizacion de
    backends.  Usar para casos de presion de registros / control de flujo complejo
    donde el codegen del JIT/AOT podria divergir del interprete.
    """
    out = out or ctx.tag
    # SIN CTPE: el precomputo CTPE usa el JIT y HORNEA su resultado en el .velb;
    # si el JIT tiene un bug, contaminaria tambien al interprete -> el oraculo
    # dejaria de ser fiable.  Compilar sin CTPE da un oraculo (interp) limpio.
    ctx.compile_vx(ctx.src(src), out, env={"VESTA_NO_CTPE": "1"})

    _, log = ctx.run_velb(out, schedulers=1, mode="vm")
    oracle = get_r00(log)  # el interprete (sin CTPE) define la verdad
    if oracle is None:
        ctx.fail("%s: el interprete (oraculo) no produjo R0" % label, log)
        return
    ctx.ok("%s (interp oraculo) -> R0 = 0x%x" % (label, oracle))

    _, log = ctx.run_velb(out, schedulers=1, mode="jit")
    got = get_r00(log)
    if got != oracle:
        ctx.fail("%s DIVERGE: jit R0 == %s != interp 0x%x" % (label, got, oracle),
                 log)
        return
    ctx.ok("%s (jit == interp)" % label)

    if aot:
        # El AOT se construye con la configuracion POR DEFECTO a proposito: el
        # precomputo CTPE corre en los TRES modos, asi que forzar aqui
        # VESTA_NO_CTPE taparia justo los fallos que solo aparecen al plegar.
        exe = aot_build(ctx, ctx.src(src), out + "_aot", label + " (-m aot)")
        rc_raw, _ = ctx.run([exe])
        # Un binario que CASCA no "devuelve" un valor: Windows entrega el
        # NTSTATUS (0xC0000005 = access violation, 0xC00000FD = desbordamiento
        # de pila) y POSIX un negativo con la senal.  Enmascarar a 8 bits
        # convierte 0xC0000005 en un inocente "exit == 5" y manda a buscar un
        # error de CALCULO donde lo que hay es un CUELGUE.  Se detecta ANTES de
        # truncar, y se adjunta el log de la construccion.
        if rc_raw < 0 or (rc_raw & 0xC0000000) == 0xC0000000:
            ctx.fail("%s: el binario AOT CASCO (codigo 0x%X)" %
                     (label, rc_raw & 0xFFFFFFFF),
                     getattr(ctx, "last_aot_log", ""))
            return
        rc = exit_code(rc_raw)
        # el oraculo es un R0 completo; el exit-code AOT son 8 bits -> comparar
        # el byte bajo (misma convencion que h_verify_3modes con exit-codes).
        if (oracle & 0xFF) != (rc & 0xFF):
            ctx.fail("%s DIVERGE: aot exit == %d != interp 0x%x (byte bajo)" %
                     (label, rc, oracle),
                     getattr(ctx, "last_aot_log", ""))
            return
        ctx.ok("%s (aot == interp)" % label)


def h_ctpe_conformance(ctx, label, src, out=None):
    """El precomputo CTPE no puede cambiar el resultado observable del programa.

    CTPE ejecuta `main` al compilar y hornea su resultado como constante.  Si
    esa constante no coincide con lo que el programa produce de verdad, el
    compilador emite un binario incorrecto -- y como el precomputo esta ACTIVO
    POR DEFECTO, eso afecta a cualquier compilacion, no solo al AOT.

    Se compila el MISMO fuente dos veces, con y sin precomputo, y se exige el
    mismo R0.  La version con CTPE se compila dentro del directorio temporal
    del caso a proposito: su cache vive en `.cache/ctpe` RELATIVO al cwd, asi
    que compilando ahi esta siempre FRIO.  Con un cache caliente el pliegue se
    leeria ya hecho y un error de calculo pasaria inadvertido, que es
    exactamente como este fallo llego a parecer intermitente.
    """
    out = out or ctx.tag
    ctx.compile_vx(ctx.src(src), out + "_noctpe",
                   env=dict(os.environ, VESTA_NO_CTPE="1"))
    _, log = ctx.run_velb(out + "_noctpe", schedulers=1, mode="vm")
    ref = get_r00(log)
    if ref is None:
        ctx.fail("%s: la version sin precomputo no produjo R0" % label, log)
        return
    ctx.ok("%s (sin CTPE) -> R0 = 0x%x" % (label, ref))

    ctx.compile_vx(ctx.src(src), out + "_ctpe", cwd=ctx.dir)
    _, log = ctx.run_velb(out + "_ctpe", schedulers=1, mode="vm")
    got = get_r00(log)
    if got != ref:
        ctx.fail("%s: el precomputo CAMBIA el resultado: R0 == %s, sin "
                 "precomputo 0x%x" % (label, got, ref), log)
        return
    ctx.ok("%s (con CTPE == sin CTPE)" % label)

    # Y en AOT, que es donde el precomputo tiene MAS formas de estropear el
    # binario: comparte el pipeline vreg con el JIT pero su salida se EJECUTA
    # EN OTRO PROCESO, asi que cualquier cosa que el precomputo deje puesta en
    # el codegen (p.ej. los polls de safepoint del watchdog, cuya direccion de
    # handler solo vive en el compilador) se convierte en un binario que casca.
    # Sin esta pata la comprobacion no vale: el mismo bug que la motivo pasaba
    # el camino del interprete sin despeinarse.
    # Directorio PROPIO para esta pata: el cache de CTPE es relativo al cwd, y
    # la pata anterior ya lo calento en `ctx.dir`.  Con el cache caliente el
    # pliegue se LEE en vez de ejecutarse, y entonces el precomputo no llega a
    # compilar nada por JIT -- que es justo la condicion que destapa el fallo.
    # Sin este detalle la comprobacion pasa siempre y no vale para nada.
    aot_dir = ctx.path(out + "_ctpe_aotdir")
    os.makedirs(aot_dir, exist_ok=True)
    exe = aot_build(ctx, ctx.src(src), out + "_ctpe_aot",
                    label + " (-m aot con CTPE)", cwd=aot_dir)
    if not exe:
        return
    rc_raw, _ = ctx.run([exe])
    if rc_raw < 0 or (rc_raw & 0xC0000000) == 0xC0000000:
        ctx.fail("%s: con precomputo el binario AOT CASCO (codigo 0x%X)" %
                 (label, rc_raw & 0xFFFFFFFF),
                 getattr(ctx, "last_aot_log", ""))
        return
    if exit_code(rc_raw) != (ref & 0xFF):
        ctx.fail("%s: con precomputo el AOT devuelve %d, sin precomputo 0x%x "
                 "(byte bajo)" % (label, exit_code(rc_raw), ref),
                 getattr(ctx, "last_aot_log", ""))
        return
    ctx.ok("%s (aot con CTPE == sin CTPE)" % label)


def h_diff3_stdout(ctx, label, src, out=None, aot=True):
    """Como h_diff3 pero comparando la SALIDA byte a byte, no R0.

    Hace falta para las cadenas: una divergencia de codificacion o de
    representacion no cambia el valor de retorno, asi que h_diff3 no la ve.
    El interprete es el oraculo; JIT y AOT deben producir el mismo texto.
    """
    out = out or label
    ctx.compile_vx(ctx.src(src), out)
    import os as _os
    if not _os.path.exists(ctx.path(out + ".velb")):
        return

    _, salida_vm = ctx.run_velb(out, mode="vm", stats=False)
    if not salida_vm.strip():
        ctx.fail("%s (-m vm): sin salida" % label)
        return
    ctx.ok("%s (-m vm) -> %d lineas" % (label, len(salida_vm.splitlines())))

    _, salida_jit = ctx.run_velb(out, mode="jit", stats=False)
    if salida_jit != salida_vm:
        ctx.fail("%s DIVERGE jit != interp" % label,
                 "--- interp ---\n%s\n--- jit ---\n%s"
                 % (salida_vm, salida_jit))
        return
    ctx.ok("%s (jit == interp)" % label)

    if not aot:
        return
    exe = aot_build(ctx, ctx.src(src), out + "_aot", label + " (-m aot)")
    if not exe:
        return
    _, salida_aot = ctx.run([exe])
    if salida_aot != salida_vm:
        ctx.fail("%s DIVERGE aot != interp" % label,
                 "--- interp ---\n%s\n--- aot ---\n%s"
                 % (salida_vm, salida_aot))
        return
    ctx.ok("%s (aot == interp)" % label)


def wsl_disponible():
    """True si se puede ejecutar un ELF de Linux desde aqui (WSL en marcha).

    Los binarios ELF que emite el AOT solo se pueden PROBAR en Linux; en
    Windows se comprueba que compilan, pero eso no dice si funcionan.  WSL
    cierra ese hueco cuando esta disponible.
    """
    if not sys.platform.startswith("win"):
        return False
    try:
        r = subprocess.run(["wsl.exe", "-e", "sh", "-c", "echo ok"],
                           capture_output=True, timeout=60)
        return r.returncode == 0 and b"ok" in r.stdout
    except Exception:
        return False


def wsl_run_elf(elf_path, timeout=120):
    """Ejecuta un ELF en WSL.  Devuelve (rc, salida) o (None, motivo).

    El binario se copia a /tmp porque en /mnt/... el bit de ejecucion depende
    de como este montado el volumen.
    """
    linux_src = "/mnt/" + elf_path[0].lower() + elf_path[2:].replace("\\", "/")
    guion = ("cp '%s' /tmp/vx_e2e_bin && chmod +x /tmp/vx_e2e_bin && "
             "/tmp/vx_e2e_bin; echo __RC=$?" % linux_src)
    try:
        r = subprocess.run(["wsl.exe", "-e", "sh", "-c", guion],
                           capture_output=True, timeout=timeout)
    except Exception as exc:
        return None, "no se pudo ejecutar en WSL: %s" % exc
    salida = (r.stdout + r.stderr).decode("utf-8", "replace")
    salida = salida.replace("\x00", "")
    rc = None
    for linea in salida.splitlines():
        if linea.startswith("__RC="):
            try:
                rc = int(linea[5:].strip())
            except ValueError:
                pass
    if rc is None:
        return None, "no se obtuvo codigo de salida:\n" + salida
    return rc, salida


def aot_build(ctx, src_abs, out, label, cwd=None, fmt=None, env=None,
              extra=None):
    """Compila un .vx (ruta absoluta) a ejecutable nativo y devuelve su ruta.

    El emisor PE escribe el fichero SIN extension .exe; el .sh probaba ambos
    nombres (`[ -f "$exe.exe" ] && exe="$exe.exe"`).  Aqui se replica y ademas
    se renombra a .exe en Windows para poder ejecutarlo.

    `extra` son flags que se anaden a la linea de compilacion (p.ej.
    `--target embed`), para los casos que comprueban justamente que el binario
    cambia segun con que se pida.
    """
    args = [VM_EXE, "-m", "aot", "--vesta", src_abs,
            "--format", fmt or AOT_FMT, "--emit", "exe",
            "-o", ctx.path(out)]
    if extra:
        args += [str(a) for a in extra]
    _, log = ctx.run(args, cwd=cwd, env=env)
    # Se guarda el log de la construccion para poder adjuntarlo si luego el
    # binario diverge: sin el, un "aot exit == N" no dice NADA de por que.
    ctx.last_aot_log = log
    base = ctx.path(out)
    if os.path.exists(base + ".exe"):
        return base + ".exe"
    if os.path.exists(base):
        if sys.platform.startswith("win"):
            # En Windows hay que renombrarlo para poder ejecutarlo.
            try:
                os.replace(base, base + ".exe")
                return base + ".exe"
            except OSError:
                return base
        return base
    ctx.fail("%s: no se produjo exe nativo" % label, log)


def grep_q(text, pattern):
    """Equivalente de `grep -qE <pattern>` (busca en cualquier linea)."""
    return re.search(pattern, text, re.MULTILINE) is not None


def grep_c(text, pattern):
    """Equivalente de `grep -cE <pattern>`: numero de LINEAS que casan."""
    rx = re.compile(pattern)
    return sum(1 for ln in text.split("\n") if rx.search(ln))


def expect_lines(ctx, log, label, patterns):
    """Replica el bucle `for pat in ...; do grep -qE ...` de los bloques EXPECT."""
    for pat in patterns:
        if not grep_q(log, pat):
            ctx.fail("%s: falta linea '%s' en output" % (label, pat), log)


# ---------------------------------------------------------------------------
# Registro de casos
# ---------------------------------------------------------------------------

CASES = []       # lista de (orden, tag, fn, serial)
_AUTO_SEQ = [0]  # contador para los casos sin `line` explicita


def _register(tag, fn, serial, line):
    """Registra un caso.  `line` = linea del .sh original (ordena el reporte).

    Los casos de la seccion inline se registran sin `line` y reciben un orden
    automatico creciente; como esa seccion cubre las lineas 44-1418 del .sh y
    todo lo demas viene con `line` >= 1547, el orden final coincide con el del
    script original.
    """
    if line is None:
        _AUTO_SEQ[0] += 1
        line = _AUTO_SEQ[0]
    if any(c[1] == tag for c in CASES):
        raise RuntimeError("tag de caso duplicado: %s" % tag)
    CASES.append((line, tag, fn, serial))


def case(tag, serial=False, line=None):
    """Decorador que registra un caso a medida."""
    def deco(fn):
        _register(tag, fn, serial, line)
        return fn
    return deco


def r0_case(tag, label, src, expected, line=None, schedulers=1, lasterr=False):
    """Registra un caso `verify_r0` sin escribir una funcion a mano."""
    def fn(ctx):
        h_verify_r0(ctx, label, src, expected, out=tag,
                    schedulers=schedulers, lasterr=lasterr)
    fn.__name__ = "case_" + tag
    _register(tag, fn, False, line)


def fails_case(tag, label, src, pattern, line=None):
    def fn(ctx):
        h_verify_compile_fails(ctx, label, src, pattern)
    fn.__name__ = "case_" + tag
    _register(tag, fn, False, line)


def warns_r0_case(tag, label, src, pattern, expected, line=None):
    """Compila (debe SUCEDER), exige un warning con `pattern` en el log, y
    verifica R00.  Para diagnosticos no-fatales (el programa igual corre)."""
    def fn(ctx):
        _, log = ctx.compile_vx(ctx.src(src), tag)
        if not re.search(bre_to_py(pattern), log):
            ctx.fail("%s: no aparecio el warning '%s'" % (label, pattern), log)
        ctx.ok("%s (warning '%s' emitido)" % (label, pattern))
        _, rlog = ctx.run_velb(tag, schedulers=1)
        got = get_r00(rlog)
        if got != expected:
            ctx.fail("%s: R00 == %s, se esperaba %d" % (label, got, expected),
                     rlog)
        ctx.ok("%s -> R0 = %d" % (label, expected))
    fn.__name__ = "case_" + tag
    _register(tag, fn, False, line)


def const_reject_case(tag, label, body, line=None):
    def fn(ctx):
        h_verify_const_reject(ctx, label, body)
    fn.__name__ = "case_" + tag
    _register(tag, fn, False, line)


def modes3_agree_case(tag, label, src, line=None):
    """Registra un caso `verify_3modes_agree` (sin valor esperado a mano)."""
    def fn(ctx):
        h_verify_3modes_agree(ctx, label, src, out=tag)
    fn.__name__ = "case_" + tag
    _register(tag, fn, False, line)


def modes3_case(tag, label, src, expected, line=None):
    def fn(ctx):
        h_verify_3modes(ctx, label, src, expected, out=tag)
    fn.__name__ = "case_" + tag
    _register(tag, fn, False, line)


def aot_case(tag, label, src, expected, line=None):
    """Un ejemplo que solo corre en nativo.  Ver @c h_verify_aot_only."""
    def fn(ctx):
        h_verify_aot_only(ctx, label, src, expected, out=tag)
    fn.__name__ = "case_" + tag
    _register(tag, fn, False, line)


def diff3_stdout_case(tag, label, src, line=None, aot=True):
    """Red diferencial sobre la SALIDA: interp = oraculo, jit y aot iguales."""
    def fn(ctx):
        h_diff3_stdout(ctx, label, src, out=tag, aot=aot)
    fn.__name__ = "case_" + tag
    _register(tag, fn, False, line)


def fault3_case(tag, label, src, code, exit_want, line=None):
    """Un fallo sin capturar, en los tres modos.

    Interprete y JIT tienen que contarlo igual: el codigo del catalogo, la
    cadena de llamadas con el fuente subrayado, y el codigo de salida.  El AOT
    a nivel 0 NO reporta a proposito -- el nativo tiene que ser ligero -- asi
    que ahi solo se exige que NO salga con cero: reventar y decir que todo fue
    bien es lo unico inaceptable en los tres.
    """
    def fn(ctx):
        ctx.compile_vx(ctx.src(src), tag)
        for modo in ("vm", "jit"):
            rc, log = ctx.run_velb(tag, schedulers=1, mode=modo)
            if code not in log:
                ctx.fail("%s (-m %s): no aparece %s" % (label, modo, code), log)
            if "Stack trace" not in log:
                ctx.fail("%s (-m %s): sin cadena de llamadas" % (label, modo), log)
            got = exit_code(rc)
            if got != exit_want:
                ctx.fail("%s (-m %s): sale %d, se esperaba %d"
                         % (label, modo, got, exit_want), log)
            ctx.ok("%s (-m %s) -> %s, sale %d" % (label, modo, code, exit_want))
        exe = aot_build(ctx, ctx.src(src), tag + "_aot", label + " (-m aot)")
        rc, _ = ctx.run([exe])
        if exit_code(rc) == 0:
            ctx.fail("%s (-m aot): salio con cero tras reventar" % label)
        ctx.ok("%s (-m aot) -> muere sin decir nada, como debe" % label)
    fn.__name__ = "case_" + tag
    _register(tag, fn, False, line)


def caught_fault_case(tag, label, src, expected, line=None):
    """Un fallo del sistema CAPTURADO con `try/catch`, en interprete y JIT.

    Comprueba el valor devuelto, que solo sale bien si el `catch` corrio Y el
    programa siguio despues.  Ese "y siguio despues" es la parte que se rompio
    sin que nadie se enterara: quien recuperaba el fallo cerraba el proceso
    tambien cuando alguien lo habia atrapado.

    El modo nativo queda fuera a proposito: sin desenrollado de excepciones
    nativo (AOT.7) no puede convertir un fallo del procesador en excepcion.
    """
    def fn(ctx):
        ctx.compile_vx(ctx.src(src), tag)
        ctx.ok("compilacion %s -> .velb" % src)
        for modo in ("vm", "jit"):
            _, log = ctx.run_velb(tag, schedulers=1, mode=modo)
            got = get_r00(log)
            if got != expected:
                ctx.fail("%s (-m %s): R00 == %s, se esperaba %d"
                         % (label, modo, got, expected), log)
            ctx.ok("%s (-m %s) -> R0 = %d" % (label, modo, expected))
    fn.__name__ = "case_" + tag
    _register(tag, fn, False, line)


def vm_jit_r0_case(tag, label, src, expected, line=None):
    """Comprueba el valor devuelto en interprete y JIT, sin el modo nativo.

    Existe para los programas que no se pueden comprobar en nativo todavia y
    que NO capturan ningun fallo.  Antes se colaban por `caught_fault_case`,
    que hace lo mismo -- corre esos dos modos y mira R00 -- pero cuyo NOMBRE
    afirma que el programa atrapa un fallo del sistema con `try/catch` y sigue
    adelante.  Registrar aqui uno que no tiene ni un `try` no rompia nada, y
    ese era el problema: la suite parecia cubrir la recuperacion de fallos en
    un caso que no la ejercita, asi que romperla no lo habria hecho fallar.
    """
    def fn(ctx):
        ctx.compile_vx(ctx.src(src), tag)
        ctx.ok("compilacion %s -> .velb" % src)
        for modo in ("vm", "jit"):
            _, log = ctx.run_velb(tag, schedulers=1, mode=modo)
            got = get_r00(log)
            if got != expected:
                ctx.fail("%s (-m %s): R00 == %s, se esperaba %d"
                         % (label, modo, got, expected), log)
            ctx.ok("%s (-m %s) -> R0 = %d" % (label, modo, expected))
    fn.__name__ = "case_" + tag
    _register(tag, fn, False, line)


def asm_lift_case(tag, label, src, line=None):
    """El MISMO fuente, elevado y sin elevar, tiene que hacer lo mismo.

    Pasar un bloque `asm` a IR es una transformacion, y una transformacion se
    comprueba comparando el antes con el despues.  Hasta ahora la unica forma de
    hacerlo era reescribir el programa a mano poniendo `volatile` -- que ademas
    cambia OTRA cosa, la optimizacion, asi que ni siquiera era la misma
    comparacion --, y por eso un elevado que producia un IR de aspecto impecable
    y hacia que el programa devolviera otro numero solo se vio de casualidad.

    Aqui se compila dos veces el mismo fichero, una con `VESTA_ASM_NO_LIFT=1`, y
    se comparan los tres modos.  No se fija un valor esperado a proposito: lo que
    se comprueba es que elevar NO CAMBIE NADA, que es la propiedad que importa y
    la unica que no envejece cuando el elevado aprenda mas casos.
    """
    def fn(ctx):
        ctx.compile_vx(ctx.src(src), tag + "_lift")
        ctx.compile_vx(ctx.src(src), tag + "_op",
                       env={"VESTA_ASM_NO_LIFT": "1"})
        ctx.ok("compilacion %s (elevado y opaco)" % src)
        # Si el elevado no elevo nada, las dos versiones son el mismo binario y
        # compararlas no comprueba nada.  Un caso que no puede fallar da un OK
        # que enganya, asi que se dice en voz alta en lugar de callarlo.
        try:
            b1 = open(ctx.path(tag + "_lift.velb"), "rb").read()
            b2 = open(ctx.path(tag + "_op.velb"), "rb").read()
            if b1 == b2:
                ctx.warn("%s: el elevado no elevo nada -- las dos versiones son "
                         "identicas y la comparacion no tiene mordida" % src)
        except OSError:
            pass
        for modo in ("vm", "jit"):
            _, l1 = ctx.run_velb(tag + "_lift", schedulers=1, mode=modo)
            _, l2 = ctx.run_velb(tag + "_op", schedulers=1, mode=modo)
            a, b = get_r00(l1), get_r00(l2)
            if a != b:
                ctx.fail("%s (-m %s): elevado da %s y opaco da %s -- elevar "
                         "cambio el resultado" % (label, modo, a, b), l1)
            if a is None:
                ctx.fail("%s (-m %s): ninguna de las dos versiones devolvio "
                         "nada" % (label, modo), l1)
            ctx.ok("%s (-m %s) -> elevado == opaco (%s)" % (label, modo, a))
        # El nativo compara el codigo de salida del ejecutable.
        e1 = aot_build(ctx, ctx.src(src), tag + "_lift_aot", label + " (-m aot)")
        rc1, _ = ctx.run([e1])
        e2 = aot_build(ctx, ctx.src(src), tag + "_op_aot", label + " (-m aot op)",
                       env={"VESTA_ASM_NO_LIFT": "1"})
        rc2, _ = ctx.run([e2])
        if exit_code(rc1) != exit_code(rc2):
            ctx.fail("%s (-m aot): elevado sale %d y opaco %d"
                     % (label, exit_code(rc1), exit_code(rc2)))
        ctx.ok("%s (-m aot) -> elevado == opaco (%d)" % (label, exit_code(rc1)))
    fn.__name__ = "case_" + tag
    _register(tag, fn, False, line)


def diff3_case(tag, label, src, line=None, aot=True):
    """Red de seguridad diferencial: interp=oraculo, jit y aot deben COINCIDIR.
    Sin valor esperado; cualquier divergencia entre backends rompe el build."""
    def fn(ctx):
        h_diff3(ctx, label, src, out=tag, aot=aot)
    fn.__name__ = "case_" + tag
    _register(tag, fn, False, line)


# ===========================================================================
# Seccion inline (tests 1-54 del .sh original).
#
# Estos tests son anteriores al helper verify_r0 y estaban escritos a mano.
# Se conservan tal cual, incluidas sus comprobaciones extra (LastErr, greps
# sobre el .vel, dobles corridas con distinto numero de schedulers).  Ojo: NO
# pasaban --schedulers, a diferencia de verify_r0; se respeta.
# ===========================================================================

@case("aritmetica")
def _(ctx):
    """1. Aritmetica simple: 1 + 2 * 3 = 7."""
    ctx.compile_vx(ctx.src("00_aritmetica.vx"), "aritmetica")
    ctx.ok("compilacion .vx -> .velb")
    _, log = ctx.run_velb("aritmetica")
    got = get_r00(log)
    if got is None:
        ctx.fail("no se localizo R00 en la salida de --stats", log)
    if got != 7:
        ctx.fail("R00 == %s, se esperaba 7" % got, log)
    ctx.ok("R00 == 7 (1 + 2 * 3)")


@case("factorial")
def _(ctx):
    """2. Factorial recursivo: 10! = 3628800."""
    ctx.compile_vx(ctx.src("01_factorial.vx"), "factorial")
    ctx.ok("compilacion factorial.vx -> .velb")
    _, log = ctx.run_velb("factorial")
    got = get_r00(log)
    if got != 3628800:
        ctx.fail("factorial(10) == %s, se esperaba 3628800" % got, log)
    ctx.ok("factorial(10) == 3628800")


@case("hola")
def _(ctx):
    """3. Hola mundo (strings + FFI vio_println)."""
    ctx.compile_vx(ctx.src("02_hola_mundo.vx"), "hola")
    ctx.ok("compilacion 02_hola_mundo.vx -> .velb")
    _, log = ctx.run_velb("hola", stats=False)
    if "Hola Mundo desde Vesta-lang!" not in log:
        ctx.fail("hola_mundo no imprimio 'Hola Mundo desde Vesta-lang!'", log)
    ctx.ok("hola_mundo imprime 'Hola Mundo desde Vesta-lang!'")


@case("contador")
def _(ctx):
    """4. Contador con for-loop + println: valida A.2 (asignacion + loops)."""
    ctx.compile_vx(ctx.src("03_contador.vx"), "contador")
    ctx.ok("compilacion 03_contador.vx -> .velb")
    _, log = ctx.run_velb("contador", stats=False)
    iters = grep_c(log, r"^iteracion$")
    if not (iters == 5 and "== Contador Vesta-lang ==" in log and "== Fin ==" in log):
        ctx.fail("contador output incorrecto (esperado 5 'iteracion' + header + footer)",
                 log)
    ctx.ok("contador imprime 5 iteraciones + header + footer")


@case("escribir")
def _(ctx):
    """5. Escritura de fichero: valida fopen / fwrite / fclose end-to-end."""
    ctx.compile_vx(ctx.src("04_escribe_fichero.vx"), "escribir")
    ctx.ok("compilacion 04_escribe_fichero.vx -> .velb")
    # El .sh hacia `cd $TMP_DIR` para que salida_vx.txt cayera ahi; aqui se
    # usa cwd= (no se puede hacer chdir global con casos en paralelo).
    _, log = ctx.run([VM_EXE, "--run", "escribir.velb"], cwd=ctx.dir)
    out_txt = ctx.path("salida_vx.txt")
    if not os.path.exists(out_txt):
        ctx.fail("el programa no creo salida_vx.txt", log)
    if "Hola desde " not in read_text(out_txt):
        ctx.fail("salida_vx.txt no contiene el texto esperado", read_text(out_txt))
    ctx.ok("salida_vx.txt creado con contenido esperado")
    if "== Hecho ==" not in log:
        ctx.fail("stdout no contiene la marca de cierre", log)
    ctx.ok("stdout contiene marca '== Hecho =='")


@case("sp")
def _(ctx):
    """6. Struct con campos: valida A.3 (struct decl + variable struct + p.x)."""
    ctx.compile_vx(ctx.src("05_struct_punto.vx"), "sp")
    ctx.ok("compilacion 05_struct_punto.vx -> .velb")
    _, log = ctx.run_velb("sp")
    got = get_r00(log)
    if got != 42:
        ctx.fail("struct Punto: R00 == %s, se esperaba 42" % got, log)
    ctx.ok("Punto.x + Punto.y == 42 (10 + 32)")


@case("sm")
def _(ctx):
    """7. Multiples structs vivos: regresion del truncamiento de `mov reg, rsp`."""
    ctx.compile_vx(ctx.src("06_struct_multi.vx"), "sm")
    ctx.ok("compilacion 06_struct_multi.vx -> .velb")
    _, log = ctx.run_velb("sm")
    got = get_r00(log)
    if got != 21:
        ctx.fail("multi struct: R00 == %s, se esperaba 21" % got, log)
    ctx.ok("a.x+a.y+a.z + b.x+b.y+b.z == 21 (1+2+3 + 4+5+6)")


@case("ptrs")
def _(ctx):
    """8. Punteros raw: &x address-taken, *p deref, *p = v, out params."""
    ctx.compile_vx(ctx.src("07_punteros.vx"), "ptrs")
    ctx.ok("compilacion 07_punteros.vx -> .velb")
    _, log = ctx.run_velb("ptrs")
    got = get_r00(log)
    if got != 142:
        ctx.fail("punteros raw: R00 == %s, se esperaba 142" % got, log)
    ctx.ok("punteros raw: read_ptr(&a) + read_ptr(&b) == 142 (100 + 42)")


@case("pl")
def _(ctx):
    """9. Puntero address-taken en while: regresion de liveness across back-edges."""
    ctx.compile_vx(ctx.src("08_punteros_loop.vx"), "pl")
    ctx.ok("compilacion 08_punteros_loop.vx -> .velb")
    _, log = ctx.run_velb("pl")
    got = get_r00(log)
    if got != 55:
        ctx.fail("punteros + loop: R00 == %s, se esperaba 55" % got, log)
    ctx.ok("puntero address-taken en while: sum 1..10 == 55")


@case("pa")
def _(ctx):
    """10. Aritmetica puntero (p + n) y subscript p[i]."""
    ctx.compile_vx(ctx.src("09_punteros_arith.vx"), "pa")
    ctx.ok("compilacion 09_punteros_arith.vx -> .velb")
    _, log = ctx.run_velb("pa")
    got = get_r00(log)
    if got != 12:
        ctx.fail("aritmetica puntero: R00 == %s, se esperaba 12" % got, log)
    ctx.ok("p[0]+p[1]+p[2]+*(p+3) == 12 (con p[3]=6)")


@case("hm")
def _(ctx):
    """11. malloc/free + LOAD/STORE via movh."""
    ctx.compile_vx(ctx.src("10_heap_malloc.vx"), "hm")
    ctx.ok("compilacion 10_heap_malloc.vx -> .velb")
    _, log = ctx.run_velb("hm")
    got = get_r00(log)
    if got != 285:
        ctx.fail("malloc/free: R00 == %s, se esperaba 285" % got, log)
    ctx.ok("malloc(40) array i32[10] suma cuadrados == 285")


@case("an")
def _(ctx):
    """12. Arrays nativos T[N] en stack y T[] como parametro."""
    ctx.compile_vx(ctx.src("11_arrays_nativos.vx"), "an")
    ctx.ok("compilacion 11_arrays_nativos.vx -> .velb")
    _, log = ctx.run_velb("an")
    got = get_r00(log)
    if got != 55:
        ctx.fail("arrays nativos: R00 == %s, se esperaba 55" % got, log)
    ctx.ok("i32[10] decay a i32[] + sum_array == 55 (1+2+...+10)")


# --- Tests 13-29: POO / herencia / AOP / reflexion.  Todos con check de
#     LastErr (el .sh exigia que no hubiera error de runtime).

def _inline_r0(ctx, src, out, expected, label_fail, ok_msg, lasterr=True,
               ok_compile=None):
    """Patron comun de los tests inline: compilar, correr, R00 [+ LastErr]."""
    ctx.compile_vx(ctx.src(src), out)
    ctx.ok(ok_compile or ("compilacion %s -> .velb" % src))
    _, log = ctx.run_velb(out)
    got = get_r00(log)
    if got != expected:
        ctx.fail("%s: R00 == %s, se esperaba %d" % (label_fail, got, expected), log)
    if lasterr:
        check_lasterr(ctx, log, label_fail)
    ctx.ok(ok_msg)
    return log


@case("cb")
def _(ctx):
    """13. POO basico: class + ctor + new + obj.field + obj.method."""
    _inline_r0(ctx, "12_clases_basico.vx", "cb", 7, "POO basico",
               "new Punto(3,4).sum() == 7  (LastErr=0)")


@case("cm")
def _(ctx):
    """14. Clases con modificadores y expression-bodied."""
    _inline_r0(ctx, "13_clases_modificadores.vx", "cm", 25, "modificadores",
               "Vec(5).dot() expression-bodied == 25  (LastErr=0)")


@case("cv")
def _(ctx):
    """15. Encapsulacion: campos privados, getters publicos, metodo final."""
    _inline_r0(ctx, "14_clases_visibilidad.vx", "cv", 100, "visibilidad",
               "Cuenta(10).abonar(90).leerSaldo() == 100  (LastErr=0)")


@case("he")
def _(ctx):
    """16. Herencia: Perro : Animal con override @Override."""
    _inline_r0(ctx, "15_herencia_basica.vx", "he", 176, "herencia",
               "Perro(7).{edad+vivir()+sonido()} == 176 (override @Override)  (LastErr=0)")


@case("aop")
def _(ctx):
    """17. AOP basico: @Aspect Tracer con @Before y @After sobre Service.run."""
    _inline_r0(ctx, "16_aop_basico.vx", "aop", 99, "AOP",
               "@Aspect+@Before+@After sobre Service.run -> R0 = 99 (cadena BEFORE/M/AFTER)  (LastErr=0)")


@case("ecs")
def _(ctx):
    """18. ECS basico (Struct-of-Arrays + sistemas iterativos)."""
    _inline_r0(ctx, "17_ecs_basico.vx", "ecs", 100, "ECS",
               "ECS SoA pos+vel x 8 entidades, system_movement+sum -> R0 = 100  (LastErr=0)")


@case("refl")
def _(ctx):
    """19. Reflexion MVP: forName(name) == getClass(obj)."""
    _inline_r0(ctx, "18_reflexion_basica.vx", "refl", 1, "reflexion",
               'forName("Animal") == getClass(new Animal()) -> R0 = 1  (LastErr=0)')


@case("tco")
def _(ctx):
    """20. TCO: el optimizador debe emitir `tailcall` + R0 = 42.

    Se compila con VESTA_NO_CTPE para verificar el CODEGEN del tailcall: con CTPE
    activo (default), main = `return wrapper(20)` se PRECOMPUTA a la constante 42
    y el tailcall de wrapper se elimina por DCE (correcto: el resultado es el
    mismo).  La funcionalidad se valida por el R0 = 42 de abajo (en modo normal).
    """
    ctx.compile_vx(ctx.src("19_tco_basico.vx"), "tco",
                   extra=["--vx-emit-only"], env={"VESTA_NO_CTPE": "1"})
    n = grep_c(read_text(ctx.path("tco.vel")), "tailcall")
    if n < 1:
        ctx.fail("TCO no se aplico (esperado >= 1 tailcall en .vel)")
    ctx.ok("TCO emite %d instrucciones tailcall en wrapper+main" % n)
    _, log = ctx.run_velb("tco")
    got = get_r00(log)
    if got != 42:
        ctx.fail("TCO: R00 == %s, se esperaba 42 (helper(21) = 42)" % got, log)
    check_lasterr(ctx, log, "TCO")
    ctx.ok("TCO chain wrapper->helper -> R0 = 42  (LastErr=0)")


@case("rf2")
def _(ctx):
    """21. Reflexion ext: getField devuelve FieldInfo* != 0 / 0."""
    _inline_r0(ctx, "20_reflexion_field.vx", "rf2", 1, "getField",
               "getField('edad')!=0 && getField('noexiste')==0 -> R0 = 1  (LastErr=0)")


@case("iface")
def _(ctx):
    """22. Interfaces basico: interface IServicio + class Servicio."""
    _inline_r0(ctx, "21_interfaces_basico.vx", "iface", 1, "interfaces",
               "interface IServicio + class Servicio (forName + dispatch) -> R0 = 1  (LastErr=0)")


@case("poly")
def _(ctx):
    """23. Polimorfismo via interface type -> R0 = 30."""
    _inline_r0(ctx, "22_iface_polimorfismo.vx", "poly", 30, "polimorfismo",
               "dispatch dinamico via interface type (callm + findmethod) -> R0 = 30  (LastErr=0)")


@case("around")
def _(ctx):
    """24. AROUND advice + proceed() -> R0 = 1007."""
    _inline_r0(ctx, "23_aop_around.vx", "around", 1007, "AROUND",
               "@Around wrap() { proceed()+1000 } sobre Service.run()=7 -> R0 = 1007  (LastErr=0)")


@case("tc")
def _(ctx):
    """25. try/catch/throw basico -> R0 = 1007."""
    _inline_r0(ctx, "24_try_catch.vx", "tc", 1007, "try/catch",
               "try { throw MyExc(7) } catch (MyExc e) { 1000+e.valor } -> R0 = 1007  (LastErr=0)")


@case("tmf")
def _(ctx):
    """26. try/multi-catch/finally -> R0 = 1057."""
    _inline_r0(ctx, "25_try_multi_finally.vx", "tmf", 1057, "try/multi/finally",
               "multi-catch (ExcA, ExcB) + finally -> R0 = 1057  (LastErr=0)")


@case("fe")
def _(ctx):
    """27. foreach sobre array nativo T[N] -> R0 = 55."""
    _inline_r0(ctx, "26_foreach.vx", "fe", 55, "foreach",
               "foreach sobre i32[10] sum = 1+2+...+10 -> R0 = 55  (LastErr=0)")


@case("gen")
def _(ctx):
    """28. Generics MVP - Box<T> con monomorphizacion compile-time."""
    _inline_r0(ctx, "27_generics_box.vx", "gen", 141, "generics",
               "Box<i32>(42).read() + Box<i64>(99).read() = 141  (LastErr=0)")


@case("genav")
def _(ctx):
    """29. Generics avanzado - dos type params Pair<K,V>."""
    _inline_r0(ctx, "28_generics_avanzado.vx", "genav", 37, "generics avanzado",
               "Pair<i32,i32>(3,4) + Pair<i64,i64>(10,20) = 37  (LastErr=0)")


@case("opt")
def _(ctx):
    """30. Optional via VM ops isnull/unwrap -> R0 = 1050.

    El .sh tenia aqui un grep de 'isnull' sobre el .vel cuyo cuerpo era `true`
    (no-op): no comprobaba nada.  Se replica el comportamiento (sin chequeo).
    """
    _inline_r0(ctx, "29_optional.vx", "opt", 1050, "optional",
               "Optional via VM isnull/unwrap (no template wrapper) -> R0 = 1050  (LastErr=0)")


@case("uwn")
def _(ctx):
    """31. unwrap(null) lanza NullPointerException catchable -> R0 = 999."""
    _inline_r0(ctx, "30_unwrap_null.vx", "uwn", 999, "unwrap-null",
               "try { unwrap(null) } catch () { 999 } -> R0 = 999  (LastErr=0)")


@case("nn")
def _(ctx):
    """32. Operador !! (assert non-null) + modificador nonnull -> R0 = 222."""
    _inline_r0(ctx, "31_nonnull_bangbang.vx", "nn", 222, "!!/nonnull",
               "!!tag (unwrap) + nonnull T = !!tag -> R0 = 222  (LastErr=0)")


@case("nn_neg")
def _(ctx):
    """33. nonnull rechaza compile-time literal null (test negativo)."""
    vx = ctx.path("nn_neg.vx")
    with open(vx, "w", encoding="utf-8") as f:
        f.write("class T { public T() {} }\n"
                "i32 main() { nonnull T x = null; return 0; }\n")
    _, log = ctx.run([VM_EXE, "--vesta", vx, "-o", ctx.path("nn_neg")])
    if os.path.exists(ctx.path("nn_neg.velb")):
        ctx.fail("nonnull negativo: la compilacion debio fallar pero produjo .velb",
                 log)
    if "nonnull" not in log:
        ctx.fail("nonnull negativo: no se reporto el error esperado", log)
    ctx.ok("nonnull T x = null; rechazado en compile time")


@case("bb")
def _(ctx):
    """34. Sintaxis `T !!name` en var-decl + params -> R0 = 23."""
    _inline_r0(ctx, "32_bangbang_decl.vx", "bb", 23, "T !!name",
               "Tag !!tag = ... y i32 addOne(Tag !!arg) -> R0 = 23  (LastErr=0)")


@case("pn")
def _(ctx):
    """35. Un null pasado a `T !!arg` mata el proceso al entrar, y no se captura.

    Antes se capturaba y este mismo programa devolvia 999.  Pero afirmar que
    algo no es nulo y equivocarse es un BUG del programa, no una condicion
    recuperable: seguir corriendo solo sirve para hacerlo con la suposicion ya
    rota.  Y ademas en nativo NO hay desenrollado de excepciones, asi que ahi
    siempre murio -- el mismo programa hacia una cosa al interpretarlo y otra
    al compilarlo, que es peor que cualquiera de las dos.

    Se comprueba que el `catch` NO corre (nada de 999) y que el fallo se
    cuenta: codigo del catalogo y cadena de llamadas.
    """
    vx = ctx.path("pn.vx")
    with open(vx, "w", encoding="utf-8") as f:
        f.write("class T { public T() {} }\n"
                "i32 use(T !!arg) { return 1; }\n"
                "i32 main() {\n"
                "    T x = null;\n"
                "    i32 r = 0;\n"
                "    try { r = use(x); } catch () { r = 999; }\n"
                "    return r;\n"
                "}\n")
    _, log = ctx.run([VM_EXE, "--vesta", vx, "-o", ctx.path("pn")])
    if not os.path.exists(ctx.path("pn.velb")):
        ctx.fail("compilacion de pn.vx no produjo .velb", log)
    _, log = ctx.run_velb("pn")
    got = get_r00(log)
    if got == 999:
        ctx.fail("param-null-check: el catch corrio; ya no debe capturarse", log)
    if "VX7001" not in log:
        ctx.fail("param-null-check: no aparece VX7001 (puntero nulo)", log)
    if "Stack trace" not in log:
        ctx.fail("param-null-check: sin cadena de llamadas", log)
    ctx.ok("T !!arg en param: null pasado mata el proceso, sin capturar -> VX7001")


@case("orb")
def _(ctx):
    """36. Optional<T> y Result<V,E> como BUILTINS (sin clases en bytecode)."""
    ctx.compile_vx(ctx.src("33_optional_result_builtin.vx"), "orb",
                   extra=["--vx-emit-only"])
    vel = read_text(ctx.path("orb.vel"))
    if grep_q(vel, r"^Optional_|^Result_|^__new_Optional|^__new_Result"):
        ctx.fail("el bytecode contiene clases Optional_*/Result_* "
                 "(debio ser builtin sin monomorphizacion)")
    ctx.ok("compilacion 33_optional_result_builtin.vx -> .velb "
           "(sin clases Optional_*/Result_*)")
    _, log = ctx.run_velb("orb")
    got = get_r00(log)
    if got != 1057:
        ctx.fail("builtin Optional/Result: R00 == %s, se esperaba 1057" % got, log)
    check_lasterr(ctx, log, "builtin Optional/Result")
    ctx.ok("Optional<i32> + Result<i32,i32> (Some/None/Ok/Err/isPresent/unwrap/"
           "isOk/value) -> R0 = 1057  (LastErr=0)")


@case("orav")
def _(ctx):
    """37. Funcion devuelve Result; implicit Some en var-decl -> R0 = 3154."""
    _inline_r0(ctx, "34_optional_result_avanzado.vx", "orav", 3154,
               "Optional/Result avanzado",
               "divide() devuelve Result, implicit Some, error tratado -> R0 = 3154  (LastErr=0)")


@case("mh")
def _(ctx):
    """38. must-handle: Result ignorado en expression-statement -> compile error."""
    vx = ctx.path("mh.vx")
    with open(vx, "w", encoding="utf-8") as f:
        f.write("Result<i32, i32> divide(i32 a, i32 b) {\n"
                "    if (b == 0) { return Err(1); }\n"
                "    return Ok(a / b);\n"
                "}\n"
                "i32 main() {\n"
                "    divide(10, 2);\n"
                "    return 0;\n"
                "}\n")
    _, log = ctx.run([VM_EXE, "--vesta", vx, "-o", ctx.path("mh")])
    if os.path.exists(ctx.path("mh.velb")):
        ctx.fail("must-handle: la compilacion debio fallar pero produjo .velb", log)
    if not re.search(r"Result.*debe ser manejado", log):
        ctx.fail("must-handle: no se reporto el error esperado", log)
    ctx.ok("Result ignorado en expression-statement rechazado en compile time")


@case("sync")
def _(ctx):
    """39. synchronized basico: el .vel debe emitir gchandle+monenter+monexit."""
    ctx.compile_vx(ctx.src("35_synchronized_basico.vx"), "sync",
                   extra=["--vx-emit-only"])
    ctx.ok("compilacion 35_synchronized_basico.vx -> .velb")
    vel = read_text(ctx.path("sync.vel"))
    if "gchandle " not in vel:
        ctx.fail("synchronized: el .vel no contiene 'gchandle' "
                 "(debio emitirse antes de monenter)")
    if "monenter " not in vel:
        ctx.fail("synchronized: el .vel no contiene 'monenter'")
    if "monexit " not in vel:
        ctx.fail("synchronized: el .vel no contiene 'monexit'")
    _, log = ctx.run_velb("sync")
    got = get_r00(log)
    if got != 10:
        ctx.fail("synchronized: R00 == %s, se esperaba 10" % got, log)
    check_lasterr(ctx, log, "synchronized")
    ctx.ok("synchronized(this) loop 10x increment + read -> R0 = 10  "
           "(gchandle+monenter+monexit, LastErr=0)")


@case("sthrow")
def _(ctx):
    """40. synchronized + exception safety: monexit antes de propagar."""
    _inline_r0(ctx, "36b_sync_throw_simple.vx", "sthrow", 1007,
               "synchronized+throw",
               "synchronized + throw + outer try/catch -> R0 = 1007 "
               "(monexit en handler implicito)", lasterr=False)


@case("sret")
def _(ctx):
    """41. synchronized + return safety: cleanup_stack antes del RET."""
    _inline_r0(ctx, "37_synchronized_return.vx", "sret", 6,
               "synchronized+return",
               "synchronized + return temprano -> R0 = 6 (cleanup_stack correctamente)",
               lasterr=False)


@case("sex")
def _(ctx):
    """42. synchronized + exception safety EXTENDED (lock+rethrow+2do sync)."""
    _inline_r0(ctx, "36_synchronized_exception.vx", "sex", 104,
               "synchronized+rethrow+continue",
               "synchronized + throw capturado + 2 invocaciones extras -> R0 = 104",
               lasterr=False)


@case("spw")
def _(ctx):
    """43. spawn basico: parent crea hijo con spawn { ... }, recibe PID."""
    _inline_r0(ctx, "38_spawn_basico.vx", "spw", 100, "spawn basico",
               "spawn { body } devuelve PID valido (parent retorna 100)",
               lasterr=False)


@case("spr")
def _(ctx):
    """44. spawn + IPC unidireccional: hijo envia, padre recibe."""
    _inline_r0(ctx, "39b_spawn_recv_only.vx", "spr", 555, "spawn recv-only",
               "hijo envia 555 -> padre recibe via msgrecv() -> R0 = 555",
               lasterr=False)


@case("pp")
def _(ctx):
    """45. Ping-pong padre-hijo bidireccional."""
    _inline_r0(ctx, "39_spawn_pingpong.vx", "pp", 777, "ping-pong",
               "ping-pong padre <-> hijo via pid()/msgsend/msgrecv -> R0 = 777",
               lasterr=False)


@case("fut")
def _(ctx):
    """46. future + spawn + fulfill + await cross-process."""
    _inline_r0(ctx, "40_future_basico.vx", "fut", 42, "future cross-process",
               "future_alloc + spawn + fulfill + await cross-process -> R0 = 42",
               lasterr=False)


@case("asy")
def _(ctx):
    """47. @Async sugar: wrapper + helper __async_compute + await."""
    ctx.compile_vx(ctx.src("41_async_basico.vx"), "asy",
                   extra=["--vx-emit-only"])
    ctx.ok("compilacion 41_async_basico.vx -> .velb")
    if "__async_compute" not in read_text(ctx.path("asy.vel")):
        ctx.fail("@Async: el .vel no contiene el helper '__async_compute'")
    _, log = ctx.run_velb("asy")
    got = get_r00(log)
    if got != 42:
        ctx.fail("@Async: R00 == %s, se esperaba 42" % got, log)
    ctx.ok("@Async + await sugar -> R0 = 42 (wrapper + __async_compute helper "
           "+ return interception)")


@case("prop")
def _(ctx):
    """48. Propiedades (getter + setter) y @Inline -> R0 = 30."""
    ctx.compile_vx(ctx.src("42_propiedades_basico.vx"), "prop",
                   extra=["--vx-emit-only"])
    ctx.ok("compilacion 42_propiedades_basico.vx -> .velb")
    vel = read_text(ctx.path("prop.vel"))
    if "Caja__get_valor:" not in vel:
        ctx.fail("properties: el .vel no contiene 'Caja__get_valor'")
    if "Caja__set_valor:" not in vel:
        ctx.fail("properties: el .vel no contiene 'Caja__set_valor'")
    _, log = ctx.run_velb("prop")
    got = get_r00(log)
    if got != 30:
        ctx.fail("properties + @Inline: R00 == %s, se esperaba 30" % got, log)
    ctx.ok("properties (get/set) + @Inline expansion -> R0 = 30")


@case("par")
def _(ctx):
    """49. Paralelismo OS-thread real: mismo resultado con 1 y 4 schedulers."""
    ctx.compile_vx(ctx.src("43_paralelismo_real.vx"), "par")
    ctx.ok("compilacion 43_paralelismo_real.vx -> .velb")
    _, log = ctx.run_velb("par", schedulers=1)
    got = get_r00(log)
    if got != 2002000:
        ctx.fail("paralelismo (1 sched): R00 == %s, se esperaba 2002000" % got, log)
    ctx.ok("4 hijos suma=2002000 con --schedulers 1 (cooperativo)")
    _, log = ctx.run_velb("par", schedulers=4)
    got = get_r00(log)
    if got != 2002000:
        ctx.fail("paralelismo (4 scheds): R00 == %s, se esperaba 2002000" % got, log)
    ctx.ok("4 hijos suma=2002000 con --schedulers 4 (paralelismo OS-thread real)")


@case("place")
def _(ctx):
    """50. spawn placement (Auto / Here / Pinned) -> 1000 con 1 y 4 scheds."""
    ctx.compile_vx(ctx.src("45_spawn_placement.vx"), "place",
                   extra=["--vx-emit-only"])
    ctx.ok("compilacion 45_spawn_placement.vx -> .velb")
    vel = read_text(ctx.path("place.vel"))
    if not grep_q(vel, r"^    spawn r"):
        ctx.fail("placement: el .vel no contiene la instruccion 'spawn r' (Auto)")
    if "spawnon" not in vel:
        ctx.fail("placement: el .vel no contiene la instruccion 'spawnon' (Here/Pinned)")
    _, log = ctx.run_velb("place", schedulers=1)
    got = get_r00(log)
    if got != 1000:
        ctx.fail("placement (1 sched): R00 == %s, se esperaba 1000" % got, log)
    ctx.ok("placement Auto/Here/Pinned con --schedulers 1 -> R0 = 1000")
    _, log = ctx.run_velb("place", schedulers=4)
    got = get_r00(log)
    if got != 1000:
        ctx.fail("placement (4 scheds): R00 == %s, se esperaba 1000" % got, log)
    ctx.ok("placement Auto/Here/Pinned con --schedulers 4 -> R0 = 1000")


@case("here")
def _(ctx):
    """51. spawn here observable: 100 con 1 sched, 200 con 4 scheds."""
    ctx.compile_vx(ctx.src("46_spawn_here_observable.vx"), "here")
    ctx.ok("compilacion 46_spawn_here_observable.vx -> .velb")
    _, log = ctx.run_velb("here", schedulers=1)
    got = get_r00(log)
    if got != 100:
        ctx.fail("spawn here (1 sched): R00 == %s, se esperaba 100 (mismo sched)"
                 % got, log)
    ctx.ok("spawn here vs Auto con --schedulers 1 -> ambos en sched 0 (R0=100)")
    _, log = ctx.run_velb("here", schedulers=4)
    got = get_r00(log)
    if got != 200:
        ctx.fail("spawn here (4 scheds): R00 == %s, se esperaba 200 (distintos sched)"
                 % got, log)
    ctx.ok("spawn here vs Auto con --schedulers 4 -> distintos schedulers (R0=200)")


@case("rs")
def _(ctx):
    """52. rspawn frontend: bytecode + helper con return interception."""
    ctx.compile_vx(ctx.src("47_rspawn_basico.vx"), "rs",
                   extra=["--vx-emit-only"])
    ctx.ok("compilacion 47_rspawn_basico.vx -> .velb")
    vel = read_text(ctx.path("rs.vel"))
    if "rspawn r" not in vel:
        ctx.fail("rspawn: el .vel no contiene la instruccion 'rspawn r'")
    if "__rspawn_0:" not in vel:
        ctx.fail("rspawn: el .vel no contiene el helper '__rspawn_0:'")
    # awk '/^__rspawn_0:/,/^__rspawn_0_ret:/' -> rango de lineas entre ambos.
    body = []
    inside = False
    for ln in vel.split("\n"):
        if ln.startswith("__rspawn_0:"):
            inside = True
        if inside:
            body.append(ln)
        if inside and ln.startswith("__rspawn_0_ret:"):
            break
    body = "\n".join(body)
    if "mov r0," not in body:
        ctx.fail("rspawn: el helper __rspawn_0 no contiene 'mov r0, <reg>'")
    if "hlt" not in body:
        ctx.fail("rspawn: el helper __rspawn_0 no contiene 'hlt' "
                 "(interception del return)")
    ctx.ok("rspawn emite bytecode + helper con return interception")
    _, log = ctx.run_velb("rs", schedulers=1)
    hx = get_r00_hex(log)
    if hx not in ("0x00000000ffffffff", "0xffffffff", "0xffffffffffffffff"):
        ctx.fail("rspawn local: R00 == %s, se esperaba 0xFFFFFFFF "
                 "(handle invalido sin nodo remoto)" % hx, log)
    ctx.ok("rspawn en modo no-distribuido devuelve handle invalido (0xFFFFFFFF)")


@case("loadmod", serial=True)
def _(ctx):
    """53+54. loadmodule: failure path + carga real del plugin.

    Los dos tests del .sh se fusionan en un unico caso SERIAL porque comparten
    una ruta GLOBAL fija (<raiz>/_test_plugin.velb) que el caller lleva
    hardcodeada: no pueden correr en paralelo ni entre si ni con nadie que
    toque ese fichero.
    """
    plugin_global = os.path.join(ROOT, "_test_plugin.velb")

    # -- 53: path inexistente -> load failure -> R0 = 0.
    if os.path.exists(plugin_global):
        os.remove(plugin_global)
    ctx.compile_vx(ctx.src("49_loadmodule_caller.vx"), "lm",
                   extra=["--vx-emit-only"])
    ctx.ok("compilacion 49_loadmodule_caller.vx -> .velb")
    if "loadmod r" not in read_text(ctx.path("lm.vel")):
        ctx.fail("loadmodule: el .vel no contiene la instruccion 'loadmod r'")
    ctx.ok("loadmodule emite bytecode loadmod")
    _, log = ctx.run_velb("lm", schedulers=1)
    got = get_r00(log)
    if got != 0:
        ctx.fail("loadmodule failure path: R00 == %s, se esperaba 0 (file not found)"
                 % got, log)
    ctx.ok("loadmodule con path inexistente -> load failure -> R0 = 0 (rama esperada)")

    # -- 54: carga real del plugin SIN --vx-base (rebase transparente).
    try:
        ctx.compile_vx(ctx.src("48_loadmodule_plugin.vx"), "plugin")
        shutil.copyfile(ctx.path("plugin.velb"), plugin_global)
        ctx.ok("compilacion plugin sin flags (rebase transparente via reloc table)")
        ctx.compile_vx(ctx.src("49_loadmodule_caller.vx"), "xmod")
        _, log = ctx.run_velb("xmod", schedulers=1)
        got = get_r00(log)
        if got != 100:
            ctx.fail("cross-module: R00 == %s, se esperaba 100 "
                     "(loadmodule + forName OK)" % got, log)
        ctx.ok("cross-module loadmodule + forName(PluginGreeter) -> R0 = 100")
    finally:
        if os.path.exists(plugin_global):
            os.remove(plugin_global)


# ===========================================================================
# Bloques a medida (interleavados con los helpers segun la linea del .sh).
# ===========================================================================

def _bug_dir(name):
    """Directorio de un test de tests/bugs/ (los usa la bateria de  M)."""
    return os.path.join(ROOT, "tests", "bugs", name)


def _rm(*paths):
    for p in paths:
        try:
            if os.path.isdir(p):
                shutil.rmtree(p, ignore_errors=True)
            elif os.path.exists(p):
                os.remove(p)
        except OSError:
            pass


def _rm_glob(directory, *patterns):
    import glob as _glob
    for pat in patterns:
        for p in _glob.glob(os.path.join(directory, pat)):
            _rm(p)


def _env(**kw):
    e = os.environ.copy()
    e.update({k: str(v) for k, v in kw.items()})
    return e


def _projects_cache():
    return os.path.join(ROOT, ".vx_cache", "projects")


@case("qs_ir", line=1547)
def _(ctx):
    """63. Validacion IR via --vx-emit-ir (cabeceras pre/post + phi >= 4)."""
    _, log = ctx.run([VM_EXE, "--vesta", ctx.src("58_quicksort.vx"),
                      "--vx-emit-ir", "-o", ctx.path("qs_ir")])
    ir = ctx.path("qs_ir.ir")
    if not os.path.exists(ir):
        ctx.fail("--vx-emit-ir no genero qs_ir.ir", log)
    ctx.ok("--vx-emit-ir genera fichero .ir")
    txt = read_text(ir)
    if "SSA IR pre-optimizacion" not in txt:
        ctx.fail("--vx-emit-ir: no aparece la cabecera 'SSA IR pre-optimizacion'")
    if "SSA IR post-optimizacion" not in txt:
        ctx.fail("--vx-emit-ir: no aparece la cabecera 'SSA IR post-optimizacion'")
    ctx.ok("--vx-emit-ir muestra IR pre y post optimizacion")
    n = grep_c(txt, r"phi\.")
    if n < 4:
        ctx.fail("--vx-emit-ir: solo %d instrucciones phi (esperadas >=4 con loops)" % n)
    ctx.ok("--vx-emit-ir contiene %d instrucciones phi (>=4 esperadas)" % n)


@case("io65", line=1589)
def _(ctx):
    """65. I/O: interpolacion ${...} + flush + builtins."""
    ctx.compile_vx(ctx.src("65_io_format.vx"), "io65")
    ctx.ok("compilacion 65_io_format.vx -> .velb")
    _, log = ctx.run_velb("io65", schedulers=1, stats=False)
    for pat, msg in (
            (r"^Hola desde !", "no aparece 'Hola desde !'"),
            (r"^x=42, y=100", "interpolacion x/y incorrecta"),
            (r"^suma=142", "interpolacion suma incorrecta"),
            (r"^activo=true", "interpolacion bool incorrecta"),
            (r"^FIN", "marcador FIN ausente (flush no funciono?)")):
        if not grep_q(log, pat):
            ctx.fail("io_format: " + msg, log)
    ctx.ok("interpolacion ${...} + flush + builtins de I/O -> output correcto")


@case("col66", line=1622)
def _(ctx):
    """66. Codigos ANSI: al menos 10 bytes ESC en el output."""
    ctx.compile_vx(ctx.src("66_io_colors.vx"), "col66")
    ctx.ok("compilacion 66_io_colors.vx -> .velb")
    args = [VM_EXE, "--run", ctx.path("col66.velb"), "--schedulers", "1"]
    p = subprocess.run(args, capture_output=True)
    # El .sh contaba tokens "033" en un dump `od -An -c`, que equivale a contar
    # bytes ESC (0x1b) en la salida.
    n = p.stdout.count(b"\x1b")
    if n < 10:
        ctx.fail("io_colors: solo %d bytes ESC (esperados >=10)" % n,
                 p.stdout.decode("utf-8", "replace"))
    ctx.ok("codigos ANSI emitidos (%d bytes ESC en output)" % n)


EXPECT77 = [
    "i8=-1", "i64=-9000000000", "u64=18000000000000000000", "bool=true",
    "char_code=65", "c=Hola mundo", "latin: bytes=13 cps=11",
    "griego: bytes=6 cps=3", "cjk: bytes=6 cps=2", "emoji: bytes=8 cps=2",
    "mix.bytes=21", "s1==s2: true", "s1==s3: false", "s1!=s3: true",
    r"empty\[\] bytes=0 cps=0", "suma=30 producto=200 resto=2", "triple=42",
    "pi=3.14", r"pi\+e=5.85", r"pi\*2=6.28", "pi/e=1.15867",
]


@case("strex77", line=1675)
def _(ctx):
    """76. Strings exhaustivo: escalares + UTF-8 multi-alfabeto + emoji."""
    ctx.compile_vx(ctx.src("76_string_exhaustive.vx"), "strex77")
    ctx.ok("compilacion 76_string_exhaustive.vx -> .velb")
    args = [VM_EXE, "--run", ctx.path("strex77.velb"),
            "--schedulers", "1", "--stats"]
    p = subprocess.run(args, capture_output=True)
    raw = p.stdout + p.stderr
    log = raw.decode("utf-8", "replace")
    got = get_r00(log)
    if got != 42:
        ctx.fail("string exhaustivo: R00=%s (esperado 42)" % got, log)
    expect_lines(ctx, log, "string exhaustivo", EXPECT77)
    # Verificacion de bytes UTF-8 sobre el volcado hex de la salida.
    hexs = raw.hex()
    if not any(g in hexs for g in ("cebacecbcec", "cebacebbcec",
                                   "cebacebbcebc", "ceb1ceb2ceb3")):
        if "ceb1" not in hexs:
            ctx.fail("string exhaustivo: bytes UTF-8 (alpha=ceb1) no encontrados "
                     "en output")
    if "f09f9880" not in hexs:
        ctx.fail("string exhaustivo: bytes emoji (F0 9F 98 80) no encontrados")
    ctx.ok("string exhaustivo (escalares + UTF-8 multi-alfabeto + emoji) -> R0 = 42")


EXPECT78 = [
    "pi=3.14", "e=2.71", "sum=5.85", "dif=0.43", "mul=8.5094", "div=1.15867",
    "c_sum=3.75", "c_mul=2", "chain=6.85", "pi>e=true", "pi<e=false",
    "pi==3.14=true", "dir=1", "nf=7", "doubled=14", r"trunc\(3.95\)=3",
    "roundtrip=42",
]


@case("fa78", line=1740)
def _(ctx):
    """77. Float arith: FADD/FSUB/FMUL/FDIV + FCMP + FTOI/ITOF."""
    ctx.compile_vx(ctx.src("77_float_arith.vx"), "fa78")
    ctx.ok("compilacion 77_float_arith.vx -> .velb")
    _, log = ctx.run_velb("fa78", schedulers=1)
    got = get_r00(log)
    if got != 42:
        ctx.fail("float arith: R00=%s (esperado 42)" % got, log)
    expect_lines(ctx, log, "float arith", EXPECT78)
    ctx.ok("float arith (FADD/FSUB/FMUL/FDIV + FCMP + FTOI/ITOF) -> R0 = 42")


EXPECT79 = ["c=3.75", "d=1.5", "small=1.23457", "nf=7", "ti=3", "back=42",
            "chain=5.25"]


@case("f79", line=1785)
def _(ctx):
    """78. f32 full: arith + fextend + fnarrow + cvt + interp."""
    ctx.compile_vx(ctx.src("78_f32_full.vx"), "f79")
    ctx.ok("compilacion 78_f32_full.vx -> .velb")
    _, log = ctx.run_velb("f79", schedulers=1)
    got = get_r00(log)
    if got != 42:
        ctx.fail("f32 full: R00=%s (esperado 42)" % got, log)
    expect_lines(ctx, log, "f32 full", EXPECT79)
    ctx.ok("f32 full (arith + fextend + fnarrow + cvt + interp) -> R0 = 42")


@case("tq81", line=1824)
def _(ctx):
    """80. Strings triple-quoted (multilinea + escapes)."""
    ctx.compile_vx(ctx.src("80_triple_quoted.vx"), "tq81")
    ctx.ok("compilacion 80_triple_quoted.vx -> .velb")
    _, log = ctx.run_velb("tq81", schedulers=1)
    got = get_r00(log)
    if got != 42:
        ctx.fail("triple-quoted: R00=%s (esperado 42)" % got, log)
    expect_lines(ctx, log, "triple-quoted",
                 ["^linea1$", "^linea2$", "^linea3$", "DEF", "comillas"])
    ctx.ok("strings triple-quoted (multilinea + escapes) -> R0 = 42")


@case("illegal96b", line=1939)
def _(ctx):
    """96b. Rechazo de escape ilegal de un Resource con destructor."""
    _, log = ctx.run([VM_EXE, "--vesta",
                      ctx.src("96b_destructor_illegal_escape.vx"),
                      "-o", ctx.path("illegal96b")])
    if not re.search(r"tiene destructor.*no puede asignarse", log):
        ctx.fail("A.31 no rechazo el caso ilegal o mensaje cambio", log)
    ctx.ok("A.31 rechaza asignacion ilegal de Resource a field con error claro")


# ---  M: bateria sobre tests/bugs/*.  Todos comparten directorios FIJOS
#     del repo, por lo que van SERIAL (el .sh los corria en secuencia y varios
#     reutilizan el mismo directorio, p.ej. m6_test lo usan M6, M5.B y M5.C).

@case("ns_partial_id")
def _(ctx):
    """Namespace PARCIAL: un tipo debe tener UNA identidad, venga del fichero
    que venga.

    `namespace pt.core;` lo declaran DOS ficheros.  El resolver devuelve el
    primero que encuentra escaneando el disco, y los simbolos importados se
    cualificaban con el nombre de ESE FICHERO -- asi que el mismo typedef
    entraba como `base__handle` o como `extra__handle` segun quien ganase, y
    luego no unificaba consigo mismo.  Se veia en la stdlib: `std.types` lo
    declaran types.vx + types/arm64.vx + types/x86_64.vx, y `uintptr` resolvia
    unas veces a `arm64__uintptr` y otras a `std__types__uintptr`.

    Aqui el tipo se DECLARA en un fichero y se CONSUME en el otro: si las dos
    identidades no coinciden, `to_raw(mk())` no pasa el chequeo de tipos.
    """
    def w(name, txt):
        with open(ctx.path(name), "w", encoding="utf-8") as f:
            f.write(txt)

    w("base.vx",
      "namespace pt.core;\n"
      "public typedef u64 handle new;\n"
      "public handle mk() { return (handle) 20; }\n")
    # SEGUNDO fichero del MISMO namespace, que usa el tipo del primero.
    w("extra.vx",
      "namespace pt.core;\n"
      "public u64 to_raw(handle h) { return (u64) h; }\n")
    w("main.vx",
      "namespace pt.app;\n"
      "import pt.core only *;\n"
      "i32 main() { return (i32) (to_raw(mk()) + 22); }\n")

    if not ctx.compile_vx(ctx.path("main.vx"), "nspid"):
        return
    _, log = ctx.run_velb("nspid", schedulers=1, mode="vm")
    got = get_r00(log)
    if got != 42:
        ctx.fail("namespace parcial: R00 == %s, se esperaba 42 (el tipo del "
                 "namespace tiene identidades distintas segun el fichero)" %
                 got, log)
        return
    ctx.ok("namespace parcial: identidad unica del tipo -> R0 = 42")


@case("ns_cobertura")
def _(ctx):
    """Cobertura de namespaces: declaracion, acceso cualificado y parciales.

    Tres cosas que deben convivir sin pisarse:

      1. DOS namespaces distintos declaran un simbolo con el MISMO nombre
         corto (`value`).  No es una colision: el namespace forma parte de la
         identidad, y el acceso cualificado los distingue.
      2. Acceso CUALIFICADO via alias (`import ... as A` -> `A.value()`), que
         es la forma en que un import plano expone lo que trae.
      3. Namespace PARCIAL: `app.alpha` esta declarado en DOS ficheros y los
         simbolos de ambos deben verse como del mismo namespace, incluido un
         tipo declarado en un fichero y usado en el otro.

    10 (alpha) + 20 (beta) + 12 (la parte partida de alpha) = 42.
    """
    def w(name, txt):
        with open(ctx.path(name), "w", encoding="utf-8") as f:
            f.write(txt)

    w("nalpha.vx",
      "namespace app.alpha;\n"
      "public typedef u64 tag new;\n"
      "public i32 value() { return 10; }\n")
    # SEGUNDO fichero del MISMO namespace: usa el tipo declarado en el primero
    # tanto en la firma como en un CAST (`(tag) 10`).  El cast es la parte
    # delicada: el parser tiene que saber que `tag` es un tipo para no leer
    # `(tag)` como una expresion entre parentesis, y ese nombre vive en el
    # fichero de al lado, no en este.
    w("nalpha2.vx",
      "namespace app.alpha;\n"
      "public i32 extra(tag t) { return (i32) ((u64) t + 2); }\n"
      "public tag mktag() { return (tag) 10; }\n")
    # Namespace DISTINTO con un simbolo del mismo nombre corto.
    w("nbeta.vx",
      "namespace app.beta;\n"
      "public i32 value() { return 20; }\n")
    w("main.vx",
      "namespace app.main;\n"
      "import app.alpha as A;\n"
      "import app.beta as B;\n"
      "i32 main() {\n"
      "    return A.value() + B.value() + A.extra(A.mktag());\n"
      "}\n")

    if not ctx.compile_vx(ctx.path("main.vx"), "nscov"):
        return
    _, log = ctx.run_velb("nscov", schedulers=1, mode="vm")
    got = get_r00(log)
    if got != 42:
        ctx.fail("cobertura de namespaces: R00 == %s, se esperaba 42" % got, log)
        return
    ctx.ok("namespaces: mismo nombre en ns distintos + cualificado + parcial "
           "-> R0 = 42")


def modulo_case(tag, carpeta, expected, line=None):
    """Un ejemplo de VARIOS ficheros: se compila su `main.vx` y se ejecuta.

    Estos viven en subcarpetas de `examples_codes_vx/` porque son modulos, no
    ficheros sueltos, y por eso se les escapaban a las dos redes: la suite los
    referenciaba por nombre y estos no tienen entrada propia, y el porton de
    compilacion (`corpus_compila.py`) excluye las subcarpetas a proposito --
    sus ficheros NO compilan por separado, solo a traves del `main.vx`.

    Resultado: toda la superficie de namespaces y de modulos -- doce ejemplos
    que funcionan -- no la guardaba nadie.  Funcionar hoy y no estar cubierto es
    estar a un refactor de romperse en silencio.

    Se comprueba en interprete Y en JIT: un modulo que resuelve bien al
    interpretarlo puede resolver mal compilado.
    """
    def fn(ctx):
        if not ctx.compile_vx(ctx.src(carpeta + "/main.vx"), tag):
            return
        for modo in ("vm", "jit"):
            _, log = ctx.run_velb(tag, schedulers=1, mode=modo)
            got = get_r00(log)
            if got != expected:
                ctx.fail("%s (-m %s): R00 == %s, se esperaba %d"
                         % (carpeta, modo, got, expected), log)
                return
            ctx.ok("%s (-m %s) -> R0 = %d" % (carpeta, modo, expected))
    fn.__name__ = "case_" + tag
    _register(tag, fn, False, line)


# Los ejemplos de VARIOS ficheros.  Todos llegan a 42 por caminos distintos --
# es la convencion del corpus -- asi que el numero no es una casualidad que se
# congela: es la respuesta que el ejemplo dice que va a dar.
modulo_case("mod_import_selectivo", "ns_import_selectivo", 42)
modulo_case("mod_import_by_namespace", "ns_import_by_namespace", 42)
modulo_case("mod_ns_internal", "ns_internal", 42)
modulo_case("mod_ns_stdlib", "ns_stdlib", 42)
modulo_case("mod_ns_impl", "ns_impl", 42)
modulo_case("mod_ns_impl_inherente", "ns_impl_inherente", 42)
modulo_case("mod_ns_concept", "ns_concept", 42)
modulo_case("mod_ns_comptime", "ns_comptime", 42)
modulo_case("mod_ns_cross_types", "ns_cross_types", 42)
modulo_case("mod_ns_interpolation", "ns_interpolation", 42)
modulo_case("mod_ns_xmod_comptime", "ns_xmod_comptime", 42)
modulo_case("mod_ns_xmod_concept", "ns_xmod_concept", 42)
modulo_case("mod_generic_fn_infer", "generic_fn_infer", 42)


def _resumen_aot(salida):
    """Lee la linea de resumen de `tests/aot/run_all.py`.

    Devuelve (ok, fallidos, saltados) o None si no aparecio -- que ya es un
    fallo: significa que el lanzador no llego a terminar.
    """
    m = re.search(r"tests/aot en '(\w+)': (\d+) OK, (\d+) fallidos, (\d+) saltados",
                  salida)
    if not m:
        return None
    return (int(m.group(2)), int(m.group(3)), int(m.group(4)))


@case("aot_harness", serial=True)
def _(ctx):
    """Los tests de `tests/aot/`, enganchados a la suite que decide.

    Son 26 comprobaciones del camino NATIVO -- enlazador propio, archivador,
    secciones, sectores de arranque, TLS, POO nativa, ancho SIMD, excepciones,
    despacho por CPU -- que hasta ahora solo se lanzaban a mano, una a una.  Por
    eso nadie sabia como estaban: al correrlas en tanda por primera vez fallaban
    15 de 26, y dentro habia fallos REALES del producto vivos desde hacia meses.

    No los cubre nada mas: la e2e compila los ejemplos de `aot/` como mucho,
    pero no enlaza con nuestro enlazador ni ejecuta el resultado ni pasa
    valgrind, que es donde salieron.

    Se corren los DOS lados, cada uno donde se puede:

      - el de aqui, siempre;
      - el de Linux, si hay WSL Y un build de Linux hecho.  Sin eso se SALTA
        dejando constancia, nunca un falso OK -- misma regla que el resto de
        casos que dependen de WSL.
    """
    build = os.path.dirname(VM_EXE)
    runner = os.path.join(ROOT, "tests", "aot", "run_all.py")
    if not os.path.isfile(runner):
        ctx.fail("no encuentro tests/aot/run_all.py")
        return

    # --- el lado de aqui ---
    _, log = ctx.run([sys.executable, runner, build], timeout=2400)
    r = _resumen_aot(log)
    if r is None:
        ctx.fail("tests/aot (lado local): el lanzador no dio resumen", log)
        return
    ok_n, mal_n, salt_n = r
    if mal_n:
        fallos = "\n".join(l for l in log.splitlines() if "FALLA" in l)
        ctx.fail("tests/aot (lado local): %d fallidos" % mal_n, fallos or log)
        return
    ctx.ok("tests/aot (lado local): %d OK, %d saltados" % (ok_n, salt_n))

    # --- el lado de Linux ---
    if not wsl_disponible():
        ctx.skip("tests/aot (lado linux): WSL no disponible, no se ejecuta")
        return
    # El build de Linux lo deja ahi el empaquetado (`installer-linux`).  Si no
    # esta, no es un fallo: es que en esta maquina no se ha construido.
    sonda = subprocess.run(
        ["wsl.exe", "-e", "sh", "-c",
         "test -x $HOME/.cache/vesta/linux-build/vm && echo hay"],
        capture_output=True, timeout=120)
    if b"hay" not in (sonda.stdout or b""):
        ctx.skip("tests/aot (lado linux): no hay build de Linux "
                 "(~/.cache/vesta/linux-build); construyelo con "
                 "`cmake --build <build> --target installer-linux`")
        return
    # La raiz se traduce con `wslpath`, que es quien sabe como esta montado
    # cada disco; escribir `/mnt/f/...` da por hecho un punto de montaje y una
    # maquina concretos.
    r2 = subprocess.run(
        ["wsl.exe", "-e", "sh", "-c",
         "cd \"$(wslpath -a '%s')\" && "
         "python3 tests/aot/run_all.py $HOME/.cache/vesta/linux-build"
         % ROOT.replace("\\", "/")],
        capture_output=True, text=True, errors="replace", timeout=2400)
    salida = (r2.stdout or "") + (r2.stderr or "")
    r = _resumen_aot(salida)
    if r is None:
        ctx.fail("tests/aot (lado linux): el lanzador no dio resumen", salida)
        return
    ok_n, mal_n, salt_n = r
    if mal_n:
        fallos = "\n".join(l for l in salida.splitlines() if "FALLA" in l)
        ctx.fail("tests/aot (lado linux): %d fallidos" % mal_n, fallos or salida)
        return
    ctx.ok("tests/aot (lado linux): %d OK, %d saltados" % (ok_n, salt_n))


@case("syscalls_linux_wsl")
def _(ctx):
    """La rama LINUX de las syscalls, compilada a ELF y EJECUTADA en WSL.

    En Windows solo se ejercita la mitad NT del ejemplo; la de Linux se elegia
    con @Target y nunca llegaba a correr, asi que podia estar rota sin que
    nadie se enterase -- y lo estaba: `mmap` recibia los argumentos en los
    registros equivocados y el proceso moria.

    El AOT evalua @Target contra el TARGET, no contra el host, asi que desde
    aqui se puede generar el ELF de Linux; WSL lo ejecuta.  Sin WSL el caso se
    salta (dejando constancia), pero NUNCA da un falso OK.
    """
    src = os.path.join(VX_DIR, "342_syscalls_os.vx")
    elf = aot_build(ctx, src, "s342_elf", "syscalls linux", fmt="elf")
    if not elf:
        ctx.fail("no se genero el ELF de la rama linux", ctx.last_aot_log)
        return
    if not wsl_disponible():
        ctx.skip("rama linux de syscalls: WSL no disponible, no se ejecuta")
        return
    rc, salida = wsl_run_elf(elf)
    if rc is None:
        ctx.fail("rama linux de syscalls: %s" % salida, ctx.last_aot_log)
        return
    if rc != 42:
        ctx.fail("rama linux de syscalls: exit %s, se esperaba 42\n%s"
                 % (rc, salida), ctx.last_aot_log)
        return
    if "7/7" not in salida:
        ctx.fail("rama linux de syscalls: no se completaron los 7 pasos\n%s"
                 % salida, ctx.last_aot_log)
        return
    ctx.ok("rama linux: 7 syscalls reales (getpid/mmap/open/write/close/"
           "munmap) en WSL -> 42")


@case("syscalls_linux_wsl_x86_32")
def _(ctx):
    """Lo mismo que el caso anterior pero en x86-32, ejecutado en WSL.

    Esta arquitectura no se ejecutaba NUNCA -- ni siquiera producia binario --,
    asi que acumulaba fallos que solo se ven corriendo: un `mov reg, imm64` que
    en modo protegido no existe, literales empaquetados de ocho en ocho, el
    detector de CPU emitido con registros de 64, y los argumentos que no caben
    en registro leidos con el paso equivocado.

    Que pase aqui prueba de una vez la convencion `int 0x80`, `old_mmap` (la
    entrada que i386 usa porque no tiene registros para seis argumentos) y el
    paso de argumentos por pila.
    """
    src = os.path.join(VX_DIR, "342_syscalls_os.vx")
    rc, log = ctx.run([VM_EXE, "-m", "aot", "--vesta", src,
                       "--aot-arch", "x86-32", "--format", "elf",
                       "--emit", "exe", "-o", ctx.path("s342_x32")])
    elf = ctx.path("s342_x32")
    if not os.path.exists(elf):
        ctx.fail("no se genero el ELF de 32 bits", log)
        return
    if not wsl_disponible():
        ctx.skip("syscalls x86-32: WSL no disponible, no se ejecuta")
        return
    rc2, salida = wsl_run_elf(elf)
    if rc2 is None:
        ctx.fail("syscalls x86-32: %s" % salida, log)
        return
    if rc2 != 42 or "7/7" not in salida:
        ctx.fail("syscalls x86-32: exit %s\n%s" % (rc2, salida), log)
        return
    ctx.ok("x86-32: 7 syscalls reales por int 0x80 (con old_mmap) en WSL -> 42")


@case("target_diag")
def _(ctx):
    """Usar un simbolo que solo existe para OTRO objetivo lo dice.

    Una decl con `@Target` que no se cumple se descarta sin parsear, asi que
    quien la use recibia "funcion no declarada" -- que es falso: la funcion
    esta declarada, solo que para otra plataforma.  Y encima el tipo vacio del
    fallo arrastraba un segundo error sobre el retorno.

    Se comprueban las dos formas del diagnostico (una variante y varias) por su
    CODIGO del catalogo, no por el texto, que depende del idioma.  Y que sea el
    UNICO error: la cascada tambien era parte del problema.
    """
    def w(name, txt):
        with open(ctx.path(name), "w", encoding="utf-8") as f:
            f.write(txt)

    # Una sola variante, de otro objetivo -> VX4001.
    w("tlib.vx",
      "namespace t.lib;\n"
      "@Target(\"os:linux\")\n"
      "public i32 solo_linux() { return 1; }\n"
      "@Target(\"os:windows\")\n"
      "public i32 solo_win() { return 2; }\n")
    w("tmain.vx",
      "namespace t.main;\n"
      "import t.lib only *;\n"
      "i32 main() { return solo_linux(); }\n")

    _, log = ctx.compile_vx(ctx.path("tmain.vx"), "tdiag1", must_succeed=False)
    if "VX4001" not in log:
        ctx.fail("simbolo de otro objetivo: se esperaba VX4001", log)
        return
    if "no declarada" in log:
        ctx.fail("simbolo de otro objetivo: sigue diciendo 'no declarada'", log)
        return
    if log.count("error:") != 1:
        ctx.fail("simbolo de otro objetivo: %d errores, se esperaba 1 (cascada)"
                 % log.count("error:"), log)
        return
    ctx.ok("simbolo de otro objetivo -> VX4001, sin cascada")

    # Varias variantes, ninguna de este objetivo -> VX4002.
    w("tlib2.vx",
      "namespace t.lib2;\n"
      "@Target(\"os:linux\")\n"
      "public i32 solo_otros() { return 1; }\n"
      "@Target(\"os:macos\")\n"
      "public i32 solo_otros() { return 2; }\n")
    w("tmain2.vx",
      "namespace t.main2;\n"
      "import t.lib2 only *;\n"
      "i32 main() { return solo_otros(); }\n")

    _, log2 = ctx.compile_vx(ctx.path("tmain2.vx"), "tdiag2", must_succeed=False)
    if "VX4002" not in log2:
        ctx.fail("varias variantes de otros objetivos: se esperaba VX4002", log2)
        return
    ctx.ok("varias variantes de otros objetivos -> VX4002")

    # El mensaje sale en el idioma pedido: es el catalogo quien lo produce.
    _, log3 = ctx.compile_vx(ctx.path("tmain.vx"), "tdiag3", must_succeed=False,
                             env={"VESTA_LANG": "es"})
    if "esta declarado con @Target" not in log3:
        ctx.fail("VX4001 no salio en espanol con VESTA_LANG=es", log3)
        return
    ctx.ok("VX4001 sale por catalogo multi-idioma (es)")


@case("reexport_chain")
def _(ctx):
    """Re-export encadenado: la identidad de un tipo no puede acumular prefijos.

    `main` importa `ch.top`, que re-exporta `ch.mid`, que re-exporta `ch.base`.
    El tipo se declara en `ch.base` y se consume en `main`, tres saltos mas
    arriba.

    Si en cada salto se vuelve a cualificar el nombre en vez de transportar la
    identidad original, el tipo termina como
    `ch__top__ch__mid__ch__base__handle` y deja de unificar consigo mismo.  La
    suite NO tenia ningun caso con cadena de re-exports, asi que un cambio que
    introducia justo ese doble prefijado pasaba los 782 pasos sin enterarse.
    """
    def w(name, txt):
        with open(ctx.path(name), "w", encoding="utf-8") as f:
            f.write(txt)

    w("cbase.vx",
      "namespace ch.base;\n"
      "public typedef u64 handle new;\n"
      "public handle mk() { return (handle) 20; }\n")
    w("cmid.vx",
      "namespace ch.mid;\n"
      "public import ch.base;\n")
    w("ctop.vx",
      "namespace ch.top;\n"
      "public import ch.mid;\n")
    w("main.vx",
      "namespace ch.app;\n"
      "import ch.top only *;\n"
      "i32 main() { handle h = mk(); return (i32) ((u64) h + 22); }\n")

    if not ctx.compile_vx(ctx.path("main.vx"), "rxch"):
        return
    _, log = ctx.run_velb("rxch", schedulers=1, mode="vm")
    got = get_r00(log)
    if got != 42:
        ctx.fail("re-export encadenado: R00 == %s, se esperaba 42 (la identidad "
                 "del tipo acumula prefijos por cada salto)" % got, log)
        return
    ctx.ok("re-export encadenado (3 saltos): identidad estable -> R0 = 42")


@case("m6", serial=True, line=2407)
def _(ctx):
    """M6: privacidad cross-module + classes con metodos en el .vxi."""
    d = _bug_dir("m6_test")
    if not os.path.exists(os.path.join(d, "main.vx")):
        return
    _rm(*[os.path.join(d, f) for f in
          ("lib.vxi", "lib.vxir", "prog.velb", "prog.vel")])
    _, log = ctx.run([VM_EXE, "--vesta", os.path.join(d, "main.vx"),
                      "-o", os.path.join(d, "prog")])
    if not os.path.exists(os.path.join(d, "prog.velb")):
        ctx.fail("compilacion M6 cross-module no produjo .velb", log)
    ctx.ok("compilacion M6 cross-module (lib.vx + main.vx) -> .velb")
    _, log = ctx.run([VM_EXE, "--run", os.path.join(d, "prog.velb"),
                      "--schedulers", "1", "--stats"])
    got = get_r00(log)
    if got != 42:
        ctx.fail("M6 callvirt cross-module: R00 == %s, se esperaba 42" % got, log)
    ctx.ok("M6 callvirt cross-module (Counter.inc + Counter.add) -> R0 = 42")
    # `strings lib.vxi | grep internal_helper` -> buscar la subcadena cruda.
    if b"internal_helper" in read_bytes(os.path.join(d, "lib.vxi")):
        ctx.fail("M6 privacy: lib.vxi expone 'internal_helper' "
                 "(deberia estar filtrado)")
    ctx.ok("M6 privacy (private internal_helper filtrado del .vxi)")


@case("gxm", serial=True, line=2439)
def _(ctx):
    """Cross-module generics via .vxi + AOT multi-modulo."""
    d = _bug_dir("gen_xmodule_test")
    if not os.path.exists(os.path.join(d, "main.vx")):
        return
    _rm_glob(d, "*.vxi", "*.vxir")
    _rm(os.path.join(d, "prog.velb"), os.path.join(d, "prog.vel"))
    _, log = ctx.run([VM_EXE, "--vesta", os.path.join(d, "main.vx"),
                      "-o", os.path.join(d, "prog")])
    if not os.path.exists(os.path.join(d, "prog.velb")):
        ctx.fail("compilacion cross-module generics no produjo .velb", log)
    _, log = ctx.run([VM_EXE, "--run", os.path.join(d, "prog.velb"),
                      "--schedulers", "1", "--stats"])
    got = get_r00(log)
    if got != 42:
        ctx.fail("cross-module generics: R00 == %s, se esperaba 42" % got, log)
    ctx.ok("cross-module generics (struct/clase/fn/concepto/spec via .vxi) -> R0 = 42")
    # AOT multi-modulo.
    _rm_glob(d, "*.vxi", "*.vxir")
    _rm(os.path.join(d, "gxmaot"), os.path.join(d, "gxmaot.velb"))
    _, log = ctx.run([VM_EXE, "--vesta", os.path.join(d, "main.vx"),
                      "-o", os.path.join(d, "gxmaot"), "-m", "aot",
                      "--format", AOT_FMT, "--emit", "exe"])
    exe = os.path.join(d, "gxmaot")
    if os.path.exists(os.path.join(d, "gxmaot.velb")) or not os.path.exists(exe):
        ctx.fail("AOT cross-module no produjo exe nativo (cayo a .velb?)", log)
    if AOT_FMT == "pe":
        # El .sh ejecutaba ./gxmaot con cwd en el dir del test.
        rc, _ = ctx.run([exe], cwd=d)
        rc = exit_code(rc)
        if rc != 42:
            ctx.fail("AOT cross-module exe nativo exit == %d, se esperaba 42" % rc)
        ctx.ok("AOT cross-module -> exe NATIVO PE (exit 42)")
    else:
        ctx.ok("AOT cross-module -> exe NATIVO ELF generado")
    _rm(os.path.join(d, "gxmaot"), os.path.join(d, "gxmaot.velb"))


@case("m4ext", serial=True, line=2498)
def _(ctx):
    """M4.ext: cache transitivo (cold miss / warm hit / invalidacion)."""
    d = _bug_dir("m4ext_test")
    if not os.path.isdir(d):
        return
    C_ORIG = "public i32 c_value() { return 10; }\n"

    def write(name, txt):
        with open(os.path.join(d, name), "w", encoding="utf-8") as f:
            f.write(txt)

    # El test reescribe fuentes versionadas del repo (el .sh hacia lo mismo con
    # heredocs).  Se guardan los bytes originales y se restauran al final para
    # dejar el working tree exactamente como estaba (incluido el fin de linea:
    # el arbol usa CRLF y escribir LF ensuciaria `git status`).
    originals = {n: read_bytes(os.path.join(d, n))
                 for n in ("c.vx", "b.vx", "main.vx")}

    def restore():
        for n, data in originals.items():
            if data:
                with open(os.path.join(d, n), "wb") as f:
                    f.write(data)

    write("c.vx", C_ORIG)
    write("b.vx", 'import "c" only c_value;\n'
                  "public i32 b_value() { return c_value() + 1; }\n")
    write("main.vx", 'import "b" only b_value;\n'
                     "i32 main() { return b_value() + 31; }\n")
    _rm_glob(d, "*.vxi", "*.vxir")
    _rm(os.path.join(d, "prog.velb"), os.path.join(d, "prog.vel"))
    env = _env(VX_NO_PROJECT_CACHE=1, VX_VERBOSE_CACHE=1)
    try:
        # (a) cold: c.vx y b.vx deben aparecer como miss.
        _, log = ctx.run([VM_EXE, "--vesta", os.path.join(d, "main.vx"),
                          "-o", os.path.join(d, "prog")], env=env)
        if not os.path.exists(os.path.join(d, "prog.velb")):
            ctx.fail("M4.ext cold compile no produjo .velb", log)
        for f in ("c.vx", "b.vx"):
            if not re.search(r"miss: .*" + re.escape(f), log):
                ctx.fail("M4.ext cold: %s no aparecio como miss" % f, log)
        ctx.ok("M4.ext cold compile (c.vx + b.vx = miss + wrote)")
        # (b) warm: ambos hit.
        _, log = ctx.run([VM_EXE, "--vesta", os.path.join(d, "main.vx"),
                          "-o", os.path.join(d, "prog")], env=env)
        for f in ("c.vx", "b.vx"):
            if not re.search(r"hit: .*" + re.escape(f), log):
                ctx.fail("M4.ext warm: %s no aparecio como hit" % f, log)
        ctx.ok("M4.ext warm compile (c.vx + b.vx = hits)")
        # (c) invalidacion transitiva: cambiar la FIRMA de c.
        write("c.vx", "public i32 c_value(i32 base) { return base + 20; }\n")
        _, log = ctx.run([VM_EXE, "--vesta", os.path.join(d, "main.vx"),
                          "-o", os.path.join(d, "prog")], env=env)
        if "miss (transitivo)" not in log:
            ctx.fail("M4.ext: cambio de firma de c no produjo 'miss (transitivo)' "
                     "para b", log)
        ctx.ok("M4.ext invalidacion transitiva (cambio firma c -> miss transitivo b)")
    finally:
        restore()


@case("l789", serial=True, line=2576)
def _(ctx):
    """L.7 + L.8 + L.9: mejoras del formato .vxi (const inline + privacidad)."""
    d = _bug_dir("m_l789_test")
    if not os.path.exists(os.path.join(d, "main.vx")):
        return
    _rm_glob(d, "*.vxi", "*.vxir")
    _rm(os.path.join(d, "prog.velb"), os.path.join(d, "prog.vel"))
    _, log = ctx.run([VM_EXE, "--vesta", os.path.join(d, "main.vx"),
                      "-o", os.path.join(d, "prog")])
    if not os.path.exists(os.path.join(d, "prog.velb")):
        ctx.fail("compilacion L.7+L.8+L.9 no produjo .velb", log)
    _, log = ctx.run([VM_EXE, "--run", os.path.join(d, "prog.velb"),
                      "--schedulers", "1", "--stats"])
    got = get_r00(log)
    if got != 42:
        ctx.fail("L.7 const inline cross-module: R00 == %s, se esperaba 42" % got,
                 log)
    ctx.ok("L.7 const importada (MAX_USERS + MAGIC_OFFSET) -> R0 = 42")
    if b"SECRET_OFFSET" in read_bytes(os.path.join(d, "lib.vxi")):
        ctx.fail("L.7 privacy: SECRET_OFFSET leakea al .vxi")
    ctx.ok("L.7 privacy (private const SECRET_OFFSET filtrado)")


@case("m5a", serial=True, line=2605)
def _(ctx):
    """M5.A: escritura atomica del cache (8 builds concurrentes)."""
    d = _bug_dir("m5_atomic_test")
    if not os.path.exists(os.path.join(d, "main.vx")):
        return
    _rm_glob(d, "*.vxi", "*.vxir", "prog*.velb", "prog*.vel", "*.tmp.*")
    procs = []
    for i in range(1, 9):
        procs.append(subprocess.Popen(
            [VM_EXE, "--vesta", os.path.join(d, "main.vx"),
             "-o", os.path.join(d, "prog_%d" % i)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT))
    for p in procs:
        p.wait()
    bad = 0
    for i in range(1, 9):
        velb = os.path.join(d, "prog_%d.velb" % i)
        if not os.path.exists(velb):
            ctx.lines.append(("FAIL", "M5.A build %d no produjo .velb" % i))
            bad = 1
            continue
        _, log = ctx.run([VM_EXE, "--run", velb, "--schedulers", "1", "--stats"])
        got = get_r00(log)
        if got != 42:
            ctx.lines.append(("FAIL",
                              "M5.A build %d: R00 == %s, se esperaba 42" % (i, got)))
            bad = 1
    if bad:
        raise CaseFail("M5.A")
    ctx.ok("M5.A atomic write (8 builds concurrentes, todos R0=42)")
    import glob as _glob
    orphans = _glob.glob(os.path.join(d, "*.tmp.*"))
    if orphans:
        ctx.fail("M5.A: huerfanos .tmp.* en el cache:", "\n".join(orphans))
    ctx.ok("M5.A sin huerfanos .tmp.*")
    _rm_glob(d, "prog_*.velb", "prog_*.vel")
    _rm(os.path.join(d, "prog.velb"), os.path.join(d, "prog.vel"))


@case("m5b", serial=True, line=2653)
def _(ctx):
    """M5.B: project-level cache (.vpc) -- cold miss+save, warm hit."""
    d = _bug_dir("m6_test")
    if not os.path.exists(os.path.join(d, "main.vx")):
        return
    _rm(_projects_cache())
    _rm(*[os.path.join(d, f) for f in
          ("lib.vxi", "lib.vxir", "prog.velb", "prog.vel")])
    env = _env(VX_VERBOSE_PROJECT_CACHE=1)
    _, log = ctx.run([VM_EXE, "--vesta", os.path.join(d, "main.vx"),
                      "-o", os.path.join(d, "prog")], env=env)
    for what in ("miss", "saved"):
        if "project-cache] " + what not in log:
            ctx.fail("M5.B cold: no aparecio '%s'" % what, log)
    _, log = ctx.run([VM_EXE, "--run", os.path.join(d, "prog.velb"),
                      "--schedulers", "1", "--stats"])
    if get_r00(log) != 42:
        ctx.fail("M5.B cold run: R00 != 42", log)
    ctx.ok("M5.B cold compile (miss + save) -> R0 = 42")
    _, log = ctx.run([VM_EXE, "--vesta", os.path.join(d, "main.vx"),
                      "-o", os.path.join(d, "prog")], env=env)
    if "project-cache] hit" not in log:
        ctx.fail("M5.B warm: no aparecio 'hit'", log)
    _, log = ctx.run([VM_EXE, "--run", os.path.join(d, "prog.velb"),
                      "--schedulers", "1", "--stats"])
    if get_r00(log) != 42:
        ctx.fail("M5.B warm run: R00 != 42")
    ctx.ok("M5.B warm compile (hit instantaneo) -> R0 = 42")


@case("m5c", serial=True, line=2696)
def _(ctx):
    """M5.C: .vel per-dep distribuible + recompilacion standalone (--worker)."""
    d = _bug_dir("m6_test")
    if not os.path.exists(os.path.join(d, "main.vx")):
        return
    _rm(_projects_cache())
    _rm(*[os.path.join(d, f) for f in
          ("lib.vxi", "lib.vxir", "lib.vel", "prog.velb", "prog.vel")])
    _, log = ctx.run([VM_EXE, "--vesta", os.path.join(d, "main.vx"),
                      "-o", os.path.join(d, "prog")],
                     env=_env(VX_NO_PROJECT_CACHE=1))
    lib_vel = os.path.join(d, "lib.vel")
    if not os.path.exists(lib_vel):
        ctx.fail("M5.C: lib.vel del dep no fue generado", log)
    ctx.ok("M5.C lib.vel standalone generado junto al .vxi")
    vel = read_text(lib_vel)
    if "Counter__inc:" not in vel:
        ctx.fail("M5.C: lib.vel no contiene Counter__inc")
    if "__module_init:" not in vel:
        ctx.fail("M5.C: lib.vel no contiene __module_init")
    ctx.ok("M5.C lib.vel contiene Counter__inc + __module_init")
    _, log = ctx.run([VM_EXE, "--worker", lib_vel,
                      "-o", os.path.join(d, "lib_standalone")])
    if not os.path.exists(os.path.join(d, "lib_standalone.velb")):
        ctx.fail("M5.C: --worker sobre lib.vel no produjo .velb", log)
    ctx.ok("M5.C lib.vel -> lib_standalone.velb via --worker")
    _rm(os.path.join(d, "lib_standalone.velb"),
        os.path.join(d, "lib_standalone.vel"))


@case("l26", serial=True, line=2735)
def _(ctx):
    """L.26: warning de imports sin usar (y sin falsos positivos)."""
    d = _bug_dir("m_l26_test")
    if not os.path.exists(os.path.join(d, "main.vx")):
        return
    _rm_glob(d, "*.vxi", "*.vxir", "*.vel")
    _rm(os.path.join(d, "prog.velb"))
    _, log = ctx.run([VM_EXE, "--vesta", os.path.join(d, "main.vx"),
                      "-o", os.path.join(d, "prog")])
    if not os.path.exists(os.path.join(d, "prog.velb")):
        ctx.fail("L.26 compile no produjo .velb", log)
    for sym in ("unused_fn", "UNUSED_CONST"):
        if "simbolo importado '%s' de 'lib' no se usa" % sym not in log:
            ctx.fail("L.26: no aparecio warning para '%s'" % sym, log)
    for sym in ("used_fn", "USED_CONST"):
        if "simbolo importado '%s' de 'lib' no se usa" % sym in log:
            ctx.fail("L.26: warning espurio para '%s' (esta usado)" % sym)
    _, log = ctx.run([VM_EXE, "--run", os.path.join(d, "prog.velb"),
                      "--schedulers", "1", "--stats"])
    if get_r00(log) != 42:
        ctx.fail("L.26 run R00 != 42", log)
    ctx.ok("L.26 unused imports (warnings emitidos + R0=42)")


@case("l30", serial=True, line=2766)
def _(ctx):
    """L.30: detector de ciclos de herencia (A:B + B:A) -> compile error."""
    d = _bug_dir("m_l30_test")
    if not os.path.exists(os.path.join(d, "cycle.vx")):
        return
    _rm(os.path.join(d, "cycle.velb"), os.path.join(d, "cycle.vel"))
    _, log = ctx.run([VM_EXE, "--vesta", os.path.join(d, "cycle.vx"),
                      "-o", os.path.join(d, "cycle")])
    if os.path.exists(os.path.join(d, "cycle.velb")):
        ctx.fail("L.30: cycle.vx produjo .velb (deberia rechazar)")
    if "ciclo de herencia detectado" not in log:
        ctx.fail("L.30: no aparecio mensaje 'ciclo de herencia detectado'", log)
    ctx.ok("L.30 ciclo de herencia A:B + B:A detectado")


@case("l20_m8", serial=True, line=2784)
def _(ctx):
    """L.20 topo levels + M8 (paralelo explicito / auto / secuencial forzado)."""
    d = _bug_dir("m_l20_test")
    if not os.path.exists(os.path.join(d, "main.vx")):
        return

    def clean():
        _rm(_projects_cache())
        _rm_glob(d, "*.vxi", "*.vxir", "*.vel")
        _rm(os.path.join(d, "prog.velb"), os.path.join(d, "prog.vel"))

    def compile_with(env):
        return ctx.run([VM_EXE, "--vesta", os.path.join(d, "main.vx"),
                        "-o", os.path.join(d, "prog")], env=env)

    def run_r0(msg):
        _, log = ctx.run([VM_EXE, "--run", os.path.join(d, "prog.velb"),
                          "--schedulers", "1", "--stats"])
        if get_r00(log) != 42:
            ctx.fail(msg, log)

    # (1) L.20: reporte de niveles topologicos.
    clean()
    _, log = compile_with(_env(VX_VERBOSE_COMPILE=1))
    if not os.path.exists(os.path.join(d, "prog.velb")):
        ctx.fail("L.20 compile no produjo .velb", log)
    if not grep_q(log, r"topo\] 4 modulos en 2 niveles, 2 modulos paralelizables"):
        ctx.fail("L.20 topo report incorrecto", log)
    for dep in ("dep_a", "dep_b", "dep_c"):
        if not grep_q(log, r"L0\].*" + dep):
            ctx.fail("%s no esta en L0" % dep)
    if not grep_q(log, r"L1\].*main.*root"):
        ctx.fail("main no esta en L1")
    run_r0("L.20 R0 != 42")
    ctx.ok("L.20 topo levels detectados (3 deps en L0 + main en L1) -> R0 = 42")

    # (2) M8: paralelo explicito con 4 threads; las lineas deben ser atomicas.
    clean()
    _, log = compile_with(_env(VX_PARALLEL_COMPILE=4, VX_VERBOSE_COMPILE=1))
    if not os.path.exists(os.path.join(d, "prog.velb")):
        ctx.fail("M8 compile paralelo no produjo .velb", log)
    if not grep_q(log, r"\[parallel\] threads=4 niveles=2"):
        ctx.fail("M8 banner [parallel] no aparece", log)
    for dep in ("dep_a", "dep_b", "dep_c"):
        if not grep_q(log, r"^\[L0\].*" + dep):
            ctx.fail("M8 %s no en L0 (atomic)" % dep)
    if not grep_q(log, r"^\[L1\].*main.*root"):
        ctx.fail("M8 main no en L1")
    run_r0("M8 paralelo R0 != 42")
    ctx.ok("M8 compilacion paralela (3 deps en L0 concurrentes via std::thread) "
           "-> R0 = 42")

    # (3) M8.auto: sin env var debe activarse igualmente.
    clean()
    _, log = compile_with(_env(VX_VERBOSE_COMPILE=1))
    if not grep_q(log, r"^\[parallel\] threads="):
        ctx.fail("M8.auto banner [parallel] auto no aparece", log)
    run_r0("M8.auto R0 != 42")
    ctx.ok("M8.auto paralelismo automatico (hardware_concurrency) -> R0 = 42")

    # (4) M8.seq: VX_PARALLEL_COMPILE=1 fuerza secuencial (sin banner).
    clean()
    _, log = compile_with(_env(VX_PARALLEL_COMPILE=1, VX_VERBOSE_COMPILE=1))
    if grep_q(log, r"^\[parallel\]"):
        ctx.fail("M8.seq VX_PARALLEL_COMPILE=1 debe ser secuencial (sin banner)",
                 log)
    ctx.ok("M8.seq VX_PARALLEL_COMPILE=1 fuerza secuencial (sin banner [parallel])")


@case("m7b", serial=True, line=2876)
def _(ctx):
    """M7.b: cross-module qualified type (new lib.Counter via namespace)."""
    d = _bug_dir("m7b_test")
    if not os.path.exists(os.path.join(d, "main.vx")):
        return
    _rm(_projects_cache())
    _rm_glob(d, "*.vxi", "*.vxir", "*.vel")
    _rm(os.path.join(d, "prog.velb"), os.path.join(d, "prog.vel"))
    _, log = ctx.run([VM_EXE, "--vesta", os.path.join(d, "main.vx"),
                      "-o", os.path.join(d, "prog")])
    if not os.path.exists(os.path.join(d, "prog.velb")):
        ctx.fail("M7.b compile no produjo .velb", log)
    _, log = ctx.run([VM_EXE, "--run", os.path.join(d, "prog.velb"),
                      "--schedulers", "1", "--stats"])
    got = get_r00(log)
    if got != 42:
        ctx.fail("M7.b qualified type R0 != 42, got %s" % got, log)
    ctx.ok("M7.b cross-module qualified type (new lib.Counter via namespace) "
           "-> R0 = 42")


@case("condcomp", serial=True, line=2898)
def _(ctx):
    """M.condcomp: @Target con AND/OR/NOT + parens (R0 depende del host)."""
    d = _bug_dir("m_condcomp_test")
    if not os.path.exists(os.path.join(d, "main.vx")):
        return
    _, log = ctx.compile_vx(os.path.join(d, "main.vx"), "cc")
    _, log = ctx.run_velb("cc", schedulers=1)
    got = get_r00(log)
    # x86_64+SSE2 -> 42 | ARM+NEON -> 30 | CPU minimo -> 28.
    if got not in (42, 30, 28):
        ctx.fail("M.condcomp R0 != {42,30,28}, got %s" % got, log)
    ctx.ok("M.condcomp @Target con AND/OR/NOT + parens -> R0 = %d" % got)


@case("condcomp_import", serial=True, line=2921)
def _(ctx):
    """M.condcomp sobre imports + ext (CPU features + semver + mode)."""
    d = _bug_dir("m_condcomp_import_test")
    if not os.path.exists(os.path.join(d, "main.vx")):
        return
    _rm(_projects_cache())
    _rm_glob(d, "*.vxi", "*.vxir", "*.vel")
    ctx.compile_vx(os.path.join(d, "main.vx"), "cci")
    _, log = ctx.run_velb("cci", schedulers=1)
    got = get_r00(log)
    # Windows -> 100-58 = 42 | Linux/macOS -> 200-58 = 142.
    if got not in (42, 142):
        ctx.fail("M.condcomp import R0 != {42,142}, got %s" % got, log)
    ctx.ok("M.condcomp @Target sobre imports (deps platform-specific) -> R0 = %d"
           % got)
    # El .sh recompila aqui el main del OTRO test (m_condcomp_test); se replica.
    d2 = _bug_dir("m_condcomp_test")
    ctx.compile_vx(os.path.join(d2, "main.vx"), "ccx", must_succeed=False)
    _, log = ctx.run_velb("ccx", schedulers=1)
    got = get_r00(log)
    if got not in (42, 30, 28):
        ctx.fail("M.condcomp ext (CPU+semver+mode) R0 inesperado=%s" % got, log)
    ctx.ok("M.condcomp ext (CPU features + semver + mode) -> R0 = %d" % got)


@case("pkgmulti", serial=True, line=2955)
def _(ctx):
    """M.pkg-dir: paquete multi-fichero + reexport (mypkg/mod.vx + utils.vx)."""
    d = _bug_dir("m_pkgdir_test")
    if not os.path.exists(os.path.join(d, "main.vx")):
        return
    _rm(_projects_cache())
    _rm_glob(os.path.join(d, "mypkg"), "*.vxi", "*.vxir", "*.vel")
    _rm_glob(d, "*.vel")
    ctx.compile_vx(os.path.join(d, "main.vx"), "pkgmulti")
    _, log = ctx.run_velb("pkgmulti", schedulers=1)
    got = get_r00(log)
    if got != 42:
        ctx.fail("M.pkg-dir multi R0 != 42, got %s" % got, log)
    ctx.ok("M.pkg-dir multi-file + reexport (mypkg/mod.vx + mypkg/utils.vx) "
           "-> R0 = 42")


@case("reexport_plain", serial=True, line=2982)
def _(ctx):
    """M.reexport ext: `public import "lib";` sin only."""
    d = _bug_dir("m_reexport_plain")
    if not os.path.exists(os.path.join(d, "main.vx")):
        return
    _rm(_projects_cache())
    _rm_glob(d, "*.vxi", "*.vxir", "*.vel")
    ctx.compile_vx(os.path.join(d, "main.vx"), "rep")
    _, log = ctx.run_velb("rep", schedulers=1)
    got = get_r00(log)
    if got != 42:
        ctx.fail("M.reexport plain R0 != 42, got %s" % got, log)
    ctx.ok("M.reexport plain (public import sin only) -> R0 = 42")


@case("mdyn", serial=True, line=3006)
def _(ctx):
    """M.dyn: hot-reload via loadmodule + unloadmodule."""
    d = _bug_dir("m_dyn_test")
    if not os.path.exists(os.path.join(d, "main.vx")):
        return
    _rm(os.path.join(d, "plugin.velb"), os.path.join(d, "plugin.vel"))
    _, log = ctx.run([VM_EXE, "--vesta", os.path.join(d, "plugin.vx"),
                      "-o", os.path.join(d, "plugin"),
                      "--vx-base", "0x10000000"])
    if not os.path.exists(os.path.join(d, "plugin.velb")):
        ctx.fail("M.dyn plugin compile no produjo .velb", log)
    ctx.compile_vx(os.path.join(d, "main.vx"), "dyn")
    _, log = ctx.run_velb("dyn", schedulers=1)
    got = get_r00(log)
    if got != 42:
        ctx.fail("M.dyn hot-reload R0 != 42, got %s" % got, log)
    ctx.ok("M.dyn hot-reload (load + use + unload + reload + use) -> R0 = 42")


@case("sandbox", serial=True, line=3037)
def _(ctx):
    """M.sandbox: capability-based sandbox (ALL / none / ffi:call / none+JIT)."""
    d = _bug_dir("m_sandbox_test")
    if not os.path.exists(os.path.join(d, "main.vx")):
        return
    ctx.compile_vx(os.path.join(d, "main.vx"), "sb")
    # Caso 1: ALL caps (default).
    _, log = ctx.run_velb("sb", schedulers=1)
    if not grep_q(log, r"^hola$"):
        ctx.fail("sandbox ALL caps: 'hola' no se imprimio", log)
    if "st=HALT" not in log:
        ctx.fail("sandbox ALL caps: proceso no llego a HALT")
    ctx.ok("sandbox ALL caps (default) -> println funciona, HALT limpio")
    # Caso 2: NONE caps.
    _, log = ctx.run_velb("sb", schedulers=1, extra=["--vx-caps", "none"])
    if grep_q(log, r"^hola$"):
        ctx.fail("sandbox NONE caps: 'hola' SI se imprimio (cap bypass)", log)
    if "st=DEAD" not in log:
        ctx.fail("sandbox NONE caps: proceso no quedo en DEAD", log)
    ctx.ok("sandbox NONE caps -> CALLN rechazado, proceso DEAD")
    # Caso 3: grant de ffi:call.
    _, log = ctx.run_velb("sb", schedulers=1, extra=["--vx-caps", "ffi:call"])
    if not grep_q(log, r"^hola$"):
        ctx.fail("sandbox ffi:call: 'hola' no se imprimio", log)
    ctx.ok("sandbox ffi:call grant -> println permitido (cap match)")
    # Caso 4: NONE caps con JIT forzado (el guard no debe poder saltarse).
    _, log = ctx.run_velb("sb", schedulers=1, extra=["--vx-caps", "none"],
                          env=_env(VESTA_JIT_THRESHOLD=1))
    if grep_q(log, r"^hola$"):
        ctx.fail("sandbox NONE bajo JIT: 'hola' SI se imprimio "
                 "(bypass del sandbox bajo JIT)", log)
    ctx.ok("sandbox NONE caps bajo JIT -> guard mantiene interp, CALLN rechazado")


@case("l16", serial=True, line=3096)
def _(ctx):
    """L.16: cache global via VX_CACHE_DIR (sin caches locales)."""
    d = _bug_dir("m4ext_test")
    if not os.path.exists(os.path.join(d, "main.vx")):
        return
    gdir = ctx.path("vx_global_cache_test")
    _rm(gdir)
    os.makedirs(gdir, exist_ok=True)
    for n in ("b", "c"):
        _rm(os.path.join(d, n + ".vxi"), os.path.join(d, n + ".vxir"),
            os.path.join(d, n + ".vel"))
    _rm(os.path.join(d, "prog.velb"), os.path.join(d, "prog.vel"))
    _, log = ctx.run([VM_EXE, "--vesta", os.path.join(d, "main.vx"),
                      "-o", os.path.join(d, "prog")],
                     env=_env(VX_CACHE_DIR=gdir, VX_NO_PROJECT_CACHE=1))
    if not os.path.exists(os.path.join(d, "prog.velb")):
        ctx.fail("L.16 compile no produjo .velb", log)
    if (os.path.exists(os.path.join(d, "b.vxi")) or
            os.path.exists(os.path.join(d, "c.vxi"))):
        ctx.fail("L.16: caches locales creados con VX_CACHE_DIR activo")
    import glob as _glob
    if not _glob.glob(os.path.join(gdir, "*.vxi")):
        ctx.fail("L.16: no se crearon .vxi en cache global")
    ctx.ok("L.16 cache global via VX_CACHE_DIR")


def _simple_bug_r0(ctx, dirname, tag, ok_msg, fail_msg, entry="main.vx"):
    """Patron comun de la bateria  M: limpiar, compilar en el dir, R0=42."""
    d = _bug_dir(dirname)
    if not os.path.exists(os.path.join(d, entry)):
        return
    _rm(_projects_cache())
    _rm_glob(d, "*.vxi", "*.vxir", "*.vel")
    _rm(os.path.join(d, "prog.velb"), os.path.join(d, "prog.vel"))
    _, log = ctx.run([VM_EXE, "--vesta", os.path.join(d, entry),
                      "-o", os.path.join(d, "prog")])
    if not os.path.exists(os.path.join(d, "prog.velb")):
        ctx.fail("%s compile no produjo .velb" % tag, log)
    _, log = ctx.run([VM_EXE, "--run", os.path.join(d, "prog.velb"),
                      "--schedulers", "1", "--stats"])
    got = get_r00(log)
    if got != 42:
        ctx.fail(fail_msg % got if "%s" in fail_msg else fail_msg, log)
    ctx.ok(ok_msg)


@case("l23", serial=True, line=3124)
def _(ctx):
    """L.23: re-export transitivo via public import."""
    _simple_bug_r0(ctx, "m_l23_test", "L.23",
                   "L.23 re-export transitivo (public import) -> R0 = 42",
                   "L.23 R0 != 42")


@case("l24", serial=True, line=3143)
def _(ctx):
    """L.24: compilacion condicional @Target("os:...")."""
    _simple_bug_r0(ctx, "m_l24_test", "L.24",
                   "L.24 @Target compilacion condicional -> R0 = 42",
                   "L.24 R0 != 42 (vale %s)")


@case("l22", serial=True, line=3162)
def _(ctx):
    """L.22: paquete-dir (import "pkg_lib" -> pkg_lib/mod.vx)."""
    d = _bug_dir("m_l22_test")
    if not os.path.exists(os.path.join(d, "main.vx")):
        return
    _rm(_projects_cache())
    _rm_glob(d, "*.vxi", "*.vxir", "*.vel")
    _rm(os.path.join(d, "prog.velb"))
    _rm_glob(os.path.join(d, "pkg_lib"), "*.vxi", "*.vxir", "*.vel")
    _, log = ctx.run([VM_EXE, "--vesta", os.path.join(d, "main.vx"),
                      "-o", os.path.join(d, "prog")])
    if not os.path.exists(os.path.join(d, "prog.velb")):
        ctx.fail("L.22 compile no produjo .velb", log)
    _, log = ctx.run([VM_EXE, "--run", os.path.join(d, "prog.velb"),
                      "--schedulers", "1", "--stats"])
    if get_r00(log) != 42:
        ctx.fail("L.22 R0 != 42", log)
    ctx.ok("L.22 paquete-dir (pkg_lib/mod.vx resuelto via 'pkg_lib') -> R0 = 42")


@case("l25", serial=True, line=3182)
def _(ctx):
    """L.25: tree-shaking (VX_TREE_SHAKE=1) reduce el tamano del .velb."""
    d = _bug_dir("m_l25_test")
    if not os.path.exists(os.path.join(d, "main.vx")):
        return

    def build(env):
        _rm(_projects_cache())
        _rm_glob(d, "*.vxi", "*.vxir", "*.vel")
        _rm(os.path.join(d, "prog.velb"))
        return ctx.run([VM_EXE, "--vesta", os.path.join(d, "main.vx"),
                        "-o", os.path.join(d, "prog")], env=env)

    build(None)
    no_shake = os.path.getsize(os.path.join(d, "prog.velb"))
    _, log = build(_env(VX_TREE_SHAKE=1, VX_VERBOSE_COMPILE=1))
    shake = os.path.getsize(os.path.join(d, "prog.velb"))
    if not grep_q(log, r"tree-shake\] dep 'unused_lib' eliminado"):
        ctx.fail("L.25: no aparecio mensaje tree-shake", log)
    if shake >= no_shake:
        ctx.fail("L.25: con shake (%d) NO menor que sin (%d)" % (shake, no_shake))
    _, log = ctx.run([VM_EXE, "--run", os.path.join(d, "prog.velb"),
                      "--schedulers", "1", "--stats"])
    if get_r00(log) != 42:
        ctx.fail("L.25 R0 != 42 con shake", log)
    ctx.ok("L.25 tree-shake (%d -> %d B) -> R0 = 42" % (no_shake, shake))


@case("l28", serial=True, line=3215)
def _(ctx):
    """L.28: firmas digitales del .velb (sign + verify + run del firmado)."""
    d = _bug_dir("m_l28_test")
    if not os.path.exists(os.path.join(d, "hello.vx")):
        return
    priv = os.path.join(d, "priv.pem")
    pub = os.path.join(d, "pub.pem")
    signed = os.path.join(d, "hello.signed.velb")
    velb = os.path.join(d, "hello.velb")
    rc, _ = ctx.run(["openssl", "genrsa", "-out", priv, "2048"])
    if not os.path.exists(priv):
        ctx.skip("L.28: openssl no disponible")
        return
    try:
        ctx.run(["openssl", "rsa", "-in", priv, "-pubout", "-out", pub])
        _rm(velb, os.path.join(d, "hello.vel"), signed)
        ctx.run([VM_EXE, "--vesta", os.path.join(d, "hello.vx"),
                 "-o", os.path.join(d, "hello")])
        _, log = ctx.run([VM_EXE, "--sign-velb", velb, "--sign-key", priv,
                          "-o", signed])
        if not os.path.exists(signed):
            ctx.fail("L.28 sign no produjo .signed.velb", log)
        _, log = ctx.run([VM_EXE, "--verify-velb", signed, "--verify-key", pub])
        if "firma VALIDA" not in log:
            ctx.fail("L.28 verify con pubkey correcta no dio VALIDA", log)
        rc, _ = ctx.run([VM_EXE, "--verify-velb", velb, "--verify-key", pub])
        if rc == 0:
            ctx.fail("L.28: verify de .velb sin firma deberia fallar")
        _, log = ctx.run([VM_EXE, "--run", signed, "--schedulers", "1", "--stats"])
        if get_r00(log) != 42:
            ctx.fail("L.28 run de firmado R0 != 42", log)
        ctx.ok("L.28 sign + verify (RSA-SHA256) + run firmado -> R0 = 42")
    finally:
        _rm(priv, pub, signed, velb, os.path.join(d, "hello.vel"))


# ===========================================================================
# Invocaciones mecanicas de helpers (verify_r0 / verify_compile_fails /
# verify_naked_3modes / verify_const_reject) del .sh original.
#
# Esta tabla se GENERO a partir del .sh (no se transcribio a mano) para que
# los ~180 valores esperados sean exactamente los del origen.   es la
# linea del .sh y fija el orden del reporte.
# ===========================================================================

r0_case("tf63", "top-level fn como fn-value", "63_topfn_as_fnvalue.vx", 42, line=1574)
r0_case("cu64", "curry: factories de closures", "64_curry_returning_closures.vx", 42, line=1583)
r0_case("iso67", "FatalError 3-casos (PHI fix + NPE + panic)", "67_fatal_isolation.vx", 142, line=1642)
r0_case("panic68", "panic + captura (kind=11)", "68_panic_capture.vx", 11, line=1647)
r0_case("str69", "string + builtins (length/cstr/concat)", "69_string_basico.vx", 42, line=1650)
r0_case("str70", "string ops + cstring + ENC", "70_string_ops_native.vx", 42, line=1653)
r0_case("bf71", "bit fields struct", "71_bit_fields.vx", 42, line=1656)
r0_case("td72", "typedef struct C-style", "72_typedef_cstyle.vx", 42, line=1659)
r0_case("il73", "array+struct init lists C-style", "73_init_lists.vx", 42, line=1662)
r0_case("bfi74", "bit fields en init list", "74_bf_init.vx", 42, line=1665)
r0_case("sm75", "metodos OO string (s.length etc)", "75_string_methods.vx", 42, line=1668)
r0_case("ca80", "compound assign (campo + indexado + deref)", "79_compound_assign.vx", 42, line=1819)
r0_case("mb82", "math builtins (sqrt/pow/sin/log/...)", "81_math_builtins.vx", 42, line=1850)
r0_case("hpat83", "is_host_ptr round-trip via address-taken local (limitacion A)", "82_host_ptr_addr_taken.vx", 42, line=1858)
r0_case("hpi84", "is_host_ptr indirecto via i32** pp = &p (limitacion A parte 2)", "83_host_ptr_indirect.vx", 42, line=1867)
r0_case("sf85", "static fields plenamente lowered (limitacion G)", "84_static_fields.vx", 42, line=1876)
r0_case("ew86", "extern WinAPI declarativo (kernel32 GetCurrentProcessId / GetTickCount)", "85_extern_winapi.vx", 42, line=1883)
r0_case("fr87", "FFI runtime dinamico (ffi_open + ffi_sym + ffi_call kernel32)", "86_ffi_runtime.vx", 42, line=1890)
r0_case("ch88", "HashMap swisstable + wyhash + SSE2 (50 puts + rehash + ops mixtas)", "87_collections_hashmap.vx", 42, line=1896)
r0_case("qdt89", "Queue + Deque (ring buffer) + TreeMap RB (floor/ceiling/remove)", "88_collections_queue_deque_tree.vx", 42, line=1900)
r0_case("sao90", "String + Array ops (indexof/starts_with/ends_with + sort/bsearch/reverse)", "89_string_array_ops.vx", 42, line=1905)
r0_case("spl91", "str_split via vstr_split_offsets (5 substrings + offsets correctos)", "91_str_split.vx", 42, line=1912)
r0_case("cp92", "Colecciones primitivas (sin extern, sin clases, free automatico)", "92_collections_primitive.vx", 42, line=1917)
r0_case("disp93", "dispose(xs) explicito + cleanup idempotente (no double-free)", "93_dispose_explicit.vx", 42, line=1921)
r0_case("esc94", "Escape detection: return ArrayList desde funcion", "94_escape_detection.vx", 42, line=1926)
modes3_case("dtr95", "Destructor RAII: 3 dtors al exit + escape (return) NO ejecuta dtor", "95_destructor_raii.vx", 42, line=1931)
r0_case("der96", "Destructor escape rules: caso legal (local + return)", "96_destructor_escape_rules.vx", 42, line=1935)
r0_case("wb97", "GC write-barrier: ArrayList retiene string handle (gc_addref)", "97_gc_writebarrier.vx", 42, line=1951)
r0_case("als98", "ArrayList<string> sintaxis natural (auto-dispatch *_gc)", "98_arraylist_string_natural.vx", 42, line=1956)
r0_case("rdf99", "A.32: Holder con Resource field, sintesis dtor recursivo", "99_dtor_recursive_fields.vx", 42, line=1961)
r0_case("rfl100", "A.34: Reflexion forName+newInstance+getMethod+invoke", "100_reflection_full.vx", 42, line=1967)
r0_case("raii101", "A.34.fix5: RAII completo (scope-local + NEWOBJ save_live_regs)", "101_raii_casos_limite.vx", 42, line=1975)
r0_case("closure_gc102", "Mejora I: closure env auto-free via GC (5000 escapadas, sin leak)", "102_closure_env_gc.vx", 42, line=1984)
r0_case("async_typed103", "Mejora II: @Async con args + Future<T> (i32/i64/bool, 4 cases)", "103_async_args_typed.vx", 42, line=1991)
r0_case("hot_loop104", "Optimizacion hot-loop: cmpjmp.cc fusion en bound check (10M iter)", "104_hot_loop_bench.vx", 42, line=1996)
modes3_case("uniq95", "unique<T> basico: unique_box + ptr_of + cleanup auto", "95_unique_ptr_basico.vx", 42, line=2002)
modes3_case("uniq96", "unique<T> move semantics (mvtake): transfer ownership", "96_unique_move.vx", 100, line=2004)
modes3_case("shr97", "shared<T> basico: shared_box + use_count + payload offset", "97_shared_basico.vx", 78, line=2006)
modes3_case("uw105", "unique_with: deleter Vesta custom (counter de releases)", "105_unique_with_vesta.vx", 3, line=2013)
modes3_case("valloc106", "unique_with + VirtualAlloc/VirtualFree (Win32 API auto-released)", "106_virtualalloc_unique.vx", 42, line=2015)
modes3_case("lifo107", "unique<T> LIFO cleanup + move chain (orden inverso)", "107_unique_lifo_move_chain.vx", 42, line=2017)
modes3_case("shrc108", "shared<T> use_count + move + ptr_of value recovery", "108_shared_use_count.vx", 42, line=2019)
modes3_case("smint109", "smart pointers integracion completa (unique + multi-release)", "109_unique_comprehensive.vx", 42, line=2021)
modes3_case("cmb235", "combo memoria: unique<gc<T>> (unique envuelve objeto GC)", "235_unique_wraps_gc.vx", 42, line=2025)
modes3_case("cmb236", "combo memoria: shared<gc<T>> (shared envuelve objeto GC)", "236_shared_wraps_gc.vx", 42, line=2027)
modes3_case("cmb237", "combo memoria: gc<Nodo> como campo de clase RAII", "237_gc_campo_y_ptr_wrapper.vx", 42, line=2029)
modes3_case("cmb238", "combo memoria: move de campo unique hacia fuera (sin double-free)", "238_move_from_field_nofree.vx", 1, line=2031)
modes3_case("cmb239", "combo memoria: borrow sobre unique y sobre shared", "239_borrow_sobre_owned.vx", 42, line=2033)
modes3_case("ret110", "unique<T> retornado desde funciones (SRET Tier 1)", "110_unique_return_from_fn.vx", 42, line=2039)
r0_case("borrow111", "borrow<T> shared multiple coexisten (R2)", "111_borrow_shared_ok.vx", 42, line=2045)
r0_case("borrow112", "borrow_mut<T> exclusive + write_borrow OK", "112_borrow_mut_ok.vx", 42, line=2047)
fails_case("berr113", "borrow R1: shared tras mutable", "113_borrow_err_mut_shared.vx", "VX2026", line=2067)
fails_case("berr114", "borrow R1: doble mutable", "114_borrow_err_double_mut.vx", "VX2026", line=2070)
fails_case("berr115", "borrow R2: mut tras shared activo", "115_borrow_err_mut_during_shared.vx", "VX2027", line=2073)
fails_case("berr116", "borrow R3: move while borrowed", "116_borrow_err_move_while_borrowed.vx", "VX2034", line=2076)
r0_case("borrow117", "borrow F2+F4: param escape + lifetime elision regla 1", "117_borrow_param_elision.vx", 42, line=2082)
r0_case("borrow118", "borrow F1: NLL libera borrow tras ultimo uso (move OK)", "118_borrow_nll.vx", 42, line=2084)
r0_case("borrow119", "borrow F3: shared reborrow lend(borrow_shared)", "119_borrow_reborrow.vx", 42, line=2086)
r0_case("borrow120", "borrow F3 ext: lend_mut(borrow_mut) reborrow con suspend", "120_borrow_reborrow_mut.vx", 42, line=2088)
r0_case("borrow121", "borrow F3 ext: lend(borrow_mut) shared reborrow con suspend", "121_borrow_shared_reborrow_of_mut.vx", 42, line=2090)
r0_case("borrow122", "borrow F3 ext: cadena 3-niveles m1->m2->m3 con stack", "122_borrow_reborrow_chain.vx", 42, line=2092)
r0_case("borrow123", "borrow realista: helper mutation (increment_by + double_value)", "123_borrow_helper_mutation.vx", 42, line=2099)
r0_case("borrow124", "borrow realista: agregador con multiples shared (weighted_sum/minimum)", "124_borrow_aggregator.vx", 42, line=2101)
r0_case("borrow125", "borrow realista: NLL con compute + move (compute_length + consume)", "125_borrow_nll_realistic.vx", 42, line=2103)
r0_case("borrow126", "borrow realista: reborrow_mut dentro de helper (outer/inner pattern)", "126_borrow_reborrow_helper.vx", 42, line=2105)
r0_case("borrow127", "borrow realista: state machine via apply_op + validador shared", "127_borrow_state_machine.vx", 42, line=2107)
r0_case("borrow128", "borrow realista: factory chain con F4 elision (3 niveles deep_read)", "128_borrow_factory_chain.vx", 42, line=2109)
fails_case("berr129", "borrow realista R1: doble mutable cross-call (E0499 rust)", "129_borrow_err_helper_double_mut.vx", "VX2026", line=2113)
fails_case("berr130", "borrow realista R4: return borrow a local (E0515 rust)", "130_borrow_err_return_local.vx", "VX2037", line=2116)
r0_case("borrow131", "borrow realista integrador: pipeline + validador + elision combinados", "131_borrow_combined_real.vx", 42, line=2122)
r0_case("comptime132", "comptime introspect: sizeof/alignof/typename/type_id/kind", "132_comptime_introspect.vx", 42, line=2129)
r0_case("comptime133", "comptime introspect: fields + methods + subtype + is_*", "133_comptime_introspect2.vx", 42, line=2136)
r0_case("comptime134", "comptime introspect: field_get/set + comptime if + for_each", "134_comptime_introspect3.vx", 42, line=2142)
r0_case("introspect135", "introspect runtime: @Introspect + find_type + type_info_*", "135_introspect_runtime.vx", 42, line=2149)
r0_case("a38_a", "A.38: ternario + comptime const + static_assert", "136_ternary_comptime_const.vx", 42, line=2156)
fails_case("a38_b", "A.38: static_assert con cond false", "137_static_assert_fail.vx", "static_assert FAILED: i32 debe ser 8 bytes", line=2161)
r0_case("a39_a", "A.39: metaprog completa (const local + block + for + str + fn)", "138_metaprog_completa.vx", 42, line=2168)
r0_case("a40_a", "A.40: comptime imperativo (var + while + break + compound)", "139_comptime_imperativo.vx", 42, line=2174)
r0_case("a41_a", "A.41: metaprog avanzada (for-init + arr + type-params + struct)", "140_metaprog_avanzada.vx", 42, line=2181)
r0_case("a42_a", "A.42: metaprog recursiva (arr strings + builders dinamicos)", "141_metaprog_nested.vx", 42, line=2187)
r0_case("a43_a", "A.43: Type-as-first-class-value (Type, comptime fn -> Type)", "142_type_first_class.vx", 42, line=2194)
r0_case("a43_b", "A.43 ext: builtins composables Type (parent_class, element_type, ...)", "143_type_composable.vx", 42, line=2202)
r0_case("a43_c", "A.43.6: method/enum introspection + comptime_print", "144_method_enum_introspect.vx", 42, line=2209)
r0_case("a43_d", "A.43.7: auto/var inferencia local de tipo", "145_auto_inference.vx", 42, line=2215)
r0_case("a43_e", "A.43.8: notify/notifyAll dentro de synchronized", "146_wait_inside_synchronized.vx", 42, line=2220)
fails_case("a43_f", "A.43.8: wait fuera de synchronized (error claro)", "146b_wait_outside_synchronized.vx", "solo puede invocarse dentro de un bloque 'synchronized", line=2222)
r0_case("a43_g", "A.43.9: macros Lisp MVP via comptime_compile", "147_macros_comptime_compile.vx", 42, line=2229)
r0_case("a43_h", "A.43.10: macros Lisp con splice/emit al AST runtime", "148_macros_emit_splice.vx", 42, line=2238)
r0_case("a43_i", "A.43.11: sugar comptime + gensym (macros hygenic)", "149_macros_hygenic_gensym.vx", 42, line=2245)
r0_case("a43_j", "A.43.12: pattern matching declarativo en macros (replace+templates)", "150_macros_pattern_template.vx", 42, line=2252)
r0_case("a43_k", "A.43.13/14/15: aliases + ops + bloque comptime", "151_sugar_aliases_block.vx", 42, line=2260)
r0_case("a43_l", "A.43.16: macros @Macro con auto-inyeccion (defmacro Lisp)", "152_macros_inject_at_macro.vx", 42, line=2268)
r0_case("a43_m", "A.43.17: @Macro composicion + recursion + globales mutables", "153_macros_compose_recurse_global.vx", 42, line=2276)
r0_case("a43_n", "A.43.18: @Macro anidados extremos -- cero overhead runtime", "154_macros_zero_runtime_overhead.vx", 42, line=2283)
r0_case("a43_o", "A.43.19: string concat O(N) en loops comptime", "155_concat_loop_optimized.vx", 42, line=2290)
r0_case("arnes_ct", "Arnes comptime: fn/block/buffer/println/introspeccion/tipos no-comptime", "293_comptime_arnes.vx", 23, line=2298)
r0_case("a43_p", "A.43.20: @Pure memoizacion + move semantics", "156_macros_pure_memoization.vx", 42, line=2305)
r0_case("a43_q", "A.43.21: multi-chunk concat O(N) (s = s + X + Y + ...)", "157_concat_multichunk.vx", 42, line=2312)
r0_case("mc_a", " MC.1: @Macro bodies lowered to IR (__macro_*)", "158_macros_lowered_to_ir.vx", 42, line=2318)
r0_case("p2_q", "P2: operador ? postfix para Result (early-return)", "163_try_operator.vx", 42, line=2324)
r0_case("shape_f64", "Bug fix: enum payload f64 (Shape areas)", "164_enum_f64_payload.vx", 42, line=2331)
modes3_case("unique_dtor", "Bug fix: unique<T> destructor via cleanup automatico", "165_unique_dtor.vx", 42, line=2339)
r0_case("z_shared", " Z: shared memory cross-process (synchronized + atomics + introspect)", "166_z_shared_memory.vx", 42, line=2347)
r0_case("z_gc", " Z.10 ext: shared GC mark+sweep STW (single-thread)", "167_z_gc_sweep.vx", 42, line=2357)
r0_case("newtypes", "Newtype + @opaque + introspeccion (typedef T name new)", "168_newtypes.vx", 42, line=2367)
r0_case("newtype_adv", "@align + explicit from/to + module-privacy", "169_newtype_advanced.vx", 42, line=2377)
r0_case("loc_calln", "u8[N] = literal + char literals + CALLN nativo", "170_local_to_calln_native.vx", 42, line=2383)
r0_case("cb_qsort", "qsort msvcrt invocando comparator  via as_native_callback", "171_callback_qsort.vx", 42, line=2385)
r0_case("str_arr", "u8[N] init string + char literal coerce + interpolacion CHAR", "172_string_array_natural.vx", 42, line=2387)
r0_case("wndproc", "WndProc Win32 real con global  incrementado por thunk", "173_wndproc_win32.vx", 42, line=2389)
r0_case("async_ch", "Async chains: fan-out 4 workers + fan-in + encadenamiento", "174_async_chains_complex.vx", 42, line=2391)
r0_case("gen_deep", "Generics anidados profundos: Box<Pair<i32, Box<i64>>>", "175_generics_deep_nesting.vx", 42, line=2393)
r0_case("adt_cplx", "ADTs con payloads complejos: Shape{Empty,Circle,Rectangle,Triangle,Labeled}", "176_adt_complex_payloads.vx", 42, line=2395)
r0_case("cb_12args", "Callback nativo con 12 args (max ABI) + multi-invocacion + globals", "177_callback_many_args.vx", 42, line=2397)
r0_case("esc_sr", "Escape analysis: scalar-replace read-only + mutable + PHI-bail", "178_escape_scalar_repl.vx", 42, line=2401)
r0_case("spec_dv", "Spec-devirt: guard-chain + fallback (implementor heredado -> CALLITF)", "179_spec_devirt_inherit.vx", 98, line=2404)
r0_case("vec182", "vectorize element-wise f64", "182_vectorize_elementwise.vx", 180960, line=3627)
r0_case("vec183", "vectorize memcpy idiom", "183_memcpy_idiom.vx", 597, line=3628)
r0_case("vec184", "vectorize reduccion f64", "184_vectorize_reduction.vx", 1204, line=3629)
r0_case("vec185", "vectorize enteros i64/i32", "185_vectorize_int.vx", 446, line=3630)
r0_case("fpl186", "JIT float params+ret+loop", "186_float_params_loop.vx", 261, line=3631)
r0_case("vun187", "vectorize unaria neg/abs/sqrt", "187_vectorize_unary.vx", 41, line=3632)
r0_case("vf188", "vectorize f32 single-prec", "188_vectorize_f32.vx", 194, line=3633)
r0_case("vw189", "vectorize while-form", "189_vectorize_while.vx", 90, line=3634)
r0_case("vfma190", "vectorize FMA dot-product", "190_vectorize_fma.vx", 441, line=3635)
r0_case("vc191", "vectorize compound c[i]+=a[i]", "191_vectorize_compound.vx", 1050, line=3636)
r0_case("vsc192", "vectorize scalar broadcast", "192_vectorize_scalar.vx", 10400, line=3637)
r0_case("vw193", "vectorize int widths i16/i8/mul", "193_vectorize_int_widths.vx", 25460, line=3638)
r0_case("vsi194", "vectorize scalar broadcast int", "194_vectorize_scalar_int.vx", 6825, line=3639)
r0_case("vax195", "vectorize axpy compound multi-op", "195_vectorize_axpy.vx", 44850, line=3640)
r0_case("fcf196", "funciones de primera clase", "196_first_class_functions.vx", 42, line=3641)
r0_case("var197", "funciones variadicas (T... rest)", "197_variadics.vx", 42, line=3642)
r0_case("cfn199", "cfn vs lambda (puntero a funcion crudo)", "199_cfn_vs_lambda.vx", 42, line=3643)
r0_case("clf200", "closure en campo (ownership sin GC)", "200_closure_en_campo.vx", 42, line=3644)
r0_case("bm201", "metodo ligado &obj.metodo", "201_metodo_ligado.vx", 42, line=3645)
r0_case("clr202", "reasignacion de campo closure (libera env+slot, RAII)", "202_closure_reasignacion.vx", 42, line=3646)
r0_case("bmc203", "metodo ligado base compuesta &getObj().m", "203_metodo_ligado_compuesto.vx", 42, line=3647)
r0_case("sce204", "struct con closure capturador que escapa por valor (move-on-return)", "204_struct_closure_escape_err.vx", 42, line=3648)
r0_case("sd206", "destructor de struct ~Struct() + move-on-return (RAII)", "206_struct_dtor.vx", 42, line=3651)
r0_case("sds207", "clase-contenedor con campo struct destructible + move-on-store", "207_struct_dtor_store_err.vx", 42, line=3652)
r0_case("sc208", "composicion de structs con RAII recursivo + acceso campo struct", "208_struct_composition.vx", 42, line=3653)
fails_case("scs209", "struct con closure capturador almacenado en campo (escape no soportado)", "209_struct_closure_store_err.vx", "se almacena en un campo que le sobrevive", line=3654)
warns_r0_case("asmpin", "asm: pin de VALOR a rsp/rbp avisa (VXA008) y compila (permitido, responsabilidad del programador; @Naked)", "asm_pin_rbp_warn.vx", "VXA008", 42, line=3654)
r0_case("asmstk", "asm: manipular la pila desde el asm (mov rsp/push/pop)", "asm_stack_manip.vx", 42, line=3654)
r0_case("asmnss", "asm: stack switch @Naked compilado nativo por el JIT", "asm_naked_stack_switch.vx", 42, line=3654)
warns_r0_case("asmnsw", "asm: reasignar rsp en funcion normal avisa (VXA010) y compila en JIT", "asm_normal_stack_warn.vx", "VXA010", 42, line=3654)
# Una instruccion que EXIGE su direccion alineada y NO la tiene: no es un aviso,
# es un error con su prueba.  Exige que el ancho se resuelva por la CLASE del
# operando (si no llegara, el diagnostico seria VXA012 "no se puede determinar el
# ancho" y este caso fallaria) y que el hecho de alineacion cruce la frontera de
# la funcion (el destino se reserva en `main` y se exige dentro de `rellena_16`).
fails_case("asmalign", "asm: direccion demostrablemente no alineada -> error (VXA013)", "asm_align_warn.vx", "VXA013", line=3654)
# Un acceso de asm que se sale de la region por la que entra.  Exige que el
# analisis diga HASTA DONDE llega cada acceso: con la extension a cero (que es
# como estaba), el comprobador de limites se lo salta y esto compila.
fails_case("asmregion", "asm: acceso fuera de la region por la que entra -> error (VX3001)", "asm_fuera_de_region.vx", "VX3001", line=3654)
# El conocimiento CRUZA la llamada: una funcion que escribe `arg#0+[0,64)` y un
# llamante que le pasa 16 bytes.  La funcion es recursiva a proposito (no se
# puede inlinear), asi que esto exige la instanciacion del efecto en el sitio de
# llamada -- con el inline, el fallo se veria por casualidad.
fails_case("regcall", "region: una llamada que escribe mas de lo que cabe -> error (VX3001)", "region_cruza_llamada.vx", "VX3001", line=3654)
# Y por DOS niveles: lo que hace la hoja sube traducido en cada sitio de llamada
# hasta donde se puede juzgar.  Las funciones son recursivas para que no se
# puedan inlinear -- si se aplanaran, el fallo se veria por casualidad.
fails_case("regcall2", "region: lo que hace una funcion dos niveles abajo -> error (VX3001)", "region_cruza_dos_llamadas.vx", "VX3001", line=3654)
modes3_case("asmwidth", "asm: lift general modela anchos x86 (8/16/32/64) en interp/jit/aot", "asm_lift_widths.vx", 42, line=3654)
modes3_case("shvar", "shift por cantidad variable (SHL/SHR/SAR via CL) en interp/jit/aot", "shift_variable.vx", 42, line=3654)
modes3_case("fpround", "float floor/ceil/round/trunc/fmin/fmax (f64+f32) en interp/jit/aot", "fp_rounding.vx", 42, line=3654)
modes3_case("asmbits", "asm lift de bits (popcnt/lzcnt/tzcnt/bswap -> IrOp neutro) en interp/jit/aot", "asm_bitops.vx", 42, line=3654)
modes3_case("asmmovext", "asm lift de movzx/movsx (extension de ancho) en interp/jit/aot", "asm_movext.vx", 42, line=3654)
modes3_case("asmcmpset", "asm lift fusiona cmp+setcc en comparacion tipada (signed/unsigned/eq) en interp/jit/aot", "asm_cmp_setcc.vx", 42, line=3654)
modes3_case("asmcmpcmov", "asm lift fusiona cmp+cmovcc en select branchless en interp/jit/aot", "asm_cmp_cmov.vx", 42, line=3654)
modes3_case("asmbranch", "asm lift trocea ramas (jmp/jCC) en IR-CFG (max via branch) en interp/jit/aot", "asm_branch.vx", 42, line=3654)
modes3_case("asmloop", "asm lift baja un bucle asm (back-edge) a IR-CFG (suma via loop) en interp/jit/aot", "asm_loop.vx", 42, line=3654)
modes3_case("asmrotate", "asm lift de rol/ror a ROTL/ROTR (const + variable por CL) en interp/jit/aot", "asm_rotate.vx", 42, line=3654)
modes3_case("asmdivmod", "asm lift de div/idiv 64/64 (xor rdx/cqo + div) -> DIV+MOD en interp/jit/aot", "asm_divmod.vx", 42, line=3654)
modes3_case("asmnonadj", "asm flags-as-SSA: setcc no-adyacente al cmp (mov/lea intermedios) + lea base+index + register(rbx) lifteado, en interp/jit/aot", "asm_cmp_nonadj.vx", 42, line=3654)
modes3_case("asmloopdec", "asm flags-as-SSA: bucle contador dec rcx; jnz (ZF de una ALU, sin cmp) -> IR-CFG, en interp/jit/aot", "asm_loop_dec.vx", 42, line=3654)
modes3_case("asmsubjcc", "asm flags-as-SSA: sub fija flags como cmp -> jl/jb tras sub (magnitud signed/unsigned) en interp/jit/aot", "asm_sub_jcc.vx", 42, line=3654)
modes3_case("asmmul", "asm lift de mul/imul 1-op (RDX:RAX 128b): RAX=mul, RDX=umulhi/smulhi (sin op IR nueva) en interp/jit/aot", "asm_mul.vx", 42, line=3654)
modes3_case("asmimul3xchg", "asm lift de imul rd,rs,imm (3-op) + xchg r,r (swap del register-file) en interp/jit/aot", "asm_imul3_xchg.vx", 42, line=3654)
modes3_case("asmcdqe", "asm lift de cdqe/cwde/cbw (sign-extend del acumulador, NO no-op) en interp/jit/aot", "asm_cdqe.vx", 42, line=3654)
modes3_case("asmadcsbb", "asm flags-as-SSA con CF: adc/sbb (aritmetica 128b bignum) en interp/jit/aot", "asm_adc_sbb.vx", 42, line=3654)
modes3_case("asmjc", "asm flags-as-SSA con CF: jc/jnc (deteccion de overflow por carry tras add) en interp/jit/aot", "asm_jc.vx", 42, line=3654)
modes3_case("asmmemdisp", "asm lift de memoria completa [base+idx*scale+disp] (mov load/store + movzx/movsx desde memoria) en interp/jit/aot", "asm_mem_disp.vx", 42, line=3654)
modes3_case("asmjs", "asm flags-as-SSA con SF: js/jns/sets (bit de signo del resultado de una ALU) en interp/jit/aot", "asm_js.vx", 42, line=3654)


@case("effects_report")
def _(ctx):
    """Modelo unico de efectos: --analyze --effects deriva contratos + mapa de
    COBERTURA.  factorial es puro/determinista y sus efectos se infieren
    enteros; un programa con reflexion/FFI reporta opacidad fundamental
    (ffi-nativo), que no es imprecision sino una region que no se puede
    demostrar desde aqui."""
    # (1) factorial: puro, sin lagunas.  --effects es flag de primera clase.
    code, log = ctx.run([VM_EXE, "--analyze", ctx.src("01_factorial.vx")])
    if code != 0:
        ctx.fail("--effects salio con codigo %d" % code, log)
        return
    if "Contratos : pure" not in log:
        ctx.fail("factorial deberia derivar el contrato 'pure'", log)
        return
    if "efectos: todos se infirieron sin subir al maximo" not in log:
        ctx.fail("factorial no deberia tener efectos que suban al maximo", log)
        return
    ctx.ok("factorial: pure + efectos completos")
    # (2) reflexion/FFI: opacidad fundamental reportada.
    code, log = ctx.run([VM_EXE, "--analyze",
                         ctx.src("100_reflection_full.vx")])
    if code != 0:
        ctx.fail("--effects (reflexion) salio con codigo %d" % code, log)
        return
    if "ffi-nativo" not in log or "opacidad fundamental" not in log:
        ctx.fail("el programa con FFI deberia reportar opacidad fundamental", log)
        return
    # No debe quedar ninguna laguna de COBERTURA (op-sin-modelar) en el corpus.
    if "op-sin-modelar" in log:
        ctx.fail("hay IrOps sin modelar en el motor de efectos (cerrar cobertura)",
                 log)
        return
    ctx.ok("reflexion/FFI: opacidad fundamental reportada, sin lagunas de cobertura")
modes3_case("uf210", "unique<T> como campo de contenedor (RAII, deleter al destruir)", "210_unique_en_campo.vx", 42, line=3657)
modes3_case("ur211", "reasignacion de campo unique<T> (libera el anterior, sin fuga)", "211_unique_reassign.vx", 42, line=3658)
r0_case("sf212", "shared<T> en campo de contenedor (refcount no-GC, inc-on-store + dec-on-dtor)", "212_shared_en_campo.vx", 42, line=3659)
r0_case("ch213", "copy-hook __clone__ (tipo refcount de usuario en )", "213_copy_hook_refcount.vx", 42, line=3660)
r0_case("ch214", "copy-hook en campo de contenedor (Rc refcount en campo)", "214_copy_hook_en_campo.vx", 42, line=3661)
fails_case("mo215", "move-only: use-after-move de struct gestionado sin copy-hook", "215_move_only_err.vx", "tras moverlo", line=3662)
r0_case("ch216", "copy-hook en paso por valor (Rc refcount, clone+dtor en el call)", "216_copy_hook_por_valor.vx", 42, line=3665)
r0_case("sh217", "shared<T> refcount no-GC (inc-on-copy + free determinista al llegar a 0)", "217_shared_refcount_nogc.vx", 42, line=3666)
r0_case("gen218", "structs genericos (Caja<T>, Par<K,V>, anidados, metodos, introspeccion)", "218_structs_genericos.vx", 42, line=3667)
r0_case("gen219", "genericos con tipos de usuario + punteros (Caja<Punto>, Caja<Obj>, Caja<i64*>, Caja<VirtualPtr>)", "219_genericos_tipos_usuario.vx", 42, line=3668)
r0_case("gen220", "funciones libres genericas (id<T>, primero<K,V>, inferencia, llamadas anidadas)", "220_funciones_genericas.vx", 42, line=3669)
r0_case("gen221", "inferencia generica (CTAD Caja c = ...; auto c = ...)", "221_inferencia_generica.vx", 42, line=3670)
r0_case("gen222", "metodos genericos (obj.m<U>() en struct/clase, explicito+inferido, multi-param, U!=T)", "222_metodos_genericos.vx", 42, line=3671)
r0_case("gen223", "conceptos/constraints (built-in + predicado + bloque + estructural + composicion + where)", "223_conceptos_genericos.vx", 42, line=3672)
fails_case("gen224", "constraint violada (Punto no es Numeric)", "224_conceptos_error.vx", "no satisface el concepto 'Numeric'", line=3673)
r0_case("gen225", "especializacion total + parcial (Caja<T> / Caja<i64> / Caja<Punto> / Caja<T*>)", "225_especializacion.vx", 42, line=3676)
r0_case("gen226", "especializacion avanzada (clase + funcion + patron anidado Caja<Inner<T>>)", "226_especializacion_avanzada.vx", 42, line=3677)
r0_case("gen227", "concepts avanzado (firma estructural completa + where en metodos genericos)", "227_concepts_avanzado.vx", 42, line=3678)
fails_case("gen228", "concepto estructural rechaza firma incorrecta (bool area() != i64 area())", "228_concept_firma_error.vx", "no satisface el concepto 'Figura'", line=3679)
r0_case("gen229", "typedef/using como type-arg de genericos (#4 metodo, #6 bound, #7 spec)", "229_typedef_genericos.vx", 42, line=3682)
r0_case("def170", "defaults de campo + ={} + default() (struct + templates)", "258_struct_defaults.vx", 155, line=3691)
r0_case("cl171", "compound literals (Tipo){...} en args/returns + templates", "259_compound_literals.vx", 119, line=3692)
r0_case("cd172", "new Clase() auto-init de defaults (herencia + generico)", "260_class_defaults.vx", 159, line=3693)
r0_case("tc_ex", "contratos de tipo @pod/@no_heap/@size (--analyze)", "analyze/type_contracts.vx", 140, line=3694)
r0_case("ctr_ex", "contratos de efecto/coste: fn libre + metodo + when: por arch y por T", "analyze/contracts.vx", 110, line=3694)
r0_case("ov173", "overlay struct sobre buffer: read/write tipado por offset", "261_overlay_basics.vx", 23629, line=3699)
r0_case("ctd294", "typedefs C (sufijos/ctypes/multi-decl/union/arrays/anonimos/elaborado)", "294_c_typedefs.vx", 42, line=3704)
r0_case("cfp295", "punteros a funcion C (campo/typedef/param/var/promocion cfn)", "295_c_func_ptr.vx", 42, line=3705)
r0_case("ccr296", "const-correctness C por nivel (usos validos)", "296_const_correct.vx", 42, line=3706)
r0_case("cec297", "captura expr: comptime fn (valor) vs @Macro (codigo inyectado)", "297_comptime_expr_capture.vx", 42, line=3707)
r0_case("oip298", "only-import de namespace parcial (uintptr por @Target)", "298_only_import_partial_ns.vx", 42, line=3708)
r0_case("syscalls_os", "syscalls del SO por std.syscall, seleccionadas con @Target", "342_syscalls_os.vx", 42)
r0_case("array_local_reduccion", "recorrer un array sumando: local (pila VM) y de malloc (host)", "343_array_local_reduccion.vx", 42)
r0_case("wideint_mul_fuzz", "u128.__mul__ contra oraculo externo (20000 productos aleatorios)", "344_wideint_mul_fuzz.vx", 42)
r0_case("panic_modulo_importado", "enlace: modulo importado con panic() + global en el consumidor", "345_panic_modulo_importado.vx", 42)
# Sin AOT: capturar con try/catch exige el desenrollado nativo de
# excepciones, que sigue pendiente (el binario nativo aborta en vez de
# entrar al handler).  En interprete y JIT el FatalError si se captura.
# Ejemplos que ya eran tests (verifican R0 = 42) y no estaban registrados:
# se ejecutaban a mano o no se ejecutaban.  Un cuarto del corpus quedaba
# fuera de la suite, que podia marcar todo en verde con ejemplos rotos.
r0_case("105_decjnz_bench", "105 decjnz bench", "105_decjnz_bench.vx", 42)
r0_case("105b_decjnz_simple", "105b decjnz simple", "105b_decjnz_simple.vx", 42)
r0_case("159_macro_expr_capture", "159 macro expr capture", "159_macro_expr_capture.vx", 42)
r0_case("161_macro_ffi_compile_time", "161 macro ffi compile time", "161_macro_ffi_compile_time.vx", 42)
r0_case("162_macro_comptime_data", "162 macro comptime data", "162_macro_comptime_data.vx", 42)
r0_case("243_atomics", "243 atomics", "243_atomics.vx", 42)
r0_case("245_atomic_builtins", "245 atomic builtins", "245_atomic_builtins.vx", 42)
r0_case("40_operator_overload", "40 operator overload", "40_operator_overload.vx", 42)
r0_case("41_struct_methods", "41 struct methods", "41_struct_methods.vx", 42)
r0_case("42_struct_operator", "42 struct operator", "42_struct_operator.vx", 42)
r0_case("44_operator_overload2", "44 operator overload2", "44_operator_overload2.vx", 42)
r0_case("45_string_op_override", "45 string op override", "45_string_op_override.vx", 42)
r0_case("53_enum_simple", "53 enum simple", "53_enum_simple.vx", 42)
r0_case("59_arraylist", "59 arraylist", "59_arraylist.vx", 42)
r0_case("60_stack_iface", "60 stack iface", "60_stack_iface.vx", 42)
r0_case("static_assert_capturado", "una asercion incumplida se captura con try/catch en comptime", "368_static_assert_capturado.vx", 42)
fails_case("literal_base_invalida", "un 2 en un literal binario se rechaza al compilar", "366_literal_base_invalida.vx", "digito que no pertenece a la base")
fails_case("literal_sin_digitos", "un prefijo de base sin digitos se rechaza al compilar", "367_literal_sin_digitos.vx", "literal entero sin digitos")
r0_case("wideint_literales", "literales mas anchos que la palabra en los seis tipos", "364_wideint_literales.vx", 42)
r0_case("literal_bases", "literal ancho en binario, octal, hexadecimal y decimal", "365_literal_bases.vx", 42)
# `std.memory` desde FUERA, por TODAS sus variantes y en los TRES modos.
#
# Ningun ejemplo lo importaba, asi que la suite pasaba entera mientras
# `import std.memory` estaba roto: el modulo compila SUELTO y solo falla al
# consumirlo.  Ademas el TAMANO elige la implementacion (pocos bytes, bloques de
# registro ancho, lo grande, las colas solapadas), asi que un solo tamano dejaria
# casi todas sin tocar: el ejemplo barre 24 tramos x copia y relleno = 48
# comprobaciones byte a byte, y cada modo baja el asm por su cuenta.
@case("import_std_memory", line=None)
def _(ctx):
    """std.memory desde fuera: 24 tamanos x memcpy/memset, en los tres modos."""
    etiqueta = "importar std.memory desde fuera (24 tamanos x copia/relleno)"
    ctx.compile_vx(ctx.src("366_import_std_memory.vx"), "e366")
    ctx.ok("compilacion 366_import_std_memory.vx -> .velb")
    for modo in ("vm", "jit"):
        _, log = ctx.run_velb("e366", schedulers=1, mode=modo)
        got = get_r00(log)
        if got != 48:
            ctx.fail("%s (-m %s): R00 == %s, se esperaban 48" % (etiqueta, modo, got), log)
        ctx.ok("%s (-m %s) -> 48/48" % (etiqueta, modo))
    exe = aot_build(ctx, ctx.src("366_import_std_memory.vx"), "e366_aot",
                    etiqueta + " (-m aot)")
    rc, _ = ctx.run([exe])
    got = exit_code(rc)
    if got != 48:
        ctx.fail("%s (-m aot): sale %d, se esperaban 48" % (etiqueta, got), "")
    ctx.ok("%s (-m aot) -> 48/48" % etiqueta)
r0_case("ctor_comptime_modulo", "constructor comptime de un tipo de otro modulo", "363_ctor_comptime_modulo.vx", 42)
r0_case("asm_dse", "un asm no es barrera, pero se respeta lo que lee, lo que cambia y lo que escribe", "372_asm_dse.vx", 42)
r0_case("campo_por_puntero", "el '.' atraviesa un puntero: leer, escribir, ++, metodo, encadenar, &campo y recorrer una lista", "371_campo_por_puntero.vx", 42)
r0_case("optional_overlay", "un overlay dentro de un Optional guarda el HANDLE, no una copia: la vista sigue apuntando al buffer original", "373_optional_overlay.vx", 1673)
r0_case("fuera_de_region_ok", "lo que cabe en su hueco no molesta: ultimo qword del buffer y copia ensanchada de un agregado de 3 bytes", "374_fuera_de_region.vx", 42)
fails_case("region375", "un acceso demostrablemente fuera de su region corta la compilacion", "375_fuera_de_region_mal.vx", "outside stack")
fails_case("region376", "con tamano SIMBOLICO tambien se demuestra: el acceso se sale del mayor bloque posible", "376_rango_simbolico.vx", "outside")
r0_case("rango_ok", "el rango tambien sirve para NO estorbar: acceso que cabe en cualquier tamano posible", "377_rango_ok.vx", 42)
fails_case("region378", "un indice VARIABLE se juzga por su rango: el intervalo entero cae fuera del objeto", "378_indice_variable.vx", "outside")

# Semantica de la cadena de aspectos.  No van en `diff3_case` porque el AOP no
# existe en compilacion nativa (se rechaza con un error), asi que se comprueban
# en interprete y JIT.  Fijan el ORDEN y lo que ve cada advice, que es lo que
# cualquier optimizacion del despacho -- devirtualizar, tejer, integrar -- tiene
# que dejar intacto: hasta ahora eso lo cubrian dos ejemplos que solo miraban el
# resultado final, y el resultado final no distingue una cadena bien recorrida
# de otra que casualmente suma lo mismo.
vm_jit_r0_case("aop_cadena_orden", "orden de la cadena: los @Before, el metodo y el @After, y el @After ve los args ORIGINALES", "379_aop_cadena_orden.vx", 42)
vm_jit_r0_case("aop_around_anidado", "varios @Around se ANIDAN, y el primero declarado es el mas externo", "380_aop_around_anidado.vx", 147)
vm_jit_r0_case("aop_after_returning", "@AfterReturning recibe el RESULTADO del metodo, no sus argumentos", "381_aop_after_returning.vx", 742)
r0_case("ctor_importado", "construir un struct declarado en otro modulo", "362_ctor_importado.vx", 42)
r0_case("ctor_comptime", "constructor comptime: recoge la llamada cuando ninguna sobrecarga encaja", "361_ctor_comptime.vx", 42)
r0_case("enum_valor_importado", "enum con valor importado: conserva valores y compara por contenido", "359_enum_valor_importado.vx", 42)
r0_case("wideint_completo", "recorrido completo de u128/i128/u256/i256/u512/i512 con toString", "358_wideint_completo.vx", 42)
r0_case("herencia_interpolacion", "metodo heredado que devuelve texto interpolado (el clon perdia la interpolacion)", "357_herencia_interpolacion.vx", 42)
r0_case("generica_desde_metodo", "funcion generica monomorfizada desde el cuerpo de un metodo", "356_generica_desde_metodo.vx", 42)
r0_case("wideint_512_signed", "i512: signo, negacion, desplazamiento aritmetico y division con signo", "355_wideint_512_signed.vx", 42)
r0_case("wideint_512", "u512: tercer piso, acarreo entre mitades de 256 y division contrastada con la mul", "354_wideint_512.vx", 42)
r0_case("wideint_256_div", "u256/i256: division shift-resta, contrastada con la multiplicacion", "353_wideint_256_div.vx", 42)
r0_case("wideint_256_mul", "u256: multiplicacion modular y producto completo de 128x128", "352_wideint_256_mul.vx", 42)
r0_case("wideint_carry", "acarreo y prestamo como primitivas de u128, propagados por Wide256", "351_wideint_carry.vx", 42)
r0_case("wideint_256_signed", "i256: negacion, comparadores con signo y desplazamiento aritmetico", "350_wideint_256_signed.vx", 42)
r0_case("wideint_256", "u256: acarreo y prestamo entre mitades de 128, desplazamientos que cruzan la frontera", "349_wideint_256.vx", 42)
r0_case("comptime_literal_import", "std.comptime.literal cross-module: parse de un entero en compile-time", "348_comptime_literal_import.vx", 42)
r0_case("div_cero_detiene", "una division por cero detiene el proceso; capturada es un FatalError", "347_div_cero_detiene.vx", 42)
caught_fault_case("fallo_sistema_capturado", "un fallo del procesador capturado con try/catch, y el programa sigue", "369_fallo_del_sistema_capturado.vx", 48)
caught_fault_case("instr_no_soportada", "una instruccion que este procesador no tiene se cuenta y se captura", "370_instruccion_no_soportada.vx", 46)
asm_lift_case("asm_elevado_equivale", "elevar un asm a IR no cambia lo que el programa hace", "371_asm_elevado_equivale.vx")
modes3_case("asm_destruye_registro", "un asm que destruye un registro no se lleva por delante lo que hubiera vivo", "372_asm_destruye_registro.vx", 42)
asm_lift_case("asm_destruye_registro_eq", "destruir un registro da lo mismo elevado que opaco", "372_asm_destruye_registro.vx")
# Las 32 variantes de std.memory, cada una por su nombre y comprobada byte a
# byte, ejecutando solo las que este procesador soporta.  Interp+JIT: el nativo
# queda fuera porque el numero depende de los rasgos de la maquina y el arnes
# compara el valor devuelto, no el codigo de salida.
vm_jit_r0_case("std_memory_variantes", "las 32 variantes de std.memory, una por una y byte a byte", "367_std_memory_variantes.vx", 42)
modes3_case("optional_struct", "Optional<T> con T = struct por valor (payload dimensionado + copia)", "346_optional_struct.vx", 52)
r0_case("cme299", "captura expr CROSS-MODULO (src(expr) en otro modulo, DSL crudo)", "299_cross_module_expr.vx", 42, line=3709)
r0_case("scs300", "source(expr) de std.comptime (re-export + siembra transitiva)", "300_stdlib_comptime_source.vx", 42, line=3710)
r0_case("mch301", "@Macro genera codigo con helper comptime expr (CALLVM no fold-vacio)", "301_macro_codegen_helper.vx", 42, line=3711)
r0_case("cev302", "enum C-style valued (typedef enum + bare enum + backing inferido/string/u8)", "302_c_enum_valued.vx", 42, line=3712)
r0_case("csf303", "structs C: multi-declarador de campo + struct tagless top-level", "303_c_struct_fields.vx", 42, line=3713)
r0_case("ctt304", "comptime fn con retorno typedef del modulo importada cross-modulo", "304_comptime_typedef_import.vx", 42, line=3714)
r0_case("aef305", "enum ADT payloadless como campo de struct (plano + typedef struct)", "305_adt_enum_field.vx", 42, line=3715)
r0_case("als306", "@align(N) a nivel de struct (plano + typedef struct): size padeado + align", "306_align_struct.vx", 42, line=3716)
r0_case("nec307", "forwarding de expr-capture anidado (comptime fn pasa su expr a otra)", "307_nested_expr_capture.vx", 42, line=3717)
r0_case("nrv308", "variadico crudo '...' en @Naked (N args en arg-regs del ABI, sin vacount)", "308_naked_raw_variadic.vx", 42, line=3718)
r0_case("osp309", "struct opaco 'typedef struct Tag *P;' (incompleto completable + deref)", "309_opaque_struct_ptr.vx", 42, line=3719)
r0_case("mne310", "@Macro inyecta codigo con expr-capture anidado (forward del expr param)", "310_macro_nested_expr.vx", 42, line=3720)
r0_case("bfc311", "compilador Brainfuck SOLO comptime (enum tokens + match + s[i] + lambda infer)", "311_bf_comptime.vx", 42, line=3721)
r0_case("gca312", "compound assign sobre global float/int (bits IEEE vs aritmetica entera)", "312_global_compound_assign.vx", 42, line=3727)
r0_case("gxm313", "globals de otro modulo: const inlineado + string desde su literal + mutable con storage compartido", "313_globals_cross_module/main.vx", 42, line=3729)
r0_case("ovl314", "operadores sobrecargados: aritmeticos, compuestos, ++/--, bitwise, comparacion, ! y &&", "314_operadores_sobrecargados.vx", 42, line=3731)
r0_case("ovl315", "operadores de acceso sobrecargados: *x, x = v, x(...) y x{...}", "315_operadores_llamada_deref.vx", 42, line=3733)
fails_case("ovl316", "'a{...}' sobre un tipo que no declara __braces__", "316_braces_sin_dunder_err.vx", "no declara '__braces__'", line=3735)
r0_case("rmw317", "fusion read-modify-write: `g = g OP x` -> `g OP= x` (atomico sin load suelto, 10 operadores)", "317_rmw_fusion.vx", 42, line=3737)
r0_case("atm318", "atomic<T> de la stdlib: las 3 formas del incremento, compare_swap y swap", "318_atomic_tipo.vx", 42, line=3739)
r0_case("atg319", "struct como global + contador atomico global compartido", "319_atomic_global.vx", 42, line=3741)
r0_case("nwt320", "typedef T X new sobre tipos de usuario: struct, clase y enum", "320_newtype_tipos_usuario.vx", 42, line=3743)
r0_case("str321", "cadenas conocidas al compilar: literales adyacentes, \"a\"+\"b\" y a+b via variables", "321_strings_comptime.vx", 42, line=3745)
r0_case("tryasg474", "asignar a una variable de fuera DENTRO del init de otra, en un try que lanza", "474_try_assign_en_init.vx", 60, line=3746)
r0_case("asynctipos475", "@Async con parametros de tipos aliased (no primitivos sueltos)", "475_async_tipos_no_listados.vx", 42, line=3748)
r0_case("retspawn476", "`return` a mano dentro del cuerpo de un spawn (y una lambda dentro, que si retorna)", "476_return_en_spawn.vx", 42, line=3750)
r0_case("dtorvirt477", "destructor por tabla (clase extendida) vs directo (clase que nadie extiende)", "477_dtor_virtual.vx", 42, line=3752)
r0_case("finales478", "clases final: las dos formas, con visibilidad, y una final que SI hereda", "478_clases_finales.vx", 42, line=3754)
fails_case("finalher479", "heredar de una clase final es error de compilacion", "479_final_hereda_err.vx", "declarada final", line=3756)
r0_case("parmet480", "un metodo acepta lo mismo que una funcion suelta: puntero a funcion y no-nulo", "480_params_metodo.vx", 42, line=3758)
r0_case("varmet481", "variadico en los SEIS contextos: funcion, metodo, ctor, struct, interfaz y lambda", "481_variadicos_todos.vx", 42, line=3760)
r0_case("matrizparam482", "matriz COMPLETA de parametros: cada forma en cada contexto (funcion, comptime, metodo, ctor, struct, interfaz, lambda)", "482_matriz_parametros.vx", 42, line=3762)
r0_case("params_modo483", "cuantos argumentos caben segun el modo: doce en nativo, repartidos en bytecode (@Target)", "483_params_limite_por_modo.vx", 42, line=3764)
r0_case("dtorslot484", "destructores: hueco cero de la tabla, override, y la CADENA hacia la base en orden", "484_dtor_slot_cero.vx", 42, line=3766)
r0_case("regnames485", "nombres del usuario que coinciden con registros (clase, campo, metodo, funcion, parametro, local)", "485_nombres_de_registro.vx", 42, line=3768)
r0_case("payloadvar486", "la carga de una variante admite lo mismo que un parametro (newtype por constante, nombre de funcion)", "486_payload_variante.vx", 42, line=3770)
r0_case("companchos487", "un tipo estrecho sigue siendolo al ejecutar en compilacion: el registro es transporte, no tipo", "487_comptime_anchos.vx", 42, line=3772)
r0_case("extimpl488", "impl: metodos anadidos desde fuera con 0..3 parametros, sobre struct y sobre clase, con y sin concepto", "488_impl_metodos.vx", 42, line=3774)
r0_case("arguni489", "la MISMA expresion como argumento en las siete formas de llamar (funcion, ctor, metodo, estatico, struct, closure, variante)", "489_argumentos_uniformes.vx", 42, line=3776)
fails_case("ctornomet490", "un constructor no se puede llamar como metodo de instancia (viven en la misma lista)", "490_ctor_no_es_metodo.vx", "no tiene un metodo", line=3778)
fails_case("extret491", "'extension' esta retirada y el error dice con que se sustituye", "491_extension_retirada_err.vx", "ya no existe", line=3780)
r0_case("vecall492", "todas las formas que el vectorizador reconoce, y las dos que no: la salida es la misma con y sin vectorizar, asi que lo que se comprueba es el IR (tools/verify_vectorize.sh idiomas)", "492_vectorizador_completo.vx", 42, line=3782)
r0_case("stdnum493", "std.numeric desde fuera: las diez operaciones, con el segundo import que rompia la instanciacion de plantillas cross-module", "493_std_numeric.vx", 42, line=3784)
modes3_case("upcast494", "una subclase cabe donde se espera la base en los SEIS sitios que preguntan si un valor cabe (declarar, reasignar, devolver, argumento, campo, parametro de un set); la reasignacion y tres mas no lo aceptaban", "494_asignar_subclase.vx", 42, line=3786)
modes3_case("itfherencia495", "heredar de una clase Y cumplir una interfaz: las dos numeraciones de metodos no se pueden pisar.  Las dos formas en que se solapan: sin constructor declarado (el primer metodo de la clase cae donde el primero de la interfaz) y con una interfaz de dos metodos (el segundo cae sobre un metodo de la clase)", "495_interfaz_y_herencia.vx", 42, line=3788)
modes3_case("itfcadena496", "una interfaz que extiende a otra que extiende a otra: quien cumple la de arriba vale para todas las de abajo, al asignar, al reasignar, al pasar como argumento y al preguntarselo al compilador.  El padre de una interfaz se guarda en la SUPERCLASE, y el recorrido del comprobador solo miraba la lista de interfaces", "496_interfaces_encadenadas.vx", 42, line=3790)
modes3_case("tdstruct497", "las dos formas de declarar un agregado admiten lo mismo dentro de las llaves: metodos, acceso y miembros estaticos.  La forma C tenia su propio analizador -- una copia cuyo comentario decia \"reusar\" y copiaba -- que se habia quedado en los campos a secas", "497_typedef_struct_completo.vx", 42, line=3792)
modes3_case("typename498", "typename<T>() nombra cualquier tipo del lenguaje.  La introspeccion tenia su propia tabla y las ocho colecciones primitivas no estaban: caian a un default que devolvia \"?\", pese a que el compilador escribe su nombre en cualquier mensaje de error", "498_typename_completo.vx", 42, line=3794)
modes3_case("alinea499", "la alineacion de un campo NO es su tamano: un Result mide 24 y se alinea a 8.  El layout la tomaba igual al tamano -- 24, que ni es potencia de dos -- y el struct media 72 donde le bastan 40.  La alineacion buena estaba en la tabla de la introspeccion, al lado", "499_alineacion_campos.vx", 42, line=3796)
modes3_case("estbuf500", "un metodo estatico que devuelve algo que viaja por buffer: quien llama y quien es llamado tienen que estar de acuerdo en QUE hace falta buffer, CUANTO mide y DONDE vive.  Las tres fallaban por su cuenta, en clase y en struct, que se resuelven por caminos distintos", "500_estaticos_retorno_buffer.vx", 42, line=3798)
modes3_case("estlambda501", "un metodo estatico que devuelve un lambda o un puntero inteligente.  La condicion de \"esto viaja por buffer\" estaba escrita NUEVE veces y ninguna lista estaba completa: la de este camino contaba cinco casos de siete y se dejaba fuera justo estos dos, asi que el metodo escribia encima de su primer argumento de verdad", "501_estaticos_lambda_y_unique.vx", 42, line=3800)
modes3_case("metstruct502", "un metodo de instancia que devuelve un struct por valor: el metodo declaraba el buffer y quien llamaba no lo reservaba ni lo pasaba, porque sus dos listas de \"esto viaja por buffer\" tenian cuatro y tres casos respectivamente", "502_metodo_devuelve_struct.vx", 42, line=3802)
modes3_case("optptr503", "sacar el valor de un Optional<T*> daba un puntero SIN marcar de que memoria es, asi que el deref se emitia con la instruccion de la maquina virtual sobre una direccion del anfitrion y devolvia cero, en silencio.  La regla estaba escrita en cuatro sitios y ninguno cubria este; hacia falta una llamada nativa detras para destaparlo", "503_optional_de_puntero.vx", 42, line=3804)
modes3_case("optsinmarca504", "un Optional cuyo valor no puede ser cero no necesita una palabra aparte que diga si hay algo: el cero sobra y sirve de marca, y el conjunto mide 8 en vez de 16.  Se aplica solo donde el tipo lo promete (un prestamo), nunca a un T* crudo, donde Some(nulo) dejaria de distinguirse de vacio", "504_optional_sin_marca.vx", 42, line=3806)
modes3_case("nonnull505", "`nonnull` se comprueba al asignar (antes solo se rechazaba el literal null), y no cuesta nada cuando el valor no puede ser nulo: el pase que quita comprobaciones demostrables las borra.  Ademas `nonnull` y `!!` son la misma cosa, asi que escribir `!!` al asignar a un nonnull es redundante y tampoco cuesta", "505_nonnull_se_cumple.vx", 42, line=3808)
modes3_case("ayudantes507", "unwrap_or(x, def) y expect(x, \"msg\"): la salida que NO mata el proceso y la que si pero diciendo por que.  Desde que fallar una afirmacion es fatal, importa que la forma recuperable sea la comoda -- antes solo estaba escribir el if a mano --.  Los dos se montan con las mismas dos piezas que isPresent y unwrap; ninguno vuelve a escribir como se lee un Optional", "507_ayudantes_optional.vx", 42, line=3810)
modes3_case("sufijos512", "un literal puede decir de que tipo es (42_i8, 0xFF_u32, 3.14_f64), en cualquier base y con `_` separando millares.  Sin sufijo lo sigue poniendo el contexto, que es la forma normal; el sufijo sirve cuando no hay contexto o cuando decirlo aclara", "512_sufijos_de_tipo.vx", 55, line=3812)
fails_case("neg_sufijo_c",
           "un sufijo de C no nombra ningun tipo de Vesta: `100L` dice `long`, "
           "y hasta ahora se consumia sin efecto ninguno -- el literal valia "
           "i32 igual, o sea que el sufijo mentia a quien viniera de C",
           "513_neg_sufijo_c.vx", "Vesta has no such type")
fails_case("neg_sufijo_no_cabe",
           "un literal que se contradice: el sufijo dice u8 y 300 no es "
           "ningun u8.  Truncar es una decision y se escribe: `(u8) 300`",
           "514_neg_sufijo_no_cabe.vx", "does not fit in its own suffix")
fails_case("neg_sufijo_entero_en_float",
           "sufijo entero sobre un numero con decimales: perder la parte "
           "decimal tambien es una decision y tambien se escribe",
           "515_neg_sufijo_entero_en_float.vx", "integer suffix")
modes3_case("uniquepalabra517", "un unique<T> mide UNA palabra: guarda el puntero y nada mas, porque quien libera va en el TIPO.  Antes median dos y la segunda era un CERO con el liberador de por defecto -- ocho bytes por una constante en el caso mas frecuente --, y hacia falta porque no habia forma de decirlo en una firma.  Comprueba que el cambio no se nota: los dos liberadores, adoptar y empaquetar, mover, campo, reasignar y devolver", "517_unique_una_palabra.vx", 31, line=3815)
modes3_case("uniquecampo518", "un unique<T> dentro de un objeto es un puntero dentro del objeto: el campo ES la ranura.  Antes guardaba la DIRECCION de otra ranura reservada aparte -- dos saltos de memoria y dos reservas para un solo recurso --, y esa ranura estaba SIEMPRE en la memoria del anfitrion aunque el contenedor viviera en la de la maquina virtual.  Por eso el ejemplo pone el mismo campo en una clase y en un struct, que viven en sitios distintos", "518_unique_campo_sin_rodeo.vx", 42, line=3816)
modes3_case("resultgrande516", "un Result cuyo valor no cabe en una palabra: la disposicion estaba escrita a mano en seis sitios (24 bytes, valor en el 8, error en el 16), y ademas un agregado se guardaba como una palabra en vez de copiar sus bytes -- lo que se sacaba eran CEROS, sin error ni aviso.  Mismo fallo que tenia Optional y mismo arreglo: preguntar a un solo sitio", "516_result_payload_grande.vx", 42, line=3814)
const_reject_case("cneg_ptr_pointee", "escribir *p con const i32* (pointee const)", "const i32* p; i32 c = 1; p = &c; *p = 2;", line=3747)
const_reject_case("cneg_ptr_const", "reasignar q con i32* const (puntero const)", "i32 c = 1; i32* const q = &c; i32 d = 2; q = &d;", line=3749)
const_reject_case("cneg_var", "escribir a variable const no-puntero", "const i32 x = 5; x = 6;", line=3751)

# --- Los BANCOS DE PRUEBAS, en los tres modos ---------------------------------
#
# Tambien tienen que dar el mismo resultado interpretados, compilados al vuelo y
# compilados a nativo, y no se comprobaba: solo se tocaban al MEDIR, que es algo
# que se hace de vez en cuando.  Asi que un cambio del generador de codigo podia
# dejarlos rotos y no se sabia hasta la siguiente medicion -- y eso paso: en
# Linux casi todos morian y aqui la suite seguia verde, porque lo que rompia era
# la reserva de memoria, que alli pasa por llamadas al sistema y aqui no.
#
# Sin valor esperado a mano: un banco devuelve una suma de control que depende
# de su trabajo, y fijarla aqui seria copiar un numero que nadie ha comprobado.
# Lo que se afirma es que los tres modos COINCIDEN, con el interprete de
# oraculo.
modes3_agree_case("bench_alloc_huge", "banco alloc_huge: los tres modos coinciden", "benchmark/alloc_huge/main.vx")
modes3_agree_case("bench_alloc_large", "banco alloc_large: los tres modos coinciden", "benchmark/alloc_large/main.vx")
modes3_agree_case("bench_alloc_medium", "banco alloc_medium: los tres modos coinciden", "benchmark/alloc_medium/main.vx")
modes3_agree_case("bench_alloc_small", "banco alloc_small: los tres modos coinciden", "benchmark/alloc_small/main.vx")
modes3_agree_case("bench_array_sum", "banco array_sum: los tres modos coinciden", "benchmark/array_sum/main.vx")
modes3_agree_case("bench_bitops", "banco bitops: los tres modos coinciden", "benchmark/bitops/main.vx")
modes3_agree_case("bench_branch_unpredict", "banco branch_unpredict: los tres modos coinciden", "benchmark/branch_unpredict/main.vx")
modes3_agree_case("bench_callvirt", "banco callvirt: los tres modos coinciden", "benchmark/callvirt/main.vx")
modes3_agree_case("bench_callvirt_hot", "banco callvirt_hot: los tres modos coinciden", "benchmark/callvirt_hot/main.vx")
modes3_agree_case("bench_cmp_fusion", "banco cmp_fusion: los tres modos coinciden", "benchmark/cmp_fusion/main.vx")
modes3_agree_case("bench_fib_recursive", "banco fib_recursive: los tres modos coinciden", "benchmark/fib_recursive/main.vx")
modes3_agree_case("bench_fp_jit", "banco fp_jit: los tres modos coinciden", "benchmark/fp_jit/main.vx")
modes3_agree_case("bench_hash_lookup", "banco hash_lookup: los tres modos coinciden", "benchmark/hash_lookup/main.vx")
modes3_agree_case("bench_int_mixed", "banco int_mixed: los tres modos coinciden", "benchmark/int_mixed/main.vx")
modes3_agree_case("bench_intops_jit", "banco intops_jit: los tres modos coinciden", "benchmark/intops_jit/main.vx")
modes3_agree_case("bench_jit_method", "banco jit_method: los tres modos coinciden", "benchmark/jit_method/main.vx")
modes3_agree_case("bench_mem_class", "banco mem_class: los tres modos coinciden", "benchmark/mem_class/main.vx")
modes3_agree_case("bench_mem_malloc_free", "banco mem_malloc_free: los tres modos coinciden", "benchmark/mem_malloc_free/main.vx")
modes3_agree_case("bench_mem_struct", "banco mem_struct: los tres modos coinciden", "benchmark/mem_struct/main.vx")
modes3_agree_case("bench_memcpy_loop", "banco memcpy_loop: los tres modos coinciden", "benchmark/memcpy_loop/main.vx")
modes3_agree_case("bench_nested_loops", "banco nested_loops: los tres modos coinciden", "benchmark/nested_loops/main.vx")
modes3_agree_case("bench_obj_accum", "banco obj_accum: los tres modos coinciden", "benchmark/obj_accum/main.vx")
modes3_agree_case("bench_pic_real", "banco pic_real: los tres modos coinciden", "benchmark/pic_real/main.vx")
modes3_agree_case("bench_polymorphic", "banco polymorphic: los tres modos coinciden", "benchmark/polymorphic/main.vx")
modes3_agree_case("bench_quicksort", "banco quicksort: los tres modos coinciden", "benchmark/quicksort/main.vx")
modes3_agree_case("bench_rotops_jit", "banco rotops_jit: los tres modos coinciden", "benchmark/rotops_jit/main.vx")
modes3_agree_case("bench_state_machine", "banco state_machine: los tres modos coinciden", "benchmark/state_machine/main.vx")
modes3_agree_case("bench_string_hot", "banco string_hot: los tres modos coinciden", "benchmark/string_hot/main.vx")
modes3_agree_case("bench_string_workout", "banco string_workout: los tres modos coinciden", "benchmark/string_workout/main.vx")
modes3_agree_case("bench_struct_field", "banco struct_field: los tres modos coinciden", "benchmark/struct_field/main.vx")
modes3_agree_case("bench_tight_loop", "banco tight_loop: los tres modos coinciden", "benchmark/tight_loop/main.vx")
modes3_agree_case("bench_vec_axpy", "banco vec_axpy: los tres modos coinciden", "benchmark/vec_axpy/main.vx")
const_reject_case("cneg_incdec", "++ sobre variable const", "const i32 x = 5; x++;", line=3753)
const_reject_case("cneg_discard", "descartar const: i32* = const i32*", "const i32* cp; i32 c = 1; cp = &c; i32* m = cp;", line=3755)
modes3_case("en284", "concepts+enums (is_enum, Enum, ValuedEnum, backing, concepto usuario)", "284_enum_concepts.vx", 42, line=3817)
fails_case("en285", "constraint ValuedEnum rechaza un enum ADT (Shape sin valor)", "285_enum_concept_error.vx", "no satisface el concepto 'ValuedEnum'", line=3819)
modes3_case("en286", "concepto como predicado (Enum/ValuedEnum/Numeric<T>() + usuario + composicion)", "286_concept_predicate.vx", 42, line=3824)
modes3_case("en287", "comptime block: vars normales sin anotar + enums + control de flujo", "287_comptime_vars.vx", 42, line=3826)
modes3_case("ca288", "inline asm en comptime fn (ComptimeVM: interp/JIT/AOT)", "288_comptime_asm.vx", 42, line=3832)
modes3_case("ca289", "comptime const + static_assert desde asm fn (ComptimeVM)", "289_comptime_asm_const.vx", 42, line=3836)
modes3_case("ca290", "comptime fn llama a helper @Naked (asm transitivo, ComptimeVM)", "290_comptime_asm_naked.vx", 42, line=3840)
modes3_case("ca291", "static_assert en comptime block sobre valor de asm (ComptimeVM)", "291_comptime_asm_block_assert.vx", 42, line=3843)
fails_case("ca292", "static_assert falso sobre valor de asm comptime (pass-2 autoritativo)", "292_comptime_asm_assert_fail.vx", "static_assert FAILED: V debe ser 99", line=3846)
modes3_case("naked231", "LIM-B: fn normal llama @Naked del mismo fichero", "231_naked_call_from_normal.vx", 42, line=3850)
modes3_case("fiber230", "230 fiber ping-pong (primitivo @Naked inlineado)", "230_fiber_pingpong.vx", 10, line=3852)
modes3_case("cmb240", "combo memoria: unique<T> envuelve otro owned (shared/unique)", "240_unique_wraps_owned.vx", 42, line=3859)
modes3_case("cmb241", "combo memoria: unique<T*> envuelve puntero raw + ptr_of", "241_unique_wraps_rawptr.vx", 42, line=3861)
modes3_case("cmb242", "combo memoria: move(unique) hacia un campo (heap slot)", "242_move_into_field.vx", 1, line=3863)
modes3_case("cmb243", "combo memoria: move(unique_with) transfiere deleter estatico", "243_move_custom_deleter.vx", 1, line=3865)
modes3_case("cmb244", "combo memoria: gc<T> con campo owned (shared) -> dtor directo AOT", "244_gc_owned_field_aot.vx", 42, line=3870)
modes3_case("cmb245", "combo memoria: gc<T> generico anidado (gc_box) + cero fuga -> 3 modos", "245_gc_nested_generic.vx", 43, line=3877)
modes3_case("gc249", "gc AOT: scan preciso de raices (walk por tamano de frame) preserva la raiz viva", "249_gc_aot_precise_scan.vx", 42, line=4028)
modes3_case("gc250", "gc: compactacion mark-compact del OldGen (sliding in-place, opt-in)", "250_gc_compact.vx", 42, line=4039)
modes3_case("gc252", "gc: campo-referencia gc<Clase> tras major_gc (read encadenado seguro)", "252_gc_ref_field.vx", 42, line=4097)


# --- herencia estatica de structs + Self ----------------------------------
modes3_case("herencia_self", "herencia estatica de structs + Self (campos/metodos heredados, Self covariante, fluent)", "322_herencia_self.vx", 84, line=4210)
modes3_case("struct_copy_return", "regresion SROA: copiar this a local + modificar campo + return (struct 1 campo)", "323_struct_copy_return.vx", 147, line=4211)
fails_case("abstract_neg", "struct @Abstract no instanciable por valor", "324_abstract_negativo.vx", "es @Abstract")
modes3_case("iface_abstract", "interfaz (concept, contrato) vs @Abstract (base con impl); struct usa ambos", "325_interfaz_vs_abstract.vx", 67)
fails_case("iface_no_sat", "struct declara ': IConcepto' pero no lo satisface", "326_interfaz_no_satisface_err.vx", "no satisface el concepto")
modes3_case("abs_chain_iface", "@Abstract hereda de @Abstract + interfaz heredada verificada en el concreto", "327_abstract_cadena_iface.vx", 50)
modes3_case("virtual_dispatch", "@Virtual: dispatch dinamico por vtable (Figura*->area() del tipo real), interp=jit=aot", "328_virtual_dispatch.vx", 42)
fails_case("virtual_self_err", "Self prohibido en metodo @Virtual (mecanismos opuestos)", "329_virtual_self_err.vx", "no puede usarse en un metodo @Virtual")
diff3_case("regpress_udivmod", "presion de registros (udivmod): interp=oraculo, jit y aot deben coincidir", "330_regalloc_pressure_udivmod.vx")


@case("ctpe_udivmod")
def case_ctpe_udivmod(ctx):
    """El precomputo no puede alterar el resultado del udivmod bajo presion."""
    h_ctpe_conformance(ctx, "CTPE conforme (udivmod bajo presion)",
                       "330_regalloc_pressure_udivmod.vx")
diff3_case("wideint_import", "import cross-module de struct con metodos+herencia+operadores (u128 de std.wideint)", "331_wideint_import.vx")
diff3_case("struct_static", "metodos static en struct (factorias sin this, SRET + escalar)", "332_struct_static_methods.vx")
diff3_case("struct_static_fields", "campos static en struct (contador/singleton por-tipo)", "334_struct_static_fields.vx")
diff3_case("wideint_signed", "i128 con signo: div/mod truncados, neg, comparadores (std.wideint)", "333_wideint_signed.vx")
diff3_case("struct_constructors", "constructores de struct value-type con overload por aridad", "335_struct_constructors.vx")
diff3_case("comptime_ctor_literal", "constructor comptime de struct (i64 + param expr): literales de tipo usuario", "337_comptime_ctor_literal.vx")
diff3_case("comptime_parse_literal", "parseo de literal entero en comptime (ctor expr -> helper de parseo -> IntLit)", "338_comptime_parse_literal.vx")
diff3_stdout_case("string_conformance", "matriz de conformidad de cadenas: misma salida en interp, JIT y AOT", "339_string_conformance.vx")
diff3_stdout_case("spill_opcodes", "opcodes con operando derramado: misma salida en interp, JIT y AOT", "340_spill_opcodes.vx")
diff3_stdout_case("spill_reflexion", "reflexion con operando derramado (jit == interp; AOT la rechaza por diseno)", "341_spill_reflexion.vx", aot=False)


# --- stdlib: ejemplos y tests de la biblioteca estandar de Vesta -----------
modes3_case("stdlib_atomic", "stdlib atomic<T>: anchos 1/2/4/8 + f32/f64 + bool + disponibilidad por where", "stdlib/atomic.vx", 161, line=4200)


# --- Concurrencia de verdad: hilos del SO y el planificador M:N ------------
#
# Estos NO corren en el interprete y no es un fallo suyo: piden hilos del
# sistema operativo, el planificador M:N de fibras y exclusion mutua entre
# hilos paralelos, y eso solo existe en el binario nativo.  Todos siguen el
# mismo convenio que sus cabeceras describen -- devuelven 42 si el resultado
# salio EXACTO, es decir si la exclusion mutua hizo su trabajo y no se perdio
# ni se duplico ninguna tarea --, asi que un 42 aqui no es un numero magico:
# es la unica salida posible cuando la concurrencia es correcta.
#
# Estaban los diez SIN CUBRIR: la suite daba 934 pasos verdes sin ejecutar una
# sola linea de canales, select, mutex, pools ni hilos.
aot_case("conc_sync_contention", "contencion general del planificador de fibras", "237_sync_general_contention.vx", 42)
aot_case("conc_real_threads", "dos HILOS del SO bajo el monitor: 100000 incrementos exactos", "238_real_threads.vx", 42)
aot_case("conc_pool_stealing", "planificador M:N con robo de trabajo (deque Chase-Lev): arbol fork-join", "241_pool_workstealing.vx", 42)
aot_case("conc_pool_fibers", "fibras que ceden el turno dentro del pool", "242_pool_fibers_yield.vx", 42)
aot_case("conc_channels", "canales con buffer sobre el M:N: productor/consumidor con park/wake real", "244_channels.vx", 42)
aot_case("conc_chan_close", "cerrar un canal despierta a quien espera", "250_chan_close.vx", 42)
aot_case("conc_select", "select sobre varios canales", "252_select.vx", 42)
aot_case("conc_select_send", "select del lado del envio", "253_select_send.vx", 42)
aot_case("conc_select_mixed", "select mezclando envio y recepcion", "254_select_mixed.vx", 42)
aot_case("conc_mutex", "mutex cooperativo de fibras cross-hilo: 4x20000 incrementos exactos", "255_mutex.vx", 42)
# El interprete los ejecuta sin quejarse pero devuelve 0: el trabajo lo hacen
# los hilos, que ahi no existen.  Un 0 silencioso es peor que un fallo, y por
# eso se les pide el modo en el que su respuesta significa algo.
aot_case("conc_spawn_threads", "spawn sobre hilos del SO", "239_spawn_threads.vx", 42)
aot_case("conc_spawn_captures", "spawn con capturas sobre hilos del SO", "240_spawn_captures.vx", 42)


# --- Ejemplos que corrian igual en los tres modos y nadie ejecutaba ---------
#
# Estaban fuera de la suite sin motivo: se comprobo uno por uno que interprete,
# JIT y nativo dan el MISMO resultado.  Los que caben en un codigo de salida
# (<= 255) se fijan por valor exacto; los que no, van por la red diferencial --
# el codigo de salida de un binario son 8 bits, y exigir ahi un 0x2476 seria
# pedirle al AOT algo que no puede contestar.
modes3_case("macro_walk_pchase", "macro que recorre una cadena de punteros en tiempo de compilacion", "160_macro_walk_pchase.vx", 42)
modes3_case("vreg_obj_loop_callvirt", "bucle con despacho virtual sobre objeto (camino vreg)", "180_vreg_obj_loop_callvirt.vx", 34)
modes3_case("vreg_alloca_vm_escape", "reserva local que escapa a memoria de la VM", "181_vreg_alloca_vm_escape.vx", 70)
modes3_case("fiber_lifecycle", "ciclo de vida de una fibra: crear, cambiar, terminar", "232_fiber_lifecycle.vx", 2)
modes3_case("chan_try", "canal en su forma NO bloqueante (try_send / try_recv)", "251_chan_try.vx", 42)
modes3_case("overlay_dynamic", "vista con campos cuyo offset se decide en ejecucion", "262_overlay_dynamic.vx", 128)
modes3_case("overlay_scan", "recorrido de una estructura con vistas encadenadas", "265_overlay_scan.vx", 140)
modes3_case("overlay_elf_parser", "leer las cabeceras de un ELF con vistas", "272_overlay_elf_parser.vx", 2)
modes3_case("overlay_pe_parser", "leer las cabeceras de un PE con vistas", "273_overlay_pe_parser.vx", 2)
modes3_case("overlay_parent_walk", "una vista que sube a la que la contiene", "276_overlay_parent_walk.vx", 162)
modes3_case("overlay_element_tlv", "elementos tipo-longitud-valor sobre una vista", "277_overlay_element_tlv.vx", 170)
modes3_case("overlay_extent", "extension de una vista calculada de sus propios campos", "278_overlay_extent.vx", 40)
modes3_case("bounds_check_elim", "el optimizador quita comprobaciones de limites que ya sabe ciertas", "315_bounds_check_elim.vx", 55)
modes3_case("sync_tiny", "sincronizacion en su forma minima", "35b_sync_tiny.vx", 1)
modes3_case("lambda_simple", "lambda sin mas", "50_lambda_simple.vx", 42)
modes3_case("lambda_no_capture", "lambda que no captura nada: baja a funcion suelta", "50b_lambda_no_capture.vx", 42)
modes3_case("lambda_captura", "lambda que captura de su entorno", "51_lambda_captura.vx", 30)
modes3_case("lambda_hof", "lambdas pasadas y devueltas como valores", "52_lambda_hof.vx", 100)
modes3_case("enum_payload", "enum cuyas variantes llevan datos", "54_enum_payload.vx", 105)
modes3_case("linkedlist_basico", "lista enlazada: construir y recorrer", "55_linkedlist_basico.vx", 6)
modes3_case("linkedlist_hof", "lista enlazada con funciones de orden superior", "56_linkedlist_hof.vx", 21)
modes3_case("rpn_calc", "calculadora en notacion polaca: se comprueba a si misma y devuelve 42", "61_rpn_calc.vx", 42)
modes3_case("compose_curry", "composicion y aplicacion parcial de funciones", "62_compose_curry.vx", 42)
modes3_case("match_repro", "reproductor minimo de match", "90_match_repro.vx", 2)
modes3_case("dbg_walk", "cadena de llamadas minima (reproductor del depurador)", "_dbg_test.vx", 42)
modes3_case("ffi_kernel32", "FFI declarativa contra kernel32", "beep_bepp.vx", 0)
modes3_case("borrow_unique_owner", "prestamo sobre un unique como duenno (reproductor)", "bug3.vx", 0)
modes3_case("borrow_class_owner", "prestamo con duenno de clase (reproductor)", "bug3_class.vx", 30)
# Escribir un AGREGADO por un prestamo mutable.  Estaba roto y nadie lo veia:
# write_borrow emitia un STORE, y el valor SSA de un struct es un PUNTERO a su
# buffer -> escribia esa direccion sobre los ocho primeros bytes del propio
# struct, y los campos salian siendo las dos mitades de un puntero.
modes3_case("borrow_struct_write", "escribir un struct por un prestamo mutable", "bug3_struct.vx", 90)
modes3_case("borrow_repro4", "prestamo, cuarto reproductor", "bug4.vx", 3)
modes3_case("unique_chain", "unique que atraviesa una cadena de llamadas", "check_chain.vx", 99)
modes3_case("unique_multi", "varios unique en el mismo ambito, liberados al reves", "check_multi.vx", 42)
modes3_case("unique_return", "unique devuelto: el duenno se va con el retorno", "check_return_unique.vx", 42)
modes3_case("unique_with_return", "unique vivo cuando la funcion retorna por otra rama", "check_with_return.vx", 42)
modes3_case("fmt_spec", "especificadores de formato en la interpolacion", "test_fmt_spec.vx", 0)
diff3_case("vectorize_fmsub", "vectorizacion: multiplicar y restar fundidos", "200_vectorize_fmsub.vx")
diff3_case("vectorize_f32_scalar", "vectorizacion de f32 con un escalar difundido", "201_vectorize_f32_scalar.vx")
diff3_case("f32_param_coercion", "conversion de f32 al pasarlo como parametro", "202_f32_param_coercion.vx")
diff3_case("vectorize_scalar_factor", "reduccion vectorial con factor escalar", "203_vectorize_scalar_factor.vx")
diff3_case("vectorize_two_scaled", "dos vectores escalados en la misma expresion", "204_vectorize_two_scaled.vx")
diff3_case("overlay_block", "vista sobre un bloque de bytes", "263_overlay_block.vx")
diff3_case("overlay_block_if", "vista cuyos campos dependen de una condicion", "264_overlay_block_if.vx")
diff3_case("match_int", "match sobre enteros y chars (el switch de Vesta)", "266_match_int.vx")
diff3_case("match_string", "match sobre cadenas constantes", "267_match_string.vx")
diff3_case("match_string_runtime", "match sobre cadenas conocidas en ejecucion", "268_match_string_runtime.vx")
diff3_case("match_range", "match por rangos de valores", "269_match_range.vx")
diff3_case("overlay_array", "arrays dentro de una vista", "270_overlay_array.vx")
diff3_case("overlay_pe_sections", "recorrer la tabla de secciones de un PE", "271_overlay_pe_sections.vx")
diff3_case("overlay_checked", "vista con comprobacion de limites", "274_overlay_checked.vx")
diff3_case("overlay_rva_resolver", "resolver direcciones virtuales relativas desde la vista", "275_overlay_rva_resolver.vx")
diff3_case("overlay_assembler", "ensamblar una estructura escribiendo por la vista", "279_overlay_assembler.vx")
diff3_case("overlay_endian", "vistas con campos de orden de bytes contrario", "280_overlay_endian.vx")
diff3_case("overlay_endian_ctx", "el orden de bytes sale del contexto de la propia vista", "281_overlay_endian_ctx.vx")
diff3_case("valued_enums", "enums con valor explicito, estilo C", "283_valued_enums.vx")
diff3_case("paralelismo_heavy", "carga paralela sostenida sobre el planificador", "44_paralelismo_heavy.vx")


# ---  AS: inline asm ---------------------------------------------------

def _write_vx(ctx, name, body):
    p = ctx.path(name)
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write(body)
    return p


def _find_gcc():
    """gcc del PATH, con el fallback a TDM-GCC que usaba el .sh."""
    g = shutil.which("gcc")
    if g:
        return g
    for cand in (r"C:\TDM-GCC-64\bin\gcc.exe", "/c/TDM-GCC-64/bin/gcc.exe"):
        if os.path.exists(cand):
            return cand
    return None


AS_INC1 = """u64 main() {
    register("rax") u64 v = 41;
    asm volatile {
        inc rax
    };
    return v;
}
"""


@case("as_inc1", line=3258)
def _(ctx):
    """ AS inc.1: asm { } a bytecode, sin flags -> 42."""
    vx = _write_vx(ctx, "as_inc1.vx", AS_INC1)
    rc, log = ctx.run([VM_EXE, "--vesta", vx, "-o", ctx.path("as_inc1")])
    if rc != 0:
        ctx.fail(" AS: asm{} a bytecode (sin flag) debio compilar", log)
    if not os.path.exists(ctx.path("as_inc1.velb")):
        ctx.fail(" AS: asm{} a bytecode no produjo .velb")
    _, log = ctx.run_velb("as_inc1", schedulers=1)
    got = get_r00(log)
    if got != 42:
        ctx.fail(" AS inc.1: inc rax (41) debio dar 42, dio %s"
                 % get_r00_hex(log), log)
    ctx.ok(" AS asm { } a bytecode compila + ejecuta via JIT (sin flags) -> 42")


AS_PORTC_CASES = [
    # (tag, linea, fichero, fuente, exit esperado, ok_msg)
    ("as_inc3_add", 3299, """u64 main() {
    register("rax") u64 a = 30;
    register("rcx") u64 b = 12;
    asm volatile {
        add rax, rcx
    } clobbers("cc");
    return a;
}
""", 42, " AS inc.3 port-C ejecuta 'add rax, rcx' (30+12) -> 42"),
    ("as_inc3_pc", 3324, """u64 main() {
    register("rdi") u64 inv = 0xFF;
    register("rax") u64 outv;
    asm volatile {
        popcnt rax, rdi
    } clobbers("cc");
    return outv;
}
""", 8, " AS inc.3 port-C ejecuta 'popcnt rax, rdi' (output-only) -> 8"),
    ("as_inc3_sib", 3349, """u64 main() {
    u64 acc = 0;
    {
        register("rax") u64 a = 30;
        register("rcx") u64 b = 12;
        asm volatile { add rax, rcx } clobbers("cc");
        acc = a;
    }
    {
        register("rax") u64 c = 5;
        register("rcx") u64 d = 5;
        asm volatile { add rax, rcx } clobbers("cc");
        acc = acc + c;
    }
    return acc;
}
""", 52, " AS inc.3 scopes hermanos con mismo registro fisico -> 52 (sin colision)"),
]


def _as_portc_case(tag, source, want, ok_msg):
    """Registra un caso port-C: --port c + gcc + ejecutar (exit-code)."""
    def fn(ctx):
        gcc = _find_gcc()
        if not gcc:
            ctx.fail(" AS inc.3: no se encontro gcc para compilar el .c "
                     "de --port c")
        vx = _write_vx(ctx, tag + ".vx", source)
        rc, log = ctx.run([VM_EXE, "--vesta", vx, "--port", "c",
                           "-o", ctx.path(tag)])
        if rc != 0:
            ctx.fail(" AS inc.3: --port c fallo para %s" % tag, log)
        exe = ctx.path(tag + ".exe")
        rc, log = ctx.run([gcc, "-O2", "-std=c11", ctx.path(tag + ".c"),
                           "-o", exe])
        if rc != 0:
            ctx.fail(" AS inc.3: gcc fallo al compilar %s.c" % tag, log)
        rc, _ = ctx.run([exe])
        rc = exit_code(rc)
        if rc != want:
            ctx.fail(" AS inc.3: %s debio dar %d, dio %d" % (tag, want, rc))
        ctx.ok(ok_msg)
    fn.__name__ = "case_" + tag
    return fn


for _t, _ln, _s, _w, _m in AS_PORTC_CASES:
    _register(_t, _as_portc_case(_t, _s, _w, _m), False, _ln)


AS_NEG_CASES = [
    # (tag, linea, fuente, patron de error, ok_msg)
    ("as_inc3_conf", 3385, """u64 main() {
    register("rax") u64 a = 1;
    {
        register("rax") u64 b = 2;
        asm volatile { nop } clobbers("cc");
    }
    return a;
}
""", "conflicto de register",
     " AS inc.3 conflicto same-reg en scopes anidados rechazado",
     " AS inc.3: conflicto same-reg anidado debio fallar"),
    ("as_inc3_addr", 3406, """u64 main() {
    register("rax") u64 a = 5;
    u64* p = &a;
    return a;
}
""", "no se puede tomar la direccion",
     " AS inc.3 '&' sobre variable register() rechazado",
     " AS inc.3: &reg_var debio fallar"),
    ("as_inc4b_bad", 3499, """u64 main() {
    register("rax") u64 a = 5;
    asm volatile noinfer {
        frobnicate rax, rax
    };
    return a;
}
""", "inline asm",
     " AS inc.4b validacion de sintaxis (Keystone) rechaza mnemonico invalido",
     " AS inc.4b: asm con mnemonico invalido debio fallar el compile"),
]


def _as_neg_case(tag, source, pattern, ok_msg, fail_msg):
    def fn(ctx):
        vx = _write_vx(ctx, tag + ".vx", source)
        rc, log = ctx.run([VM_EXE, "--vesta", vx, "--port", "c",
                           "-o", ctx.path(tag)])
        if rc == 0:
            ctx.fail(fail_msg, log)
        if pattern not in log:
            ctx.fail(" AS: no se reporto el error esperado ('%s')" % pattern,
                     log)
        ctx.ok(ok_msg)
    fn.__name__ = "case_" + tag
    return fn


for _t, _ln, _s, _p, _m, _f in AS_NEG_CASES:
    _register(_t, _as_neg_case(_t, _s, _p, _m, _f), False, _ln)


AS_INC4_INF = """u64 main() {
    register("rax") u64 a = 30;
    register("rcx") u64 b = 12;
    asm volatile {
        add rax, rcx
    };
    return a;
}
"""


@case("as_inc4_inf", line=3423)
def _(ctx):
    """ AS inc.4 (f): inferencia de clobbers añade 'cc' -> 42."""
    gcc = _find_gcc()
    if not gcc:
        ctx.fail(" AS inc.4: no se encontro gcc")
    vx = _write_vx(ctx, "as_inc4_inf.vx", AS_INC4_INF)
    rc, log = ctx.run([VM_EXE, "--vesta", vx, "--port", "c",
                       "-o", ctx.path("as_inc4_inf")])
    if rc != 0:
        ctx.fail(" AS inc.4: --port c fallo para as_inc4_inf", log)
    if '"cc"' not in read_text(ctx.path("as_inc4_inf.c")):
        ctx.fail(" AS inc.4: la inferencia no añadio 'cc' a la clobber-list")
    rc, log = ctx.run([gcc, "-O2", "-std=c11", ctx.path("as_inc4_inf.c"),
                       "-o", ctx.path("as_inc4_inf.exe")])
    if rc != 0:
        ctx.fail(" AS inc.4: gcc fallo al compilar as_inc4_inf.c", log)
    rc, _ = ctx.run([ctx.path("as_inc4_inf.exe")])
    rc = exit_code(rc)
    if rc != 42:
        ctx.fail(" AS inc.4: add con clobbers inferidos debio dar 42, dio %d"
                 % rc)
    ctx.ok(" AS inc.4 inferencia de clobbers ('cc' auto) -> 42")


AS_INC4_MOV = """u64 main() {
    register("rax") u64 a = 5;
    asm volatile {
        mov rcx, rax
        add rax, rcx
    };
    return a;
}
"""


@case("as_inc4_mov", line=3454)
def _(ctx):
    """ AS inc.4 (g): la inferencia detecta el clobber de rcx -> 10."""
    gcc = _find_gcc()
    if not gcc:
        ctx.fail(" AS inc.4: no se encontro gcc")
    vx = _write_vx(ctx, "as_inc4_mov.vx", AS_INC4_MOV)
    rc, log = ctx.run([VM_EXE, "--vesta", vx, "--port", "c",
                       "-o", ctx.path("as_inc4_mov")])
    if rc != 0:
        ctx.fail(" AS inc.4: --port c fallo para as_inc4_mov", log)
    if '"rcx"' not in read_text(ctx.path("as_inc4_mov.c")):
        ctx.fail(" AS inc.4: la inferencia no detecto el clobber 'rcx'")
    # El .sh no comprobaba el resultado del gcc en este caso.
    ctx.run([gcc, "-O2", "-std=c11", ctx.path("as_inc4_mov.c"),
             "-o", ctx.path("as_inc4_mov.exe")])
    rc, _ = ctx.run([ctx.path("as_inc4_mov.exe")])
    rc = exit_code(rc)
    if rc != 10:
        ctx.fail(" AS inc.4: mov+add con rcx inferido debio dar 10, dio %d"
                 % rc)
    ctx.ok(" AS inc.4 inferencia detecta clobber de registro no-ligado (rcx) "
           "-> 10")


AS_INC4_NI = """u64 main() {
    register("rax") u64 a = 30;
    register("rcx") u64 b = 12;
    asm volatile noinfer {
        add rax, rcx
    };
    return a;
}
"""


@case("as_inc4_ni", line=3479)
def _(ctx):
    """ AS inc.4 (h): `noinfer` desactiva la inferencia (sin 'cc')."""
    vx = _write_vx(ctx, "as_inc4_ni.vx", AS_INC4_NI)
    rc, log = ctx.run([VM_EXE, "--vesta", vx, "--port", "c",
                       "-o", ctx.path("as_inc4_ni")])
    if rc != 0:
        ctx.fail(" AS inc.4: --port c fallo para as_inc4_ni", log)
    if '"cc"' in read_text(ctx.path("as_inc4_ni.c")):
        ctx.fail(" AS inc.4: noinfer no debio inferir 'cc'")
    ctx.ok(" AS inc.4 'noinfer' desactiva la inferencia de clobbers")


AS_INC5_PC = """u64 main() {
    register("rdi") u64 inv = 0xFF;
    register("rax") u64 outv;
    asm volatile {
        popcnt rax, rdi
    };
    return outv;
}
"""

AS_INC5_XFN = """u64 bitcount(u64 x) {
    register("rdi") u64 inv = x;
    register("rax") u64 outv;
    asm volatile {
        popcnt rax, rdi
    };
    return outv;
}
u64 main() {
    return bitcount(0xFF) + bitcount(0x0F);
}
"""


@case("as_inc5_pc", line=3520)
def _(ctx):
    """ AS inc.5 (a): inline-asm sin flags, main-only -> 8."""
    vx = _write_vx(ctx, "as_inc5_pc.vx", AS_INC5_PC)
    rc, log = ctx.run([VM_EXE, "--vesta", vx, "-o", ctx.path("as_inc5_pc")])
    if rc != 0:
        ctx.fail(" AS inc.5: compile fallo para as_inc5_pc", log)
    if not os.path.exists(ctx.path("as_inc5_pc.velb")):
        ctx.fail(" AS inc.5: no produjo .velb")
    _, log = ctx.run_velb("as_inc5_pc", schedulers=1)
    got = get_r00(log)
    if got != 8:
        ctx.fail(" AS inc.5: popcnt(0xFF) debio dar 8, dio %s" % got, log)
    ctx.ok(" AS inc.5 inline-asm sin flags 'popcnt rax, rdi' -> 8")


@case("as_inc5_xfn", line=3550)
def _(ctx):
    """ AS inc.5 (b): cross-fn (helper con inline-asm no inlineado) -> 12."""
    vx = _write_vx(ctx, "as_inc5_xfn.vx", AS_INC5_XFN)
    rc, log = ctx.run([VM_EXE, "--vesta", vx, "-o", ctx.path("as_inc5_xfn")])
    if rc != 0:
        ctx.fail(" AS inc.5: compile fallo para as_inc5_xfn", log)
    _, log = ctx.run_velb("as_inc5_xfn", schedulers=1)
    got = get_r00(log)
    if got != 12:
        ctx.fail(" AS inc.5: cross-fn bitcount debio dar 12, dio %s" % got, log)
    ctx.ok(" AS inc.5 cross-fn (helper inline-asm no inlineado) -> 12")


@case("fin_de_linea")
def _(ctx):
    """El mismo programa en LF, CRLF y CR: mismo resultado y misma linea.

    Un fichero de texto termina sus lineas de tres maneras segun de donde
    venga, y el lenguaje no puede comportarse distinto por eso.  El CR a secas
    era el que mentia: contaba todo el fichero como UNA linea, asi que el
    programa compilaba pero sus diagnosticos senalaban al sitio equivocado --
    peor que no compilar, porque parece que funciona.
    """
    prog = ("i32 main() {\n"
            "    i32 x = 40;\n"
            "    asm ( reg a = x, ) {\n"
            "        add a, 2\n"
            "    }\n"
            "    return a;\n"
            "}\n")
    # El error va en la linea 5 a proposito: es lo que se comprueba.
    malo = ("i32 main() {\n"
            "    i32 a = 1;\n"
            "    i32 b = 2;\n"
            "    i32 c = 3;\n"
            "    return no_existe;\n"
            "}\n")
    for nombre, sep in (("lf", "\n"), ("crlf", "\r\n"), ("cr", "\r")):
        vx = ctx.path("eol_%s.vx" % nombre)
        with open(vx, "wb") as f:
            f.write(prog.replace("\n", sep).encode("utf-8"))
        rc, log = ctx.run([VM_EXE, "--vesta", vx, "-o", ctx.path("eol_" + nombre)])
        if rc != 0:
            ctx.fail("fin de linea %s: no compilo" % nombre, log)
        _, rlog = ctx.run_velb("eol_" + nombre, schedulers=1)
        got = get_r00(rlog)
        if got != 42:
            ctx.fail("fin de linea %s: dio %s, esperado 42" % (nombre, got), rlog)
        ctx.ok("fin de linea %s -> 42" % nombre)

        # Y la linea que se cita en un diagnostico es la misma en los tres.
        vxe = ctx.path("eole_%s.vx" % nombre)
        with open(vxe, "wb") as f:
            f.write(malo.replace("\n", sep).encode("utf-8"))
        _, elog = ctx.run([VM_EXE, "--vesta", vxe, "-o", ctx.path("eole_" + nombre)])
        if not re.search(r"eole_%s\.vx:5:" % nombre, elog):
            ctx.fail("fin de linea %s: el error no se situa en la linea 5"
                     % nombre, elog)
        ctx.ok("fin de linea %s: el diagnostico cita la linea 5" % nombre)


@case("asm_examples", line=3576)
def _(ctx):
    """Bucle sobre examples_codes_vx/asm/*.vx con marcadores @expect."""
    d = os.path.join(VX_DIR, "asm")
    if not os.path.isdir(d):
        return
    import glob as _glob
    for exf in sorted(_glob.glob(os.path.join(d, "*.vx"))):
        bn = os.path.basename(exf)[:-3]
        rc, log = ctx.run([VM_EXE, "--vesta", exf,
                           "-o", ctx.path("asmex_" + bn)])
        if rc != 0:
            ctx.fail(" AS ejemplo %s no compilo" % bn, log)
        _, log = ctx.run_velb("asmex_" + bn, schedulers=1)
        rhex = get_r00_hex(log)
        src = read_text(exf)
        if "@expect-run" in src:
            # No determinista: basta con que ejecute y produzca R00.
            if rhex is None:
                ctx.fail(" AS ejemplo %s no ejecuto" % bn, log)
            ctx.ok(" AS ejemplo asm/%s ejecuta (no determinista)" % bn)
            continue
        m = re.search(r"@expect[ \t]+(0x[0-9a-fA-F]+|[0-9]+)", src)
        want_txt = m.group(1) if m else None
        if want_txt is None:
            continue
        want = bash_arith(want_txt)
        got = get_r00(log)
        if rhex is None or got != want:
            ctx.fail(" AS ejemplo %s dio %s, esperado %s"
                     % (bn, rhex if rhex else "<nada>", want_txt), log)
        ctx.ok(" AS ejemplo asm/%s -> %s" % (bn, want_txt))


@case("asmsym198", line=3608)
def _(ctx):
    """ AS: inline-asm referenciando simbolos propios (AOT PE) -> 42."""
    src = ctx.src("198_inline_asm_symbols.vx")
    if not os.path.exists(src):
        return
    # El .sh forzaba --format pe (no NAKED_AOT_FMT) y ponia el .exe en -o.
    exe = ctx.path("asmsym198.exe")
    rc, log = ctx.run([VM_EXE, "-m", "aot", "--vesta", src, "--format", "pe",
                       "--emit", "exe", "-o", exe])
    if rc != 0:
        ctx.fail(" AS asm-simbolos: compile AOT fallo", log)
    rc, _ = ctx.run([exe])
    rc = exit_code(rc)
    if rc != 42:
        ctx.fail(" AS asm-simbolos: PE dio exit=%d, esperado 42" % rc)
    ctx.ok(" AS asm-simbolos propios (call/mov-imm64/lea/[global]) -> 42")


@case("ci205", line=3649)
def _(ctx):
    """Interop C: header tipado + consumidor C compilado con gcc -> exit 42."""
    gcc = _find_gcc()
    if not gcc:
        ctx.skip("interop C: header tipado + consumidor C (gcc) (gcc no disponible)")
        return
    out = "ci205"
    _, log = ctx.run([VM_EXE, "--vesta", ctx.src("205_c_interop.vx"),
                      "--port", "c", "--emit-header", "-o", ctx.path(out)])
    if not (os.path.exists(ctx.path(out + ".h")) and
            os.path.exists(ctx.path(out + ".c"))):
        ctx.fail("interop C: no se generaron %s.h / %s.c" % (out, out), log)
    ctx.ok("interop C: header tipado + consumidor C (gcc) -> %s.h + %s.c generados"
           % (out, out))
    exe = ctx.path(out + "_exe")
    _, log = ctx.run([gcc, "-std=c11", "-O2", "-I", ctx.dir,
                      '-DVX_IFACE_HEADER="%s.h"' % out,
                      ctx.src("205_c_interop_consumer.c"), ctx.path(out + ".c"),
                      "-o", exe])
    if not (os.path.exists(exe) or os.path.exists(exe + ".exe")):
        ctx.fail("interop C: gcc no compilo el consumidor C", log)
    if os.path.exists(exe + ".exe"):
        exe += ".exe"
    rc, _ = ctx.run([exe])
    rc = exit_code(rc)
    if rc != 42:
        ctx.fail("interop C: el consumidor C salio con %d, se esperaba 42" % rc)
    ctx.ok("interop C: header tipado + consumidor C (gcc) -> consumidor C exit = 42")


# --- Finalizacion GC: 3 helpers con la misma forma (vm/jit SIN --schedulers,
#     luego AOT por exit-code).

GC_FIN_CASES = [
    ("fin246", 3880, "246_gc_finalize_escape.vx", 5,
     "246 finalizacion GC caso escape (deleter custom via finalizador)",
     "compilacion no produjo ejecutable"),
    ("fin247", 3926, "247_gc_class_dtor_finalize.vx", 2,
     "247 finalizador GC gc<Clase> con ~Clase() (CLASS_DTOR)",
     "no se produjo exe nativo"),
    ("fin248", 3975, "248_gc_unique_shared_finalize.vx", 1,
     "248 finalizador GC gc<unique<T>> (gc_finalize_all deterministico)",
     "no se produjo exe nativo"),
]


def _gc_fin_case(tag, src, want, label, aot_fail_msg):
    def fn(ctx):
        ctx.compile_vx(ctx.src(src), tag)
        for m in ("vm", "jit"):
            # Ojo: estos tres NO pasaban --schedulers en el .sh.
            _, log = ctx.run_velb(tag, mode=m)
            got = get_r00(log)
            if got != want:
                ctx.fail("%s (-m %s): R00 == %s, se esperaba %d"
                         % (label, m, got, want), log)
            ctx.ok("%s (-m %s) -> R0 = %d" % (label, m, want))
        exe = aot_build(ctx, ctx.src(src), tag + "_aot",
                        "%s (-m aot): %s" % (label, aot_fail_msg))
        rc, _ = ctx.run([exe])
        rc = exit_code(rc)
        if rc != want:
            ctx.fail("%s (-m aot): exit == %d, se esperaba %d" % (label, rc, want))
        ctx.ok("%s (-m aot) -> exit = %d" % (label, want))
    fn.__name__ = "case_" + tag
    return fn


for _t, _ln, _s, _w, _lb, _fm in GC_FIN_CASES:
    _register(_t, _gc_fin_case(_t, _s, _w, _lb, _fm), False, _ln)


@case("gc251", line=4042)
def _(ctx):
    """251: compactacion GC en AOT via field-maps (fragmentar+mover+0 stale)."""
    label = "251 compactacion GC en AOT via field-maps (fragmentar+mover+0 stale)"
    exe = aot_build(ctx, ctx.src("251_gc_compact_aot.vx"), "gc251_aot",
                    "%s: no se produjo exe nativo" % label)
    rc, _ = ctx.run([exe])
    rc = exit_code(rc)
    if rc != 42:
        ctx.fail("%s (sin compactar): exit == %d, se esperaba 42" % (label, rc))
    ctx.ok("%s (AOT sin compactar) -> exit = 42" % label)
    p = subprocess.run([exe], capture_output=True,
                       env=_env(VESTA_GC_COMPACT_ALWAYS=1, VESTA_GC_VERIFY_MOVE=1,
                                VESTA_GC_DEBUG=1))
    vlog = (p.stderr or b"").decode("utf-8", "replace")
    if p.returncode != 42:
        ctx.fail("%s (compactando): exit == %d, se esperaba 42"
                 % (label, p.returncode), vlog)
    if "moved=2000 collected=2000" not in vlog:
        ctx.fail("%s: la compactacion no movio los 2000 nodos vivos" % label, vlog)
    if "stale_roots=0 stale_fields=0" not in vlog:
        ctx.fail("%s: el verificador detecto punteros stale tras compactar" % label,
                 vlog)
    ctx.ok("%s (AOT compactando) -> exit = 42, moved=2000, 0 stale" % label)


@case("gc253", line=4100)
def _(ctx):
    """253: nursery preciso + write-barrier old->young (interp / jit / aot).

    El .sh usaba tres funciones separadas donde la de JIT REUTILIZABA el .velb
    compilado por la de interp; aqui van juntas por esa dependencia.
    """
    l_interp = "253 nursery preciso + write-barrier old->young (interp, oraculo)"
    l_jit = "253 nursery preciso + write-barrier old->young (jit)"
    l_aot = "253 nursery preciso (AOT: barrier no-op, lista via major)"
    ctx.compile_vx(ctx.src("253_gc_nursery_precise.vx"), "gc253")
    _, log = ctx.run_velb("gc253", schedulers=1, mode="vm")
    got = get_r00(log)
    if got != 42:
        ctx.fail("%s: R00 == %s, se esperaba 42" % (l_interp, got), log)
    ctx.ok("%s -> R0 = 42" % l_interp)
    _, log = ctx.run_velb("gc253", schedulers=1, mode="jit")
    got = get_r00(log)
    if got != 42:
        ctx.fail("%s: R00 == %s, se esperaba 42" % (l_jit, got), log)
    ctx.ok("%s -> R0 = 42" % l_jit)
    # El leg AOT no pasaba --format ni --emit exe.
    _, log = ctx.run([VM_EXE, "-m", "aot", "--vesta",
                      ctx.src("253_gc_nursery_precise.vx"),
                      "-o", ctx.path("gc253aot")])
    exe = ctx.path("gc253aot.exe")
    if not os.path.exists(exe):
        exe = ctx.path("gc253aot")
    if not os.path.exists(exe):
        ctx.fail("%s: la compilacion AOT no produjo ejecutable" % l_aot, log)
    rc, _ = ctx.run([exe])
    rc = exit_code(rc)
    if rc != 42:
        ctx.fail("%s: exit AOT == %d, se esperaba 42" % (l_aot, rc))
    ctx.ok("%s -> exit = 42" % l_aot)


# --- Concurrencia cooperativa y fibras: vm/jit por R00 y AOT por exit-code
#     (que trunca a 8 bits, de ahi los `mod 256`).

COOP_CASES = [
    ("coop233", 4173, "233_coop_yield.vx", 123123, 243,
     "233 F3 yield cooperativo round-robin (vx_async import)", False),
    ("coop234", 4223, "234_sync_contention.vx", 42, 42,
     "234 F4-a monitor-yield cooperativo bajo contienda (sin deadlock)", False),
    ("fn235", 4273, "235_fiber_swapctx.vx", 1212, 188,
     "235 FN.1/FN.2 fibras via primitivo abstracto ( NORMAL)", True),
    ("fn236", 4328, "236_fiber_stackful.vx", 666, 154,
     "236 FN.3 fibras stackful (3 fibras, estado local a traves de yields)", True),
    ("si254", 4374, "254_syncimpl_hook.vx", 42, 42,
     "254 @SyncImpl synchronized hookeable", False),
]


def _coop_case(tag, src, want, want_aot, label, jit_eq_vm):
    def fn(ctx):
        ctx.compile_vx(ctx.src(src), tag)
        _, log = ctx.run_velb(tag, schedulers=1, mode="vm")
        got = get_r00(log)
        if got != want:
            ctx.fail("%s (-m vm): R00 == %s, se esperaba %d" % (label, got, want),
                     log)
        ctx.ok("%s (-m vm) -> R0 = %d" % (label, want))
        _, log = ctx.run_velb(tag, schedulers=1, mode="jit")
        got = get_r00(log)
        if got != want:
            ctx.fail("%s (-m jit): R00 == %s, se esperaba %d" % (label, got, want),
                     log)
        ctx.ok("%s (-m jit) -> R0 = %d%s"
               % (label, want, " (== vm)" if jit_eq_vm else ""))
        exe = aot_build(ctx, ctx.src(src), tag + "_aot",
                        "%s (-m aot): no se produjo exe nativo" % label)
        rc, _ = ctx.run([exe])
        rc = exit_code(rc)
        if rc != want_aot:
            extra = (" (%d mod 256)" % want) if want_aot != want else ""
            ctx.fail("%s (-m aot): exit == %d, se esperaba %d%s"
                     % (label, rc, want_aot, extra))
        extra = (" (%d mod 256)" % want) if want_aot != want else ""
        ctx.ok("%s (-m aot) -> exit = %d%s" % (label, want_aot, extra))
    fn.__name__ = "case_" + tag
    return fn


for _t, _ln, _s, _w, _wa, _lb, _je in COOP_CASES:
    _register(_t, _coop_case(_t, _s, _w, _wa, _lb, _je), False, _ln)


@case("nkx", serial=True, line=4425)
def _(ctx):
    """LIM-A: @Naked cross-modulo en los 3 modos (vm / jit / aot)."""
    d = _bug_dir("naked_xmodule_test")
    if not os.path.exists(os.path.join(d, "main.vx")):
        return
    _rm_glob(d, "*.vxi", "*.vxir")
    _rm(os.path.join(d, "prog.velb"), os.path.join(d, "prog.vel"))
    _, log = ctx.run([VM_EXE, "--vesta", os.path.join(d, "main.vx"),
                      "-o", os.path.join(d, "prog")])
    if not os.path.exists(os.path.join(d, "prog.velb")):
        ctx.fail("LIM-A cross-module compilacion no produjo .velb", log)
    if (not os.path.exists(os.path.join(d, "naked_mod.vxi")) and
            not os.path.exists(os.path.join(d, "src", "modules", "naked_mod.vxi"))):
        ctx.ok("LIM-A cross-module .vxi (bit @Naked serializado en el formato)")
    else:
        ctx.ok("LIM-A cross-module .vxi presente")
    for m in ("vm", "jit"):
        _, log = ctx.run([VM_EXE, "-m", m, "--run",
                          os.path.join(d, "prog.velb"),
                          "--schedulers", "1", "--stats"])
        got = get_r00(log)
        if got != 42:
            ctx.fail("LIM-A (-m %s): R00 == %s, se esperaba 42" % (m, got), log)
        ctx.ok("LIM-A cross-module @Naked (-m %s) -> R0 = 42" % m)
    _rm_glob(d, "*.vxi", "*.vxir")
    _rm(os.path.join(d, "nkxaot"), os.path.join(d, "nkxaot.velb"))
    _, log = ctx.run([VM_EXE, "-m", "aot", "--vesta", os.path.join(d, "main.vx"),
                      "-o", os.path.join(d, "nkxaot"),
                      "--format", AOT_FMT, "--emit", "exe"])
    exe = os.path.join(d, "nkxaot")
    if os.path.exists(exe + ".exe"):
        exe += ".exe"
    try:
        if os.path.exists(os.path.join(d, "nkxaot.velb")) or not os.path.exists(exe):
            ctx.fail("LIM-A AOT cross-module no produjo exe nativo", log)
        rc, _ = ctx.run([exe])
        rc = exit_code(rc)
        if rc != 42:
            ctx.fail("LIM-A (-m aot): exit == %d, se esperaba 42" % rc, log)
        ctx.ok("LIM-A cross-module @Naked (-m aot) -> exit = 42")
    finally:
        _rm_glob(d, "*.vxi", "*.vxir")
        _rm(os.path.join(d, "prog.velb"), os.path.join(d, "prog.vel"),
            os.path.join(d, "nkxaot"), os.path.join(d, "nkxaot.velb"),
            os.path.join(d, "nkxaot.exe"))


def _bytes_case(tag, line, src, expected_bytes, msgs, with_aot=True):
    """Casos que comparan la salida BYTE A BYTE contra una referencia.

    `msgs` = (label_fail, ok_suffix).  Replica los `cmp -s` del .sh.
    """
    def fn(ctx):
        label, ok_sfx = msgs
        ctx.compile_vx(ctx.src(src), tag)
        modes = ["vm", "jit"] + (["aot"] if with_aot else [])
        for m in modes:
            if m == "aot":
                exe = aot_build(ctx, ctx.src(src), tag + "_aot",
                                "%s (-m aot): no se produjo exe nativo" % label)
                p = subprocess.run([exe], capture_output=True)
            else:
                p = subprocess.run([VM_EXE, "-m", m, "--run",
                                    ctx.path(tag + ".velb"), "--schedulers", "1"],
                                   capture_output=True)
            if p.stdout != expected_bytes:
                ctx.fail("%s (-m %s): %s" % (label, m, msgs[0]),
                         "obtenido: %s\nesperado: %s"
                         % (p.stdout.hex(), expected_bytes.hex()))
            ctx.ok("%s (-m %s) -> %s" % (label, m, ok_sfx))
    fn.__name__ = "case_" + tag
    _register(tag, fn, False, line)


_bytes_case("tc181", 4486, "181_truecolor.vx",
            b"\x1b[38;2;255;128;0mnaranja\x1b[0m\n"
            b"\x1b[48;2;0;0;255mfondo azul\x1b[0m\n"
            b"\x1b[38;2;10;200;30mrgb runtime\x1b[0m\n",
            ("truecolor", "secuencia SGR 24-bit correcta"))

_bytes_case("hpnb255", 4529, "255_host_ptr_null_branch.vx", b"byte0=66\n",
            ("BUG-1 host-ptr null branch", "byte0=66"))

# Sin leg AOT: el AOT bare no compila la construccion de StringObject GC.
_bytes_case("sbi256", 4568, "256_str_build_interp.vx",
            b"\x1b[48;2;0;75;125m\n",
            ("BUG-2 str build interp", "secuencia ANSI correcta"),
            with_aot=False)

_bytes_case("sbcf257", 4591, "257_str_build_char_fmt.vx", b"\x1b" + b"X\n",
            ("BUG-3 str build :char", "ESC + X"))


READ_EXTERN_PE = ('extern "kernel32.dll" { fn CreateFileA(u8* n, u32 a, u32 s, '
                  'u64 se, u32 d, u32 f, u64 t) -> u64; fn GetFileSizeEx(u64 h, '
                  'i64* sz) -> i32; fn ReadFile(u64 h, u8* b, u32 nn, u32* nr, '
                  'u64 o) -> i32; fn CloseHandle(u64 h) -> i32; }')
READ_SIZE_PE = ('u8* pcz=path.cstr(); u64 hz=CreateFileA(pcz,(u32)0x80000000,'
                '(u32)1,(u64)0,(u32)3,(u32)0x80,(u64)0); '
                'if(hz==0xFFFFFFFFFFFFFFFF){return 0;} i64 size=0; '
                'i32 gsz=GetFileSizeEx(hz,&size); CloseHandle(hz); '
                'if(gsz==0){return 0;}')
READ_INTO_PE = ('u8* pcr=path.cstr(); u64 hr=CreateFileA(pcr,(u32)0x80000000,'
                '(u32)1,(u64)0,(u32)3,(u32)0x80,(u64)0); '
                'if(hr==0xFFFFFFFFFFFFFFFF){free(buf);return 0;} u32 nrd=0; '
                'i32 okr=ReadFile(hr,buf,(u32)size,&nrd,(u64)0); CloseHandle(hr); '
                'i64 n=(i64)nrd; if(okr==0){free(buf);return 0;}')
READ_EXTERN_ELF = ('extern "libc.so.6" { fn open(u8* p, i32 f, i32 m) -> i32; '
                   'fn read(i32 fd, u8* b, u64 c) -> i64; '
                   'fn lseek(i32 fd, i64 o, i32 w) -> i64; '
                   'fn close(i32 fd) -> i32; }')
READ_SIZE_ELF = ('u8* pcz=path.cstr(); i32 fdz=open(pcz,(i32)0,(i32)0); '
                 'if(fdz<0){return 0;} i64 size=lseek(fdz,(i64)0,(i32)2); '
                 'lseek(fdz,(i64)0,(i32)0);')
READ_INTO_ELF = ('u8* pcr=path.cstr(); i32 fdr=open(pcr,(i32)0,(i32)0); '
                 'if(fdr<0){free(buf);return 0;} i64 n=read(fdr,buf,(u64)size); '
                 'close(fdr);')

RB_SELFMOD_TPL = """%(EXTERN)s
i32 read_u16le(u8* buf, i32 off) { i32 b0=(i32)buf[off]; i32 b1=(i32)buf[off+1]; return b0|(b1<<8); }
i32 read_u32le(u8* buf, i32 off) { i32 b0=(i32)buf[off]; i32 b1=(i32)buf[off+1]; i32 b2=(i32)buf[off+2]; i32 b3=(i32)buf[off+3]; return b0|(b1<<8)|(b2<<16)|(b3<<24); }
class BMP_Image {
    public i32 file_magic; public i32 size_img; public i32 offset_data; public i32 size_header;
    public i32 width; public i32 height; public i32 color_planes; public i32 bit_pixel;
    public i32 method_compression; public i32 size_img_raw; public i32 horizontal_res;
    public i32 vertical_res; public i32 color_palette; public i32 important_colors;
    public u8* raw; public i64 raw_len;
    public BMP_Image() { this.raw = null; this.raw_len = 0; }
    public ~BMP_Image() { if (this.raw != null) { free(this.raw); this.raw = null; } }
    public i32 load(string path) {
        %(SIZE)s
        if (size <= 0) { return 0; }
        u8* buf = malloc(size + 1);
        %(INTO)s
        if (n != size) { free(buf); return 0; }
        buf[size]=0; this.raw = buf; this.raw_len = size;
        this.file_magic=read_u16le(buf,0); this.size_img=read_u32le(buf,2); this.offset_data=read_u32le(buf,10);
        this.size_header=read_u32le(buf,14); this.width=read_u32le(buf,18); this.height=read_u32le(buf,22);
        this.color_planes=read_u16le(buf,26); this.bit_pixel=read_u16le(buf,28); this.method_compression=read_u32le(buf,30);
        this.size_img_raw=read_u32le(buf,34); this.horizontal_res=read_u32le(buf,38); this.vertical_res=read_u32le(buf,42);
        this.color_palette=read_u32le(buf,46); this.important_colors=read_u32le(buf,50);
        return 1;
    }
    public void printBMPAttributes() {
        println("File Header: ${this.file_magic:hex}"); println("Image Size: ${this.size_img} bytes");
        println("Offset Init Data: ${this.offset_data}"); println("");
        println("Header:"); println("  Size Header: ${this.size_header} bytes");
        println("  Width: ${this.width} pixels"); println("  Height: ${this.height} pixels");
        println("  Color Planes: ${this.color_planes}"); println("  Bits per Pixel: ${this.bit_pixel}");
        println("Compression Method: ${this.method_compression}"); println("Raw Image Size: ${this.size_img_raw} bytes");
        println("Horizontal Resolution: ${this.horizontal_res} pixels/meter");
        println("Vertical Resolution: ${this.vertical_res} pixels/meter");
        println("Color Palette: ${this.color_palette}"); println("Important Colors: ${this.important_colors}");
    }
    public void dumpTerminal() {
        i32 width=this.width; i32 height=this.height; i32 bytes_per_row=width*3;
        i32 padding=(4-(bytes_per_row%%4))%%4; i32 row_padded=bytes_per_row+padding; i32 base=this.offset_data; u8* buf=this.raw;
        i32 fila=height-1;
        while (fila>=0) { i32 col=0;
            while (col<width) { i32 index=base+fila*row_padded+col*3;
                i32 b=(i32)buf[index]; i32 g=(i32)buf[index+1]; i32 r=(i32)buf[index+2];
                print("${bg_rgb(r, g, b)} ${RESET}"); col=col+1; }
            println(""); fila=fila-1; }
    }
}
i32 main() {
    BMP_Image img = new BMP_Image();
    if (img.load("Ejemplo60x3.bmp") == 0) { println("El archivo Ejemplo60x3.bmp no pudo encontrarse o no existe."); return 1; }
    img.printBMPAttributes(); println(""); img.dumpTerminal(); return 0;
}
"""


@case("rbmod", line=4644)
def _(ctx):
    """ReaderBMP modular: volcado byte-exacto vs la referencia single-file."""
    rb = os.path.join(VX_DIR, "reader_bmp")
    if not os.path.exists(os.path.join(rb, "reader_bmp.vx")):
        return

    def run_capture(argv, cwd):
        p = subprocess.run(argv, cwd=cwd, capture_output=True)
        return p.stdout

    # (1) Referencia 60x3 desde la version single-file (se quita la 1a linea,
    #     "Leidos N bytes ...", que la modular no imprime).
    ctx.compile_vx(os.path.join(rb, "reader_bmp.vx"), "rbsf60")
    out = run_capture([VM_EXE, "-m", "vm", "--run", ctx.path("rbsf60.velb"),
                       "--schedulers", "1"], cwd=rb)
    ref60 = out.split(b"\n", 1)[1] if b"\n" in out else b""

    # (2) Referencia 3x60: misma fuente con el nombre del .bmp sustituido.
    src3x60 = read_text(os.path.join(rb, "reader_bmp.vx")).replace(
        "Ejemplo60x3.bmp", "Ejemplo3x60.bmp")
    p3 = ctx.path("rbsf3x60.vx")
    with open(p3, "w", encoding="utf-8", newline="\n") as f:
        f.write(src3x60)
    ctx.compile_vx(p3, "rbsf3x60", must_succeed=False)
    out = run_capture([VM_EXE, "-m", "vm", "--run", ctx.path("rbsf3x60.velb"),
                       "--schedulers", "1"], cwd=rb)
    ref3x60 = out.split(b"\n", 1)[1] if b"\n" in out else b""

    # (3) Version modular (main.vx importa bmp.vx): 2 imagenes x 2 modos.
    ctx.compile_vx(os.path.join(rb, "main.vx"), "rbmod")
    for img, ref in (("Ejemplo60x3", ref60), ("Ejemplo3x60", ref3x60)):
        for m in ("vm", "jit"):
            got = run_capture([VM_EXE, "-m", m, "--run", ctx.path("rbmod.velb"),
                               "--schedulers", "1", "--", img + ".bmp"], cwd=rb)
            if got != ref:
                ctx.fail("ReaderBMP modular %s (-m %s): bytes != referencia"
                         % (img, m),
                         "obtenido %d bytes, referencia %d bytes"
                         % (len(got), len(ref)))
            ctx.ok("ReaderBMP modular %s (-m %s) -> volcado byte-exacto" % (img, m))

    # (4) Leg AOT con una variante auto-contenida generada al vuelo (usa FFI
    #     del SO en vez de vx_fileio).
    if AOT_FMT == "pe":
        body = RB_SELFMOD_TPL % {"EXTERN": READ_EXTERN_PE, "SIZE": READ_SIZE_PE,
                                 "INTO": READ_INTO_PE}
    else:
        body = RB_SELFMOD_TPL % {"EXTERN": READ_EXTERN_ELF,
                                 "SIZE": READ_SIZE_ELF, "INTO": READ_INTO_ELF}
    selfmod = _write_vx(ctx, "rb_selfmod.vx", body)
    exe = aot_build(ctx, selfmod, "rb_selfmod",
                    "ReaderBMP AOT auto-contenida no produjo exe nativo")
    got = run_capture([exe], cwd=rb)
    if got != ref60:
        ctx.fail("ReaderBMP AOT (features vx_fileio/bg_rgb): bytes != referencia",
                 "obtenido %d bytes, referencia %d bytes" % (len(got), len(ref60)))
    ctx.ok("ReaderBMP AOT Ejemplo60x3 (-m aot, features) -> volcado byte-exacto")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_case(entry):
    """Ejecuta un caso y devuelve (tag, lines, n_ok, ok?)."""
    _, tag, fn, _ = entry
    ctx = Ctx(tag)
    try:
        fn(ctx)
        return (tag, ctx.lines, ctx.n_ok, True)
    except CaseFail:
        return (tag, ctx.lines, ctx.n_ok, False)
    except Exception as e:      # error del propio harness: reportarlo como fallo
        import traceback
        ctx.lines.append(("FAIL", "%s: excepcion del harness: %s" % (tag, e)))
        ctx.lines.append(("DETAIL", traceback.format_exc()))
        return (tag, ctx.lines, ctx.n_ok, False)


# --- Fallos sin capturar: se cuentan igual en interprete y JIT ---
fault3_case("fallo_division_cero",
            "division entre cero con cadena de tres marcos",
            "369_fallo_division_cero.vx", "VX7002", 136)
fault3_case("fallo_panic", "panic sin capturar",
            "370_fallo_panic.vx", "VX7011", 134)


@case("target_tier")
def _(ctx):
    """El eje `tier:` de @Target elige UNA variante, y la que toca.

    Cada variante devuelve un numero distinto a proposito: asi el resultado no
    solo dice que compilo, dice CUAL se eligio.  Y se comprueban los dos lados
    del eje -- el binario nativo y la ruta de bytecode --, porque lo que hay
    que fijar es justamente que en bytecode NINGUN tier vale: alli no hay
    binario del que hablar, y una variante marcada para un tier no debe colarse
    donde ese tier no existe.
    """
    src = "520_target_tier.vx"
    ctx.compile_vx(ctx.src(src), "ttier")
    for modo in ("vm", "jit"):
        _, log = ctx.run_velb("ttier", schedulers=1, mode=modo)
        got = get_r00(log)
        if got != 4:
            ctx.fail("tier (-m %s): R00 == %s, se esperaba 4 (sin tier)"
                     % (modo, got), log)
        ctx.ok("tier (-m %s) -> 4: en bytecode ningun tier vale" % modo)
    # `bare` es el valor por defecto de --target; `embed` se pide.
    for destino, quiere in (("bare", 3), ("embed", 2)):
        exe = aot_build(ctx, ctx.src(src), "ttier_" + destino,
                        "tier (-m aot --target %s)" % destino,
                        extra=["--target", destino])
        rc, log = ctx.run([exe])
        if exit_code(rc) != quiere:
            ctx.fail("tier (-m aot --target %s): sale %d, se esperaba %d"
                     % (destino, exit_code(rc), quiere), log)
        ctx.ok("tier (-m aot --target %s) -> %d" % (destino, quiere))


@case("excepcion_sin_capturar")
def _(ctx):
    """Un `throw` que nadie recoge: se ve, y se ve IGUAL en los tres modos.

    Aqui no vale el criterio flojo de `fault3_case` -- "que al menos no salga
    con cero" --, porque los tres fallaban de tres maneras distintas y las tres
    eran silenciosas o peores: interprete y JIT paraban sin decir nada y
    saliendo con CERO, y el nativo se colgaba para siempre.

    Se exige lo mismo a los tres: que lo impreso antes de fallar siga estando,
    que se cuente por la salida de error y que se salga con 134.  Y a los dos
    que tienen metadatos, ademas, el nombre de la clase y la cadena.
    """
    tag = "excsc"
    ctx.compile_vx(ctx.src("519_excepcion_sin_capturar.vx"), tag)
    for modo in ("vm", "jit"):
        rc, log = ctx.run_velb(tag, schedulers=1, stats=False, mode=modo)
        if exit_code(rc) != 134:
            ctx.fail("sin capturar (-m %s): sale %d, se esperaba 134"
                     % (modo, exit_code(rc)), log)
        if "saldo inicial: 100" not in log:
            ctx.fail("sin capturar (-m %s): se perdio lo impreso antes de "
                     "fallar" % modo, log)
        if "VX7026" not in log:
            ctx.fail("sin capturar (-m %s): no se cuenta" % modo, log)
        if "SinFondos" not in log:
            ctx.fail("sin capturar (-m %s): no dice que clase se lanzo"
                     % modo, log)
        if "Stack trace" not in log:
            ctx.fail("sin capturar (-m %s): sin cadena de llamadas"
                     % modo, log)
        ctx.ok("sin capturar (-m %s) -> VX7026 SinFondos, sale 134" % modo)
    exe = aot_build(ctx, ctx.src("519_excepcion_sin_capturar.vx"),
                    tag + "_aot", "sin capturar (-m aot)")
    rc, log = ctx.run([exe])
    if exit_code(rc) != 134:
        ctx.fail("sin capturar (-m aot): sale %d, se esperaba 134"
                 % exit_code(rc), log)
    if "saldo inicial: 100" not in log:
        ctx.fail("sin capturar (-m aot): se perdio lo impreso antes de fallar",
                 log)
    if "uncaught exception" not in log:
        ctx.fail("sin capturar (-m aot): no se cuenta", log)
    ctx.ok("sin capturar (-m aot) -> se cuenta y sale 134")
@case("expect508")
def _(ctx):
    """`expect` que falla: dice QUE se dio por hecho, y despues muere.

    `unwrap` que falla solo puede contar el mensaje generico del catalogo, que
    dice lo que paso y no lo que se esperaba.  `expect` deja escrito el supuesto
    en el propio sitio, y es lo unico que queda cuando falla -- por eso se
    comprueba que el texto sale, no solo que el proceso muere.

    Interprete y JIT: el mensaje propio, el codigo del catalogo y la cadena de
    llamadas.  El nativo NO reporta a ese nivel a proposito (tiene que ser
    ligero), asi que ahi solo se exige que no salga con cero.
    """
    ctx.compile_vx(ctx.src("508_expect_falla.vx"), "expect508")
    ctx.ok("compilacion 508_expect_falla.vx -> .velb")
    for modo in ("vm", "jit"):
        rc, log = ctx.run_velb("expect508", schedulers=1, mode=modo)
        if "el limite de reintentos venia de la configuracion" not in log:
            ctx.fail("expect (-m %s): no sale el mensaje del sitio" % modo, log)
        if "VX7001" not in log:
            ctx.fail("expect (-m %s): no aparece VX7001" % modo, log)
        if "Stack trace" not in log:
            ctx.fail("expect (-m %s): sin cadena de llamadas" % modo, log)
        if exit_code(rc) == 0:
            ctx.fail("expect (-m %s): salio con cero tras reventar" % modo, log)
        ctx.ok("expect (-m %s) -> mensaje del sitio + VX7001, muere" % modo)
    exe = aot_build(ctx, ctx.src("508_expect_falla.vx"), "expect508_aot",
                    "expect que falla (-m aot)")
    rc, _ = ctx.run([exe])
    if exit_code(rc) == 0:
        ctx.fail("expect (-m aot): salio con cero tras reventar")
    ctx.ok("expect (-m aot) -> muere, como debe")


fails_case("neg_unwrap_or_tipo",
           "unwrap_or: el valor de repuesto tiene que ser del tipo del valor",
           "509_neg_unwrap_or_tipo.vx", "el valor por defecto es")
fails_case("neg_expect_mensaje",
           "expect: el mensaje tiene que estar escrito en el sitio (se emite "
           "como texto conocido al compilar)",
           "510_neg_expect_mensaje.vx", "una cadena escrita en el sitio")
fails_case("neg_unwrap_or_aridad",
           "unwrap_or con un solo argumento: se parece demasiado a unwrap, que "
           "SI mata el proceso, asi que se rechaza en vez de interpretarlo",
           "511_neg_unwrap_or_aridad.vx", "se esperaban 2 argumentos")


fault3_case("unwrap_fatal506",
            "afirmar que hay algo y equivocarse mata el proceso en los TRES "
            "modos, y ningun catch lo intercepta: es un bug del programa, no "
            "una condicion recuperable.  Antes se capturaba en interprete y "
            "JIT y mataba en nativo -- el mismo programa hacia dos cosas "
            "distintas segun el modo",
            "506_unwrap_fallido_es_fatal.vx", "VX7001", 139)


def main():
    global VM_EXE, TMP_ROOT
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("build_dir", help="directorio con vm.exe / vm")
    ap.add_argument("-j", "--jobs", type=int, default=0,
                    help="casos en paralelo (0 = automatico)")
    ap.add_argument("-k", "--filter", default=None,
                    help="ejecutar solo los casos cuyo tag contenga esta cadena")
    ap.add_argument("--keep", action="store_true",
                    help="no borrar el directorio temporal al terminar")
    ap.add_argument("--verify-ir", action="store_true",
                    help="hacer que el compilador verifique el IR que "
                         "construye (cada valor definido una vez, operandos "
                         "existentes, todo bloque acabado y acabado en su "
                         "ultima instruccion)")
    args = ap.parse_args()

    # La verificacion va por variable de entorno para que la vean TODAS las
    # invocaciones del compilador, incluidas las que un caso lanza por su
    # cuenta.  Los problemas salen por el error estandar y el caso los
    # arrastra a su registro.
    if args.verify_ir:
        os.environ["VESTA_VERIFY_IR"] = "1"

    vm = os.path.join(args.build_dir, "vm.exe")
    if not os.path.exists(vm):
        vm = os.path.join(args.build_dir, "vm")
    if not os.path.exists(vm):
        sys.exit("FAIL: no se encuentra vm[.exe] en %s" % args.build_dir)
    VM_EXE = os.path.abspath(vm)
    TMP_ROOT = tempfile.mkdtemp(prefix="vxe2e_")

    entries = sorted(CASES, key=lambda c: c[0])
    if args.filter:
        entries = [e for e in entries if args.filter in e[1]]
    par = [e for e in entries if not e[3]]
    ser = [e for e in entries if e[3]]

    jobs = args.jobs or min(8, os.cpu_count() or 4)
    results = {}
    try:
        # Los casos paralelizables van al pool; los que tocan estado global
        # (directorios fijos del repo) se ejecutan despues, de uno en uno.
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            for tag, lines, n_ok, ok in pool.map(run_case, par):
                results[tag] = (lines, n_ok, ok)
        for e in ser:
            tag, lines, n_ok, ok = run_case(e)
            results[tag] = (lines, n_ok, ok)
    finally:
        if not args.keep:
            shutil.rmtree(TMP_ROOT, ignore_errors=True)

    # Reporte en el orden del .sh original (determinista pese al paralelismo).
    steps = 0
    failed = []
    for _, tag, _, _ in entries:
        lines, n_ok, ok = results[tag]
        for kind, msg in lines:
            if kind == "DETAIL":
                print("      | " + msg.replace("\n", "\n      | "))
            else:
                print("%s: %s" % (kind, msg))
        steps += n_ok
        if not ok:
            failed.append(tag)

    # INVARIANTES del compilador, no casos.  Van al final porque no prueban un
    # programa: prueban una propiedad de la que dependen otras decisiones.  El
    # del cache puro sostiene que reclamar espacio sea seguro; si se rompe, hay
    # que enterarse en ese commit y no meses despues.
    import subprocess as _sp
    _inv = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "test_cache_puro.py")
    if os.path.exists(_inv):
        print("")
        _r = _sp.run([sys.executable, _inv, args.build_dir], capture_output=True,
                     text=True)
        for _l in _r.stdout.splitlines():
            print(_l)
        if _r.returncode != 0:
            failed.append("cache-puro")
        else:
            steps += 1

    print("")
    if failed:
        print("=== e2e: %d pasos OK, %d casos fallidos (%s) ==="
              % (steps, len(failed), ", ".join(failed)))
        sys.exit(1)
    print("=== e2e: %d pasos OK, 0 fallidos (%d casos) ==="
          % (steps, len(entries)))


modes3_case("direccion_parametros",
            "in/out/inout: la marca vale en TODO lo que se declara",
            "521_direccion_parametros.vx", 52)


@case("efectos_extern_target")
def _(ctx):
    """Los efectos de una externa, y que dependan del OBJETIVO.

    Las dos mitades importan por separado.  Que compile y corra prueba que lo
    definido no estorba; lo que de verdad se fija aqui es la SEGUNDA: el mismo
    fichero, la misma declaracion, un solo simbolo, y el veredicto cambia al
    cambiar de objetivo.  Eso es lo que no se puede conseguir repitiendo la
    declaracion con `@Target` -- alli lo que cambia es que simbolo existe --, y
    por eso se comprueba mirando el error y no solo el codigo de salida.
    """
    src = "522_efectos_extern_target.vx"
    ctx.compile_vx(ctx.src(src), "fxtgt")
    _, log = ctx.run_velb("fxtgt", schedulers=1)
    got = get_r00(log)
    if got != 42:
        ctx.fail("efectos extern: R00 == %s, se esperaba 42" % got, log)
        return
    if "Hola FFI!" not in log:
        ctx.fail("efectos extern: no salio lo impreso por la nativa", log)
        return
    ctx.ok("efectos extern (windows) -> 42, y la nativa imprimio")
    # Y para Linux la definicion dice que SI puede entrar en panico, asi que el
    # `@nopanic` de quien la llama se incumple.  Se exige el codigo del
    # catalogo: que falle no basta -- podria fallar por cualquier otra cosa --.
    rc, log2 = ctx.run([VM_EXE, "-m", "aot", "--vesta", ctx.src(src),
                        "--format", "elf", "--emit", "obj",
                        "-o", ctx.path("fxtgt_l")])
    if "VXT004" not in log2:
        ctx.fail("efectos extern: apuntando a linux el @nopanic tenia que "
                 "incumplirse (VXT004) y no salio", log2)
        return
    ctx.ok("efectos extern (linux) -> VXT004: el mismo fichero, otro veredicto")




# ---------------------------------------------------------------------------
# La direccion (`in`/`out`/`inout`) tiene que INCUMPLIRSE cuando toca.
#
# El camino positivo lo cubre `521_direccion_parametros`, y por si solo no
# demuestra nada: una marca que se acepta y no hace nada tambien compila y
# tambien da 52.  Lo que hay que fijar es que CUMPLE lo que promete, y eso solo
# se ve cuando el programa que la rompe NO compila.
#
# Se comprueba el CODIGO del catalogo y no el texto donde lo hay: el texto sale
# en el idioma activo y cambiaria el resultado del test segun la variable de
# entorno.  Donde el mensaje aun no esta en el catalogo se busca un trozo
# estable.
# ---------------------------------------------------------------------------
DIR_NEG_CASES = [
    ("dir_neg_in_ptr", """i64 f(in i64* p) {
    (*p) = 1;
    return 0;
}
""", "lvalue 'const'",
     "in: escribir por un puntero `in` rechazado",
     "in: escribir por un puntero `in` debio fallar"),
    ("dir_neg_in_valor", """i64 f(in i64 x) {
    x = 1;
    return x;
}
""", "lvalue 'const'",
     "in: escribir la copia de un valor `in` rechazado",
     "in: escribir la copia de un valor `in` debio fallar"),
    ("dir_neg_in_local", """i32 main() {
    i64 v = 1;
    in i64* p = &v;
    (*p) = 2;
    return 0;
}
""", "lvalue 'const'",
     "in: el permiso vale igual en una VARIABLE, no solo en un parametro",
     "in: escribir por una variable `in` debio fallar"),
    ("dir_neg_in_auto", """i32 main() {
    i64 v = 1;
    in auto p = &v;
    (*p) = 2;
    return 0;
}
""", "lvalue 'const'",
     "in: la promesa SOBREVIVE a la inferencia de tipo",
     "in: escribir por un `in auto` debio fallar"),
    ("dir_neg_out_const", """i64 f(out const i64* p) {
    return 0;
}
""", "VXT006",
     "out sobre un pointee `const`: la contradiccion se detecta",
     "out sobre un pointee `const` debio fallar"),
    # `out` sobre un valor SI significa algo en un parametro -- es el parametro
    # de salida, y funciona (ver `parametros_salida`) --, pero en una variable
    # no: ahi no hay ningun llamante que ceda el hueco.
    ("dir_neg_out_valor", """i32 main() {
    out i64 x = 1;
    return (i32) x;
}
""", "VXT009",
     "out sobre una VARIABLE: no hay llamante que ceda un hueco",
     "out sobre una variable debio dar VXT009"),
    ("dir_neg_out_arg_no_lvalue", """void f(out i64 x) {
    x = 1;
}
i32 main() {
    f(3);
    return 0;
}
""", "VXT011",
     "el argumento de un `out` tiene que ser un SITIO donde escribir",
     "pasar un literal a un `out` debio fallar"),
    ("dir_neg_tipo_marca_perdida", """void escribe(out i64 r) {
    r = 7;
}
i32 main() {
    cfn(i64*) -> void perdida = &escribe;
    return 0;
}
""", "incompatible con tipo declarado",
     "la marca no se cae al guardar la funcion en una variable",
     "guardar un `out` en un cfn sin marca debio fallar"),
    ("dir_neg_tipo_marca_inventada", """void por_puntero(i64* p) {
    *p = 9;
}
i32 main() {
    cfn(out i64) -> void inventada = &por_puntero;
    return 0;
}
""", "incompatible con tipo declarado",
     "el tipo no puede prometer lo que la funcion no dice",
     "prometer `out` sobre una funcion sin marca debio fallar"),
    ("dir_neg_out_ctor_no_lvalue", """class Kaja {
    public i64 v;
    public Kaja(i64 x, out i64 eco) { this.v = x; eco = x; }
}
i32 main() {
    Kaja k = new Kaja(6, 3);
    return 0;
}
""", "VXT011",
     "un constructor exige lo mismo que cualquier otra llamada",
     "pasar un literal al `out` de un constructor debio fallar"),
    ("dir_neg_tipo_borrow_indirecto", """void dos(inout i64 a, inout i64 b) {
    a = a + 1;
    b = b + 1;
}
i32 main() {
    cfn(inout i64, inout i64) -> void f = &dos;
    i64 x = 1;
    f(x, x);
    return (i32) x;
}
""", "VX2026",
     "las reglas de prestamo valen tambien por PUNTERO a funcion",
     "dos `inout` al mismo dueno por puntero debieron fallar"),
    ("dir_neg_tipo_otra_marca", """void escribe(out i64 r) {
    r = 7;
}
i32 main() {
    cfn(inout i64) -> void otra = &escribe;
    return 0;
}
""", "incompatible con tipo declarado",
     "`inout` promete mas que `out`: no son el mismo tipo",
     "cambiar `out` por `inout` en el tipo debio fallar"),
]


def _dir_neg_case(tag, source, pattern, ok_msg, fail_msg):
    def fn(ctx):
        vx = _write_vx(ctx, tag + ".vx", source)
        rc, log = ctx.run([VM_EXE, "--vesta", vx, "-o", ctx.path(tag)])
        if rc == 0:
            ctx.fail(fail_msg, log)
            return
        if pattern not in log:
            ctx.fail("%s: fallo, pero no por lo esperado ('%s')"
                     % (tag, pattern), log)
            return
        ctx.ok(ok_msg)
    fn.__name__ = "case_" + tag
    return fn


for _t, _s, _p, _m, _f in DIR_NEG_CASES:
    _register(_t, _dir_neg_case(_t, _s, _p, _m, _f), False, None)




modes3_case("direccion_campos",
            "in/out en un CAMPO: struct, clase y overlay",
            "523_direccion_campos.vx", 8)


# La direccion en un campo tiene que INCUMPLIRSE igual que en un parametro.
# Si el permiso solo valiera donde se declara y no donde se usa, la marca seria
# documentacion: se leeria como una promesa y no obligaria a nada.
DIR_CAMPO_NEG_CASES = [
    ("dir_neg_campo_struct", """struct Caja {
    in i64* p;
}
i32 main() {
    i64 a = 1;
    Caja c;
    c.p = &a;
    (*c.p) = 2;
    return 0;
}
""", "lvalue 'const'",
     "in en un campo de struct: escribir por ahi rechazado",
     "in en un campo de struct: escribir por ahi debio fallar"),
    ("dir_neg_campo_clase", """class C {
    public in i64* p;
}
i32 main() {
    return 0;
}
i64 romper(C c) {
    (*c.p) = 2;
    return 0;
}
""", "lvalue 'const'",
     "in en un campo de clase: escribir por ahi rechazado",
     "in en un campo de clase: escribir por ahi debio fallar"),
    ("dir_neg_campo_overlay", """@overlay
struct V {
    out const i64* p @0x00;
}
i32 main() {
    return 0;
}
""", "VXT006",
     "la contradiccion con `const` se detecta tambien en un overlay",
     "out sobre un pointee const en un overlay debio fallar"),
    ("dir_neg_retorno", """class C {
    public in i64* m() {
        return null;
    }
}
i32 main() {
    return 0;
}
""", "VXT010",
     "la marca en un tipo de RETORNO se rechaza: no hay a quien dar el permiso",
     "in en un tipo de retorno debio fallar"),
]

for _t, _s, _p, _m, _f in DIR_CAMPO_NEG_CASES:
    _register(_t, _dir_neg_case(_t, _s, _p, _m, _f), False, None)




modes3_case("parametros_salida",
            "out/inout sobre un valor: el parametro de SALIDA",
            "524_parametros_salida.vx", 59)




# Los dos que se colaron al implementar el parametro de salida.  El positivo no
# los habria cogido: los dos COMPILAN, y uno hasta ejecuta.
DIR_OUT_BUG_CASES = [
    ("dir_neg_out_sin_escribir", """void f(out i64 x) {
    return;
}
i32 main() {
    i64 v = 9;
    f(v);
    return (i32) v;
}
""", "VXT012",
     "un `out` que el cuerpo nunca escribe: promete y no cumple",
     "un `out` sin escribir debio fallar"),
]

for _t, _s, _p, _m, _f in DIR_OUT_BUG_CASES:
    _register(_t, _dir_neg_case(_t, _s, _p, _m, _f), False, None)


@case("out_en_metodo")
def _(ctx):
    """Un `out` en un METODO tiene que devolver el valor, igual que en una
    funcion suelta.

    Se colo: el metodo se baja por otro camino, asi que el parametro se quedaba
    como un valor corriente.  La asignacion del cuerpo compilaba a un calculo
    MUERTO -- sin store y sin error -- y el argumento viajaba por VALOR donde el
    llamado esperaba una direccion.  Devolvia 0 y no se quejaba nadie.
    """
    src = """class C {
    public void dividir(i32 a, i32 b, out i32 c) { c = a / b; }
}
i32 main() {
    C k = new C();
    i32 r;
    k.dividir(9, 3, r);
    return r;
}
"""
    vx = _write_vx(ctx, "out_metodo.vx", src)
    if not ctx.compile_vx(vx, "outmet"):
        return
    for modo in ("vm", "jit"):
        _, log = ctx.run_velb("outmet", schedulers=1, mode=modo)
        got = get_r00(log)
        if got != 3:
            ctx.fail("out en metodo (-m %s): R00 == %s, se esperaba 3"
                     % (modo, got), log)
            return
        ctx.ok("out en metodo (-m %s) -> 3" % modo)




# `in`/`out` y el borrow checker son LO MISMO dicho de dos formas: `in` presta
# compartido y `out`/`inout` exclusivo.  Lo comprueba el mismo checker, asi que
# estos casos salen de las reglas que ya existian (R1/R2) y no de una segunda
# idea de quien puede aliasar a quien.
DIR_ALIAS_CASES = [
    ("dir_neg_alias_inout", """void f(inout i64 a, inout i64 b) {
    a = b;
}
i32 main() {
    i64 x = 1;
    f(x, x);
    return 0;
}
""", "VX2026",
     "dos `inout` al mismo dueno: aliasing mutable, por R1 del borrow checker",
     "dos `inout` al mismo dueno debio fallar"),
]

for _t, _s, _p, _m, _f in DIR_ALIAS_CASES:
    _register(_t, _dir_neg_case(_t, _s, _p, _m, _f), False, None)


@case("dir_alias_compartido")
def _(ctx):
    """Dos `in` al MISMO dueno SI valen: son prestamos compartidos.

    Importa tanto como el negativo.  Una regla de aliasing que rechazara esto
    seria inutilizable -- pasar la misma cosa dos veces para leerla es normal --
    y se aprenderia a desactivar.  Sale de R2, que ya existia.
    """
    src = """i64 suma(in i64* a, in i64* b) {
    return (*a) + (*b);
}
i32 main() {
    i64 x = 21;
    return (i32) suma(&x, &x);
}
"""
    vx = _write_vx(ctx, "dir_alias_ok.vx", src)
    if not ctx.compile_vx(vx, "diralias"):
        return
    _, log = ctx.run_velb("diralias", schedulers=1)
    got = get_r00(log)
    if got != 42:
        ctx.fail("dos `in` al mismo dueno: R00 == %s, se esperaba 42" % got, log)
        return
    ctx.ok("dos `in` al mismo dueno -> 42: compartidos, es legitimo")




@case("fmt_corpus_formateado")
def _(ctx):
    """Todo el corpus esta formateado, y se comprueba SIN una lista que
    mantener.

    `fmt_test` corre sobre `tests/vx/fmt_corpus.txt`, que se genera a mano.
    Eso deja un hueco silencioso: al anadir un ejemplo, el formateador deja de
    mirarlo hasta que alguien se acuerda de regenerar la lista -- y se
    acumulan: en un momento dado faltaban 31 ficheros --.

    `vesta fmt check` recorre el DIRECTORIO, asi que no hay lista que se quede
    atras.  No sustituye a `fmt_test` -- ese comprueba ademas idempotencia y
    que el programa siga siendo el mismo --, pero si cierra el hueco de
    cobertura, que es el que no avisa.
    """
    # `tests` y `tools` tambien: estaban fuera de la red y ahi se acumularon 66
    # ficheros sin formatear.  Se comprobo uno a uno que formatearlos NO cambia
    # lo que el programa hace -- compilando y ejecutando el antes y el despues
    # --, asi que no habia nada que decidir: era cobertura que faltaba.
    for d in ("examples_codes_vx", "stdlib", "tests", "tools"):
        rc, log = ctx.run([VM_EXE, "fmt", "check", os.path.join(ROOT, d)])
        if rc != 0:
            ctx.fail("fmt check %s: hay ficheros sin formatear (pasa "
                     "`vesta fmt %s`)" % (d, d), log)
            return
        ctx.ok("fmt check %s: todo formateado" % d)




modes3_case("direccion_y_borrow",
            "in/out y el borrow checker: la misma regla, dos notaciones",
            "525_direccion_y_borrow.vx", 42)




modes3_case("escritura_por_puntero_indirecto",
            "lo que escribe una funcion llamada por PUNTERO se ve fuera",
            "526_escritura_por_puntero_indirecto.vx", 21)




# `out` en TODOS los caminos, no solo "alguna vez".  El hecho que lo contesta
# vive en el ASA (`DefiniteStoreFacts`) y se calcula sobre el IR, que es quien
# ya tiene el grafo de flujo: escribir un segundo recorrido sobre el AST habria
# sido producir dos veces lo mismo, y el segundo se queda atras.
DIR_OUT_FLUJO_CASES = [
    ("dir_neg_out_una_rama", """void f(out i64 x, bool c) {
    if (c) {
        x = 1;
    }
}
i32 main() {
    i64 v = 9;
    f(v, false);
    return (i32) v;
}
""", "VXT012",
     "un `out` escrito en UNA rama y no en la otra: la version que solo miraba "
     "si se escribia ALGUNA vez dejaba pasar esto",
     "un `out` sin escribir en todos los caminos debio fallar"),
]

for _t, _s, _p, _m, _f in DIR_OUT_FLUJO_CASES:
    _register(_t, _dir_neg_case(_t, _s, _p, _m, _f), False, None)


@case("dir_out_flujo_ok")
def _(ctx):
    """Los dos casos que NO debe acusar, que importan tanto como el negativo.

    Un analisis de "para todos los caminos" que se equivoque hacia el lado malo
    rechaza codigo correcto, y entonces se aprende a rodearlo.  Aqui: escribirlo
    en las dos ramas vale, y DELEGAR el relleno en otra funcion tambien -- por
    ahi el analisis no puede ver si se escribe, asi que se calla en vez de
    acusar.
    """
    src = """void en_las_dos(out i64 x, bool c) {
    if (c) { x = 1; } else { x = 2; }
}
void relleno(i64* p) { (*p) = 3; }
void delega(out i64 x) { relleno(&x); }
i32 main() {
    i64 a = 0;
    en_las_dos(a, false);
    i64 b = 0;
    delega(b);
    return (i32) (a + b);
}
"""
    vx = _write_vx(ctx, "dir_out_flujo_ok.vx", src)
    if not ctx.compile_vx(vx, "dsok"):
        return
    for modo in ("vm", "jit"):
        _, log = ctx.run_velb("dsok", schedulers=1, mode=modo)
        got = get_r00(log)
        if got != 5:
            ctx.fail("out en todos los caminos (-m %s): R00 == %s, se esperaba 5"
                     % (modo, got), log)
            return
        ctx.ok("out en todos los caminos (-m %s) -> 5" % modo)



# ---------------------------------------------------------------------------
# La direccion FORMA PARTE del tipo de una funcion.
#
# El positivo enseña las dos direcciones del cast; el negativo fija que sin el
# cast la marca NO se cae en silencio, que es lo unico que hace que el tipo
# sirva de algo.
# ---------------------------------------------------------------------------
modes3_case("direccion_en_el_tipo",
            "in/out/inout dentro del tipo de un puntero a funcion",
            "527_direccion_en_el_tipo.vx", 45)

fails_case("direccion_tipo_err",
           "perder o inventar la marca en el tipo es un ERROR",
           "528_direccion_tipo_err.vx", "incompatible con tipo declarado")

# Las OCHO formas de llamar bajan por caminos distintos, y cuatro de ellos no
# tomaban la direccion: el metodo de un struct, una lambda en una variable, un
# metodo ligado y un constructor.  Ninguno daba un error -- daban CERO --, asi
# que lo que hay que fijar es que las ocho coincidan.
#
# Se comprueba CADA LINEA y no solo el total: si el total fuera lo unico, una
# regresion diria "19 en vez de 21" y habria que ir a buscar cual de los ocho
# se rompio.  Es la diferencia entre un test que avisa y uno que ademas dice
# QUE pasa, que es lo que se le pide al resto del sistema.
OUT_CAMINOS_LINEAS = [
    r"suelta: +1",
    r"metodo struct: +2",  # se bajaba por un camino propio -> daba CERO
    r"metodo clase: +3",
    r"cfn: +1",
    r"fn \(variable\): +1",  # escribia a traves de un numero -> moria en 0x0
    r"metodo ligado: +3",  # pedia la direccion de una direccion
    r"ctor struct: +4",  # no habia forma de llamarlo
    r"ctor clase: +6",
    r"total = 21",
]


# La MATRIZ de efectos de una funcion externa: las catorce palabras, y que le
# cuesta cada una a quien llama.
#
# Lo que hay que fijar NO es que compile -- eso lo hacia tambien cuando la
# palabra se aceptaba y no llegaba a ningun sitio --, sino que CADA UNA cambie
# el veredicto de la manera documentada.  El fallo que esto cierra era el peor
# posible: declarar `@blocks` dejaba la funcion MAS limpia que no declarar
# nada, porque encendia "alguien hablo" (que quita el efecto maximo) y luego el
# eje se perdia al serializar el IR.
#
# La tabla es la del propio ejemplo, para que las dos no puedan divergir: si
# alguien cambia una y no la otra, esto falla.
EFECTOS_FFI_QUITAN = {
    "con_io": ["pure", "mem_free", "deterministic", "freestanding"],
    "con_throws": ["pure", "mem_free", "nothrow"],
    "con_panics": ["pure", "nopanic"],
    "con_alloc": ["pure", "mem_free", "heap_free", "gc_free"],
    "con_nondet": ["deterministic"],
    "con_keeps_state": ["pure", "mem_free", "readonly", "deterministic"],
    # El mundo PARTIDO: la misma palabra con otra parte da otro veredicto.
    # Es lo que se pierde si "lee el mundo" es una sola cosa.
    "con_reads_env": ["mem_free"],                    # config: no cambia
    "con_reloj": ["mem_free", "deterministic"],       # clock: si cambia
    "con_writes_env": ["pure", "mem_free", "readonly", "deterministic",
                       "freestanding"],
    "con_blocks": ["pure", "mem_free"],
    "con_traps": ["pure", "mem_free"],
}
# Lo que sale cuando NADA esta encendido, que es contra lo que se compara.
EFECTOS_FFI_BASE = ["pure", "mem_free", "readonly", "leaf", "nothrow",
                    "nopanic", "deterministic", "heap_free", "gc_free",
                    "freestanding"]


@case("efectos_ffi", line=None)
def _(ctx):
    """Las catorce palabras de efectos de una externa, una por una."""
    src = ctx.src("530_efectos_ffi.vx")
    _, log = ctx.run([VM_EXE, "--analyze", src])
    # Los contratos de cada envoltorio: la linea `Contratos` que sigue a su
    # nombre.  Se mira POR FUNCION y no en todo el volcado, porque las otras
    # si son puras y darian un falso OK.
    lineas = log.splitlines()
    contratos = {}
    for i, l in enumerate(lineas):
        marca = l.strip()
        for corto in list(EFECTOS_FFI_QUITAN) + ["sin_nada"]:
            if marca.endswith("__" + corto):
                for j in range(i + 1, min(i + 4, len(lineas))):
                    if "Contratos" in lineas[j]:
                        contratos[corto] = set(
                            lineas[j].split(":", 1)[1].split())
                        break
    if "sin_nada" not in contratos:
        ctx.fail("no se pudo leer el analisis de 530_efectos_ffi.vx", log)
        return
    # La base: con las cinco negativas, TODO se cumple.  Si esto falla, lo
    # demas no significa nada -- se estaria comparando contra otra cosa --.
    faltan = [c for c in EFECTOS_FFI_BASE if c not in contratos["sin_nada"]]
    if faltan:
        ctx.fail("con las cinco negativas faltan contratos: %s" % faltan, log)
        return
    ctx.ok("las cinco negativas no encienden nada (%d contratos)"
           % len(EFECTOS_FFI_BASE))
    for corto, quita in sorted(EFECTOS_FFI_QUITAN.items()):
        got = contratos.get(corto)
        if got is None:
            ctx.fail("no se pudo leer el analisis de '%s'" % corto, log)
            return
        # Los que la palabra TIENE que quitar.
        sobran = [c for c in quita if c in got]
        if sobran:
            ctx.fail("'%s' tenia que quitar %s y siguen ahi: %s"
                     % (corto, quita, sobran), log)
            return
        # Y los que NO tiene que tocar: un efecto que se lleva por delante mas
        # de lo suyo tambien es un fallo, y sin esto no se veria.
        deberian = [c for c in EFECTOS_FFI_BASE if c not in quita]
        perdidos = [c for c in deberian if c not in got]
        if perdidos:
            ctx.fail("'%s' no tenia que tocar %s" % (corto, perdidos), log)
            return
        ctx.ok("%s -> quita exactamente %s" % (corto, ",".join(quita)))


@case("out_por_todos_los_caminos", line=None)
def _(ctx):
    """Un `out` cumple lo mismo se llame como se llame, en los tres modos."""
    etiqueta = "un `out` se llame como se llame (8 caminos)"
    src = "529_out_por_todos_los_caminos.vx"
    ctx.compile_vx(ctx.src(src), "e529")
    # Las lineas ANTES del total: `fail` aborta el caso, asi que comprobar
    # primero la suma dejaria el detalle sin llegar a mirarse -- y el detalle
    # es justo lo que hace falta cuando algo se rompe.
    for modo in ("vm", "jit"):
        _, log = ctx.run_velb("e529", schedulers=1, mode=modo)
        expect_lines(ctx, log, "%s (-m %s)" % (etiqueta, modo),
                     OUT_CAMINOS_LINEAS)
        got = get_r00(log)
        if got != 21:
            ctx.fail("%s (-m %s): R00 == %s, se esperaban 21"
                     % (etiqueta, modo, got), log)
        ctx.ok("%s (-m %s) -> los 8 caminos" % (etiqueta, modo))
    exe = aot_build(ctx, ctx.src(src), "e529_aot", etiqueta + " (-m aot)")
    rc, log = ctx.run([exe])
    expect_lines(ctx, log, etiqueta + " (-m aot)", OUT_CAMINOS_LINEAS)
    got = exit_code(rc)
    if got != 21:
        ctx.fail("%s (-m aot): sale %d, se esperaban 21" % (etiqueta, got), log)
    ctx.ok("%s (-m aot) -> los 8 caminos" % etiqueta)


if __name__ == "__main__":
    main()
