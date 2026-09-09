#!/usr/bin/env python3
"""Nuestro linker honra `/DEFAULTLIB` de un objeto de MSVC y resuelve contra el CRT.

# LADO: windows

Que se prueba, y por que importa
--------------------------------
Un objeto compilado en modo MSVC referencia cosas que el mismo no define.  El
caso tipico es el guardia de pila, que `clang-cl` y `cl` activan POR DEFECTO:
el codigo llama a `__security_check_cookie` y lee `__security_cookie`, y las dos
las define el CRT de Microsoft.

El objeto no da eso por supuesto: lleva la instruccion dentro, en una seccion
`.drectve`, escrita como `/DEFAULTLIB:libcmt.lib`.  Es decir, el propio objeto
dice contra que hay que enlazarlo.

Nuestro linker DESCARTABA esa seccion, asi que esos simbolos salian como no
resueltos y el enlace fallaba.  No faltaba ninguna definicion que tuvieramos que
inventar -- estan en `libcmt.lib`, ahi al lado --: lo que faltaba era leer la
peticion.  Este test comprueba que ya se lee y que sirve para algo.

No basta con que el enlace SALGA: eso podria pasar por cualquier otro motivo --
que el simbolo se colara por otra via, que no llegara a referenciarse.  Asi que
ademas se comprueba que el binario resultante trae dentro codigo del CRT, que es
algo que solo puede haber llegado extrayendo miembros de `libcmt.lib`.

Y las rutas ya no hace falta ponerlas a mano: el enlazador busca en las
variables de los tres convenios (`VESTA_LIBPATH`, `LIB`, `LIBRARY_PATH`) y, si
no hay ninguna, localiza la instalacion por su cuenta.  Por eso el test corre
tal cual, sin `vcvars` delante.

    python tests/aot/msvc_drectve_test.py <build_dir>
"""
import os
import shutil
import subprocess

from aot_harness import AotTest

t = AotTest()

CLANG_CL = r"C:\Program Files\LLVM\bin\clang-cl.exe"
if not os.path.isfile(CLANG_CL):
    CLANG_CL = shutil.which("clang-cl") or ""
if not CLANG_CL:
    t.saltar("no hay clang-cl: este test necesita un objeto en modo MSVC")

def hay_crt_de_msvc():
    """Si en esta maquina hay un libcmt.lib al que llegar, por la via que sea.

    Se mira lo mismo que mira el enlazador: las variables de los tres convenios
    y, si no hay ninguna, la instalacion de Visual Studio.  Cuando no hay CRT el
    test NO aplica y se salta: un rojo permanente por falta de herramienta se
    acaba ignorando, y con el se ignoran los rojos de verdad.
    """
    for var in ("VESTA_LIBPATH", "LIB", "LIBRARY_PATH"):
        for d in os.environ.get(var, "").split(";"):
            if d and os.path.isfile(os.path.join(d, "libcmt.lib")):
                return True

    pf86 = os.environ.get("ProgramFiles(x86)", "")
    vswhere = os.path.join(pf86, "Microsoft Visual Studio", "Installer",
                           "vswhere.exe")
    if not os.path.isfile(vswhere):
        return False
    p = subprocess.run([vswhere, "-latest", "-products", "*", "-property",
                        "installationPath"], capture_output=True, text=True)
    inst = (p.stdout or "").strip().splitlines()
    if not inst:
        return False
    ver_txt = os.path.join(inst[0], "VC", "Auxiliary", "Build",
                           "Microsoft.VCToolsVersion.default.txt")
    if not os.path.isfile(ver_txt):
        return False
    with open(ver_txt) as f:
        ver = f.read().strip()
    return os.path.isfile(os.path.join(inst[0], "VC", "Tools", "MSVC", ver,
                                       "lib", "x64", "libcmt.lib"))


if not hay_crt_de_msvc():
    t.saltar("no hay un CRT de MSVC en esta maquina al que resolver")

# --- El objeto en modo MSVC, con el guardia de pila TAL CUAL --------------
# Un array local grande fuerza marco, que es lo que hace que el compilador
# meta el guardia; no se toca /GS, porque desactivarlo seria esquivar justo lo
# que se quiere probar.
c_src = t.wpath("guardia.c")
with open(c_src, "w") as f:
    f.write("long long suma_c(long long x) {\n"
            "    volatile long long a[64];\n"
            "    long long s = 0;\n"
            "    for (long long i = 0; i < 64; i++) a[i] = i * x;\n"
            "    for (long long i = 0; i < 64; i++) s += a[i];\n"
            "    return s;\n"
            "}\n")

c_obj = t.wpath("guardia.obj")
r = subprocess.run([CLANG_CL, "/c", "/O1", "/Fo:" + c_obj, c_src],
                   capture_output=True, text=True)
if not os.path.isfile(c_obj):
    t.fail("FALLO: clang-cl no produjo el objeto: " + (r.stderr or "")[:200])
    t.finish()

# Que de verdad pide la libreria; si no, el test no estaria probando nada.
with open(c_obj, "rb") as f:
    crudo = f.read()
if b"/DEFAULTLIB:libcmt" not in crudo:
    t.fail("FALLO: el objeto no trae /DEFAULTLIB:libcmt -- sin eso este test "
           "no mide lo que dice medir")
    t.finish()
print("  el objeto pide /DEFAULTLIB:libcmt")

# --- Un objeto nuestro que aporte main ------------------------------------
vx = t.write("guardia.vx", "i64 main() { return 7; }\n")
vx_obj = t.wpath("guardia_vx.obj")
if not t.compile_aot(vx, vx_obj, emit="obj", fmt="pe"):
    t.fail("FALLO: no se emitio el .obj de Vesta")
    t.finish()

rc = 0
exe = t.wpath("guardia.exe")

p = subprocess.run([t.vm, "--link", c_obj, vx_obj, "-o", exe, "--format", "pe"],
                   capture_output=True, text=True)
salida = (p.stdout or "") + (p.stderr or "")

if not os.path.isfile(exe):
    print("FALLO: no se enlazo: " + salida.strip()[:300])
    if "__security_cookie" in salida:
        print("       (el simbolo del guardia quedo sin resolver: la directiva "
              "/DEFAULTLIB no se esta atendiendo)")
    rc = 1
else:
    print("  enlazado")
    ex = t.run_exit(exe)
    if ex != 7:
        print("FALLO: el binario devolvio %d, se esperaba 7" % ex)
        rc = 1
    else:
        print("  el binario corre y devuelve 7")

    # Que HAYA entrado codigo del CRT, no solo que el enlace no se quejara.
    #
    # `.chks64` la aporta un miembro de libcmt.lib, asi que solo puede estar
    # ahi si el enlazador extrajo miembros de esa biblioteca -- y a esa
    # biblioteca solo se llega por la directiva del objeto.  Sin esta
    # comprobacion, un enlace que resolviera el simbolo por cualquier otra via
    # pasaria el test igual.
    with open(exe, "rb") as f:
        img = f.read()
    if b".chks64" not in img:
        print("FALLO: el binario no trae nada del CRT -- entonces el enlace "
              "salio por otro motivo y esto no prueba la directiva")
        rc = 1
    else:
        print("  el binario trae miembros extraidos de libcmt.lib")

# --- Segundo nivel: lo que pide un MIEMBRO del archivo -------------------
#
# Un `.lib` no es una caja cerrada.  Al extraer un miembro para resolver un
# simbolo, ese miembro trae su propia `.drectve` pidiendo mas bibliotecas, y hay
# que atenderla igual.  Mirar solo los objetos de entrada cubriria el primer
# nivel y dejaria el segundo sin atender -- y eso no se ve como "falta una
# biblioteca", se ve como un simbolo sin resolver cuyo nombre no dice de donde
# tenia que salir.
#
# Como se comprueba: el objeto de abajo pide UNICAMENTE libcmt y oldnames, pero
# usar la biblioteca estandar obliga a extraer miembros de libcmt que a su vez
# piden la UCRT.  Si en el binario final aparece `ucrtbase.dll`, es que se
# siguio la cadena entera; con un solo nivel no habria forma de llegar ahi.
c2_src = t.wpath("stdio.c")
with open(c2_src, "w") as f:
    f.write("#include <stdio.h>\n"
            "long long usa_stdio(long long x) {\n"
            "    char b[64];\n"
            "    snprintf(b, sizeof(b), \"%lld\", x);\n"
            "    return (long long)b[0];\n"
            "}\n")

c2_obj = t.wpath("stdio.obj")
subprocess.run([CLANG_CL, "/c", "/O1", "/Fo:" + c2_obj, c2_src],
               capture_output=True, text=True)
if not os.path.isfile(c2_obj):
    print("FALLO: clang-cl no produjo el objeto de stdio")
    rc = 1
else:
    with open(c2_obj, "rb") as f:
        dir2 = f.read()
    if b"/DEFAULTLIB:ucrt" in dir2:
        print("  (el objeto ya pide la UCRT por si mismo: este caso no probaria"
              " el segundo nivel)")
    exe2 = t.wpath("profundo.exe")
    p2 = subprocess.run([t.vm, "--link", c2_obj, vx_obj, "-o", exe2,
                         "--format", "pe"], capture_output=True, text=True)
    if not os.path.isfile(exe2):
        print("FALLO: no se enlazo el caso de segundo nivel: "
              + ((p2.stdout or "") + (p2.stderr or "")).strip()[:300])
        rc = 1
    else:
        with open(exe2, "rb") as f:
            img2 = f.read()
        if b"ucrtbase.dll" not in img2 and b"api-ms-win-crt" not in img2:
            print("FALLO: no hay rastro de la UCRT -- la directiva de un "
                  "miembro del archivo no se atendio")
            rc = 1
        else:
            print("  la biblioteca que pidio un MIEMBRO del archivo tambien se "
                  "resolvio")

if rc:
    t.fail("=== msvc_drectve_test: FALLOS ===")
t.finish()
