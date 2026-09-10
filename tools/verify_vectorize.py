#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify_vectorize.py -- Afirma que cada forma de bucle SIGUE ensanchandose.

Aqui un fallo NO SE VE: un bucle que deja de reconocerse se baja de uno en uno,
da exactamente el mismo numero, y cualquier test que compare resultados pasa
igual -- solo que el programa va mas lento.

Es una comprobacion ABSOLUTA, y por eso los minimos estan escritos en este
fichero.  Ver que cambio en lo emitido ya lo hace `tools/ir_snapshot.py`, que
compara dos fotos del IR; pero comparar no basta para esto, porque si algo se
rompe y luego se vuelve a fotografiar, la rotura se convierte en la referencia
y no salta nunca mas.  Y medir lo rapido que va ya lo hace
`tools/bench_vectorize.py`.  Esto responde a la tercera pregunta, que ninguna
de las dos responde: sigue ocurriendo?

Lo que comprueba son las funciones de `std.numeric`, no bucles escritos para el
test.  La libreria ES la escritura canonica de cada forma y es lo que un
programa de verdad llama, asi que es lo que tiene que seguir ensanchandose; un
bucle escrito aparte solo para el test puede seguir disparando mientras la
libreria deja de hacerlo.

Uso:  python tools/verify_vectorize.py [--build-dir cmake-build-release]
"""

import argparse
import os
import re
import shutil
import subprocess
import sys

# Instrucciones que operan varios carriles a la vez.  OJO: las ETIQUETAS de los
# bloques que monta el vectorizador se llaman igual (vec_main_hdr_3:), asi que
# no vale con buscar la cadena "vec_" -- hay que exigir que sea una
# instruccion, o sea que abra la linea y que el opcode este en esta lista.
WIDE_OPS = ("binop", "binop_s", "unop", "bcast",
            "acc_zero", "acc_add", "acc_combine", "acc_store", "acc_fma")

RE_FUNC = re.compile(r"^(?:@function|function|func)\s+([A-Za-z_][A-Za-z_0-9]*)")
RE_WIDE = re.compile(r"^[ \t]*vec_(?:%s)[ \t]" % "|".join(WIDE_OPS))
# memcpy/memset: cuando el bucle era una copia o un relleno, el mejor resultado
# NO es ensancharlo sino que desaparezca entero y quede una sola instruccion de
# bloque.  Contar eso como cero seria leerlo justo al reves.
RE_BULK = re.compile(r"^[ \t]*(?:memcpy|memset)[ \t]")

# Los dos ejemplos que se compilan, y de donde sale cada expectativa.
SOURCES = ("493_std_numeric.vx", "492_vectorizador_completo.vx")

# Instancias de la libreria que TIENEN que ensancharse.
#
# Que el tipo este en el nombre no es un detalle: el ancho del elemento decide
# cuantos carriles caben, asi que cada uno toma un camino distinto y hay que
# fijarlos por separado.
LIBRARY_MUST_WIDEN = (
    "add_i64", "add_i32", "add_f32", "add_f64",
    "sub_i64",
    "mul_i32", "mul_i16", "mul_f32", "mul_f64",
    "div_f32", "div_f64",
    # El reparto de un escalar en f32 estuvo bajando de uno en uno y daba el
    # mismo numero, asi que nada lo delataba.  Va fijado por eso.
    "add_scalar_i64", "add_scalar_f32",
    "mul_scalar_i32", "mul_scalar_f32",
    "add_into_i64", "sub_into_i64", "sub_into_i8",
    # Negar: los dos extremos de ancho y uno de cada familia.
    "negate_f64", "negate_f32", "negate_i64", "negate_i32", "negate_i16",
    "negate_i8",
    "sum_i64", "sum_u32", "sum_f32", "sum_f64",
)

# La copia no se ensancha: se reconoce que el bucle entero es un movimiento de
# bloque y queda UNA instruccion, que es mejor.  Su sitio en la libreria es
# std.memory, no std.numeric, asi que se comprueba con los bucles a mano de 492.
RAW_MUST_BULK = ("copy_while", "copy_for")

# Y las formas que HOY no se reconocen.  Se fijan igual que las demas: si
# alguna empieza a ensancharse sera porque alguien lo hizo a proposito, y
# entonces esta lista es la que hay que mover.
# Formas escritas a mano que SI se ensanchan y que la libreria no cubre.
#
# Una cadena de operaciones sobre el mismo elemento no cabe en una funcion de
# libreria: `std.numeric` da una operacion por llamada, y encadenarlas
# escribiendo el array intermedio seria peor que escribir el bucle.
RAW_MUST_WIDEN = ("chain",)

# Y las formas que HOY no se reconocen.  Se fijan igual que las demas: si
# alguna empieza a ensancharse sera porque alguien lo hizo a proposito, y
# entonces esta lista es la que hay que mover.
RAW_MUST_NOT_WIDEN = (
    # Producto de 64 bits: solo existe empaquetado con AVX-512DQ, y el
    # generador de codigo aun no emite esa instruccion.
    "scalar_i64",
)


def run(cmd, timeout=900):
    """Ejecuta un comando y devuelve (codigo, salida combinada)."""
    try:
        p = subprocess.run(cmd, timeout=timeout,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return p.returncode, p.stdout.decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return -1, "(agotado el tiempo)"


def count_by_function(ir_path):
    """Cuenta, por funcion, las instrucciones anchas y las de bloque.

    @param ir_path Fichero con el volcado del IR.
    @return dict nombre -> (anchas, bloque).
    """
    out = {}
    if not os.path.exists(ir_path):
        return out
    current = ""
    with open(ir_path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = RE_FUNC.match(line)
            if m:
                current = m.group(1)
                out.setdefault(current, [0, 0])
                continue
            if not current:
                continue
            if RE_WIDE.match(line):
                out[current][0] += 1
            elif RE_BULK.match(line):
                out[current][1] += 1
    return {k: tuple(v) for k, v in out.items()}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--build-dir", default="cmake-build-release")
    args = ap.parse_args()

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    vm = ""
    for name in ("vm.exe", "vm"):
        p = os.path.join(root, args.build_dir, name)
        if os.path.exists(p):
            vm = p
            break
    if not vm:
        sys.stderr.write("no encuentro el binario en %s -- compila primero\n"
                         % args.build_dir)
        return 2

    work = os.path.join(os.environ.get("TEMP", "/tmp"), "vecverify")
    os.makedirs(work, exist_ok=True)

    # Se mide en CADA arquitectura que el compilador sabe targetear, no solo en
    # la de quien compila.  Que una forma se reconozca no deberia depender del
    # objetivo -- la decision se toma sobre el IR, que es comun -- y esa es
    # justamente la afirmacion que hay que comprobar, no dar por buena: el dia
    # que una de las dos deje de reconocer algo, se ve aqui y no en la maquina
    # de quien lo sufra.
    objetivos = [("del compilador", []),
                 ("aarch64", ["-m", "aot", "--aot-arch", "aarch64",
                              "--format", "elf", "--emit", "obj"])]
    por_objetivo = {}
    for etiqueta, extra in objetivos:
        counts = {}
        for name in SOURCES:
            src = os.path.join(root, "examples_codes_vx", name)
            if not os.path.exists(src):
                sys.stderr.write("falta %s\n" % src)
                return 2
            # Las caches se tiran para que lo que se mide se genere de verdad.
            shutil.rmtree(os.path.join(root, ".cache"), ignore_errors=True)
            base = os.path.join(work,
                                os.path.splitext(name)[0] + "_" +
                                etiqueta.replace(" ", "_"))
            run([vm] + extra + ["--vx-emit-ir", "--vesta", src, "-o", base])
            if not os.path.exists(base + ".ir"):
                sys.stderr.write("no se genero el IR de %s (%s)\n"
                                 % (name, etiqueta))
                return 2
            counts.update(count_by_function(base + ".ir"))
        por_objetivo[etiqueta] = counts
    counts = por_objetivo["del compilador"]

    # El IR trae los nombres cualificados; aqui se buscan por el corto, que es
    # como se escriben en las listas de arriba.
    def find(short):
        for full, v in counts.items():
            if full == short or full.endswith("__" + short):
                return v
        return (0, 0)

    bad = 0
    for short in LIBRARY_MUST_WIDEN:
        wide, _ = find(short)
        if wide < 1:
            print("DEJO DE ENSANCHAR: std.numeric.%s" % short)
            bad += 1
        else:
            print("  ok  std.numeric  %-18s anchas=%d" % (short, wide))
    for short in RAW_MUST_WIDEN:
        wide, _ = find(short)
        if wide < 1:
            print("DEJO DE ENSANCHAR: %s (escrito a mano)" % short)
            bad += 1
        else:
            print("  ok  a mano       %-18s anchas=%d" % (short, wide))
    for short in RAW_MUST_BULK:
        _, bulk = find(short)
        if bulk < 1:
            print("DEJO DE SER UNA COPIA DE BLOQUE: %s" % short)
            bad += 1
        else:
            print("  ok  copia        %-18s bloque=%d" % (short, bulk))
    for short in RAW_MUST_NOT_WIDEN:
        wide, _ = find(short)
        if wide > 0:
            print("EMPEZO A ENSANCHARSE: %s (anchas=%d).  Si es a proposito,"
                  " muevelo a LIBRARY_MUST_WIDEN." % (short, wide))
            bad += 1
        else:
            print("  ok  limite       %-18s anchas=0 (documentado)" % short)

    # Y que los programas SIGAN CORRIENDO.  Contar instrucciones del IR no dice
    # que el codigo sea correcto: una arista mal puesta da un bucle que no
    # termina, y el conteo sale idéntico porque las instrucciones estan todas.
    # Paso justamente por eso: este arnes decia "todo bien" mientras el
    # programa se colgaba.
    for name in SOURCES:
        src = os.path.join(root, "examples_codes_vx", name)
        base = os.path.join(work, os.path.splitext(name)[0] + "_run")
        shutil.rmtree(os.path.join(root, ".cache"), ignore_errors=True)
        run([vm, "--vesta", src, "-o", base], timeout=300)
        velb = base + ".velb"
        if not os.path.exists(velb):
            print("NO COMPILA: %s" % name)
            bad += 1
            continue
        rc, out = run([vm, "--run", velb, "--stats"], timeout=120)
        m = re.search(r"R00=0x0*([0-9a-f]+)", out)
        got = int(m.group(1), 16) if m else -1
        if rc != 0 or got != 42:
            print("NO DEVUELVE 42: %s (R00=%s)" % (name, got))
            bad += 1
        else:
            print("  ok  ejecuta     %-18s R00=42" % os.path.splitext(name)[0])

    # Y que las dos arquitecturas reconozcan LO MISMO.  Si un dia dejan de
    # coincidir puede ser deliberado -- una maquina tiene una instruccion que la
    # otra no --, pero tiene que verse y decidirse, no ocurrir sin que nadie se
    # entere.
    otro = por_objetivo.get("aarch64", {})
    for nombre, (wide, bulk) in sorted(counts.items()):
        if not nombre.startswith(("std__numeric__",
                                  "ejemplos__vectorizador_completo__")):
            continue
        w2, b2 = otro.get(nombre, (-1, -1))
        if (w2, b2) != (wide, bulk):
            print("DIFIERE POR ARQUITECTURA: %s -- aqui anchas=%d bloque=%d,"
                  " en aarch64 anchas=%d bloque=%d"
                  % (nombre, wide, bulk, w2, b2))
            bad += 1
    if bad == 0:
        print("  ok  aarch64      reconoce exactamente lo mismo")

    if bad == 0:
        print("todas las formas siguen como estaban, y los programas corren.")
        return 0
    print("")
    print("%d formas cambiaron.  El programa sigue dando el mismo numero -- por"
          " eso hace falta mirar esto y no la salida." % bad)
    return 1


if __name__ == "__main__":
    sys.exit(main())
