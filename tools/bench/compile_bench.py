#!/usr/bin/env python3
"""Cuanto tarda cada lenguaje en COMPILAR, y cuanto le sirve su cache.

Es un modulo aparte de `run_all_benches.py` a proposito.  Medir la ejecucion y
medir la compilacion se parecen solo en que ambos cronometran un proceso: el
modelo de ruido, el de cache y hasta lo que significa "en frio" son distintos, y
mezclarlos en el mismo bucle acaba en un arnes que hace mal las dos cosas.

Lo que se mide, y por que son varios ejes y no uno:

  frio          Sin ninguna cache: ni la del compilador ni la del sistema.  Es
                lo que paga quien clona el repositorio y compila por primera
                vez.  Definirlo bien es la mitad del trabajo, porque cada
                herramienta guarda su cache en un sitio distinto y "frio" para
                una puede ser "caliente" para otra.

  incremental   Con las caches ya calientes y UN fichero tocado.  Es el numero
                que se paga cien veces al dia.  Solo significa algo en un
                proyecto de varios modulos: en un fichero suelto no hay nada
                que reconstruir incrementalmente.

  crecimiento   Como cambia el tiempo al crecer el codigo, en los dos
                regimenes.  Un solo tamano no distingue lineal de cuadratico, y
                esa diferencia es la que decide si un proyecto grande sera
                usable.

  realimentacion  Cuanto tarda el programador en VER el error.  No es una
                compilacion: no genera codigo ni enlaza.  Cada lenguaje lo hace
                con un comando distinto y hay que decirlo, porque comparar un
                `-fsyntax-only` contra un enlazado completo no compara nada.

Y una advertencia que este banco existe para no repetir.  Medido en esta
maquina, compilar uno de los benchmarks del corpus -- 40 lineas -- cuesta lo
MISMO que compilar un fichero vacio: 104 ms contra 107 en gcc, 133 contra 135 en
rustc, 313 contra 306 en javac.  Entre el 94% y el 103% de ese tiempo es
arrancar el compilador.  Por eso aqui las fuentes se GENERAN con un tamano
controlado: para que haya algo que compilar.  Y por eso se mide y se resta el
suelo de cada herramienta.

El banco esta partido en modulos (ver `compilacion/`).  Aqui solo quedan los
argumentos, la eleccion de herramientas y el bucle que corre las fases.

Ejemplos:

    python tools/bench/compile_bench.py                    # las de por defecto
    python tools/bench/compile_bench.py --listar-fases
    python tools/bench/compile_bench.py --fase dependencias # solo esa
    python tools/bench/compile_bench.py --fase crecimiento --lineas 1500,6000,24000
    python tools/bench/compile_bench.py --fase todas
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from compilacion.comun import (  # noqa: E402
    C,
    ELEGIDO,
    buscar_compiladores,
    elegir_compilador,
    find_project_root,
    find_vm_candidates,
    prompt_choose_vm,
)
from compilacion.comun import get_tool_version  # noqa: E402
from compilacion import entorno  # noqa: E402
from compilacion.contexto import Ctx  # noqa: E402
from compilacion.fases import FASES, seleccionar  # noqa: E402
from compilacion.generadores import GENERADORES  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("vm_path", nargs="?", default="")
    p.add_argument("--fase", type=str, default="",
                   help="que fases correr, separadas por comas (ver "
                        "--listar-fases).  `todas` las corre todas.  Vacio = "
                        "las de por defecto, que dejan fuera las mas largas.")
    p.add_argument("--listar-fases", action="store_true",
                   help="enseña las fases que hay y termina.")
    p.add_argument("--tamanos", type=str, default="1500,6000,24000",
                   help="tamanos EN LINEAS de codigo.  En lineas y no en "
                        "funciones porque cada lenguaje escribe un numero "
                        "distinto de lineas por funcion, y pedir lo mismo en "
                        "funciones hacia que unos compilaran 6k lineas y "
                        "otros 5k -- que no es una comparacion.  Cada fila "
                        "publica las lineas que de verdad compilo.  MISMA "
                        "lista que `--lineas` a proposito: las figuras "
                        "monoliticas y las repartidas se leen por parejas, y "
                        "con bases distintas la pareja no compara nada.")
    p.add_argument("--lineas", type=str, default="1500,6000,24000",
                   help="tamanos EN LINEAS para la fase de crecimiento.  Se "
                        "piden en lineas y no en funciones porque cada "
                        "lenguaje escribe un numero distinto de lineas por "
                        "funcion, y comparar 'mil funciones' seria comparar "
                        "programas de tamanos distintos.")
    p.add_argument("--grande", action="store_true",
                   help="anade un cuarto tamano de 80k lineas a `--tamanos` y "
                        "`--lineas`.  Es el punto que convierte los cruces "
                        "entre lenguajes en MEDIDA en vez de extrapolacion: "
                        "sin el, los interesantes (~31k con rustc, ~65k con "
                        "Go) caen fuera de lo medido.  No va por defecto "
                        "porque multiplica lo que tarda la tanda.")
    p.add_argument("--paralelismo", type=str, default="ambos",
                   choices=("secuencial", "maquina", "ambos"),
                   help="que ejes correr en las fases de varios modulos.  "
                        "`secuencial` pone a todos a un hilo y mide la "
                        "eficiencia del compilador; `maquina` deja a cada uno "
                        "usar la maquina (Vesta con su paralelismo "
                        "automatico, `make -j`, `go build -p N`) y mide lo "
                        "que sufre el usuario.  `ambos` (por defecto) publica "
                        "los dos: su distancia es cuanto aprovecha cada "
                        "herramienta la maquina, que no se veia en ningun "
                        "sitio.  Comparar los ocho hilos de Vesta contra una "
                        "invocacion secuencial de gcc no era falso, pero "
                        "tampoco se estaba diciendo.")
    p.add_argument("--sin-graficas", action="store_true",
                   help="no generar las graficas del banco.")
    p.add_argument("--jobs", type=int, default=0,
                   help="compilaciones de VERIFICACION en paralelo "
                        "(default: nucleos - 2).  Las MEDIDAS siguen "
                        "secuenciales siempre: paralelizarlas mediria la "
                        "carga de la maquina, no el compilador.")
    p.add_argument("--cc", type=str, default="",
                   help="compilador de C a usar.  Sin esto: si hay varios "
                        "instalados se pregunta.")
    p.add_argument("--cxx", type=str, default="",
                   help="compilador de C++ a usar.")
    p.add_argument("--escalado", action="store_true",
                   help="atajo antiguo para pedir la fase `escalado`.  Hoy no "
                        "hace falta: TODAS las fases van por defecto (ver "
                        "`fases/__init__.py`).  Se mantiene para no romper "
                        "guiones que ya lo usan.")
    p.add_argument("--ficheros", type=int, default=20,
                   help="en cuantos ficheros se reparte el programa para la "
                        "comparacion mono/multi (default 20)")
    p.add_argument("--repes", type=int, default=5,
                   help="medidas por caso (default 5)")
    p.add_argument("--timeout", type=float, default=600.0)
    p.add_argument("--langs", type=str, default="",
                   help="lista separada por comas; vacio = todos")
    # Con destino por defecto, como el banco de ejecucion: una tanda que tarda
    # minutos y no deja nada escrito obliga a repetirla para comparar, y a
    # nadie se le ocurre pedir el fichero ANTES de ver si el resultado
    # interesa.  Relativo = junto a la raiz del proyecto.
    p.add_argument("--out-json", type=str, default="bench_compilacion.json")
    args = p.parse_args()

    if args.listar_fases:
        print(f"{C.BOLD}Fases del banco de compilacion{C.RESET}")
        for f in FASES:
            marca = "  " if f.por_defecto else f"{C.DIM}*{C.RESET} "
            print(f"  {marca}{C.BOLD}{f.id:<18}{C.RESET}{f.titulo}")
        print(f"\n{C.DIM}  Todas corren por defecto.  Para una sola:\n"
              f"    --fase dependencias   |   --fase arranque,caudal   |   "
              f"--fase todas\n"
              f"  Los nombres viejos (1, 2, 2b, 2c...) siguen valiendo: "
              f"renombrar no puede romper un guion que ya existe.{C.RESET}")
        return 0

    raiz = find_project_root(Path(__file__).resolve())
    # Que instancia de Vesta se mide.  Igual que el banco de ejecucion: si hay
    # varias construcciones (release, debug, la del PATH) se pregunta, porque
    # medir la equivocada da numeros que no significan nada y no se nota.
    if args.vm_path:
        vm = Path(args.vm_path)
        if not vm.is_file():
            print(f"{C.RED}[error]{C.RESET} no encuentro el binario vesta: {vm}")
            return 1
    else:
        vm = prompt_choose_vm(find_vm_candidates(raiz))

    # Sin `--langs`, se usan todos los que ESTeN instalados.  Pedidos a mano,
    # se respetan aunque falten: si alguien nombra una herramienta que no
    # tiene, lo que quiere es enterarse, no que se le ignore en silencio.
    n_c, r_c = elegir_compilador(
        "C", buscar_compiladores(["gcc", "clang", "cc"]), args.cc)
    n_cpp, r_cpp = elegir_compilador(
        "C++", buscar_compiladores(["g++", "clang++", "c++"]), args.cxx)
    if r_c:
        ELEGIDO["c"] = r_c
    if r_cpp:
        ELEGIDO["cpp"] = r_cpp

    herramienta = {"c": r_c or "gcc", "cpp": r_cpp or "g++",
                   "rust": "rustc", "go": "go", "java": "javac",
                   "nim": "nim", "python": sys.executable}
    if args.langs:
        langs = [l.strip() for l in args.langs.split(",") if l.strip()]
    else:
        langs = []
        ausentes = []
        for ln in GENERADORES:
            h = herramienta.get(ln)
            if h is None or shutil.which(h) or Path(h).is_file():
                langs.append(ln)
            else:
                ausentes.append("%s (%s)" % (ln, h))
        if ausentes:
            print(f"{C.YELLOW}[aviso]{C.RESET} sin instalar, se omiten: "
                  + ", ".join(ausentes))

    # `--escalado` es anterior a `--fase` y se mantiene: era la forma de pedir
    # esa fase y romperla obligaria a cambiar guiones que ya existen.
    pedidas = args.fase
    if args.escalado and "2bis" not in pedidas:
        pedidas = (pedidas + ",2bis") if pedidas else "2bis"
    fases = seleccionar(pedidas)
    if not fases:
        print(f"{C.RED}[error]{C.RESET} ninguna fase que correr.")
        return 1

    base_tmp = Path(os.environ.get("TEMP", "/tmp")) / "vesta_compile_bench"
    shutil.rmtree(base_tmp, ignore_errors=True)
    base_tmp.mkdir(parents=True, exist_ok=True)
    # `--grande` se aplica a las DOS listas: si solo entrara en una, las
    # figuras monoliticas y las repartidas volverian a apoyarse en bases
    # distintas, que es justo lo que igualar los tamanos vino a arreglar.
    GRANDE = 80000
    tamanos = [int(t) for t in args.tamanos.split(",") if t.strip()]
    lineas = [int(t) for t in args.lineas.split(",") if t.strip()]
    if args.grande:
        if GRANDE not in tamanos:
            tamanos.append(GRANDE)
        if GRANDE not in lineas:
            lineas.append(GRANDE)
        args.lineas = ",".join(str(x) for x in lineas)
    ctx = Ctx(
        args=args, vm=vm, raiz=raiz, langs=langs,
        tamanos=tamanos,
        jobs=args.jobs if args.jobs > 0 else max(1, (os.cpu_count() or 4) - 2),
        base_tmp=base_tmp, dir_cache=base_tmp / "_cache",
        entorno_base=dict(os.environ),
    )
    # DONDE se mide, antes de medir nada.  Va al JSON entero y al terminal
    # resumido: sin esto, dos tandas de maquinas distintas dan ficheros
    # indistinguibles y no hay forma de saberlo despues.
    ctx.resultados["entorno"] = entorno.recoger(
        vm, raiz, base_tmp, herramienta, get_tool_version)

    print(f"{C.BOLD}Tiempos de compilacion{C.RESET}")
    print(f"{C.DIM}  fuentes generadas en {base_tmp}{C.RESET}")
    print(f"{C.DIM}  {entorno.resumen(ctx.resultados['entorno'])}{C.RESET}")
    print(f"{C.DIM}  fases: {', '.join(f.id for f in fases)}{C.RESET}")

    # El suelo lo descuentan casi todas las demas.  Si no se pidio, se avisa en
    # vez de publicar restas contra un cero: una columna `sin arranque` que en
    # realidad es el tiempo entero se lee como si fuera neto y enganaria.
    if not any(f.id == "1" for f in fases) and len(fases) < len(FASES):
        print(f"{C.YELLOW}[aviso]{C.RESET} sin la fase 1 no hay suelo que "
              f"descontar: la columna 'sin arranque' saldra vacia.")

    # Las librerias de dibujo se comprueban AHORA, no al dibujar.  Enterarse de
    # que faltan cuando la tanda ya ha terminado no sirve de nada: hay que
    # instalarlas y volver a medirlo todo.  Aqui todavia se esta a tiempo de
    # cortar con Ctrl-C, instalar y relanzar sin haber gastado nada.
    if not args.sin_graficas:
        from compilacion import graficas  # noqa: E402
        falta = graficas.diagnostico_dependencias()
        if falta:
            print(f"{C.YELLOW}[aviso]{C.RESET} {falta}")
            print(f"{C.DIM}         La tanda sigue y el JSON se escribe igual; "
                  f"lo unico que no habra son las graficas.  Con "
                  f"`--sin-graficas` este aviso no sale.{C.RESET}")

    for f in fases:
        f.fn(ctx)

    # Ruta absoluta o, si es relativa, junto a la raiz del proyecto: lanzar el
    # banco desde otro directorio no deberia dejar el JSON en un sitio distinto
    # cada vez.
    ruta_json = (Path(args.out_json) if os.path.isabs(args.out_json)
                 else raiz / args.out_json)

    if not args.sin_graficas:
        try:
            from compilacion import graficas  # noqa: E402
            destino = ruta_json.parent / "bench_plots_compilacion"
            hechas = graficas.dibujar(ctx.resultados, destino)
            print()
            if hechas:
                print(f"{C.GREEN}[ok]{C.RESET} graficas: {destino}")
                for k in sorted(hechas):
                    print("  ", k)
            else:
                # Cero figuras CON las librerias puestas solo puede ser que los
                # datos no dan para ninguna.  Antes esto no imprimia nada y era
                # indistinguible de "el banco no dibuja graficas".
                print(f"{C.YELLOW}[aviso]{C.RESET} ninguna grafica: las fases "
                      f"que corrieron no dejaron datos suficientes.  Cada "
                      f"figura necesita al menos dos tamanos de su fase.")
        except Exception as e:  # noqa: BLE001
            print()
            print(f"{C.YELLOW}[aviso]{C.RESET} no pude generar graficas: {e}")

    ruta_json.parent.mkdir(parents=True, exist_ok=True)
    ruta_json.write_text(json.dumps(ctx.resultados, indent=2), encoding="utf-8")
    print()
    print(f"{C.GREEN}[ok]{C.RESET} JSON: {ruta_json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
