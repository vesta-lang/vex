#!/usr/bin/env python3
"""Mide el CODIGO que sale de compilar, no lo que tarda en correr.

    python tools/bench/codegen_size.py <build> [-o salida.json] [-k patron] [-j N]

Compila cada ejemplo a binario nativo y anota cuanto ocupan sus secciones: el
codigo por un lado y los datos por otro, que mezclados esconden de que fue el
cambio.  Sale en el formato que lee `compare_json.py`, asi que la comparacion
contra una referencia -- media geometrica, umbral del cinco por ciento -- ya
esta hecha:

    python tools/bench/codegen_size.py cmake-build-release -o antes.json
    ...cambiar algo...
    python tools/bench/codegen_size.py cmake-build-release -o despues.json
    python tools/bench/compare_json.py antes.json despues.json

Por que esto y no un cronometro: medir el binario ENTERO desde fuera no sirve
para detectar una regresion en un programa pequenyo.  Medido en esta maquina,
un hola mundo da +-90% de dispersion en tiempo de pared, y el arranque del
proceso -- unos 6,2 millones de ciclos -- tapa por completo lo que el programa
hace: un programa que no hace NADA y uno vectorizado miden lo mismo.  El
tamanyo del codigo, en cambio, es exacto y no tiene ruido: dos compilaciones
del mismo fuente dan el MISMO numero.

No detecta una regresion que no cambie el codigo emitido -- peor localidad, por
ejemplo --.  Para eso hace falta medir por dentro; esto es la parte que se
puede tener sin ruido.
"""

import argparse
import concurrent.futures
import json
import os

import subprocess
import sys

RAIZ = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EJEMPLOS = os.path.join(RAIZ, "examples_codes_vx")

def _secciones_pe(ruta):
    """Tamanyo REAL de cada seccion de un PE, por nombre.

    Se lee del fichero en vez de desensamblarlo por dos motivos.  El
    desensamblado no cubre el binario entero -- sobre uno de 15 KB devuelve
    cuarenta y cuatro lineas --, asi que contar instrucciones mediria un trozo
    arbitrario.  Y el tamanyo del FICHERO va en multiplos de 512, asi que dos
    programas distintos dan el mismo numero y un cambio pequenyo no se ve.

    Se usa @c VirtualSize y no @c SizeOfRawData: el segundo esta redondeado al
    alineamiento del fichero y volveria a esconder los cambios pequenyos.
    """
    try:
        with open(ruta, "rb") as fh:
            datos = fh.read()
    except OSError:
        return {}
    if len(datos) < 0x40 or datos[:2] != b"MZ":
        return {}
    pe = int.from_bytes(datos[0x3C:0x40], "little")
    if pe + 24 > len(datos) or datos[pe:pe + 4] != b"PE\0\0":
        return {}
    n_secs = int.from_bytes(datos[pe + 6:pe + 8], "little")
    tam_opt = int.from_bytes(datos[pe + 20:pe + 22], "little")
    base = pe + 24 + tam_opt
    out = {}
    for i in range(n_secs):
        sh = base + i * 40
        if sh + 40 > len(datos):
            break
        nombre = datos[sh:sh + 8].rstrip(b"\0").decode("latin-1")
        out[nombre] = int.from_bytes(datos[sh + 8:sh + 12], "little")
    return out


def _medir(vm, fuente, tmp_dir):
    """Compila un ejemplo a nativo y devuelve sus numeros, o None si no compila.

    Que un ejemplo no compile a nativo NO es un fallo de esto: hay ejemplos que
    piden runtime y solo corren en la maquina virtual.  Se omiten, y el
    contador de omitidos se imprime al final para que no pasen por medidos.
    """
    nombre = os.path.splitext(os.path.basename(fuente))[0]
    salida = os.path.join(tmp_dir, nombre + ".exe")
    try:
        r = subprocess.run(
            [vm, "-m", "aot", "--vesta", fuente, "--format", "pe", "--emit",
             "exe", "-o", salida],
            capture_output=True, text=True, timeout=300)
    except (subprocess.TimeoutExpired, OSError):
        return None
    if r.returncode != 0 or not os.path.exists(salida):
        return None

    fila = {"bench": nombre}
    secs = _secciones_pe(salida)
    # `.text` es lo que de verdad dice si el generador de codigo empeoro; el
    # resto de secciones se anotan porque un cambio ahi tambien cuenta (mas
    # datos constantes, mas tabla de importaciones), pero por separado: mezclar
    # codigo y datos en un solo numero esconde de que fue el cambio.
    for clave, valor in (("vx_text", secs.get(".text")),
                         ("vx_rodata", secs.get(".rdata") or secs.get(".rodata")),
                         ("vx_data", secs.get(".data"))):
        if valor:
            fila[clave] = valor
    if len(fila) == 1:
        # Sin secciones legibles no hay medida; decirlo es mejor que anotar el
        # tamanyo del fichero y que parezca fina una medida de 512 en 512.
        return None
    return fila


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("build", help="directorio del build (con vm/vm.exe)")
    ap.add_argument("-o", "--salida", default="codegen_size.json")
    ap.add_argument("-k", "--filtro", default="",
                    help="subcadena para quedarse solo con unos ejemplos")
    ap.add_argument("-j", "--trabajos", type=int, default=4)
    args = ap.parse_args()

    vm = os.path.join(RAIZ, args.build, "vm.exe")
    if not os.path.exists(vm):
        vm = os.path.join(RAIZ, args.build, "vm")
    if not os.path.exists(vm):
        print("no encuentro el binario en " + args.build, file=sys.stderr)
        return 2

    fuentes = sorted(
        os.path.join(EJEMPLOS, f) for f in os.listdir(EJEMPLOS)
        if f.endswith(".vx") and (not args.filtro or args.filtro in f))
    if not fuentes:
        print("ningun ejemplo casa con el filtro", file=sys.stderr)
        return 2

    tmp_dir = os.path.join(RAIZ, ".codegen_size_tmp")
    os.makedirs(tmp_dir, exist_ok=True)

    filas = []
    with concurrent.futures.ThreadPoolExecutor(args.trabajos) as pool:
        for fila in pool.map(lambda f: _medir(vm, f, tmp_dir), fuentes):
            if fila:
                filas.append(fila)

    filas.sort(key=lambda f: f["bench"])
    with open(args.salida, "w", encoding="utf-8") as fh:
        json.dump({"results": filas}, fh, indent=1)

    omitidos = len(fuentes) - len(filas)
    print("%d medidos, %d omitidos (no compilan a nativo) -> %s"
          % (len(filas), omitidos, args.salida))
    return 0


if __name__ == "__main__":
    sys.exit(main())
