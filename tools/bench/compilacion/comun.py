#!/usr/bin/env python3
"""Lo que comparten todos los modulos del banco de compilacion.

Aqui vive lo que no pertenece a ninguna etapa concreta: que compilador de C se
eligio, el color de cada lenguaje y el atajo para importar las utilidades del
arnes de ejecucion.  Va aparte para que un modulo que solo genera fuentes no
tenga que saber nada de terminales ni de estadistica.
"""
from __future__ import annotations

import sys
from pathlib import Path

# El arnes de ejecucion vive en el directorio de arriba y ya trae medido lo que
# aqui hace falta (colores, indicador de progreso, resumen estadistico).
# Duplicarlo daria dos definiciones de "mediana" que podrian separarse.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from run_all_benches import (  # noqa: E402
    C,
    Spinner,
    _stats_summary,
    buscar_compiladores,
    elegir_compilador,
    find_project_root,
    find_vm_candidates,
    get_tool_version,
    prompt_choose_vm,
    serie_asentada,
    una_medida,
)

__all__ = [
    "C", "Spinner", "_stats_summary", "buscar_compiladores",
    "elegir_compilador", "find_project_root", "find_vm_candidates",
    "get_tool_version", "prompt_choose_vm", "serie_asentada", "una_medida",
    "ELEGIDO", "COLOR_LANG", "color_de",
]

# Cual de los compiladores instalados se usa.  Se decide UNA vez al arrancar y
# todas las ordenes lo consultan: tener gcc y clang a la vez es lo normal, y
# coger a ciegas el primero del PATH etiquetaria como gcc un numero que produjo
# clang.
ELEGIDO = {"c": "gcc", "cpp": "g++"}

# Un color por lenguaje, el MISMO que usa el banco de ejecucion: las dos tandas
# se leen a menudo una al lado de la otra, y que C sea azul aqui y verde alli
# obliga a releer la etiqueta en cada fila.
COLOR_LANG = {
    "c": C.BLUE,
    "cpp": C.MAGENTA,
    "rust": C.RUST,
    "go": C.TEAL,
    "java": C.RED,
    "nim": C.YELLOW,
    "python": C.CYAN,
    "vesta": C.GREEN,
    "vesta_aot": C.ORANGE,
}


def color_de(lang: str) -> str:
    """Color del lenguaje, o ninguno si no es uno de los conocidos."""
    return COLOR_LANG.get(lang, "")
