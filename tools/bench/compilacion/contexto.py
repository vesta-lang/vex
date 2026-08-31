#!/usr/bin/env python3
"""Lo que comparten las fases, y que es una fase.

Antes el banco era un `main()` de setecientas lineas con las ocho fases una
detras de otra.  Eso tenia dos consecuencias practicas: no se podia correr una
sola -- y la tanda entera son muchos minutos, asi que comprobar un cambio en la
ultima obligaba a pasar por todas --, y anadir una fase era intercalar codigo
en mitad de ese bloque.

Ahora cada fase es una funcion que recibe este contexto.  Anadir una es
escribir la funcion y ponerla en el registro; correr solo una es `--fase 2c`.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from .generadores import GENERADORES


@dataclass
class Ctx:
    """Todo lo que las fases comparten.

    Se pasa entero en vez de por parametros sueltos porque cada fase usa cosas
    distintas y la lista cambiaria al anadir la siguiente.
    """

    args: argparse.Namespace
    vm: Path
    raiz: Path
    langs: list[str]
    tamanos: list[int]
    jobs: int
    base_tmp: Path
    dir_cache: Path
    entorno_base: dict
    suelo: dict = field(default_factory=dict)
    # El mismo suelo, pero sin cache.  Es OTRO numero -- el arranque tambien
    # se paga distinto en frio -- y restar el que no toca falsea la curva de
    # crecimiento.
    suelo_frio: dict = field(default_factory=dict)
    resultados: dict = field(default_factory=dict)

    @property
    def ejes(self) -> list[str]:
        """Los ejes de paralelismo que hay que correr, en orden.

        Vive aqui y no en cada fase porque las cuatro que compilan varios
        modulos tienen que estar de acuerdo: si una publica el eje `maquina` y
        otra el `secuencial` sin decirlo, sus tablas dejan de poder leerse
        juntas.
        """
        from .ordenes import MAQUINA, SECUENCIAL
        pedido = getattr(self.args, "paralelismo", "ambos")
        if pedido == "ambos":
            return [SECUENCIAL, MAQUINA]
        return [pedido]

    @property
    def nucleos(self) -> int:
        """Cuantos hilos se le conceden a una herramienta en el eje `maquina`.

        El mismo tope que usa el compilador Vesta por su cuenta (8): darle mas
        a `make -j` seria concederle a C una maquina que a Vesta no se le da.
        """
        import os
        return max(1, min(8, os.cpu_count() or 1))

    def __post_init__(self) -> None:
        # `suelo` es el MISMO objeto dentro de los resultados: las fases lo
        # rellenan segun miden y el JSON tiene que ver lo ultimo, no una foto
        # vacia tomada al arrancar.
        self.resultados.setdefault("casos", [])
        self.resultados["suelo"] = self.suelo
        # El de frio tambien: las graficas que restan el arranque necesitan el
        # que toca en cada regimen, y restar el caliente a una medida en frio
        # deja dentro la parte que solo se paga sin cache -- justo lo que este
        # campo existe para evitar.  Sin exportarlo, el JSON solo llevaba la
        # mitad y quien lo leyera despues no podia hacer bien esa resta.
        self.resultados["suelo_frio"] = self.suelo_frio

    def fuente(self, ln: str, n: int) -> Optional[Path]:
        """La fuente de @p n funciones para @p ln, generandola si no esta.

        Existe porque las fases dejaron de correr siempre todas.  La de
        realimentacion leia los ficheros que habia escrito la de compilacion
        completa, asi que pedirla sola no media nada: no encontraba ninguno y
        se saltaba todas sus filas sin decir por que.  Ahora cualquiera pide la
        fuente que necesita y aparece.
        """
        entrada = GENERADORES.get(ln)
        if entrada is None:
            return None
        nombre, gen = entrada
        d = self.base_tmp / ("gen_%s_%d" % (ln, n))
        d.mkdir(parents=True, exist_ok=True)
        ruta = d / nombre
        if not ruta.is_file():
            ruta.write_text(gen(n), encoding="utf-8")
        return ruta


@dataclass
class Fase:
    """Una fase del banco: que mide, como se la nombra y si va por defecto."""

    id: str  # lo que se escribe en `--fase`
    titulo: str
    fn: Callable[[Ctx], None]
    por_defecto: bool = True
