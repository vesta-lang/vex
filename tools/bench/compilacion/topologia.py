#!/usr/bin/env python3
"""Topologia de dependencias, y que se rehace al tocar algo.

La misma cantidad de codigo con otra FORMA -- ancha, en cadena, en diamante --
cuesta cosas distintas al reconstruir, porque lo que cambia es hasta donde se
propaga una invalidacion.  Aqui tambien viven las mutaciones (tocar un
comentario, un cuerpo, una interfaz) y el recuento de artefactos rehechos, que
es lo que distingue "no reconstruye" de "reconstruye deprisa".
"""
from __future__ import annotations

import hashlib
import shutil
import sys
from pathlib import Path
from typing import Optional

from .comun import ELEGIDO
from .multi import _trozos


def dependencias(k: int, forma: str) -> tuple[list[list[int]], list[int]]:
    """Devuelve (deps por modulo, modulos que importa el principal)."""
    if forma == "cadena":
        deps = [[] if j == 0 else [j - 1] for j in range(k)]
        return deps, [k - 1]
    if forma == "diamante":
        # m0 es la base; m1..mk-2 dependen de ella; mk-1 es la cima.
        deps = [[] for _ in range(k)]
        for j in range(1, k - 1):
            deps[j] = [0]
        deps[k - 1] = list(range(1, k - 1))
        return deps, [k - 1]
    return [[] for _ in range(k)], list(range(k))   # ancha


def escribir_topologia(lang: str, n: int, k: int, forma: str,
                       d: Path) -> Optional[list[str]]:
    """Escribe el programa con la forma de dependencias pedida.

    Cada modulo expone UNA funcion publica que llama a las de sus dependencias,
    mas relleno hasta repartir las `n` funciones.  El relleno es lo que da peso;
    la funcion publica es la que crea la arista.
    """
    d.mkdir(parents=True, exist_ok=True)
    deps, raiz = dependencias(k, forma)
    trozos = _trozos(n, k)
    if len(trozos) < k:
        return None
    ficheros: list[str] = []

    def relleno_llaves(t, tipo, decl):
        return "".join(decl % (i, tipo, i) for i in t)

    if lang in ("c", "cpp"):
        ext = "c" if lang == "c" else "cpp"
        for j in range(k):
            inc = "".join('#include "m%d.h"\n' % o for o in deps[j])
            llam = "".join(" + pub%d(x)" % o for o in deps[j])
            filler = "".join(
                "static long long r%d_%d(long long x) { return x * 3 + %d; }\n"
                % (j, i, i) for i in trozos[j])
            (d / ("m%d.h" % j)).write_text(
                "#pragma once\nlong long pub%d(long long x);\n" % j,
                encoding="utf-8")
            (d / ("m%d.%s" % (j, ext))).write_text(
                inc + '#include "m%d.h"\n' % j + filler +
                "long long pub%d(long long x) { return x%s; }\n" % (j, llam),
                encoding="utf-8")
            ficheros.append("m%d.%s" % (j, ext))
        inc = "".join('#include "m%d.h"\n' % o for o in raiz)
        llam = "".join("    s += pub%d(%d);\n" % (o, o) for o in raiz)
        (d / ("main.%s" % ext)).write_text(
            inc + "int main(void) {\n    long long s = 0;\n" + llam +
            "    return (int)(s % 251);\n}\n", encoding="utf-8")
        ficheros.append("main.%s" % ext)
        return ficheros

    if lang in ("vesta", "vesta_aot"):
        for j in range(k):
            imp = "".join('import "m%d" only pub%d;\n' % (o, o) for o in deps[j])
            llam = "".join(" + pub%d(x)" % o for o in deps[j])
            filler = "".join(
                "i64 r%d_%d(i64 x) { return x * 3 + %d; }\n" % (j, i, i)
                for i in trozos[j])
            (d / ("m%d.vx" % j)).write_text(
                imp + "namespace top.m%d;\n\n" % j + filler +
                "public i64 pub%d(i64 x) { return x%s; }\n" % (j, llam),
                encoding="utf-8")
            ficheros.append("m%d.vx" % j)
        imp = "".join('import "m%d" only pub%d;\n' % (o, o) for o in raiz)
        llam = "".join("    s = s + pub%d(%d);\n" % (o, o) for o in raiz)
        (d / "main.vx").write_text(
            imp + "\ni32 main() {\n    i64 s = 0;\n" + llam +
            "    return (i32) (s % 251);\n}\n", encoding="utf-8")
        ficheros.append("main.vx")
        return ficheros

    if lang == "rust":
        for j in range(k):
            usos = "".join("use crate::m%d::pub%d;\n" % (o, o) for o in deps[j])
            llam = "".join(".wrapping_add(pub%d(x))" % o for o in deps[j])
            filler = "".join(
                "fn r%d_%d(x: i64) -> i64 { x.wrapping_mul(3).wrapping_add(%d) }\n"
                % (j, i, i) for i in trozos[j])
            (d / ("m%d.rs" % j)).write_text(
                usos + filler +
                "pub fn pub%d(x: i64) -> i64 { x%s }\n" % (j, llam),
                encoding="utf-8")
            ficheros.append("m%d.rs" % j)
        mods = "".join("mod m%d;\n" % j for j in range(k))
        llam = "".join("    s = s.wrapping_add(m%d::pub%d(%d));\n" % (o, o, o)
                       for o in raiz)
        (d / "main.rs").write_text(
            mods + "fn main() {\n    let mut s: i64 = 0;\n" + llam +
            "    std::process::exit((s % 251) as i32);\n}\n", encoding="utf-8")
        ficheros.append("main.rs")
        return ficheros

    if lang == "go":
        # Go no deja importar dentro del mismo paquete: la topologia se expresa
        # con llamadas entre ficheros, que es como el lenguaje lo entiende.
        for j in range(k):
            llam = "".join(" + pub%d(x)" % o for o in deps[j])
            filler = "".join(
                "func r%d_%d(x int64) int64 { return x*3 + %d }\n" % (j, i, i)
                for i in trozos[j])
            (d / ("m%d.go" % j)).write_text(
                "package main\n\n" + filler +
                "func pub%d(x int64) int64 { return x%s }\n" % (j, llam),
                encoding="utf-8")
            ficheros.append("m%d.go" % j)
        llam = "".join("\ts += pub%d(%d)\n" % (o, o) for o in raiz)
        (d / "main.go").write_text(
            "package main\n\nimport \"os\"\n\nfunc main() {\n\tvar s int64 = 0\n"
            + llam + "\tos.Exit(int(s % 251))\n}\n", encoding="utf-8")
        ficheros.append("main.go")
        return ficheros

    if lang == "java":
        for j in range(k):
            llam = "".join(" + M%d.pub%d(x)" % (o, o) for o in deps[j])
            filler = "".join(
                "    static long r%d_%d(long x) { return x * 3 + %d; }\n"
                % (j, i, i) for i in trozos[j])
            (d / ("M%d.java" % j)).write_text(
                "public class M%d {\n" % j + filler +
                "    public static long pub%d(long x) { return x%s; }\n}\n"
                % (j, llam), encoding="utf-8")
            ficheros.append("M%d.java" % j)
        llam = "".join("        s += M%d.pub%d(%d);\n" % (o, o, o) for o in raiz)
        (d / "Main.java").write_text(
            "public class Main {\n    public static void main(String[] a) {\n"
            "        long s = 0;\n" + llam +
            "        System.exit((int)(s % 251));\n    }\n}\n", encoding="utf-8")
        ficheros.append("Main.java")
        return ficheros
    return None


# Como se escribe un comentario y una funcion publica nueva en cada lenguaje.
# Hace falta para fabricar cambios de distinta PROFUNDIDAD sobre un proyecto ya
# construido, que es lo unico que revela la granularidad de invalidacion de
# cada compilador.
_COMENTARIO = {"c": "//", "cpp": "//", "rust": "//", "go": "//", "java": "//",
               "python": "#", "vesta": "//", "vesta_aot": "//"}

_FUNCION_NUEVA = {
    "c": "long long extra%d(long long x) { return x + %d; }\n",
    "cpp": "long long extra%d(long long x) { return x + %d; }\n",
    "rust": "pub fn extra%d(x: i64) -> i64 { x + %d }\n",
    "go": "func extra%d(x int64) int64 { return x + %d }\n",
    "python": "def extra%d(x):\n    return x + %d\n",
    "vesta": "public i64 extra%d(i64 x) { return x + %d; }\n",
    "vesta_aot": "public i64 extra%d(i64 x) { return x + %d; }\n",
}


def mutar(ruta: Path, lang: str, clase: str, vuelta: int) -> bool:
    """Cambia @p ruta con la PROFUNDIDAD pedida.  Devuelve False si no aplica.

    Las tres clases responden a preguntas distintas y por eso se miden aparte:

      comentario  El fichero cambia de fecha y de contenido, pero nada de lo
                  que declara.  Un compilador que compare contenidos con lo que
                  ya sabe puede saltarselo entero; uno que solo mire fechas, no.

      cuerpo      Cambia la implementacion de una funcion, no su firma.  Quien
                  guarde interfaz y cuerpo por separado solo tiene que rehacer
                  ese modulo; quien no, arrastra a todos sus dependientes.

      interfaz    Aparece una funcion publica nueva.  Lo que el modulo OFRECE
                  cambia, asi que revalidar a los dependientes es obligado.  Es
                  el techo: nadie deberia poder saltarselo.
    """
    if not ruta.is_file():
        return False
    texto = ruta.read_text(encoding="utf-8")
    if clase == "comentario":
        ruta.write_text(texto + "%s cambio %d\n" % (_COMENTARIO[lang], vuelta),
                        encoding="utf-8")
        return True
    if clase == "cuerpo":
        # `* 3 +` aparece en el cuerpo de todas las funciones generadas, en los
        # siete lenguajes.  Alternar el factor garantiza que CADA vuelta es un
        # cambio real y no una reescritura identica.
        viejo = "* 3 +" if (vuelta % 2 == 0) else "* 4 +"
        nuevo = "* 4 +" if (vuelta % 2 == 0) else "* 3 +"
        if viejo not in texto:
            return False
        ruta.write_text(texto.replace(viejo, nuevo, 1), encoding="utf-8")
        return True
    if clase == "interfaz":
        plantilla = _FUNCION_NUEVA.get(lang)
        if plantilla is None:
            return False
        ruta.write_text(texto + plantilla % (vuelta, vuelta), encoding="utf-8")
        return True
    return False


# Que artefactos intermedios deja cada herramienta, para poder CONTAR cuales
# rehace.  Los que no dejan ninguno observable (una sola invocacion de gcc, o
# una cache opaca como la de Go) se quedan fuera de esa cuenta en vez de
# rellenarse con un cero que se leeria como "no rehizo nada".
ARTEFACTOS = {
    "vesta": ("*.vxi", "*.vxir"),
    "vesta_aot": ("*.vxi", "*.vxir"),
    "java": ("clases/*.class",),
    "rust": ("*.rmeta", "*.rlib"),
}


def huella_artefactos(d: Path, lang: str) -> dict[str, str]:
    """Hash de cada artefacto intermedio que hay ahora mismo en @p d."""
    patrones = ARTEFACTOS.get(lang)
    if not patrones:
        return {}
    out: dict[str, str] = {}
    for pat in patrones:
        for p in d.glob(pat):
            try:
                out[p.name] = hashlib.sha256(p.read_bytes()).hexdigest()[:16]
            except OSError:
                pass
    return out


def contar_rehechos(antes: dict[str, str],
                    despues: dict[str, str]) -> tuple[int, int, int]:
    """Devuelve (rehechos, reutilizados, nuevos).

    Es la medida FUERTE del asunto: el tiempo lo ensucian la cache del sistema,
    otros procesos y la paginacion, pero que un artefacto cambie o no es un
    hecho.  Si cambiar el CUERPO de un modulo rehace solo el suyo y cambiar su
    INTERFAZ rehace ademas los de quien depende de el, la frontera esta
    haciendo su trabajo -- y eso ya no depende de cuanto tardara la maquina.
    """
    rehechos = sum(1 for k, v in despues.items()
                   if k in antes and antes[k] != v)
    reutilizados = sum(1 for k, v in despues.items()
                       if k in antes and antes[k] == v)
    nuevos = sum(1 for k in despues if k not in antes)
    return (rehechos, reutilizados, nuevos)


def _makefile_c(lang: str, ficheros: list[str], salida: Path,
                nucleos: int) -> Optional[list[str]]:
    """Un Makefile que compila cada unidad por separado, y la orden `make -j`.

    gcc y clang no paralelizan: una invocacion con N ficheros los compila uno
    detras de otro.  Lo que hace un proyecto de C de verdad es `make -jN`, y
    esa es la unica forma honesta de ponerlos en el eje `maquina` -- si no, se
    compararia el paralelismo de Vesta contra la ausencia del suyo, que no es
    una propiedad del compilador sino de como se le llamo.

    Escribe el Makefile en el directorio del caso.  Devuelve None si no hay
    `make`, y entonces el llamante se queda en secuencial y lo APUNTA, en vez
    de publicar como paralelo algo que no lo fue.
    """
    if not shutil.which("make"):
        return None
    cc = ELEGIDO["c"] if lang == "c" else ELEGIDO["cpp"]
    std = "-std=c11" if lang == "c" else "-std=c++17"
    d = salida.parent
    objs = [f + ".o" for f in ficheros]
    lineas = [
        "CC = %s" % cc,
        "CFLAGS = -O2 %s" % std,
        "OBJS = %s" % " ".join(objs),
        "",
        "%s: $(OBJS)" % salida.name,
        "\t$(CC) $(OBJS) -o %s" % salida.name,
        "",
        "%.o: %",
        "\t$(CC) $(CFLAGS) -c $< -o $@",
        "",
    ]
    (d / "Makefile.bench").write_text("\n".join(lineas), encoding="utf-8")
    return ["make", "-f", "Makefile.bench", "-j", str(max(1, nucleos)),
            salida.name]


def orden_multi(lang: str, ficheros: list[str], salida: Path,
                vm: Path, paralelo: str = "", nucleos: int = 1) -> list[str]:
    """Orden que compila el proyecto repartido.  Cada herramienta lo recibe
    como ella lo entiende: unos quieren todas las unidades, otros solo el
    fichero raiz y ya siguen las dependencias.

    @p paralelo elige el eje (ver `ordenes.PARALELISMO`).  Lo que cambia por
    herramienta:
      c / cpp  `maquina` usa `make -jN`, porque una sola invocacion de gcc con
               N ficheros es secuencial por construccion.
      go       `-p N`, que es su numero de paquetes en paralelo.
      vesta    va por entorno (`VX_PARALLEL_COMPILE`), no por la orden.
      rust     una sola crate: no hay paralelismo de unidades que pedirle.
    """
    if lang in ("c", "cpp"):
        if paralelo == "maquina":
            cmd = _makefile_c(lang, ficheros, salida, nucleos)
            if cmd:
                return cmd
            # Sin `make` no se puede paralelizar C aqui; se cae a secuencial.
            # El llamante lo marca en el JSON para que nadie lea esta fila
            # como si fuera del eje `maquina`.
        exe = ELEGIDO["c"] if lang == "c" else ELEGIDO["cpp"]
        std = "-std=c11" if lang == "c" else "-std=c++17"
        return [exe, "-O2", std] + ficheros + ["-o", str(salida)]
    if lang == "go":
        # `-p` es cuantos paquetes compila a la vez.  Sin fijarlo usa los
        # nucleos de la maquina, asi que en el eje secuencial hay que pedirle
        # explicitamente 1 o Go entraria paralelo en la tabla secuencial.
        p = ["-p", "1"] if paralelo == "secuencial" else (
            ["-p", str(max(1, nucleos))] if paralelo == "maquina" else [])
        return ["go", "build"] + p + ["-o", str(salida)] + ficheros
    if lang == "java":
        return ["javac", "-d", str(salida.parent / "clases")] + ficheros
    if lang == "rust":
        # Misma cache incremental que en `orden_compilar`, y por el mismo
        # motivo: sin ella se mediria a Rust siempre en frio y su aporte de
        # cache saldria como 1.00x.  `enfriar` la borra.
        return ["rustc", "-O", "-C",
                "incremental=" + str(salida.parent / "rustc-inc"),
                "main.rs", "-o", str(salida)]
    if lang == "vesta":
        return [str(vm), "--vesta", "main.vx", "-o", str(salida)]
    if lang == "vesta_aot":
        fmt = "pe" if sys.platform == "win32" else "elf"
        return [str(vm), "-m", "aot", "--vx", "main.vx", "-o",
                str(salida) + ".exe", "--emit", "exe", "--format", fmt]
    return []


