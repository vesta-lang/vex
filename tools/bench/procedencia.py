#!/usr/bin/env python3
"""De QUE codigo salio una medida.

Una medida sin esto no dice nada el dia que aparece una regresion: se ve que
algo empeoro, pero no desde cuando ni contra que comparar.  Con el commit y la
fecha, dos ficheros de medida acotan el cambio a un rango del historial.

Lo usan `codegen_size.py` y `runtime_cycles.py`.  Vive aparte para que no
acaben con dos ideas distintas de que es la procedencia -- que es como dos
copias de lo mismo se separan sin que nadie lo note.
"""

import datetime
import os
import subprocess

RAIZ = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _git(*args):
    """Ejecuta git en la raiz del repo; cadena vacia si no se puede."""
    try:
        r = subprocess.run(("git",) + args, cwd=RAIZ, capture_output=True,
                           text=True, timeout=30)
        return r.stdout.strip() if r.returncode == 0 else ""
    except (subprocess.TimeoutExpired, OSError):
        return ""


def recoger(build=""):
    """Devuelve la ficha de procedencia de esta medida.

    @param build Directorio del build usado, si se sabe.
    @return dict con el commit, su fecha, si el arbol tenia cambios sueltos y
            cuando se midio.
    """
    sucio = _git("status", "--porcelain")
    return {
        "commit": _git("rev-parse", "HEAD"),
        "commit_corto": _git("rev-parse", "--short", "HEAD"),
        "commit_fecha": _git("log", "-1", "--format=%cI"),
        "commit_asunto": _git("log", "-1", "--format=%s"),
        "rama": _git("rev-parse", "--abbrev-ref", "HEAD"),
        # Si el arbol tenia cambios sin commitear, el commit NO identifica lo
        # que se midio: la medida no se puede reproducir a partir de el, y
        # decirlo evita atribuir despues una regresion al commit equivocado.
        "arbol_sucio": bool(sucio),
        "ficheros_sueltos": len(sucio.splitlines()) if sucio else 0,
        "medido": datetime.datetime.now().astimezone().isoformat(
            timespec="seconds"),
        "build": build,
    }


def describir(meta):
    """Una linea legible con la procedencia, para imprimirla al comparar."""
    if not meta:
        return "(sin procedencia: medida de una version anterior de la herramienta)"
    partes = []
    if meta.get("commit_corto"):
        partes.append(meta["commit_corto"])
    if meta.get("rama"):
        partes.append("[" + meta["rama"] + "]")
    if meta.get("commit_fecha"):
        partes.append(meta["commit_fecha"][:10])
    if meta.get("arbol_sucio"):
        partes.append("+%d sin commitear" % meta.get("ficheros_sueltos", 0))
    if meta.get("medido"):
        partes.append("medido " + meta["medido"][:16].replace("T", " "))
    return "  ".join(partes) if partes else "(sin procedencia)"
