#!/usr/bin/env python3
"""Harness compartido para los smoke tests del LSP de Vesta (portados de bash).

Cada test construye una secuencia JSON-RPC con framing Content-Length, la envia
por stdin al binario `vesta_lsp` y verifica su stdout.  Portable Linux/Windows
(solo stdlib de Python).

    python tests/lsp/<test>.py <ruta-al-vesta_lsp[.exe]>
"""
import json
import os
import subprocess
import sys


def frame(obj):
    """Enmarca un objeto JSON como mensaje LSP (Content-Length + CRLF + cuerpo)."""
    body = json.dumps(obj).encode("utf-8")
    return b"Content-Length: %d\r\n\r\n%s" % (len(body), body)


def check_bin():
    """Valida argv[1] = ruta al vesta_lsp ejecutable; devuelve la ruta o sale."""
    if len(sys.argv) < 2 or not os.path.exists(sys.argv[1]):
        sys.stderr.write("uso: python %s <vesta_lsp[.exe]>\n"
                         % os.path.basename(sys.argv[0]))
        sys.exit(2)
    # Ruta absoluta con separadores nativos (CreateProcess en Windows no
    # resuelve rutas relativas con '/').
    return os.path.abspath(sys.argv[1])


def run_lsp(lsp_bin, msgs, timeout=120):
    """Envia @p msgs (lista de dicts) enmarcados por stdin; devuelve stdout (str)."""
    data = b"".join(frame(m) for m in msgs)
    try:
        # El IDIOMA se fija aqui, no se hereda.  El servidor toma el suyo del
        # entorno (VESTA_LANG > LC_ALL > LANG), asi que un test que afirma
        # sobre el TEXTO -- "funcion", "complejidad" -- pasa o falla segun la
        # maquina en la que corra.  Fijarlo es lo que lo hace una prueba y no
        # una casualidad.
        env = dict(os.environ)
        env["VESTA_LANG"] = "es"
        p = subprocess.run([lsp_bin], input=data, capture_output=True,
                           timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        sys.stderr.write("FALLO: el servidor LSP no termino (timeout)\n")
        return ""
    return p.stdout.decode("utf-8", errors="replace")


# --- mensajes JSON-RPC comunes ------------------------------------------------
def m_initialize(id_=1, root_uri=None):
    return {"jsonrpc": "2.0", "id": id_, "method": "initialize",
            "params": {"processId": None, "rootUri": root_uri, "capabilities": {}}}


def m_initialized():
    return {"jsonrpc": "2.0", "method": "initialized", "params": {}}


def m_did_open(uri, text, lang="vx", version=1):
    return {"jsonrpc": "2.0", "method": "textDocument/didOpen",
            "params": {"textDocument": {"uri": uri, "languageId": lang,
                                        "version": version, "text": text}}}


def m_shutdown(id_=99):
    return {"jsonrpc": "2.0", "id": id_, "method": "shutdown", "params": None}


def m_exit():
    return {"jsonrpc": "2.0", "method": "exit", "params": None}


def file_uri(path):
    """Convierte una ruta de disco en un URI file:// portable (Windows -> file:///C:/...)."""
    p = os.path.abspath(path).replace("\\", "/")
    if len(p) >= 2 and p[1] == ":":  # unidad Windows
        return "file:///" + p
    return "file://" + p


def resp_for_id(out, id_):
    """Devuelve las lineas de @p out que contienen la respuesta con "id":<id_>."""
    needle = '"id":%d' % id_
    return "\n".join(ln for ln in out.splitlines() if needle in ln)


def m_completion(uri, line, char, id_):
    return {"jsonrpc": "2.0", "id": id_, "method": "textDocument/completion",
            "params": {"textDocument": {"uri": uri},
                       "position": {"line": line, "character": char}}}


def m_request(method, id_, params):
    """Peticion JSON-RPC generica."""
    return {"jsonrpc": "2.0", "id": id_, "method": method, "params": params}


def m_pos(method, uri, line, char, id_, context=None):
    """Peticion posicional (hover/definition/references)."""
    params = {"textDocument": {"uri": uri},
              "position": {"line": line, "character": char}}
    if context is not None:
        params["context"] = context
    return {"jsonrpc": "2.0", "id": id_, "method": method, "params": params}


def decode_semantic_data(nums):
    """Decodifica el array plano de semantic tokens (quintetos con deltas) a una
    lista de (line, col, tokenType) en posiciones absolutas."""
    out = []
    line = col = 0
    for i in range(0, len(nums) - 4, 5):
        dl, ds, _length, typ = nums[i], nums[i + 1], nums[i + 2], nums[i + 3]
        if dl == 0:
            col += ds
        else:
            line += dl
            col = ds
        out.append((line, col, typ))
    return out


def extract_data_array(out):
    """Extrae el array de enteros de `"data":[...]` (ultima aparicion)."""
    import re
    last = None
    for m in re.finditer(r'"data":\[([0-9,]*)\]', out):
        last = m.group(1)
    if not last:
        return []
    return [int(x) for x in last.split(",") if x.strip()]


class Report:
    """Acumula OK/FALLO y produce el exit-code final."""

    def __init__(self, name):
        self.name = name
        self.fail = 0

    def check(self, cond, ok_msg, fail_msg):
        if cond:
            print("OK  " + ok_msg)
        else:
            print("FALLO  " + fail_msg)
            self.fail = 1

    def finish(self):
        print("%s: %s" % (self.name, "TODO OK" if self.fail == 0 else "HUBO FALLOS"))
        sys.exit(self.fail)
