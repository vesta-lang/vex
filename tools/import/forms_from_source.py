#!/usr/bin/env python3
"""La FORMA de cada opcode, leida del FUENTE de su manejador.

Por que existe, y por que aparte del derivador
---------------------------------------------
Ya hay un derivador que saca esto recorriendo el CODIGO MAQUINA del manejador
(`test_efectos_opcodes`).  Funciona, y tiene un defecto que no se le puede
quitar: depende de COMO compilo el compilador.  Cada idioma que reconoce --
plegar la base de un banco dentro del indice, guardar un puntero en un registro
que sobrevive a la llamada, derramar el quinto argumento a la pila -- existe
porque GCC eligio una forma concreta.  Con otra version, o con clang, esos
idiomas dejan de aparecer y la respuesta se degrada sin que nada falle.

El fuente NO depende de eso.  Y hay una diferencia real entre las dos mitades
del problema:

  - los EFECTOS (banderas, pila, marco, contador de programa) estan repartidos
    por los ayudantes a los que el manejador llama, asi que hay que SEGUIR
    llamadas -- y eso, sobre texto, no se puede hacer con garantias: un regex no
    distingue una llamada de un `if`;
  - la FORMA (que campo del operando se lee y cual se escribe) es LOCAL.  Esta
    escrita en las primeras lineas de cada manejador, siempre igual:

        const uint8_t r_dst = (instr.data_instruction.reg_data.reg1 >> 4) & 0xF;
        const uint8_t r_src = instr.data_instruction.reg_data.reg1 & 0xF;
        ...
        vm->registers.regs[r_dst].qword(0);      // lo ESCRIBE
        ... vm->registers.regs[r_src].qword()    // lo LEE

Asi que la forma si se puede leer del texto, y ademas es donde esta la verdad:
lo que el opcode hace lo decide el manejador, no el compilador que lo traduce.

Que hace y que NO
-----------------
Reconoce el patron de arriba y nada mas.  Un manejador que no lo siga sale como
DESCONOCIDO, con su motivo, y no se inventa nada: quedarse callado con una forma
a medias seria peor que no dar ninguna -- se reordenarian instrucciones que si
dependian --.

No escribe declaraciones: produce un informe.  Declarar sigue siendo un acto
deliberado, y esto es lo que lo hace mecanico en vez de adivinado.

Uso:
    python tools/import/forms_from_source.py            # informe legible
    python tools/import/forms_from_source.py --json     # para comparar
    python tools/import/forms_from_source.py --check efectos.json
        Contrasta lo leido del fuente con lo que el derivador saco del codigo
        maquina.  Sale con codigo 1 si se CONTRADICEN.

Que significa cada resultado del contraste
------------------------------------------
El derivador se queda corto cuando no puede seguir una llamada, asi que lo suyo
es una COTA INFERIOR: lo que encuentra esta, lo que no encuentra puede estar.
El contraste, entonces, no es de igualdad:

    maquina incluido en fuente  ->  CONFIRMA.  Dos caminos que no comparten
                                    nada dicen lo mismo.
    maquina NO incluido         ->  CONTRADICCION.  El manejador toca un campo
                                    que su propio fuente no menciona: o el
                                    lector del fuente se equivoca, o el opcode
                                    hace algo por un camino que nadie ve.  Las
                                    dos cosas hay que mirarlas.
    solo el fuente              ->  una sola fuente.  Vale para declarar -- el
                                    fuente es la autoridad -- pero no esta
                                    comprobado por nadie mas.
"""

import json
import pathlib
import re
import sys

RAIZ = pathlib.Path(__file__).resolve().parent.parent.parent
FUENTES = sorted((RAIZ / "src" / "runtime").glob("exec_instruction*.cpp"))

# Los seis campos del operando, en el mismo orden que `operand_field_bit` y que
# el `RegSlot` del descodificador: campo (reg1, reg2) por parte (entero, bajo,
# alto).
CAMPOS = ["reg1", "reg1.bajo", "reg1.alto", "reg2", "reg2.bajo", "reg2.alto"]

# Como se escribe cada campo en el fuente.  El orden importa: los patrones con
# nibble tienen que probarse ANTES que el del byte entero, que es prefijo suyo.
_R = r"instr\.data_instruction\.reg_data\."
PATRONES = [
    (2, re.compile(r"\(\s*" + _R + r"reg1\s*>>\s*4\s*\)\s*&\s*0x[fF]")),
    (5, re.compile(r"\(\s*" + _R + r"reg2\s*>>\s*4\s*\)\s*&\s*0x[fF]")),
    (1, re.compile(_R + r"reg1\s*&\s*0x[fF]")),
    (4, re.compile(_R + r"reg2\s*&\s*0x[fF]")),
    (0, re.compile(_R + r"reg1\b")),
    (3, re.compile(_R + r"reg2\b")),
]

# `const uint8_t NOMBRE = <expresion>;` -- la ligadura de un campo a un nombre.
LIGADURA = re.compile(
    r"const\s+uint8_t\s+(\w+)\s*=\s*([^;]+);", re.S)

# Un uso del banco: `registers.regs[X]` o `registers.zmm[X]`, donde X es o un
# nombre local ya ligado a un campo, o el campo escrito EN LINEA.  Las dos
# formas salen en el codigo y significan lo mismo; no reconocer la segunda
# dejaba fuera 73 manejadores.
USO = re.compile(
    r"registers\.(regs|zmm)\[\s*([^\]]+?)\s*\]\s*(\.?\w*)\s*\(?")

CABECERA = re.compile(
    r"^void\s+exec_instr_(\w+)\s*\(\s*ProcessVM\s*\*\w+,\s*"
    r"const\s+DecodedInstr\s*&\w*\s*\)\s*\{", re.M)

# Metodos de `GeneralRegister`/`ZmmRegister` que ESCRIBEN cuando llevan
# argumento.  Sin argumento son lectores: `qword()` lee, `qword(v)` escribe.
ESCRITORES = {"qword", "dword_lo", "word_lo", "byte_lo", "raw", "write_f32",
              "write_f64", "set"}


def campo_de(expr):
    """El indice de campo al que se refiere @p expr, o None."""
    for idx, pat in PATRONES:
        if pat.search(expr):
            return idx
    return None


def analiza(cuerpo):
    """Devuelve (lee, escribe, lee_vec, escribe_vec, motivo)."""
    # 1. Que nombre local esta ligado a que campo del operando.
    ligado = {}
    for m in LIGADURA.finditer(cuerpo):
        idx = campo_de(m.group(2))
        if idx is not None:
            ligado[m.group(1)] = idx


    lee = esc = vlee = vesc = 0
    vistos = 0
    for m in USO.finditer(cuerpo):
        banco, dentro, metodo = m.group(1), m.group(2), m.group(3)
        if dentro in ligado:
            idx = ligado[dentro]
        else:
            # El campo escrito en linea dentro de los corchetes.
            idx = campo_de(dentro)
            if idx is None:
                continue
        vistos += 1
        bit = 1 << idx
        # Escribe si el metodo es de escritura Y lleva argumento; el texto tras
        # el parentesis lo dice.  `raw()` lee, `raw(v)` no existe: se distingue
        # por el caracter siguiente.
        fin = m.end()
        met = metodo.lstrip(".")
        arg = fin < len(cuerpo) and cuerpo[fin] != ")"
        escribe = met in ESCRITORES and arg
        # Tomar la direccion (`&regs[x]`) o pasarlo por referencia no marcada
        # cuenta como escritura POSIBLE: no se puede saber sin seguir, y aqui no
        # se sigue.  Se dice, no se supone.
        if cuerpo[max(0, m.start() - 1)] == "&":
            return 0, 0, 0, 0, "toma la direccion de un registro: hay que seguirla"
        if banco == "zmm":
            if escribe:
                vesc |= bit
            else:
                vlee |= bit
        else:
            if escribe:
                esc |= bit
            else:
                lee |= bit
    if vistos == 0:
        return 0, 0, 0, 0, ("no usa ningun campo del operando contra el banco "
                            "de registros")
    return lee, esc, vlee, vesc, ""


def texto(m):
    return ",".join(CAMPOS[i] for i in range(6) if m >> i & 1) or "-"


def contrasta(filas, ruta_maquina):
    """Contrasta lo leido del fuente con lo derivado del codigo maquina."""
    mc = json.loads(pathlib.Path(ruta_maquina).read_text(encoding="utf-8"))
    por_nombre = {f["nombre"]: f for f in filas if not f["motivo"]}
    ok = contra = solo = 0
    malos = []
    for o in mc["opcodes"]:
        if not o.get("implementada"):
            continue
        h = por_nombre.get(o["nombre"])
        if h is None:
            continue
        d_lee, d_esc = o["form_read"], o["form_write"]
        s_lee = h["lee"] | h["lee_vec"]
        s_esc = h["escribe"] | h["escribe_vec"]
        if d_lee == 0 and d_esc == 0:
            solo += 1
            continue
        if (d_lee & ~s_lee) == 0 and (d_esc & ~s_esc) == 0:
            ok += 1
        else:
            contra += 1
            malos.append((o["nombre"], texto(d_lee), texto(s_lee),
                          texto(d_esc), texto(s_esc)))
    print("Fuente contra codigo maquina, sobre %d opcodes comparables:" %
          (ok + contra + solo))
    print("  %3d  el codigo maquina CONFIRMA lo leido del fuente" % ok)
    print("  %3d  se CONTRADICEN" % contra)
    print("  %3d  solo los ve el fuente (una sola fuente, no comprobado)" % solo)
    for m in malos:
        print("\n  %s" % m[0])
        print("    maquina  lee=%s  escribe=%s" % (m[1], m[3]))
        print("    fuente   lee=%s  escribe=%s" % (m[2], m[4]))
    if contra:
        print("\nUn manejador toca un campo que su propio fuente no menciona.")
        return 1
    return 0


def main():
    json_out = "--json" in sys.argv[1:]
    check = None
    if "--check" in sys.argv[1:]:
        i = sys.argv.index("--check")
        if i + 1 >= len(sys.argv):
            print("uso: --check <efectos.json>", file=sys.stderr)
            return 2
        check = sys.argv[i + 1]
    filas = []
    for ruta in FUENTES:
        s = ruta.read_text(encoding="utf-8", errors="replace")
        for m in CABECERA.finditer(s):
            nombre = m.group(1)
            j = s.find("\nvoid exec_instr_", m.end())
            cuerpo = s[m.end(): j if j > 0 else len(s)]
            lee, esc, vlee, vesc, motivo = analiza(cuerpo)
            filas.append({
                "nombre": nombre, "fichero": ruta.name,
                "lee": lee, "escribe": esc,
                "lee_vec": vlee, "escribe_vec": vesc,
                "motivo": motivo,
            })
    if check is not None:
        return contrasta(filas, check)
    if json_out:
        json.dump({"handlers": filas}, sys.stdout, indent=1)
        print()
        return 0

    con = [f for f in filas if not f["motivo"]]
    print("FORMA leida del FUENTE de cada manejador\n")
    print("%-22s %-30s %-22s %s" % ("manejador", "lee", "escribe", "banco"))
    for f in sorted(con, key=lambda x: x["nombre"]):
        vec = "VEC" if (f["lee_vec"] or f["escribe_vec"]) else ""
        print("%-22s %-30s %-22s %s" % (
            f["nombre"],
            texto(f["lee"] or f["lee_vec"]),
            texto(f["escribe"] or f["escribe_vec"]), vec))
    sin = [f for f in filas if f["motivo"]]
    print("\n%d de %d con forma leida; %d sin ella:" %
          (len(con), len(filas), len(sin)))
    porque = {}
    for f in sin:
        porque.setdefault(f["motivo"], []).append(f["nombre"])
    for k, v in sorted(porque.items(), key=lambda kv: -len(kv[1])):
        print("  %3d  %s" % (len(v), k))
        print("       %s" % ", ".join(sorted(v)[:10]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
