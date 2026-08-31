#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TLS (thread_local) nativo en AOT: PE (Windows) y ELF (Linux).

Valida que `thread_local` de  se emite a TLS NATIVO por nuestro codegen, sin
emutls ni runtime C.  Los PROGRAMAS viven como ejemplos en
examples_codes_vx/aot/ (64-68); este script SOLO los compila y verifica el exit
(no hardcodea la fuente).

PE (corre nativo en Windows, sin WSL):
  - 64-68: el emisor PE sintetiza _tls_index + callbacks + IMAGE_TLS_DIRECTORY;
    el acceso lee el bloque TLS del hilo del TEB (gs:[0x58]) + offset (SECREL).
  - 67 ademas prueba el AISLAMIENTO por-hilo REAL con un hilo Win32.
  - 70: TLS en una .dll PE (plantilla via __vx_tls_init / DllMain sintetico);
    host C (gcc) verifica plantilla + aislamiento por-hilo.

ELF (compila/ejecuta via WSL):
  - F/G: -nativo (reusan los ejemplos 65/66) -- seccion SHF_TLS + PT_TLS,
    acceso fs:0 + lea@tpoff (TPOFF32) que --emit exe / --link resuelven.
  - A-E: INTEROP del linker propio (vm --link) con objetos TLS de gcc -- cubren
    los 4 modelos ELF: local-exec, initial-exec (GOTTPOFF), general-dynamic
    (TLSGD relajado) y x86-32 (R_386_TLS_LE).  Los .c son fixtures de gcc.

Uso:  python tests/aot/tls_test.py <build_dir>
"""
import os
import shutil
import subprocess
import sys


# LADO: windows  (prueba los DOS objetivos: el PE aqui, el ELF via WSL)
#
# `wsl` solo existe DESDE Windows.  Lanzado desde dentro de WSL este test
# moria con "No such file or directory: 'wsl'", que parecia un fallo suyo y
# era estar del lado equivocado.  Ahora se dice y se salta.
HAY_WSL = shutil.which("wsl") is not None


def wsl(cmd):
    return subprocess.run(["wsl", "bash", "-c", cmd], capture_output=True,
                          text=True)


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def main():
    if len(sys.argv) < 2:
        print("uso: tls_test.py <build_dir>")
        return 2
    if not HAY_WSL:
        print("SALTADO: no hay `wsl`.  Este test se lanza DESDE Windows y usa "
              "WSL para la mitad de Linux; desde dentro de WSL no aplica.")
        return 77

    build = os.path.abspath(sys.argv[1])
    vm = os.path.join(build, "vm.exe")
    if not os.path.exists(vm):
        vm = os.path.join(build, "vm")
    repo = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    rc_pe = 0

    # --- PE: thread_local -nativo (TLS directory de Windows).  Corre nativo
    # (sin WSL).  El emisor PE sintetiza _tls_index + callbacks +
    # IMAGE_TLS_DIRECTORY; el acceso usa gs:[0x58] -> [_tls_index] -> bloque.
    # Los programas viven como EJEMPLOS en examples_codes_vx/aot/ (no
    # hardcodeados aqui): el test compila cada uno a PE y verifica el exit. ---
    aot_ex = os.path.join(repo, "examples_codes_vx", "aot")
    # (fichero del ejemplo, exit esperado).  Ver la cabecera de cada .vx.
    pe_cases = [
        ("64_thread_local_basico.vx", 5),
        ("65_thread_local_multi.vx", 112),
        ("66_thread_local_fn_loop.vx", 10),
        ("67_thread_local_hilos.vx", 11099),  # aislamiento por-hilo (Win32)
        ("68_thread_local_float.vx", 42),      # plantilla float + comptime const
        ("69_thread_local_puntero.vx", 33),    # &tls + thread_local puntero
    ]
    if vm.endswith(".exe") and os.name == "nt":
        pe = os.path.join(repo, "_tls_pe")
        os.makedirs(pe, exist_ok=True)
        try:
            for ex, exp in pe_cases:
                src = os.path.join(aot_ex, ex)
                if not os.path.exists(src):
                    print(f"TLS-PE: falta el ejemplo {ex}, omitido")
                    continue
                ep = os.path.join(pe, ex.replace(".vx", ".exe"))
                run([vm, "--vx", src, "-m", "aot", "--emit", "exe",
                     "--format", "pe", "-o", ep])
                got = run([ep]).returncode if os.path.exists(ep) else -1
                if got == exp:
                    print(f"TLS-PE {ex}: exit={exp} OK")
                else:
                    print(f"TLS-PE {ex}: EXIT MISMATCH got={got} exp={exp}")
                    rc_pe = 1
            # --- DLL: TLS en una .dll PE.  El emisor sintetiza el TLS directory
            # y, ademas, fija AddressOfEntryPoint -> __vx_tls_init (DllMain
            # minimo) para que la plantilla se aplique en cada attach.  El host
            # C carga la .dll con LoadLibrary y verifica plantilla (12) +
            # aislamiento por-hilo (child=12).  Necesita gcc en PATH. ---
            gcc_ok = run(["gcc", "--version"]).returncode == 0
            ex70 = os.path.join(aot_ex, "70_thread_local_dll.vx")
            host70 = os.path.join(aot_ex, "70_thread_local_dll_host.c")
            if gcc_ok and os.path.exists(ex70) and os.path.exists(host70):
                dpe = os.path.join(repo, "_tls_dll")
                os.makedirs(dpe, exist_ok=True)
                try:
                    dll = os.path.join(dpe, "tls.dll")
                    hexe = os.path.join(dpe, "thost.exe")
                    run([vm, "--vx", ex70, "-m", "aot", "--emit", "shared",
                         "--format", "pe", "-o", dll])
                    run(["gcc", host70, "-o", hexe])
                    got = (run([hexe, dll]).returncode
                           if os.path.exists(hexe) and os.path.exists(dll)
                           else -1)
                    if got == 0:
                        print("TLS-PE 70_thread_local_dll (.dll DllMain): "
                              "exit=0 OK")
                    else:
                        print(f"TLS-PE 70_thread_local_dll: EXIT MISMATCH "
                              f"got={got} exp=0")
                        rc_pe = 1
                finally:
                    import shutil
                    shutil.rmtree(dpe, ignore_errors=True)
            else:
                print("TLS-PE 70 (.dll): gcc/ejemplo no disponible, omitido")
        finally:
            import shutil
            shutil.rmtree(pe, ignore_errors=True)

    if wsl("echo ok").stdout.strip().splitlines()[-1:] != ["ok"]:
        print("TLS: WSL no disponible (ELF omitido)")
        return rc_pe
    # WSL debe poder compilar (gcc) y ejecutar ELF64.
    if wsl("which gcc >/dev/null 2>&1 && echo yes").stdout.strip()[-3:] != "yes":
        print("TLS: gcc no disponible en WSL, omitido")
        return rc_pe

    work = os.path.join(repo, "_tls_test")
    wm = "/mnt/" + repo[0].lower() + repo[1:].replace("\\", "/").replace(
        ":", "") + "/_tls_test"
    os.makedirs(work, exist_ok=True)
    rc = 0
    try:
        wsl(f"cp $(ls /usr/lib/x86_64-linux-gnu/libc.so.6 "
            f"/lib/x86_64-linux-gnu/libc.so.6 2>/dev/null | head -1) "
            f"{wm}/libc.so.6")
        libc = os.path.join(work, "libc.so.6")
        if not os.path.exists(libc):
            print("TLS: libc.so.6 no encontrada, omitido")
            return rc_pe

        # --- A) .tdata simple ---
        with open(os.path.join(work, "tl.c"), "w") as f:
            f.write("__thread int counter = 5;\n"
                    "long long get_counter(void){ return counter; }\n")
        wsl(f"cd {wm} && gcc -O2 -c tl.c -o tl.o")
        with open(os.path.join(work, "ma.vx"), "w") as f:
            f.write('extern "tl" { fn get_counter() -> i64; }\n'
                    'i64 main(){ return get_counter(); }\n')
        run([vm, "--vx", os.path.join(work, "ma.vx"), "-m", "aot", "--emit",
             "obj", "--format", "elf", "-o", os.path.join(work, "ma.o")])
        run([vm, "--link", os.path.join(work, "ma.o"),
             os.path.join(work, "tl.o"), libc, "-o",
             os.path.join(work, "pa"), "--format", "elf"])
        ra = wsl(f"cd {wm} && chmod +x pa && ./pa").returncode
        if ra == 5:
            print("TLS-A (.tdata, __thread): exit=5 OK")
        else:
            print(f"TLS-A: EXIT MISMATCH got={ra} exp=5")
            rc = 1

        # --- B) .tdata + .tbss + varios tamanos ---
        with open(os.path.join(work, "tl2.c"), "w") as f:
            f.write("__thread int a = 5;\n"
                    "__thread int b;\n"
                    "__thread long long c = 100;\n"
                    "long long compute(void){ b = 7; return a + b + c; }\n")
        wsl(f"cd {wm} && gcc -O2 -c tl2.c -o tl2.o")
        with open(os.path.join(work, "mb.vx"), "w") as f:
            f.write('extern "tl2" { fn compute() -> i64; }\n'
                    'i64 main(){ return compute(); }\n')
        run([vm, "--vx", os.path.join(work, "mb.vx"), "-m", "aot", "--emit",
             "obj", "--format", "elf", "-o", os.path.join(work, "mb.o")])
        run([vm, "--link", os.path.join(work, "mb.o"),
             os.path.join(work, "tl2.o"), libc, "-o",
             os.path.join(work, "pb"), "--format", "elf"])
        rb = wsl(f"cd {wm} && chmod +x pb && ./pb").returncode
        if rb == 112:
            print("TLS-B (.tdata + .tbss + tamanos mixtos): exit=112 OK")
        else:
            print(f"TLS-B: EXIT MISMATCH got={rb} exp=112")
            rc = 1

        # --- C) initial-exec (GOTTPOFF): el TPOFF vive en una entrada GOT ---
        with open(os.path.join(work, "tc.c"), "w") as f:
            f.write("__thread int v = 5;\n"
                    "long long get_v(void){ return v; }\n")
        wsl(f"cd {wm} && gcc -O2 -fPIC -ftls-model=initial-exec "
            f"-c tc.c -o tc.o")
        with open(os.path.join(work, "mc.vx"), "w") as f:
            f.write('extern "tc" { fn get_v() -> i64; }\n'
                    'i64 main(){ return get_v(); }\n')
        run([vm, "--vx", os.path.join(work, "mc.vx"), "-m", "aot", "--emit",
             "obj", "--format", "elf", "-o", os.path.join(work, "mc.o")])
        run([vm, "--link", os.path.join(work, "mc.o"),
             os.path.join(work, "tc.o"), libc, "-o",
             os.path.join(work, "pc"), "--format", "elf"])
        rcc = wsl(f"cd {wm} && chmod +x pc && ./pc").returncode
        if rcc == 5:
            print("TLS-C (initial-exec GOTTPOFF): exit=5 OK")
        else:
            print(f"TLS-C: EXIT MISMATCH got={rcc} exp=5")
            rc = 1

        # --- D) general-dynamic (TLSGD) relajado a local-exec ---
        with open(os.path.join(work, "td.c"), "w") as f:
            f.write("__thread int w = 42;\n"
                    "long long get_w(void){ return w; }\n")
        # -fPIC sin tls-model -> el compilador emite TLSGD (general-dynamic).
        wsl(f"cd {wm} && gcc -O2 -fPIC -ftls-model=global-dynamic "
            f"-c td.c -o td.o")
        with open(os.path.join(work, "md.vx"), "w") as f:
            f.write('extern "td" { fn get_w() -> i64; }\n'
                    'i64 main(){ return get_w(); }\n')
        run([vm, "--vx", os.path.join(work, "md.vx"), "-m", "aot", "--emit",
             "obj", "--format", "elf", "-o", os.path.join(work, "md.o")])
        run([vm, "--link", os.path.join(work, "md.o"),
             os.path.join(work, "td.o"), libc, "-o",
             os.path.join(work, "pd"), "--format", "elf"])
        rdd = wsl(f"cd {wm} && chmod +x pd && ./pd").returncode
        if rdd == 42:
            print("TLS-D (general-dynamic TLSGD->local-exec): exit=42 OK")
        else:
            print(f"TLS-D: EXIT MISMATCH got={rdd} exp=42")
            rc = 1

        # --- E) x86-32 local-exec (R_386_TLS_LE) ---
        # Necesita multilib (gcc -m32) + libc.so.6 i386 + poder ejecutar ELF32.
        m32_ok = wsl("echo 'int main(){return 0;}' | gcc -m32 -xc -o /dev/null "
                     "- 2>/dev/null && echo yes").stdout.strip()[-3:] == "yes"
        libc32 = os.path.join(work, "libc32.so.6")
        wsl(f"cp $(ls /usr/lib32/libc.so.6 "
            f"/usr/lib/i386-linux-gnu/libc.so.6 "
            f"/lib/i386-linux-gnu/libc.so.6 2>/dev/null | head -1) "
            f"{wm}/libc32.so.6 2>/dev/null")
        if m32_ok and os.path.exists(libc32):
            with open(os.path.join(work, "te.c"), "w") as f:
                f.write("__thread int a = 5;\n"
                        "__thread int b;\n"
                        "__thread long long c = 100;\n"
                        "long long compute(void){ b=7; return a+b+c; }\n")
            wsl(f"cd {wm} && gcc -m32 -O2 -c te.c -o te.o")
            with open(os.path.join(work, "me.vx"), "w") as f:
                f.write('extern "te" { fn compute() -> i64; }\n'
                        'i64 main(){ return compute(); }\n')
            run([vm, "--vx", os.path.join(work, "me.vx"), "-m", "aot",
                 "--emit", "obj", "--format", "elf", "--aot-arch", "x86-32",
                 "-o", os.path.join(work, "me.o")])
            run([vm, "--link", os.path.join(work, "me.o"),
                 os.path.join(work, "te.o"), libc32, "-o",
                 os.path.join(work, "pe"), "--format", "elf"])
            ree = wsl(f"cd {wm} && chmod +x pe && ./pe").returncode
            if ree == 112:
                print("TLS-E (x86-32 local-exec R_386_TLS_LE): exit=112 OK")
            else:
                print(f"TLS-E: EXIT MISMATCH got={ree} exp=112")
                rc = 1
        else:
            print("TLS-E (x86-32): multilib/libc32 no disponible, omitido")

        # --- F) -NATIVO (--emit obj + --link): thread_local emitido por
        # nuestro codegen (sin C).  Reusa el EJEMPLO 65 (multi-var): seccion
        # SHF_TLS (.tdata) + acceso fs:0 + lea@tpoff + reloc R_X86_64_TPOFF32 que
        # el --link resuelve.  Sin emutls, sin runtime C, todo del lenguaje. ---
        ex65 = os.path.join(aot_ex, "65_thread_local_multi.vx")
        run([vm, "--vx", ex65, "-m", "aot", "--emit", "obj", "--format", "elf",
             "-o", os.path.join(work, "vtl.o")])
        run([vm, "--link", os.path.join(work, "vtl.o"), libc, "-o",
             os.path.join(work, "vtl"), "--format", "elf"])
        rf = wsl(f"cd {wm} && chmod +x vtl && ./vtl").returncode
        if rf == 112:
            print("TLS-F (ELF -nativo --emit obj + --link): exit=112 OK")
        else:
            print(f"TLS-F: EXIT MISMATCH got={rf} exp=112")
            rc = 1

        # --- G) -nativo por --emit exe DIRECTO (sin --link): el emisor de
        # ejecutable ELF resuelve el TPOFF inline + monta PT_TLS.  Reusa el
        # EJEMPLO 66 (TLS en funcion no-main + loop, persistencia por-hilo). ---
        ex66 = os.path.join(aot_ex, "66_thread_local_fn_loop.vx")
        run([vm, "--vx", ex66, "-m", "aot", "--emit", "exe", "--format", "elf",
             "-o", os.path.join(work, "vtg")])
        rg = wsl(f"cd {wm} && chmod +x vtg && ./vtg").returncode
        if rg == 10:
            print("TLS-G (ELF -nativo --emit exe + fn/loop): exit=10 OK")
        else:
            print(f"TLS-G: EXIT MISMATCH got={rg} exp=10")
            rc = 1
        return rc or rc_pe
    finally:
        import shutil
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
