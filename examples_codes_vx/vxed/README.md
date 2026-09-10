# vxed

`vxed` es un editor de texto fullscreen para terminal escrito en .
Funciona en estilo TUI (al modo `nano` / `pico`): la pantalla se
redibuja entera tras cada tecla, el cursor se mueve con flechas y el
texto se inserta directamente donde apunta.

Es un proyecto autocontenido, gestionado con `vm pkg`.

## Requisitos

- `vm` instalado y disponible en el `PATH`.

  ```bash
  vm --version
  ```

- Windows con `msvcrt.dll` y `kernel32.dll` (presentes por defecto).
  El editor las usa para entrada raw de teclado y para detectar el
  tamano de la consola.

- Terminal con soporte ANSI VT100 (cualquier terminal moderno: Windows
  Terminal, PowerShell 7+, cmd.exe con VirtualTerminalLevel activo,
  iTerm2, gnome-terminal, etc.).

## Controles del editor

| Tecla | Accion |
|:------|:-------|
| Flechas | Mover el cursor |
| `Home` / `End` | Inicio / fin de la linea actual |
| `PageUp` / `PageDown` | Scroll de una pantalla |
| `Enter` | Insertar salto de linea |
| `Backspace` | Borrar el caracter anterior al cursor |
| `Delete` | Borrar el caracter bajo el cursor |
| Cualquier caracter imprimible | Se inserta en la posicion del cursor |
| `Ctrl-S` | Guardar el buffer en el archivo actual |
| `Ctrl-O` | Guardar como (pide un nombre nuevo) |
| `Ctrl-F` | Buscar texto (pide patron, con wrap al inicio) |
| `Ctrl-Z` | Deshacer ultimo cambio (pila de 64 snapshots) |
| `F1` | Mostrar pantalla de ayuda |
| `Ctrl-Q` / `Esc` | Salir |

Cualquier otra tecla (teclas multimedia, teclas modificadoras sueltas,
combinaciones no listadas) se ignora silenciosamente sin salir del
editor.

La barra de estado en la parte inferior muestra:

```text
 * sample.txt  L3:C12/24  F1=ayuda  Ctrl-S=guardar  Ctrl-F=buscar  Ctrl-Z=undo  Ctrl-Q=salir
```

El asterisco aparece cuando hay cambios sin guardar; `L:C` es la
posicion del cursor (linea : columna), y el numero tras `/` es el
total de lineas.  Tras una accion (guardar, buscar, undo) el lado
derecho muestra un mensaje de resultado hasta la proxima tecla.  Las
lineas que estan mas alla del final del buffer se muestran como `~`
en gris, al estilo de `vi`.

## Estructura del proyecto

```text
vxed/
  vx.toml           manifest del proyecto
  README.md          este archivo
  src/
    main.vx         orquestador + loop principal
    modules/
      buffer.vx     buffer de texto (insert, delete, cursor)
      file_io.vx    lectura y escritura via FFI msvcrt
      history.vx    pila de snapshots para Ctrl-Z (max 64)
      input.vx      entrada raw + parser dual scancode/VT100
      keys.vx       constantes KEY_*/VK_*
      screen.vx     render ANSI + consulta de tamano de consola
      search.vx     busqueda de substring sobre el buffer
  sample.txt         (opcional) archivo que se cargara al abrir
  vxed.velb         (generado por build) ejecutable
  sample.out.txt     (generado al guardar) salida
```

## Como usar el proyecto

Posicionate dentro del directorio `vxed/` antes de cada comando.

### 1. Instalar dependencias

```bash
vm pkg install
```

### 2. Compilar

```bash
vm pkg run build
```

El script `build` invoca al compilador  sobre `src/main.vx` y
produce `vxed.velb`.

### 3. Preparar un archivo opcional

Si existe un archivo llamado `sample.txt` en el directorio actual, el
editor lo carga automaticamente al arrancar.  Crea uno o copia el que
quieras editar:

```bash
echo "Hola
mundo." > sample.txt
```

Sin `sample.txt`, el editor abre con un buffer vacio.

### 4. Ejecutar

```bash
vm pkg run run
```

La consola entra en modo fullscreen y el editor pasa a controlar la
pantalla.  Usa los controles listados arriba para editar; `Ctrl-S`
guarda y `Ctrl-Q` cierra.

Para ejecutar con estadisticas de runtime (instrucciones VM, MIPS,
memoria del GC):

```bash
vm pkg run stats
```

## Otros comandos del gestor

```bash
vm pkg list                            # paquetes instalados
vm pkg verify                          # check de integridad
vm pkg audit                           # auditoria de seguridad
vm pkg inspect src/modules/buffer.vxi # inspeccion de un .vxi
```

## Resolucion de problemas

**La pantalla muestra `[2J[H` y otros bloques de caracteres extranos
en lugar de redibujarse**: el terminal no esta interpretando codigos
ANSI.  En Windows usa Windows Terminal o PowerShell 7+; en `cmd.exe`
clasico activa el soporte con:

```cmd
reg add HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1
```

**El editor sale al pulsar una flecha o tecla especial**: tu terminal
envia secuencias VT100 (`ESC [ A` para flecha arriba, etc.) y el
editor las interpreta como `Esc` solo si el parser falla.  Las
versiones actuales del editor soportan tanto el protocolo legacy
(`0x00`/`0xE0` + scancode, conhost clasico) como VT100 (Windows
Terminal, PowerShell 7, terminales POSIX), distinguiendo `Esc` puro
de prefijo VT mediante un breve sondeo con `_kbhit`.  Si aun ves este
comportamiento, recompila el editor (`vm pkg run build`) para
asegurarte de tener la version mas reciente.

**Tras `Ctrl-Q` la consola sigue en modo "raw"**: en raros casos el
terminal puede no recuperar el modo de linea.  Cierra y vuelve a abrir
la consola, o ejecuta:

```cmd
mode con cols=80 lines=25
```

**Error de compilacion tras actualizar `vm`**: borra los caches y
reinstala:

```bash
rm -rf .cache vx_modules vx.lock vxed.velb
vm pkg install
vm pkg run build
```

## Limitaciones conocidas de esta version

- **Entrada de teclado solo Windows**: el editor usa `_kbhit` /
  `_getch` de `msvcrt.dll` para lectura raw, lo que es especifico de
  Windows.  Soporte POSIX requeriria conmutar a `termios` + `read`.
- **Sin Unicode / multibyte**: el buffer es estrictamente bytes ASCII.
  Caracteres UTF-8 se muestran como `.`.
- **Undo limitado**: la pila de snapshots tiene capacidad fija de 64.
  Cambios mas antiguos se descartan (ring buffer).  Cada caracter
  insertado consume un snapshot, asi que escritura larga puede llenar
  la pila rapido.
- **Sin replace interactivo, sin numeros de linea en la margen, sin
  syntax highlighting, sin seleccion ni copy/paste**: estas son
  features de futuras versiones.
- **`Ctrl-F` solo busca hacia adelante con wrap**: no hay busqueda
  hacia atras ni resaltado de coincidencias.
