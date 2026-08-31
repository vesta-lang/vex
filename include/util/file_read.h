/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file util/file_read.h
 * @brief Leer un fichero entero por el camino corto del sistema.
 *
 * POR QUE.  `std::ifstream` monta encima del fichero un `streambuf` con su
 * propio bufer y su capa de conversion, y para traerse un fichero de una vez
 * eso es trabajo que nadie ha pedido.  En Windows, ademas, `CreateFileA`
 * traduce la cadena a UTF-16 y la ruta DOS al espacio de nombres del nucleo
 * (`\??\F:\...`) antes de acabar llamando a `NtOpenFile`; esa traduccion se
 * puede hacer aqui, una vez, y quitarla de cada apertura.
 *
 * Medido sobre los 1.424 paquetes del almacen de diagnostico (12 KiB de
 * media), lo mejor de cuatro pasadas alternando el orden, tres corridas:
 *
 *     ifstream, fichero entero          33,4 ms
 *     CreateFile + ReadFile, entero     28,4 ms
 *     CreateFile + 3 tramos             32,0 ms
 *     NtOpenFile + 3 tramos             32,3 ms
 *     NtOpenFile + fichero entero       27,7 ms   <- esto
 *
 * Dos cosas que ensenan esos numeros y conviene no olvidar:
 *
 *  1. El grueso del coste es ABRIR, no leer -- unos 20 us por fichero.  Leer
 *     solo la cola de cada paquete en vez del paquete entero apenas ahorraba
 *     nada, y leerlo en tres tramos SALIA CARO: con 12 KiB el fichero son tres
 *     paginas, asi que tres lecturas cuestan mas que una.  Quien quiera ir mas
 *     rapido que esto no lo consigue leyendo menos, sino abriendo menos.
 *  2. Por eso la funcion lee ENTERO y no ofrece leer por tramos: para los
 *     tamanos que maneja el proyecto seria mas lento, y una API que invita a
 *     hacer lo lento es una trampa esperando.
 *
 * En POSIX el equivalente es `open` + `read`, que ya es la llamada del sistema
 * sin capas encima.  `mmap` seria mas barato todavia SI el que lo llama pudiera
 * mirar el contenido en el sitio; como aqui se copia a un vector, el mapeo solo
 * anadiria dos llamadas mas.  Si algun dia alguien necesita mirar sin copiar,
 * ese es el momento de anadir una vista mapeada, no antes.
 *
 * No se incluye `windows.h` aqui: define `VOID` como macro y rompe cualquier
 * `enum class` que use ese nombre.  Vive en el `.cpp`.
 */
#ifndef VESTA_UTIL_FILE_READ_H
#define VESTA_UTIL_FILE_READ_H

#include <cstdint>
#include <string>
#include <vector>

namespace util {

/**
 * @brief Lee @p path entero en @p out.
 * @param path Ruta del fichero.
 * @param out  Destino; queda vacio si no se pudo leer COMPLETO.
 * @return true solo si se leyo el fichero entero.
 */
bool read_whole_file(const std::string &path, std::vector<uint8_t> &out);

/**
 * @brief Escribe @p bytes en @p path, creandolo o truncandolo.
 *
 * Por el mismo camino corto que @ref read_whole_file y por el mismo motivo:
 * `std::ofstream` mete su propia capa de bufer, y cuando los bytes ya estan
 * todos en memoria esa capa no aporta nada y se paga entera.  Medido con VTune
 * en un acierto de cache de un proyecto de 6k lineas -- que escribe 7,9 MiB --
 * el `write` de msvcrt se llevaba 38,7 ms de los ~80 de CPU del acierto.
 *
 * NO es atomico: escribe directamente sobre el destino.  Para lo que tiene que
 * publicarse de una pieza esta @ref fs::write_file_atomic, que escribe a un
 * temporal y renombra.  Aqui se ofrece el camino directo porque para el
 * artefacto de SALIDA eso es lo que se hacia siempre, y hacerlo atomico
 * significaba escribir 7,9 MiB y despues copiarlos otra vez cuando el
 * renombrado no puede sustituir al destino.
 *
 * @param path  Destino.
 * @param bytes Contenido.
 * @return true solo si se escribio ENTERO.
 */
bool write_whole_file(const std::string &path,
                      const std::vector<uint8_t> &bytes);

/**
 * @brief Lee SOLO un tramo de un fichero.
 *
 * CUANDO USAR ESTO Y CUANDO NO, que es lo que se aprendio midiendo: para un
 * fichero PEQUENO -- del tamano de unas pocas paginas -- leer un tramo NO
 * compensa, y leer varios sale peor que traerse el fichero entero.  Compensa
 * cuando el fichero es grande y el tramo pequeno: sacar 500 bytes de un
 * paquete de 2 MiB leyendolo entero es tirar 2 MiB por cada nodo.
 *
 * Regla practica: si el tramo es la mayor parte del fichero, @ref
 * read_whole_file; si es una porcion menor de algo grande, esto.
 *
 * @param path   Ruta.
 * @param offset Desde donde.
 * @param count  Cuantos bytes.
 * @param out    Destino; vacio si no se pudieron leer los @p count.
 * @return true solo si se leyo el tramo COMPLETO.
 */
bool read_file_range(const std::string &path, uint64_t offset, size_t count,
                     std::vector<uint8_t> &out);

/**
 * @brief Un directorio abierto UNA vez, para leer varios de sus ficheros.
 *
 * Cada fichero se abre dando solo su nombre de hoja y el descriptor del
 * directorio como raiz, asi que el nucleo resuelve un componente en lugar de
 * recorrer la ruta entera una y otra vez.  Es `openat` de POSIX; en Windows
 * solo esta en la API del nucleo (`RootDirectory` de OBJECT_ATTRIBUTES) porque
 * `CreateFile` no ofrece nada equivalente.
 *
 * Medido sobre los 1.424 paquetes, frente a abrir cada uno por su ruta
 * absoluta: 26,2 ms contra 26,8.  Un 2%, consistente en las tres corridas pero
 * modesto, y conviene saber por que: lo caro de abrir no es recorrer la ruta
 * -- el gestor de objetos ya cachea los directorios intermedios -- sino crear
 * el objeto de fichero, la entrada en la tabla de descriptores y comprobar los
 * permisos.  Eso se paga igual.  Aqui sale a cuenta porque el directorio hay
 * que abrirlo de todas formas para enumerarlo, asi que el 2% es gratis.
 *
 * Quien espere mas de esta clase se llevara un chasco: no reduce el NUMERO de
 * aperturas, que es lo que de verdad cuesta.  Para eso hay que tener menos
 * ficheros, no abrirlos mas barato.
 */
class DirectoryReader {
  public:
    /// Abre @p dir_path.  Comprobar con ok() antes de usarlo.
    explicit DirectoryReader(const std::string &dir_path);
    ~DirectoryReader();

    DirectoryReader(const DirectoryReader &) = delete;
    DirectoryReader &operator=(const DirectoryReader &) = delete;

    /// @return false si el directorio no se pudo abrir; entonces hay que tirar
    /// de read_whole_file() con la ruta completa.
    bool ok() const;

    /**
     * @brief Lee entero un fichero de este directorio.
     * @param leaf_name Nombre a secas, sin ninguna parte de la ruta.
     * @param out       Destino; vacio si no se pudo leer COMPLETO.
     */
    bool read_file(const std::string &leaf_name,
                   std::vector<uint8_t> &out) const;

  private:
#if defined(_WIN32)
    void *handle_; ///< HANDLE, sin arrastrar windows.h hasta aqui.
#else
    int fd_;
#endif
};

} // namespace util

#endif // VESTA_UTIL_FILE_READ_H
