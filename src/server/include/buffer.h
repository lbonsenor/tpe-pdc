#ifndef BUFFER_H
#define BUFFER_H

#include <stdbool.h>

/**
 * buffer.h - Buffer para I/O
 * 
 * Buffer de bytes con punteros de lectura y escritura
 */

typedef struct buffer buffer;

/// @brief Crea un nuevo buffer con capacidad inicial
/// @param capacity Tamaño del buffer en bytes
/// @return Puntero al buffer o NULL si falla
buffer *buffer_init(size_t capacity);

/// @brief Destruye el buffer y libera memoria
/// @param b El buffer a destruir
void buffer_destroy(buffer *b);

/// @brief Vacía el contenido de un buffer
/// @param b Buffer a resetear
void buffer_reset(buffer *b);

bool buffer_is_full(buffer *b);

#endif