#ifndef USERS_H
#define USERS_H

/**
 * users.h - Sistema de manejo de authorized users
 */

#include <stdbool.h>
#include <stddef.h>

/// @brief Inicializa el sistema de usuarios
void users_init(void);

/// @brief Destruye el sistema de usuarios
void users_destroy(void);

/// @brief Agrega un usuario, en caso de que ya exista, actualiza la passwd
/// @param username Usuario (máx. 255 chars)
/// @param password Contraseña (máx. 255 chars)
/// @return true si se agregó exitosamente
bool users_add(const char *username, const char *password);

/// @brief Busca el usuario en el sistema y lo elimina
/// @param username Usuario a eliminar
/// @return true si eliminó, false si no existe
bool users_remove(const char *username);

/// @brief Valida si la password de un user es correcta
/// @param username Usuario
/// @param password Contraseña a validar
/// @return true si las credenciales son válidas
bool users_authenticate(const char *username, const char *password);

/// @brief Obtiene la cantidad de users registrados
/// @param  
/// @return Cantidad de usuarios
size_t users_count(void);

/// @brief Lista todos los nombres de usuarios registrados
/// @param buffer       Buffer donde escribir la lista
/// @param buffer_len   Tamaño del buffer
/// @return Cantidad de chars escritos en el buffer
size_t users_list(char *buffer, size_t buffer_len);

#endif