#ifndef ACCESS_LOG_H
#define ACCESS_LOG_H

#include <time.h>
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

/**
 * Sistema de registro de accesos para auditoría
 * Permite a un administrador entender los accesos de cada usuario
 */

/// @brief Inicializa el sistema de access log
/// @param log_file_path Ruta al archivo de log (NULL para stderr)
void access_log_init(const char *log_file_path);

/// @brief Cierra el sistema de access log
void access_log_close(void);

/// @brief Registra una conexión exitosa
/// @param username Usuario que se conectó (NULL si sin autenticación)
/// @param client_addr Dirección del cliente
/// @param dest_host Hostname o IP de destino
/// @param dest_port Puerto de destino
/// @param dest_addr Dirección IP de destino resuelta
void access_log_connection(
    const char *username,
    const struct sockaddr *client_addr,
    const char *dest_host,
    uint16_t dest_port,
    const struct sockaddr *dest_addr
);

/// @brief Registra el cierre de una conexión
/// @param username Usuario que se conectó
/// @param dest_host Hostname o IP de destino
/// @param dest_port Puerto de destino
/// @param bytes_sent Bytes enviados al destino
/// @param bytes_received Bytes recibidos del destino
/// @param duration_sec Duración de la conexión en segundos
void access_log_disconnect(
    const char *username,
    const char *dest_host,
    uint16_t dest_port,
    uint64_t bytes_sent,
    uint64_t bytes_received,
    time_t duration_sec
);

/// @brief Registra un intento de conexión fallido
/// @param username Usuario que intentó conectarse
/// @param client_addr Dirección del cliente
/// @param dest_host Hostname o IP de destino
/// @param dest_port Puerto de destino
/// @param reason Razón del fallo
void access_log_failed(
    const char *username,
    const struct sockaddr *client_addr,
    const char *dest_host,
    uint16_t dest_port,
    const char *reason
);

/// @brief Registra un intento de autenticación
/// @param username Usuario que intentó autenticarse
/// @param client_addr Dirección del cliente
/// @param success Si la autenticación fue exitosa
void access_log_auth(
    const char *username,
    const struct sockaddr *client_addr,
    bool success
);

#endif
