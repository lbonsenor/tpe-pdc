#ifndef DISSECTOR_H
#define DISSECTOR_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * Sistema de disección de protocolos para monitoreo de credenciales
 * Similar a ettercap - captura usuarios y contraseñas en protocolos de texto plano
 */

// Tipos de protocolos que podemos detectar
typedef enum {
    PROTO_UNKNOWN = 0,
    PROTO_POP3,
    PROTO_HTTP,
    PROTO_FTP,
    PROTO_SMTP,
} protocol_type_t;

// Estructura para almacenar credenciales capturadas
typedef struct {
    protocol_type_t protocol;
    char username[256];
    char password[256];
    char dest_host[256];
    uint16_t dest_port;
    char timestamp[32];
} captured_credentials_t;

/// @brief Inicializa el sistema de disección
/// @param enabled Si el sistema debe estar activo
/// @param log_file Archivo donde guardar las credenciales (NULL para stderr)
void dissector_init(bool enabled, const char *log_file);

/// @brief Cierra el sistema de disección
void dissector_close(void);

/// @brief Analiza datos del cliente al servidor
/// @param data Buffer de datos
/// @param len Longitud de los datos
/// @param dest_host Host de destino
/// @param dest_port Puerto de destino
/// @return true si se detectó una credencial
bool dissector_process_client_data(
    const uint8_t *data,
    size_t len,
    const char *dest_host,
    uint16_t dest_port
);

/// @brief Analiza datos del servidor al cliente
/// @param data Buffer de datos
/// @param len Longitud de los datos
/// @return true si se procesaron datos relevantes
bool dissector_process_server_data(
    const uint8_t *data,
    size_t len
);

/// @brief Obtiene el total de credenciales capturadas
size_t dissector_get_credential_count(void);

/// @brief Verifica si el dissector está habilitado
bool dissector_is_enabled(void);

#endif
