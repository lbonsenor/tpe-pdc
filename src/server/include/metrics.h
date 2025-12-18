#ifndef METRICS_H
#define METRICS_H

/**
 * Sistema de métricas para el proxy SOCKS5
 */

#include <stddef.h>
#include <stdint.h>
#include <time.h>

struct metrics
{
    size_t total_connections;           
    size_t current_connections;         
    size_t failed_connections;          
    size_t max_concurrent_connections;  
    
    uint64_t bytes_sent;             
    uint64_t bytes_received;            
    uint64_t bytes_transferred;         
    
    size_t auth_success;                
    size_t auth_failed;                 
    
    time_t start_time; 
};

/// @brief Inicializa el sistema de métricas
void metrics_init(void);

/// @brief Registra una nueva conexión
void metrics_connection_new(void);

/// @brief Registra el cierre de una conexión
void metrics_connection_close(void);

/// @brief Registra una conexión fallida
void metrics_connection_failed(void);

/// @brief Registra bytes enviados al cliente
void metrics_bytes_sent(size_t bytes);

/// @brief Registra bytes recibidos del cliente
void metrics_bytes_received(size_t bytes);

/// @brief Registra una autenticación exitosa
void metrics_auth_success(void);

/// @brief Registra una autenticación fallida
void metrics_auth_failed(void);

/// @brief Obtiene las métricas actuales
const struct metrics *metrics_get(void);

/// @brief Formatea las métricas en un buffer
/// @returns el número de bytes escritos
int metrics_format(char *buffer, size_t size);


#endif