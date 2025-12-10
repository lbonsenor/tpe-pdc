#ifndef SOCKS5NIO_H
#define SOCKS5NIO_H

#include "selector.h"

/**
 * socks5nio.h - Servidor SOCKSv5 con I/O no bloqueante
 */

/// @brief Handler para aceptar nuevas conexiones SOCKSv5
/// @param key 
void socksv5_passive_accept(struct selector_key *key);

/// @brief Destruye el pool de conexiones SOCKS5
void socksv5_pool_destroy(void);


#endif