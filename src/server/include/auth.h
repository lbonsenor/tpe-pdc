#ifndef AUTH_H
#define AUTH_H

/**
 * auth.h - Parser para autenticacion user/passwd SOCKS5
 */

#include <stdint.h>
#include <stdbool.h>
#include "buffer.h"

#define AUTH_VERSION 0x01

enum auth_status {
    AUTH_STATUS_SUCCESS = 0x00,
    AUTH_STATUS_FAILURE = 0xFF
};

enum auth_state {
    AUTH_STATE_VERSION,
    AUTH_STATE_ULEN,
    AUTH_STATE_UNAME,
    AUTH_STATE_PLEN,
    AUTH_STATE_PASSWD,
    AUTH_STATE_DONE,
    AUTH_STATE_ERROR,
};

struct auth_parser {
    enum auth_state state;
    
    uint8_t version;
    uint8_t ulen;
    uint8_t plen;
    
    char username[256];
    char password[256];
    
    uint8_t username_read;
    uint8_t password_read;
    
    void *data;
};

/// @brief Inicializa el parser de autenticación
/// @param p El Auth Parser
void auth_parser_init(struct auth_parser *p);

/// @brief Parsea datos del buffer 
/// @param b        Buffer con datos
/// @param p        Parser
/// @param error    Se setea a true si hay error de protocolo
/// @return Estado actual del parser
enum auth_state auth_consume(buffer *b, struct auth_parser *p, bool *error);

/// @brief Validacion de si el parse se completó o no
/// @param  
/// @param error 
/// @return True si el parseo está completo
bool auth_is_done(enum auth_state state, bool *error);

/// @brief Escribe la respeusta de autenticación al buffer
/// @param b Buffer donde escribir
/// @param status Success o Failure 
/// @return 0 si OK, -1 si se llenó el buffer
int auth_marshall(buffer *b, enum auth_status status);

#endif