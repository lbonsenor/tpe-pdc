#ifndef HELLO_H
#define HELLO_H

#include <stdbool.h>
#include <buffer.h>
#include <stdint.h>

/**
 * hello.h - Parser para mensaje HELLO de SOCKS5
 */

#define SOCKS_VERSION 0x05

// https://datatracker.ietf.org/doc/html/rfc1928#:~:text=METHOD,-are
enum socks_hello_method {
    SOCKS_HELLO_NOAUTHENTICATION_REQUIRED   = 0x00,
    SOCKS_HELLO_GSSAPI                      = 0x01,
    SOCKS_HELLO_USERNAME_PASSWORD           = 0x02,
    SOCKS_HELLO_NO_ACCEPTABLE_METHODS       = 0xFF
};

// https://datatracker.ietf.org/doc/html/rfc1928#:~:text=VER
enum hello_state {
    HELLO_VERSION,
    HELLO_NMETHODS,
    HELLO_METHODS,
    HELLO_DONE,
    HELLO_ERROR
};

struct hello_parser {
    enum hello_state state;

    uint8_t version;
    uint8_t nmethods; 
    uint8_t methods_read;

    void (*on_authentication_method)(struct hello_parser *p, uint8_t method);
    void *data;
};

/// @brief Inicializacion de un parser
/// @param p 
void hello_parser_init(struct hello_parser *p);

/// @brief Parsea datos del buffer
/// @param b        Buffer
/// @param p        Parser
/// @param error    Puntero a bool donde se seteara a true si hay error en el protocolo
/// @return Estado del Parser
enum hello_state hello_consume(buffer *b, struct hello_parser *p, bool *error);

/// @brief Verificacion si el parseo se completó
/// @param state
/// @param error 
/// @return 
bool hello_is_done(enum hello_state state, bool *error);

/// @brief Escribe la respuesta HELLO al buffer
/// @param b        Buffer donde escribir
/// @param method   Método seleccionado
/// @return 0 si OK, -1 si el buffer esta lleno
int hello_marshall(buffer *b, uint8_t method);

/// @brief Cierra el parser
/// @param p 
/// @return 
int hello_parser_close(struct hello_parser *p);

#endif