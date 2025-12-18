#ifndef SOCKS5_H
#define SOCKS5_H

#include <netdb.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/socket.h>

#include "buffer.h"
#include "hello.h"
#include "request.h"
#include "auth.h"
#include "stm.h"

// Tamaño del buffer para I/O
#define BUFFER_SIZE 8192


// Enum para el estado del copiado (bitmask)
enum copy_duplex {
    DUPLEX_READ  = 1 << 0,
    DUPLEX_WRITE = 1 << 1,
};

/** usado por HELLO_READ, HELLO_WRITE */
struct hello_st {
    buffer               *rb, *wb;
    struct hello_parser   parser;
    uint8_t               method;
};

struct request_st {
    buffer                 *rb, *wb;
    struct request_parser   parser;     
    enum socks_reply        reply;      
    struct addrinfo        *current_addr;  
};

struct auth_st {
    buffer                  *rb, *wb;
    struct auth_parser      parser;
    enum auth_status        status;
};

struct connecting {
    int             *fd;
    struct addrinfo *current_addr;
};

struct copy {
    int     *fd;
    buffer  *rb, *wb;
    int     duplex; // Usa los valores de enum copy_duplex
    struct copy *other;
};

// La estructura principal del cliente
/*
 * Si bien cada estado tiene su propio struct que le da un alcance
 * acotado, disponemos de la siguiente estructura para hacer una única
 * alocación cuando recibimos la conexión.
 *
 * Se utiliza un contador de referencias (references) para saber cuando debemos
 * liberarlo finalmente, y un pool para reusar alocaciones previas.
 */
struct socks5 {
    struct state_machine          stm;

    union {
        struct hello_st           hello;
        struct request_st         request;
        struct auth_st            auth;
        struct copy               copy;
    } client;

    union {
        struct connecting         conn;
        struct copy               copy;
    } orig;

    int                     client_fd;
    struct sockaddr_storage client_addr;
    socklen_t               client_addr_len;

    int                     origin_fd;
    struct addrinfo         *origin_resolution; // Resultado del DNS asíncrono

    uint8_t                 raw_buff_a[BUFFER_SIZE];
    uint8_t                 raw_buff_b[BUFFER_SIZE];
    buffer                  read_buffer;
    buffer                  write_buffer;

    // Campos para access logging y métricas
    char                    username[256];      // Usuario autenticado
    char                    dest_host[256];     // Hostname o IP destino
    uint16_t                dest_port;          // Puerto destino
    time_t                  connect_time;       // Momento de conexión
    uint64_t                bytes_to_origin;    // Bytes enviados al destino
    uint64_t                bytes_from_origin;  // Bytes recibidos del destino

    struct socks5           *next;
    uint32_t                references;
};

// TODO verificar si lo vamos a usar o no
typedef struct socks5 client_session;

#endif