#ifndef REQUEST_H
#define REQUEST_H

/**
 * request.h - Parser para REQUEST de SOCKSv5
 */

#include <stdbool.h>

#include "buffer.h"

// https://en.wikipedia.org/wiki/SOCKS#SOCKS5:~:text=Client%20connection%20request 
enum socks_cmd {
    SOCKS_CMD_CONNECT       = 0x01,
    SOCKS_CMD_BIND          = 0x02,
    SOCKS_CMD_UPD_ASSOCIATE = 0x03
};

// https://en.wikipedia.org/wiki/SOCKS#SOCKS5:~:text=SOCKS5%20address
enum socks_atyp {
    SOCKS_ATYP_IPV4     = 0x01,
    SOCKS_ATYP_DOMAIN   = 0x03,
    SOCKS_ATYP_IPV6     = 0x04,
};

// https://en.wikipedia.org/wiki/SOCKS#SOCKS5:~:text=Response%20packet%20from%20server
enum socks_reply {
    SOCKS_REPLY_SUCCEEDED                   = 0x00,
    SOCKS_REPLY_GENERAL_FAILURE             = 0x01,
    SOCKS_REPLY_CONNECTION_NOT_ALLOWED      = 0x02,
    SOCKS_REPLY_NETWORK_UNREACHABLE         = 0x03,
    SOCKS_REPLY_HOST_UNREACHABLE            = 0x04,
    SOCKS_REPLY_CONNECTION_REFUSED          = 0x05,
    SOCKS_REPLY_TTL_EXPIRED                 = 0x06,
    SOCKS_REPLY_COMMAND_NOT_SUPPORTED       = 0x07,
    SOCKS_REPLY_ADDRESS_TYPE_NOT_SUPPORTED  = 0x08,
};

enum request_state {
    REQUEST_VERSION,
    REQUEST_CMD,
    REQUEST_RSV,
    REQUEST_ATYP,
    REQUEST_DSTADDR_FQDN_LEN,
    REQUEST_DSTADDR_FQDN,
    REQUEST_DSTADDR_IPV4,
    REQUEST_DSTADDR_IPV6,
    REQUEST_DSTPORT,
    REQUEST_DONE,
    REQUEST_ERROR,
};

struct request_parser
{
    enum request_state state;

    uint8_t version;
    uint8_t cmd;
    uint8_t atyp;

    union
    {
        uint8_t ipv4[4];
        uint8_t ipv6[16];
        char domain[256]
    } dest_addr;
    
    // para fqdn
    uint8_t domain_len;
    uint8_t domain_bytes_Read;

    // para ipv4/6
    uint8_t addr_bytes_read;

    // port
    uint16_t dest_port;
    uint8_t port_bytes_Read;

    void *data;
} request_parser;

/// @brief Inicializa el parser
/// @param p 
void request_parser_init(struct request_parser *p);

/// @brief Parsea datos del buffer
/// @param b        Buffer con datos
/// @param p        Parser
/// @param error    Se setea a true si hay error de protocolo
/// @return Estado del parser
enum request_state request_consume(buffer *b, struct request_parser *p, bool *error);

/// @brief Validacion de completitud del parseo
/// @param state
/// @param error 
/// @return True si el parseo esta completo
bool is_request_done(enum request_state state, bool *error);

/// @brief Escribe la respuesta REQUEST al buffer
/// @param b        Buffer donde escribir
/// @param reply    Código de respuesta
/// @return 0 si OK, -1 si el buffer se llenó
int request_marshall(buffer *b, enum socks_reply reply);

/// @brief Cierra el parser
/// @param p 
void request_parser_close(struct request_parser *p);


#endif