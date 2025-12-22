/**
 * socks5nio.c  - controla el flujo de un proxy SOCKSv5 (sockets no bloqueantes)
 */
//defines for freeaddrinfo (test feature macros)
#define _POSIX_C_SOURCE 200112L
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "buffer.h"
#include "hello.h"
#include "request.h"
#include "auth.h"
#include "stm.h"
#include "socks5nio.h"
#include "netutils.h"
#include "users.h"
#include "socks5.h"
#include "access_log.h"
#include "dissector.h"
#include "metrics.h"
#include "logger.h"

#define BUFFER_SIZE 8192

#define N(x) (sizeof(x)/sizeof((x)[0]))

// Estructura para pasar argumentos al hilo de resolución DNS
struct selector_resolution_args {
    char host[256];      // Copia del FQDN
    char service[16];    // Puerto como string
    int fd;              // File descriptor del cliente (para notificar al selector)
    fd_selector s;       // Puntero al selector principal
};

/** maquina de estados general */
enum socks_v5state {
    /**
     * recibe el mensaje `hello` del cliente, y lo procesa
     *
     * Intereses:
     *     - OP_READ sobre client_fd
     *
     * Transiciones:
     *   - HELLO_READ  mientras el mensaje no esté completo
     *   - HELLO_WRITE cuando está completo
     *   - ERROR       ante cualquier error (IO/parseo)
     */
    HELLO_READ,

    /**
     * envía la respuesta del `hello' al cliente.
     *
     * Intereses:
     *     - OP_WRITE sobre client_fd
     *
     * Transiciones:
     *   - HELLO_WRITE  mientras queden bytes por enviar
     *   - REQUEST_READ cuando se enviaron todos los bytes
     *   - ERROR        ante cualquier error (IO/parseo)
     */
    HELLO_WRITE,

    /**
     * recibe el mensaje `request` del cliente y lo procesa
     * 
     * Intereses:
     *      - OP_READ sobre client_fd
     *
     * Transiciones:
     *      - REQUEST_READ      mientras el mensaje no esté completo
     *      - REQUEST_RESOLVE   si necesita resolver el hostname
     *      - REQUEST_CONNECT   si puede conectar directamente
     *      - ERROR             ante cualquier error
     */
    REQUEST_READ,

    /**
     * resuelve el FQDN del request de forma asincronica
     * 
     * Intereses:
     *      - OP_NOOP
     * 
     * Transiciones:
     *      - REQUEST_CONNECTING    cuando la resolución está lista
     *      - ERROR                  si falla la resolución
     */
    REQUEST_RESOLVE,
    
    /**
     * intenta conectar al origin server
     * 
     * Intereses:
     *      - OP_WRITE sobre origin_fd
     * 
     * Transiciiones:
     *      - REQUEST_CONNECTING    mientras no se complete
     *      - REQUEST_WRITE         cuando se conecta exitosamente
     *      - ERROR                 si falla la conexión
     */
    REQUEST_CONNECTING,
    
    /**
     * envía la rta del request al cliente
     * 
     * Intereses:
     *      - OP_WRITE sobre client_fd
     * 
     * Transiciones:
     *      - REQUEST_WRITE mientras queden bytes
     *      - COPY          cuando se envió todo
     *      - ERROR         ante cualquier error
     */
    REQUEST_WRITE,

    /**
     * recibe las credenciales del cliente
     * 
     * Intereses:
     *      - OP_READ sobre client_fd
     *  
     * Transiciones:
     *      - AUTH_READ     mientras el mensaje no esté completo
     *      - AUTH_WRITE    cuando está completo
     *      - ERROR         ante cualquier error
     */
    AUTH_READ,

    /**
     * envía la respuesta de auth al client
     * 
     * Intereses:
     *      - OP_WRITE sobre client_fd
     * 
     * Transiciones:
     *      - AUTH_WRITE    mientras queden bytes
     *      - REQUEST_READ  si la autenticación es exitosa
     *      - ERROR         si la auth falló o error I/O
     */
    AUTH_WRITE,

    /**
     * copia datos entre client y origin
     * 
     * Intereses:
     *      - OP_READ   si hay espacio en el write_buffer 
     *      - OP_WRITE  si hay datos en el read_buffer
     * 
     * Transiciones:
     *      - COPY  cuando hay datos para copiar
     *      - DONE  cuando ambas direcciones cerraron
     */
    COPY,

    // estados terminales
    DONE,
    ERROR,
};


static const uint32_t       max_pool    = 50;  // ? - Esta en minusculas, asumo que es un static const, pero no debería ser un #define?
static uint32_t             pool_size   = 0;
static struct socks5        *pool       = NULL;

// Forward declarations
static void hello_read_init(const unsigned state, struct selector_key *key);
static unsigned hello_read(struct selector_key *key);
static unsigned hello_write(struct selector_key *key);
static unsigned hello_process(struct selector_key *key);
static void request_init(const unsigned state, struct selector_key *key);
static unsigned request_read(struct selector_key *key);
static unsigned request_process(struct selector_key *key);
static void request_read_close(const unsigned state, struct selector_key *key);
static unsigned request_resolve_done(struct selector_key *key);
static void connecting_init(const unsigned state, struct selector_key *key);
static unsigned request_connecting(struct selector_key *key);
static unsigned request_write(struct selector_key *key);
static void copy_init(const unsigned state, struct selector_key *key);
static unsigned copy_read(struct selector_key *key);
static unsigned copy_write(struct selector_key *key);
static void auth_init(const unsigned state, struct selector_key *key);
static unsigned auth_read(struct selector_key *key);
static unsigned auth_write(struct selector_key *key);
static void auth_read_close(const unsigned state, struct selector_key *key);
// Prototipo de la función del hilo
static void *resolution_thread(void *arg);
static void request_resolve_init(const unsigned state, struct selector_key *key);

/** definición de handlers para cada estado */
static const struct state_definition client_statbl[] = {
    {
        .state              = HELLO_READ,
        .on_arrival         = hello_read_init,
        .on_read_ready      = hello_read,
    },{
        .state              = HELLO_WRITE,
        .on_write_ready     = hello_write,
    },{
        .state              = REQUEST_READ,
        .on_arrival         = request_init,
        .on_departure       = request_read_close,
        .on_read_ready      = request_read,
    },{
        .state            = REQUEST_RESOLVE,
        .on_arrival       = request_resolve_init, // Lanza el hilo
        .on_block_ready   = request_resolve_done, // Recibe el resultado (callback)
    },{
        .state              = REQUEST_CONNECTING,
        .on_arrival         = connecting_init,
        .on_write_ready     = request_connecting,
    },{
        .state              = REQUEST_WRITE,
        .on_write_ready     = request_write,
    },{
        .state              = AUTH_READ,
        .on_arrival         = auth_init,             
        .on_departure       = auth_read_close,       
        .on_read_ready      = auth_read,             
    },{
        .state              = AUTH_WRITE,
        .on_write_ready     = auth_write,           
    },{
        .state              = COPY,
        .on_arrival         = copy_init,
        .on_read_ready      = copy_read,
        .on_write_ready     = copy_write,
    },{
        .state              = DONE,
    },{
        .state              = ERROR
    }
};

static void *resolution_thread(void *arg) {
    struct selector_resolution_args *args = (struct selector_resolution_args *)arg;
    
    struct addrinfo hints = {
        .ai_family   = AF_UNSPEC,    // IPv4 o IPv6
        .ai_socktype = SOCK_STREAM,  // TCP
        .ai_flags    = AI_PASSIVE,
        .ai_protocol = 0,
    };
    struct addrinfo *result = NULL;

    int ret = getaddrinfo(args->host, args->service, &hints, &result);

    if (ret != 0) {
        // Falló la resolución: notificamos con NULL
        selector_notify_block_with_result(args->s, args->fd, NULL);
    } else {
        // Éxito: pasamos la lista de direcciones resuelta
        selector_notify_block_with_result(args->s, args->fd, result);
    }

    free(args); // Liberamos la memoria de los argumentos
    return NULL;
}

static struct socks5 *
socks5_new(int client_fd) {
    struct socks5 *ret;

    if (pool != NULL)
    {
        ret = pool;
        pool = pool->next;
        ret->next = NULL;
        pool_size--;
    } else
    {
        ret = malloc(sizeof(*ret));
        if (ret == NULL)
        {
            return NULL;
        }  
    }
    
    memset(ret, 0, sizeof(*ret));

    ret->client_fd          = client_fd;
    ret->origin_fd          = -1;
    ret->origin_resolution  = NULL;
    ret->references         = 1;

    buffer_init(&ret->read_buffer, BUFFER_SIZE, ret->raw_buff_a);
    buffer_init(&ret->write_buffer, BUFFER_SIZE, ret->raw_buff_b);

    ret->stm.initial    = HELLO_READ;
    ret->stm.max_state  = ERROR;
    ret->stm.states     = client_statbl;

    stm_init(&ret->stm);
    
    // Manually initialize hello state since on_arrival might not trigger
    ret->client.hello.rb = &ret->read_buffer;
    ret->client.hello.wb = &ret->write_buffer;
    hello_parser_init(&ret->client.hello.parser);
    
    return ret;
}

/**
 * destruye un  `struct socks5', tiene en cuenta las referencias
 * y el pool de objetos.
 */
static void
socks5_destroy(struct socks5 *s) {
    if(s == NULL) {
        // nada para hacer
    } else if(s->references == 1) {
        if(s != NULL) {
            // Clean up origin_resolution before pooling/freeing
            if(s->origin_resolution != NULL) {
                // Check if this is a manually allocated addrinfo (for direct IP)
                struct addrinfo *ai = s->origin_resolution;
                if (ai->ai_next == NULL && ai->ai_addr != NULL) {
                    // Likely manually allocated, free both addr and ai
                    free(ai->ai_addr);
                    free(ai);
                } else {
                    // From getaddrinfo, use freeaddrinfo
                    freeaddrinfo(s->origin_resolution);
                }
                s->origin_resolution = NULL;
            }
            
            if(pool_size < max_pool) {
                s->next = pool;
                pool    = s;
                pool_size++;
            } else {
                free(s);
            }
        }
    } else {
        s->references -= 1;
    }
}

void
socksv5_pool_destroy(void) {
    struct socks5 *next, *s;
    for(s = pool; s != NULL ; s = next) {
        next = s->next;
        free(s);
    }
}

/** obtiene el struct (socks5 *) desde la llave de selección  */
#define ATTACHMENT(key) ( (struct socks5 *)(key)->data)

/* declaración forward de los handlers de selección de una conexión
 * establecida entre un cliente y el proxy.
 */
static void socksv5_read   (struct selector_key *key);
static void socksv5_write  (struct selector_key *key);
static void socksv5_block  (struct selector_key *key);
static void socksv5_close  (struct selector_key *key);

static const struct fd_handler socks5_handler = {
    .handle_read   = socksv5_read,
    .handle_write  = socksv5_write,
    .handle_close  = socksv5_close,
    .handle_block  = socksv5_block,
};

/** Intenta aceptar la nueva conexión entrante*/
void
socksv5_passive_accept(struct selector_key *key) {
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    struct socks5 *state = NULL;

    const int client = accept(key->fd, (struct sockaddr*) &client_addr,
                                                          &client_addr_len);
    
    if(client == -1) {
        goto fail;
    }
    
    if(selector_fd_set_nio(client) == -1) {
        goto fail;
    }
    
    state = socks5_new(client);
    if(state == NULL) {
        goto fail;
    }
    
    memcpy(&state->client_addr, &client_addr, client_addr_len);
    state->client_addr_len = client_addr_len;
    
    // Inicializar campos para logging
    state->username[0] = '\0';
    state->dest_host[0] = '\0';
    state->dest_port = 0;
    state->connect_time = time(NULL);
    state->bytes_to_origin = 0;
    state->bytes_from_origin = 0;
    
    // Registrar nueva conexión en métricas
    metrics_connection_new();

    if(SELECTOR_SUCCESS != selector_register(key->s, client, &socks5_handler,
                                              OP_READ, state)) {
        goto fail;
    }
    
    return;
    
fail:
    if (state != NULL) {
        if (state->client_fd != -1) {
            close(state->client_fd);
        }
        free(state);
    } else if(client != -1) {
        close(client);
    }
}

// Keep these functions (they handle I/O, not protocol):

static void
hello_read_init(const unsigned state, struct selector_key *key) {
    (void)state;
    struct hello_st *d = &ATTACHMENT(key)->client.hello;
    
    d->rb = &(ATTACHMENT(key)->read_buffer);
    d->wb = &(ATTACHMENT(key)->write_buffer);
    
    hello_parser_init(&d->parser);
}

static unsigned
hello_read(struct selector_key *key) {
    struct hello_st *d = &ATTACHMENT(key)->client.hello;
    unsigned ret = HELLO_READ;
    bool error = false;
    
    buffer *b = d->rb;
    
    // Add safety check
    if (b == NULL) {
        // Buffer not initialized, initialize now
        d->rb = &(ATTACHMENT(key)->read_buffer);
        d->wb = &(ATTACHMENT(key)->write_buffer);
        hello_parser_init(&d->parser);
        b = d->rb;
    }
    
    size_t nbytes;
    uint8_t *ptr = buffer_write_ptr(b, &nbytes);
    ssize_t n = recv(key->fd, ptr, nbytes, 0);
    
    if (n > 0) {
        buffer_write_adv(b, n);
        enum hello_state st = hello_consume(b, &d->parser, &error);
        if (hello_is_done(st, &error)) {
            if (error) {
                ret = ERROR;
            } else {
                ret = hello_process(key);
            }
        }
    } else {
        ret = ERROR;
    }
    
    return ret;
}

static unsigned
hello_process(struct selector_key *key) {
    struct hello_st *d = &ATTACHMENT(key)->client.hello;
    unsigned ret = HELLO_WRITE;
    
    uint8_t method;

    if (users_count() > 0)
    {
        method = 0x02;
    } else
    {
        method = 0x00;
    }
    
    d->method = method;
    
    if (hello_marshall(d->wb, method) == -1) {  // Calls hello.c
        ret = ERROR;
    } else {
        selector_set_interest_key(key, OP_WRITE);
    }
    
    return ret;
}

static unsigned
hello_write(struct selector_key *key) {
    struct hello_st *d = &ATTACHMENT(key)->client.hello;
    unsigned ret = HELLO_WRITE;
    
    buffer *b = d->wb;
    size_t nbytes;
    uint8_t *ptr = buffer_read_ptr(b, &nbytes);
    ssize_t n = send(key->fd, ptr, nbytes, MSG_NOSIGNAL);
    
    if (n == -1) {
        ret = ERROR;
    } else {
        buffer_read_adv(b, n);
        if (!buffer_can_read(b)) {
            if (d->method == 0x02) ret  = AUTH_READ;  // Continue to request phase
            else ret                    = REQUEST_READ;
            
            selector_set_interest_key(key, OP_READ);
        }
    }
    
    return ret;
}

///////////////////////////////////////////////////////////////////////////////
// REQUEST handlers

static void
request_init(const unsigned state, struct selector_key *key) {
    (void)state;
    struct request_st *d = &ATTACHMENT(key)->client.request;
    
    d->rb = &(ATTACHMENT(key)->read_buffer);
    d->wb = &(ATTACHMENT(key)->write_buffer);
    d->reply = SOCKS_REPLY_GENERAL_FAILURE;
    
    request_parser_init(&d->parser);
}

static unsigned
request_read(struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;
    unsigned ret = REQUEST_READ;
    bool error = false;
    
    buffer *b = d->rb;
    size_t nbytes;
    uint8_t *ptr = buffer_write_ptr(b, &nbytes);
    ssize_t n = recv(key->fd, ptr, nbytes, 0);
    
    if (n > 0) {
        buffer_write_adv(b, n);
        enum request_state st = request_consume(b, &d->parser, &error);
        
        if (is_request_done(st, &error)) {
            if (error) {
                d->reply = SOCKS_REPLY_GENERAL_FAILURE;
                ret = ERROR;
            } else {
                ret = request_process(key);
            }
        }
    } else if (n == 0) {
        ret = DONE;
    } else {
        d->reply = SOCKS_REPLY_GENERAL_FAILURE;
        ret = ERROR;
    }
    
    return ret;
}

static unsigned
request_process(struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;
    struct socks5 *s = ATTACHMENT(key);

    fprintf(stderr,
        "[REQ] version=%u cmd=%u atyp=%u port=%u\n",
        d->parser.version,
        d->parser.cmd,
        d->parser.atyp,
        d->parser.dest_port);
    
    // Guardar destino para logging
    s->dest_port = d->parser.dest_port;
    if (d->parser.atyp == SOCKS_ATYP_DOMAIN) {
        strncpy(s->dest_host, d->parser.dest_addr.domain, sizeof(s->dest_host) - 1);
        s->dest_host[sizeof(s->dest_host) - 1] = '\0';
    } else if (d->parser.atyp == SOCKS_ATYP_IPV4) {
        inet_ntop(AF_INET, &d->parser.dest_addr.ipv4, s->dest_host, sizeof(s->dest_host));
    } else if (d->parser.atyp == SOCKS_ATYP_IPV6) {
        inet_ntop(AF_INET6, &d->parser.dest_addr.ipv6, s->dest_host, sizeof(s->dest_host));
    }

    // unused variable 'ret' removed
    
    if (d->parser.version != 5) {
        d->reply = SOCKS_REPLY_GENERAL_FAILURE;
        return ERROR;
    }
    
    if (d->parser.cmd != SOCKS_CMD_CONNECT) {
        d->reply = SOCKS_REPLY_COMMAND_NOT_SUPPORTED;
        return ERROR;
    }
    
    switch (d->parser.atyp) {
        case SOCKS_ATYP_IPV4:
        case SOCKS_ATYP_IPV6:
            d->current_addr = NULL; // IPs raw handled in connecting_init
            return REQUEST_CONNECTING;
        case SOCKS_ATYP_DOMAIN:
            return REQUEST_RESOLVE;
        default:
            d->reply = SOCKS_REPLY_ADDRESS_TYPE_NOT_SUPPORTED;
            // instead of going for ERROR, go to REQUEST_WRITE
            return REQUEST_WRITE;
    }
    // Nunca debería llegar aquí
    return ERROR;
}

static void
request_read_close(const unsigned state, struct selector_key *key) {
    (void)state;
    (void)key;
}

///////////////////////////////////////////////////////////////////////////////
// REQUEST_RESOLVE handlers

// 1. Al entrar al estado: Lanzamos el hilo
static void request_resolve_init(const unsigned state, struct selector_key *key) {
    (void)state;
    struct request_st *d = &ATTACHMENT(key)->client.request;
    
    struct selector_resolution_args *args = malloc(sizeof(*args));
    if (args == NULL) {
        d->reply = SOCKS_REPLY_GENERAL_FAILURE;
        selector_set_interest_key(key, OP_WRITE);
        return; // El state machine debería manejar el error
    }

    strncpy(args->host, d->parser.dest_addr.domain, sizeof(args->host) - 1);
    args->host[sizeof(args->host) - 1] = '\0';
    
    snprintf(args->service, sizeof(args->service), "%d", d->parser.dest_port);
    
    args->fd = key->fd;
    args->s  = key->s;

    pthread_t tid;
    // Creamos el hilo en modo detached (no necesitamos hacer join)
    if (pthread_create(&tid, NULL, resolution_thread, args) != 0) {
        free(args);
        d->reply = SOCKS_REPLY_GENERAL_FAILURE;
        selector_set_interest_key(key, OP_WRITE); // Ir a enviar error
    } else {
        pthread_detach(tid);
        // Desuscribimos el interés temporalmente.
        // El selector quedará "dormido" para este FD hasta que el hilo avise.
        selector_set_interest_key(key, OP_NOOP);
    }
}

// 2. Cuando el hilo termina (notificación del selector):
static unsigned request_resolve_done(struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;
    struct socks5 *s     = ATTACHMENT(key);

    // El selector modificado (el de referencia) ya inyectó el resultado en s->origin_resolution - VERIFICAR    
    if (s->origin_resolution == NULL) {
        // El hilo retornó NULL -> Falló el DNS
        d->reply = SOCKS_REPLY_HOST_UNREACHABLE;
        // Pasar por REQUEST_WRITE para enviar la respuesta de error
        return REQUEST_WRITE;
    }

    d->current_addr = s->origin_resolution;
    // Reactivamos intereses (el estado CONNECTING se encargará de poner OP_WRITE en el origin_fd)
    return REQUEST_CONNECTING;
}

/*
static unsigned
request_resolve_done(struct selector_key *key) {
    fprintf(stderr, "[RESOLVE_DONE] called\n");
    struct request_st *d = &ATTACHMENT(key)->client.request;
    struct socks5 *s = ATTACHMENT(key);
    
    if (s->origin_resolution == NULL) {
        d->reply = SOCKS_REPLY_HOST_UNREACHABLE;
        return ERROR;
    }
    
    d->current_addr = s->origin_resolution;
    return REQUEST_CONNECTING;
}
*/

///////////////////////////////////////////////////////////////////////////////
// REQUEST_CONNECTING handlers

static void
connecting_init(const unsigned state, struct selector_key *key) {
    fprintf(stderr, "[CONNECT_INIT] fd=%d atyp=%u\n", key->fd, ATTACHMENT(key)->client.request.parser.atyp);
    
    (void)state;
    struct connecting *d = &ATTACHMENT(key)->orig.conn;
    struct request_st *req = &ATTACHMENT(key)->client.request;
    struct socks5 *s = ATTACHMENT(key);
    
    d->fd = &s->origin_fd;

    selector_set_interest(key->s, s->client_fd, OP_NOOP);
    
    if (req->parser.atyp == SOCKS_ATYP_DOMAIN) {
        struct addrinfo hints = {
            .ai_family = AF_UNSPEC,
            .ai_socktype = SOCK_STREAM,
            .ai_flags = 0,
            .ai_protocol = 0,
        };
        
        char port_str[6];
        snprintf(port_str, sizeof(port_str), "%d", req->parser.dest_port);
        
        int ret = getaddrinfo(req->parser.dest_addr.domain, port_str, &hints, &s->origin_resolution);

        fprintf(stderr, "[CONNECT_INIT] getaddrinfo ret=%d res=%p\n", ret, (void *)s->origin_resolution);
        
        if (ret != 0 || s->origin_resolution == NULL) {
            req->reply = SOCKS_REPLY_HOST_UNREACHABLE;
            s->origin_resolution = NULL;
            return;
        }
        
        d->current_addr = s->origin_resolution;
    } else {
        struct addrinfo *ai = malloc(sizeof(struct addrinfo));
        if (ai == NULL) {
            req->reply = SOCKS_REPLY_GENERAL_FAILURE;
            return;
        }
        
        memset(ai, 0, sizeof(*ai));
        ai->ai_family = (req->parser.atyp == SOCKS_ATYP_IPV4) ? AF_INET : AF_INET6;
        ai->ai_socktype = SOCK_STREAM;
        
        if (ai->ai_family == AF_INET) {
            struct sockaddr_in *addr = malloc(sizeof(struct sockaddr_in));
            memset(addr, 0, sizeof(*addr));
            addr->sin_family = AF_INET;
            memcpy(&addr->sin_addr, req->parser.dest_addr.ipv4, 4);
            addr->sin_port = htons(req->parser.dest_port);
            ai->ai_addr = (struct sockaddr *)addr;
            ai->ai_addrlen = sizeof(*addr);
        } else {
            struct sockaddr_in6 *addr = malloc(sizeof(struct sockaddr_in6));
            memset(addr, 0, sizeof(*addr));
            addr->sin6_family = AF_INET6;
            memcpy(&addr->sin6_addr, req->parser.dest_addr.ipv6, 16);
            addr->sin6_port = htons(req->parser.dest_port);
            ai->ai_addr = (struct sockaddr *)addr;
            ai->ai_addrlen = sizeof(*addr);
        }
        
        s->origin_resolution = ai;
        d->current_addr = ai;
    }
    
    // Start connection attempt
    if (d->current_addr != NULL) {
        *d->fd = socket(d->current_addr->ai_family, 
                       d->current_addr->ai_socktype,
                       d->current_addr->ai_protocol);
        
        if (*d->fd != -1) {
            selector_fd_set_nio(*d->fd);
            
            int ret = connect(*d->fd, d->current_addr->ai_addr, d->current_addr->ai_addrlen);
            
            if (ret == -1 && (errno == EINPROGRESS || errno == EALREADY)) {
                // Register for write events to know when connection completes
                // Increment references since we're registering another fd
                s->references++;
                selector_register(key->s, *d->fd, &socks5_handler, OP_WRITE, ATTACHMENT(key));
            } else if (ret == 0) {
                // Connected immediately (unlikely but possible)
                s->references++;
                selector_register(key->s, *d->fd, &socks5_handler, OP_NOOP, ATTACHMENT(key));
            }
        }
    }
}

static unsigned
request_connecting(struct selector_key *key) {
    struct connecting *d = &ATTACHMENT(key)->orig.conn;
    struct request_st *req = &ATTACHMENT(key)->client.request;
    unsigned ret = REQUEST_CONNECTING;
    
    // Solo intentamos una dirección por vez, y solo avanzamos a la siguiente
    // si el intento anterior falló de inmediato. Si EINPROGRESS, esperamos evento.
    while (d->current_addr != NULL) {
        if (*d->fd == -1) {
            *d->fd = socket(d->current_addr->ai_family,
                           d->current_addr->ai_socktype,
                           d->current_addr->ai_protocol);
            if (*d->fd == -1) {
                fprintf(stderr, "[CONNECTING] socket() failed: %s\n", strerror(errno));
                d->current_addr = d->current_addr->ai_next;
                continue;
            }
            if (selector_fd_set_nio(*d->fd) == -1) {
                fprintf(stderr, "[CONNECTING] selector_fd_set_nio() failed: %s\n", strerror(errno));
                close(*d->fd);
                *d->fd = -1;
                d->current_addr = d->current_addr->ai_next;
                continue;
            }
        }

        fprintf(stderr, "[CONNECTING] intentando connect() a %p...\n", (void*)d->current_addr->ai_addr);
        int connect_ret = connect(*d->fd, d->current_addr->ai_addr, d->current_addr->ai_addrlen);
        if (connect_ret == 0 || (connect_ret == -1 && errno == EISCONN)) {
            fprintf(stderr, "[CONNECTING] connected OK\n");
            struct socks5 *s = ATTACHMENT(key);
            req->reply = SOCKS_REPLY_SUCCEEDED;
            ret = REQUEST_WRITE;
            selector_set_interest(key->s, *d->fd, OP_NOOP);
            selector_set_interest(key->s, s->client_fd, OP_WRITE);
            access_log_connection(
                s->username[0] != '\0' ? s->username : NULL,
                (struct sockaddr *)&s->client_addr,
                s->dest_host,
                s->dest_port,
                d->current_addr->ai_addr
            );
            return ret;
        } else if (connect_ret == -1 && (errno == EINPROGRESS || errno == EALREADY)) {
            fprintf(stderr, "[CONNECTING] EINPROGRESS/EALREADY, esperando evento de escritura\n");
            struct socks5 *s = ATTACHMENT(key);
            s->references++;
            selector_register(key->s, *d->fd, &socks5_handler, OP_WRITE, ATTACHMENT(key));
            // No avanzar a la siguiente dirección hasta que este intento termine
            return REQUEST_CONNECTING;
        } else {
            fprintf(stderr, "[CONNECTING] connect() fallo: %s\n", strerror(errno));
            close(*d->fd);
            *d->fd = -1;
            d->current_addr = d->current_addr->ai_next;
            // break para salir del ciclo y esperar próxima llamada
            break;
        }
    }

    // Si llegamos aquí y no quedan direcciones, fallaron todas
    if (d->current_addr == NULL) {
        fprintf(stderr, "[CONNECTING] todas las direcciones fallaron\n");
        req->reply = SOCKS_REPLY_HOST_UNREACHABLE;
        // Pasar por REQUEST_WRITE para enviar la respuesta de error
        return REQUEST_WRITE;
    }

    return ret;
}

///////////////////////////////////////////////////////////////////////////////
// REQUEST_WRITE handlers

static unsigned
request_write(struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;
    fprintf(stderr, "[REQUEST_WRITE] reply=%u\n", d->reply);
    unsigned ret = REQUEST_WRITE;
    
    buffer *b = d->wb;
    
    if (!buffer_can_read(b)) {
        if (request_marshall(b, d->reply) == -1) {
            ret = ERROR;
            return ret;
        }
    }

    size_t nbytes;
    uint8_t *ptr = buffer_read_ptr(b, &nbytes);
    ssize_t n = send(key->fd, ptr, nbytes, MSG_NOSIGNAL);

    if (n == -1) {
        ret = ERROR;
    } else {
        buffer_read_adv(b, n);
        if (!buffer_can_read(b)) {
            if (d->reply == SOCKS_REPLY_SUCCEEDED) {
                ret = COPY;
            } else {
                // Si fue un error, cerramos la conexión después de enviar la respuesta
                ret = DONE;
            }
        }
    }

    return ret;
}

///////////////////////////////////////////////////////////////////////////////
// AUTH handlers
static void
auth_init(const unsigned state, struct selector_key *key) {
    (void)state;
    struct auth_st *d = &ATTACHMENT(key)->client.auth;

    d->rb = &(ATTACHMENT(key)->read_buffer);
    d->wb = &(ATTACHMENT(key)->write_buffer);
    d->status = AUTH_STATUS_FAILURE;

    auth_parser_init(&d->parser);       // por defecto fallo

    buffer_reset(d->rb);
    buffer_reset(d->wb);
}

static unsigned
auth_read(struct selector_key *key) {
    struct auth_st *d = &ATTACHMENT(key)->client.auth;
    unsigned ret = AUTH_READ;
    bool error = false;

    buffer *b = d->rb;
    size_t nbytes;
    uint8_t *ptr = buffer_write_ptr(b, &nbytes);
    ssize_t n = recv(key->fd, ptr, nbytes, 0);

    if (n > 0)
    {
        buffer_write_adv(b, n);
        enum auth_state st = auth_consume(b, &d->parser, &error);
        if (auth_is_done(st, &error))
        {
            if (error)
            {
                d->status = AUTH_STATUS_FAILURE;
                ret = AUTH_WRITE;
                selector_set_interest_key(key, OP_WRITE);
            } else 
            {
                if (users_authenticate(d->parser.username, d->parser.password))
                {
                    struct socks5 *s = ATTACHMENT(key);
                    
                    // Guardar username para access logging
                    strncpy(s->username, d->parser.username, sizeof(s->username) - 1);
                    s->username[sizeof(s->username) - 1] = '\0';
                    
                    // Log autenticación exitosa
                    access_log_auth(d->parser.username, 
                                   (struct sockaddr *)&s->client_addr, 
                                   true);
                    metrics_auth_success();
                    
                    d->status = AUTH_STATUS_SUCCESS;
                    ret = AUTH_WRITE;
                } else
                {
                    struct socks5 *s = ATTACHMENT(key);
                    
                    // Log autenticación fallida
                    access_log_auth(d->parser.username,
                                   (struct sockaddr *)&s->client_addr,
                                   false);
                    metrics_auth_failed();
                    
                    d->status = AUTH_STATUS_FAILURE;
                    ret = AUTH_WRITE;
                }

                selector_set_interest_key(key, OP_WRITE);
            }
            
        }
        
    } else if (n == 0)
    {
        ret = DONE;
    } else 
    {
        d->status = AUTH_STATUS_FAILURE;
        ret = ERROR;
    }

    return ret;
    
}

static unsigned
auth_write(struct selector_key *key) {
    struct auth_st *d = &ATTACHMENT(key)->client.auth;
    unsigned ret = AUTH_WRITE;

    buffer *b = d->wb;

    if (!buffer_can_read(b))
    {
        if (auth_marshall(b, d->status) == -1)
        {
            ret = ERROR;
            return ret;
        }
        
    }
    
    size_t nbytes;
    uint8_t *ptr = buffer_read_ptr(b, &nbytes);

    ssize_t n = send(key->fd, ptr, nbytes, MSG_NOSIGNAL);

    if (n == -1)
    {
        ret = ERROR;
    } else
    {
        buffer_read_adv(b, n);
        if (!buffer_can_read(b))
        {
            if (d->status == AUTH_STATUS_SUCCESS)
            {
                ret = REQUEST_READ;
                selector_set_interest_key(key, OP_READ);
            } else
            {
                ret = ERROR;
            }
            
            
        }
        
    }
    
    return ret;
}

static void
auth_read_close(const unsigned state, struct selector_key *key) {
    (void) state;
    (void) key;
}

///////////////////////////////////////////////////////////////////////////////
// COPY handlers

static void
copy_init(const unsigned state, struct selector_key *key) {
    (void)state;
    struct socks5 *s = ATTACHMENT(key);
    
    // Compact read_buffer to move any pipelined data to the beginning
    buffer_compact(&s->read_buffer);
    
    // Reset write_buffer (SOCKS5 response was sent from here)
    buffer_reset(&s->write_buffer);
    
    // Client: read into read_buffer, write from write_buffer
    s->client.copy.fd = &s->client_fd;
    s->client.copy.rb = &s->write_buffer;  // Read from write_buffer to send to client
    s->client.copy.wb = &s->read_buffer;   // Write client data into read_buffer
    s->client.copy.duplex = DUPLEX_READ | DUPLEX_WRITE;
    s->client.copy.other = &s->orig.copy;
    
    // Origin: read into write_buffer, write from read_buffer
    s->orig.copy.fd = &s->origin_fd;
    s->orig.copy.rb = &s->read_buffer;     // Read from read_buffer to send to origin
    s->orig.copy.wb = &s->write_buffer;    // Write origin data into write_buffer
    s->orig.copy.duplex = DUPLEX_READ | DUPLEX_WRITE;
    s->orig.copy.other = &s->client.copy;
    
    // If there's data in read_buffer (pipelined from client), set origin to write
    if (buffer_can_read(&s->read_buffer)) {
        selector_set_interest(key->s, s->origin_fd, OP_WRITE);
        selector_set_interest_key(key, OP_NOOP);
    } else {
        selector_set_interest_key(key, OP_READ);
        selector_set_interest(key->s, s->origin_fd, OP_READ);
    }
}

static unsigned
copy_read(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    // Determine which side we're reading from
    struct copy *d = (key->fd == s->client_fd) ? &s->client.copy : &s->orig.copy;
    
    if (!(d->duplex & DUPLEX_READ)) {
        return COPY;
    }
    
    buffer *b = d->wb;
    size_t nbytes;
    uint8_t *ptr = buffer_write_ptr(b, &nbytes);
    
    if (nbytes == 0) {
        // Buffer is full, stop reading from this side
        selector_set_interest_key(key, OP_NOOP);
        return COPY;
    }
    
    ssize_t n = recv(key->fd, ptr, nbytes, 0);
    
    if (n > 0) {
        buffer_write_adv(b, n);
        
        // Rastrear bytes y diseccionar si es desde el cliente
        if (key->fd == s->client_fd) {
            s->bytes_to_origin += n;
            metrics_bytes_received(n);
            
            // Diseccionar datos del cliente buscando credenciales
            if (dissector_is_enabled()) {
                dissector_process_client_data(ptr, n, s->dest_host, s->dest_port);
            }
        } else {
            s->bytes_from_origin += n;
            metrics_bytes_sent(n);
        }
        
        // Enable writing on the other side
        selector_set_interest(key->s, *d->other->fd, OP_WRITE);
        // If buffer is now full, stop reading
        if (!buffer_can_write(b)) {
            selector_set_interest_key(key, OP_NOOP);
        }
    } else if (n == 0) {
        // EOF - close this read direction
        d->duplex &= ~DUPLEX_READ;
        selector_set_interest_key(key, OP_NOOP);  // Stop reading from this fd
        if (d->other->duplex & DUPLEX_WRITE) {
            // If there's no more data to send, close the write on the other side
            buffer *send_buf = d->other->rb;
            size_t pending_bytes;
            buffer_read_ptr(send_buf, &pending_bytes);
            if (pending_bytes == 0) {
                shutdown(*d->other->fd, SHUT_WR);
                d->other->duplex &= ~DUPLEX_WRITE;
            }
        }
    } else {
        return ERROR;
    }
    
    if (!(d->duplex & DUPLEX_READ) && !(d->duplex & DUPLEX_WRITE) &&
        !(d->other->duplex & DUPLEX_READ) && !(d->other->duplex & DUPLEX_WRITE)) {
        return DONE;
    }
    
    return COPY;
}

static unsigned
copy_write(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    // Determine which side we're writing to
    struct copy *d = (key->fd == s->client_fd) ? &s->client.copy : &s->orig.copy;
    
    if (!(d->duplex & DUPLEX_WRITE)) {
        return COPY;
    }
    
    buffer *b = d->rb;
    size_t nbytes;
    uint8_t *ptr = buffer_read_ptr(b, &nbytes);
    
    if (nbytes == 0) {
        // Nothing to write, disable writing and enable reading
        fd_interest new_interest = OP_NOOP;
        if (d->duplex & DUPLEX_READ) {
            new_interest = OP_READ;
        }
        selector_set_interest_key(key, new_interest);
        return COPY;
    }
    
    ssize_t n = send(key->fd, ptr, nbytes, MSG_NOSIGNAL);
    
    if (n > 0) {
        buffer_read_adv(b, n);
        // Buffer now has space, enable reading from the other side
        if (buffer_can_write(b)) {
            selector_set_interest(key->s, *d->other->fd, OP_READ);
        }
        // Check if we still have data to write
        if (!buffer_can_read(b)) {
            // No more data, switch to read if possible
            fd_interest new_interest = OP_NOOP;
            if (d->duplex & DUPLEX_READ) {
                new_interest = OP_READ;
            }
            selector_set_interest_key(key, new_interest);
        }
    } else {
        return ERROR;
    }
    
    if (!(d->duplex & DUPLEX_READ) && !(d->duplex & DUPLEX_WRITE) &&
        !(d->other->duplex & DUPLEX_READ) && !(d->other->duplex & DUPLEX_WRITE)) {
        return DONE;
    }
    
    return COPY;
}

///////////////////////////////////////////////////////////////////////////////
// Handlers top level de la conexión pasiva.
// son los que emiten los eventos a la maquina de estados.

static void
socksv5_done(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    
    if (s == NULL) {
        return;
    }
    
    if (s->origin_fd != -1) {
        selector_unregister(key->s, s->origin_fd);
        s->origin_fd = -1;
    }
    
    selector_unregister(key->s, key->fd);
    
    socks5_destroy(s);
}

static void
socksv5_close(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    
    if (s == NULL) {
        return;
    }
    
    // Log disconnect si llegó al estado de COPY (conexión establecida)
    if (s->dest_host[0] != '\0') {
        time_t duration = time(NULL) - s->connect_time;
        access_log_disconnect(
            s->username[0] != '\0' ? s->username : NULL,
            s->dest_host,
            s->dest_port,
            s->bytes_to_origin,
            s->bytes_from_origin,
            duration
        );
    }
    
    // Actualizar métricas
    metrics_connection_close();
    
    // Save values we need before any operations that might free s
    int client_fd = s->client_fd;
    int origin_fd = s->origin_fd;
    int this_fd = key->fd;
    fd_selector selector = key->s;
    
    // Unregister the other fd first (if it exists and is different)
    if (client_fd != -1 && origin_fd != -1 && client_fd != origin_fd) {
        int other_fd = (this_fd == client_fd) ? origin_fd : client_fd;
        selector_unregister(selector, other_fd);
    }
    
    // Unregister this fd (selector_unregister will close it)
    selector_unregister(selector, this_fd);
    
    // Decrement references - may free s
    socks5_destroy(s);
}

static void
socksv5_read(struct selector_key *key) {
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    
    const enum socks_v5state st = stm_handler_read(stm, key);
    
    if (ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void
socksv5_write(struct selector_key *key) {
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    
    const enum socks_v5state st = stm_handler_write(stm, key);
    
    if (ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void
socksv5_block(struct selector_key *key) {
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_block(stm, key);
    
    if (ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}
