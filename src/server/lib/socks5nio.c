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
#include "stm.h"
#include "socks5nio.h"
#include "netutils.h"

#define BUFFER_SIZE 8192

#define N(x) (sizeof(x)/sizeof((x)[0]))


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
     *      - ERRO          ante cualquier error
     */
    REQUEST_WRITE,

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

////////////////////////////////////////////////////////////////////
// Definición de variables para cada estado

/** usado por HELLO_READ, HELLO_WRITE */
struct hello_st {
    /** buffer utilizado para I/O */
    buffer               *rb, *wb;
    struct hello_parser   parser;
    /** el método de autenticación seleccionado */
    uint8_t               method;
} ;

struct request_st {
    buffer                 *rb, *wb;
    struct request_parser   parser;     
    enum socks_reply        reply;      
    
    struct addrinfo        *current_addr;  
};

struct connecting {
    int             *fd;
    struct addrinfo *current_addr;
};

struct copy {
    int     *fd;
    buffer  *rb, *wb;

    int     duplex;

    struct copy *other;
};

enum copy_duplex {
    DUPLEX_READ = 1 << 0,
    DUPLEX_WRITE = 1 << 1,
};

/*
 * Si bien cada estado tiene su propio struct que le da un alcance
 * acotado, disponemos de la siguiente estructura para hacer una única
 * alocación cuando recibimos la conexión.
 *
 * Se utiliza un contador de referencias (references) para saber cuando debemos
 * liberarlo finalmente, y un pool para reusar alocaciones previas.
 */
struct socks5 {
// …
    /** maquinas de estados */
    struct state_machine          stm;

    /** estados para el client_fd */
    union {
        struct hello_st           hello;
        struct request_st         request;
        struct copy               copy;
    } client;
    /** estados para el origin_fd */
    union {
        struct connecting         conn;
        struct copy               copy;
    } orig;

    int                     client_fd;
    struct sockaddr_storage client_addr;
    socklen_t               client_addr_len;

    int                     origin_fd;
    struct addrinfo         *origin_resolution;

    uint8_t                 raw_buff_a[BUFFER_SIZE];
    uint8_t                 raw_buff_b[BUFFER_SIZE];
    buffer                  read_buffer;
    buffer                  write_buffer;

    struct socks5           *next;
    uint32_t                references;
};

static const uint32_t       max_pool    = 50;  // ? - Esta en minusculas, asumo que es un static const, pero no debería ser un #define?
static uint32_t             pool_size   = 0;
static struct socks5        *pool       = NULL;

// Forward declarations
static void hello_read_init(const unsigned state, struct selector_key *key);
static unsigned hello_read(struct selector_key *key);
static unsigned hello_write(struct selector_key *key);
static unsigned hello_process(struct selector_key *key);

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
        // .on_arrival         = request_init,         // TODO
        // .on_read_ready      = request_read,         // TODO
    },{
        .state              = REQUEST_RESOLVE,
        // .on_block_ready     = request_resolve_done, // TODO
    },{
        .state              = REQUEST_CONNECTING,
        // .on_arrival         = connecting_init,      // TODO
        // .on_write_ready     = request_connecting,   // TODO
    },{
        .state              = REQUEST_WRITE,
        // .on_write_ready     = request_write,        // TODO
    },{
        .state              = COPY,
        // .on_arrival         = copy_init,            // TODO
        // .on_read_ready      = copy_read,            // TODO
        // .on_write_ready     = copy_write,           // TODO
    },{
        .state              = DONE,
    },{
        .state              = ERROR
    }
};

/** realmente destruye */
static void
socks5_destroy_(struct socks5* s) {
    if(s->origin_resolution != NULL) {
        freeaddrinfo(s->origin_resolution);
        s->origin_resolution = 0;
    }
    free(s);
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
            if(pool_size < max_pool) {
                s->next = pool;
                pool    = s;
                pool_size++;
            } else {
                socks5_destroy_(s);
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
    
    uint8_t method = 0x00;  // NO_AUTH
    
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
            ret = DONE;  // Or REQUEST_READ if continuing
            selector_set_interest_key(key, OP_NOOP);
        }
    }
    
    return ret;
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
    
    if (s != NULL) {
        if (s->client_fd != -1) {
            close(s->client_fd);
            s->client_fd = -1;
        }
        
        if (s->origin_fd != -1) {
            close(s->origin_fd);
            s->origin_fd = -1;
        }
        
        free(s);
    }
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
