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
    // struct request_parser   parser;     // TODO - Commented until request.h is complete
    // enum socks_reply        reply;      // TODO - Commented until request.h is complete
    
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


/** realmente destruye */
static void
socks5_destroy_(struct socks5* s) {
    if(s->origin_resolution != NULL) {
        freeaddrinfo(s->origin_resolution);
        s->origin_resolution = 0;
    }
    free(s);
}

static void hello_read_init(const unsigned state, struct selector_key *key);
static unsigned hello_read(struct selector_key *key);
static unsigned hello_write(struct selector_key *key);  // Add this line
static unsigned hello_process(struct selector_key *key);

/** definición de handlers para cada estado */
static const struct state_definition client_statbl[] = {
    {
        .state            = HELLO_READ,
        .on_arrival       = hello_read_init,
        .on_read_ready    = hello_read,
    },
    {
        .state            = HELLO_WRITE,
        .on_write_ready   = hello_write,
    },
    {
        .state            = DONE,
        // No handlers - terminal state
    },
    {
        .state            = ERROR,
        // No handlers - terminal state
    },
};

static struct socks5 *
socks5_new(int client_fd) {
    printf("DEBUG: socks5_new called with fd=%d\n", client_fd);
    
    struct socks5 *ret = malloc(sizeof(*ret));
    
    printf("DEBUG: malloc returned %p\n", (void*)ret);
    
    if(ret == NULL) {
        goto finally;
    }
    
    memset(ret, 0x00, sizeof(*ret));
    
    printf("DEBUG: Initializing state machine\n");
    
    ret->client_fd = client_fd;
    
    // Initialize buffers
    buffer_init(&ret->read_buffer, N(ret->raw_buff_a), ret->raw_buff_a);
    buffer_init(&ret->write_buffer, N(ret->raw_buff_b), ret->raw_buff_b);
    
    ret->client.hello.rb = &(ret->read_buffer);
    ret->client.hello.wb = &(ret->write_buffer);
    
    // Initialize state machine BEFORE calling stm_init
    ret->stm.initial   = HELLO_READ;
    ret->stm.max_state = DONE;  // Change from ERROR to DONE
    ret->stm.states    = client_statbl;
    
    printf("DEBUG: About to call stm_init\n");
    stm_init(&ret->stm);
    printf("DEBUG: stm_init returned\n");
    
    printf("DEBUG: socks5_new completed successfully\n");
    
finally:
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
    
    printf("DEBUG: Accepted client fd=%d\n", client);
    
    if(client == -1) {
        goto fail;
    }
    
    printf("DEBUG: Setting client fd to non-blocking\n");
    if(selector_fd_set_nio(client) == -1) {
        printf("DEBUG: Failed to set non-blocking\n");
        goto fail;
    }
    
    printf("DEBUG: Creating socks5 state\n");
    state = socks5_new(client);
    if(state == NULL) {
        printf("DEBUG: Failed to create socks5 state\n");
        goto fail;
    }
    
    printf("DEBUG: Copying client address\n");
    memcpy(&state->client_addr, &client_addr, client_addr_len);
    state->client_addr_len = client_addr_len;

    printf("DEBUG: Registering client fd=%d with selector\n", client);
    if(SELECTOR_SUCCESS != selector_register(key->s, client, &socks5_handler,
                                              OP_READ, state)) {
        printf("DEBUG: Failed to register client with selector\n");
        goto fail;
    }
    
    printf("DEBUG: Successfully registered client\n");
    return;
    
fail:
    printf("DEBUG: In fail block, client=%d, state=%p\n", client, (void*)state);
    if(client != -1) {
        close(client);
    }
    socks5_destroy(state);
}

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
hello_write(struct selector_key *key) {
    struct hello_st *d = &ATTACHMENT(key)->client.hello;
    unsigned ret = HELLO_WRITE;
    
    printf("DEBUG: hello_write called for fd=%d\n", key->fd);
    
    buffer *b = d->wb;
    size_t nbytes;
    uint8_t *ptr = buffer_read_ptr(b, &nbytes);
    
    printf("DEBUG: Sending %zu bytes\n", nbytes);
    
    ssize_t n = send(key->fd, ptr, nbytes, MSG_NOSIGNAL);
    
    if (n == -1) {
        printf("DEBUG: send failed: %s\n", strerror(errno));
        ret = ERROR;
    } else {
        printf("DEBUG: Sent %zd bytes\n", n);
        buffer_read_adv(b, n);
        
        if (!buffer_can_read(b)) {
            printf("DEBUG: Write complete, transitioning to DONE\n");
            ret = DONE;  // HELLO handshake complete
            
            // Since we're done, close the connection or move to next state
            // For now, just mark as done
            selector_set_interest_key(key, OP_NOOP);  // No more events
        }
    }
    
    printf("DEBUG: hello_write returning state=%u\n", ret);
    return ret;
}

static unsigned
hello_process(struct selector_key *key) {
    struct hello_st *d = &ATTACHMENT(key)->client.hello;
    unsigned ret = HELLO_WRITE;
    
    // Determine which authentication method to use
    // For now, just accept NO AUTHENTICATION (0x00)
    uint8_t method = 0x00;
    
    // Marshall the response into write buffer
    if (hello_marshall(d->wb, method) == -1) {
        ret = ERROR;
    } else {
        // Switch to write mode
        selector_set_interest_key(key, OP_WRITE);
    }
    
    return ret;
}

static void
socksv5_done(struct selector_key *key) {
    // Unregister and close the connection
    if (key->fd != -1) {
        selector_unregister(key->s, key->fd);
        close(key->fd);
    }
}

static void
socksv5_read(struct selector_key *key) {
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    
    printf("DEBUG: socksv5_read called, current state=%u\n", stm->current);
    
    const enum socks_v5state st = stm_handler_read(stm, key);
    
    printf("DEBUG: stm_handler_read returned state=%u\n", st);
    
    if (ERROR == st || DONE == st) {
        printf("DEBUG: Terminal state reached in read, calling socksv5_done\n");
        socksv5_done(key);
    }
}

static void
socksv5_write(struct selector_key *key) {
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    
    printf("DEBUG: socksv5_write called, current state=%u\n", stm->current);
    
    const enum socks_v5state st = stm_handler_write(stm, key);
    
    printf("DEBUG: stm_handler_write returned state=%u\n", st);
    
    if (ERROR == st || DONE == st) {
        printf("DEBUG: Terminal state reached, calling socksv5_done\n");
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

static void
socksv5_close(struct selector_key *key) {
    socks5_destroy(ATTACHMENT(key));
}
