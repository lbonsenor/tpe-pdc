#ifndef SELECTOR_H
#define SELECTOR_H

#include <time.h>

/**
 * selector.h - Multiplexor de I/O no bloqueante usando epoll()
 * 
 * Permite registrar file descriptors y asociar callbacks para eventos de read, write y 
 * close de una conexión
 * 
 * Se decidió hacer el cambio de select() a epoll() por razones de performance y escalabilidad
 */

typedef struct fdselector *fd_selector;

typedef enum {
    SELECTOR_SUCCESS    = 0,
    SELECTOR_ENOMEM     = 1,
    SELECTOR_MAXFD      = 2,
    SELECTOR_IARGS      = 3,
    SELECTOR_IO         = 4,
} selector_status;

/// @brief Conjunto de BIT Flags que indican el tipo de operacion
typedef enum {
    OP_NOOP     = 0,
    OP_READ     = 1 << 0,
    OP_WRITE    = 1 << 1,
    OP_BLOCK    = 1 << 2,
} fd_interest;

typedef struct selector_key 
{
    fd_selector s;
    int         fd;
    void        *data;  // Datos arbitrarios
} selector_key;

/**
 * Callback para eventos de un fd.
 * Todos los callbacks reciben la misma estructura selector_key.
 */
typedef struct fd_handler {
    void (*handle_read)  (struct selector_key *key);
    void (*handle_write) (struct selector_key *key);
    void (*handle_block) (struct selector_key *key);
    void (*handle_close) (struct selector_key *key);
} fd_handler;

/// @brief Configuración inicial del selector
struct selector_init {
    int signal;
    struct timespec select_timeout;
};

/// @brief      Inicia la librería
/// @param conf Configuración inicial del selector
/// @return     SELECTOR_IARGS en caso de que la configuración este vacía
selector_status selector_init(const struct selector_init *conf);

/// @brief      Libera los recursos globales 
/// @return     Si la función logró realizarse o, en su defecto, el tipo de error
selector_status selector_close(void);

/// @brief Crea un nuevo selector
/// @param max_fds La cantidad máxima de file descriptors
/// @return 
fd_selector selector_new(const size_t max_fds);

/// @brief Destruye un selector
/// @param s El selector a destruir
/** Destroy selector and free all resources */
void selector_destroy(fd_selector s);

/// @brief Registra un fd en el selector
/// @param s        Selector
/// @param fd       File Descriptor
/// @param handler  Callback para los eventos del fd
/// @param event    Eventos iniciales
/// @param data     Puntero arbitrario que se pasará a los callbacks
/// @return 
selector_status selector_register(fd_selector s, int fd, const fd_handler * handler, fd_interest event, void *data);

/// @brief Desregistra un file descriptor del selector
/// @param s    Selector
/// @param fd   File Descriptor
/// @return 
void selector_unregister(fd_selector s, const int fd);

/// @brief Modifica los eventos de un file descriptor ya registrado
/// @param s    Selector
/// @param fd   File Descriptor
/// @param i    Evento
/// @return 
selector_status selector_set_interest(fd_selector s, int fd, fd_interest i);

/// @brief Versión de selector_set_interest pero usando selector_key
/// @param key 
/// @param i 
/// @return 
selector_status selector_set_interest_key(struct selector_key *key, fd_interest i);

int selector_fd_set_nio(int fd);
selector_status selector_select(fd_selector s);
const char *selector_error(fd_selector s);

/// @brief Invalidates the data pointer for a given fd (sets to NULL)
/// @param s    Selector
/// @param fd   File Descriptor
void selector_invalidate_data(fd_selector s, int fd);

#endif