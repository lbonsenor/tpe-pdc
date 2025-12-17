#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <sys/eventfd.h>
#include <fcntl.h>
#include <errno.h>  // Add this at the top with other includes

#include "../include/selector.h"
#include "selector.h"

#define ERROR_DEFAULT_MSG "Something went wrong"
#define MAX_EVENTS 64
#define INVALID_FD -1

/** Configuración global del selector */
static struct selector_init selector_config;

typedef struct item
{
    int         fd;
    fd_interest interest;
    fd_handler  handler;
    void        *data;
} item;

struct fdselector {
    item        *fds;
    size_t      max_fds;

    int         epoll_fd;
    int         event_fd;

    pthread_mutex_t mutex;
};


selector_status selector_init(const struct selector_init *conf)
{
    if (conf == NULL)
    {
        return SELECTOR_IARGS;
    }
    
    memcpy(&selector_config, conf, sizeof(selector_config));
    return SELECTOR_SUCCESS;
}

selector_status selector_close(void)
{
    return SELECTOR_SUCCESS;
}

fd_selector selector_new(const size_t max_fds)
{
    fd_selector s = (fd_selector) malloc(sizeof(*s));
    if (s == NULL)
    {
        return NULL;
    }
    
    s->max_fds = max_fds;
    s->fds = (item*) calloc(max_fds, sizeof(*s->fds));

    if (s->fds == NULL)
    {
        free(s);
        return NULL;
    }
    
    for (size_t i = 0; i < max_fds; i++)
    {
        s->fds[i].fd = INVALID_FD;                      // Los inicializo como invalidos
    }

    s->epoll_fd = epoll_create1(EPOLL_CLOEXEC); // Close-On-Exec
    if (s->epoll_fd == INVALID_FD)
    {
        free(s->fds);
        free(s);
        return NULL;
    }

    s->event_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC); 
    if (s->event_fd == INVALID_FD)
    {
        close(s->epoll_fd);
        free(s->fds);
        free(s);                
        return NULL;
    }
    
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = s->event_fd;
    if (epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, s->event_fd, &ev) == -1)
    {
        close(s->event_fd);
        close(s->epoll_fd);
        free(s->fds);
        free(s);                
        return NULL;
    }

    if (pthread_mutex_init(&s->mutex, NULL) != 0)
    {
        epoll_ctl(s->epoll_fd, EPOLL_CTL_DEL, s->event_fd, NULL);
        close(s->event_fd);
        close(s->epoll_fd);
        free(s->fds);
        free(s);                // ? - Posiblemente debería ser un jump, repite codigo 
        return NULL;
    }
    
    return s;
}

void selector_destroy(fd_selector s) {
    if (s == NULL) {
        return;
    }
    
    // Close epoll_fd BEFORE freeing s->fds
    if (s->epoll_fd != -1) {
        close(s->epoll_fd);
    }
    
    if (s->event_fd != -1) {
        close(s->event_fd);
    }
    
    // Unregister all file descriptors
    if (s->fds != NULL) {
        for (size_t i = 0; i < s->max_fds; i++) {
            if (s->fds[i].fd != INVALID_FD) {
                // Don't close the fd here, just clean up
                s->fds[i].fd = INVALID_FD;
            }
        }
        free(s->fds);  // Free fds array
        s->fds = NULL; // Prevent double-free
    }
    
    free(s);  // Free the selector itself LAST
}

static u_int32_t interest_to_epoll(fd_interest interest) { 
    uint32_t events = 0;

    // Binary math
    if (interest & OP_READ)
    {
        events = interest | EPOLLIN;
    }
    
    if (interest & OP_WRITE)
    {
        events = interest | EPOLLOUT;
    }
    
    // Es buena practica monitorear errores/excepciones
    events = events | EPOLLERR | EPOLLHUP | EPOLLRDHUP;   // Error | Hung Up | Peer Closed Write Side
    return events;
    
}

selector_status selector_register(fd_selector s, int fd, const fd_handler *handler, fd_interest interest, void *data)
{
    if (s == NULL || fd < 0 || fd >= (int)s->max_fds || handler == NULL)
    {
        return SELECTOR_IARGS;
    }
    
    pthread_mutex_lock(&s->mutex);

    if (s->fds[fd].fd != INVALID_FD)
    {
        pthread_mutex_unlock(&s->mutex);
        return SELECTOR_IARGS;
    }
    
    s->fds[fd].fd = fd;
    s->fds[fd].data = data;
    s->fds[fd].interest = interest;
    s->fds[fd].handler = *handler;

    struct epoll_event ev;
    ev.events = interest_to_epoll(interest);
    ev.data.fd = fd;

    if (epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1)
    {
        s->fds[fd].fd = -1;
        pthread_mutex_unlock(&s->mutex);
        return SELECTOR_IO;
    }

    pthread_mutex_unlock(&s->mutex);
    return SELECTOR_SUCCESS;
}

selector_status selector_unregister(fd_selector s, int fd) { 
    if (s == NULL || fd < 0 || fd >= (int) s->max_fds)
    {
        return SELECTOR_IARGS;
    }

    pthread_mutex_lock(&s->mutex);
    
    if (s->fds[fd].fd == INVALID_FD)
    {
        pthread_mutex_unlock(&s->mutex);
        return SELECTOR_IARGS;
    }

    epoll_ctl(s->epoll_fd, EPOLL_CTL_DEL, fd, NULL);

    s->fds[fd].fd = INVALID_FD;
    s->fds[fd].interest = OP_NOOP;
    
    pthread_mutex_unlock(&s->mutex);
    return SELECTOR_SUCCESS;
}

selector_status selector_set_interest(fd_selector s, int fd, fd_interest i) {
    if (s == NULL || fd < 0 || fd >= (int) s->max_fds)
    {
        return SELECTOR_IARGS;
    }

    pthread_mutex_lock(&s->mutex);

    if (s->fds[fd].fd == INVALID_FD)
    {
        pthread_mutex_unlock(&s->mutex);
        return SELECTOR_IARGS;
    }

    s->fds[fd].interest = i;
    
    struct epoll_event ev;
    ev.events = interest_to_epoll(i);
    ev.data.fd = fd;
    
    if (epoll_ctl(s->epoll_fd, EPOLL_CTL_MOD, fd, &ev) == -1)
    {
        pthread_mutex_unlock(&s->mutex);
        return SELECTOR_IO;
    }

    pthread_mutex_unlock(&s->mutex);
    return SELECTOR_SUCCESS;
}

selector_status selector_set_interest_key(struct selector_key *key, fd_interest i) {
    if (key == NULL) {
        return SELECTOR_IARGS;
    }
    return selector_set_interest(key->s, key->fd, i);
}

int selector_fd_set_nio(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

selector_status selector_select(fd_selector s) {
    if (s == NULL) {
        return SELECTOR_IARGS;
    }

    struct epoll_event events[MAX_EVENTS];
    int timeout = selector_config.select_timeout.tv_sec * 1000 + 
                  selector_config.select_timeout.tv_nsec / 1000000;  // Convert nanoseconds to milliseconds
    
    int n = epoll_wait(s->epoll_fd, events, MAX_EVENTS, timeout);
    
    if (n < 0) {
        if (errno == EINTR) {
            return SELECTOR_SUCCESS;  // Interrupted, not an error
        }
        return SELECTOR_IO;
    }
    
    for (int i = 0; i < n; i++) {
        struct epoll_event *e = &events[i];
        item *it = (item *)e->data.ptr;
        
        if (it == NULL || it->fd == INVALID_FD) {
            continue;
        }
        
        struct selector_key key = {
            .s    = s,
            .fd   = it->fd,
            .data = it->data,
        };
        
        if (e->events & EPOLLIN) {
            if (it->handler.handle_read) {
                it->handler.handle_read(&key);
            }
        }
        
        if (e->events & EPOLLOUT) {
            if (it->handler.handle_write) {
                it->handler.handle_write(&key);
            }
        }
        
        if (e->events & (EPOLLERR | EPOLLHUP)) {
            if (it->handler.handle_close) {
                it->handler.handle_close(&key);
            }
        }
    }
    
    return SELECTOR_SUCCESS;
}

const char *selector_error(fd_selector s) {
    (void)s;  // Unused parameter
    return strerror(errno);
}