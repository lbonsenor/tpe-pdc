#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <sys/eventfd.h>

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
    fd_event    event;
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

void selector_destroy(fd_selector s)
{
    if (s == NULL)
    {
        return;         // ? - Quizas cambiar de void a selector_status 
    }

    if (s->fds != NULL)
    {
        for (size_t i = 0; i < s->max_fds; i++)
        {
            if (s->fds[i].fd != INVALID_FD 
                && s->fds[i].handler.handle_close != NULL)
            {
                struct selector_key key = {
                    .s = s,
                    .fd = s->fds[i].fd,
                    .data = s->fds[i].data,
                };
                s->fds[i].handler.handle_close(&key);
            }
            free(s->fds);
        }
    }

    if (s->epoll_fd != INVALID_FD)
    {
        close(s->epoll_fd);
    }

    if (s->event_fd != INVALID_FD)
    {
        close(s->event_fd);
    }
    
    pthread_mutex_destroy(&s->mutex);
    free(s);
}

static u_int32_t event_to_epoll(fd_event event) { 
    uint32_t events = 0;

    // Binary math
    if (event & OP_READ)
    {
        event = event | EPOLLIN;
    }
    
    if (event & OP_WRITE)
    {
        event = event | EPOLLOUT;
    }
    
    // Es buena practica monitorear errores/excepciones
    event = event | EPOLLERR | EPOLLHUP | EPOLLRDHUP;   // Error | Hung Up | Peer Closed Write Side
    return events;
    
}

selector_status selector_register(fd_selector s, int fd, const fd_handler *handler, fd_event event, void *data)
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
    s->fds[fd].event = event;
    s->fds[fd].handler = *handler;

    struct epoll_event ev;
    ev.events = event_to_epoll(event);
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
    s->fds[fd].event = OP_NOOP;
    
    pthread_mutex_unlock(&s->mutex);
    return SELECTOR_SUCCESS;
}

selector_status selector_set_event(fd_selector s, int fd, fd_event e) {
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

    s->fds[fd].event = e;
    
    struct epoll_event ev;
    ev.events = event_to_epoll(e);
    ev.data.fd = fd;
    
    if (epoll_ctl(s->epoll_fd, EPOLL_CTL_MOD, fd, &ev) == -1)
    {
        pthread_mutex_unlock(&s->mutex);
        return SELECTOR_IO;
    }

    pthread_mutex_unlock(&s->mutex);
    return SELECTOR_SUCCESS;
}

selector_status selector_set_event_key(struct selector_key *key, fd_event e) {
    if (key == NULL) {
        return SELECTOR_IARGS;
    }
    return selector_set_event(key->s, key->fd, e);
}