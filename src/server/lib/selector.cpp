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
        s->fds[i].fd = -1;                      // Los inicializo como invalidos
    }

    s->epoll_fd = epoll_create1(EPOLL_CLOEXEC); // Close-On-Exec
    if (s->epoll_fd == -1)
    {
        free(s->fds);
        free(s);
        return NULL;
    }

    s->event_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC); // Por pedido de la catedra tienen que ser NO bloqueantes
    if (s->event_fd == -1)
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
