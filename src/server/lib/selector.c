#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <sys/eventfd.h>
#include <fcntl.h>
#include <errno.h>

#include <stdio.h>

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

fd_selector selector_new(const size_t initial_elements) {
    fd_selector s = calloc(1, sizeof(*s));
    
    if (s == NULL) {
        return NULL;
    }
    
    s->max_fds = initial_elements;
    s->fds = calloc(initial_elements, sizeof(*s->fds));
    
    for (size_t i = 0; i < initial_elements; i++)
    {
        s->fds[i].fd = INVALID_FD;
    }

    s->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
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
        free(s);
        return NULL;
    }
    
    return s;
}

void selector_destroy(fd_selector s) {
    if (s == NULL) {
        return;
    }
    
    for (size_t i = 0; i < s->max_fds; i++) {
        if (s->fds[i].fd != INVALID_FD) {
            if (s->fds[i].handler.handle_close) {
                struct selector_key key = {
                    .s = s,
                    .fd = s->fds[i].fd,
                    .data = s->fds[i].data,
                };
                s->fds[i].handler.handle_close(&key);
            }
            
            // Don't close here - handle_close is responsible for cleanup
            // Just mark as invalid in case handle_close didn't
            if (s->fds[i].fd != INVALID_FD) {
                close(s->fds[i].fd);
                s->fds[i].fd = INVALID_FD;
            }
        }
    }
    
    if (s->epoll_fd != -1) {
        close(s->epoll_fd);
    }
    
    free(s->fds);
    free(s);
}

selector_status selector_register(fd_selector s, int fd, const fd_handler *handler,
                                   fd_interest interest, void *data) {
    if (s == NULL || handler == NULL || fd < 0 || fd >= (int)s->max_fds) {
        return SELECTOR_IARGS;
    }
    
    pthread_mutex_lock(&s->mutex);

    if (s->fds[fd].fd != INVALID_FD)
    {
        pthread_mutex_unlock(&s->mutex);
        return SELECTOR_IARGS;
    }
    
    s->fds[fd].fd = fd;
    s->fds[fd].handler = *handler;
    s->fds[fd].data = data;
    
    struct epoll_event event;
    event.events = 0;
    
    if (interest & OP_READ) {
        event.events |= EPOLLIN;
    }
    if (interest & OP_WRITE) {
        event.events |= EPOLLOUT;
    }
    
    event.data.ptr = &s->fds[fd];
    
    if (epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0) {
        return SELECTOR_IO;
    }
    
    pthread_mutex_unlock(&s->mutex);
    return SELECTOR_SUCCESS;
}

void
selector_unregister(fd_selector s, const int fd) {
    if (s == NULL || fd < 0 || fd >= (int)s->max_fds) {
        return;
    }
    
    struct item *item = &s->fds[fd];
    
    if (item->fd == INVALID_FD) {
        return;
    }
    
    if (s->epoll_fd != -1) {
        struct epoll_event ev = {0};
        epoll_ctl(s->epoll_fd, EPOLL_CTL_DEL, fd, &ev);
    }
    
    close(fd);
    
    item->fd = INVALID_FD;
    item->interest = OP_NOOP;
    item->data = NULL;
}

selector_status selector_set_interest(fd_selector s, int fd, fd_interest interest) {
    if (s == NULL || fd < 0 || fd >= (int)s->max_fds) {
        return SELECTOR_IARGS;
    }
    
    struct epoll_event event;
    event.events = 0;
    event.data.ptr = &s->fds[fd];
    
    if (interest & OP_READ) {
        event.events |= EPOLLIN;
    }
    if (interest & OP_WRITE) {
        event.events |= EPOLLOUT;
    }
    
    if (epoll_ctl(s->epoll_fd, EPOLL_CTL_MOD, fd, &event) < 0) {
        return SELECTOR_IO;
    }
    
    return SELECTOR_SUCCESS;
}

selector_status selector_set_interest_key(struct selector_key *key, fd_interest interest) {
    if (key == NULL || key->s == NULL) {
        return SELECTOR_IARGS;
    }
    
    fd_selector s = key->s;
    int fd = key->fd;
    
    if (fd < 0 || fd >= (int)s->max_fds) {
        return SELECTOR_IARGS;
    }
    
    struct epoll_event event;
    event.events = 0;
    event.data.ptr = &s->fds[fd];
    
    if (interest & OP_READ) {
        event.events |= EPOLLIN;
    }
    if (interest & OP_WRITE) {
        event.events |= EPOLLOUT;
    }
    
    if (epoll_ctl(s->epoll_fd, EPOLL_CTL_MOD, fd, &event) < 0) {
        return SELECTOR_IO;
    }
    
    return SELECTOR_SUCCESS;
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
                  selector_config.select_timeout.tv_nsec / 1000000;
    
    int n = epoll_wait(s->epoll_fd, events, MAX_EVENTS, timeout);
    
    if (n < 0) {
        if (errno == EINTR) {
            return SELECTOR_SUCCESS;
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
                // Check if fd was unregistered during handler
                if (it->fd == INVALID_FD || it->data == NULL) {
                    continue;
                }
            }
        }
        
        if (e->events & EPOLLOUT) {
            if (it->handler.handle_write) {
                it->handler.handle_write(&key);
                // Check if fd was unregistered during handler
                if (it->fd == INVALID_FD || it->data == NULL) {
                    continue;
                }
            }
        }
        
        if (e->events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
            // Double-check fd is still valid and data not invalidated
            if (it->fd != INVALID_FD && it->data != NULL && it->handler.handle_close) {
                key.data = it->data;  // Refresh key data
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

void
selector_invalidate_data(fd_selector s, int fd) {
    if (s == NULL || fd < 0 || (size_t)fd >= s->max_fds) {
        return;
    }
    if (s->fds[fd].fd == fd) {
        s->fds[fd].data = NULL;
    }
}