#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <sys/eventfd.h>
#include <fcntl.h>
#include <errno.h>  // Add this at the top with other includes
#include <stdio.h> // For debugging prints

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
    printf("DEBUG: selector_new called with initial_elements=%zu\n", initial_elements);
    
    fd_selector s = calloc(1, sizeof(*s));
    
    printf("DEBUG: calloc returned: %p\n", (void*)s);
    
    if (s == NULL) {
        return NULL;
    }
    
    s->max_fds = initial_elements;
    s->fds = calloc(initial_elements, sizeof(*s->fds));
    
    printf("DEBUG: allocated fds array: %p, size=%zu\n", (void*)s->fds, initial_elements);
    
    for (size_t i = 0; i < initial_elements; i++)
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
    
    printf("DEBUG: selector_destroy called\n");
    
    // Close all registered file descriptors and cleanup items
    for (size_t i = 0; i < s->max_fds; i++) {
        if (s->fds[i].fd != INVALID_FD) {
            printf("DEBUG: Cleaning up fd=%d\n", s->fds[i].fd);
            
            // Call close handler if it exists (this should free the socks5 object)
            if (s->fds[i].handler.handle_close) {
                struct selector_key key = {
                    .s = s,
                    .fd = s->fds[i].fd,
                    .data = s->fds[i].data,
                };
                printf("DEBUG: Calling handle_close for fd=%d, data=%p\n", 
                       s->fds[i].fd, s->fds[i].data);
                s->fds[i].handler.handle_close(&key);
            } else {
                printf("DEBUG: No close handler for fd=%d, data=%p (this is OK for server socket)\n",
                       s->fds[i].fd, s->fds[i].data);
            }
            
            close(s->fds[i].fd);
            s->fds[i].fd = INVALID_FD;
        }
    }
    
    // Close epoll fd
    if (s->epoll_fd != -1) {
        close(s->epoll_fd);
    }
    
    // Free the fds array
    free(s->fds);
    
    // Free the selector itself
    free(s);
    
    printf("DEBUG: selector_destroy completed\n");
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

selector_status selector_register(fd_selector s, int fd, const fd_handler *handler,
                                   fd_interest interest, void *data) {
    printf("DEBUG: selector_register called: fd=%d, interest=%d\n", fd, interest);
    
    if (s == NULL || handler == NULL || fd < 0 || fd >= (int)s->max_fds) {  // Add handler == NULL check
        printf("DEBUG: Invalid args: s=%p, handler=%p, fd=%d, max_fds=%zu\n", 
               (void*)s, (void*)handler, fd, s ? s->max_fds : 0);
        return SELECTOR_IARGS;
    }
    
    pthread_mutex_lock(&s->mutex);

    if (s->fds[fd].fd != INVALID_FD)
    {
        pthread_mutex_unlock(&s->mutex);
        return SELECTOR_IARGS;
    }
    
    // Set up the item
    s->fds[fd].fd = fd;
    s->fds[fd].handler = *handler;
    s->fds[fd].data = data;
    
    // Add to epoll
    struct epoll_event event;
    event.events = 0;
    
    if (interest & OP_READ) {
        event.events |= EPOLLIN;
    }
    if (interest & OP_WRITE) {
        event.events |= EPOLLOUT;
    }
    
    event.data.ptr = &s->fds[fd];  // IMPORTANT: Set pointer to the item!
    
    if (epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0) {
        return SELECTOR_IO;
    }
    
    pthread_mutex_unlock(&s->mutex);
    return SELECTOR_SUCCESS;
}

void
selector_unregister(fd_selector s, const int fd) {
    printf("DEBUG: selector_unregister called with fd=%d\n", fd);
    
    if (s == NULL || fd < 0 || fd >= (int)s->max_fds) {
        printf("DEBUG: selector_unregister - invalid params\n");
        return;
    }
    
    struct item *item = &s->fds[fd];
    
    if (item->fd == INVALID_FD) {
        printf("DEBUG: selector_unregister - fd=%d already unregistered\n", fd);
        return;
    }
    
    printf("DEBUG: Removing fd=%d from epoll\n", fd);
    
    // Remove from epoll BEFORE closing the fd
    if (s->epoll_fd != -1) {
        struct epoll_event ev = {0};
        int ret = epoll_ctl(s->epoll_fd, EPOLL_CTL_DEL, fd, &ev);
        if (ret == -1) {
            printf("DEBUG: epoll_ctl DEL failed for fd=%d: %s\n", 
                   fd, strerror(errno));
        } else {
            printf("DEBUG: epoll_ctl DEL succeeded for fd=%d\n", fd);
        }
    }
    
    // Now close the file descriptor
    printf("DEBUG: Closing fd=%d\n", fd);
    close(fd);
    
    // Mark as invalid
    item->fd = INVALID_FD;
    item->interest = OP_NOOP;
    item->data = NULL;
    
    printf("DEBUG: fd=%d unregistered and closed\n", fd);
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

selector_status selector_set_interest_key(struct selector_key *key, fd_interest interest) {
    if (key == NULL || key->s == NULL) {
        return SELECTOR_IARGS;
    }
    
    fd_selector s = key->s;
    int fd = key->fd;
    
    printf("DEBUG: selector_set_interest_key: fd=%d, interest=%d\n", fd, interest);
    
    if (fd < 0 || fd >= (int)s->max_fds) {
        return SELECTOR_IARGS;
    }
    
    // DON'T modify the handler - just update epoll interest
    struct epoll_event event;
    event.events = 0;
    event.data.ptr = &s->fds[fd];  // Keep the same data pointer
    
    if (interest & OP_READ) {
        event.events |= EPOLLIN;
    }
    if (interest & OP_WRITE) {
        event.events |= EPOLLOUT;
    }
    
    printf("DEBUG: epoll_ctl MOD fd=%d, events=0x%x\n", fd, event.events);
    
    if (epoll_ctl(s->epoll_fd, EPOLL_CTL_MOD, fd, &event) < 0) {
        perror("epoll_ctl MOD");
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
    
    printf("DEBUG: epoll_wait returned n=%d\n", n);
    
    if (n < 0) {
        if (errno == EINTR) {
            return SELECTOR_SUCCESS;
        }
        return SELECTOR_IO;
    }
    
    for (int i = 0; i < n; i++) {
        struct epoll_event *e = &events[i];
        item *it = (item *)e->data.ptr;
        
        if (it == NULL) {
            printf("DEBUG: Event %d has NULL data.ptr, skipping\n", i);
            continue;
        }
        
        printf("DEBUG: Processing event %d: fd=%d, events=0x%x, it=%p\n", 
               i, it->fd, e->events, (void*)it);
        printf("DEBUG: it->handler: read=%p, write=%p, close=%p\n",
               (void*)it->handler.handle_read,
               (void*)it->handler.handle_write,
               (void*)it->handler.handle_close);
        
        if (it->fd == INVALID_FD) {
            printf("DEBUG: fd is INVALID_FD, skipping\n");
            continue;
        }
        
        struct selector_key key = {
            .s    = s,
            .fd   = it->fd,
            .data = it->data,
        };
        
        if (e->events & EPOLLIN) {
            printf("DEBUG: EPOLLIN event, handle_read=%p\n", 
                   (void*)(it->handler.handle_read));
            
            if (it->handler.handle_read) {
                printf("DEBUG: Calling handle_read for fd=%d\n", it->fd);
                it->handler.handle_read(&key);
                printf("DEBUG: handle_read returned\n");
            } else {
                printf("DEBUG: handle_read is NULL!\n");
            }
        }
        
        if (e->events & EPOLLOUT) {
            printf("DEBUG: EPOLLOUT event, handle_write=%p\n", 
                   (void*)(it->handler.handle_write));
            
            if (it->handler.handle_write) {
                printf("DEBUG: Calling handle_write for fd=%d\n", it->fd);
                it->handler.handle_write(&key);
                printf("DEBUG: handle_write returned\n");
            } else {
                printf("DEBUG: handle_write is NULL!\n");
            }
        }
        
        if (e->events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
            printf("DEBUG: Error/Hangup event for fd=%d\n", it->fd);
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