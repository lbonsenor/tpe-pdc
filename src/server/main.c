/**
 * main.c - servidor proxy socks concurrente
 *
 * Interpreta los argumentos de línea de comandos, y monta un socket
 * pasivo.
 *
 * Todas las conexiones entrantes se manejarán en éste hilo.
 *
 * Se descargará en otro hilos las operaciones bloqueantes (resolución de
 * DNS utilizando getaddrinfo), pero toda esa complejidad está oculta en
 * el selector.
 */
#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>

#include <unistd.h>
#include <sys/types.h>   // socket
#include <sys/socket.h>  // socket
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>

#include "include/args.h"
#include "include/socks5.h"
#include "include/selector.h"
#include "include/socks5nio.h"
#include "include/users.h"

static bool done = false;
static struct socks5args args;

// metricas
static size_t mng_total_connections = 0;
static size_t mng_current_connections = 0;

static void
sigterm_handler(const int signal) {
    printf("signal %d, cleaning up and exiting\n",signal);
    done = true;
}

static void cleanup(fd_selector selector, int server_fd, int mng_fd) {
    if (server_fd != -1) close(server_fd);
    if (mng_fd != -1) close(mng_fd);
    
    if (selector != NULL) {
        selector_destroy(selector);  // This should free all resources
    }

    users_destroy();
    socksv5_pool_destroy();
}

static void users_setup() {
    users_init();

    for (size_t i = 0; i < args.users_count; i++)
    {
        users_add(args.users[i].name, args.users[i].pass);
    }
    
    size_t user_count = users_count();
    printf("[INFO] Usuarios configurados: %zu\n", user_count);
    
    if (user_count > 0) {
        printf("[INFO] Autenticación REQUERIDA (método 0x02)\n");
    } else {
        printf("[WARNING] Autenticación DESHABILITADA (método 0x00)\n");
    }

}

static int listener_setup(const char *addr, unsigned short port) {
    struct addrinfo hints, *res = NULL, *rp;
    int fd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags    = AI_PASSIVE;

    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%u", port);

    int rc = getaddrinfo(addr, port_str, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc));
        return -1;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;

        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

        if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;

        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);

    if (fd < 0) return -1;

    if (listen(fd, 20) < 0) {
        close(fd);
        return -1;
    }

    if (selector_fd_set_nio(fd) == -1) {
        close(fd);
        return -1;
    }

    return fd;
}

struct mng_conn {
    size_t bytes;
};

static void mng_read(struct selector_key *key);

static void mng_close(struct selector_key *key) {
    mng_current_connections--;
    free(key->data);
}

static void mng_passive_accept(struct selector_key *key) {
    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr);

    int client = accept(key->fd, (struct sockaddr *)&addr, &len);
    if (client < 0) return;

    if (selector_fd_set_nio(client) == -1) {
        close(client);
        return;
    }

    struct mng_conn *conn = calloc(1, sizeof(*conn));
    if (conn == NULL) {
        close(client);
        return;
    }

    mng_total_connections++;
    mng_current_connections++;

    const struct fd_handler handler = {
        .handle_read  = mng_read,
        .handle_write = NULL,
        .handle_close = mng_close,
    };

    selector_register(key->s, client, &handler, OP_READ, conn);
}

static void mng_read(struct selector_key *key) {
    char buf[256];
    ssize_t n = recv(key->fd, buf, sizeof(buf) - 1, 0);

    if (n <= 0) {
        selector_unregister(key->s, key->fd);
        return;
    }

    buf[n] = 0;

    if (strncmp(buf, "STATS", 5) == 0) {
        char reply[256];
        int len = snprintf(reply, sizeof(reply),
            "connections.total=%zu\n"
            "connections.current=%zu\n",
            mng_total_connections,
            mng_current_connections);

        send(key->fd, reply, len, MSG_NOSIGNAL);
    } else if (strncmp(buf, "QUIT", 4) == 0) {
        selector_unregister(key->s, key->fd);
    } else {
        const char *err = "ERR unknown command\n";
        send(key->fd, err, strlen(err), MSG_NOSIGNAL);
    }
}

int main(const int argc, char **argv) {
    parse_args(argc, argv, &args);
    printf("Starting server...\n");
    
    users_setup();
    
    // no tenemos nada que leer de stdin
    // close(0);

    const struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = {
            .tv_sec  = 10,
            .tv_nsec = 0,
        }
    };

    if(0 != selector_init(&conf)) {
        perror("selector_init");
        return 1;
    }

    fd_selector selector = selector_new(1024);
    if(selector == NULL) 
    {
        perror("selector_new");
        return 1;
    }

    int socks_fd = listener_setup(args.socks_addr, args.socks_port);
    int mng_fd   = listener_setup(args.mng_addr, args.mng_port);

    if (socks_fd < 0 || mng_fd < 0)
    {
        perror("listener_setup");
        cleanup(selector, socks_fd, mng_fd);
        return 1;
    }
    
    printf("SOCKS listening on %s:%u\n", args.socks_addr, args.socks_port);
    printf("MNG   listening on %s:%u\n", args.mng_addr,   args.mng_port);
    fflush(stdout);  // KEEP THIS ONE - ensures message shows before blocking

    // man 7 ip. no importa reportar nada si falla.
    // setsockopt(socks_server, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));

    // registrar sigterm es útil para terminar el programa normalmente.
    // esto ayuda mucho en herramientas como valgrind.
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT,  sigterm_handler);

    const struct fd_handler socks_handler = {
        .handle_read = socksv5_passive_accept
    };

    const struct fd_handler mng_handler = {
        .handle_read = mng_passive_accept
    };

    selector_register(selector, socks_fd, &socks_handler, OP_READ, NULL);
    selector_register(selector, mng_fd, &mng_handler, OP_READ, NULL);
    
    while (!done) {
        if (selector_select(selector) != SELECTOR_SUCCESS) {
            if (errno == EINTR) continue;
            break;
        }
    }
    
    cleanup(selector, socks_fd, mng_fd);
    return 0;
}
