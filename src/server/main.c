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
#include "include/logger.h"
#include "include/access_log.h"
#include "include/dissector.h"
#include "include/metrics.h"

static bool done = false;
static struct socks5args args;

// metricas
static size_t mng_total_connections = 0;
static size_t mng_current_connections = 0;

static void
sigterm_handler(const int signal) {
    LOGI("signal %d received, cleaning up and exiting", signal);
    done = true;
}

static void cleanup(fd_selector selector, int server_fd, int mng_fd) {
    // selector_destroy will call close handlers for all registered fds
    // and then close them, so we don't need to close server_fd/mng_fd manually
    if (selector != NULL) {
        selector_destroy(selector);
    } else {
        // If selector wasn't created, close manually
        if (server_fd != -1) close(server_fd);
        if (mng_fd != -1) close(mng_fd);
    }

    users_destroy();
    socksv5_pool_destroy();
    access_log_close();
    dissector_close();
}

static void users_setup() {
    users_init();

    for (size_t i = 0; i < args.users_count; i++)
    {
        users_add(args.users[i].name, args.users[i].pass);
    }
    
    size_t user_count = users_count();
    LOGI("Usuarios configurados: %zu", user_count);
    
    if (user_count > 0) {
        LOGI("Autenticación REQUERIDA (método 0x02)");
    } else {
        LOGW("Autenticación DESHABILITADA (método 0x00)");
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
        LOGE("getaddrinfo(%s:%u) failed: %s",
            addr ? addr : "NULL",
            port,
            gai_strerror(rc));
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
    if (key->data != NULL) {
        free(key->data);
    }
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
        // Connection closed - clean up before unregistering
        mng_close(key);
        selector_unregister(key->s, key->fd);
        return;
    }

    buf[n] = 0;

    if (strncmp(buf, "STATS", 5) == 0) {
        char reply[1024];
        int len = metrics_format(reply, sizeof(reply));
        send(key->fd, reply, len, MSG_NOSIGNAL);
    } else if (strncmp(buf, "LISTUSERS", 9) == 0) {
        char reply[2048];
        int len = snprintf(reply, sizeof(reply), "users.count=%zu\n", users_count());
        len += users_list(reply + len, sizeof(reply) - len);
        send(key->fd, reply, len, MSG_NOSIGNAL);
    } else if (strncmp(buf, "ADDUSER ", 8) == 0) {
        // Format: ADDUSER username password
        char username[256] = {0};
        char password[256] = {0};
        if (sscanf(buf + 8, "%255s %255s", username, password) == 2) {
            if (users_add(username, password)) {
                const char *ok = "OK user added/updated\n";
                send(key->fd, ok, strlen(ok), MSG_NOSIGNAL);
            } else {
                const char *err = "ERR failed to add user (limit reached?)\n";
                send(key->fd, err, strlen(err), MSG_NOSIGNAL);
            }
        } else {
            const char *err = "ERR invalid format (use: ADDUSER username password)\n";
            send(key->fd, err, strlen(err), MSG_NOSIGNAL);
        }
    } else if (strncmp(buf, "DELUSER ", 8) == 0) {
        // Format: DELUSER username
        char username[256] = {0};
        if (sscanf(buf + 8, "%255s", username) == 1) {
            if (users_remove(username)) {
                const char *ok = "OK user deleted\n";
                send(key->fd, ok, strlen(ok), MSG_NOSIGNAL);
            } else {
                const char *err = "ERR user not found\n";
                send(key->fd, err, strlen(err), MSG_NOSIGNAL);
            }
        } else {
            const char *err = "ERR invalid format (use: DELUSER username)\n";
            send(key->fd, err, strlen(err), MSG_NOSIGNAL);
        }
    } else if (strncmp(buf, "USERS", 5) == 0) {
        char reply[256];
        size_t count = users_count();
        int len = snprintf(reply, sizeof(reply),
            "users.count=%zu\n",
            count);
        send(key->fd, reply, len, MSG_NOSIGNAL);
    } else if (strncmp(buf, "CREDS", 5) == 0) {
        char reply[256];
        size_t count = dissector_get_credential_count();
        int len = snprintf(reply, sizeof(reply),
            "credentials.captured=%zu\n"
            "credentials.enabled=%s\n",
            count,
            dissector_is_enabled() ? "true" : "false");
        send(key->fd, reply, len, MSG_NOSIGNAL);
    } else if (strncmp(buf, "HELP", 4) == 0) {
        const char *help = 
            "Available commands:\n"
            "  STATS - Show server statistics\n"
            "  USERS - Show user count\n"
            "  LISTUSERS - List all usernames\n"
            "  ADDUSER <user> <pass> - Add/update user\n"
            "  DELUSER <user> - Delete user\n"
            "  CREDS - Show credential capture stats\n"
            "  HELP  - Show this help\n"
            "  QUIT  - Close connection\n";
        send(key->fd, help, strlen(help), MSG_NOSIGNAL);
    } else if (strncmp(buf, "QUIT", 4) == 0) {
        // Clean up before unregistering
        mng_close(key);
        selector_unregister(key->s, key->fd);
    } else {
        const char *err = "ERR unknown command (try HELP)\n";
        send(key->fd, err, strlen(err), MSG_NOSIGNAL);
    }
}

int main(const int argc, char **argv) {
    logger_init(LOG_DEBUG);
    parse_args(argc, argv, &args);
    LOGI("Starting SOCKS5 server");
    
    users_setup();
    
    // Inicializar sistema de access log
    access_log_init("access.log");
    LOGI("Access logging initialized");
    
    // Inicializar sistema de métricas
    metrics_init();
    LOGI("Metrics system initialized");
    
    // Inicializar dissector de credenciales
    dissector_init(args.disectors_enabled, "credentials.log");
    if (args.disectors_enabled) {
        LOGI("Credential dissector ENABLED");
    } else {
        LOGI("Credential dissector DISABLED");
    }
    
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
        LOGE("selector_init failed: %s", strerror(errno));
        return 1;
    }

    // Increased from 1024 to 2048 to support 500+ concurrent connections
    // Each SOCKS connection uses 2 FDs (client + origin)
    // 2048 / 2 = 1024 theoretical max connections (minus overhead)
    fd_selector selector = selector_new(2048);
    if(selector == NULL) 
    {
        LOGE("selector_new failed");
        return 1;
    }

    int socks_fd = listener_setup(args.socks_addr, args.socks_port);
    int mng_fd   = listener_setup(args.mng_addr, args.mng_port);

    if (socks_fd < 0 || mng_fd < 0)
    {
        LOGE("listener_setup failed");
        cleanup(selector, socks_fd, mng_fd);
        return 1;
    }
    
    LOGI("SOCKS listening on %s:%u", args.socks_addr, args.socks_port);
    LOGI("MNG   listening on %s:%u", args.mng_addr,   args.mng_port);
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
