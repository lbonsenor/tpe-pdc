/**
 * SOCKSv5 Management Client
 * ITBA Protocolos de Comunicación 2025/2
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <strings.h>

#define BUFFER_SIZE 4096
#define DEFAULT_MNG_PORT 8080
#define DEFAULT_MNG_ADDR "127.0.0.1"

struct client_args {
    char *mng_addr;
    unsigned short mng_port;
    int interactive;
};

static void usage(const char *progname) {
    fprintf(stderr,
            "Usage: %s [OPTION]...\n"
            "\n"
            "SOCKS5 Management Client\n"
            "\n"
            "Options:\n"
            "   -h               Print this help and exit\n"
            "   -L <addr>        Management server address (default: 127.0.0.1)\n"
            "   -P <port>        Management server port (default: 8080)\n"
            "   -i               Interactive mode (default if no command given)\n"
            "   -c <command>     Execute single command and exit\n"
            "\n"
            "Available commands:\n"
            "   STATS            Show server statistics\n"
            "   USERS            Show number of registered users\n"
            "   LISTUSERS        List all registered users\n"
            "   ADDUSER <u> <p>  Add new user with username and password\n"
            "   DELUSER <user>   Delete user\n"
            "   CREDS            Show captured credentials count\n"
            "   HELP             Show server help\n"
            "   QUIT             Disconnect from server\n"
            "\n"
            "Examples:\n"
            "   %s                           # Interactive mode\n"
            "   %s -c STATS                  # Get statistics\n"
            "   %s -c \"ADDUSER alice pass\"   # Add user\n"
            "   %s -L 192.168.1.100 -P 9090  # Connect to remote server\n"
            "\n",
            progname, progname, progname, progname, progname);
    exit(1);
}

static unsigned short port(const char *s) {
    char *end = 0;
    const long sl = strtol(s, &end, 10);

    if (end == s || '\0' != *end
        || ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno)
        || sl < 1 || sl > USHRT_MAX) {
        fprintf(stderr, "Invalid port: %s (must be 1-65535)\n", s);
        exit(1);
    }
    return (unsigned short)sl;
}

static void parse_args(int argc, char **argv, struct client_args *args) {
    memset(args, 0, sizeof(*args));
    
    args->mng_addr = DEFAULT_MNG_ADDR;
    args->mng_port = DEFAULT_MNG_PORT;
    args->interactive = -1; // Auto-detect
    
    int c;
    char *command = NULL;
    
    while ((c = getopt(argc, argv, "hL:P:ic:")) != -1) {
        switch (c) {
            case 'h':
                usage(argv[0]);
                break;
            case 'L':
                args->mng_addr = optarg;
                break;
            case 'P':
                args->mng_port = port(optarg);
                break;
            case 'i':
                args->interactive = 1;
                break;
            case 'c':
                command = optarg;
                args->interactive = 0;
                break;
            default:
                fprintf(stderr, "Unknown option: %c\n", c);
                usage(argv[0]);
        }
    }
    
    // If no mode specified, default to interactive
    if (args->interactive == -1) {
        args->interactive = (command == NULL) ? 1 : 0;
    }
    
    // Store command if provided
    if (command != NULL && args->interactive == 0) {
        // We'll handle the command in main
    }
}

static int connect_to_server(const char *addr, unsigned short port_num) {
    int sock;
    struct addrinfo hints, *res, *rp;
    char port_str[6];
    
    snprintf(port_str, sizeof(port_str), "%u", port_num);
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    int status = getaddrinfo(addr, port_str, &hints, &res);
    if (status != 0) {
        fprintf(stderr, "Error resolving address %s: %s\n", addr, gai_strerror(status));
        return -1;
    }
    
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == -1) {
            continue;
        }
        
        if (connect(sock, rp->ai_addr, rp->ai_addrlen) != -1) {
            break; // Success
        }
        
        close(sock);
    }
    
    freeaddrinfo(res);
    
    if (rp == NULL) {
        fprintf(stderr, "Failed to connect to %s:%u\n", addr, port_num);
        return -1;
    }
    
    return sock;
}

static int send_command(int sock, const char *cmd) {
    size_t len = strlen(cmd);
    size_t sent = 0;
    
    while (sent < len) {
        ssize_t n = write(sock, cmd + sent, len - sent);
        if (n <= 0) {
            if (n < 0) {
                perror("write");
            }
            return -1;
        }
        sent += n;
    }
    
    // Send newline
    if (write(sock, "\n", 1) != 1) {
        perror("write");
        return -1;
    }
    
    return 0;
}

static int receive_response(int sock, char *buffer, size_t bufsize) {
    size_t received = 0;
    int newline_count = 0;
    
    // Set a timeout for reading
    struct timeval tv;
    tv.tv_sec = 1;  // 1 second timeout
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
    
    while (received < bufsize - 1) {
        ssize_t n = read(sock, buffer + received, bufsize - received - 1);
        if (n < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                // Timeout - assume we got full response
                break;
            }
            perror("read");
            break;
        }
        if (n == 0) {
            // Connection closed
            break;
        }
        
        // Count newlines to detect end of multi-line responses
        for (ssize_t i = 0; i < n; i++) {
            if (buffer[received + i] == '\n') {
                newline_count++;
            }
        }
        
        received += n;
        buffer[received] = '\0';
        
        // If we got at least one newline and haven't received data for a bit, done
        if (newline_count > 0) {
            // Small delay to check if more data is coming
            tv.tv_sec = 0;
            tv.tv_usec = 50000; // 50ms
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
        }
    }
    
    // Reset to blocking
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
    
    return received;
}

static void interactive_mode(int sock) {
    char buffer[BUFFER_SIZE];
    char input[BUFFER_SIZE];
    
    printf("Connected to management server. Type HELP for available commands, QUIT to exit.\n");
    
    while (1) {
        printf("> ");
        fflush(stdout);
        
        if (fgets(input, sizeof(input), stdin) == NULL) {
            break;
        }
        
        // Remove newline
        input[strcspn(input, "\n")] = 0;
        
        // Skip empty lines
        if (strlen(input) == 0) {
            continue;
        }
        
        // Send command
        if (send_command(sock, input) < 0) {
            fprintf(stderr, "Failed to send command\n");
            break;
        }
        
        // Check if user wants to quit
        if (strcasecmp(input, "QUIT") == 0) {
            printf("Disconnecting...\n");
            break;
        }
        
        // Receive response
        memset(buffer, 0, sizeof(buffer));
        int received = receive_response(sock, buffer, sizeof(buffer));
        if (received > 0) {
            printf("%s", buffer);
            if (buffer[received - 1] != '\n') {
                printf("\n");
            }
        }
    }
}

static void command_mode(int sock, const char *cmd) {
    char buffer[BUFFER_SIZE];
    
    // Send command
    if (send_command(sock, cmd) < 0) {
        fprintf(stderr, "Failed to send command\n");
        exit(1);
    }
    
    // Receive and print response
    memset(buffer, 0, sizeof(buffer));
    int received = receive_response(sock, buffer, sizeof(buffer));
    if (received > 0) {
        printf("%s", buffer);
        if (buffer[received - 1] != '\n') {
            printf("\n");
        }
    } else {
        fprintf(stderr, "Failed to receive response\n");
        exit(1);
    }
    
    // Connection will be closed by caller - no need to send QUIT
}

int main(int argc, char **argv) {
    struct client_args args;
    parse_args(argc, argv, &args);
    
    // Connect to server
    int sock = connect_to_server(args.mng_addr, args.mng_port);
    if (sock < 0) {
        exit(1);
    }
    
    // Execute command or enter interactive mode
    if (args.interactive) {
        interactive_mode(sock);
    } else {
        // Build command from remaining arguments
        char cmd[BUFFER_SIZE] = "";
        for (int i = optind; i < argc; i++) {
            if (i > optind) {
                strcat(cmd, " ");
            }
            strcat(cmd, argv[i]);
        }
        
        // If -c was used, the command is already in optarg
        if (strlen(cmd) == 0) {
            // Find the -c option's argument
            optind = 1; // Reset
            int c;
            while ((c = getopt(argc, argv, "hL:P:ic:")) != -1) {
                if (c == 'c') {
                    strncpy(cmd, optarg, sizeof(cmd) - 1);
                    break;
                }
            }
        }
        
        if (strlen(cmd) > 0) {
            command_mode(sock, cmd);
        }
    }
    
    close(sock);
    return 0;
}