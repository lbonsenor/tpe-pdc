#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include "../include/dissector.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <sys/time.h>

static bool dissector_enabled = false;
static FILE *cred_log_file = NULL;
static pthread_mutex_t dissector_mutex = PTHREAD_MUTEX_INITIALIZER;
static size_t credential_count = 0;

// Estado para parseo POP3
typedef struct {
    char username[256];
    bool waiting_for_pass;
} pop3_state_t;

static pop3_state_t pop3_state = {0};

// Helper para obtener timestamp
static void get_timestamp(char *buffer, size_t size) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    
    struct tm tm;
    localtime_r(&tv.tv_sec, &tm);
    
    snprintf(buffer, size, "%04d-%02d-%02d %02d:%02d:%02d",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec);
}

// Helper para verificar si es texto ASCII imprimible
static bool is_printable_text(const uint8_t *data, size_t len) {
    if (len == 0) return false;
    
    size_t printable = 0;
    for (size_t i = 0; i < len && i < 100; i++) {
        if (isprint(data[i]) || data[i] == '\r' || data[i] == '\n' || data[i] == '\t') {
            printable++;
        }
    }
    
    return (printable * 100 / (len < 100 ? len : 100)) > 80;
}

// Detectar protocolo basado en puerto y contenido
static protocol_type_t detect_protocol(const uint8_t *data, size_t len, uint16_t port) {
    if (!is_printable_text(data, len)) {
        return PROTO_UNKNOWN;
    }
    
    // POP3 típicamente en puerto 110
    if (port == 110 || port == 995) {
        return PROTO_POP3;
    }
    
    // HTTP en puerto 80/8080
    if (port == 80 || port == 8080 || port == 443) {
        if (len > 4 && (memcmp(data, "GET ", 4) == 0 || 
                        memcmp(data, "POST", 4) == 0 ||
                        memcmp(data, "PUT ", 4) == 0)) {
            return PROTO_HTTP;
        }
    }
    
    // FTP en puerto 21
    if (port == 21) {
        return PROTO_FTP;
    }
    
    // SMTP en puerto 25
    if (port == 25 || port == 587) {
        return PROTO_SMTP;
    }
    
    return PROTO_UNKNOWN;
}

// Parsear comando POP3
static bool parse_pop3_command(const uint8_t *data, size_t len,
                               const char *dest_host, uint16_t dest_port) {
    // Convertir a string (asumiendo que es texto)
    char buffer[1024];
    size_t copy_len = len < sizeof(buffer) - 1 ? len : sizeof(buffer) - 1;
    memcpy(buffer, data, copy_len);
    buffer[copy_len] = '\0';
    
    // Remover \r\n
    char *newline = strchr(buffer, '\r');
    if (newline) *newline = '\0';
    newline = strchr(buffer, '\n');
    if (newline) *newline = '\0';
    
    // Parsear comando USER
    if (strncasecmp(buffer, "USER ", 5) == 0) {
        strncpy(pop3_state.username, buffer + 5, sizeof(pop3_state.username) - 1);
        pop3_state.username[sizeof(pop3_state.username) - 1] = '\0';
        pop3_state.waiting_for_pass = true;
        return false; // Aún no tenemos credenciales completas
    }
    
    // Parsear comando PASS
    if (strncasecmp(buffer, "PASS ", 5) == 0 && pop3_state.waiting_for_pass) {
        char password[256];
        strncpy(password, buffer + 5, sizeof(password) - 1);
        password[sizeof(password) - 1] = '\0';
        
        // Registrar credencial capturada
        char timestamp[32];
        get_timestamp(timestamp, sizeof(timestamp));
        
        if (cred_log_file != NULL) {
            fprintf(cred_log_file,
                    "[%s] CAPTURED protocol=POP3 host=%s:%u user=%s pass=%s\n",
                    timestamp, dest_host, dest_port,
                    pop3_state.username, password);
            fflush(cred_log_file);
        }
        
        credential_count++;
        
        // Limpiar estado
        memset(&pop3_state, 0, sizeof(pop3_state));
        
        return true;
    }
    
    return false;
}

// Parsear HTTP básico (buscar Authorization header)
static bool parse_http_basic_auth(const uint8_t *data, size_t len,
                                  const char *dest_host, uint16_t dest_port) {
    // Convertir a string
    char buffer[4096];
    size_t copy_len = len < sizeof(buffer) - 1 ? len : sizeof(buffer) - 1;
    memcpy(buffer, data, copy_len);
    buffer[copy_len] = '\0';
    
    // Buscar "Authorization: Basic "
    char *auth_header = strstr(buffer, "Authorization: Basic ");
    if (auth_header == NULL) {
        auth_header = strstr(buffer, "authorization: basic ");
    }
    
    if (auth_header != NULL) {
        char timestamp[32];
        get_timestamp(timestamp, sizeof(timestamp));
        
        char *encoded = auth_header + 21; // longitud de "Authorization: Basic "
        char *end = strpbrk(encoded, "\r\n");
        if (end) *end = '\0';
        
        if (cred_log_file != NULL) {
            fprintf(cred_log_file,
                    "[%s] CAPTURED protocol=HTTP host=%s:%u basic_auth=%s (base64)\n",
                    timestamp, dest_host, dest_port, encoded);
            fflush(cred_log_file);
        }
        
        credential_count++;
        return true;
    }
    
    return false;
}

void dissector_init(bool enabled, const char *log_file) {
    pthread_mutex_lock(&dissector_mutex);
    
    dissector_enabled = enabled;
    credential_count = 0;
    memset(&pop3_state, 0, sizeof(pop3_state));
    
    if (enabled) {
        if (log_file != NULL) {
            cred_log_file = fopen(log_file, "a");
            if (cred_log_file == NULL) {
                fprintf(stderr, "Warning: Could not open credential log file %s, using stderr\n",
                        log_file);
                cred_log_file = stderr;
            }
        } else {
            cred_log_file = stderr;
        }
        
        char timestamp[32];
        get_timestamp(timestamp, sizeof(timestamp));
        fprintf(cred_log_file, "\n=== Credential Monitor Started: %s ===\n", timestamp);
        fflush(cred_log_file);
    }
    
    pthread_mutex_unlock(&dissector_mutex);
}

void dissector_close(void) {
    pthread_mutex_lock(&dissector_mutex);
    
    if (cred_log_file != NULL && cred_log_file != stderr) {
        char timestamp[32];
        get_timestamp(timestamp, sizeof(timestamp));
        fprintf(cred_log_file, "=== Credential Monitor Closed: %s ===\n", timestamp);
        fprintf(cred_log_file, "Total credentials captured: %zu\n\n", credential_count);
        fflush(cred_log_file);
        fclose(cred_log_file);
        cred_log_file = NULL;
    }
    
    dissector_enabled = false;
    
    pthread_mutex_unlock(&dissector_mutex);
}

bool dissector_process_client_data(
    const uint8_t *data,
    size_t len,
    const char *dest_host,
    uint16_t dest_port)
{
    if (!dissector_enabled || data == NULL || len == 0) {
        return false;
    }
    
    pthread_mutex_lock(&dissector_mutex);
    
    protocol_type_t proto = detect_protocol(data, len, dest_port);
    bool captured = false;
    
    switch (proto) {
        case PROTO_POP3:
            captured = parse_pop3_command(data, len, dest_host, dest_port);
            break;
            
        case PROTO_HTTP:
            captured = parse_http_basic_auth(data, len, dest_host, dest_port);
            break;
            
        case PROTO_FTP:
        case PROTO_SMTP:
            // TODO: Implementar parsers para FTP y SMTP
            break;
            
        default:
            break;
    }
    
    pthread_mutex_unlock(&dissector_mutex);
    
    return captured;
}

bool dissector_process_server_data(const uint8_t *data, size_t len) {
    // Por ahora solo procesamos datos del cliente
    // En el futuro podríamos analizar respuestas del servidor
    (void)data;
    (void)len;
    return false;
}

size_t dissector_get_credential_count(void) {
    pthread_mutex_lock(&dissector_mutex);
    size_t count = credential_count;
    pthread_mutex_unlock(&dissector_mutex);
    return count;
}

bool dissector_is_enabled(void) {
    return dissector_enabled;
}
