#define _POSIX_C_SOURCE 200809L
#include "../include/access_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/time.h>

static FILE *log_file = NULL;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

// Helper para obtener timestamp
static void get_timestamp(char *buffer, size_t size) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    
    struct tm tm;
    localtime_r(&tv.tv_sec, &tm);
    
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", &tm);
}

// Helper para convertir sockaddr a string
static void sockaddr_to_string(const struct sockaddr *addr, char *buffer, size_t size) {
    if (addr == NULL) {
        snprintf(buffer, size, "unknown");
        return;
    }
    
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
        inet_ntop(AF_INET, &addr_in->sin_addr, buffer, size);
    } else if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
        inet_ntop(AF_INET6, &addr_in6->sin6_addr, buffer, size);
    } else {
        snprintf(buffer, size, "unknown");
    }
}

void access_log_init(const char *log_file_path) {
    pthread_mutex_lock(&log_mutex);
    
    if (log_file_path != NULL) {
        log_file = fopen(log_file_path, "a");
        if (log_file == NULL) {
            fprintf(stderr, "Warning: Could not open access log file %s, using stderr\n", 
                    log_file_path);
            log_file = stderr;
        }
    } else {
        log_file = stderr;
    }
    
    // Write header
    char timestamp[32];
    get_timestamp(timestamp, sizeof(timestamp));
    fprintf(log_file, "\n=== Access Log Started: %s ===\n", timestamp);
    fflush(log_file);
    
    pthread_mutex_unlock(&log_mutex);
}

void access_log_close(void) {
    pthread_mutex_lock(&log_mutex);
    
    if (log_file != NULL && log_file != stderr) {
        char timestamp[32];
        get_timestamp(timestamp, sizeof(timestamp));
        fprintf(log_file, "=== Access Log Closed: %s ===\n\n", timestamp);
        fflush(log_file);
        fclose(log_file);
        log_file = NULL;
    }
    
    pthread_mutex_unlock(&log_mutex);
}

void access_log_connection(
    const char *username,
    const struct sockaddr *client_addr,
    const char *dest_host,
    uint16_t dest_port,
    const struct sockaddr *dest_addr)
{
    if (log_file == NULL) return;
    
    pthread_mutex_lock(&log_mutex);
    
    char timestamp[32];
    get_timestamp(timestamp, sizeof(timestamp));
    
    char client_ip[INET6_ADDRSTRLEN];
    sockaddr_to_string(client_addr, client_ip, sizeof(client_ip));
    
    char dest_ip[INET6_ADDRSTRLEN];
    sockaddr_to_string(dest_addr, dest_ip, sizeof(dest_ip));
    
    fprintf(log_file, 
            "[%s] CONNECT user=%s client=%s dest=%s:%u (%s)\n",
            timestamp,
            username ? username : "anonymous",
            client_ip,
            dest_host,
            dest_port,
            dest_ip);
    fflush(log_file);
    
    pthread_mutex_unlock(&log_mutex);
}

void access_log_disconnect(
    const char *username,
    const char *dest_host,
    uint16_t dest_port,
    uint64_t bytes_sent,
    uint64_t bytes_received,
    time_t duration_sec)
{
    if (log_file == NULL) return;
    
    pthread_mutex_lock(&log_mutex);
    
    char timestamp[32];
    get_timestamp(timestamp, sizeof(timestamp));
    
    fprintf(log_file,
            "[%s] DISCONNECT user=%s dest=%s:%u bytes_out=%lu bytes_in=%lu duration=%lds\n",
            timestamp,
            username ? username : "anonymous",
            dest_host,
            dest_port,
            (unsigned long)bytes_sent,
            (unsigned long)bytes_received,
            (long)duration_sec);
    fflush(log_file);
    
    pthread_mutex_unlock(&log_mutex);
}

void access_log_failed(
    const char *username,
    const struct sockaddr *client_addr,
    const char *dest_host,
    uint16_t dest_port,
    const char *reason)
{
    if (log_file == NULL) return;
    
    pthread_mutex_lock(&log_mutex);
    
    char timestamp[32];
    get_timestamp(timestamp, sizeof(timestamp));
    
    char client_ip[INET6_ADDRSTRLEN];
    sockaddr_to_string(client_addr, client_ip, sizeof(client_ip));
    
    fprintf(log_file,
            "[%s] FAILED user=%s client=%s dest=%s:%u reason=%s\n",
            timestamp,
            username ? username : "anonymous",
            client_ip,
            dest_host,
            dest_port,
            reason);
    fflush(log_file);
    
    pthread_mutex_unlock(&log_mutex);
}

void access_log_auth(
    const char *username,
    const struct sockaddr *client_addr,
    bool success)
{
    if (log_file == NULL) return;
    
    pthread_mutex_lock(&log_mutex);
    
    char timestamp[32];
    get_timestamp(timestamp, sizeof(timestamp));
    
    char client_ip[INET6_ADDRSTRLEN];
    sockaddr_to_string(client_addr, client_ip, sizeof(client_ip));
    
    fprintf(log_file,
            "[%s] AUTH user=%s client=%s result=%s\n",
            timestamp,
            username,
            client_ip,
            success ? "SUCCESS" : "FAILED");
    fflush(log_file);
    
    pthread_mutex_unlock(&log_mutex);
}
