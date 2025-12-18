#include "metrics.h"
#include <stdio.h>
#include <string.h>
#include <pthread.h>

static struct metrics global_metrics;
static pthread_mutex_t metrics_mutex = PTHREAD_MUTEX_INITIALIZER;

void metrics_init(void) {
    pthread_mutex_lock(&metrics_mutex);
    
    memset(&global_metrics, 0, sizeof(global_metrics));
    global_metrics.start_time = time(NULL);
    
    pthread_mutex_unlock(&metrics_mutex);
}

void metrics_connection_new(void) {
    pthread_mutex_lock(&metrics_mutex);
    
    global_metrics.total_connections++;
    global_metrics.current_connections++;
    
    if (global_metrics.current_connections > global_metrics.max_concurrent_connections) {
        global_metrics.max_concurrent_connections = global_metrics.current_connections;
    }
    
    pthread_mutex_unlock(&metrics_mutex);
}

void metrics_connection_close(void) {
    pthread_mutex_lock(&metrics_mutex);
    
    if (global_metrics.current_connections > 0) {
        global_metrics.current_connections--;
    }
    
    pthread_mutex_unlock(&metrics_mutex);
}

void metrics_connection_failed(void) {
    pthread_mutex_lock(&metrics_mutex);
    
    global_metrics.failed_connections++;
    
    pthread_mutex_unlock(&metrics_mutex);
}

void metrics_bytes_sent(size_t bytes) {
    pthread_mutex_lock(&metrics_mutex);
    
    global_metrics.bytes_sent += bytes;
    global_metrics.bytes_transferred += bytes;
    
    pthread_mutex_unlock(&metrics_mutex);
}

void metrics_bytes_received(size_t bytes) {
    pthread_mutex_lock(&metrics_mutex);
    
    global_metrics.bytes_received += bytes;
    global_metrics.bytes_transferred += bytes;
    
    pthread_mutex_unlock(&metrics_mutex);
}

void metrics_auth_success(void) {
    pthread_mutex_lock(&metrics_mutex);
    
    global_metrics.auth_success++;
    
    pthread_mutex_unlock(&metrics_mutex);
}

void metrics_auth_failed(void) {
    pthread_mutex_lock(&metrics_mutex);
    
    global_metrics.auth_failed++;
    
    pthread_mutex_unlock(&metrics_mutex);
}

const struct metrics *metrics_get(void) {
    // Nota: en una implementación más segura, deberíamos
    // copiar las métricas bajo el mutex y retornar la copia
    return &global_metrics;
}

int metrics_format(char *buffer, size_t size) {
    pthread_mutex_lock(&metrics_mutex);
    
    time_t now = time(NULL);
    time_t uptime = now - global_metrics.start_time;
    
    // Calcular días, horas, minutos, segundos
    int days = uptime / 86400;
    int hours = (uptime % 86400) / 3600;
    int minutes = (uptime % 3600) / 60;
    int seconds = uptime % 60;
    
    int len = snprintf(buffer, size,
        "=== SOCKS5 PROXY METRICS ===\n"
        "\n"
        "Server Status:\n"
        "  uptime=%dd %dh %dm %ds\n"
        "\n"
        "Connections:\n"
        "  total=%zu\n"
        "  current=%zu\n"
        "  max_concurrent=%zu\n"
        "  failed=%zu\n"
        "\n"
        "Data Transfer:\n"
        "  bytes_sent=%llu\n"
        "  bytes_received=%llu\n"
        "  bytes_total=%llu\n"
        "\n"
        "Authentication:\n"
        "  success=%zu\n"
        "  failed=%zu\n",
        days, hours, minutes, seconds,
        global_metrics.total_connections,
        global_metrics.current_connections,
        global_metrics.max_concurrent_connections,
        global_metrics.failed_connections,
        (unsigned long long)global_metrics.bytes_sent,
        (unsigned long long)global_metrics.bytes_received,
        (unsigned long long)global_metrics.bytes_transferred,
        global_metrics.auth_success,
        global_metrics.auth_failed);
    
    pthread_mutex_unlock(&metrics_mutex);
    
    return len;
}