#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>

/*
 * Niveles de logging
 */
typedef enum {
    LOG_ERROR = 0,
    LOG_WARN,
    LOG_INFO,
    LOG_DEBUG
} log_level_t;

/*
 * Inicializa el logger.
 * level: nivel mínimo que se imprimirá.
 */
void logger_init(log_level_t level);

/*
 * Cambia el nivel de logging en runtime.
 */
void logger_set_level(log_level_t level);

/*
 * Log interno (no usar directamente).
 */
void logger_log(log_level_t level, const char *file, int line, const char *fmt, ...) __attribute__((format(printf, 4, 5)));

/*
 * Macros públicas
 */
#define LOGE(fmt, ...) logger_log(LOG_ERROR, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOGW(fmt, ...) logger_log(LOG_WARN,  __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOGI(fmt, ...) logger_log(LOG_INFO,  __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOGD(fmt, ...) logger_log(LOG_DEBUG, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#endif