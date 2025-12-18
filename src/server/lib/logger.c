#include "logger.h"

#include <stdarg.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>

static log_level_t current_level = LOG_INFO;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

static const char *level_to_string(log_level_t level) {
    switch (level) {
        case LOG_ERROR: return "ERROR";
        case LOG_WARN:  return "WARN";
        case LOG_INFO:  return "INFO";
        case LOG_DEBUG: return "DEBUG";
        default:        return "UNKNOWN";
    }
}

void logger_init(log_level_t level) {
    pthread_mutex_lock(&log_mutex);
    current_level = level;
    pthread_mutex_unlock(&log_mutex);
}

void logger_set_level(log_level_t level) {
    pthread_mutex_lock(&log_mutex);
    current_level = level;
    pthread_mutex_unlock(&log_mutex);
}

void logger_log(log_level_t level,
                const char *file,
                int line,
                const char *fmt, ...) {
    if (level > current_level) {
        return;
    }

    pthread_mutex_lock(&log_mutex);

    struct timeval tv;
    gettimeofday(&tv, NULL);

    struct tm tm;
    struct tm *tmp = localtime(&tv.tv_sec);
    if (tmp != NULL) {
        tm = *tmp;
    } else {
        memset(&tm, 0, sizeof(tm));
    }

    char timebuf[32];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tm);

    fprintf(stderr, "%s.%03ld [%s] %s:%d: ",
            timebuf,
            tv.tv_usec / 1000,
            level_to_string(level),
            file,
            line);

    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    fputc('\n', stderr);
    fflush(stderr);

    pthread_mutex_unlock(&log_mutex);
}
