#ifndef PROMPT_H
#define PROMPT_H

#include <stdbool.h>
#include <stddef.h>

typedef enum {
    COLOR_RESET = 0,
    COLOR_CYAN,
    COLOR_GREEN,
    COLOR_YELLOW,
    COLOR_RED,
    COLOR_GRAY,
    COLOR_WHITE
} prompt_color;

typedef bool (*validator_func)(const char *input, char *error_msg, size_t error_size);

typedef struct input_config {
    const char *title;
    const char *placeholder;
    validator_func validator;
    size_t max_length;
    bool required;
} input_config;

typedef struct select_config {
    const char *title;
    const char **options;
    size_t option_count;
    int default_index;
} select_config;

typedef struct confirm_config {
    const char *title;
    bool is_yes_default;
} confirm_config;

void prompt_init(void);

void prompt_cleanup(void);

char* prompt_input(const struct input_config *config);

char* prompt_password(const struct input_config *config);

int prompt_select(const struct select_config *config);

bool prompt_confirm(const struct confirm_config *config);

#endif