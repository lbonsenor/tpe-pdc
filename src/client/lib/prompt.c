#include "../include/prompt.h"

#include <termios.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct termios termios;
static bool terminal_initialized = false;

static const char* color_codes[] = {
    [COLOR_RESET] = "\033[0m",
    [COLOR_CYAN] = "\033[96m",
    [COLOR_GREEN] = "\033[92m",
    [COLOR_YELLOW] = "\033[93m",
    [COLOR_RED] = "\033[91m",
    [COLOR_GRAY] = "\033[90m",
    [COLOR_WHITE] = "\033[97m"
};

#define BOX_EMPTY "◇"
#define BOX_FILLED "◆"
#define RADIO_EMPTY "○"
#define RADIO_FILLED "●"
#define BOX_VERTICAL "│"
#define BOX_CORNER "└"

// non-character key actions
#define UP 1000
#define DOWN 1001
#define RIGHT 1002
#define LEFT 1003
#define DELETE 1004

// ASCII
#define DEL 127
#define BACKSPACE 8
#define CTRL_C 3

#define REQUIRED_FIELD "This field is required"

#define DEFAULT_MAX_LENGTH 1024

static void enable_raw_mode(void) {
    if (!terminal_initialized)
    {
        tcgetattr(STDIN_FILENO, &termios);
        terminal_initialized = true;
    }
    
    struct termios raw = termios;
    raw.c_lflag &= ~(ECHO | ICANON | ISIG);
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
}

static void disable_raw_mode(void) {
    if (terminal_initialized)
    {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &termios);
    }
}

static void clear_line(void) {
    printf("\033[2K\r");
}

static void move_cursor_up(int n) {
    if (n > 0) printf("\033[%dA", n);
}

static void move_cursor_down(int n) {
    if (n > 0) printf("\033[%dB", n);
}

static void hide_cursor(void) {
    printf("\033[?25l");
    fflush(stdout);
}

static void show_cursor(void) {
    printf("\033[?25h");
    fflush(stdout);
}

static void set_color(prompt_color color) {
    printf("%s", color_codes[color]);
}

static int read_key(void) {
    char c;
    if (read(STDIN_FILENO, &c, 1) == 1)
    {
        if (c == '\033')
        {
            char seq[3];
            if (read(STDIN_FILENO, &seq[0], 1) != 1) return c;
            if (read(STDIN_FILENO, &seq[1], 1) != 1) return c;

            if (seq[0] == '[')
            {
                switch (seq[1])
                {
                    case 'A': return UP;
                    case 'B': return DOWN;
                    case 'C': return RIGHT;
                    case 'D': return LEFT;
                    case '3': {
                        char del;
                        if (read(STDIN_FILENO, &del, 1) == 1 && del == '~')
                        {
                            return DELETE;
                        }
                        return c;
                    }
                }
            }   
            return c;
        }
        return c;
    }
    return -1;
}

void prompt_cleanup(void) {
    disable_raw_mode();
    show_cursor();
}

char* prompt_input(const struct input_config *config) {
    enable_raw_mode();
    hide_cursor();

    size_t buffer_size = config->max_length > 0 ? config->max_length : DEFAULT_MAX_LENGTH;
    char *input = calloc(buffer_size, sizeof(char));
    size_t input_len = 0;
    size_t cursor_pos = 0;
    bool done = false;
    bool first_render = true;
    char error_msg[256] = {0};

    while (!done)
    {
        /* Clear previous output - move up one line at a time */
        if (!first_render) {
            clear_line();          
            move_cursor_up(1);    
            clear_line();          
            move_cursor_up(1);    
            clear_line();         
        }
        first_render = false;

        set_color(COLOR_CYAN);
        printf("%s  %s\n", BOX_EMPTY, config->title);
        set_color(COLOR_RESET);
        printf("%s  ", BOX_VERTICAL);

        if (input_len == 0 && config->placeholder)
        {
            set_color(COLOR_GRAY);
            printf("%s", config->placeholder);
            set_color(COLOR_RESET);
        } else
        {
            for (size_t i = 0; i < input_len; i++)
            {
                if (i == cursor_pos)
                {
                    set_color(COLOR_GREEN);
                    printf("%c", input[i]);
                    set_color(COLOR_RESET);
                } else {
                    printf("%c", input[i]);
                }
            }
            if (cursor_pos == input_len) 
            {
                set_color(COLOR_GREEN);
                printf("_");
                set_color(COLOR_RESET);
            }
        }
        printf("\n");

        if (error_msg[0])
        {
            set_color(COLOR_RED);
            printf("%s  %s", BOX_VERTICAL, error_msg);
            set_color(COLOR_RESET);
        }
        
        fflush(stdout);

        int key = read_key();
        
        switch (key)
        {
            case CTRL_C:
                free(input);
                prompt_cleanup();
                printf("\n");
                exit(0);
                break;

            case '\n':
            case '\r':
                error_msg[0] = '\0';
                if (config->required && input_len == 0)
                {
                    snprintf(error_msg, sizeof(error_msg), REQUIRED_FIELD);
                    continue;
                }
                
                if (config->validator && input_len > 0)
                {
                    if (!config->validator(input, error_msg, sizeof(error_msg)))
                    {
                        continue;
                    }
                    
                }

                done = true;
                break;

            case DEL:
            case BACKSPACE:    
                if (cursor_pos > 0)
                {
                    memmove(&input[cursor_pos - 1], &input[cursor_pos], input_len - cursor_pos);
                    input_len--;
                    cursor_pos--;
                    input[input_len] = '\0';
                    error_msg[0] = '\0';
                }
                break;

            case DELETE: 
                if (cursor_pos < input_len) 
                {
                    memmove(&input[cursor_pos], &input[cursor_pos + 1], input_len - cursor_pos - 1);
                    input_len--;
                    input[input_len] = '\0';
                    error_msg[0] = '\0';
                }
                break;
                
            case LEFT:  
                if (cursor_pos > 0) cursor_pos--;
                break;
                
            case RIGHT:  
                if (cursor_pos < input_len) cursor_pos++;
                break;
                
            default:
                if (key >= 32 && key < 127)
                {
                    if (input_len < buffer_size - 1)
                    {
                        memmove(&input[cursor_pos + 1], &input[cursor_pos], input_len - cursor_pos);
                        input[cursor_pos] = key;
                        input_len++;
                        cursor_pos++;
                        input[input_len] = '\0';
                        error_msg[0] = '\0';
                    }
                }
                break;
        }
    }
    
    clear_line();          
    move_cursor_up(1);     
    clear_line();          
    move_cursor_up(1);     
    clear_line();          
    
    set_color(COLOR_CYAN);
    printf("%s  %s\n", BOX_FILLED, config->title);
    set_color(COLOR_RESET);
    printf("%s  ", BOX_VERTICAL);
    set_color(COLOR_GREEN);
    printf("%s\n", input);
    set_color(COLOR_RESET);
    
    show_cursor();
    disable_raw_mode();
    
    return input;
}

int prompt_select(const struct select_config *config) {
    enable_raw_mode();
    hide_cursor();

    int selected = config->default_index >= 0 ? config->default_index : 0;
    bool done = false;
    bool first_render = true;

    while (!done)
    {
        if (!first_render) {
            clear_line();                           
            for (size_t i = 0; i < config->option_count + 1; i++)
            {
                move_cursor_up(1);                  
                clear_line();                       
            }
        }
        first_render = false;

        set_color(COLOR_CYAN);
        printf("%s  %s\n", BOX_EMPTY, config->title);
        set_color(COLOR_RESET);

        for (size_t i = 0; i < config->option_count; i++)
        {
            printf("%s  ", BOX_VERTICAL);

            if ((int)i == selected)
            {
                set_color(COLOR_GREEN);
                printf("%s %s\n", RADIO_FILLED, config->options[i]);
                set_color(COLOR_RESET);
            } else
            {
                printf("%s %s\n", RADIO_EMPTY, config->options[i]);
            }
        }

        fflush(stdout);

        int key = read_key();

        switch (key)
        {
            case CTRL_C:
                prompt_cleanup();
                printf("\n");
                exit(0);
                break;

            case '\n':
            case '\r':
                done = true;
                break;
            
            case UP:
                selected = (selected - 1 + config->option_count) % config->option_count;
                break;
            
            case DOWN:
                selected = (selected + 1) % config->option_count;
                break;

            default:
                break;
        }
    }
    
    clear_line();                           
    for (size_t i = 0; i < config->option_count + 1; i++)
    {
        move_cursor_up(1);                 
        clear_line();                       
    }
    
    set_color(COLOR_CYAN);
    printf("%s  %s\n", BOX_FILLED, config->title);
    set_color(COLOR_RESET);
    printf("%s  ", BOX_VERTICAL);
    set_color(COLOR_GREEN);
    printf("%s\n", config->options[selected]);
    set_color(COLOR_RESET);

    show_cursor();
    disable_raw_mode();
    
    return selected;
}

bool prompt_confirm(const struct confirm_config *config) {
    enable_raw_mode();
    hide_cursor();
    
    bool choice = config->is_yes_default;
    bool done = false;
    bool first_render = true;
    
    while (!done) 
    {
        if (!first_render) {
            clear_line();          
            move_cursor_up(1);     
            clear_line();         
            move_cursor_up(1);     
            clear_line();          
        }
        first_render = false;
        
        set_color(COLOR_CYAN);
        printf("%s  %s\n", BOX_EMPTY, config->title);
        set_color(COLOR_RESET);
        printf("%s  ", BOX_VERTICAL);
        
        if (choice) 
        {
            set_color(COLOR_GREEN);
            printf("%s Yes", RADIO_FILLED);
            set_color(COLOR_RESET);
            printf(" / %s No\n", RADIO_EMPTY);
        } else 
        {
            printf("%s Yes", RADIO_EMPTY);
            printf(" / ");
            set_color(COLOR_GREEN);
            printf("%s No\n", RADIO_FILLED);
            set_color(COLOR_RESET);
        }
        
        fflush(stdout);
        
        int key = read_key();
        
        switch (key) 
        {
            case CTRL_C:
                prompt_cleanup();
                printf("\n");
                exit(0);
                break;

            case '\n':
            case '\r':
                done = true;
                break;
                
            case LEFT:  
            case RIGHT:  
            case 'h':
            case 'l':
                choice = !choice;
                break;
                
            case 'y':
            case 'Y':
                choice = true;
                done = true;
                break;
                
            case 'n':
            case 'N':
                choice = false;
                done = true;
                break;
        }
    }
    
    clear_line();          
    move_cursor_up(1);     
    clear_line();          
    move_cursor_up(1);     
    clear_line();         
    
    set_color(COLOR_CYAN);
    printf("%s  %s\n", BOX_FILLED, config->title);
    set_color(COLOR_RESET);
    printf("%s  ", BOX_CORNER);
    set_color(choice ? COLOR_GREEN : COLOR_RED);
    printf("%s\n", choice ? "Yes" : "No");
    set_color(COLOR_RESET);
    
    show_cursor();
    disable_raw_mode();
    
    return choice;
}