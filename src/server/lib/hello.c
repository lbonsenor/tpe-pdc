#include <string.h>
#include <stdbool.h>
#include "hello.h"
#include "buffer.h"

void hello_parser_init(struct hello_parser *p) {
    p->state = HELLO_VERSION;
    // Don't set method_idx, just initialize what exists in the struct
}

enum hello_state hello_consume(buffer *b, struct hello_parser *p, bool *error) {
    *error = false;
    
    while (buffer_can_read(b)) {
        uint8_t byte = buffer_read(b);
        
        switch (p->state) {
            case HELLO_VERSION:
                if (byte != 0x05) {
                    *error = true;
                    p->state = HELLO_ERROR;
                    return HELLO_ERROR;
                }
                p->state = HELLO_NMETHODS;
                break;
                
            case HELLO_NMETHODS:
                p->nmethods = byte;
                // nmethods will track how many methods we need to read
                p->state = (byte > 0) ? HELLO_METHODS : HELLO_DONE;
                break;
                
            case HELLO_METHODS:
                // Call the callback for each method
                if (p->on_authentication_method) {
                    p->on_authentication_method(p, byte);
                }
                // Decrement nmethods to track remaining methods
                p->nmethods--;
                if (p->nmethods == 0) {
                    p->state = HELLO_DONE;
                }
                break;
                
            case HELLO_DONE:
            case HELLO_ERROR:
                return p->state;
        }
    }
    
    return p->state;
}

bool hello_is_done(enum hello_state state, bool *error) {
    if (state == HELLO_ERROR) {
        if (error) *error = true;
        return true;
    }
    return state == HELLO_DONE;
}

int hello_marshall(buffer *b, uint8_t method) {
    size_t n;
    uint8_t *buff = buffer_write_ptr(b, &n);
    
    if (n < 2) {
        return -1;
    }
    
    buff[0] = 0x05;  // SOCKSv5
    buff[1] = method;
    buffer_write_adv(b, 2);
    
    return 2;
}