#include <string.h>
#include <arpa/inet.h>
#include "hello.h"

void hello_parser_init(struct hello_parser *p) {
    p->state = hello_version;
    memset(p, 0, sizeof(*p));
}

enum hello_state hello_consume(buffer *b, struct hello_parser *p, bool *errored) {
    enum hello_state state = p->state;
    
    while (buffer_can_read(b)) {
        uint8_t c = buffer_read(b);
        
        switch (state) {
            case hello_version:
                if (c == 0x05) {  // SOCKS version 5
                    state = hello_nmethods;
                } else {
                    state = hello_error;
                    *errored = true;
                }
                break;
                
            case hello_nmethods:
                p->remaining = c;  // Number of methods
                if (p->remaining > 0) {
                    state = hello_methods;
                } else {
                    state = hello_error;
                    *errored = true;
                }
                break;
                
            case hello_methods:
                // Store the method (we just need to know if NO_AUTH is present)
                if (c == 0x00) {  // NO_AUTH
                    p->method = 0x00;
                }
                p->remaining--;
                
                if (p->remaining == 0) {
                    state = hello_done;
                }
                break;
                
            case hello_done:
            case hello_error:
                // Terminal states
                break;
        }
        
        p->state = state;
        
        if (hello_is_done(state, errored)) {
            break;
        }
    }
    
    return state;
}

bool hello_is_done(enum hello_state state, bool *errored) {
    return state == hello_done || state == hello_error || (errored && *errored);
}

int hello_marshall(buffer *b, uint8_t method) {
    size_t n;
    uint8_t *buff = buffer_write_ptr(b, &n);
    
    if (n < 2) {
        return -1;  // Not enough space
    }
    
    buff[0] = 0x05;  // SOCKS version 5
    buff[1] = method; // Selected method (0x00 for NO_AUTH)
    
    buffer_write_adv(b, 2);
    return 2;
}