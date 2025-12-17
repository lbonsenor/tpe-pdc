#ifndef HELLO_H
#define HELLO_H

#include <stdint.h>
#include <stdbool.h>
#include "buffer.h"

enum hello_state {
    hello_version,
    hello_nmethods,
    hello_methods,
    hello_done,
    hello_error,
};

struct hello_parser {
    enum hello_state state;
    uint8_t remaining;  // Remaining methods to read
    uint8_t method;     // Selected method (0x00 for NO_AUTH)
};

/** Initialize hello parser */
void hello_parser_init(struct hello_parser *p);

/** 
 * Consume bytes from buffer and parse HELLO message 
 * Returns current state, sets errored on parse error
 */
enum hello_state hello_consume(buffer *b, struct hello_parser *p, bool *errored);

/** Check if parsing is complete */
bool hello_is_done(enum hello_state state, bool *errored);

/** 
 * Marshall HELLO response into buffer
 * Returns number of bytes written, -1 on error
 */
int hello_marshall(buffer *b, uint8_t method);

#endif