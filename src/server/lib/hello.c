#include <string.h>

#include "hello.h"

void hello_parser_init(struct hello_parser *p)
{
    if (p != NULL)
    {
        memset(p, 0, sizeof(*p));
        p->state = HELLO_VERSION;
    }
}

enum hello_state hello_consume(buffer *b, struct hello_parser *p, bool *error)
{
    if (p == NULL || b == NULL || error == NULL)
    {
        if (error) *error = true;
        return HELLO_ERROR;
    }
    
    *error = false;

    while (buffer_can_read(b) && p->state != HELLO_DONE && p->state != HELLO_ERROR)
    {
        size_t nbytes;
        uint8_t *ptr = buffer_read_ptr(b, &nbytes);

        if (nbytes == 0)
            break;
        
        switch (p->state)
        {
            case HELLO_VERSION:
                p->version = *ptr;
                buffer_read_adv(b, 1);

                if (p->version != SOCKS_VERSION)
                {
                    p->state = HELLO_ERROR;
                    *error = true;
                } else
                {
                    p->state = HELLO_NMETHODS;
                }
                break;
            
            case HELLO_NMETHODS:
                p->nmethods = *ptr;
                buffer_read_adv(b, 1);

                if (p->nmethods == 0)
                {
                    p->state = HELLO_ERROR;
                    *error = true;
                } else
                {
                    p->state = HELLO_METHODS;
                    p->methods_read = 0;
                }
                break;

            case HELLO_METHODS:
                if (p->on_authentication_method != NULL)
                {
                    p->on_authentication_method(p, *ptr);
                }
                buffer_read_adv(b, 1);
                p->methods_read++;
                
                if (p->methods_read >= p->nmethods)
                {
                    p->state = HELLO_DONE;
                }
                break;
                
            default:
                p->state = HELLO_ERROR;
                *error = true;
                break;
        }

    }

    return p->state;
}

bool hello_is_done(enum hello_state state, bool *error)
{
    return state == HELLO_DONE || state == HELLO_ERROR;
}

int hello_marshall(buffer *b, uint8_t method)
{
    if (b == NULL || !buffer_can_write(b)) 
        return -1;
    
    size_t nbytes;
    uint8_t *ptr = buffer_write_ptr(b, &nbytes);
    
    if (nbytes < 2) 
        return -1;
    
    ptr[0] = SOCKS_VERSION;
    ptr[1] = method;
    buffer_write_adv(b, 2);
    
    return 0;
}

int hello_parser_close(struct hello_parser *p)
{
    // TODO
}
