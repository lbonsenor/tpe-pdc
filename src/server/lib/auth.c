#include "auth.h"
#include <string.h>

void auth_parser_init(struct auth_parser *p)
{
    if (p != NULL)
    {
        memset(p, 0, sizeof(*p));
        p->state = AUTH_STATE_VERSION;
    }
    
}

enum auth_state auth_consume(buffer *b, struct auth_parser *p, bool *error){
    if (p == NULL || b == NULL || error == NULL)
    {
        if (error) *error = true;
        return AUTH_STATE_ERROR;
    }

    *error = false;

    while (buffer_can_read(b) && p->state != AUTH_STATE_DONE && p->state != AUTH_STATE_ERROR)
    {
        size_t nbytes;
        uint8_t *ptr = buffer_read_ptr(b, &nbytes);

        if (nbytes == 0)
        {
            break;
        }
        
        switch (p->state)
        {
            case AUTH_STATE_VERSION:
                p->version = *ptr;
                buffer_read_adv(b, 1);

                if (p->version != AUTH_VERSION)
                {
                    p->state = AUTH_STATE_ERROR;
                    *error = true;
                } else
                {
                    p->state = AUTH_STATE_ULEN;
                }
                break;
            case AUTH_STATE_ULEN:
                p->ulen = *ptr;
                buffer_read_adv(b, 1);

                if (p->ulen == 0)
                {
                    p->state = AUTH_STATE_ERROR;
                    *error = true;
                } else {
                    p->username_read = 0;
                    p->state = AUTH_STATE_UNAME;
                }
                break;
            case AUTH_STATE_UNAME:
                if (p->username_read < p->ulen && p->username_read < 255)
                {
                    p->username[p->username_read++] = *ptr;
                    buffer_read_adv(b, 1);

                    if (p->username_read >= p->ulen)
                    {
                        p->username[p->username_read] = '\0';
                        p->state = AUTH_STATE_PLEN;
                    } 
                } else
                {
                    p->state = AUTH_STATE_ERROR;
                    *error = true;
                }
                break;
            case AUTH_STATE_PLEN:
                p->plen = *ptr;
                buffer_read_adv(b, 1);

                if (p->plen == 0)
                {
                    p->state = AUTH_STATE_ERROR;
                    *error = true;
                } else 
                {
                    p->password_read = 0;
                    p->state = AUTH_STATE_PASSWD;
                }
                break;

            case AUTH_STATE_PASSWD:
                if (p->password_read < p->plen && p->password_read < 255)
                {
                    p->password[p->password_read++] = *ptr;
                    buffer_read_adv(b, 1);

                    if (p->password_read >= p->plen)
                    {
                        p->password[p->password_read] = '\0';
                        p->state = AUTH_STATE_DONE;
                    } 
                } else
                {
                    p->state = AUTH_STATE_ERROR;
                    *error = true;
                }
                break;                
                
            default:
                p->state = AUTH_STATE_ERROR;
                *error = true;
                break;
        }
    }
    
    return p->state;
}

bool auth_is_done(enum auth_state state, bool *error)
{
    return state == AUTH_STATE_DONE || state == AUTH_STATE_ERROR || (error && *error);
}

int auth_marshall(buffer *b, enum auth_status status)
{
    if (b == NULL || !buffer_can_write(b))
        return -1;

    size_t nbytes;
    uint8_t *ptr = buffer_write_ptr(b, &nbytes);

    if (nbytes < 2)
        return -1;
    
    ptr[0] = AUTH_VERSION;  
    ptr[1] = status;        
    
    buffer_write_adv(b, 2);
    
    return 0;
    
}
