#include "../include/request.h"

#include <string.h>
#include <arpa/inet.h>
#include "request.h"

void request_parser_init(struct request_parser *p)
{   
    if (p != NULL)
    {
        memset(p, 0, sizeof(*p));
        p->state = REQUEST_VERSION;
    }   
}

enum request_state request_consume(buffer *b, struct request_parser *p, bool *error)
{
    if (p == NULL || b == NULL || error == NULL)
    {
        if (error) *error = true;
        return REQUEST_ERROR;
    }
    
    *error = false;

    while (buffer_can_read(b) && p->state != REQUEST_DONE && p->state != REQUEST_ERROR)
    {
        size_t nbytes;
        uint8_t *ptr = buffer_read_ptr(b, &nbytes);

        if (nbytes == 0)
        {
            break;
        }

        switch (p->state)
        {
            case REQUEST_VERSION:
                p->version = *ptr;
                buffer_read_adv(b, 1);

                if (p->version != 0x05)
                {
                    p->state = REQUEST_ERROR;
                    *error = true;
                } else
                {
                    p->state = REQUEST_CMD;
                }
                break;
            
            case REQUEST_CMD:
                p->cmd = *ptr;
                buffer_read_adv(b, 1);

                if (p->cmd < 0x01 || p->cmd > 0x03)
                {
                    p->state = REQUEST_ERROR;
                    *error = true;
                } else
                {
                    p->state = REQUEST_RSV;
                }
                break;
            
            case REQUEST_RSV:
                if (*ptr != 0x00)
                {
                    p->state = REQUEST_ERROR;
                    *error = true;
                } else
                {
                    buffer_read_adv(b, 1);
                    p->state = REQUEST_ATYP;
                }
                break;
                
            case REQUEST_ATYP:
                p->atyp = *ptr;
                buffer_read_adv(b, 1);
                
                p->addr_bytes_read = 0;
                p->domain_bytes_read = 0;

                switch (p->atyp)
                {
                    case SOCKS_ATYP_IPV4:
                        p->state = REQUEST_DSTADDR_IPV4;
                        break;
                    case SOCKS_ATYP_IPV6:
                        p->state = REQUEST_DSTADDR_IPV6;
                        break;
                    case SOCKS_ATYP_DOMAIN:
                        p->state = REQUEST_DSTADDR_FQDN_LEN;
                        break;
                    default:
                        p->state = REQUEST_ERROR;
                        *error = true;
                        break;
                }
                break;
            
                case REQUEST_DSTADDR_IPV4:
                    p->dest_addr.ipv4[p->addr_bytes_read++] = *ptr;
                    buffer_read_adv(b, 1);

                    if (p->addr_bytes_read >= 4)
                    {
                        p->port_bytes_read = 0;
                        p->state = REQUEST_DSTPORT;
                    }
                    break;
                    
                case REQUEST_DSTADDR_IPV6:
                    p->dest_addr.ipv6[p->addr_bytes_read++] = *ptr;
                    buffer_read_adv(b, 1);

                    if (p->addr_bytes_read >= 16)
                    {
                        p->port_bytes_read = 0;
                        p->state = REQUEST_DSTPORT;
                    }
                    break;
                    
                case REQUEST_DSTADDR_FQDN_LEN:
                    p->domain_len = *ptr;
                    buffer_read_adv(b, 1);

                    if (p->domain_len == 0)
                    {
                        p->state = REQUEST_ERROR;
                        *error = true;
                    } else
                    {
                        p->domain_bytes_read = 0;
                        p->state = REQUEST_DSTADDR_FQDN;
                    }
                    break;
                
                case REQUEST_DSTADDR_FQDN:
                    if (p->domain_bytes_read < p->domain_len && p->domain_bytes_read < 255)
                    {
                        p->dest_addr.domain[p->domain_bytes_read++] = *ptr;
                        buffer_read_adv(b, 1);

                        if (p->domain_bytes_read >= p->domain_len)
                        {
                            p->dest_addr.domain[p->domain_bytes_read] = '\0';
                            p->port_bytes_read = 0;
                            p->state = REQUEST_DSTPORT;
                        }
                    } else
                    {
                        p->state = REQUEST_ERROR;
                        *error = true;
                    }
                    break;

                case REQUEST_DSTPORT:
                    if (p->port_bytes_read == 0)
                    {
                        p->dest_port = (*ptr) << 8; // byte mas significativo
                        p->port_bytes_read = 1;
                    } else
                    {
                        p->dest_port = p->dest_port | *ptr; // byte menos significativo
                        p->port_bytes_read = 2;
                    }

                    buffer_read_adv(b, 1);
                    if (p->port_bytes_read >= 2)
                    {
                        p->state = REQUEST_DONE;
                    }
                    break;
                
            default:
                p->state = REQUEST_ERROR;
                *error = true;
                break;
        }
        
    }
    return p->state;

}

int request_marshall(buffer *b, enum socks_reply reply)
{
    if (b == NULL || !buffer_can_write(b))
    {
        return -1;
    }
    
    size_t nbytes;
    uint8_t *ptr = buffer_write_ptr(b, &nbytes);

    if (nbytes < 10)
    {
        return -1;
    }
    
    ptr[0] = 0x05;           // VER
    ptr[1] = reply;          // REP
    ptr[2] = 0x00;           // RSV
    ptr[3] = 0x01;           // ATYP = IPv4
    ptr[4] = 0x00;           // BND.ADDR = 0.0.0.0
    ptr[5] = 0x00;
    ptr[6] = 0x00;
    ptr[7] = 0x00;
    ptr[8] = 0x00;           // BND.PORT = 0
    ptr[9] = 0x00;

    buffer_write_adv(b, 10);

    return 0;
}

bool is_request_done(enum request_state state, bool *error)
{
    return state == REQUEST_DONE || state == REQUEST_ERROR;
}

void request_parser_close(struct request_parser *p)
{
    // Nothing to free currently
    (void)p;
}


