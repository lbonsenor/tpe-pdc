/**
 * stm.c - pequeño motor de maquina de estados donde los eventos son los
 *         del selector.c
 */
#include <stdio.h>
#include "stm.h"

void
stm_init(struct state_machine *stm) {
    if (stm == NULL || stm->states == NULL) {
        return;
    }
    
    stm->current = stm->initial;
}

static const struct state_definition *
state_from_stm(struct state_machine *stm) {
    if (stm == NULL || stm->states == NULL) {
        return NULL;
    }
    
    for (unsigned i = 0; i <= stm->max_state; i++) {
        if (stm->states[i].state == stm->current) {
            return &stm->states[i];
        }
    }
    
    return NULL;
}

static void
handle_transition(struct state_machine *stm, unsigned next, struct selector_key *key) {
    if (stm == NULL || next > stm->max_state) {
        return;
    }
    
    const struct state_definition *old_state = state_from_stm(stm);
    if (old_state != NULL && old_state->on_departure != NULL) {
        old_state->on_departure(stm->current, key);
    }
    
    stm->current = next;
    
    const struct state_definition *new_state = state_from_stm(stm);
    if (new_state != NULL && new_state->on_arrival != NULL) {
        new_state->on_arrival(next, key);
    }
}

unsigned
stm_handler_read(struct state_machine *stm, struct selector_key *key) {
    const struct state_definition *state = state_from_stm(stm);
    
    if (state == NULL || state->on_read_ready == NULL) {
        return stm->current;
    }
    
    unsigned next = state->on_read_ready(key);
    
    if (next != stm->current) {
        handle_transition(stm, next, key);
    }
    
    return next;
}

unsigned
stm_handler_write(struct state_machine *stm, struct selector_key *key) {
    const struct state_definition *state = state_from_stm(stm);
    
    if (state == NULL || state->on_write_ready == NULL) {
        return stm->current;
    }
    
    unsigned next = state->on_write_ready(key);
    
    if (next != stm->current) {
        handle_transition(stm, next, key);
    }
    
    return next;
}

unsigned
stm_handler_block(struct state_machine *stm, struct selector_key *key) {
    const struct state_definition *state = state_from_stm(stm);
    
    if (state == NULL || state->on_block_ready == NULL) {
        return stm->current;
    }
    
    unsigned next = state->on_block_ready(key);
    
    if (next != stm->current) {
        handle_transition(stm, next, key);
    }
    
    return next;
}

void
stm_handler_close(struct state_machine *stm, struct selector_key *key) {
    const struct state_definition *state = state_from_stm(stm);
    
    if (state != NULL && state->on_departure != NULL) {
        state->on_departure(stm->current, key);
    }
}

unsigned
stm_state(struct state_machine *stm) {
    return stm->current;
}
