/**
 * stm.c - pequeño motor de maquina de estados donde los eventos son los
 *         del selector.c
 */
#include <stdio.h>
#include "stm.h"

void
stm_init(struct state_machine *stm) {
    printf("DEBUG: stm_init called, stm=%p\n", (void*)stm);
    printf("DEBUG: initial=%u, max_state=%u, states=%p\n", 
           stm->initial, stm->max_state, (void*)stm->states);
    
    if (stm == NULL || stm->states == NULL) {
        printf("DEBUG: ERROR - stm or states is NULL!\n");
        return;
    }
    
    stm->current = stm->initial;
    
    printf("DEBUG: Looking for initial state %u in state table\n", stm->initial);
    
    // Find initial state and call on_arrival if needed
    for (unsigned i = 0; i <= stm->max_state; i++) {
        printf("DEBUG: Checking states[%u].state = %u\n", i, stm->states[i].state);
        
        if (stm->states[i].state == stm->initial) {
            printf("DEBUG: Found initial state, on_arrival=%p\n", 
                   (void*)stm->states[i].on_arrival);
            
            // Note: on_arrival will be called later when selector_key is available
            break;
        }
    }
    
    printf("DEBUG: stm_init completed\n");
}

static const struct state_definition *
state_from_stm(struct state_machine *stm) {
    if (stm == NULL || stm->states == NULL) {
        return NULL;
    }
    
    // Find the current state in the state table
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
    
    printf("DEBUG: Transitioning from state %u to %u\n", stm->current, next);
    
    // Call on_departure for current state if it exists
    const struct state_definition *old_state = state_from_stm(stm);
    if (old_state != NULL && old_state->on_departure != NULL) {
        old_state->on_departure(stm->current, key);
    }
    
    // Update current state
    stm->current = next;
    
    // Find the new state and call on_arrival if it exists
    const struct state_definition *new_state = state_from_stm(stm);
    if (new_state != NULL && new_state->on_arrival != NULL) {
        printf("DEBUG: Calling on_arrival for state %u\n", next);
        new_state->on_arrival(next, key);
    }
}

unsigned
stm_handler_read(struct state_machine *stm, struct selector_key *key) {
    printf("DEBUG: stm_handler_read called, current=%u\n", stm->current);
    
    const struct state_definition *state = state_from_stm(stm);
    
    printf("DEBUG: state=%p, on_read_ready=%p\n", 
           (void*)state, (void*)(state ? state->on_read_ready : NULL));
    
    if (state == NULL || state->on_read_ready == NULL) {
        printf("DEBUG: No read handler for state %u\n", stm->current);
        return stm->current;
    }
    
    unsigned next = state->on_read_ready(key);
    
    printf("DEBUG: on_read_ready returned next=%u\n", next);
    
    if (next != stm->current) {
        handle_transition(stm, next, key);
    }
    
    return next;
}

unsigned
stm_handler_write(struct state_machine *stm, struct selector_key *key) {
    printf("DEBUG: stm_handler_write called, current=%u\n", stm->current);
    
    const struct state_definition *state = state_from_stm(stm);
    
    printf("DEBUG: state=%p, on_write_ready=%p\n", 
           (void*)state, (void*)(state ? state->on_write_ready : NULL));
    
    if (state == NULL || state->on_write_ready == NULL) {
        printf("DEBUG: No write handler for state %u\n", stm->current);
        return stm->current;
    }
    
    unsigned next = state->on_write_ready(key);
    
    printf("DEBUG: on_write_ready returned next=%u\n", next);
    
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
