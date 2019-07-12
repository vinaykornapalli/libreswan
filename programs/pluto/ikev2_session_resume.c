/*
 *  Helper functions and ticket store for IKEv2 Session Resumption
*/
#include <unistd.h>
#include "state.h"
#include "packet.h"
#include "lswalloc.h"

#include "ikev2_session_resume.h"

/* Functions for making and emitting ticket payload*/

/* */
bool create_ticket_payload(struct state *st, struct ticket_payload *t_payload) {
    size_t len = sizeof(ticket_by_value);
    struct ticket_by_value *ticket = alloc_bytes( len, 
                                       "Ticket by value memory allocation");
    //copying the state to the ticket.
    ticket->st = *st;
    
    chunk_t ticket_body;
    ticket_body = chunk(ticket , len);
    //The chunk value is stored in ticket payload.
    t_payload->ticket = ticket_body;
    return TRUE;
}

bool emit_ticket_payload(struct ticket_payload *t_payload, pb_stream *pbs) {
        // To-do: Lifetime is to be added at the time of emiting
		return out_chunk(t_payload->ticket, pbs, "opaque_ticket");
}
