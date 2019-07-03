/*
 *  Helper functions and ticket store for IKEv2 Session Resumption
*/

#include "ikev2_session_resume.h"
#include "state.h"
#include "packet.h"


/* Functions for making and emitting ticket payload*/

bool create_ticket_payload(chunk_t ticket, struct ticket_payload *t_payload) {
    t_payload->ticket = ticket;
    return TRUE;
}

bool emit_ticket_payload(struct ticket_payload *t_payload, pb_stream *pbs) {
		return out_chunk(t_payload->ticket, pbs, "PPK_ID");
}