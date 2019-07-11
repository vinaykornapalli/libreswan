/*
 *  Helper functions and ticket store for IKEv2 Session Resumption
*/

#ifndef IKEV2_SESSION_RESUME_H
#define IKEV2_SESSION_RESUME_H

#include "state.h"
#include "packet.h"
#include "deltatime.h"

/*
 * There are two types for ticket:
 * 1.Ticket by Value
 * 2.Ticket by Reference
 * Whenever a initiator(client) requests for a ticket the responder should select any of
 * the above types and send it to client but client should not have any idea about the type 
 * received.


*/

/* Ticket by value structures */
struct ticket_by_value {

/*currently bear state without any encryption is sent*/
 struct state st;
};

/* Ticket by reference structures */

struct ikev2_state_ref {

};

struct ticket_by_reference {
   uint8_t format_version;

};

struct ticket_payload {
    deltatime_t lifetime;
    chunk_t ticket;

};


/* Functions related to ticket */

extern bool create_ticket_payload(struct state *st struct ticket_payload *t_payload);
extern bool emit_ticket_payload(struct ticket_payload *t_payload, pb_stream *pbs);
extern bool client_recv_ticket(pb_stream *pbs);


#endif