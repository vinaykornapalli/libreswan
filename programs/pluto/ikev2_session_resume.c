/*
 *  Helper functions and ticket store for IKEv2 Session Resumption
*/
#include <unistd.h>
#include "state.h"
#include "packet.h"
#include "lswalloc.h"

#include "ikev2_session_resume.h"

#define USE_TICKET_BY_VALUE 1
#define USE_TICKET_BY_REFERENCE 0

/* Functions for making and emitting ticket payload*/



struct chunk_t *st_to_ticket(const struct state *st) {

    struct *ticket_payload ticket_payl = alloc_bytes(sizeof(ticket_payload));

    if (USE_TICKET_BY_VALUE) {
       struct ticket_by_value *tk = &(ticket_payl->ticket.tk_by_value);

       /*To be set as 1 for this version of protocol*/
       tk->format_version = 1;
       /*This has no use but implemented as per RFC*/
       tk->reserved = 0;

       struct ike_ticket_state *ts = &(tk->ike_tk_state);

       ts->st_ike_spis = st->st_ike_spis;
       /* IDi */
       ts->st_myuserport = st->st_myuserport;
       ts->st_myuserprotoid = st->st_myuserprotoid;
       /* IDr */
       ts->st_peeruserport = st->st_peeruserport;
       ts->st_peeruserprotoid = st->st_peeruserprotoid;

       /*SKEYSEED OLD*/
       ts->st_skey_d_nss = st->st_skey_d_nss;

       /* All the IKE negotiations */
       ts->st_oakley = st->st_oakley;
    }


    chunk_t *ticket_payl_chunk = chunk(ticket_payl , sizeof(ticket_payload));
    return ticket_payl_chunk;
}

struct state *ticket_to_st(const struct chunk_t *ticket) {



return st; 
}





/* */
// bool create_ticket_payload(struct state *st, struct ticket_payload *t_payload) {
//     size_t len = sizeof(ticket_by_value);
//     struct ticket_by_value *ticket = alloc_bytes( len, 
//                                        "Ticket by value memory allocation");
//     //copying the state to the ticket.
//     ticket->st = *st;
    
//     chunk_t ticket_body;
//     ticket_body = chunk(ticket , len);
//     //The chunk value is stored in ticket payload.
//     t_payload->ticket = ticket_body;
//     return TRUE;
// }

// bool emit_ticket_payload(struct ticket_payload *t_payload, pb_stream *pbs) {
//         // To-do: Lifetime is to be added at the time of emiting
// 		return out_chunk(t_payload->ticket, pbs, "opaque_ticket");
// }
