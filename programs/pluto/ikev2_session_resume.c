/*
 *  Helper functions and ticket store for IKEv2 Session Resumption
*/
#include <unistd.h>
#include "state.h"
#include "packet.h"
#include "lswalloc.h"
#include "state_db.h"
#include "timer.h"
#include "ikev2_session_resume.h"

/* currently ticket by value is used */
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

}


void ikev2_session_resume_outI1(fd_t whack_sock,
			      struct connection *c,
			      struct state *st,
			      ) {
    /* set up reply */
    init_out_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
                 "reply packet");

    /* HDR out */
    pb_stream rbody = open_v2_message(&reply_stream, ike_sa(st),
                                      NULL /* request */,
                                      ISAKMP_v2_IKE_SESSION_RESUME);
    if (!pbs_ok(&rbody)) {
        return;
    }

    /* send NONCE */
    {
        pb_stream pb;
        struct ikev2_generic in = {
            .isag_np = ISAKMP_NEXT_v2N,
            .isag_critical = build_ikev2_critical(false),
        };

        if (!out_struct(&in, &ikev2_nonce_desc, &rbody, &pb) ||
            !out_chunk(st->st_ni, &pb, "IKEv2 nonce"))
            return STF_INTERNAL_ERROR;

        close_output_pbs(&pb);
    }
    /* send TICKET_OPAQUE */
    if (!emit_v2NChunk(v2N_TICKET_OPAQUE, &(st->ticket_stored), &rbody)) {
			return;
	}

    close_output_pbs(&reply_stream);
    record_outbound_ike_msg(st, &reply_stream, "Request packet for Session Resumption");
    
}



/* Functions related to hibernate/resume connection */
void hibernate_connection(struct connection *c) {

    struct state *pst = state_with_serialno(c->newest_isakmp_sa);
    struct state *cst = state_with_serialno(c->newest_ipsec_sa);

    /* Deleting the child sa of the current state */
    event_force(EVENT_SA_EXPIRE, cst);
    /* Marking parent state as hibernated */
    pst->st_hibernated = TRUE;
    /* State should be tranistioned in STATE_PARENT_HIBERNATED */
    change_state(pst->st_state, STATE_PARENT_HIBERNATED);
}



void resume_connection(struct connection *c) {

/*The state should be recovered and session resumption exchange starts*/

}



