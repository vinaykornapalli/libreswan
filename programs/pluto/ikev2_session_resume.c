/*
 *  Helper functions and ticket store for IKEv2 Session Resumption
*/
#include <unistd.h>
#include <pk11pub.h>
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

    struct ticket_payload *ticket_payl = alloc_bytes(sizeof(struct ticket_payload));

       struct ticket_by_value tk ;

       /*To be set as 1 for this version of protocol*/
       tk.format_version = RESUME_TICKET_VERSION;
       /*This has no use but implemented as per RFC*/
       tk.reserved = 0;

       {
           struct ike_ticket_state ts;

           /* IDi */
           memcpy(&ts.IDi, &(st->st_connection->spd.this.id), sizeof(struct id));

           /* IDr */

           memcpy(&ts.IDr, &(st->st_connection->spd.that.id), sizeof(struct id));

           /* SPIi */
           memcpy(&ts.SPIi, st->st_ike_spis.initiator.bytes, IKE_SA_SPI_SIZE);

           /* SPIr */
           memcpy(&ts.SPIr, st->st_ike_spis.responder.bytes, IKE_SA_SPI_SIZE);

           /*SKEYSEED OLD*/
           memcpy(&ts.st_skey_d_nss, st->st_skey_d_nss, sizeof(PK11SymKey));

           /* All the IKE negotiations */

           memcpy(&ts.st_oakley, st->st_oakley, sizeof(trans_attrs));

            tk.ike_tk_state = ts;
       }

      

       memcpy(&ticket_payl->ticket.tk_by_value , &tk , sizeof(ticket_by_value));
       
    
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
    if(cst!=NULL) {
         event_force(EVENT_SA_EXPIRE, cst);
    }
     
    if(pst!=NULL) {
        /* Marking parent state as hibernated */
        pst->st_hibernated = TRUE;
        /* State should be tranistioned in STATE_PARENT_HIBERNATED */
        change_state(pst->st_state, STATE_PARENT_HIBERNATED);
    }
   
}



void resume_connection(struct connection *c) {

/*The state should be recovered and session resumption exchange starts*/
   struct state *pst = state_with_serialno(c->newest_isakmp_sa);

   if(pst!=NULL && pst->st_hibernated == TRUE) {
       pst->st_hibernated = FALSE;
       change_state(pst->st_state, STATE_PARENT_RESUME);
       /* Session-Resumption Exchange type should be started from here*/
   }

}



