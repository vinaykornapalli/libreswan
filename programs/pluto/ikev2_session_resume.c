/*
 *  Helper functions and ticket store for IKEv2 Session Resumption
*/
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include "sysdep.h"
#include "constants.h"
#include "lswlog.h"

#include "defs.h"
#include "id.h"
#include "x509.h"
#include "pluto_x509.h"
#include "certs.h"
#include "connections.h"        /* needs id.h */
#include "state.h"
#include "packet.h"
#include "crypto.h"
#include "crypt_symkey.h"
#include "ike_alg.h"
#include "log.h"
#include "demux.h"      /* needs packet.h */
#include "pluto_crypt.h"  /* for pluto_crypto_req & pluto_crypto_req_cont */
#include "ikev2.h"
#include "ipsec_doi.h"  /* needs demux.h and state.h */
#include "timer.h"
#include "whack.h"      /* requires connections.h */
#include "server.h"
#include "spdb.h"
#include "nat_traversal.h"
#include "vendor.h"
#include "ip_address.h"
#include "ikev2_send.h"
#include "state_db.h"
#include "ietf_constants.h"
#include "ikev2_cookie.h"
#include "plutoalg.h" /* for default_ike_groups */
#include "ikev2_message.h"	/* for ikev2_decrypt_msg() */
#include "pluto_stats.h"
#include "keywords.h"
#include "ikev2_msgid.h"
#include "ip_endpoint.h"
#include "hostpair.h"/* for find_v2_host_connection() */
#include "send.h"
#include "ikev2_session_resume.h"



/* Functions for making and emitting ticket payload*/



chunk_t st_to_ticket(const struct state *st) {

    struct ticket_payload *ticket_payl = alloc_bytes(sizeof(struct ticket_payload) , "Ticket Payload");

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

           /*SKEYSEED OLD
           currently some issue with it
           memcpy(ts.st_skey_d_nss, st->st_skey_d_nss, sizeof(PK11SymKey));
           */

           /* All the IKE negotiations */

           memcpy(&ts.st_oakley, &(st->st_oakley), sizeof(struct trans_attrs));

            tk.ike_tk_state = ts;
       }

      

       memcpy(&ticket_payl->ticket.tk_by_value , &tk , sizeof(struct ticket_by_value));
       
    
    chunk_t ticket_payl_chunk = chunk(ticket_payl , sizeof(struct ticket_payload));
    return ticket_payl_chunk;
}
/*
struct state *ticket_to_st(const chunk_t *ticket) {

}
*/


static struct msg_digest *fake_md(struct state *st)
{
	struct msg_digest *fake_md = alloc_md("fake IKEv2 msg_digest");
	fake_md->st = st;
	fake_md->from_state = st->st_state->kind;
	fake_md->hdr.isa_msgid = v2_INVALID_MSGID;
	fake_md->hdr.isa_version = (IKEv2_MAJOR_VERSION << ISA_MAJ_SHIFT);
	fake_md->fake_dne = true;
	/* asume first microcode is valid */
	fake_md->svm = st->st_state->v2_transitions;
	return fake_md;
}



stf_status ikev2_session_resume_outI1(struct state *st) {

    /* Suspended state should be transitioned back 
     *STATE_PARENT_HIBERNATED -> STATE_PARENT_RESUME_I1
     */
     struct msg_digest *mdp;
     mdp = fake_md(st);
     complete_v2_state_transition(pst, &mdp, STF_OK);




    /* set up reply for first session exchange message */
    init_out_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
                 "reply packet");

    /* HDR out */
    pb_stream rbody = open_v2_message(&reply_stream, ike_sa(st),
                                      NULL /* request */,
                                      ISAKMP_v2_IKE_SESSION_RESUME);
    if (!pbs_ok(&rbody)) {
        return STF_INTERNAL_ERROR;
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
    if (!emit_v2Nchunk(v2N_TICKET_OPAQUE, &(st->ticket_stored), &rbody)) {
			return STF_INTERNAL_ERROR;
	}

    close_output_pbs(&reply_stream);
    record_outbound_ike_msg(st, &reply_stream, "Request packet for Session Resumption");

    return STF_OK;
}

// stf_status ikev2_session_resume_inI1outR1(struct state *st, struct msg_digest *md) {

    
//     for (struct payload_digest *ntfy = md->chain[ISAKMP_NEXT_v2N]; ntfy != NULL; ntfy = ntfy->next) {
// 		switch(ntfy->payload.v2n.isan_type) {
//               case v2N_TICKET_OPAQUE:
//                  chunk_t tk_payl;
//                  clonetochunk(tk_payl,ntfy->pbs.cur, pbs_left(&ntfy->pbs),"Ticket Opaque stored");
//                  struct state *st = ticket_to_st(&tk_payl);
//                  freeanychunk(tk_payl);
//                  break;
//         }
//     }
// }




/* Functions related to hibernate/resume connection */
void hibernate_connection(struct connection *c) {

    struct state *pst = state_with_serialno(c->newest_isakmp_sa);
    struct state *cst = state_with_serialno(c->newest_ipsec_sa);
    struct msg_digest *mdp;
    /* Deleting the child sa of the current state */
    whack_log(RC_COMMENT, "cst to be deleted - %d", c->newest_ipsec_sa);
    if(cst!=NULL) {
        
        event_force(EVENT_SA_EXPIRE, cst);
    }
     
    if(pst!=NULL) {
        /* Marking parent state as hibernated */
        pst->st_hibernated = TRUE;
        /* State should be tranistioned in STATE_PARENT_HIBERNATED */
        mdp = fake_md(pst);
        complete_v2_state_transition(pst, &mdp, STF_OK);
    }
   
}







