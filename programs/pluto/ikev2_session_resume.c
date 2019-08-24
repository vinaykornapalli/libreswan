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

           ts.sk_d_old = chunk_from_symkey("sk_d_old" , st->st_skey_d_nss);

           memcpy(&ts.st_oakley, &(st->st_oakley), sizeof(struct trans_attrs));

            tk.ike_tk_state = ts;
       }

      

       memcpy(&ticket_payl->tk_by_value , &tk , sizeof(struct ticket_by_value));
       
    
    chunk_t ticket_payl_chunk = chunk(ticket_payl , sizeof(struct ticket_payload));
    return ticket_payl_chunk;
}



bool ticket_to_st(const struct state *st , const chunk_t ticket) {
  /* Extraction of ticket */
  struct ike_ticket_state  tk;
  memcpy(&tk , ticket.ptr , ticket.len);
  st->st_oakley = tk.st_oakley;
  st->st_skey_d_nss = symkey_from_chunk("sk_d_old" , tk.sk_d_old);
  return TRUE;
}



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



/*
 *
 ***************************************************************
 *                       SESSION_RESUME_PARENT_OUTI1       *****
 ***************************************************************
 *  
 *
 *
 */

static void ikev2_session_resume_outI1_continue(struct state *st, struct msg_digest **mdp,
				 struct pluto_crypto_req *r);

static stf_status ikev2_session_resume_outI1_common(struct state *st);

void ikev2_session_resume_outI1(struct state *st) {

    push_cur_state(st);
    passert(st->st_ike_version == IKEv2);
	passert(st->st_state->kind == STATE_PARENT_HIBERNATED);
	st->st_original_role = ORIGINAL_INITIATOR;
	passert(st->st_sa_role == SA_INITIATOR);
   
    request_nonce("Session Resume Initiator Nonce Ni" , st ,ikev2_session_resume_outI1_continue);
    
}

void ikev2_session_resume_outI1_continue(struct state *st, struct msg_digest **mdp,
				 struct pluto_crypto_req *r)
{
	DBG(DBG_CONTROL,
		DBG_log("ikev2_session_resume_outI1_continue for #%lu",
			st->st_serialno));
	unpack_nonce(&st->st_ni, r);
	stf_status e = ikev2_session_resume_outI1_common(st);
	/* needed by complete state transition */
	if (*mdp == NULL) {
		*mdp = fake_md(st);
	}
	complete_v2_state_transition((*mdp)->st, mdp, e);
}

stf_status ikev2_session_resume_outI1_common(struct state *st) {


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
            !out_chunk(st->st_ni, &pb, "IKEv2 Session Resume nonce"))
            return STF_INTERNAL_ERROR;

        close_output_pbs(&pb);
    }
    /* send TICKET_OPAQUE */
    if (!emit_v2Nchunk(v2N_TICKET_OPAQUE, &(st->ticket_stored), &rbody)) {
			return STF_INTERNAL_ERROR;
	}

    close_output_pbs(&reply_stream);
    record_outbound_ike_msg(st, &reply_stream, "Request packet for Session Resumption");
    reset_cur_state();
    return STF_OK;
}

/*
 *
 ***************************************************************
 *                       SESSION_RESUME_PARENT_INI1        *****
 ***************************************************************
 *  -
 *
 *
 */

static crypto_req_cont_func ikev2_session_resume_inI1outR1_continue;	/* forward decl and type assertion */
static crypto_transition_fn ikev2_session_resume_inI1outR1_continue_tail;	/* forward decl and type assertion */

stf_status ikev2_session_resume_inI1outR1(struct state *st, struct msg_digest *md) {

    /* Accepting the ticket and generating state out of it */
    for (struct payload_digest *ntfy = md->chain[ISAKMP_NEXT_v2N]; ntfy != NULL; ntfy = ntfy->next) {
		switch(ntfy->payload.v2n.isan_type) {
              case v2N_TICKET_OPAQUE:
                 chunk_t tk_payl;
                 clonetochunk(tk_payl,ntfy->pbs.cur, pbs_left(&ntfy->pbs),"Ticket Opaque stored");
                 /*If we are unable to form a state from ticket we should send No Acknowledgement*/
                 if(!ticket_to_st(st , tk_payl))
                    st->st_send_ticket_nack =TRUE;
                 freeanychunk(tk_payl);
                 break;
              default:
                	DBG(DBG_CONTROLMORE,
			    DBG_log("Received unauthenticated %s notify - ignored",
				    enum_name(&ikev2_notify_names,
					      ntfy->payload.v2n.isan_type)));
        }
    }

    request_nonce("Session Resume Responder Nonce Nr" , st ,ikev2_session_resume_inI1outR1_continue);
    return STF_OK;

}

static void ikev2_session_resume_inI1outR1_continue(struct state *st,
					    struct msg_digest **mdp,
					    struct pluto_crypto_req *r)
{
	DBG(DBG_CONTROL,
		DBG_log("ikev2_session_resume_inI1outR1_continue for #%lu: calculated nonce, sending R1",
			st->st_serialno));

	passert(*mdp != NULL);
	stf_status e = ikev2_session_resume_inI1outR1_continue_tail(st, *mdp, r);
	/* replace (*mdp)->st with st ... */
	complete_v2_state_transition((*mdp)->st, mdp, e);
}

static stf_status ikev2_session_resume_inI1outR1_continue_tail(struct state *st,
						       struct msg_digest *md,
						       struct pluto_crypto_req *r)
{
      /* make sure HDR is at start of a clean buffer */
	init_out_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
		     "reply packet");

	/* HDR out */
	pb_stream rbody = open_v2_message(&reply_stream, ike_sa(st),
					  md /* response */,
					  ISAKMP_v2_IKE_SESSION_RESUME);
	if (!pbs_ok(&rbody)) {
		return STF_INTERNAL_ERROR;
	}

   	/* Ni in */
	RETURN_STF_FAILURE(accept_v2_nonce(md, &st->st_ni, "Ni"));

  
    /* send NONCE */
	unpack_nonce(&st->st_nr, r);
	{
		pb_stream pb;
		struct ikev2_generic in = {
			.isag_np = ISAKMP_NEXT_v2N,
			.isag_critical = build_ikev2_critical(false),
		};

		if (!out_struct(&in, &ikev2_nonce_desc, &rbody, &pb) ||
		    !out_chunk(st->st_nr, &pb, "IKEv2 Session Resume nonce"))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&pb);
	}
    
    if (st->st_send_ticket_nack) {
        if (!emit_v2N(v2N_TICKET_NACK, &rbody))
            return STF_INTERNAL_ERROR;
    }


    close_output_pbs(&rbody);
	close_output_pbs(&reply_stream);

	record_outbound_ike_msg(st, &reply_stream,
		"reply packet for ikev2_session_resume_inI1outR1");

    return STF_OK;

}
/*
 *
 ***************************************************************
 *                       SESSION_RESUME_PARENT_inR1        *****
 ***************************************************************
 *  
 *
 *
 */
static crypto_req_cont_func ikev2_session_resume_inR1outI2_continue;	/* forward decl and type assertion */
static crypto_transition_fn ikev2_session_resume_inR1outI2_tail;	/* forward decl and type assertion */

stf_status ikev2_session_resume_inR1outI2(struct state *st, struct msg_digest *md) {


    /* First see if there is any no acknowledgement received */
    for (struct payload_digest *ntfy = md->chain[ISAKMP_NEXT_v2N]; ntfy != NULL; ntfy = ntfy->next) {
        if (ntfy->payload.v2n.isan_spisize != 0) {
            libreswan_log("Notify payload for IKE must have zero length SPI - message dropped");
            return STF_IGNORE;
        }

        if (ntfy->payload.v2n.isan_type >= v2N_STATUS_FLOOR) {
            pstat(ikev2_recv_notifies_s, ntfy->payload.v2n.isan_type);
        }
        else {
            pstat(ikev2_recv_notifies_e, ntfy->payload.v2n.isan_type);
        }

        switch (ntfy->payload.v2n.isan_type) {
            case v2N_TICKET_NACK:
                /* we should continue with normal ikev2 init exchange */
                return STF_FAIL;
            default:
                DBG(DBG_CONTROLMORE,
			    DBG_log("Received unauthenticated %s notify - ignored",
				    enum_name(&ikev2_notify_names,
					      ntfy->payload.v2n.isan_type)));
              
        }
    }

    /* Ni in */
	RETURN_STF_FAILURE(accept_v2_nonce(md, &st->st_nr, "Ni"));
    
    /*to-do: Right time to start generating new keys from old keys */

    return STF_OK;
}


static void ikev2_parent_inR1outI2_continue(struct state *st,
					    struct msg_digest **mdp,
					    struct pluto_crypto_req *r)
{
	DBG(DBG_CONTROL,
		DBG_log("ikev2_session_resume_inR1outI2_continue for #%lu: sending I2",
			st->st_serialno));

	passert(*mdp != NULL);
	stf_status e = ikev2_session_resume_inR1outI2_tail(st, *mdp, r);
	/* replace (*mdp)->st with st ... */
	complete_v2_state_transition((*mdp)->st, mdp, e);
}

static stf_status ikev2_parent_inR1outI2_tail(struct state *pst, struct msg_digest *md,
					      struct pluto_crypto_req *r)
{

}

/* Functions related to hibernate/resume connection */
void hibernate_connection(struct connection *c) {

    struct state *pst = state_with_serialno(c->newest_isakmp_sa);
    struct state *cst = state_with_serialno(c->newest_ipsec_sa);
    /* Deleting the child sa of the current state */
    whack_log(RC_COMMENT, "cst to be deleted - %ld", c->newest_ipsec_sa);
    if(cst!=NULL) {
        event_force(EVENT_SA_EXPIRE, cst);
    }
     
    if(pst!=NULL) {
        /* Marking parent state as hibernated */
        pst->st_hibernated = TRUE;
        /* State should be tranistioned in STATE_PARENT_HIBERNATED */
         change_state(pst ,STATE_PARENT_HIBERNATED);
    }
   
}






