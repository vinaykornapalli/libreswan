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
		   id_buf ibuf ;
		   memcpy(&ts.IDi ,str_id(&st->st_connection->spd.this.id , &ibuf) , IDTOA_BUF);
           /* IDr */
		   id_buf rbuf;
		   memcpy(&ts.IDr ,str_id(&st->st_connection->spd.that.id , &rbuf) , IDTOA_BUF);

           /* SPIi */
           memcpy(&ts.SPIi, st->st_ike_spis.initiator.bytes, IKE_SA_SPI_SIZE);

           /* SPIr */
           memcpy(&ts.SPIr, st->st_ike_spis.responder.bytes, IKE_SA_SPI_SIZE);

           /*old skeyseed*/
           chunk_t sk = chunk_from_symkey("sk_d_old" , st->st_skey_d_nss);
		   memcpy(&ts.sk_d_old , sk.ptr , sk.len);
           /*Accepted proposals by Responder*/
           memcpy(&ts.ike_algos, st->st_accepted_ike_proposal, sizeof(struct ike_proposals));

           ts.authentication_method = st->st_connection->spd.that.authby;

            tk.ike_tk_state = ts;
       }

      

       memcpy(&ticket_payl->tk_by_value , &tk , sizeof(struct ticket_by_value));
       
    
    chunk_t ticket_payl_chunk = chunk(ticket_payl , sizeof(struct ticket_payload));
    return ticket_payl_chunk;
}



bool ticket_to_st(const struct state *st , const chunk_t ticket) {
  /* Extraction of ticket */

  if (ticket.len <= 1) {
      /*something went wrong*/
   return FALSE;
  }
  void *crnt = ticket.ptr;

  /*IDs*/
  err_t ughi = atoid(crnt ,&st->st_connection->spd.this.id , FALSE);
  crnt+=IDTOA_BUF;
  err_t ughr = atoid(crnt , &st->st_connection->spd.that.id , FALSE);
  crnt+=IDTOA_BUF;
  if (ughi!=NULL || ughr!=NULL) {
      return FALSE;
  }

  /*SPIs*/
  memcpy(st->st_ike_spis.initiator.bytes, crnt, IKE_SA_SPI_SIZE);
  crnt+=IKE_SA_SPI_SIZE;
  memcpy(st->st_ike_spis.responder.bytes, crnt, IKE_SA_SPI_SIZE);
  crnt+=IKE_SA_SPI_SIZE;

  /*sk_d_old*/
  size_t key_length = *crnt;
  crnt+=1;
  chunk_t key_chunk = {
	  .ptr = crnt,
	  .len = key_length
  }
  st->st_skey_d_nss = symkey_from_chunk("sk_d_old" , key_chunk);

   /*All the SA negotiations this is the reason for not having SAi,SAr in session exchange*/
   crnt+=MAX_OAKLEY_KEY_LEN;
   size_t proposal_size = sizeof(struct ike_proposals);
   memcpy(st->st_accepted_ike_proposal,crnt, proposal_size);

    /*Now extract st_oakley out of it.*/
   	if (!ikev2_proposal_to_trans_attrs(st->st_accepted_ike_proposal,
					   &st->st_oakley)) {
		return FALSE;
	}

  crnt+=proposal_size;
  /*authentication method*/
  memcpy(st->st_connection->spd.that.authby, crnt , sizeof(struct(auth_alg_names)));
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
 * Initiate an Oakley Main Mode exchange.
 *       HDR, N(TICKET_OPAQUE), Ni   -->
 *
 * Note: This is called on whack command ipsec whack --resume --name <con name>
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
    chunk_t ticket_opaque = st->ticket_stored
    if (!emit_v2Nchunk(v2N_TICKET_OPAQUE, &ticket_opaque, &rbody)) {
			return STF_INTERNAL_ERROR;
	}
    freeanychunk(ticket_opaque);

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
 * no state: none I1 --> R1
 *                <-- HDR, N(TICKET_OPAQUE), Ni
 * HDR, Nr -->
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
 * STATE_PARENT_RESUME_I1: R1 --> I2
 *                     <--  HDR, Nr
 * HDR, SK {IDi, [CERT,] [CERTREQ,]
 *      [IDr,] AUTH, SAi2,
 *      TSi, TSr}      -->
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

    /* Nr in */
	RETURN_STF_FAILURE(accept_v2_nonce(md, &st->st_nr, "Nr"));
    
    /*to-do: Right time to start generating new keys from old keys */

    /*

    -Function should be something like this.
    calc_skeyseed_v2(st, "ikev2_session_resume_inR1outI2",
		    ORIGINAL_INITIATOR,
		    NULL, NULL, &st->st_ike_spis,
		    ikev2_session_resume_inR1outI2_continue);
    */

    return STF_SUSPEND;
}


static void ikev2_session_resume_inR1outI2_continue(struct state *st,
					    struct msg_digest **mdp,
					    struct pluto_crypto_req *r)
{
	DBG(DBG_CONTROL,
		DBG_log("ikev2_session_resume_inR1outI2_continue for #%lu: generating keys, sending I2",
			st->st_serialno));

	passert(*mdp != NULL);
	stf_status e = ikev2_session_resume_inR1outI2_tail(st, *mdp, r);
	/* replace (*mdp)->st with st ... */
	complete_v2_state_transition((*mdp)->st, mdp, e);
}

/* 
  Things that happen different in session-resumption auth when compared with normal auth.
*   1) old IDi and IDr should be used here.
*   2)The authentication method to be used is chosen from ticket.
*    3)Certificates are to be stored in ticket if needed but for time being we can leave it.
*    4)Nat detention status and SPIs are two be done in new exchange again.
*    5)initiator of IKEV2_SESSION_RESUME is the Original Initiator.
*    6)IKE SA algos are to be taken from ticket.
*    7)peer vendor IDs,MOBIKE, configuration payload information, 
      peer support redirects should be done again.
*/

/*XXX: totally taken from ikev2_parent.c as it is a static function over there.*/
static stf_status ikev2_send_auth(struct state *st,
				  enum original_role role,
				  enum next_payload_types_ikev2 np,
				  const unsigned char *idhash_out,
				  pb_stream *outpbs,
				  chunk_t *null_auth /* optional out */)
{
	/* st could be parent or child */
	struct state *pst = IS_CHILD_SA(st) ?
		state_with_serialno(st->st_clonedfrom) : st;

	/* ??? should c be based on pst?  Does it matter? */
	pexpect(st->st_connection == pst->st_connection);
	const struct connection *c = st->st_connection;

	enum keyword_authby authby = c->spd.this.authby;

	if (null_auth != NULL)
		*null_auth = EMPTY_CHUNK;

	/* ??? this is the last use of st.  Could/should it be pst? */
	/* ??? I think that only a parent can have st->st_peer_wants_null set */
	pexpect(st->st_peer_wants_null == pst->st_peer_wants_null);
	if (st->st_peer_wants_null) {
		/* we allow authby=null and IDr payload told us to use it */
		authby = AUTH_NULL;
	} else if (authby == AUTH_UNSET) {
		/*
		 * Asymmetric policy unset.
		 * Pick up from symmetric policy, in order of preference!
		 */
		/* ??? what about POLICY_ECDSA? */
		if (c->policy & POLICY_RSASIG) {
			authby = AUTH_RSASIG;
		} else if (c->policy & POLICY_PSK) {
			authby = AUTH_PSK;
		} else if (c->policy & POLICY_AUTH_NULL) {
			authby = AUTH_NULL;
		} else {
			/* leave authby == AUTH_UNSET */
			/* ??? we will surely crash with bad_case */
		}
	}

	struct ikev2_a a = {
		.isaa_np = np,
		.isaa_critical = build_ikev2_critical(false),
	};

	switch (authby) {
	case AUTH_RSASIG:
		a.isaa_type = pst->st_seen_hashnotify &&
			c->sighash_policy != LEMPTY ?
				IKEv2_AUTH_DIGSIG : IKEv2_AUTH_RSA;
		break;
	case AUTH_ECDSA:
		a.isaa_type = IKEv2_AUTH_DIGSIG;
		break;
	case AUTH_PSK:
		a.isaa_type = IKEv2_AUTH_PSK;
		break;
	case AUTH_NULL:
		a.isaa_type = IKEv2_AUTH_NULL;
		break;
	case AUTH_NEVER:
	default:
		bad_case(authby);
	}

	pb_stream a_pbs;

	if (!out_struct(&a, &ikev2_a_desc, outpbs, &a_pbs)) {
		/* loglog(RC_LOG_SERIOUS, "Failed to emit IKE_AUTH payload"); */
		return STF_INTERNAL_ERROR;
	}

	switch (a.isaa_type) {
	case IKEv2_AUTH_RSA:
		if (!ikev2_calculate_rsa_hash(pst, role, idhash_out, &a_pbs,
			NULL /* we don't keep no_ppk_auth */,
			IKEv2_AUTH_HASH_SHA1))
		{
			loglog(RC_LOG_SERIOUS, "Failed to find our RSA key");
			return STF_FATAL;
		}
		break;

	case IKEv2_AUTH_PSK:
	case IKEv2_AUTH_NULL:
		/* emit */
		if (!ikev2_emit_psk_auth(authby, pst, idhash_out, &a_pbs))
		{
			loglog(RC_LOG_SERIOUS, "Failed to find our PreShared Key");
			return STF_FATAL;
		}
		break;

	case IKEv2_AUTH_DIGSIG:
	{
		enum notify_payload_hash_algorithms hash_algo;

		if (pst->st_hash_negotiated & NEGOTIATE_AUTH_HASH_SHA2_512) {
			hash_algo = IKEv2_AUTH_HASH_SHA2_512;
		} else if (pst->st_hash_negotiated & NEGOTIATE_AUTH_HASH_SHA2_384) {
			hash_algo = IKEv2_AUTH_HASH_SHA2_384;
		} else if (pst->st_hash_negotiated & NEGOTIATE_AUTH_HASH_SHA2_256) {
			hash_algo = IKEv2_AUTH_HASH_SHA2_256;
		} else {
			loglog(RC_LOG_SERIOUS, "DigSig: no compatible DigSig hash algo");
			return STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
		}

		if (!ikev2_send_asn1_hash_blob(hash_algo, &a_pbs, authby))
			return STF_INTERNAL_ERROR;

		switch (authby) {
		case AUTH_ECDSA:
		{
			if (!ikev2_calculate_ecdsa_hash(pst, role, idhash_out, &a_pbs,
				NULL /* don't grab value */,
				hash_algo))
			{
				loglog(RC_LOG_SERIOUS, "DigSig: failed to find our ECDSA key");
				return STF_FATAL;
			}
			break;
		}
		case AUTH_RSASIG:
		{
			if (!ikev2_calculate_rsa_hash(pst, role, idhash_out, &a_pbs,
				NULL /* we don't keep no_ppk_auth */,
				hash_algo))
			{
				loglog(RC_LOG_SERIOUS, "DigSig: failed to find our RSA key");
				return STF_FATAL;
			}
			break;
		}
		default:
			libreswan_log("unknown remote authentication type for DigSig");
			return STF_FAIL;
		}
		break;
	}

	default:
		bad_case(a.isaa_type);
	}

	/* We sent normal IKEv2_AUTH_RSA but if the policy also allows
	 * AUTH_NULL, we will send a Notify with NULL_AUTH in separate
	 * chunk. This is only done on the initiator in IKE_AUTH, and
	 * not repeated in rekeys.
	 */
	if (null_auth != NULL &&
	    authby == AUTH_RSASIG &&
	    c->policy & POLICY_AUTH_NULL) {
		/* store in null_auth */
		if (!ikev2_create_psk_auth(AUTH_NULL, pst, idhash_out,
			null_auth))
		{
			loglog(RC_LOG_SERIOUS, "Failed to calculate additional NULL_AUTH");
			return STF_FATAL;
		}
	}

	close_output_pbs(&a_pbs);
	return STF_OK;
}

static bool need_configuration_payload(const struct connection *const pc,
			    const lset_t st_nat_traversal)
{
	return (pc->spd.this.modecfg_client &&
		(!pc->spd.this.cat || LHAS(st_nat_traversal, NATED_HOST)));
}

/*XXX: The only difference between this function and the one in ikev2_parent.c 
  is that this donot have finish dh call. To be refactored later.
*/
static stf_status ikev2_session_resume_inR1outI2_tail(struct state *pst, struct msg_digest *md,
					      struct pluto_crypto_req *r)
{
	struct connection *const pc = pst->st_connection;	/* parent connection */
	struct ppk_id_payload ppk_id_p;
	struct ike_sa *ike = pexpect_ike_sa(pst);

	/*
	 * If we and responder are willing to use a PPK,
	 * we need to generate NO_PPK_AUTH as well as PPK-based AUTH payload
	 */
	if (LIN(POLICY_PPK_ALLOW, pc->policy) && pst->st_seen_ppk) {
		chunk_t *ppk_id;
		chunk_t *ppk = get_ppk(pst->st_connection, &ppk_id);

		if (ppk != NULL) {
			DBG(DBG_CONTROL, DBG_log("found PPK and PPK_ID for our connection"));

			pexpect(pst->st_sk_d_no_ppk == NULL);
			pst->st_sk_d_no_ppk = reference_symkey(__func__, "sk_d_no_ppk", pst->st_skey_d_nss);

			pexpect(pst->st_sk_pi_no_ppk == NULL);
			pst->st_sk_pi_no_ppk = reference_symkey(__func__, "sk_pi_no_ppk", pst->st_skey_pi_nss);

			pexpect(pst->st_sk_pr_no_ppk == NULL);
			pst->st_sk_pr_no_ppk = reference_symkey(__func__, "sk_pr_no_ppk", pst->st_skey_pr_nss);

			create_ppk_id_payload(ppk_id, &ppk_id_p);
			DBG(DBG_CONTROL, DBG_log("ppk type: %d", (int) ppk_id_p.type));
			DBG(DBG_CONTROL, DBG_dump_hunk("ppk_id from payload:", ppk_id_p.ppk_id));

			ppk_recalculate(ppk, pst->st_oakley.ta_prf,
						&pst->st_skey_d_nss,
						&pst->st_skey_pi_nss,
						&pst->st_skey_pr_nss);
			libreswan_log("PPK AUTH calculated as initiator");
		} else {
			if (pc->policy & POLICY_PPK_INSIST) {
				loglog(RC_LOG_SERIOUS, "connection requires PPK, but we didn't find one");
				return STF_FATAL;
			} else {
				libreswan_log("failed to find PPK and PPK_ID, continuing without PPK");
				/* we should omit sending any PPK Identity, so we pretend we didn't see USE_PPK */
				pst->st_seen_ppk = FALSE;
			}
		}
	}

	ikev2_log_parentSA(pst);

	/* XXX This is too early and many failures could lead to not needing a child state */
	struct child_sa *child = ikev2_duplicate_state(pexpect_ike_sa(pst),
						       IPSEC_SA,
						       SA_INITIATOR);	/* child state */
	struct state *cst = &child->sa;

	/* XXX because the early child state ends up with the try counter check, we need to copy it */
	cst->st_try = pst->st_try;

	/*
	 * XXX: This is so lame.  Need to move the current initiator
	 * from IKE to the CHILD so that the post processor doesn't
	 * get confused.  If the IKE->CHILD switch didn't happen this
	 * wouldn't be needed.
	 */
	v2_msgid_switch_initiator(ike, child, md);

	binlog_refresh_state(cst);
	md->st = cst;

	/*
	 * XXX: Danger!
	 *
	 * Because the code above has blatted MD->ST with the child
	 * state (CST) and this function's caller is going to try to
	 * complete the V2 state transition on MD->ST (i.e., CST) and
	 * using the state-transition MD->SVM the IKE SA (PST) will
	 * never get to complete its state transition.
	 *
	 * Get around this by forcing the state transition here.
	 *
	 * But what should happen?  A guess is to just leave MD->ST
	 * alone.  The CHILD SA doesn't really exist until after the
	 * IKE SA has processed and approved of the response to this
	 * IKE_AUTH request.
	 */

	pexpect(md->svm->timeout_event == EVENT_RETRANSMIT); /* for CST */
	delete_event(pst);
	event_schedule(EVENT_SA_REPLACE, deltatime(PLUTO_HALFOPEN_SA_LIFE), pst);
	change_state(pst, STATE_PARENT_I2);

	/*
	 * XXX:
	 *
	 * Should this code use clone_in_pbs_as_chunk() which uses
	 * pbs_room() (.roof-.start)?  The original code:
	 *
	 * 	clonetochunk(st->st_firstpacket_him, md->message_pbs.start,
	 *		     pbs_offset(&md->message_pbs),
	 *		     "saved first received packet");
	 *
	 * and clone_out_pbs_as_chunk() both use pbs_offset()
	 * (.cur-.start).
	 *
	 * Suspect it doesn't matter as the code initializing
	 * .message_pbs forces .roof==.cur - look for the comment
	 * "trim padding (not actually legit)".
	 */
	/* record first packet for later checking of signature */
	pst->st_firstpacket_him = clone_out_pbs_as_chunk(&md->message_pbs,
							 "saved first received packet");

	/* beginning of data going out */

	/* make sure HDR is at start of a clean buffer */
	init_out_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
		 "reply packet");

	/* HDR out */

	pb_stream rbody = open_v2_message(&reply_stream, ike_sa(pst),
					  NULL /* request */,
					  ISAKMP_v2_IKE_AUTH);
	if (!pbs_ok(&rbody)) {
		return STF_INTERNAL_ERROR;
	}

	if (IMPAIR(ADD_UNKNOWN_PAYLOAD_TO_AUTH)) {
		if (!emit_v2UNKNOWN("IKE_AUTH request", &rbody)) {
			return STF_INTERNAL_ERROR;
		}
	}

	/* insert an Encryption payload header (SK) */

	v2SK_payload_t sk = open_v2SK_payload(&rbody, ike_sa(pst));
	if (!pbs_ok(&sk.pbs)) {
		return STF_INTERNAL_ERROR;
	}

	/* actual data */

	/* decide whether to send CERT payload */

	/* it should use parent not child state */
	bool send_cert = ikev2_send_cert_decision(cst);
	bool ic =  pc->initial_contact && (pst->st_ike_pred == SOS_NOBODY);
	bool send_idr = ((pc->spd.that.id.kind != ID_NULL && pc->spd.that.id.name.len != 0) ||
				pc->spd.that.id.kind == ID_NULL); /* me tarzan, you jane */

	DBG(DBG_CONTROL, DBG_log("IDr payload will %sbe sent", send_idr ? "" : "NOT "));

	/* send out the IDi payload */

	unsigned char idhash[MAX_DIGEST_LEN];
	unsigned char idhash_npa[MAX_DIGEST_LEN];	/* idhash for NO_PPK_AUTH (npa) */

	{
		struct ikev2_id i_id = {
			.isai_np = ISAKMP_NEXT_v2NONE,
		};
		pb_stream i_id_pbs;
		chunk_t id_b;
		struct hmac_ctx id_ctx;

		hmac_init(&id_ctx, pst->st_oakley.ta_prf, pst->st_skey_pi_nss);
		v2_build_id_payload(&i_id, &id_b,
				 &pc->spd.this);
		i_id.isai_critical = build_ikev2_critical(false);

		/* HASH of ID is not done over common header */
		unsigned char *const id_start =
			sk.pbs.cur + NSIZEOF_isakmp_generic;

		if (!out_struct(&i_id,
				&ikev2_id_i_desc,
				&sk.pbs,
				&i_id_pbs) ||
		    !out_chunk(id_b, &i_id_pbs, "my identity"))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&i_id_pbs);

		/* calculate hash of IDi for AUTH below */

		const size_t id_len = sk.pbs.cur - id_start;

		DBG(DBG_CRYPT, DBG_dump("idhash calc I2", id_start, id_len));
		hmac_update(&id_ctx, id_start, id_len);
		hmac_final(idhash, &id_ctx);

		if (pst->st_seen_ppk && !LIN(POLICY_PPK_INSIST, pc->policy)) {
			struct hmac_ctx id_ctx_npa;

			hmac_init(&id_ctx_npa, pst->st_oakley.ta_prf, pst->st_sk_pi_no_ppk);
			/* ID payload that we've build is the same */
			hmac_update(&id_ctx_npa, id_start, id_len);
			hmac_final(idhash_npa, &id_ctx_npa);
		}
	}

	if (IMPAIR(ADD_UNKNOWN_PAYLOAD_TO_AUTH_SK)) {
		if (!emit_v2UNKNOWN("IKE_AUTH's SK request", &sk.pbs)) {
			return STF_INTERNAL_ERROR;
		}
	}

	/* send [CERT,] payload RFC 4306 3.6, 1.2) */
	if (send_cert) {
		stf_status certstat = ikev2_send_cert(cst, &sk.pbs);
		if (certstat != STF_OK)
			return certstat;

		/* send CERTREQ  */
		bool send_certreq = ikev2_send_certreq_INIT_decision(cst, ORIGINAL_INITIATOR);
		if (send_certreq) {
			char buf[IDTOA_BUF];
			dntoa(buf, IDTOA_BUF, cst->st_connection->spd.that.ca);
			DBG(DBG_X509,
			    DBG_log("Sending [CERTREQ] of %s", buf));
			ikev2_send_certreq(cst, md, &sk.pbs);
		}
	}

	/* you Tarzan, me Jane support */
	if (send_idr) {
		struct ikev2_id r_id;
		pb_stream r_id_pbs;
		chunk_t id_b;
		r_id.isai_type = ID_NONE;

		switch (pc->spd.that.id.kind) {
		case ID_DER_ASN1_DN:
			r_id.isai_type = ID_DER_ASN1_DN;
			break;
		case ID_FQDN:
			r_id.isai_type = ID_FQDN;
			break;
		case ID_USER_FQDN:
			r_id.isai_type = ID_USER_FQDN;
			break;
		case ID_KEY_ID:
			r_id.isai_type = ID_KEY_ID;
			break;
		case ID_NULL:
			r_id.isai_type = ID_NULL;
			break;
		default:
			DBG(DBG_CONTROL, DBG_log("Not sending IDr payload for remote ID type %s",
				enum_show(&ike_idtype_names, pc->spd.that.id.kind)));
			break;
		}

		if (r_id.isai_type != ID_NONE) {
			v2_build_id_payload(&r_id,
				 &id_b,
				 &pc->spd.that);
			r_id.isai_np = ic ? ISAKMP_NEXT_v2N : ISAKMP_NEXT_v2AUTH;

			if (!out_struct(&r_id, &ikev2_id_r_desc, &sk.pbs,
				&r_id_pbs) ||
			    !out_chunk(id_b, &r_id_pbs, "IDr"))
				return STF_INTERNAL_ERROR;

			close_output_pbs(&r_id_pbs);
		}
	}

	if (ic) {
		libreswan_log("sending INITIAL_CONTACT");
		if (!emit_v2N(v2N_INITIAL_CONTACT, &sk.pbs))
			return STF_INTERNAL_ERROR;
	} else {
		DBG(DBG_CONTROL, DBG_log("not sending INITIAL_CONTACT"));
	}

	/* send out the AUTH payload */
	chunk_t null_auth;	/* we must free this */

	stf_status authstat = ikev2_send_auth(cst, ORIGINAL_INITIATOR, 0,
					      idhash, &sk.pbs, &null_auth);
	if (authstat != STF_OK) {
		freeanychunk(null_auth);
		return authstat;
	}

	if (need_configuration_payload(pc, pst->hidden_variables.st_nat_traversal)) {
		stf_status cpstat = ikev2_send_cp(pst, ISAKMP_NEXT_v2SA,
						  &sk.pbs);
		if (cpstat != STF_OK) {
			freeanychunk(null_auth);
			return cpstat;
		}
	}

	/*
	 * Switch to first pending child request for this host pair.
	 * ??? Why so late in this game?
	 *
	 * Then emit SA2i, TSi and TSr and NOTIFY payloads related
	 * to the IPsec SA.
	 */

	/* so far child's connection is same as parent's */
	passert(pc == cst->st_connection);

	lset_t policy = pc->policy;

	/* child connection */
	struct connection *cc = first_pending(pst, &policy, &cst->st_whack_sock);

	if (cc == NULL) {
		cc = pc;
		DBG(DBG_CONTROL, DBG_log("no pending CHILD SAs found for %s Reauthentication so use the original policy",
			cc->name));
	}

	if (cc != cst->st_connection) {
		/* ??? DBG_log not conditional on some DBG selector */
		char cib[CONN_INST_BUF];
		DBG_log("Switching Child connection for #%lu to \"%s\"%s from \"%s\"%s",
				cst->st_serialno, cc->name,
				fmt_conn_instance(cc, cib),
				pc->name, fmt_conn_instance(pc, cib));
	}
	/* ??? this seems very late to change the connection */
	update_state_connection(cst, cc);

	/* code does not support AH+ESP, which not recommended as per RFC 8247 */
	struct ipsec_proto_info *proto_info
		= ikev2_child_sa_proto_info(pexpect_child_sa(cst), cc->policy);
	proto_info->our_spi = ikev2_child_sa_spi(&cc->spd, cc->policy);
	const chunk_t local_spi = THING_AS_CHUNK(proto_info->our_spi);

	/*
	 * A CHILD_SA established during an AUTH exchange does
	 * not propose DH - the IKE SA's SKEYSEED is always
	 * used.
	 */
	struct ikev2_proposals *child_proposals =
		get_v2_ike_auth_child_proposals(cc, "IKE SA initiator emitting ESP/AH proposals");
	if (!ikev2_emit_sa_proposals(&sk.pbs, child_proposals,
				     &local_spi)) {
		freeanychunk(null_auth);
		return STF_INTERNAL_ERROR;
	}

	cst->st_ts_this = ikev2_end_to_ts(&cc->spd.this);
	cst->st_ts_that = ikev2_end_to_ts(&cc->spd.that);

	v2_emit_ts_payloads(pexpect_child_sa(cst), &sk.pbs, cc);

	if ((cc->policy & POLICY_TUNNEL) == LEMPTY) {
		DBG(DBG_CONTROL, DBG_log("Initiator child policy is transport mode, sending v2N_USE_TRANSPORT_MODE"));
		/* In v2, for parent, protoid must be 0 and SPI must be empty */
		if (!emit_v2N(v2N_USE_TRANSPORT_MODE, &sk.pbs)) {
			freeanychunk(null_auth);
			return STF_INTERNAL_ERROR;
		}
	} else {
		DBG(DBG_CONTROL, DBG_log("Initiator child policy is tunnel mode, NOT sending v2N_USE_TRANSPORT_MODE"));
	}

	if (!emit_v2N_compression(cst, true, &sk.pbs)) {
		freeanychunk(null_auth);
		return STF_INTERNAL_ERROR;
	}

	if (cc->send_no_esp_tfc) {
		if (!emit_v2N(v2N_ESP_TFC_PADDING_NOT_SUPPORTED, &sk.pbs)) {
			freeanychunk(null_auth);
			return STF_INTERNAL_ERROR;
		}
	}

	if (LIN(POLICY_MOBIKE, cc->policy)) {
		cst->st_sent_mobike = pst->st_sent_mobike = TRUE;
		if (!emit_v2N(v2N_MOBIKE_SUPPORTED, &sk.pbs)) {
			freeanychunk(null_auth);
			return STF_INTERNAL_ERROR;
		}
	}
	if (pst->st_seen_ppk) {
		pb_stream ppks;

		if (!emit_v2Npl(v2N_PPK_IDENTITY, &sk.pbs, &ppks) ||
		    !emit_unified_ppk_id(&ppk_id_p, &ppks)) {
			freeanychunk(null_auth);
			return STF_INTERNAL_ERROR;
		}
		close_output_pbs(&ppks);

		if (!LIN(POLICY_PPK_INSIST, cc->policy)) {
			stf_status s = ikev2_calc_no_ppk_auth(pst, idhash_npa,
				&pst->st_no_ppk_auth);
			if (s != STF_OK) {
				freeanychunk(null_auth);
				return s;
			}

			if (!emit_v2Nchunk(v2N_NO_PPK_AUTH,
					&pst->st_no_ppk_auth, &sk.pbs)) {
				freeanychunk(null_auth);
				return STF_INTERNAL_ERROR;
			}
		}
	}

	if (null_auth.ptr != NULL) {
		if (!emit_v2Nchunk(v2N_NULL_AUTH, &null_auth, &sk.pbs)) {
			freeanychunk(null_auth);
			return STF_INTERNAL_ERROR;
		}
		freeanychunk(null_auth);
	}
    
	/*N(TICKET_REQUEST) is a notification payload for request ticket from responder*/
     
	 if (LIN(POLICY_SESSION_RESUME, cc->policy)) { 
		 if (!emit_v2N(v2N_TICKET_REQUEST, &sk.pbs)) {
			 return STF_INTERNAL_ERROR;
		 }
	 }

	/* send CP payloads */
	if (pc->modecfg_domains != NULL || pc->modecfg_dns != NULL) {
		ikev2_send_cp(pst, ISAKMP_NEXT_v2NONE, &sk.pbs);
	}

	if (!close_v2SK_payload(&sk)) {
		return STF_INTERNAL_ERROR;
	}
	close_output_pbs(&rbody);
	close_output_pbs(&reply_stream);

	/*
	 * For AUTH exchange, store the message in the IKE SA.  The
	 * attempt to create the CHILD SA could have failed.
	 */
	return record_outbound_v2SK_msg(&sk.ike->sa, &reply_stream, &sk,
					"sending IKE_AUTH request");
}

/*
 *
 ***************************************************************
 *                       SESSION_PARENT_inI2               *****
 ***************************************************************
 *  -
 *
 *
 */

static crypto_req_cont_func ikev2_session_resume_ike_sa_process_auth_request_no_skeyid_continue;	/* type asssertion */

stf_status ikev2_session_resume_ike_sa_process_auth_request_no_skeyid(struct state *st,
						       struct msg_digest *md UNUSED)
{
	/* for testing only */
	if (IMPAIR(SEND_NO_IKEV2_AUTH)) {
		libreswan_log(
			"IMPAIR_SEND_NO_IKEV2_AUTH set - not sending IKE_AUTH packet");
		return STF_IGNORE;
	}
    
    /*
    This method is to be written.
    	calc_skeyseed_v2(st, "ikev2_inI2outR2 KE",
		    ORIGINAL_RESPONDER,
		    NULL, NULL, &st->st_ike_spis,
		    ikev2_session_resume_ike_sa_process_auth_request_no_skeyid_continue);
    */
	return STF_SUSPEND;
}

static void ikev2_session_resume_ike_sa_process_auth_request_no_skeyid_continue(struct state *st,
								 struct msg_digest **mdp,
								 struct pluto_crypto_req *r)
{
	DBG(DBG_CONTROL,
		DBG_log("ikev2_parent_inI2outR2_continue for #%lu: generating keys, sending R2",
			st->st_serialno));

	passert(*mdp != NULL); /* IKE_AUTH request */

	/* extract calculated values from r */

	if (!finish_dh_v2(st, r, FALSE)) {
		/*
		 * Since dh failed, the channel isn't end-to-end
		 * encrypted.  Send back a clear text notify and then
		 * abandon the connection.
		 */
		DBG(DBG_CONTROL, DBG_log("aborting IKE SA: DH failed"));
		send_v2N_response_from_md(*mdp, v2N_INVALID_SYNTAX, NULL);
		/* replace (*mdp)->st with st ... */
		complete_v2_state_transition((*mdp)->st, mdp, STF_FATAL);
		return;
	}

	ikev2_process_state_packet(pexpect_ike_sa(st), st, mdp);
}

static stf_status ikev2_session_resume_inI2outR2_continue_tail(struct state *st,
						       struct msg_digest *md);

stf_status ikev2_session_resume_ike_sa_process_auth_request(struct state *st,
					     struct msg_digest *md)
{
	/* The connection is "up", start authenticating it */

	/*
	 * This log line establishes that the packet's been decrypted
	 * and now it is being processed for real.
	 *
	 * XXX: move this into ikev2.c?
	 */
	LSWLOG(buf) {
		lswlogf(buf, "processing decrypted ");
		lswlog_msg_digest(buf, md);
	}

	stf_status e = ikev2_session_resume_inI2outR2_continue_tail(st, md);
	LSWDBGP(DBG_CONTROL, buf) {
		lswlogs(buf, "ikev2_session_resume_inI2outR2_continue_tail returned ");
		lswlog_v2_stf_status(buf, e);
	}

	/*
	 * if failed OE, delete state completly, no create_child_sa
	 * allowed so childless parent makes no sense. That is also
	 * the reason why we send v2N_AUTHENTICATION_FAILED, even
	 * though authenticated succeeded. It shows the remote end
	 * we have deleted the SA from our end.
	 */
	if (e >= STF_FAIL &&
	    (st->st_connection->policy & POLICY_OPPORTUNISTIC)) {
		DBG(DBG_OPPO,
			DBG_log("(pretending?) Deleting opportunistic Parent with no Child SA"));
		e = STF_FATAL;
		send_v2N_response_from_state(ike_sa(st), md,
					     v2N_AUTHENTICATION_FAILED,
					     NULL/*no data*/);
	}

	return e;
}

static stf_status ikev2_session_resume_inI2outR2_continue_tail(struct state *st,
						       struct msg_digest *md)
{
	struct ike_sa *ike = ike_sa(st);
	stf_status ret;
	enum ikev2_auth_method atype;

	ikev2_log_parentSA(st);

	struct state *pst = IS_CHILD_SA(md->st) ?
		state_with_serialno(md->st->st_clonedfrom) : md->st;
	/* going to switch to child st. before that update parent */
	if (!LHAS(pst->hidden_variables.st_nat_traversal, NATED_HOST))
		update_ike_endpoints(ike, md);

	nat_traversal_change_port_lookup(md, st); /* shouldn't this be pst? */

	if (!v2_decode_certs(ike, md)) {
		pexpect(ike->sa.st_sa_role == SA_RESPONDER);
		pexpect(ike->sa.st_remote_certs.verified == NULL);
		/*
		 * The 'end-cert' was bad so all the certs have been
		 * tossed.  However, since this is the responder
		 * stumble on.  There might be a connection that still
		 * authenticates (after a switch?).
		 */
		loglog(RC_LOG_SERIOUS, "X509: CERT payload bogus or revoked");
	}
	/* this call might update connection in md->st */
	if (!ikev2_decode_peer_id(md)) {
		event_force(EVENT_SA_EXPIRE, st);
		pstat_sa_failed(&ike->sa, REASON_AUTH_FAILED);
		release_pending_whacks(st, "Authentication failed");
		/* this is really STF_FATAL but we need to send a reply packet out */
		return STF_FAIL + v2N_AUTHENTICATION_FAILED;
	}

	atype = md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2a.isaa_type;
	if (IS_LIBUNBOUND && id_ipseckey_allowed(st, atype)) {
		ret = idi_ipseckey_fetch(md);
		if (ret != STF_OK) {
			loglog(RC_LOG_SERIOUS, "DNS: IPSECKEY not found or usable");
			return ret;
		}
	}

	return ikev2_session_resume_inI2outR2_id_tail(md);
}

stf_status ikev2_session_resume_inI2outR2_id_tail(struct msg_digest *md)
{
	struct state *const st = md->st;
	lset_t policy = st->st_connection->policy;
	unsigned char idhash_in[MAX_DIGEST_LEN];
	bool found_ppk = FALSE;
	bool ppkid_seen = FALSE;
	bool noppk_seen = FALSE;
	chunk_t null_auth = EMPTY_CHUNK;
	struct payload_digest *ntfy;

	/*
	 * The NOTIFY payloads we receive in the IKE_AUTH request are either
	 * related to the IKE SA, or the Child SA. Here we only process the
	 * ones related to the IKE SA.
	 */
	for (ntfy = md->chain[ISAKMP_NEXT_v2N]; ntfy != NULL; ntfy = ntfy->next) {
		switch (ntfy->payload.v2n.isan_type) {
		case v2N_PPK_IDENTITY:
		{
			struct ppk_id_payload payl;

			DBG(DBG_CONTROL, DBG_log("received PPK_IDENTITY"));
			if (ppkid_seen) {
				loglog(RC_LOG_SERIOUS, "Only one PPK_IDENTITY payload may be present");
				return STF_FATAL;
			}
			ppkid_seen = TRUE;

			if (!extract_ppk_id(&ntfy->pbs, &payl)) {
				DBG(DBG_CONTROL, DBG_log("failed to extract PPK_ID from PPK_IDENTITY payload. Abort!"));
				return STF_FATAL;
			}

			const chunk_t *ppk = get_ppk_by_id(&payl.ppk_id);
			freeanychunk(payl.ppk_id);
			if (ppk != NULL)
				found_ppk = TRUE;

			if (found_ppk && LIN(POLICY_PPK_ALLOW, policy)) {
				ppk_recalculate(ppk, st->st_oakley.ta_prf,
						&st->st_skey_d_nss,
						&st->st_skey_pi_nss,
						&st->st_skey_pr_nss);
				st->st_ppk_used = TRUE;
				libreswan_log("PPK AUTH calculated as responder");
			} else {
				libreswan_log("ignored received PPK_IDENTITY - connection does not require PPK or PPKID not found");
			}
			break;
		}

		case v2N_NO_PPK_AUTH:
		{
			pb_stream pbs = ntfy->pbs;
			size_t len = pbs_left(&pbs);

			DBG(DBG_CONTROL, DBG_log("received NO_PPK_AUTH"));
			if (noppk_seen) {
				loglog(RC_LOG_SERIOUS, "Only one NO_PPK_AUTH payload may be present");
				return STF_FATAL;
			}
			noppk_seen = TRUE;

			if (LIN(POLICY_PPK_INSIST, policy)) {
				DBG(DBG_CONTROL, DBG_log("Ignored NO_PPK_AUTH data - connection insists on PPK"));
				break;
			}

			chunk_t no_ppk_auth = alloc_chunk(len, "NO_PPK_AUTH");

			if (!in_raw(no_ppk_auth.ptr, len, &pbs, "NO_PPK_AUTH extract")) {
				loglog(RC_LOG_SERIOUS, "Failed to extract %zd bytes of NO_PPK_AUTH from Notify payload", len);
				freeanychunk(no_ppk_auth);
				return STF_FATAL;
			}
			freeanychunk(st->st_no_ppk_auth);	/* in case this was already occupied */
			st->st_no_ppk_auth = no_ppk_auth;
			break;
		}

		case v2N_MOBIKE_SUPPORTED:
			DBG(DBG_CONTROLMORE, DBG_log("received v2N_MOBIKE_SUPPORTED %s",
				st->st_sent_mobike ?
					"and sent" : "while it did not sent"));
			st->st_seen_mobike = TRUE;
			break;

		case v2N_NULL_AUTH:
		{
			pb_stream pbs = ntfy->pbs;
			size_t len = pbs_left(&pbs);

			DBG(DBG_CONTROL, DBG_log("received v2N_NULL_AUTH"));
			null_auth = alloc_chunk(len, "NULL_AUTH");
			if (!in_raw(null_auth.ptr, len, &pbs, "NULL_AUTH extract")) {
				loglog(RC_LOG_SERIOUS, "Failed to extract %zd bytes of NULL_AUTH from Notify payload", len);
				freeanychunk(null_auth);
				return STF_FATAL;
			}
			break;
		}
		case v2N_INITIAL_CONTACT:
			DBG(DBG_CONTROLMORE, DBG_log("received v2N_INITIAL_CONTACT"));
			st->st_seen_initialc = TRUE;
			break;

        case v2N_TICKET_REQUEST:
		    DBG(DBG_CONTROLMORE, DBG_log("TICKET_REQUEST received"));
			st->st_seen_ticket_request = TRUE;
			break;

		/* Child SA related NOTIFYs are processed later in ikev2_process_ts_and_rest() */
		case v2N_USE_TRANSPORT_MODE:
		case v2N_IPCOMP_SUPPORTED:
		case v2N_ESP_TFC_PADDING_NOT_SUPPORTED:
			break;

		default:
			DBG(DBG_CONTROLMORE, DBG_log("Received unknown/unsupported notify %s - ignored",
				enum_name(&ikev2_notify_names,
					ntfy->payload.v2n.isan_type)));
			break;
		}
	}

	/*
	 * If we found proper PPK ID and policy allows PPK, use that.
	 * Otherwise use NO_PPK_AUTH
	 */
	if (found_ppk && LIN(POLICY_PPK_ALLOW, policy))
		freeanychunk(st->st_no_ppk_auth);

	if (!found_ppk && LIN(POLICY_PPK_INSIST, policy)) {
		loglog(RC_LOG_SERIOUS, "Requested PPK_ID not found and connection requires a valid PPK");
		freeanychunk(null_auth);
		return STF_FATAL;
	}

	/* calculate hash of IDi for AUTH below */
	{
		struct hmac_ctx id_ctx;
		const pb_stream *id_pbs = &md->chain[ISAKMP_NEXT_v2IDi]->pbs;
		unsigned char *idstart = id_pbs->start + NSIZEOF_isakmp_generic;
		unsigned int idlen = pbs_room(id_pbs) - NSIZEOF_isakmp_generic;

		hmac_init(&id_ctx, st->st_oakley.ta_prf, st->st_skey_pi_nss);
		DBG(DBG_CRYPT, DBG_dump("idhash verify I2", idstart, idlen));
		hmac_update(&id_ctx, idstart, idlen);
		hmac_final(idhash_in, &id_ctx);
	}

	/* process CERTREQ payload */
	if (md->chain[ISAKMP_NEXT_v2CERTREQ] != NULL) {
		DBG(DBG_CONTROLMORE,
		    DBG_log("received CERTREQ payload; going to decode it"));
		ikev2_decode_cr(md);
	}

	/* process AUTH payload */

	enum keyword_authby that_authby = st->st_connection->spd.that.authby;

	passert(that_authby != AUTH_NEVER && that_authby != AUTH_UNSET);

	if (!st->st_ppk_used && st->st_no_ppk_auth.ptr != NULL) {
		/*
		 * we didn't recalculate keys with PPK, but we found NO_PPK_AUTH
		 * (meaning that initiator did use PPK) so we try to verify NO_PPK_AUTH.
		 */
		DBG(DBG_CONTROL, DBG_log("going to try to verify NO_PPK_AUTH."));
		/* making a dummy pb_stream so we could pass it to v2_check_auth */
		pb_stream pbs_no_ppk_auth;
		pb_stream pbs = md->chain[ISAKMP_NEXT_v2AUTH]->pbs;
		size_t len = pbs_left(&pbs);
		init_pbs(&pbs_no_ppk_auth, st->st_no_ppk_auth.ptr, len, "pb_stream for verifying NO_PPK_AUTH");

		if (!v2_check_auth(md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2a.isaa_type,
				st, ORIGINAL_RESPONDER, idhash_in,
				&pbs_no_ppk_auth,
				st->st_connection->spd.that.authby, "no-PPK-auth"))
		{
			struct ike_sa *ike = ike_sa(st);
			send_v2N_response_from_state(ike, md,
						     v2N_AUTHENTICATION_FAILED,
						     NULL/*no data*/);
			freeanychunk(null_auth);	/* ??? necessary? */
			pstat_sa_failed(&ike->sa, REASON_AUTH_FAILED);
			return STF_FATAL;
		}
		DBG(DBG_CONTROL, DBG_log("NO_PPK_AUTH verified"));
	} else {
		bool policy_null = LIN(POLICY_AUTH_NULL, st->st_connection->policy);
		bool policy_rsasig = LIN(POLICY_RSASIG, st->st_connection->policy);

		/*
		 * if received NULL_AUTH in Notify payload and we only allow NULL Authentication,
		 * proceed with verifying that payload, else verify AUTH normally
		 */
		if (null_auth.ptr != NULL && policy_null && !policy_rsasig) {
			/* making a dummy pb_stream so we could pass it to v2_check_auth */
			pb_stream pbs_null_auth;
			size_t len = null_auth.len;

			DBG(DBG_CONTROL, DBG_log("going to try to verify NULL_AUTH from Notify payload"));
			init_pbs(&pbs_null_auth, null_auth.ptr, len, "pb_stream for verifying NULL_AUTH");
			if (!v2_check_auth(IKEv2_AUTH_NULL, st,
					ORIGINAL_RESPONDER, idhash_in,
					&pbs_null_auth, AUTH_NULL, "NULL_auth from Notify Payload"))
			{
				struct ike_sa *ike = ike_sa(st);
				send_v2N_response_from_state(ike, md,
							     v2N_AUTHENTICATION_FAILED,
							     NULL/*no data*/);
				freeanychunk(null_auth);
				pstat_sa_failed(&ike->sa, REASON_AUTH_FAILED);
				return STF_FATAL;
			}
			DBG(DBG_CONTROL, DBG_log("NULL_AUTH verified"));
		} else {
			DBGF(DBG_CONTROL, "verifying AUTH payload");
			if (!v2_check_auth(md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2a.isaa_type,
					st, ORIGINAL_RESPONDER, idhash_in,
					&md->chain[ISAKMP_NEXT_v2AUTH]->pbs,
					st->st_connection->spd.that.authby, "I2 Auth Payload")) {
				struct ike_sa *ike = ike_sa(st);
				send_v2N_response_from_state(ike, md,
							     v2N_AUTHENTICATION_FAILED,
							     NULL/*no data*/);
				freeanychunk(null_auth);
				pstat_sa_failed(&ike->sa, REASON_AUTH_FAILED);
				return STF_FATAL;
			}
		}
	}

	/* AUTH succeeded */

	freeanychunk(null_auth);

#ifdef XAUTH_HAVE_PAM
	if (st->st_connection->policy & POLICY_IKEV2_PAM_AUTHORIZE)
		return ikev2_start_pam_authorize(st);
#endif
	return ikev2_session_resume_inI2outR2_auth_tail(st, md, TRUE);
}

static stf_status ikev2_session_resume_inI2outR2_auth_tail(struct state *st,
						   struct msg_digest *md,
						   bool pam_status)
{
	struct connection *const c = st->st_connection;

	if (!pam_status) {
		/*
		 * TBD: send this notification encrypted because the
		 * AUTH payload succeed
		 */
		send_v2N_response_from_state(ike_sa(st), md,
					     v2N_AUTHENTICATION_FAILED,
					     NULL/*no data*/);
		return STF_FATAL;
	}

	/*
	 * Now create child state.
	 * As we will switch to child state, force the parent to the
	 * new state now.
	 *
	 * XXX: Danger!  md->svm points to a state transition that
	 * mashes the IKE SA's initial state in and the CHILD SA's
	 * final state.  Hence, the need to explicitly force the final
	 * IKE SA state.  There should instead be separate state
	 * transitions for the IKE and CHILD SAs and then have the IKE
	 * SA invoke the CHILD SA's transition.
	 */
	pexpect(md->svm->next_state == STATE_V2_IPSEC_R);
	ikev2_ike_sa_established(pexpect_ike_sa(st), md->svm,
				 STATE_PARENT_R2);

	if (LHAS(st->hidden_variables.st_nat_traversal, NATED_HOST)) {
		/* ensure we run keepalives if needed */
		if (c->nat_keepalive)
			nat_traversal_ka_event();
	}

	/* send response */
	if (LIN(POLICY_MOBIKE, c->policy) && st->st_seen_mobike) {
		if (c->spd.that.host_type == KH_ANY) {
			/* only allow %any connection to mobike */
			st->st_sent_mobike = TRUE;
		} else {
			libreswan_log("not responding with v2N_MOBIKE_SUPPORTED, that end is not %%any");
		}
	}

	bool send_redirect = FALSE;

	if (st->st_seen_redirect_sup &&
	    (LIN(POLICY_SEND_REDIRECT_ALWAYS, c->policy) ||
	     (!LIN(POLICY_SEND_REDIRECT_NEVER, c->policy) &&
	      require_ddos_cookies()))) {
		if (c->redirect_to == NULL) {
			loglog(RC_LOG_SERIOUS, "redirect-to is not specified, can't redirect requests");
		} else {
			send_redirect = TRUE;
		}
	}

	/* make sure HDR is at start of a clean buffer */
	init_out_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
		 "reply packet");

	/* HDR out */

	pb_stream rbody = open_v2_message(&reply_stream, ike_sa(st),
					  md /* response */,
					  ISAKMP_v2_IKE_AUTH);

	if (IMPAIR(ADD_UNKNOWN_PAYLOAD_TO_AUTH)) {
		if (!emit_v2UNKNOWN("IKE_AUTH reply", &rbody)) {
			return STF_INTERNAL_ERROR;
		}
	}

	/* decide to send CERT payload before we generate IDr */
	bool send_cert = ikev2_send_cert_decision(st);

	/* insert an Encryption payload header */

	v2SK_payload_t sk = open_v2SK_payload(&rbody, ike_sa(st));
	if (!pbs_ok(&sk.pbs)) {
		return STF_INTERNAL_ERROR;
	}

	if (IMPAIR(ADD_UNKNOWN_PAYLOAD_TO_AUTH_SK)) {
		if (!emit_v2UNKNOWN("IKE_AUTH's SK reply", &sk.pbs)) {
			return STF_INTERNAL_ERROR;
		}
	}

	/* send any NOTIFY payloads */
	if (st->st_sent_mobike) {
		if (!emit_v2N(v2N_MOBIKE_SUPPORTED, &sk.pbs))
			return STF_INTERNAL_ERROR;
	}

	if (st->st_ppk_used) {
		if (!emit_v2N(v2N_PPK_IDENTITY, &sk.pbs))
			return STF_INTERNAL_ERROR;
	}

	if (send_redirect) {
		if (!emit_redirect_notification(c->redirect_to, NULL, &sk.pbs))
			return STF_INTERNAL_ERROR;

		st->st_sent_redirect = TRUE;	/* mark that we have sent REDIRECT in IKE_AUTH */
	}

	if (LIN(POLICY_TUNNEL, c->policy) == LEMPTY && st->st_seen_use_transport) {
		if (!emit_v2N(v2N_USE_TRANSPORT_MODE, &sk.pbs))
			return STF_INTERNAL_ERROR;
	}

	if (!emit_v2N_compression(st, st->st_seen_use_ipcomp, &sk.pbs))
		return STF_INTERNAL_ERROR;

	if (c->send_no_esp_tfc) {
		if (!emit_v2N(v2N_ESP_TFC_PADDING_NOT_SUPPORTED, &sk.pbs))
			return STF_INTERNAL_ERROR;
	}

	if (LIN(POLICY_SESSION_RESUME, c->policy) && st->st_seen_ticket_request) {
		chunk_t tk_payl_chunk = st_to_ticket(st);
		if (!emit_v2Nchunk(v2N_TICKET_LT_OPAQUE, &tk_payl_chunk, &sk.pbs)) {
			return STF_INTERNAL_ERROR;
		}
		freeanychunk(tk_payl_chunk);

		
		/* N(TICKET_ACK) comes into action if there are any packet size limitations 
		To-do: Need to find those situations. */
	    #if 0
		if (!emit_v2N(v2N_TICKET_ACK, &sk.pbs))
			return STF_INTERNAL_ERROR;
		DBG(DBG_CONTROLMORE, DBG_log("TICKET_ACK sent"));
		#endif

		/*As per RFC 
		 "Returns an N(TICKET_NACK) payload, if it refuses to grant a
          ticket for some reason."
		 But currently exact reason for not granting is not determined yet.
		*/
         
		#if 0
		if (!emit_v2N(v2N_TICKET_NACK, &sk.pbs))
			return STF_INTERNAL_ERROR;
		#endif
	    
	}

	
	    
	
	

	/* send out the IDr payload */
	unsigned char idhash_out[MAX_DIGEST_LEN];

	{
		struct ikev2_id r_id = {
			.isai_np = ISAKMP_NEXT_v2NONE,
			.isai_type = ID_NULL,
			/* critical bit zero */
		};
		pb_stream r_id_pbs;
		chunk_t id_b;
		struct hmac_ctx id_ctx;
		unsigned char *id_start;
		unsigned int id_len;

		hmac_init(&id_ctx, st->st_oakley.ta_prf, st->st_skey_pr_nss);
		if (st->st_peer_wants_null) {
			/* make it the Null ID */
			/* r_id already set */
			id_b = EMPTY_CHUNK;
		} else {
			v2_build_id_payload(&r_id,
					 &id_b,
					 &c->spd.this);
		}

		id_start = sk.pbs.cur + NSIZEOF_isakmp_generic;

		if (!out_struct(&r_id, &ikev2_id_r_desc, &sk.pbs,
				&r_id_pbs) ||
		    !out_chunk(id_b, &r_id_pbs, "my identity"))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&r_id_pbs);

		/* calculate hash of IDi for AUTH below */
		id_len = sk.pbs.cur - id_start;
		DBG(DBG_CRYPT,
		    DBG_dump("idhash calc R2", id_start, id_len));
		hmac_update(&id_ctx, id_start, id_len);
		hmac_final(idhash_out, &id_ctx);
	}

	DBG(DBG_CONTROLMORE,
	    DBG_log("assembled IDr payload"));

	/*
	 * send CERT payload RFC 4306 3.6, 1.2:([CERT,] )
	 * upon which our received I2 CERTREQ is ignored,
	 * but ultimately should go into the CERT decision
	 */
	if (send_cert) {
		stf_status certstat = ikev2_send_cert(st, &sk.pbs);
		if (certstat != STF_OK)
			return certstat;
	}

	/* authentication good, see if there is a child SA being proposed */
	unsigned int auth_np;

	if (md->chain[ISAKMP_NEXT_v2SA] == NULL ||
	    md->chain[ISAKMP_NEXT_v2TSi] == NULL ||
	    md->chain[ISAKMP_NEXT_v2TSr] == NULL) {
		/* initiator didn't propose anything. Weird. Try unpending our end. */
		/* UNPEND XXX */
		if ((c->policy & POLICY_OPPORTUNISTIC) == LEMPTY) {
			libreswan_log("No CHILD SA proposals received.");
		} else {
			DBG(DBG_CONTROLMORE, DBG_log("No CHILD SA proposals received"));
		}
		auth_np = ISAKMP_NEXT_v2NONE;
	} else {
		DBG(DBG_CONTROLMORE, DBG_log("CHILD SA proposals received"));
		auth_np = (c->pool != NULL && md->chain[ISAKMP_NEXT_v2CP] != NULL) ?
			ISAKMP_NEXT_v2CP : ISAKMP_NEXT_v2SA;
	}

	DBG(DBG_CONTROLMORE,
	    DBG_log("going to assemble AUTH payload"));

	/* now send AUTH payload */
	{
		stf_status authstat = ikev2_send_auth(st,
						      ORIGINAL_RESPONDER, auth_np,
						      idhash_out,
						      &sk.pbs, NULL);
						      /* ??? NULL - don't calculate additional NULL_AUTH ??? */

		if (authstat != STF_OK)
			return authstat;
	}

	if (auth_np == ISAKMP_NEXT_v2SA || auth_np == ISAKMP_NEXT_v2CP) {
		/* must have enough to build an CHILD_SA */
		stf_status ret = ikev2_child_sa_respond(md, &sk.pbs,
							ISAKMP_v2_IKE_AUTH);

		/* note: st: parent; md->st: child */
		if (ret != STF_OK) {
			LSWDBGP(DBG_CONTROL, buf) {
				lswlogs(buf, "ikev2_child_sa_respond returned ");
				lswlog_v2_stf_status(buf, ret);
			}
			return ret; /* we should continue building a valid reply packet */
		}
	}

	if (!close_v2SK_payload(&sk)) {
		return STF_INTERNAL_ERROR;
	}
	close_output_pbs(&rbody);
	close_output_pbs(&reply_stream);

	/*
	 * For AUTH exchange, store the message in the IKE SA.
	 * The attempt to create the CHILD SA could have
	 * failed.
	 */
	return record_outbound_v2SK_msg(&sk.ike->sa, &reply_stream, &sk,
					"replying to IKE_AUTH request");
}




/* Functions related to hibernate/resume connection */
void hibernate_connection(struct connection *c) {

    struct state *pst = state_with_serialno(c->newest_isakmp_sa);
    struct state *cst = state_with_serialno(c->newest_ipsec_sa);
    /* Deleting the child sa of the current state */
    whack_log(RC_COMMENT, "cst to be deleted - %ld", c->newest_ipsec_sa);
    if(cst!=NULL) {
		/* TODO: this should not send a delete notify */
        event_force(EVENT_SA_EXPIRE, cst);
    }
     
    if(pst!=NULL) {
        /* Marking parent state as hibernated */
        pst->st_hibernated = TRUE;
        /* State should be tranistioned in STATE_PARENT_HIBERNATED */
         change_state(pst ,STATE_PARENT_HIBERNATED);
    }
   
}






