/*
 *  Helper functions and ticket store for IKEv2 Session Resumption
*/

#ifndef IKEV2_SESSION_RESUME_H
#define IKEV2_SESSION_RESUME_H

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include "state.h"
#include "packet.h"
#include "deltatime.h"
#include "id.h"
#include <pk11pub.h>

/*
 * There are two types for ticket:
 * 1.Ticket by Value
 * 2.Ticket by Reference
 * Whenever a initiator(client) requests for a ticket the responder should select any of
 * the above types and send it to client but client should not have any idea about the type 
 * received.


*/

struct ike_ticket_state {
    /* IDi */
    struct id IDi;
    /* IDr */
    struct id IDr;

    /* SPIi */ 
    uint8_t SPIi[IKE_SA_SPI_SIZE];
    
    /* SPIr */
    uint8_t SPIr[IKE_SA_SPI_SIZE];

    /* Reference to sk_d_old */
    chunk_t sk_d_old;

    /* All the chosen Algorithm Description */
    struct trans_attrs st_oakley;

    enum keyword_authby authentication_method;

    deltatime_t expiration_time;
};

/* Ticket by value structures */
struct ticket_by_value {

    /* 1 for this version of the protocol */
    uint8_t format_version;

    /* sent as 0, ignored by receiver. */
    uint8_t reserved;

    /* Reference to the key stored in NSS database */
#if 0
    PK11SymKey key_id;

    u_char IV[MAX_DIGEST_LEN];
#endif
    
    /* The part to be encrypted */
    struct ike_ticket_state ike_tk_state;

};



/* Ticket Payload */
struct ticket_payload {

    struct ticket_by_value tk_by_value; 
     /*
      The reason for lifetime to be present outside ticket is 
      -The client will clear expired tickets.
    */
    deltatime_t lifetime;
};


/* Functions related to ticket */
chunk_t st_to_ticket(const struct state *st);
bool ticket_to_st(const struct state *st , const chunk_t ticket);


/* Functions related to Session Resume Exchange */
void ikev2_session_resume_outI1(struct state *st);
stf_status ikev2_session_resume_inI1outR1(struct state *st, struct msg_digest *md);
stf_status ikev2_session_resume_inR1outI2(struct state *st, struct msg_digest *md);
stf_status ikev2_session_resume_ike_sa_process_auth_request_no_skeyid(struct state *st,
                                                             struct msg_digest *md UNUSED);


/* Functions related to hibernate/resume connection */
void hibernate_connection(struct connection *c);

#endif