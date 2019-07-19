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

   struct {
    /* 1 for this version of the protocol */
    uint8_t format_version;

    /* sent as 0, ignored by receiver. */
    uint8_t reserved;

    /* Reference to the key stored in NSS database */
    uint8_t *key_id;

    u_char IV[MAX_DIGEST_LEN];

    struct {
        /* IDi */
        uint8_t st_myuserprotoid;
        uint16_t st_myuserport;

        /* IDr */
        uint8_t st_peeruserprotoid;
        uint16_t st_peeruserport;

        /* SPIi , SPIr */
        ike_spis_t st_ike_spis;

        /* Reference to sk_d_old */
        PK11SymKey *st_skey_d_nss;

        /* Established Proposals */
        struct ikev2_proposal *st_accepted_ike_proposal;

        /* Authentication Methods */
        oakley_auth_t auth;

        /* All the chosen Algorithm Description */
        struct trans_attrs st_oakley;

        Deltatime_t expiration_time;

    } ike_sa_state;

   } protected_part;
   
   u_int32_t mac ;
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
struct chunk_t *st_to_ticket(const struct state *st);
struct state *ticket_to_st(const struct chunk_t *ticket);


#endif