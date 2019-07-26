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

struct ike_ticket_state {
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

    /* All the chosen Algorithm Description */
    struct trans_attrs st_oakley;

    Deltatime_t expiration_time;
}

/* Ticket by value structures */
struct ticket_by_value {

    /* 1 for this version of the protocol */
    uint8_t format_version;

    /* sent as 0, ignored by receiver. */
    uint8_t reserved;

    /* Reference to the key stored in NSS database */
    PK11SymKey *key_id;

    u_char IV[MAX_DIGEST_LEN];
    
    /* The part to be encrypted */
    struct ike_ticket_state ike_tk_state;

   
   u_int32_t mac ;
};

/* Ticket by reference structures */

struct ikev2_state_ref {

};

struct ticket_by_reference {
   uint8_t format_version;

};

/* Ticket Payload */
struct ticket_payload {
    /*
      The reason for lifetime to be present outside ticket is 
      -The client will clear expired tickets.
    */
    deltatime_t lifetime;
    /*
      
    */
    union ticket {
      struct ticket_by_value tk_by_value; 
      struct ticket_by_reference tk_by_ref;
    } ticket;
};


/* Functions related to ticket */
struct chunk_t *st_to_ticket(const struct state *st);
struct state *ticket_to_st(const struct chunk_t *ticket);


#endif