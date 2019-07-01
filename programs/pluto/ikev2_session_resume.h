/*
 *  Helper functions and ticket store for IKEv2 Session Resumption
*/

#ifndef IKEV2_SESSION_RESUME_H
#define IKEV2_SESSION_RESUME_H

#include "state.h"
#include "packet.h"

/*
 * There are two types for ticket:
 * 1.Ticket by Value
 * 2.Ticket by Reference
 * Whenever a initiator(client) requests for a ticket the responder should select any of
 * the above types and send it to client but client should not have any idea about the type 
 * received.


*/


struct ticket_by_value {

};

struct ticket_by_reference {
   uint8_t 
};

struct ticket_payload {
    chunk_t ticket;
    
};



#endif