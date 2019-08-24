/* do RSA operations for IKEv2
 *
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2018 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
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
#include "certs.h"
#include "connections.h"        /* needs id.h */
#include "state.h"
#include "packet.h"
#include "crypto.h"
#include "ike_alg.h"
#include "ike_alg_hash.h"
#include "log.h"
#include "demux.h"      /* needs packet.h */
#include "pluto_crypt.h"  /* for pluto_crypto_req & pluto_crypto_req_cont */
#include "ikev2.h"
#include "server.h"
#include "vendor.h"
#include "keys.h"
#include "secrets.h"
#include "crypt_hash.h"
#include "ietf_constants.h"

static const u_char der_digestinfo[] = {
	0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
	0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
};
static const int der_digestinfo_len = sizeof(der_digestinfo);

static bool RSA_ikev2_calculate_sighash(const struct state *st,
				    enum original_role role,
				    const unsigned char *idhash,
				    const chunk_t firstpacket,
				    unsigned char *sig_octets, /* output */
				    size_t *sig_size, /* input & output */
				    enum notify_payload_hash_algorithms hash_algo)
{
	const chunk_t *nonce;
	const char *nonce_name;

	if (role == ORIGINAL_INITIATOR) {
		/* on initiator, we need to hash responders nonce */
		nonce = &st->st_nr;
		nonce_name = "inputs to hash2 (responder nonce)";
	} else {
		nonce = &st->st_ni;
		nonce_name = "inputs to hash2 (initiator nonce)";
	}

	DBG(DBG_CRYPT,
	    DBG_dump_hunk("inputs to hash1 (first packet)", firstpacket);
	    DBG_dump_hunk(nonce_name, *nonce);
	    DBG_dump("idhash", idhash, st->st_oakley.ta_prf->prf_output_size));

	const struct hash_desc *hd;

	switch (hash_algo) {
#ifdef USE_SHA1
	case IKEv2_AUTH_HASH_SHA1:
		hd = &ike_alg_hash_sha1;
		break;
#endif
#ifdef USE_SHA2
	case IKEv2_AUTH_HASH_SHA2_256:
		hd = &ike_alg_hash_sha2_256;
		break;
	case IKEv2_AUTH_HASH_SHA2_384:
		hd = &ike_alg_hash_sha2_384;
		break;
	case IKEv2_AUTH_HASH_SHA2_512:
		hd = &ike_alg_hash_sha2_512;
		break;
#endif
	default:
		libreswan_log("unknown or unsupported hash algorithm %d",
			hash_algo); /* no enum_name for this? */
		return FALSE;
	}

	passert(hd->hash_digest_size <= *sig_size);
	struct crypt_hash *ctx = crypt_hash_init("sighash", hd);

	crypt_hash_digest_hunk(ctx, "first packet", firstpacket);
	crypt_hash_digest_hunk(ctx, "nonce", *nonce);

	/* we took the PRF(SK_d,ID[ir]'), so length is prf hash length */
	crypt_hash_digest_bytes(ctx, "IDHASH", idhash,
				st->st_oakley.ta_prf->prf_output_size);

	crypt_hash_final_bytes(&ctx, sig_octets, hd->hash_digest_size);
	*sig_size = hd->hash_digest_size;

	return TRUE;
}

bool ikev2_calculate_rsa_hash(struct state *st,
			      enum original_role role,
			      const unsigned char *idhash,
			      pb_stream *a_pbs,
			      chunk_t *no_ppk_auth, /* optional output */
			      enum notify_payload_hash_algorithms hash_algo)
{
	statetime_t start = statetime_start(st);
	const struct connection *c = st->st_connection;
	const struct RSA_private_key *k = get_RSA_private_key(c);

	if (k == NULL) {
		libreswan_log("No RSA private key found");
		return FALSE;
	}

	unsigned int sz = k->pub.k;

	/*
	 * Allocate large enough space for any digest.
	 * Bound could be tightened because the signature octets are
	 * only concatenated to a SHA1 hash.
	 */
	unsigned char signed_octets[MAX_DIGEST_LEN + RSA_SHA1_SIGNED_OCTETS];
	size_t signed_len;

	switch (hash_algo) {
	case IKEv2_AUTH_HASH_SHA1:
		/* old style RSA with SHA1 */
		memcpy(signed_octets, der_digestinfo, der_digestinfo_len);

		signed_len = sizeof(signed_octets) - der_digestinfo_len;
		if (!RSA_ikev2_calculate_sighash(st, role, idhash,
					st->st_firstpacket_me,
					signed_octets + der_digestinfo_len,
					&signed_len,
					hash_algo))
		{
			return FALSE;
		}
		signed_len += der_digestinfo_len;
		break;

	case IKEv2_AUTH_HASH_SHA2_256:
	case IKEv2_AUTH_HASH_SHA2_384:
	case IKEv2_AUTH_HASH_SHA2_512:
		signed_len = sizeof(signed_octets);
		if (!RSA_ikev2_calculate_sighash(st, role, idhash,
					st->st_firstpacket_me,
					signed_octets,
					&signed_len,
					hash_algo))
		{
			return FALSE;
		}
		break;

	default:
		libreswan_log("unknown or unsupported hash algorithm");
		return FALSE;
	}

	passert(RSA_MIN_OCTETS <= sz && 4 + signed_len < sz &&
		sz <= RSA_MAX_OCTETS);

	DBG(DBG_CRYPT,
	    DBG_dump("v2rsa octets", signed_octets, signed_len));

	{
		/* now generate signature blob */
		u_char sig_val[RSA_MAX_OCTETS];
		statetime_t sign_time = statetime_start(st);
		int shr = sign_hash_RSA(k, signed_octets, signed_len,
					sig_val, sz, hash_algo);
		statetime_stop(&sign_time, "%s() calling sign_hash_RSA()", __func__);
		if (shr == 0)
			return FALSE;

		passert(shr == (int)sz);
		if (no_ppk_auth != NULL) {
			clonetochunk(*no_ppk_auth, sig_val, sz, "NO_PPK_AUTH chunk");
			DBG(DBG_PRIVATE, DBG_dump_hunk("NO_PPK_AUTH payload", *no_ppk_auth));
		} else {
			if (!out_raw(sig_val, sz, a_pbs, "rsa signature"))
				return FALSE;
		}
	}

	statetime_stop(&start, "%s()", __func__);
	return TRUE;
}

static err_t try_RSA_signature_v2(const u_char hash_val[MAX_DIGEST_LEN],
				  size_t hash_len,
				  const pb_stream *sig_pbs, struct pubkey *kr,
				  struct state *st,
				  enum notify_payload_hash_algorithms hash_algo)
{
	const u_char *sig_val = sig_pbs->cur;
	size_t sig_len = pbs_left(sig_pbs);
	const struct RSA_public_key *k = &kr->u.rsa;

	if (k == NULL)
		return "1" "no key available"; /* failure: no key to use */

	/* decrypt the signature -- reversing RSA_sign_hash */
	if (sig_len != k->k)
		return "1" "SIG length does not match public key length";

	err_t ugh = RSA_signature_verify_nss(k, hash_val, hash_len, sig_val,
					     sig_len, hash_algo);
	if (ugh != NULL)
		return ugh;

	unreference_key(&st->st_peer_pubkey);
	st->st_peer_pubkey = reference_key(kr);

	return NULL;
}

stf_status ikev2_verify_rsa_hash(struct state *st,
				 enum original_role role,
				 const unsigned char *idhash,
				 pb_stream *sig_pbs,
				 enum notify_payload_hash_algorithms hash_algo)
{
	statetime_t start = statetime_start(st);
	enum original_role invertrole = (role == ORIGINAL_INITIATOR ? ORIGINAL_RESPONDER : ORIGINAL_INITIATOR);

	unsigned char calc_hash[MAX_DIGEST_LEN];
	size_t hash_len = sizeof(calc_hash);
	if (!RSA_ikev2_calculate_sighash(st, invertrole, idhash, st->st_firstpacket_him,
				calc_hash, &hash_len, hash_algo)) {
		return STF_FATAL;
	}

	stf_status retstat = RSA_check_signature_gen(st, calc_hash, hash_len,
					  sig_pbs, hash_algo, try_RSA_signature_v2);
	statetime_stop(&start, "%s()", __func__);
	return retstat;
}
