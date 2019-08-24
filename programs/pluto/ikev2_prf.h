/*
 * Calculate IKEv2 prf and keying material, for libreswan
 *
 * Copyright (C) 2007 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
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
 */

#ifndef _IKEV2_PRF_H
#define _IKEV2_PRF_H

#include "lswnss.h"
#include "ike_spi.h"
#include "chunk.h"
#include "shunk.h"

struct prf_desc;

/*
 * IKE SA
 */
PK11SymKey *ikev2_prfplus(const struct prf_desc *prf_desc,
			  PK11SymKey *key, PK11SymKey *seed,
			  size_t required_keymat);

PK11SymKey *ikev2_ike_sa_skeyseed(const struct prf_desc *prf_desc,
				  const chunk_t Ni, const chunk_t Nr,
				  PK11SymKey *dh_secret);

PK11SymKey *ikev2_ike_sa_rekey_skeyseed(const struct prf_desc *prf_desc,
					PK11SymKey *old_SK_d,
					PK11SymKey *new_dh_secret,
					const chunk_t Ni, const chunk_t Nr);

PK11SymKey *ikev2_ike_sa_keymat(const struct prf_desc *prf_desc,
				PK11SymKey *skeyseed,
				const chunk_t Ni, const chunk_t Nr,
				const ike_spis_t *ike_spis,
				size_t required_bytes);

/*
 * Child SA
 */
PK11SymKey *ikev2_child_sa_keymat(const struct prf_desc *prf_desc,
				  PK11SymKey *SK_d,
				  PK11SymKey *new_dh_secret,
				  const chunk_t Ni, const chunk_t Nr,
				  size_t required_bytes);

/*
 * Authentication.
 */

chunk_t ikev2_psk_auth(const struct prf_desc *prf_desc, chunk_t pss,
		       chunk_t first_packet, chunk_t nonce, shunk_t id_hash);

#endif
