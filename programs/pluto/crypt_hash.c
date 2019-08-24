/*
 * Hash algorithms, for libreswan
 *
 * Copyright (C) 2016-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2019 D. Hugh Redelmeier <hugh@mimosa.com>
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

#include <stdlib.h>

#include "lswalloc.h"
#include "lswlog.h"
#include "ike_alg.h"
#include "ike_alg_hash_ops.h"
#include "crypt_hash.h"
#include "crypt_symkey.h"

struct crypt_hash {
	struct hash_context *context;
	const char *name;
	const struct hash_desc *desc;
};

struct crypt_hash *crypt_hash_init(const char *name, const struct hash_desc *hash_desc)
{
	DBGF(DBG_CRYPT, "%s hash %s init",
	     name, hash_desc->common.name);
	struct hash_context *context =
		hash_desc->hash_ops->init(hash_desc, name);
	if (context == NULL) {
		return NULL;
	}
	struct crypt_hash *hash = alloc_thing(struct crypt_hash, name);
	*hash = (struct crypt_hash) {
		.context = context,
		.name = name,
		.desc = hash_desc,
	};
	return hash;
}

void crypt_hash_digest_symkey(struct crypt_hash *hash,
			      const char *name, PK11SymKey *symkey)
{
	if (DBGP(DBG_CRYPT)) {
		DBG_log("%s hash %s digest %s-key@%p (size %zu)",
			hash->name, hash->desc->common.name,
			name, symkey, sizeof_symkey(symkey));
		DBG_symkey(hash->name, name, symkey);
	}
	hash->desc->hash_ops->digest_symkey(hash->context, name, symkey);
}

void crypt_hash_digest_byte(struct crypt_hash *hash,
			    const char *name, uint8_t byte)
{
	if (DBGP(DBG_CRYPT)) {
		DBG_log("%s hash %s digest %s-byte@0x%x (%d)",
			hash->name, hash->desc->common.name,
			name, byte, byte);
		DBG_dump(NULL, &byte, sizeof(byte));
	}
	hash->desc->hash_ops->digest_bytes(hash->context, name, &byte, 1);
}

void crypt_hash_digest_bytes(struct crypt_hash *hash,
			     const char *name,
			     const void *bytes,
			     size_t sizeof_bytes)
{
	if (DBGP(DBG_CRYPT)) {
		DBG_log("%s hash %s digest %s-bytes@%p (length %zu)",
			hash->name, hash->desc->common.name,
			name, bytes, sizeof_bytes);
		DBG_dump(NULL, bytes, sizeof_bytes);
	}
	hash->desc->hash_ops->digest_bytes(hash->context, name, bytes, sizeof_bytes);
}

void crypt_hash_final_bytes(struct crypt_hash **hashp,
			    uint8_t *bytes, size_t sizeof_bytes)
{
	struct crypt_hash *hash = *hashp;
	/* Must be correct, else hash code can crash. */
	passert(sizeof_bytes == hash->desc->hash_digest_size);
	hash->desc->hash_ops->final_bytes(&hash->context, bytes, sizeof_bytes);
	if (DBGP(DBG_CRYPT)) {
		DBG_log("%s hash %s final bytes@%p (length %zu)",
			hash->name, hash->desc->common.name,
			bytes, sizeof_bytes);
		DBG_dump(NULL, bytes, sizeof_bytes);
	}
	pfree(*hashp);
	*hashp = hash = NULL;
}

chunk_t crypt_hash_final_chunk(struct crypt_hash **hashp)
{
	struct crypt_hash *hash = *hashp;
	chunk_t chunk = alloc_chunk(hash->desc->hash_digest_size, hash->name);
	hash->desc->hash_ops->final_bytes(&hash->context, chunk.ptr, chunk.len);
	if (DBGP(DBG_CRYPT)) {
		DBG_log("%s hash %s final chunk@%p (length %zu)",
			hash->name, hash->desc->common.name,
			chunk.ptr, chunk.len);
		DBG_dump_hunk(NULL, chunk);
	}
	pfree(*hashp);
	*hashp = hash = NULL;
	return chunk;
}

PK11SymKey *crypt_hash_symkey(const char *name, const struct hash_desc *hash_desc,
			      const char *symkey_name, PK11SymKey *symkey)
{
	DBGF(DBG_CRYPT, "%s hash %s %s-key@%p (size %zu)",
	     name, hash_desc->common.name,
	     symkey_name, symkey, sizeof_symkey(symkey));
	struct crypt_hash *hash = crypt_hash_init(name, hash_desc);
	crypt_hash_digest_symkey(hash, symkey_name, symkey);
	chunk_t out = crypt_hash_final_chunk(&hash);
	PK11SymKey *key = symkey_from_hunk(name, out);
	freeanychunk(out);
	return key;
}
