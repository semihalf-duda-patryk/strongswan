/*
 * Copyright (C) 2016-2019 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "drbg_ctr.h"

#define MAX_DRBG_REQUESTS	0xfffffffe

typedef struct private_drbg_ctr_t private_drbg_ctr_t;

/**
 * Private data of an drbg_ctr_t object.
 */
struct private_drbg_ctr_t {

	/**
	 * Public drbg_ctr_t interface.
	 */
	drbg_ctr_t public;

	/**
	 * DRBG type.
	 */
	drbg_type_t type;

	/**
	 * Security strength in bits.
	 */
	uint32_t strength;

	/**
	 * Number of requests for pseudorandom bits
	 */
	uint32_t reseed_counter;

	/**
	 * Maximum number of requests for pseudorandom bits
	 */
	uint32_t max_requests;

	/**
	 * True entropy source
	 */
	rng_t *entropy;

	/**
	 * Internal state of HMAC: key
	 */
	chunk_t key;

	/**
	 * Internal state of HMAC: value
	 */
	chunk_t value;

	/**
	 * reference count
	 */
	refcount_t ref;

};

METHOD(drbg_t, get_type, drbg_type_t,
	private_drbg_ctr_t *this)
{
	return this->type;
}

METHOD(drbg_t, get_strength, uint32_t,
	private_drbg_ctr_t *this)
{
	return this->strength;
}

METHOD(drbg_t, reseed, bool,
	private_drbg_ctr_t *this)
{
	return TRUE;
}

METHOD(drbg_t, generate, bool,
	private_drbg_ctr_t *this, uint32_t len, uint8_t *out)
{
	return TRUE;
}

METHOD(drbg_t, get_ref, drbg_t*,
	private_drbg_ctr_t *this)
{
	ref_get(&this->ref);
	return &this->public.interface;
}

METHOD(drbg_t, destroy, void,
	private_drbg_ctr_t *this)
{
	if (ref_put(&this->ref))
	{
		chunk_clear(&this->key);
		chunk_clear(&this->value);
		free(this);
	}
}

/**
 * See header
 */
drbg_ctr_t *drbg_ctr_create(drbg_type_t type, uint32_t strength,
							rng_t *entropy, chunk_t personalization_str)
{
	private_drbg_ctr_t *this;
	uint32_t max_requests;
	/*
	switch (type)
	{
		case DRBG_HMAC_SHA1:
			if (strength > HASH_SIZE_SHA1 * BITS_PER_BYTE)
			{
				goto err;
			}
			prf_type = PRF_HMAC_SHA1;
			break;
		case DRBG_HMAC_SHA256:
			if (strength > HASH_SIZE_SHA256 * BITS_PER_BYTE)
			{
				goto err;
			}
			prf_type = PRF_HMAC_SHA256;
			break;
		case DRBG_HMAC_SHA512:
			if (strength > HASH_SIZE_SHA512 * BITS_PER_BYTE)
			{
				goto err;
			}
			prf_type = PRF_HMAC_SHA512;
			break;
		default:
			DBG1(DBG_LIB, "%N not supported", drbg_type_names, type)
			return NULL;
	}

	prf = lib->crypto->create_prf(prf_type);
	if (!prf)
	{
		DBG1(DBG_LIB, "creation of %N for DRBG failed",
			 pseudo_random_function_names, prf_type);
		return NULL;
	}
	*/
	max_requests = lib->settings->get_int(lib->settings,
										  "%s.plugins.drbg.max_drbg_requests",
										  MAX_DRBG_REQUESTS, lib->ns);

	INIT(this,
		.public = {
			.interface = {
				.get_type = _get_type,
				.get_strength = _get_strength,
				.reseed = _reseed,
				.generate = _generate,
				.get_ref = _get_ref,
				.destroy = _destroy,
			},
		},
		.type = type,
		.strength = strength,
		.entropy = entropy,
		/* .key = chunk_alloc(this->get_key_size(prf)), */
		/* .value = chunk_alloc(ctr->get_block_size(prf)), */
		.max_requests = max_requests,
		.reseed_counter = 1,
		.ref = 1,
	);

	return &this->public;
}
