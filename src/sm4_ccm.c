/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <gmssl/sm4.h>
#include <gmssl/mem.h>
#include <gmssl/sm4_cbc_mac.h>
#include <gmssl/error.h>


static void length_to_bytes(size_t len, size_t nbytes, uint8_t *out)
{
	uint8_t *p = out + nbytes - 1;
	while (nbytes--) {
		*p-- = len & 0xff;
		len >>= 8;
	}
}

static void ctr_n_incr(uint8_t a[16], size_t n)
{
	size_t i;
	for (i = 15; i >= 16 - n; i--) {
		a[i]++;
		if (a[i]) break;
	}
}

// TODO: add test vectors for counter overflow
static void sm4_ctr_n_encrypt(const SM4_KEY *key, uint8_t ctr[16], size_t n, const uint8_t *in, size_t inlen, uint8_t *out)
{
	uint8_t block[16];
	size_t len;

	while (inlen) {
		len = inlen < 16 ? inlen : 16;
		sm4_encrypt(key, ctr, block);
		gmssl_memxor(out, in, block, len);
		ctr_n_incr(ctr, n);
		in += len;
		out += len;
		inlen -= len;
	}
}

int sm4_ccm_encrypt(const SM4_KEY *sm4_key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	uint8_t *out, size_t taglen, uint8_t *tag)
{
	SM4_CBC_MAC_CTX mac_ctx;
	const uint8_t zeros[16] = {0};
	uint8_t block[16] = {0};
	uint8_t ctr[16] = {0};
	uint8_t mac[16];
	size_t inlen_size;

	if (ivlen < 7 || ivlen > 13) {
		error_print();
		return -1;
	}
	if (!aad && aadlen) {
		error_print();
		return -1;
	}
	if (taglen < 4 || taglen > 16 || taglen & 1) {
		error_print();
		return -1;
	}

	inlen_size = 15 - ivlen;
	if (inlen_size < 8 && inlen >= ((size_t)1 << (inlen_size * 8))) {
		error_print();
		return -1;
	}

	// sm4_cbc_mac_init with SM4_KEY
	memset(&mac_ctx, 0, sizeof(mac_ctx));
	mac_ctx.key = *sm4_key;

	block[0] |= ((aadlen > 0) & 0x1) << 6;
	block[0] |= (((taglen - 2)/2) & 0x7) << 3;
	block[0] |= (inlen_size - 1) & 0x7;
	memcpy(block + 1, iv, ivlen);
	length_to_bytes(inlen, inlen_size, block + 1 + ivlen);
	sm4_cbc_mac_update(&mac_ctx, block, 16);

	if (aad && aadlen) {
		size_t alen;

		if (aadlen < ((1<<16) - (1<<8))) {
			length_to_bytes(aadlen, 2, block);
			alen = 2;
		} else if ((uint64_t)aadlen < ((uint64_t)1<<32)) {
			block[0] = 0xff;
			block[1] = 0xfe;
			length_to_bytes(aadlen, 4, block + 2);
			alen = 6;
		} else {
			block[0] = 0xff;
			block[1] = 0xff;
			length_to_bytes(aadlen, 8, block + 2);
			alen = 10;
		}
		sm4_cbc_mac_update(&mac_ctx, block, alen);
		sm4_cbc_mac_update(&mac_ctx, aad, aadlen);
		if (alen + aadlen % 16) {
			sm4_cbc_mac_update(&mac_ctx, zeros, 16 - (alen + aadlen)%16);
		}
	}

	ctr[0] = 0;
	ctr[0] |= (inlen_size - 1) & 0x7;
	memcpy(ctr + 1, iv, ivlen);
	memset(ctr + 1 + ivlen, 0, 15 - ivlen);
	sm4_encrypt(sm4_key, ctr, block);

	ctr[15] = 1;
	sm4_ctr_n_encrypt(sm4_key, ctr, 15 - ivlen, in, inlen, out);

	sm4_cbc_mac_update(&mac_ctx, in, inlen);
	if (inlen % 16) {
		sm4_cbc_mac_update(&mac_ctx, zeros, 16 - inlen % 16);
	}
	sm4_cbc_mac_finish(&mac_ctx, mac);
	gmssl_memxor(tag, mac, block, taglen);

	gmssl_secure_clear(&mac_ctx, sizeof(mac_ctx));
	return 1;
}

int sm4_ccm_decrypt(const SM4_KEY *sm4_key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	const uint8_t *tag, size_t taglen, uint8_t *out)
{
	SM4_CBC_MAC_CTX mac_ctx;
	const uint8_t zeros[16] = {0};
	uint8_t block[16] = {0};
	uint8_t ctr[16] = {0};
	uint8_t mac[16];
	size_t inlen_size;

	if (ivlen < 7 || ivlen > 13) {
		error_print();
		return -1;
	}
	if (!aad && aadlen) {
		error_print();
		return -1;
	}
	if (taglen < 4 || taglen > 16 || taglen & 1) {
		error_print();
		return -1;
	}

	inlen_size = 15 - ivlen;
	if (inlen_size < 8 && inlen >= ((size_t)1 << (inlen_size * 8))) {
		error_print();
		return -1;
	}

	// sm4_cbc_mac_init with SM4_KEY
	memset(&mac_ctx, 0, sizeof(mac_ctx));
	mac_ctx.key = *sm4_key;

	block[0] |= ((aadlen > 0) & 0x1) << 6;
	block[0] |= (((taglen - 2)/2) & 0x7) << 3;
	block[0] |= (inlen_size - 1) & 0x7;
	memcpy(block + 1, iv, ivlen);
	length_to_bytes(inlen, inlen_size, block + 1 + ivlen);
	sm4_cbc_mac_update(&mac_ctx, block, 16);

	if (aad && aadlen) {
		size_t alen;

		if (aadlen < ((1<<16) - (1<<8))) {
			length_to_bytes(aadlen, 2, block);
			alen = 2;
		} else if ((uint64_t)aadlen < ((uint64_t)1<<32)) {
			block[0] = 0xff;
			block[1] = 0xfe;
			length_to_bytes(aadlen, 4, block + 2);
			alen = 6;
		} else {
			block[0] = 0xff;
			block[1] = 0xff;
			length_to_bytes(aadlen, 8, block + 2);
			alen = 10;
		}
		sm4_cbc_mac_update(&mac_ctx, block, alen);
		sm4_cbc_mac_update(&mac_ctx, aad, aadlen);
		if (alen + aadlen % 16) {
			sm4_cbc_mac_update(&mac_ctx, zeros, 16 - (alen + aadlen)%16);
		}
	}

	ctr[0] = 0;
	ctr[0] |= (inlen_size - 1) & 0x7;
	memcpy(ctr + 1, iv, ivlen);
	memset(ctr + 1 + ivlen, 0, 15 - ivlen);
	sm4_encrypt(sm4_key, ctr, block);

	ctr[15] = 1;
	sm4_ctr_n_encrypt(sm4_key, ctr, 15 - ivlen, in, inlen, out);

	sm4_cbc_mac_update(&mac_ctx, out, inlen); // diff from encrypt
	if (inlen % 16) {
		sm4_cbc_mac_update(&mac_ctx, zeros, 16 - inlen % 16);
	}
	sm4_cbc_mac_finish(&mac_ctx, mac);

	// diff from encrypt
	gmssl_memxor(mac, mac, block, taglen);
	if (memcmp(mac, tag, taglen) != 0) {
		error_print();
		gmssl_secure_clear(&mac_ctx, sizeof(mac_ctx));
		return -1;
	}

	gmssl_secure_clear(&mac_ctx, sizeof(mac_ctx));
	return 1;
}
