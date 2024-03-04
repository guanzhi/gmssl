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
#include <gmssl/error.h>


void sm4_ecb_encrypt(const SM4_KEY *key, const uint8_t *in, size_t nblocks, uint8_t *out)
{
	while (nblocks--) {
		sm4_encrypt(key, in, out);
		in += SM4_BLOCK_SIZE;
		out += SM4_BLOCK_SIZE;
	}
}

int sm4_ecb_padding_encrypt(const SM4_KEY *key,
    const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	uint8_t block[16];
	size_t rem = inlen % 16;
	int padding = 16 - inlen % 16;

	if (in) {
		memcpy(block, in + inlen - rem, rem);
	}
	memset(block + rem, padding, padding);
	if (inlen/16) {
		sm4_ecb_encrypt(key, in, inlen/16, out);
		out += inlen - rem;
	}
	sm4_ecb_encrypt(key, block, 1, out);
	*outlen = inlen - rem + 16;
	return 1;
}

int sm4_ecb_padding_decrypt(const SM4_KEY *key,
    const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	uint8_t block[16];
	size_t len = sizeof(block);
	int padding;

	if (inlen == 0) {
		error_puts("warning: input lenght = 0");
		return 0;
	}
	if (inlen%16 != 0 || inlen < 16) {
		error_puts("invalid ecb ciphertext length");
		return -1;
	}
	if (inlen > 16) {
		sm4_ecb_encrypt(key, in, inlen/16 - 1, out);
	}
	sm4_ecb_encrypt(key, in + inlen - 16, 1, block);

	padding = block[15];
	if (padding < 1 || padding > 16) {
		error_print();
		return -1;
	}
	len -= padding;
	memcpy(out + inlen - 16, block, len);
	*outlen = inlen - padding;
	return 1;
}

int sm4_ecb_encrypt_init(SM4_ECB_CTX *ctx, const uint8_t key[SM4_BLOCK_SIZE])
{
	sm4_set_encrypt_key(&ctx->sm4_key, key);
	memset(ctx->block, 0, SM4_BLOCK_SIZE);
	ctx->block_nbytes = 0;
	return 1;
}

int sm4_ecb_encrypt_update(SM4_ECB_CTX *ctx,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	size_t left;
	size_t nblocks;
	size_t len;

	if (ctx->block_nbytes >= SM4_BLOCK_SIZE) {
		error_print();
		return -1;
	}
	*outlen = 0;
	if (ctx->block_nbytes) {
		left = SM4_BLOCK_SIZE - ctx->block_nbytes;
		if (inlen < left) {
			memcpy(ctx->block + ctx->block_nbytes, in, inlen);
			ctx->block_nbytes += inlen;
			return 1;
		}
		memcpy(ctx->block + ctx->block_nbytes, in, left);
		sm4_ecb_encrypt(&ctx->sm4_key, ctx->block, 1, out);
		in += left;
		inlen -= left;
		out += SM4_BLOCK_SIZE;
		*outlen += SM4_BLOCK_SIZE;
	}
	if (inlen >= SM4_BLOCK_SIZE) {
		nblocks = inlen / SM4_BLOCK_SIZE;
		len = nblocks * SM4_BLOCK_SIZE;
		sm4_ecb_encrypt(&ctx->sm4_key, in, nblocks, out);
		in += len;
		inlen -= len;
		out += len;
		*outlen += len;
	}
	if (inlen) {
		memcpy(ctx->block, in, inlen);
	}
	ctx->block_nbytes = inlen;
	return 1;
}

int sm4_ecb_encrypt_finish(SM4_ECB_CTX *ctx, uint8_t *out, size_t *outlen)
{
	if (ctx->block_nbytes >= SM4_BLOCK_SIZE) {
		error_print();
		return -1;
	}
	if (sm4_ecb_padding_encrypt(&ctx->sm4_key, ctx->block, ctx->block_nbytes, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm4_ecb_decrypt_init(SM4_ECB_CTX *ctx, const uint8_t key[SM4_BLOCK_SIZE])
{
	sm4_set_decrypt_key(&ctx->sm4_key, key);
	memset(ctx->block, 0, SM4_BLOCK_SIZE);
	ctx->block_nbytes = 0;
	return 1;
}

int sm4_ecb_decrypt_update(SM4_ECB_CTX *ctx,
    const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	size_t left, len, nblocks;

	if (ctx->block_nbytes > SM4_BLOCK_SIZE) {
		error_print();
		return -1;
	}

	*outlen = 0;
	if (ctx->block_nbytes) {
		left = SM4_BLOCK_SIZE - ctx->block_nbytes;
		if (inlen <= left) {
			memcpy(ctx->block + ctx->block_nbytes, in, inlen);
			ctx->block_nbytes += inlen;
			return 1;
		}
		memcpy(ctx->block + ctx->block_nbytes, in, left);
		sm4_ecb_encrypt(&ctx->sm4_key, ctx->block, 1, out);
		in += left;
		inlen -= left;
		out += SM4_BLOCK_SIZE;
		*outlen += SM4_BLOCK_SIZE;
	}
	if (inlen > SM4_BLOCK_SIZE) {
		nblocks = (inlen-1) / SM4_BLOCK_SIZE;
		len = nblocks * SM4_BLOCK_SIZE;
		sm4_ecb_encrypt(&ctx->sm4_key, in, nblocks, out);
		in += len;
		inlen -= len;
		out += len;
		*outlen += len;
	}
	memcpy(ctx->block, in, inlen);
	ctx->block_nbytes = inlen;
	return 1;
}

int sm4_ecb_decrypt_finish(SM4_ECB_CTX *ctx, uint8_t *out, size_t *outlen)
{
	if (ctx->block_nbytes != SM4_BLOCK_SIZE) {
		error_print();
		return -1;
	}
	if (sm4_ecb_padding_decrypt(&ctx->sm4_key, ctx->block, SM4_BLOCK_SIZE, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}
