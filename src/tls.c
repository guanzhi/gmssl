/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#include <time.h>
#include <stdio.h>
#include <fcntl.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <gmssl/rand.h>
#include <gmssl/x509.h>
#include <gmssl/error.h>
#include <gmssl/mem.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/pem.h>
#include <gmssl/tls.h>


void tls_uint8_to_bytes(uint8_t a, uint8_t **out, size_t *outlen)
{
	if (out && *out) {
		*(*out)++ = a;
	}
	(*outlen)++;
}

void tls_uint16_to_bytes(uint16_t a, uint8_t **out, size_t *outlen)
{
	if (out && *out) {
		*(*out)++ = (uint8_t)(a >> 8);
		*(*out)++ = (uint8_t)a;
	}
	*outlen += 2;
}

void tls_uint24_to_bytes(uint24_t a, uint8_t **out, size_t *outlen)
{
	if (out && *out) {
		*(*out)++ = (uint8_t)(a >> 16);
		*(*out)++ = (uint8_t)(a >> 8);
		*(*out)++ = (uint8_t)(a);
	}
	(*outlen) += 3;
}

void tls_uint32_to_bytes(uint32_t a, uint8_t **out, size_t *outlen)
{
	if (out && *out) {
		*(*out)++ = (uint8_t)(a >> 24);
		*(*out)++ = (uint8_t)(a >> 16);
		*(*out)++ = (uint8_t)(a >>  8);
		*(*out)++ = (uint8_t)(a      );
	}
	(*outlen) += 4;
}

void tls_array_to_bytes(const uint8_t *data, size_t datalen, uint8_t **out, size_t *outlen)
{
	if (out && *out) {
		if (data) {
			memcpy(*out, data, datalen);
		}
		*out += datalen;
	}
	*outlen += datalen;
}

/*
这几个函数要区分data = NULL, datalen = 0 和 data = NULL, datalen != 0的情况
前者意味着数据为空，因此输出的就是一个长度
后者意味着数据不为空，只是我们不想输出数据，只输出头部的长度，并且更新整个的输出长度。 这种情况应该避免！

*/

void tls_uint8array_to_bytes(const uint8_t *data, size_t datalen, uint8_t **out, size_t *outlen)
{
	tls_uint8_to_bytes((uint8_t)datalen, out, outlen);
	tls_array_to_bytes(data, datalen, out, outlen);
}

void tls_uint16array_to_bytes(const uint8_t *data, size_t datalen, uint8_t **out, size_t *outlen)
{
	tls_uint16_to_bytes((uint16_t)datalen, out, outlen);
	tls_array_to_bytes(data, datalen, out, outlen);
}

void tls_uint24array_to_bytes(const uint8_t *data, size_t datalen, uint8_t **out, size_t *outlen)
{
	tls_uint24_to_bytes((uint24_t)datalen, out, outlen);
	tls_array_to_bytes(data, datalen, out, outlen);
}

int tls_uint8_from_bytes(uint8_t *a, const uint8_t **in, size_t *inlen)
{
	if (*inlen < 1) {
		error_print();
		return -1;
	}
	*a = *(*in)++;
	(*inlen)--;
	return 1;
}

int tls_uint16_from_bytes(uint16_t *a, const uint8_t **in, size_t *inlen)
{
	if (*inlen < 2) {
		error_print();
		return -1;
	}
	*a = *(*in)++;
	*a <<= 8;
	*a |= *(*in)++;
	*inlen -= 2;
	return 1;
}

int tls_uint24_from_bytes(uint24_t *a, const uint8_t **in, size_t *inlen)
{
	if (*inlen < 3) {
		error_print();
		return -1;
	}
	*a = *(*in)++;
	*a <<= 8;
	*a |= *(*in)++;
	*a <<= 8;
	*a |= *(*in)++;
	*inlen -= 3;
	return 1;
}

int tls_uint32_from_bytes(uint32_t *a, const uint8_t **in, size_t *inlen)
{
	if (*inlen < 4) {
		error_print();
		return -1;
	}
	*a = *(*in)++;
	*a <<= 8;
	*a |= *(*in)++;
	*a <<= 8;
	*a |= *(*in)++;
	*a <<= 8;
	*a |= *(*in)++;
	*inlen -= 4;
	return 1;
}

int tls_array_from_bytes(const uint8_t **data, size_t datalen, const uint8_t **in, size_t *inlen)
{
	if (*inlen < datalen) {
		error_print();
		return -1;
	}
	*data = *in;
	*in += datalen;
	*inlen -= datalen;
	return 1;
}

int tls_uint8array_from_bytes(const uint8_t **data, size_t *datalen, const uint8_t **in, size_t *inlen)
{
	uint8_t len;
	if (tls_uint8_from_bytes(&len, in, inlen) != 1
		|| tls_array_from_bytes(data, len, in, inlen) != 1) {
		error_print();
		return -1;
	}
	if (!len) {
		*data = NULL;
	}
	*datalen = len;
	return 1;
}

int tls_uint16array_from_bytes(const uint8_t **data, size_t *datalen, const uint8_t **in, size_t *inlen)
{
	uint16_t len;
	if (tls_uint16_from_bytes(&len, in, inlen) != 1
		|| tls_array_from_bytes(data, len, in, inlen) != 1) {
		error_print();
		return -1;
	}
	if (!len) {
		*data = NULL;
	}
	*datalen = len;
	return 1;
}

int tls_uint24array_from_bytes(const uint8_t **data, size_t *datalen, const uint8_t **in, size_t *inlen)
{
	uint24_t len;
	if (tls_uint24_from_bytes(&len, in, inlen) != 1
		|| tls_array_from_bytes(data, len, in, inlen) != 1) {
		error_print();
		return -1;
	}
	if (!len) {
		*data = NULL;
	}
	*datalen = len;
	return 1;
}

int tls_length_is_zero(size_t len)
{
	if (len) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_record_set_type(uint8_t *record, int type)
{
	if (!tls_record_type_name(type)) {
		error_print();
		return -1;
	}
	record[0] = (uint8_t)type;
	return 1;
}

int tls_record_set_protocol(uint8_t *record, int protocol)
{
	if (!tls_protocol_name(protocol)) {
		error_print();
		return -1;
	}
	record[1] = (uint8_t)(protocol >> 8);
	record[2] = (uint8_t)(protocol);
	return 1;
}

int tls_record_set_length(uint8_t *record, size_t length)
{
	uint8_t *p = record + 3;
	size_t len;
	if (length > TLS_MAX_CIPHERTEXT_SIZE) {
		error_print();
		return -1;
	}
	tls_uint16_to_bytes((uint16_t)length, &p, &len);
	return 1;
}

int tls_record_set_data(uint8_t *record, const uint8_t *data, size_t datalen)
{
	if (tls_record_set_length(record, datalen) != 1) {
		error_print();
		return -1;
	}
	memcpy(tls_record_data(record), data, datalen);
	return 1;
}

int tls_cbc_encrypt(const SM3_HMAC_CTX *inited_hmac_ctx, const SM4_KEY *enc_key,
	const uint8_t seq_num[8], const uint8_t header[5],
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	SM3_HMAC_CTX hmac_ctx;
	uint8_t last_blocks[32 + 16] = {0};
	uint8_t iv[16];
	uint8_t *mac, *padding;
	int rem, padding_len;
	int i;

	if (!inited_hmac_ctx || !enc_key || !seq_num || !header || (!in && inlen) || !out || !outlen) {
		error_print();
		return -1;
	}
	if (inlen > (1 << 14)) {
		error_print_msg("invalid tls record data length %zu\n", inlen);
		return -1;
	}
	if ((((size_t)header[3]) << 8) + header[4] != inlen) {
		error_print();
		return -1;
	}

	rem = (inlen + 32) % 16;
	memcpy(last_blocks, in + inlen - rem, rem);
	mac = last_blocks + rem;

	memcpy(&hmac_ctx, inited_hmac_ctx, sizeof(SM3_HMAC_CTX));
	sm3_hmac_update(&hmac_ctx, seq_num, 8);
	sm3_hmac_update(&hmac_ctx, header, 5);
	sm3_hmac_update(&hmac_ctx, in, inlen);
	sm3_hmac_finish(&hmac_ctx, mac);

	padding = mac + 32;
	padding_len = 16 - rem - 1;
	for (i = 0; i <= padding_len; i++) {
		padding[i] = (uint8_t)padding_len;
	}

	if (rand_bytes(iv, 16) != 1) {
		error_print();
		return -1;
	}
	memcpy(out, iv, 16);
	out += 16;

	if (inlen >= 16) {
		sm4_cbc_encrypt_blocks(enc_key, iv, in, inlen/16, out);
		out += inlen - rem;
	}
	sm4_cbc_encrypt_blocks(enc_key, iv, last_blocks, sizeof(last_blocks)/16, out);
	*outlen = 16 + inlen - rem + sizeof(last_blocks);
	return 1;
}

int tls_cbc_decrypt(const SM3_HMAC_CTX *inited_hmac_ctx, const SM4_KEY *dec_key,
	const uint8_t seq_num[8], const uint8_t enced_header[5],
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	SM3_HMAC_CTX hmac_ctx;
	uint8_t iv[16];
	const uint8_t *padding;
	const uint8_t *mac;
	uint8_t header[5];
	int padding_len;
	uint8_t hmac[32];
	int i;

	if (!inited_hmac_ctx || !dec_key || !seq_num || !enced_header || !in || !inlen || !out || !outlen) {
		error_print();
		return -1;
	}
	if (inlen % 16
		|| inlen < (16 + 0 + 32 + 16) // iv + data +  mac + padding
		|| inlen > (16 + (1<<14) + 32 + 256)) {
		error_print_msg("invalid tls cbc ciphertext length %zu\n", inlen);
		return -1;
	}

	memcpy(iv, in, 16);
	in += 16;
	inlen -= 16;

	sm4_cbc_decrypt_blocks(dec_key, iv, in, inlen/16, out);

	padding_len = out[inlen - 1];
	padding = out + inlen - padding_len - 1;
	if (padding < out + 32) {
		error_print();
		return -1;
	}
	for (i = 0; i < padding_len; i++) {
		if (padding[i] != padding_len) {
			error_puts("tls ciphertext cbc-padding check failure");
			return -1;
		}
	}

	*outlen = inlen - 32 - padding_len - 1;

	header[0] = enced_header[0];
	header[1] = enced_header[1];
	header[2] = enced_header[2];
	header[3] = (uint8_t)((*outlen) >> 8);
	header[4] = (uint8_t)(*outlen);
	mac = padding - 32;

	memcpy(&hmac_ctx, inited_hmac_ctx, sizeof(SM3_HMAC_CTX));
	sm3_hmac_update(&hmac_ctx, seq_num, 8);
	sm3_hmac_update(&hmac_ctx, header, 5);
	sm3_hmac_update(&hmac_ctx, out, *outlen);
	sm3_hmac_finish(&hmac_ctx, hmac);
	if (gmssl_secure_memcmp(mac, hmac, sizeof(hmac)) != 0) {
		error_puts("tls ciphertext mac check failure\n");
		return -1;
	}
	return 1;
}

int tls_record_encrypt(const SM3_HMAC_CTX *hmac_ctx, const SM4_KEY *cbc_key,
	const uint8_t seq_num[8], const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen)
{
	if (tls_cbc_encrypt(hmac_ctx, cbc_key, seq_num, in,
		in + 5, inlen - 5,
		out + 5, outlen) != 1) {
		error_print();
		return -1;
	}

	out[0] = in[0];
	out[1] = in[1];
	out[2] = in[2];
	out[3] = (uint8_t)((*outlen) >> 8);
	out[4] = (uint8_t)(*outlen);
	(*outlen) += 5;
	return 1;
}

int tls_record_decrypt(const SM3_HMAC_CTX *hmac_ctx, const SM4_KEY *cbc_key,
	const uint8_t seq_num[8], const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen)
{
	if (tls_cbc_decrypt(hmac_ctx, cbc_key, seq_num, in,
		in + 5, inlen - 5,
		out + 5, outlen) != 1) {
		error_print();
		return -1;
	}

	out[0] = in[0];
	out[1] = in[1];
	out[2] = in[2];
	out[3] = (uint8_t)((*outlen) >> 8);
	out[4] = (uint8_t)(*outlen);
	(*outlen) += 5;

	return 1;
}

int tls_random_generate(uint8_t random[32])
{
	uint32_t gmt_unix_time = (uint32_t)time(NULL);
	uint8_t *p = random;
	size_t len = 0;
	tls_uint32_to_bytes(gmt_unix_time, &p, &len);
	if (rand_bytes(random + 4, 28) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_prf(const uint8_t *secret, size_t secretlen, const char *label,
	const uint8_t *seed, size_t seedlen,
	const uint8_t *more, size_t morelen,
	size_t outlen, uint8_t *out)
{
	SM3_HMAC_CTX inited_hmac_ctx;
	SM3_HMAC_CTX hmac_ctx;
	uint8_t A[32];
	uint8_t hmac[32];
	size_t len;

	if (!secret || !secretlen || !label || !seed || !seedlen
		|| (!more && morelen) || !outlen || !out) {
		error_print();
		return -1;
	}

	sm3_hmac_init(&inited_hmac_ctx, secret, secretlen);

	memcpy(&hmac_ctx, &inited_hmac_ctx, sizeof(SM3_HMAC_CTX));
	sm3_hmac_update(&hmac_ctx, (uint8_t *)label, strlen(label));
	sm3_hmac_update(&hmac_ctx, seed, seedlen);
	sm3_hmac_update(&hmac_ctx, more, morelen);
	sm3_hmac_finish(&hmac_ctx, A);

	memcpy(&hmac_ctx, &inited_hmac_ctx, sizeof(SM3_HMAC_CTX));
	sm3_hmac_update(&hmac_ctx, A, sizeof(A));
	sm3_hmac_update(&hmac_ctx, (uint8_t *)label, strlen(label));
	sm3_hmac_update(&hmac_ctx, seed, seedlen);
	sm3_hmac_update(&hmac_ctx, more, morelen);
	sm3_hmac_finish(&hmac_ctx, hmac);

	len = outlen < sizeof(hmac) ? outlen : sizeof(hmac);
	memcpy(out, hmac, len);
	out += len;
	outlen -= len;

	while (outlen) {
		memcpy(&hmac_ctx, &inited_hmac_ctx, sizeof(SM3_HMAC_CTX));
		sm3_hmac_update(&hmac_ctx, A, sizeof(A));
		sm3_hmac_finish(&hmac_ctx, A);

		memcpy(&hmac_ctx, &inited_hmac_ctx, sizeof(SM3_HMAC_CTX));
		sm3_hmac_update(&hmac_ctx, A, sizeof(A));
		sm3_hmac_update(&hmac_ctx, (uint8_t *)label, strlen(label));
		sm3_hmac_update(&hmac_ctx, seed, seedlen);
		sm3_hmac_update(&hmac_ctx, more, morelen);
		sm3_hmac_finish(&hmac_ctx, hmac);

		len = outlen < sizeof(hmac) ? outlen : sizeof(hmac);
		memcpy(out, hmac, len);
		out += len;
		outlen -= len;
	}
	return 1;
}

int tls_pre_master_secret_generate(uint8_t pre_master_secret[48], int protocol)
{
	if (!tls_protocol_name(protocol)) {
		error_print();
		return -1;
	}
	pre_master_secret[0] = (uint8_t)(protocol >> 8);
	pre_master_secret[1] = (uint8_t)(protocol);
	if (rand_bytes(pre_master_secret + 2, 46) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

// 用于设置CertificateRequest
int tls_cert_type_from_oid(int oid)
{
	switch (oid) {
	case OID_sm2sign_with_sm3:
	case OID_ecdsa_with_sha1:
	case OID_ecdsa_with_sha224:
	case OID_ecdsa_with_sha256:
	case OID_ecdsa_with_sha512:
		return TLS_cert_type_ecdsa_sign;
	case OID_rsasign_with_sm3:
	case OID_rsasign_with_md5:
	case OID_rsasign_with_sha1:
	case OID_rsasign_with_sha224:
	case OID_rsasign_with_sha256:
	case OID_rsasign_with_sha384:
	case OID_rsasign_with_sha512:
		return TLS_cert_type_rsa_sign;
	}
	// TLS_cert_type_xxx 中没有为0的值
	return 0;
}

// 这两个函数没有对应的TLCP版本
int tls_sign_server_ecdh_params(const SM2_KEY *server_sign_key,
	const uint8_t client_random[32], const uint8_t server_random[32],
	int curve, const SM2_Z256_POINT *point, uint8_t *sig, size_t *siglen)
{
	uint8_t server_ecdh_params[69];
	SM2_SIGN_CTX sign_ctx;

	if (!server_sign_key || !client_random || !server_random
		|| curve != TLS_curve_sm2p256v1 || !point || !sig || !siglen) {
		error_print();
		return -1;
	}
	server_ecdh_params[0] = TLS_curve_type_named_curve;
	server_ecdh_params[1] = (uint8_t)(curve >> 8);
	server_ecdh_params[2] = (uint8_t)curve;
	server_ecdh_params[3] = 65;
	sm2_z256_point_to_uncompressed_octets(point, server_ecdh_params + 4);

	sm2_sign_init(&sign_ctx, server_sign_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH);
	sm2_sign_update(&sign_ctx, client_random, 32);
	sm2_sign_update(&sign_ctx, server_random, 32);
	sm2_sign_update(&sign_ctx, server_ecdh_params, 69);
	sm2_sign_finish(&sign_ctx, sig, siglen);

	return 1;
}

int tls_verify_server_ecdh_params(const SM2_KEY *server_sign_key,
	const uint8_t client_random[32], const uint8_t server_random[32],
	int curve, const SM2_Z256_POINT *point, const uint8_t *sig, size_t siglen)
{
	int ret;
	uint8_t server_ecdh_params[69];
	SM2_VERIFY_CTX verify_ctx;

	if (!server_sign_key || !client_random || !server_random
		|| curve != TLS_curve_sm2p256v1 || !point || !sig || !siglen
		|| siglen > SM2_MAX_SIGNATURE_SIZE) {
		error_print();
		return -1;
	}
	server_ecdh_params[0] = TLS_curve_type_named_curve;
	server_ecdh_params[1] = (uint8_t)(curve >> 8);
	server_ecdh_params[2] = (uint8_t)(curve);
	server_ecdh_params[3] = 65;
	sm2_z256_point_to_uncompressed_octets(point, server_ecdh_params + 4);

	sm2_verify_init(&verify_ctx, server_sign_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH);
	sm2_verify_update(&verify_ctx, client_random, 32);
	sm2_verify_update(&verify_ctx, server_random, 32);
	sm2_verify_update(&verify_ctx, server_ecdh_params, 69);
	ret = sm2_verify_finish(&verify_ctx, sig, siglen);
	if (ret != 1) error_print();
	return ret;
}

int tls_record_set_handshake(uint8_t *record, size_t *recordlen,
	int type, const uint8_t *data, size_t datalen)
{
	size_t handshakelen;

	if (!record || !recordlen) {
		error_print();
		return -1;
	}
	// 由于ServerHelloDone没有负载数据，因此允许 data,datalen = NULL,0
	if (datalen > TLS_MAX_PLAINTEXT_SIZE - TLS_HANDSHAKE_HEADER_SIZE) {
		error_print();
		return -1;
	}
	if (!tls_protocol_name(tls_record_protocol(record))) {
		error_print();
		return -1;
	}
	if (!tls_handshake_type_name(type)) {
		error_print();
		return -1;
	}
	handshakelen = TLS_HANDSHAKE_HEADER_SIZE + datalen;
	record[0] = TLS_record_handshake;
	record[3] = (uint8_t)(handshakelen >> 8);
	record[4] = (uint8_t)(handshakelen);
	record[5] = (uint8_t)(type);
	record[6] = (uint8_t)(datalen >> 16);
	record[7] = (uint8_t)(datalen >> 8);
	record[8] = (uint8_t)(datalen);
	if (data) {
		memcpy(tls_handshake_data(tls_record_data(record)), data, datalen);
	}
	*recordlen = TLS_RECORD_HEADER_SIZE + handshakelen;
	return 1;
}

int tls_record_get_handshake(const uint8_t *record,
	int *type, const uint8_t **data, size_t *datalen)
{
	const uint8_t *handshake;
	size_t handshake_len;
	uint24_t handshake_datalen;

	if (!record || !type || !data || !datalen) {
		error_print();
		return -1;
	}
	if (!tls_protocol_name(tls_record_protocol(record))) {
		error_print();
		return -1;
	}
	if (tls_record_type(record) != TLS_record_handshake) {
		error_print();
		return -1;
	}
	handshake = tls_record_data(record);
	handshake_len = tls_record_data_length(record);

	if (handshake_len < TLS_HANDSHAKE_HEADER_SIZE) {
		error_print();
		return -1;
	}
	if (handshake_len > TLS_MAX_PLAINTEXT_SIZE) {
		// 不支持证书长度超过记录长度的特殊情况
		error_print();
		return -1;
	}

	if (!tls_handshake_type_name(handshake[0])) {
		error_print();
		return -1;
	}
	*type = handshake[0];

	handshake++;
	handshake_len--;
	if (tls_uint24_from_bytes(&handshake_datalen, &handshake, &handshake_len) != 1) {
		error_print();
		return -1;
	}
	if (handshake_len != handshake_datalen) {
		error_print();
		return -1;
	}
	*data = handshake;
	*datalen = handshake_datalen;

	if (*datalen == 0) {
		*data = NULL;
	}
	return 1;
}

int tls_record_set_handshake_client_hello(uint8_t *record, size_t *recordlen,
	int protocol, const uint8_t random[32],
	const uint8_t *session_id, size_t session_id_len,
	const int *cipher_suites, size_t cipher_suites_count,
	const uint8_t *exts, size_t exts_len)
{
	uint8_t type = TLS_handshake_client_hello;
	uint8_t *p;
	size_t len;

	if (!record || !recordlen || !random || !cipher_suites || !cipher_suites_count) {
		error_print();
		return -1;
	}
	if (session_id) {
		if (!session_id_len
			|| session_id_len < TLS_MAX_SESSION_ID_SIZE
			|| session_id_len > TLS_MAX_SESSION_ID_SIZE) {
			error_print();
			return -1;
		}
	}
	if (cipher_suites_count > TLS_MAX_CIPHER_SUITES_COUNT) {
		error_print();
		return -1;
	}
	if (exts && !exts_len) {
		error_print();
		return -1;
	}


	p = tls_handshake_data(tls_record_data(record));
	len = 0;

	if (!tls_protocol_name(protocol)) {
		error_print();
		return -1;
	}
	tls_uint16_to_bytes((uint16_t)protocol, &p, &len);
	tls_array_to_bytes(random, 32, &p, &len);
	tls_uint8array_to_bytes(session_id, session_id_len, &p, &len);
	tls_uint16_to_bytes((uint16_t)(cipher_suites_count * 2), &p, &len);
	while (cipher_suites_count--) {
		if (!tls_cipher_suite_name(*cipher_suites)) {
			error_print();
			return -1;
		}
		tls_uint16_to_bytes((uint16_t)*cipher_suites, &p, &len);
		cipher_suites++;
	}
	tls_uint8_to_bytes(1, &p, &len);
	tls_uint8_to_bytes((uint8_t)TLS_compression_null, &p, &len);
	if (exts) {
		size_t tmp_len = len;
		if (protocol < TLS_protocol_tls12) {
			error_print();
			return -1;
		}
		tls_uint16array_to_bytes(exts, exts_len, NULL, &tmp_len);
		if (tmp_len > TLS_MAX_HANDSHAKE_DATA_SIZE) {
			error_print();
			return -1;
		}
		tls_uint16array_to_bytes(exts, exts_len, &p, &len);
	}
	if (tls_record_set_handshake(record, recordlen, type, NULL, len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_record_get_handshake_client_hello(const uint8_t *record,
	int *protocol, const uint8_t **random,
	const uint8_t **session_id, size_t *session_id_len,
	const uint8_t **cipher_suites, size_t *cipher_suites_len,
	const uint8_t **exts, size_t *exts_len)
{
	int type;
	const uint8_t *p;
	size_t len;
	uint16_t ver;
	const uint8_t *comp_meths;
	size_t comp_meths_len;

	if (!record || !protocol || !random
		|| !session_id || !session_id_len
		|| !cipher_suites || !cipher_suites_len
		|| !exts || !exts_len) {
		error_print();
		return -1;
	}
	if (tls_record_get_handshake(record, &type, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (type != TLS_handshake_client_hello) {
		error_print();
		return -1;
	}
	if (tls_uint16_from_bytes(&ver, &p, &len) != 1
		|| tls_array_from_bytes(random, 32, &p, &len) != 1
		|| tls_uint8array_from_bytes(session_id, session_id_len, &p, &len) != 1
		|| tls_uint16array_from_bytes(cipher_suites, cipher_suites_len, &p, &len) != 1
		|| tls_uint8array_from_bytes(&comp_meths, &comp_meths_len, &p, &len) != 1) {
		error_print();
		return -1;
	}

	if (!tls_protocol_name(ver)) {
		error_print();
		return -1;
	}
	*protocol = ver;

	if (*session_id) {
		if (*session_id_len == 0
			|| *session_id_len < TLS_MIN_SESSION_ID_SIZE
			|| *session_id_len > TLS_MAX_SESSION_ID_SIZE) {
			error_print();
			return -1;
		}
	}

	if (!cipher_suites) {
		error_print();
		return -1;
	}
	if (*cipher_suites_len % 2) {
		error_print();
		return -1;
	}

	if (len) {
		if (tls_uint16array_from_bytes(exts, exts_len, &p, &len) != 1) {
			error_print();
			return -1;
		}
		if (*exts == NULL) {
			error_print();
			return -1;
		}
	} else {
		*exts = NULL;
		*exts_len = 0;
	}
	if (len) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_record_set_handshake_server_hello(uint8_t *record, size_t *recordlen,
	int protocol, const uint8_t random[32],
	const uint8_t *session_id, size_t session_id_len, int cipher_suite,
	const uint8_t *exts, size_t exts_len)
{
	uint8_t type = TLS_handshake_server_hello;
	uint8_t *p;
	size_t len;

	if (!record || !recordlen || !random) {
		error_print();
		return -1;
	}
	if (session_id) {
		if (session_id_len == 0
			|| session_id_len < TLS_MIN_SESSION_ID_SIZE
			|| session_id_len > TLS_MAX_SESSION_ID_SIZE) {
			error_print();
			return -1;
		}
	}
	if (!tls_protocol_name(protocol)) {
		error_print();
		return -1;
	}
	if (!tls_cipher_suite_name(cipher_suite)) {
		error_print();
		return -1;
	}

	p = tls_handshake_data(tls_record_data(record));
	len = 0;

	tls_uint16_to_bytes((uint16_t)protocol, &p, &len);
	tls_array_to_bytes(random, 32, &p, &len);
	tls_uint8array_to_bytes(session_id, session_id_len, &p, &len);
	tls_uint16_to_bytes((uint16_t)cipher_suite, &p, &len);
	tls_uint8_to_bytes((uint8_t)TLS_compression_null, &p, &len);
	if (exts) {
		if (protocol < TLS_protocol_tls12) {
			error_print();
			return -1;
		}
		tls_uint16array_to_bytes(exts, exts_len, &p, &len);
	}
	if (tls_record_set_handshake(record, recordlen, type, NULL, len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_record_get_handshake_server_hello(const uint8_t *record,
	int *protocol, const uint8_t **random, const uint8_t **session_id, size_t *session_id_len,
	int *cipher_suite, const uint8_t **exts, size_t *exts_len)
{
	int type;
	const uint8_t *p;
	size_t len;
	uint16_t ver;
	uint16_t cipher;
	uint8_t comp_meth;

	if (!record || !protocol || !random || !session_id || !session_id_len
		|| !cipher_suite || !exts || !exts_len) {
		error_print();
		return -1;
	}
	if (tls_record_get_handshake(record, &type, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (type != TLS_handshake_server_hello) {
		error_print();
		return -1;
	}
	if (tls_uint16_from_bytes(&ver, &p, &len) != 1
		|| tls_array_from_bytes(random, 32, &p, &len) != 1
		|| tls_uint8array_from_bytes(session_id, session_id_len, &p, &len) != 1
		|| tls_uint16_from_bytes(&cipher, &p, &len) != 1
		|| tls_uint8_from_bytes(&comp_meth, &p, &len) != 1) {
		error_print();
		return -1;
	}

	if (!tls_protocol_name(ver)) {
		error_print();
		return -1;
	}
	if (ver < tls_record_protocol(record)) {
		error_print();
		return -1;
	}
	*protocol = ver;

	if (*session_id) {
		if (*session_id == 0
			|| *session_id_len < TLS_MIN_SESSION_ID_SIZE
			|| *session_id_len > TLS_MAX_SESSION_ID_SIZE) {
			error_print();
			return -1;
		}
	}

	if (!tls_cipher_suite_name(cipher)) {
		error_print();
		return -1;
	}
	*cipher_suite = cipher;

	if (comp_meth != TLS_compression_null) {
		error_print();
		return -1;
	}

	if (len) {
		if (tls_uint16array_from_bytes(exts, exts_len, &p, &len) != 1) {
			error_print();
			return -1;
		}
		if (*exts == NULL) {
			error_print();
			return -1;
		}
	} else {
		*exts = NULL;
		*exts_len = 0;
	}
	if (len) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_record_set_handshake_certificate(uint8_t *record, size_t *recordlen,
	const uint8_t *certs, size_t certslen)
{
	int type = TLS_handshake_certificate;
	uint8_t *data;
	size_t datalen;
	uint8_t *p;
	size_t len;

	if (!record || !recordlen || !certs || !certslen) {
		error_print();
		return -1;
	}
	data = tls_handshake_data(tls_record_data(record));
	p = data + tls_uint24_size();
	datalen = tls_uint24_size();
	len = 0;

	while (certslen) {
		const uint8_t *cert;
		size_t certlen;

		if (x509_cert_from_der(&cert, &certlen, &certs, &certslen) != 1) {
			error_print();
			return -1;
		}
		tls_uint24array_to_bytes(cert, certlen, NULL, &datalen);
		if (datalen > TLS_MAX_HANDSHAKE_DATA_SIZE) {
			error_print();
			return -1;
		}
		tls_uint24array_to_bytes(cert, certlen, &p, &len);
	}
	tls_uint24_to_bytes((uint24_t)len, &data, &len);
	tls_record_set_handshake(record, recordlen, type, NULL, datalen);
	return 1;
}

int tls_record_get_handshake_certificate(const uint8_t *record, uint8_t *certs, size_t *certslen)
{
	int type;
	const uint8_t *data;
	size_t datalen;
	const uint8_t *cp;
	size_t len;

	if (tls_record_get_handshake(record, &type, &data, &datalen) != 1) {
		error_print();
		return -1;
	}
	if (type != TLS_handshake_certificate) {
		error_print();
		return -1;
	}
	if (tls_uint24array_from_bytes(&cp, &len, &data, &datalen) != 1) {
		error_print();
		return -1;
	}

	*certslen = 0;
	while (len) {
		const uint8_t *a;
		size_t alen;
		const uint8_t *cert;
		size_t certlen;

		if (tls_uint24array_from_bytes(&a, &alen, &cp, &len) != 1) {
			error_print();
			return -1;
		}
		if (x509_cert_from_der(&cert, &certlen, &a, &alen) != 1
			|| asn1_length_is_zero(alen) != 1
			|| x509_cert_to_der(cert, certlen, &certs, certslen) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}

int tls_record_set_handshake_certificate_request(uint8_t *record, size_t *recordlen,
	const uint8_t *cert_types, size_t cert_types_len,
	const uint8_t *ca_names, size_t ca_names_len)
{
	int type = TLS_handshake_certificate_request;
	uint8_t *p;
	size_t len =0;
	size_t datalen = 0;

	if (!record || !recordlen) {
		error_print();
		return -1;
	}
	if (cert_types) {
		if (cert_types_len == 0 || cert_types_len > TLS_MAX_CERTIFICATE_TYPES) {
			error_print();
			return -1;
		}
	}
	if (ca_names) {
		if (ca_names_len == 0 || ca_names_len > TLS_MAX_CA_NAMES_SIZE) {
			error_print();
			return -1;
		}
	}
	tls_uint8array_to_bytes(cert_types, cert_types_len, NULL, &datalen);
	tls_uint16array_to_bytes(ca_names, ca_names_len, NULL, &datalen);
	if (datalen > TLS_MAX_HANDSHAKE_DATA_SIZE) {
		error_print();
		return -1;
	}
	p = tls_handshake_data(tls_record_data(record));
	tls_uint8array_to_bytes(cert_types, cert_types_len, &p, &len);
	tls_uint16array_to_bytes(ca_names, ca_names_len, &p, &len);
	tls_record_set_handshake(record, recordlen, type, NULL, datalen);
	return 1;
}

int tls_record_get_handshake_certificate_request(const uint8_t *record,
	const uint8_t **cert_types, size_t *cert_types_len,
	const uint8_t **ca_names, size_t *ca_names_len)
{
	int type;
	const uint8_t *cp;
	size_t len;
	size_t i;

	if (!record || !cert_types || !cert_types_len || !ca_names || !ca_names_len) {
		error_print();
		return -1;
	}
	if (tls_record_get_handshake(record, &type, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	if (type != TLS_handshake_certificate_request) {
		error_print();
		return -1;
	}
	if (tls_uint8array_from_bytes(cert_types, cert_types_len, &cp, &len) != 1
		|| tls_uint16array_from_bytes(ca_names, ca_names_len, &cp, &len) != 1
		|| tls_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}

	if (*cert_types == NULL) {
		error_print();
		return -1;
	}
	for (i = 0; i < *cert_types_len; i++) {
		if (!tls_cert_type_name((*cert_types)[i])) {
			error_print();
			return -1;
		}
	}
	if (*ca_names) {
		const uint8_t *names = *ca_names;
		size_t nameslen = *ca_names_len;
		while (nameslen) {
			if (tls_uint16array_from_bytes(&cp, &len, &names, &nameslen) != 1) {
				error_print();
				return -1;
			}
		}
	}
	return 1;
}

int tls_record_set_handshake_server_hello_done(uint8_t *record, size_t *recordlen)
{
	int type = TLS_handshake_server_hello_done;
	if (!record || !recordlen) {
		error_print();
		return -1;
	}
	tls_record_set_handshake(record, recordlen, type, NULL, 0);
	return 1;
}

int tls_record_get_handshake_server_hello_done(const uint8_t *record)
{
	int type;
	const uint8_t *p;
	size_t len;

	if (!record) {
		error_print();
		return -1;
	}
	if (tls_record_get_handshake(record, &type, &p, &len) != 1
		|| type != TLS_handshake_server_hello_done) {
		error_print();
		return -1;
	}
	if (p != NULL || len != 0) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_record_set_handshake_client_key_exchange_pke(uint8_t *record, size_t *recordlen,
	const uint8_t *enced_pms, size_t enced_pms_len)
{
	int type = TLS_handshake_client_key_exchange;
	uint8_t *p;
	size_t len = 0;

	if (!record || !recordlen || !enced_pms || !enced_pms_len) {
		error_print();
		return -1;
	}
	if (enced_pms_len > TLS_MAX_HANDSHAKE_DATA_SIZE - tls_uint16_size()) {
		error_print();
		return -1;
	}
	p = tls_handshake_data(tls_record_data(record));
	tls_uint16array_to_bytes(enced_pms, enced_pms_len, &p, &len);
	tls_record_set_handshake(record, recordlen, type, NULL, len);
	return 1;
}

int tls_record_get_handshake_client_key_exchange_pke(const uint8_t *record,
	const uint8_t **enced_pms, size_t *enced_pms_len)
{
	int type;
	const uint8_t *cp;
	size_t len;

	if (!record || !enced_pms || !enced_pms_len) {
		error_print();
		return -1;
	}
	if (tls_record_get_handshake(record, &type, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	if (type != TLS_handshake_client_key_exchange) {
		error_print();
		return -1;
	}
	if (tls_uint16array_from_bytes(enced_pms, enced_pms_len, &cp, &len) != 1
		|| tls_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_record_set_handshake_certificate_verify(uint8_t *record, size_t *recordlen,
	const uint8_t *sig, size_t siglen)
{
	int type = TLS_handshake_certificate_verify;
	uint8_t *p;
	size_t len = 0;

	if (!record || !recordlen || !sig || !siglen) {
		error_print();
		return -1;
	}
	if (siglen > TLS_MAX_SIGNATURE_SIZE) {
		error_print();
		return -1;
	}
	p = tls_handshake_data(tls_record_data(record));
	tls_uint16array_to_bytes(sig, siglen, &p, &len);
	tls_record_set_handshake(record, recordlen, type, NULL, len);
	return 1;
}

int tls_record_get_handshake_certificate_verify(const uint8_t *record,
	const uint8_t **sig, size_t *siglen)
{
	int type;
	const uint8_t *cp;
	size_t len;

	if (!record || !sig || !siglen) {
		error_print();
		return -1;
	}
	if (tls_record_get_handshake(record, &type, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	if (type != TLS_handshake_certificate_verify) {
		error_print();
		return -1;
	}
	if (tls_uint16array_from_bytes(sig, siglen, &cp, &len) != 1
		|| tls_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_record_set_handshake_finished(uint8_t *record, size_t *recordlen,
	const uint8_t *verify_data, size_t verify_data_len)
{
	int type = TLS_handshake_finished;

	if (!record || !recordlen || !verify_data || !verify_data_len) {
		error_print();
		return -1;
	}
	if (verify_data_len != 12 && verify_data_len != 32) {
		error_print();
		return -1;
	}
	tls_record_set_handshake(record, recordlen, type, verify_data, verify_data_len);
	return 1;
}

int tls_record_get_handshake_finished(const uint8_t *record, const uint8_t **verify_data, size_t *verify_data_len)
{
	int type;

	if (!record || !verify_data || !verify_data_len) {
		error_print();
		return -1;
	}
	if (tls_record_get_handshake(record, &type, verify_data, verify_data_len) != 1) {
		error_print();
		return -1;
	}
	if (type != TLS_handshake_finished) {
		error_print();
		return -1;
	}
	if (*verify_data == NULL || *verify_data_len == 0) {
		error_print();
		return -1;
	}
	if (*verify_data_len != 12 && *verify_data_len != 32) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_record_set_alert(uint8_t *record, size_t *recordlen,
	int alert_level,
	int alert_description)
{
	if (!record || !recordlen) {
		error_print();
		return -1;
	}
	if (!tls_alert_level_name(alert_level)) {
		error_print();
		return -1;
	}
	if (!tls_alert_description_text(alert_description)) {
		error_print();
		return -1;
	}
	record[0] = TLS_record_alert;
	//record[1] = protocol.major should be set by others
	//record[2] = protocol.minor should be set by others
	record[3] = 0; // length
	record[4] = 2; // length
	record[5] = (uint8_t)alert_level;
	record[6] = (uint8_t)alert_description;
	*recordlen = TLS_RECORD_HEADER_SIZE + 2;
	return 1;
}

int tls_record_get_alert(const uint8_t *record,
	int *alert_level,
	int *alert_description)
{
	if (!record || !alert_level || !alert_description) {
		error_print();
		return -1;
	}
	if (tls_record_type(record) != TLS_record_alert) {
		error_print();
		return -1;
	}
	if (record[3] != 0 || record[4] != 2) {
		error_print();
		return -1;
	}
	*alert_level = record[5];
	*alert_description = record[6];
	if (!tls_alert_level_name(*alert_level)) {
		error_print();
		return -1;
	}
	if (!tls_alert_description_text(*alert_description)) {
		error_puts("warning");
		return -1;
	}
	return 1;
}

int tls_record_set_change_cipher_spec(uint8_t *record, size_t *recordlen)
{
	if (!record || !recordlen) {
		error_print();
		return -1;
	}
	record[0] = TLS_record_change_cipher_spec;
	record[3] = 0;
	record[4] = 1;
	record[5] = TLS_change_cipher_spec;
	*recordlen = TLS_RECORD_HEADER_SIZE + 1;
	return 1;
}

int tls_record_get_change_cipher_spec(const uint8_t *record)
{
	if (!record) {
		error_print();
		return -1;
	}
	if (tls_record_type(record) != TLS_record_change_cipher_spec) {
		error_print();
		return -1;
	}
	if (record[3] != 0 || record[4] != 1) {
		error_print();
		return -1;
	}
	if (record[5] != TLS_change_cipher_spec) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_record_set_application_data(uint8_t *record, size_t *recordlen,
	const uint8_t *data, size_t datalen)
{
	if (!record || !recordlen || !data || !datalen) {
		error_print();
		return -1;
	}
	record[0] = TLS_record_application_data;
	record[3] = (datalen >> 8) & 0xff;
	record[4] = datalen & 0xff;
	memcpy(tls_record_data(record), data, datalen);
	*recordlen = TLS_RECORD_HEADER_SIZE + datalen;
	return 1;
}

int tls_record_get_application_data(uint8_t *record,
	const uint8_t **data, size_t *datalen)
{
	if (!record || !data || !datalen) {
		error_print();
		return -1;
	}
	if (tls_record_type(record) != TLS_record_application_data) {
		error_print();
		return -1;
	}
	*datalen = ((size_t)record[3] << 8) | record[4];
	*data = *datalen ? record + TLS_RECORD_HEADER_SIZE : 0;
	return 1;
}

int tls_cipher_suite_in_list(int cipher, const int *list, size_t list_count)
{
	size_t i;
	if (!list || !list_count) {
		error_print();
		return -1;
	}
	for (i = 0; i < list_count; i++) {
		if (cipher == list[i]) {
			return 1;
		}
	}
	return 0;
}

int tls_record_send(const uint8_t *record, size_t recordlen, tls_socket_t sock)
{
	tls_ret_t n;

	if (!record) {
		error_print();
		return -1;
	}
	if (recordlen < TLS_RECORD_HEADER_SIZE) {
		error_print();
		return -1;
	}
	if (tls_record_length(record) != recordlen) {
		error_print();
		return -1;
	}

	while (recordlen) {
		if ((n = tls_socket_send(sock, record, recordlen, 0)) > 0) {
			record += n;
			recordlen -= n;

		} else if (n == 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				tls_socket_wait();
			} else {
				error_puts("TCP connection closed");
				return 0;
			}
		} else {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				tls_socket_wait();
			} else {
				error_print();
				return -1;
			}
		}
	}
	return 1;
}

int tls_record_recv(uint8_t *record, size_t *recordlen, tls_socket_t sock)
{
	uint8_t *p = record;
	size_t len;
	tls_ret_t n;

	len = 5;
	while (len) {
		if ((n = tls_socket_recv(sock, p, len, 0)) > 0) {
			p += n;
			len -= n;
		} else if (n == 0) {
			tls_trace("TCP connection closed");
			*recordlen = 0;
			return 0;
		} else {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				if (len == 5) {
					return -EAGAIN;
				}
				tls_socket_wait();
			} else {
				perror("recv");
				error_print();
				return -1;
			}
		}
	}
	if (!tls_record_type_name(tls_record_type(record))) {
		error_print();
		return -1;
	}
	if (!tls_protocol_name(tls_record_protocol(record))) {
		error_print();
		return -1;
	}

	len = (size_t)record[3] << 8 | record[4];

	*recordlen = 5 + len;
	if (*recordlen > TLS_MAX_RECORD_SIZE) {
		error_print();
		return -1;
	}

	while (len) {
		if ((n = tls_socket_recv(sock, p, len, 0)) > 0) {
			p += n;
			len -= n;
		} else if (n == 0) {
			tls_trace("connection closed");
			*recordlen = 0;
			return 0;
		} else {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				tls_socket_wait();
			} else {
				perror("recv");
				error_print();
				return -1;
			}
		}
	}

	return 1;
}

int tls_seq_num_incr(uint8_t seq_num[8])
{
	int i;
	for (i = 7; i > 0; i--) {
		seq_num[i]++;
		if (seq_num[i]) break;
	}
	// FIXME: check overflow
	return 1;
}

int tls_compression_methods_has_null_compression(const uint8_t *meths, size_t methslen)
{
	if (!meths || !methslen) {
		error_print();
		return -1;
	}
	while (methslen--) {
		if (*meths++ == TLS_compression_null) {
			return 1;
		}
	}
	error_print();
	return -1;
}

int tls_send_alert(TLS_CONNECT *conn, int alert)
{
	uint8_t record[5 + 2];
	size_t recordlen;

	if (!conn) {
		error_print();
		return -1;
	}

	tls_record_set_protocol(record, conn->protocol == TLS_protocol_tls13 ? TLS_protocol_tls12 : conn->protocol);
	tls_record_set_alert(record, &recordlen, TLS_alert_level_fatal, alert);

	if (tls_record_send(record, sizeof(record), conn->sock) != 1) {
		error_print();
		return -1;
	}
	tls_record_trace(stderr, record, sizeof(record), 0, 0);
	return 1;
}

int tls_alert_level(int alert)
{
	switch (alert) {
	case TLS_alert_unexpected_message:
	case TLS_alert_bad_record_mac:
	case TLS_alert_record_overflow:
	case TLS_alert_decompression_failure:
	case TLS_alert_handshake_failure:
	case TLS_alert_illegal_parameter:
	case TLS_alert_unknown_ca:
	case TLS_alert_access_denied:
	case TLS_alert_decode_error:
	case TLS_alert_decrypt_error:
	case TLS_alert_protocol_version:
	case TLS_alert_insufficient_security:
	case TLS_alert_internal_error:
	case TLS_alert_unsupported_extension:
		return TLS_alert_level_fatal;
	case TLS_alert_user_canceled:
	case TLS_alert_no_renegotiation:
		return TLS_alert_level_warning;
	}
	return TLS_alert_level_undefined;
}

int tls_send_warning(TLS_CONNECT *conn, int alert)
{
	uint8_t record[5 + 2];
	size_t recordlen;

	if (!conn) {
		error_print();
		return -1;
	}
	if (tls_alert_level(alert) == TLS_alert_level_fatal) {
		error_print();
		return -1;
	}
	tls_record_set_protocol(record, conn->protocol == TLS_protocol_tls13 ? TLS_protocol_tls12 : conn->protocol);
	tls_record_set_alert(record, &recordlen, TLS_alert_level_warning, alert);

	if (tls_record_send(record, sizeof(record), conn->sock) != 1) {
		error_print();
		return -1;
	}
	tls_record_trace(stderr, record, sizeof(record), 0, 0);
	return 1;
}

static int tls_encrypt_send(TLS_CONNECT *conn, int record_type, const uint8_t *in, size_t inlen, size_t *sentlen)
{
	const SM3_HMAC_CTX *hmac_ctx;
	const SM4_KEY *enc_key;
	uint8_t *seq_num;
	size_t recordlen;

	if (!conn) {
		error_print();
		return -1;
	}
	if (!in || !inlen || !sentlen) {
		error_print();
		return -1;
	}

	if (inlen > TLS_MAX_PLAINTEXT_SIZE) {
		inlen = TLS_MAX_PLAINTEXT_SIZE;
	}

	if (conn->datalen) {
		error_puts("recv all buffered data before send");
		return -1;
	}

	if (conn->is_client) {
		hmac_ctx = &conn->client_write_mac_ctx;
		enc_key = &conn->client_write_enc_key;
		seq_num = conn->client_seq_num;
	} else {
		hmac_ctx = &conn->server_write_mac_ctx;
		enc_key = &conn->server_write_enc_key;
		seq_num = conn->server_seq_num;
	}

	if (tls_record_set_type(conn->databuf, record_type) != 1
		|| tls_record_set_protocol(conn->databuf, conn->protocol) != 1
		|| tls_record_set_data(conn->databuf, in, inlen) != 1) {
		error_print();
		return -1;
	}
	tls_record_trace(stderr, conn->databuf, tls_record_length(conn->databuf), 0, 0);

	if (tls_record_encrypt(hmac_ctx, enc_key, seq_num,
		conn->databuf, tls_record_length(conn->databuf),
		conn->record, &recordlen) != 1) {
		error_print();
		return -1;
	}
	tls_seq_num_incr(seq_num);

	if (tls_record_send(conn->record, recordlen, conn->sock) != 1) {
		error_print();
		return -1;
	}
	tls_encrypted_record_trace(stderr, conn->record, recordlen, 0, 0);

	*sentlen = inlen;
	return 1;
}

int tls_decrypt_recv(TLS_CONNECT *conn)
{
	int ret;
	const SM3_HMAC_CTX *hmac_ctx;
	const SM4_KEY *dec_key;
	uint8_t *seq_num;

	uint8_t *record = conn->record;
	size_t recordlen;

	if (conn->is_client) {
		hmac_ctx = &conn->server_write_mac_ctx;
		dec_key = &conn->server_write_enc_key;
		seq_num = conn->server_seq_num;
	} else {
		hmac_ctx = &conn->client_write_mac_ctx;
		dec_key = &conn->client_write_enc_key;
		seq_num = conn->client_seq_num;
	}

	tls_trace("recv Encrypted Record\n");
	if ((ret = tls_record_recv(record, &recordlen, conn->sock)) != 1) {
		if (ret < 0 && ret != -EAGAIN) error_print();
		return ret;
	}
	tls_encrypted_record_trace(stderr, record, recordlen, 0, 0);

	if (tls_record_decrypt(hmac_ctx, dec_key, seq_num,
		record, recordlen,
		conn->databuf, &conn->datalen) != 1) {
		error_print();
		return -1;
	}
	tls_seq_num_incr(seq_num);

	conn->data = tls_record_data(conn->databuf);
	conn->datalen = tls_record_data_length(conn->databuf);

	tls_record_trace(stderr, conn->databuf, tls_record_length(conn->databuf), 0, 0);

	return 1;
}

int tls_send(TLS_CONNECT *conn, const uint8_t *in, size_t inlen, size_t *sentlen)
{
	tls_trace("send ApplicationData\n");
	return tls_encrypt_send(conn, TLS_record_application_data, in, inlen, sentlen);
}

int tls_recv(TLS_CONNECT *conn, uint8_t *out, size_t outlen, size_t *recvlen)
{
	if (!conn || !out || !outlen || !recvlen) {
		error_print();
		return -1;
	}

	if (conn->datalen == 0) {
		int ret;
		if ((ret = tls_decrypt_recv(conn)) != 1) {
			if (ret < 0 && ret != -EAGAIN) error_print();
			return ret;
		}

		switch (tls_record_type(conn->record)) {
		case TLS_record_application_data:
			break;
		case TLS_record_change_cipher_spec:
			error_print();
			return -1;
		case TLS_record_alert:
			{
			// should call tls_process_alert()
			int level;
			int alert;
			tls_record_get_alert(conn->databuf, &level, &alert);
			if (alert == TLS_alert_close_notify) {
				tls_trace("recv Alert.close_notify\n");
				return 0;
			}
			tls_trace("alert received\n");
			return -1;
			}
		default:
			error_print();
			return -1;
		}
	}

	*recvlen = outlen <= conn->datalen ? outlen : conn->datalen;
	memcpy(out, conn->data, *recvlen);
	conn->data += *recvlen;
	conn->datalen -= *recvlen;

	return 1;
}

int tls_shutdown(TLS_CONNECT *conn)
{
	int ret;
	size_t recordlen;
	uint8_t alert[2];
	alert[0] = TLS_alert_level_fatal;
	alert[1] = TLS_alert_close_notify;

	if (!conn) {
		error_print();
		return -1;
	}

	tls_trace("send Alert.close_notify\n");

	if (tls_encrypt_send(conn, TLS_record_alert, alert, sizeof(alert), &recordlen) != 1) {
		error_print();
		return -1;
	}

	tls_trace("recv Alert.close_notify\n");

	if ((ret = tls_decrypt_recv(conn)) != 1) {
		if (ret == 0) tls_trace("Connection closed by remote without close_notify\n");
		else if (ret == -EAGAIN) tls_trace("-EAGAIN\n");
		else error_print();
		return -1;
	}

	return 1;
}

int tls_authorities_from_certs(uint8_t *names, size_t *nameslen, size_t maxlen, const uint8_t *certs, size_t certslen)
{
	const uint8_t *cert;
	size_t certlen;
	const uint8_t *name;
	size_t namelen;

	*nameslen = 0;
	while (certslen) {
		size_t alen = 0;
		if (x509_cert_from_der(&cert, &certlen, &certs, &certslen) != 1
			|| x509_cert_get_subject(cert, certlen, &name, &namelen) != 1
			|| asn1_sequence_to_der(name, namelen, NULL, &alen) != 1) {
			error_print();
			return -1;
		}
		if (tls_uint16_size() + alen > maxlen) {
			error_print();
			return -1;
		}
		if (alen > UINT16_MAX) {
			error_print();
			return -1;
		}
		tls_uint16_to_bytes((uint16_t)alen, &names, nameslen);
		if (asn1_sequence_to_der(name, namelen, &names, nameslen) != 1) {
			error_print();
			return -1;
		}
		maxlen -= alen;
	}
	return 1;
}

int tls_authorities_issued_certificate(const uint8_t *ca_names, size_t ca_names_len, const uint8_t *certs, size_t certslen)
{
	const uint8_t *cert;
	size_t certlen;
	const uint8_t *issuer;
	size_t issuer_len;

	if (x509_certs_get_last(certs, certslen, &cert, &certlen) != 1
		|| x509_cert_get_issuer(cert, certlen, &issuer, &issuer_len) != 1) {
		error_print();
		return -1;
	}
	while (ca_names_len) {
		const uint8_t *p;
		size_t len;
		const uint8_t *name;
		size_t namelen;

		if (tls_uint16array_from_bytes(&p, &len, &ca_names, &ca_names_len) != 1) {
			error_print();
			return -1;
		}
		if (asn1_sequence_from_der(&name, &namelen, &p, &len) != 1
			|| asn1_length_is_zero(len) != 1) {
			error_print();
			return -1;
		}
		if (x509_name_equ(name, namelen, issuer, issuer_len) == 1) {
			return 1;
		}
	}
	error_print();
	return 0;
}

int tls_cert_types_accepted(const uint8_t *types, size_t types_len, const uint8_t *client_certs, size_t client_certs_len)
{
	const uint8_t *cert;
	size_t certlen;
	int sig_alg;
	size_t i;

	if (x509_certs_get_cert_by_index(client_certs, client_certs_len, 0, &cert, &certlen) != 1) {
		error_print();
		return -1;
	}
	if ((sig_alg = tls_cert_type_from_oid(OID_sm2sign_with_sm3)) < 0) {
		error_print();
		return -1;
	}
	for (i = 0; i < types_len; i++) {
		if (sig_alg == types[i]) {
			return 1;
		}
	}
	return 0;
}

int tls_client_verify_init(TLS_CLIENT_VERIFY_CTX *ctx)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	memset(ctx, 0, sizeof(TLS_CLIENT_VERIFY_CTX));
	return 1;
}

int tls_client_verify_update(TLS_CLIENT_VERIFY_CTX *ctx, const uint8_t *handshake, size_t handshake_len)
{
	uint8_t *buf;
	if (!ctx || !handshake || !handshake_len) {
		error_print();
		return -1;
	}
	if (ctx->index < 0 || ctx->index > 7) {
		error_print();
		return -1;
	}
	if (!(buf = malloc(handshake_len))) {
		error_print();
		return -1;
	}
	memcpy(buf, handshake, handshake_len);
	ctx->handshake[ctx->index] = buf;
	ctx->handshake_len[ctx->index] = handshake_len;
	ctx->index++;
	return 1;
}

int tls_client_verify_finish(TLS_CLIENT_VERIFY_CTX *ctx, const uint8_t *sig, size_t siglen, const SM2_KEY *public_key)
{
	int ret;
	SM2_VERIFY_CTX verify_ctx;
	int i;

	if (!ctx || !sig || !siglen || !public_key) {
		error_print();
		return -1;
	}

	if (ctx->index != 8) {
		error_print();
		return -1;
	}
	if (sm2_verify_init(&verify_ctx, public_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1) {
		error_print();
		return -1;
	}
	for (i = 0; i < 8; i++) {
		if (sm2_verify_update(&verify_ctx, ctx->handshake[i], ctx->handshake_len[i]) != 1) {
			error_print();
			return -1;
		}
	}
	if ((ret = sm2_verify_finish(&verify_ctx, sig, siglen)) < 0) {
		error_print();
		return -1;
	}
	return ret;
}

void tls_client_verify_cleanup(TLS_CLIENT_VERIFY_CTX *ctx)
{
	if (ctx) {
		int i;
		for (i = 0; i< ctx->index; i++) {
			if (ctx->handshake[i]) {
				free(ctx->handshake[i]);
				ctx->handshake[i] = NULL;
				ctx->handshake_len[i] = 0;
			}
		}
	}
}

int tls_cipher_suites_select(const uint8_t *client_ciphers, size_t client_ciphers_len,
	const int *server_ciphers, size_t server_ciphers_cnt,
	int *selected_cipher)
{
	if (!client_ciphers || !client_ciphers_len
		|| !server_ciphers || !server_ciphers_cnt || !selected_cipher) {
		error_print();
		return -1;
	}
	while (server_ciphers_cnt--) {
		const uint8_t *p = client_ciphers;
		size_t len = client_ciphers_len;
		while (len) {
			uint16_t cipher;
			if (tls_uint16_from_bytes(&cipher, &p, &len) != 1) {
				error_print();
				return -1;
			}
			if (cipher == *server_ciphers) {
				*selected_cipher = *server_ciphers;
				return 1;
			}
		}
		server_ciphers++;
	}
	return 0;
}

void tls_ctx_cleanup(TLS_CTX *ctx)
{
	if (ctx) {
		gmssl_secure_clear(&ctx->signkey, sizeof(SM2_KEY));
		gmssl_secure_clear(&ctx->kenckey, sizeof(SM2_KEY));
		if (ctx->certs) free(ctx->certs);
		if (ctx->cacerts) free(ctx->cacerts);
		memset(ctx, 0, sizeof(TLS_CTX));
	}
}

int tls_ctx_init(TLS_CTX *ctx, int protocol, int is_client)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	memset(ctx, 0, sizeof(*ctx));

	switch (protocol) {
	case TLS_protocol_tlcp:
	case TLS_protocol_tls12:
	case TLS_protocol_tls13:
		ctx->protocol = protocol;
		break;
	default:
		error_print();
		return -1;
	}
	ctx->is_client = is_client ? 1 : 0;
	return 1;
}

int tls_ctx_set_cipher_suites(TLS_CTX *ctx, const int *cipher_suites, size_t cipher_suites_cnt)
{
	size_t i;

	if (!ctx || !cipher_suites || !cipher_suites_cnt) {
		error_print();
		return -1;
	}
	if (cipher_suites_cnt < 1 || cipher_suites_cnt > TLS_MAX_CIPHER_SUITES_COUNT) {
		error_print();
		return -1;
	}
	for (i = 0; i < cipher_suites_cnt; i++) {
		if (!tls_cipher_suite_name(cipher_suites[i])) {
			error_print();
			return -1;
		}
	}
	for (i = 0; i < cipher_suites_cnt; i++) {
		ctx->cipher_suites[i] = cipher_suites[i];
	}
	ctx->cipher_suites_cnt = cipher_suites_cnt;
	return 1;
}

int tls_ctx_set_ca_certificates(TLS_CTX *ctx, const char *cacertsfile, int depth)
{
	if (!ctx || !cacertsfile) {
		error_print();
		return -1;
	}
	if (depth < 0 || depth > TLS_MAX_VERIFY_DEPTH) {
		error_print();
		return -1;
	}
	if (!tls_protocol_name(ctx->protocol)) {
		error_print();
		return -1;
	}
	if (ctx->cacerts) {
		error_print();
		return -1;
	}
	if (x509_certs_new_from_file(&ctx->cacerts, &ctx->cacertslen, cacertsfile) != 1) {
		error_print();
		return -1;
	}
	if (ctx->cacertslen == 0) {
		error_print();
		return -1;
	}

	ctx->verify_depth = depth;
	return 1;
}

int tls_ctx_set_certificate_and_key(TLS_CTX *ctx, const char *chainfile,
	const char *keyfile, const char *keypass)
{
	int ret = -1;
	uint8_t *certs = NULL;
	size_t certslen;
	FILE *keyfp = NULL;
	SM2_KEY key;
	const uint8_t *cert;
	size_t certlen;
	SM2_KEY public_key;

	if (!ctx || !chainfile || !keyfile || !keypass) {
		error_print();
		return -1;
	}
	if (!tls_protocol_name(ctx->protocol)) {
		error_print();
		return -1;
	}
	if (ctx->certs) {
		error_print();
		return -1;
	}

	if (x509_certs_new_from_file(&certs, &certslen, chainfile) != 1) {
		error_print();
		goto end;
	}
	if (!(keyfp = fopen(keyfile, "r"))) {
		error_print();
		goto end;
	}
	if (sm2_private_key_info_decrypt_from_pem(&key, keypass, keyfp) != 1) {
		error_print();
		goto end;
	}
	if (x509_certs_get_cert_by_index(certs, certslen, 0, &cert, &certlen) != 1
		|| x509_cert_get_subject_public_key(cert, certlen, &public_key) != 1) {
		error_print();
		return -1;
	}
	if (sm2_public_key_equ(&key, &public_key) != 1) {
		error_print();
		return -1;
	}
	ctx->certs = certs;
	ctx->certslen = certslen;
	ctx->signkey = key;
	certs = NULL;
	ret = 1;

end:
	gmssl_secure_clear(&key, sizeof(key));
	if (certs) free(certs);
	if (keyfp) fclose(keyfp);
	return ret;
}

int tls_ctx_set_tlcp_server_certificate_and_keys(TLS_CTX *ctx, const char *chainfile,
	const char *signkeyfile, const char *signkeypass,
	const char *kenckeyfile, const char *kenckeypass)
{
	int ret = -1;
	uint8_t *certs = NULL;
	size_t certslen;
	FILE *signkeyfp = NULL;
	FILE *kenckeyfp = NULL;
	SM2_KEY signkey;
	SM2_KEY kenckey;

	const uint8_t *cert;
	size_t certlen;
	SM2_KEY public_key;

	if (!ctx || !chainfile || !signkeyfile || !signkeypass || !kenckeyfile || !kenckeypass) {
		error_print();
		return -1;
	}
	if (!tls_protocol_name(ctx->protocol)) {
		error_print();
		return -1;
	}
	if (ctx->certs) {
		error_print();
		return -1;
	}

	if (x509_certs_new_from_file(&certs, &certslen, chainfile) != 1) {
		error_print();
		return -1;
	}

	if (!(signkeyfp = fopen(signkeyfile, "r"))) {
		error_print();
		goto end;
	}
	if (sm2_private_key_info_decrypt_from_pem(&signkey, signkeypass, signkeyfp) != 1) {
		error_print();
		goto end;
	}
	if (x509_certs_get_cert_by_index(certs, certslen, 0, &cert, &certlen) != 1
		|| x509_cert_get_subject_public_key(cert, certlen, &public_key) != 1
		|| sm2_public_key_equ(&signkey, &public_key) != 1) {
		error_print();
		goto end;
	}

	if (!(kenckeyfp = fopen(kenckeyfile, "r"))) {
		error_print();
		goto end;
	}
	if (sm2_private_key_info_decrypt_from_pem(&kenckey, kenckeypass, kenckeyfp) != 1) {
		error_print();
		goto end;
	}
	if (x509_certs_get_cert_by_index(certs, certslen, 1, &cert, &certlen) != 1
		|| x509_cert_get_subject_public_key(cert, certlen, &public_key) != 1
		|| sm2_public_key_equ(&kenckey, &public_key) != 1) {
		error_print();
		goto end;
	}

	ctx->certs = certs;
	ctx->certslen = certslen;
	ctx->signkey = signkey;
	ctx->kenckey = kenckey;
	certs = NULL;
	ret = 1;

end:
	gmssl_secure_clear(&signkey, sizeof(signkey));
	gmssl_secure_clear(&kenckey, sizeof(kenckey));
	if (certs) free(certs);
	if (signkeyfp) fclose(signkeyfp);
	if (kenckeyfp) fclose(kenckeyfp);
	return ret;
}

int tls_init(TLS_CONNECT *conn, const TLS_CTX *ctx)
{
	size_t i;
	memset(conn, 0, sizeof(*conn));

	conn->protocol = ctx->protocol;
	conn->is_client = ctx->is_client;
	for (i = 0; i < ctx->cipher_suites_cnt; i++) {
		conn->cipher_suites[i] = ctx->cipher_suites[i];
	}
	conn->cipher_suites_cnt = ctx->cipher_suites_cnt;


	if (ctx->certslen > TLS_MAX_CERTIFICATES_SIZE) {
		error_print();
		return -1;
	}
	if (conn->is_client) {
		memcpy(conn->client_certs, ctx->certs, ctx->certslen);
		conn->client_certs_len = ctx->certslen;
	} else {
		memcpy(conn->server_certs, ctx->certs, ctx->certslen);
		conn->server_certs_len = ctx->certslen;
	}

	if (ctx->cacertslen > TLS_MAX_CERTIFICATES_SIZE) {
		error_print();
		return -1;
	}
	memcpy(conn->ca_certs, ctx->cacerts, ctx->cacertslen);
	conn->ca_certs_len = ctx->cacertslen;

	conn->sign_key = ctx->signkey;
	conn->kenc_key = ctx->kenckey;

	conn->quiet = ctx->quiet;

	return 1;
}

void tls_cleanup(TLS_CONNECT *conn)
{
	gmssl_secure_clear(conn, sizeof(TLS_CONNECT));
}

int tls_set_socket(TLS_CONNECT *conn, tls_socket_t sock)
{
	int flags = 0;
#ifdef _WIN32
		if( ioctlsocket(sock, FIONBIO, &flags) != 0)   {
		error_puts("socket in non-blocking mode");
		//nginx will pass a socket in non-blocking mode
		//return -1;
	}
#else
	if ((flags = fcntl(sock, F_GETFL)) == -1) {
		error_print();
		perror("fcntl error");
		return -1;
	}
	if (flags & O_NONBLOCK) {
		error_puts("socket in non-blocking mode");
		//nginx will pass a socket in non-blocking mode
		//return -1;
	}
#endif
	conn->sock = sock;
	return 1;
}

int tls_do_handshake(TLS_CONNECT *conn)
{
	switch (conn->protocol) {
	case TLS_protocol_tlcp:
		if (conn->is_client) return tlcp_do_connect(conn);
		else return tlcp_do_accept(conn);
	case TLS_protocol_tls12:
		if (conn->is_client) return tls12_do_connect(conn);
		else return tls12_do_accept(conn);
	case TLS_protocol_tls13:
		if (conn->is_client) return tls13_do_connect(conn);
		else return tls13_do_accept(conn);
	}
	error_print();
	return -1;
}

int tls_get_verify_result(TLS_CONNECT *conn, int *result)
{
	*result = conn->verify_result;
	return 1;
}
