/* ====================================================================
 * Copyright (c) 2016 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

/* put these functions under name `gmapi`, even if in the future the SDF
 * implementation is organized into a standalone sub-library, we still need
 * some convert functions between native types and the SDF types. So we can
 * mix this with SDF engine without relying on the `sdf` sub-library
 *
 * Attension: as the functions in this file can be seen as the native
 * functions of GmSSL/OpenSSL, so the return values of these functions will
 * follow the convention of OpenSSL, return 1 for success and 0 for error.
 * This is different from SAF/SDF/SKF where return 0 means success.
 */

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/sdf.h>
#include <openssl/gmapi.h>
#include <openssl/objects.h>

EC_KEY *EC_KEY_new_from_ECCrefPublicKey(const ECCrefPublicKey *ref)
{
	EC_KEY *ret;

	if (!(ret = EC_KEY_new_by_curve_name(NID_sm2p256v1))) {
		GMAPIerr(GMAPI_F_EC_KEY_NEW_FROM_ECCREFPUBLICKEY, ERR_R_EC_LIB);
		return NULL;
	}

	if (!EC_KEY_set_ECCrefPublicKey(ret, ref)) {
		GMAPIerr(GMAPI_F_EC_KEY_NEW_FROM_ECCREFPUBLICKEY,
			GMAPI_R_DECODE_EC_PUBLIC_KEY_FAILED);
		EC_KEY_free(ret);
		return NULL;
	}

	return ret;
}

int EC_KEY_set_ECCrefPublicKey(EC_KEY *ec_key, const ECCrefPublicKey *ref)
{
	int ret = 0;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;
	int nbytes;

	/* check arguments */
	if (!ec_key || !ref) {
		GMAPIerr(GMAPI_F_EC_KEY_SET_ECCREFPUBLICKEY,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	if (ref->bits != EC_GROUP_get_degree(EC_KEY_get0_group(ec_key))) {
		GMAPIerr(GMAPI_F_EC_KEY_SET_ECCREFPUBLICKEY,
			GMAPI_R_INVALID_KEY_LENGTH);
		return 0;
	}

	/* ECCrefPublicKey ==> EC_KEY */
	nbytes = (ref->bits + 7)/8;

	if (!(x = BN_bin2bn(ref->x, nbytes, NULL))) {
		GMAPIerr(GMAPI_F_EC_KEY_SET_ECCREFPUBLICKEY, ERR_R_BN_LIB);
		goto end;
	}
	if (!(y = BN_bin2bn(ref->y, nbytes, NULL))) {
		GMAPIerr(GMAPI_F_EC_KEY_SET_ECCREFPUBLICKEY, ERR_R_BN_LIB);
		goto end;
	}
	if (!EC_KEY_set_public_key_affine_coordinates(ec_key, x, y)) {
		GMAPIerr(GMAPI_F_EC_KEY_SET_ECCREFPUBLICKEY,
			GMAPI_R_INVALID_PUBLIC_KEY);
		goto end;
	}

	ret = 1;
end:
	BN_free(x);
	BN_free(y);
	return ret;
}

int EC_KEY_get_ECCrefPublicKey(EC_KEY *ec_key, ECCrefPublicKey *ref)
{
	int ret = 0;
	BN_CTX *bn_ctx = NULL;
	const EC_GROUP *group = EC_KEY_get0_group(ec_key);
	const EC_POINT *point = EC_KEY_get0_public_key(ec_key);
	BIGNUM *x;
	BIGNUM *y;

	/* check arguments */
	if (!ec_key || !ref) {
		GMAPIerr(GMAPI_F_EC_KEY_GET_ECCREFPUBLICKEY,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	/* prepare */
	if (!(bn_ctx = BN_CTX_new())) {
		GMAPIerr(GMAPI_F_EC_KEY_GET_ECCREFPUBLICKEY, ERR_R_BN_LIB);
		goto end;
	}
	BN_CTX_start(bn_ctx);
	x = BN_CTX_get(bn_ctx);
	y = BN_CTX_get(bn_ctx);
	if (!x || !y) {
		GMAPIerr(GMAPI_F_EC_KEY_GET_ECCREFPUBLICKEY, ERR_R_BN_LIB);
		goto end;
	}

	if (EC_GROUP_get_degree(group) > ECCref_MAX_BITS) {
		GMAPIerr(GMAPI_F_EC_KEY_GET_ECCREFPUBLICKEY,
			GMAPI_R_INVALID_KEY_LENGTH);
		goto end;
	}

	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field) {
		if (!EC_POINT_get_affine_coordinates_GFp(group, point, x, y, bn_ctx)) {
			GMAPIerr(GMAPI_F_EC_KEY_GET_ECCREFPUBLICKEY, ERR_R_EC_LIB);
			goto end;
		}
	} else  {
		if (!EC_POINT_get_affine_coordinates_GF2m(group, point, x, y, bn_ctx)) {
			GMAPIerr(GMAPI_F_EC_KEY_GET_ECCREFPUBLICKEY, ERR_R_EC_LIB);
			goto end;
		}
	}

	/* EC_KEY ==> ECCrefPublicKey */
	memset(ref, 0, sizeof(*ref));
	ref->bits = EC_GROUP_get_degree(group);
	if (!BN_bn2bin(x, ref->x + ECCref_MAX_LEN - BN_num_bytes(x))) {
		GMAPIerr(GMAPI_F_EC_KEY_GET_ECCREFPUBLICKEY, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_bn2bin(y, ref->y + ECCref_MAX_LEN - BN_num_bytes(y))) {
		GMAPIerr(GMAPI_F_EC_KEY_GET_ECCREFPUBLICKEY, ERR_R_BN_LIB);
		goto end;
	}

	ret = 1;
end:
	if (bn_ctx) {
		BN_CTX_end(bn_ctx);
	}
	BN_CTX_free(bn_ctx);
	return ret;
}

EC_KEY *EC_KEY_new_from_ECCrefPrivateKey(const ECCrefPrivateKey *ref)
{
	EC_KEY *ret;

	if (!(ret = EC_KEY_new_by_curve_name(NID_sm2p256v1))) {
		GMAPIerr(GMAPI_F_EC_KEY_NEW_FROM_ECCREFPRIVATEKEY, ERR_R_EC_LIB);
		return NULL;
	}

	if (!EC_KEY_set_ECCrefPrivateKey(ret, ref)) {
		GMAPIerr(GMAPI_F_EC_KEY_NEW_FROM_ECCREFPRIVATEKEY,
			GMAPI_R_DECODE_EC_PRIVATE_KEY_FAILED);
		EC_KEY_free(ret);
		return NULL;
	}

	return ret;
}

int EC_KEY_set_ECCrefPrivateKey(EC_KEY *ec_key, const ECCrefPrivateKey *ref)
{
	int ret = 0;
	BIGNUM *d = NULL;

	if (!ec_key || !ref) {
		GMAPIerr(GMAPI_F_EC_KEY_SET_ECCREFPRIVATEKEY,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (ref->bits != EC_GROUP_get_degree(EC_KEY_get0_group(ec_key))) {
		GMAPIerr(GMAPI_F_EC_KEY_SET_ECCREFPRIVATEKEY,
			GMAPI_R_INVALID_KEY_LENGTH);
		goto end;
	}

	if (!(d = BN_bin2bn(ref->K, ECCref_MAX_LEN, NULL))) {
		GMAPIerr(GMAPI_F_EC_KEY_SET_ECCREFPRIVATEKEY, ERR_R_BN_LIB);
		goto end;
	}
	if (!EC_KEY_set_private_key(ec_key, d)) {
		GMAPIerr(GMAPI_F_EC_KEY_SET_ECCREFPRIVATEKEY,
			GMAPI_R_INVALID_PRIVATE_KEY);
		goto end;
	}

	ret = 1;
end:
	BN_clear_free(d);
	return ret;
}

int EC_KEY_get_ECCrefPrivateKey(EC_KEY *ec_key, ECCrefPrivateKey *ref)
{
	const EC_GROUP *group;
	const BIGNUM *sk;
	int nbytes;

	/* check arguments */
	if (!ec_key || !ref) {
		GMAPIerr(GMAPI_F_EC_KEY_GET_ECCREFPRIVATEKEY,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	group = EC_KEY_get0_group(ec_key);
	sk = EC_KEY_get0_private_key(ec_key);

	if (!group || !sk) {
		GMAPIerr(GMAPI_F_EC_KEY_GET_ECCREFPRIVATEKEY,
			GMAPI_R_INVALID_EC_PRIVATE_KEY);
		return 0;
	}

	if (EC_GROUP_get_degree(group) > ECCref_MAX_BITS) {
		GMAPIerr(GMAPI_F_EC_KEY_GET_ECCREFPRIVATEKEY,
			GMAPI_R_INVALID_KEY_LENGTH);
		return 0;
	}

	/* EC_KEY ==> ECCrefPrivateKey */
	memset(ref, 0, sizeof(*ref));

	ref->bits = EC_GROUP_get_degree(group);

	nbytes = (EC_GROUP_get_degree(group) + 7)/8;
	if (!BN_bn2bin(sk, ref->K + nbytes - BN_num_bytes(sk))) {
		GMAPIerr(GMAPI_F_EC_KEY_GET_ECCREFPRIVATEKEY, ERR_R_BN_LIB);
		return 0;
	}

	return 1;
}

SM2CiphertextValue *SM2CiphertextValue_new_from_ECCCipher(const ECCCipher *ref)
{
	SM2CiphertextValue *ret = NULL;
	SM2CiphertextValue *cv = NULL;
	EC_GROUP *group = NULL;

	/* check arguments */
	if (!ref) {
		GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_NEW_FROM_ECCCIPHER,
			ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}
	if (ref->L > INT_MAX) {
		GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_NEW_FROM_ECCCIPHER,
			GMAPI_R_INVALID_CIPHETEXT_LENGTH);
		return NULL;
	}

	/* ECCCipher => SM2CiphertextValue */
	if (!(group = EC_GROUP_new_by_curve_name(NID_sm2p256v1))) {
		GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_NEW_FROM_ECCCIPHER,
			ERR_R_EC_LIB);
		goto end;
	}

	if (!(cv = SM2CiphertextValue_new(group))) {
		GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_NEW_FROM_ECCCIPHER,
			GMAPI_R_MALLOC_FAILED);
		goto end;
	}

	if (!SM2CiphertextValue_set_ECCCipher(cv, ref)) {
		GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_NEW_FROM_ECCCIPHER,
			GMAPI_R_INVALID_SM2_CIPHERTEXT);
		goto end;
	}

	ret = cv;
	cv = NULL;

end:
	EC_GROUP_free(group);
	SM2CiphertextValue_free(cv);
	return ret;
}

/*
 * Different vendors might have different encoding of field elements when
 * the buffer is larger than requirment. We assume the encoding to be
 * big-endian, which means that there will be prefix zeros in the buffer
 * before the field element. Another popular encoding is to use the suffix
 * zeros. When the gmapi wrapper is working with vendor's SDF
 * implementations, developers have to check the encoding of the vendor's
 * library to make sure the encoding/decoding is correct
 */
int SM2CiphertextValue_set_ECCCipher(SM2CiphertextValue *cv,
	const ECCCipher *ref)
{
	int ret = 0;
	BN_CTX *bn_ctx = NULL;
	EC_GROUP *group = NULL;
	BIGNUM *x;
	BIGNUM *y;
	int nbytes;

	/* check arguments */
	if (!cv || !ref) {
		GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_SET_ECCCIPHER,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	/* variables */
	if (!(group = EC_GROUP_new_by_curve_name(NID_sm2p256v1))) {
		GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_SET_ECCCIPHER,
			ERR_R_EC_LIB);
		goto end;
	}
	/* this will never happen with GmSSL's sdf.h */
	if (EC_GROUP_get_degree(group) > ECCref_MAX_BITS) {
		GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_SET_ECCCIPHER,
			GMAPI_R_INVALID_KEY_LENGTH);
		goto end;
	}
	nbytes = (EC_GROUP_get_degree(group) + 7)/8;

	/* malloc */
	if (!(bn_ctx = BN_CTX_new())) {
		GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_SET_ECCCIPHER,
			ERR_R_MALLOC_FAILURE);
		goto end;
	}
	BN_CTX_start(bn_ctx);
	x = BN_CTX_get(bn_ctx);
	y = BN_CTX_get(bn_ctx);
	if (!x || !y) {
		GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_SET_ECCCIPHER,
			ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* ECCCipher ==> SM2CiphertextValue */
	if (!BN_bin2bn(ref->x, ECCref_MAX_LEN, cv->xCoordinate)) {
		GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_SET_ECCCIPHER,
			ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_bin2bn(ref->y, ECCref_MAX_LEN, cv->yCoordinate)) {
		GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_SET_ECCCIPHER,
			ERR_R_BN_LIB);
		goto end;
	}

	if (!cv->ephem_point) {
		if (!(cv->ephem_point = EC_POINT_new(group))) {
			GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_SET_ECCCIPHER, ERR_R_EC_LIB);
			goto end;
		}
	}
	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field) {
		if (!EC_POINT_set_affine_coordinates_GFp(group, cv->ephem_point, x, y, bn_ctx)) {
			GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_SET_ECCCIPHER, ERR_R_EC_LIB);
			goto end;
		}
	} else  {
		if (!EC_POINT_get_affine_coordinates_GF2m(group, cv->ephem_point, x, y, bn_ctx)) {
			GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_SET_ECCCIPHER, ERR_R_EC_LIB);
			goto end;
		}
	}

	cv->mactag_size = 32;
	memcpy(cv->mactag, ref->M, 32);

	if (ref->L <= 0 || ref->L > INT_MAX) {
		GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_SET_ECCCIPHER,
			GMAPI_R_INVALID_CIPHERTEXT_LENGTH);
		goto end;
	}
	cv->ciphertext_size = (size_t)ref->L;

	if (!(cv->ciphertext = OPENSSL_realloc(cv->ciphertext, (size_t)ref->L))) {
		GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_SET_ECCCIPHER,
			GMAPI_R_MALLOC_FAILED);
		goto end;
	}
	memcpy(cv->ciphertext, ref->C, (size_t)ref->L);

	/* set return value */
	ret = 0;

end:
	EC_GROUP_free(group);
	if (bn_ctx) {
		BN_CTX_end(bn_ctx);
	}
	BN_CTX_free(bn_ctx);
	return ret;
}

/* The caller need to prepare buffer larger than `sizeof(ECCipher)` to hold
 * the result. Some vendors might change the define of `ECCCipher->C[1]` to
 * larger buffer, such as `ECCCipher->C[ECC_CIPHER_MAX_LEN]`, but our
 * implementation will not know this. So always init `ECCCipher->L` to the
 * buffer size for ciphertext.
 * Some vendors might even change the definition of `ECCCipher`, then there
 * will be compiling errors when compiled with the vendor's header file. So
 * when you will use a vendor's SDF library, do not use `openssl/sdf.h`, but
 * use the vendor's header file. Then the errors can be found by the
 * compiler.
 */
int SM2CiphertextValue_get_ECCCipher(const SM2CiphertextValue *cv,
	ECCCipher *ref)
{
	int ret = 0;
	BN_CTX *bn_ctx = NULL;
	EC_GROUP *group = NULL;
	BIGNUM *x;
	BIGNUM *y;

	/* check arguments */
	if (!cv || !ref) {
		GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_GET_ECCCIPHER,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	/* as the `ECCCipher->C[1]` default size is too small, we have to
	 * check `ECCCipher->L` to make sure caller has initialized this
	 * structure and prepared enough buffer to hold variable length
	 * ciphertext
	 */
	if (ref->L < cv->ciphertext_size) {
		GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_GET_ECCCIPHER,
			GMAPI_R_BUFFER_TOO_SMALL);
		return 0;
	}

	/* malloc */
	if (!(group = EC_GROUP_new_by_curve_name(NID_sm2p256v1))) {
		GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_GET_ECCCIPHER, ERR_R_EC_LIB);
		return 0;
	}

	if (!(bn_ctx = BN_CTX_new())) {
		GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_GET_ECCCIPHER, ERR_R_BN_LIB);
		goto end;
	}

	BN_CTX_start(bn_ctx);
	x = BN_CTX_get(bn_ctx);
	y = BN_CTX_get(bn_ctx);
	if (!x || !y) {
		GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_GET_ECCCIPHER,
			ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* SM2CiphertextValue ==> ECCCipher */
	memset(ref, 0, sizeof(*ref));

	/* encode ephem point `ECCCipher->x`, `ECCCipher->y` */
	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field) {
		if (!EC_POINT_get_affine_coordinates_GFp(group, cv->ephem_point, x, y, bn_ctx)) {
			GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_GET_ECCCIPHER, ERR_R_EC_LIB);
			goto end;
		}
	} else  {
		if (!EC_POINT_get_affine_coordinates_GF2m(group, cv->ephem_point, x, y, bn_ctx)) {
			GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_GET_ECCCIPHER,
				ERR_R_EC_LIB);
			goto end;
		}
	}
	/*
	 * check compatible of SM2CiphertextValue with EC_GROUP
	 * In gmapi we only do simple checks, i.e. length of coordinates.
	 * We assume that more checks, such as x, y in the range of [1, p]
	 * and other semantic checks should be done by the `sm2` module.
	 */
	if (BN_num_bits(x) > EC_GROUP_get_degree(group) ||
		BN_num_bits(y) > EC_GROUP_get_degree(group)) {
		GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_GET_ECCCIPHER,
			GMAPI_R_INVALID_CIPHERTEXT_POINT);
		goto end;
	}
	if (!BN_bn2bin(x, ref->x + ECCref_MAX_LEN - BN_num_bytes(x))) {
		GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_GET_ECCCIPHER,
			ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_bn2bin(y, ref->y + ECCref_MAX_LEN - BN_num_bytes(y))) {
		GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_GET_ECCCIPHER,
			ERR_R_BN_LIB);
		goto end;
	}

	/* encode mac `ECCCipher->M[32]` */
	if (cv->mactag_size != 32) {
		GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_GET_ECCCIPHER,
			GMAPI_R_INVALID_CIPHERTEXT_MAC);
		goto end;
	}
	memcpy(ref->M, cv->mactag, cv->mactag_size);

	/* encode ciphertext `ECCCipher->L`, `ECCCipher->C[]` */
	if (cv->ciphertext_size <= 0 || cv->ciphertext_size > INT_MAX) {
		GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_GET_ECCCIPHER,
			GMAPI_R_INVALID_CIPHERTEXT_LENGTH);
		goto end;
	}
	ref->L = (unsigned int)cv->ciphertext_size;
	memcpy(ref->C, cv->ciphertext, cv->ciphertext_size);

	/* set return value */
	ret = 1;
end:
	if (bn_ctx) {
		BN_CTX_end(bn_ctx);
	}
	BN_CTX_free(bn_ctx);
	EC_GROUP_free(group);
	return ret;
}

ECDSA_SIG *ECDSA_SIG_new_from_ECCSignature(const ECCSignature *ref)
{
	ECDSA_SIG *ret = NULL;
	ECDSA_SIG *sig = NULL;

	/* check arguments */
	if (!ref) {
		GMAPIerr(GMAPI_F_ECDSA_SIG_NEW_FROM_ECCSIGNATURE,
			ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}

	/* generate and convert */
	if (!(sig = ECDSA_SIG_new())) {
		GMAPIerr(GMAPI_F_ECDSA_SIG_NEW_FROM_ECCSIGNATURE,
			GMAPI_R_MALLOC_FAILED);
		goto end;
	}
	if (!ECDSA_SIG_set_ECCSignature(sig, ref)) {
		GMAPIerr(GMAPI_F_ECDSA_SIG_NEW_FROM_ECCSIGNATURE,
			GMAPI_R_INVALID_SIGNATURE);
		goto end;
	}

	/* set return value */
	ret = sig;
	sig = NULL;

end:
	ECDSA_SIG_free(sig);
	return ret;
}

int ECDSA_SIG_set_ECCSignature(ECDSA_SIG *sig, const ECCSignature *ref)
{
	int ret = 0;
	BIGNUM *r = NULL;
	BIGNUM *s = NULL;

	/* check arguments */
	if (!sig || !ref) {
		GMAPIerr(GMAPI_F_ECDSA_SIG_SET_ECCSIGNATURE,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	/* ECCSignature ==> ECDSA_SIG */
	if (!(r = BN_bin2bn(ref->r, ECCref_MAX_LEN, NULL))) {
		GMAPIerr(GMAPI_F_ECDSA_SIG_SET_ECCSIGNATURE, ERR_R_BN_LIB);
		goto end;
	}
	if (!(s = BN_bin2bn(ref->s, ECCref_MAX_LEN, NULL))) {
		GMAPIerr(GMAPI_F_ECDSA_SIG_SET_ECCSIGNATURE, ERR_R_BN_LIB);
		goto end;
	}
	/* when using `sm2p256v1`, we need to check (s, r) length correct */
	if (BN_num_bytes(r) != 256/8 || BN_num_bytes(s) != 256/8) {
		GMAPIerr(GMAPI_F_ECDSA_SIG_SET_ECCSIGNATURE,
			GMAPI_R_INVALID_SM2_SIGNATURE);
		goto end;
	}

	/* set return value
	 * `ECDSA_SIG_set0` should make sure that if failed, do not accept
	 * the value of (r, s), or there will be double-free
	 */
	if (!ECDSA_SIG_set0(sig, r, s)) {
		GMAPIerr(GMAPI_F_ECDSA_SIG_SET_ECCSIGNATURE,
			ERR_R_EC_LIB);
		goto end;
	}

	r = NULL;
	s = NULL;
	ret = 1;

end:
	BN_free(r);
	BN_free(s);
	return ret;
}

int ECDSA_SIG_get_ECCSignature(const ECDSA_SIG *sig, ECCSignature *ref)
{
	/* (r, s) are pointed to (sig->r, sig->s), so dont free (r, s) */
	const BIGNUM *r = NULL;
	const BIGNUM *s = NULL;

	/* check arguments */
	if (!sig || !ref) {
		GMAPIerr(GMAPI_F_ECDSA_SIG_GET_ECCSIGNATURE,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	/* check ECDSA_SIG
	 * `ECDSA_SIG_get0() return void
	 */
	ECDSA_SIG_get0(sig, &r, &s);

	if (BN_num_bytes(r) > ECCref_MAX_LEN ||
		BN_num_bytes(s) > ECCref_MAX_LEN) {
		GMAPIerr(GMAPI_F_ECDSA_SIG_GET_ECCSIGNATURE,
			GMAPI_R_NOT_CONVERTABLE);
		return 0;
	}

	/* ECDSA_SIG ==> ECCSignature */
	memset(ref, 0, sizeof(*ref));

	if (!BN_bn2bin(r, ref->r + ECCref_MAX_LEN - BN_num_bytes(r))) {
		GMAPIerr(GMAPI_F_ECDSA_SIG_GET_ECCSIGNATURE, ERR_R_BN_LIB);
		return 0;
	}
	if (!BN_bn2bin(s, ref->s + ECCref_MAX_LEN - BN_num_bytes(s))) {
		GMAPIerr(GMAPI_F_ECDSA_SIG_GET_ECCSIGNATURE, ERR_R_BN_LIB);
		return 0;
	}

	return 1;
}
