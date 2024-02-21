/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <gmssl/sm2.h>
#include <gmssl/mem.h>
#include <gmssl/asn1.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include <gmssl/endian.h>


#define sm2_print_bn(label,a) sm2_bn_print(stderr,0,0,label,a) // 这个不应该放在这里，应该放在测试文件中
#define USE_SM2_GCACHE

const SM2_BN SM2_P = {
	0xffffffff, 0xffffffff, 0x00000000, 0xffffffff,
	0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe,
};

const SM2_BN SM2_B = {
	0x4d940e93, 0xddbcbd41, 0x15ab8f92, 0xf39789f5,
	0xcf6509a7, 0x4d5a9e4b, 0x9d9f5e34, 0x28e9fa9e,
};

const SM2_JACOBIAN_POINT _SM2_G = {
	{
	0x334c74c7, 0x715a4589, 0xf2660be1, 0x8fe30bbf,
	0x6a39c994, 0x5f990446, 0x1f198119, 0x32c4ae2c,
	},
	{
	0x2139f0a0, 0x02df32e5, 0xc62a4740, 0xd0a9877c,
	0x6b692153, 0x59bdcee3, 0xf4f6779c, 0xbc3736a2,
	},
	{
	1, 0, 0, 0, 0, 0, 0, 0,
	},
};
const SM2_JACOBIAN_POINT *SM2_G = &_SM2_G;

const SM2_BN SM2_N = {
	0x39d54123, 0x53bbf409, 0x21c6052b, 0x7203df6b,
	0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe,
};

// u = (p - 1)/4, u + 1 = (p + 1)/4
const SM2_BN SM2_U_PLUS_ONE = {
	0x00000000, 0x40000000, 0xc0000000, 0xffffffff,
	0xffffffff, 0xffffffff, 0xbfffffff, 0x3fffffff,
};

const SM2_BN SM2_ONE = {1,0,0,0,0,0,0,0};
const SM2_BN SM2_TWO = {2,0,0,0,0,0,0,0};
const SM2_BN SM2_THREE = {3,0,0,0,0,0,0,0};



int sm2_bn_check(const SM2_BN a)
{
	int err = 0;
	int i;
	for (i = 0; i < 8; i++) {
		if (a[i] > 0xffffffff) {
			fprintf(stderr, "%s %d: error\n", __FILE__, __LINE__);
			err++;
		}
	}
	if (err)
		return -1;
	else	return 1;
}

int sm2_bn_is_zero(const SM2_BN a)
{
	int i;
	for (i = 0; i < 8; i++) {
		if (a[i] != 0)
			return 0;
	}
	return 1;
}

int sm2_bn_is_one(const SM2_BN a)
{
	int i;
	if (a[0] != 1)
		return 0;
	for (i = 1; i < 8; i++) {
		if (a[i] != 0)
			return 0;
	}
	return 1;
}

void sm2_bn_to_bytes(const SM2_BN a, uint8_t out[32])
{
	int i;
	uint8_t *p = out;

	/*
	fprintf(stderr, "sm2_bn_to_bytes:\n");
	for (i = 0; i < 8; i++) {
		fprintf(stderr, "%016lx ", a[i]);
	}
	fprintf(stderr, "\n");
	*/

	for (i = 7; i >= 0; i--) {
		uint32_t ai = (uint32_t)a[i];
		PUTU32(out, ai);
		out += sizeof(uint32_t);
	}

	/*
	for (i = 0; i < 32; i++) {
		fprintf(stderr, "%02X ", p[i]);
	}
	*/

}

void sm2_bn_from_bytes(SM2_BN r, const uint8_t in[32])
{
	int i;
	for (i = 7; i >= 0; i--) {
		r[i] = GETU32(in);
		in += sizeof(uint32_t);
	}
}

static int hexchar2int(char c)
{
	if      ('0' <= c && c <= '9') return c - '0';
	else if ('a' <= c && c <= 'f') return c - 'a' + 10;
	else if ('A' <= c && c <= 'F') return c - 'A' + 10;
	else return -1;
}

static int hex2bin(const char *in, size_t inlen, uint8_t *out)
{
	int c;
	if (inlen % 2)
		return -1;

	while (inlen) {
		if ((c = hexchar2int(*in++)) < 0)
			return -1;
		*out = (uint8_t)c << 4;
		if ((c = hexchar2int(*in++)) < 0)
			return -1;
		*out |= (uint8_t)c;
		inlen -= 2;
		out++;
	}
	return 1;
}

void sm2_bn_to_hex(const SM2_BN a, char hex[64])
{
	int i;
	for (i = 7; i >= 0; i--) {
		int len;
		len = sprintf(hex, "%08x", (uint32_t)a[i]);
		assert(len == 8);
		hex += 8;
	}
}

int sm2_bn_from_hex(SM2_BN r, const char hex[64])
{
	uint8_t buf[32];
	if (hex2bin(hex, 64, buf) < 0)
		return -1;
	sm2_bn_from_bytes(r, buf);
	return 1;
}

int sm2_bn_from_asn1_integer(SM2_BN r, const uint8_t *d, size_t dlen)
{
	uint8_t buf[32] = {0};
	if (!d || dlen == 0) {
		error_print();
		return -1;
	}
	if (dlen > sizeof(buf)) {
		error_print();
		return -1;
	}
	memcpy(buf + sizeof(buf) - dlen, d, dlen);
	sm2_bn_from_bytes(r, buf);
	return 1;
}

int sm2_bn_print(FILE *fp, int fmt, int ind, const char *label, const SM2_BN a)
{
	int ret = 0, i;
	format_print(fp, fmt, ind, "%s: ", label);

	for (i = 7; i >= 0; i--) {
		if (a[i] >= ((uint64_t)1 << 32)) {
			printf("bn_print check failed\n");
		}
		ret += fprintf(fp, "%08x", (uint32_t)a[i]);
	}
	ret += fprintf(fp, "\n");
	return ret;
}

void sm2_bn_to_bits(const SM2_BN a, char bits[256])
{
	int i, j;
	uint64_t w;
	for (i = 7; i >= 0; i--) {
		w = a[i];
		for (j = 0; j < 32; j++) {
			*bits++ = (w & 0x80000000) ? '1' : '0';
			w <<= 1;
		}
	}
}

int sm2_bn_cmp(const SM2_BN a, const SM2_BN b)
{
	int i;
	for (i = 7; i >= 0; i--) {
		if (a[i] > b[i])
			return 1;
		if (a[i] < b[i])
			return -1;
	}
	return 0;
}

int sm2_bn_equ_hex(const SM2_BN a, const char *hex)
{
	char buf[65] = {0};
	char *p = buf;
	int i;

	for (i = 7; i >= 0; i--) {
		sprintf(p, "%08x", (uint32_t)a[i]);
		p += 8;
	}
	return (strcmp(buf, hex) == 0);
}

int sm2_bn_is_odd(const SM2_BN a)
{
	return a[0] & 0x01;
}

void sm2_bn_set_word(SM2_BN r, uint32_t a)
{
	int i;
	r[0] = a;
	for (i = 1; i < 8; i++) {
		r[i] = 0;
	}
}

int sm2_bn_rshift(SM2_BN ret, const SM2_BN a, unsigned int nbits)
{
	SM2_BN r;
	int i;

	if (nbits > 31) {
		error_print();
		return -1;
	}
	if (nbits == 0) {
		sm2_bn_copy(ret, a);
	}

	for (i = 0; i < 7; i++) {
		r[i] = a[i] >> nbits;
		r[i] |= (a[i+1] << (32 - nbits)) & 0xffffffff;
	}
	r[i] = a[i] >> nbits;
	sm2_bn_copy(ret, r);
	return 1;
}

void sm2_bn_add(SM2_BN r, const SM2_BN a, const SM2_BN b)
{
	int i;
	r[0] = a[0] + b[0];

	for (i = 1; i < 8; i++) {
		r[i] = a[i] + b[i] + (r[i-1] >> 32);
	}
	for (i = 0; i < 7; i++) {
		r[i] &= 0xffffffff;
	}
}

void sm2_bn_sub(SM2_BN ret, const SM2_BN a, const SM2_BN b)
{
	int i;
	SM2_BN r;
	r[0] = ((uint64_t)1 << 32) + a[0] - b[0];
	for (i = 1; i < 7; i++) {
		r[i] = 0xffffffff + a[i] - b[i] + (r[i - 1] >> 32);
		r[i - 1] &= 0xffffffff;
	}
	r[i] = a[i] - b[i] + (r[i - 1] >> 32) - 1;
	r[i - 1] &= 0xffffffff;
	sm2_bn_copy(ret, r);
}

int sm2_bn_rand_range(SM2_BN r, const SM2_BN range)
{
	uint8_t buf[32];
	do {
		if (rand_bytes(buf, sizeof(buf)) != 1) {
			error_print();
			return -1;
		}
		sm2_bn_from_bytes(r, buf);
	} while (sm2_bn_cmp(r, range) >= 0);
	return 1;
}

int sm2_fp_rand(SM2_Fp r)
{
	if (sm2_bn_rand_range(r, SM2_P) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

void sm2_fp_add(SM2_Fp r, const SM2_Fp a, const SM2_Fp b)
{
	sm2_bn_add(r, a, b);
	if (sm2_bn_cmp(r, SM2_P) >= 0) {
		sm2_bn_sub(r, r, SM2_P);
	}
}

void sm2_fp_sub(SM2_Fp r, const SM2_Fp a, const SM2_Fp b)
{
	if (sm2_bn_cmp(a, b) >= 0) {
		sm2_bn_sub(r, a, b);
	} else {
		SM2_BN t;
		sm2_bn_sub(t, SM2_P, b);
		sm2_bn_add(r, t, a);
	}
}

void sm2_fp_dbl(SM2_Fp r, const SM2_Fp a)
{
	sm2_fp_add(r, a, a);
}

void sm2_fp_tri(SM2_Fp r, const SM2_Fp a)
{
	SM2_BN t;
	sm2_fp_dbl(t, a);
	sm2_fp_add(r, t, a);
}

void sm2_fp_div2(SM2_Fp r, const SM2_Fp a)
{
	int i;
	sm2_bn_copy(r, a);
	if (r[0] & 0x01) {
		sm2_bn_add(r, r, SM2_P);
	}
	for (i = 0; i < 7; i++) {
		r[i] = (r[i] >> 1) | ((r[i + 1] & 0x01) << 31);
	}
	r[i] >>= 1;
}

void sm2_fp_neg(SM2_Fp r, const SM2_Fp a)
{
	if (sm2_bn_is_zero(a)) {
		sm2_bn_copy(r, a);
	} else {
		sm2_bn_sub(r, SM2_P, a);
	}
}

void sm2_fp_mul(SM2_Fp r, const SM2_Fp a, const SM2_Fp b)
{
	int i, j;
	uint64_t s[16] = {0};
	SM2_BN d = {0};
	uint64_t u;

	// s = a * b
	for (i = 0; i < 8; i++) {
		u = 0;
		for (j = 0; j < 8; j++) {
			u = s[i + j] + a[i] * b[j] + u;
			s[i + j] = u & 0xffffffff;
			u >>= 32;
		}
		s[i + 8] = u;
	}

	r[0] = s[0] + s[ 8] + s[ 9] + s[10] + s[11] + s[12] + ((s[13] + s[14] + s[15]) << 1);
	r[1] = s[1] + s[ 9] + s[10] + s[11] + s[12] + s[13] + ((s[14] + s[15]) << 1);
	r[2] = s[2];
	r[3] = s[3] + s[ 8] + s[11] + s[12] + s[14] + s[15] + (s[13] << 1);
	r[4] = s[4] + s[ 9] + s[12] + s[13] + s[15] + (s[14] << 1);
	r[5] = s[5] + s[10] + s[13] + s[14] + (s[15] << 1);
	r[6] = s[6] + s[11] + s[14] + s[15];
	r[7] = s[7] + s[ 8] + s[ 9] + s[10] + s[11] + s[15] + ((s[12] + s[13] + s[14] + s[15]) << 1);

	for (i = 1; i < 8; i++) {
		r[i] += r[i - 1] >> 32;
		r[i - 1] &= 0xffffffff;
	}

	d[2] = s[8] + s[9] + s[13] + s[14];
	d[3] = d[2] >> 32;
	d[2] &= 0xffffffff;
	sm2_bn_sub(r, r, d);

	// max times ?
	while (sm2_bn_cmp(r, SM2_P) >= 0) {
		sm2_bn_sub(r, r, SM2_P);
	}
}

void sm2_fp_sqr(SM2_Fp r, const SM2_Fp a)
{
	sm2_fp_mul(r, a, a);
}

void sm2_fp_exp(SM2_Fp r, const SM2_Fp a, const SM2_Fp e)
{
	SM2_BN t;
	uint32_t w;
	int i, j;

	sm2_bn_set_one(t);
	for (i = 7; i >= 0; i--) {
		w = (uint32_t)e[i];
		for (j = 0; j < 32; j++) {
			sm2_fp_sqr(t, t);
			if (w & 0x80000000)
				sm2_fp_mul(t, t, a);
			w <<= 1;
		}
	}

	sm2_bn_copy(r, t);
}

void sm2_fp_inv(SM2_Fp r, const SM2_Fp a)
{
	SM2_BN a1;
	SM2_BN a2;
	SM2_BN a3;
	SM2_BN a4;
	SM2_BN a5;
	int i;

	sm2_fp_sqr(a1, a);
	sm2_fp_mul(a2, a1, a);
	sm2_fp_sqr(a3, a2);
	sm2_fp_sqr(a3, a3);
	sm2_fp_mul(a3, a3, a2);
	sm2_fp_sqr(a4, a3);
	sm2_fp_sqr(a4, a4);
	sm2_fp_sqr(a4, a4);
	sm2_fp_sqr(a4, a4);
	sm2_fp_mul(a4, a4, a3);
	sm2_fp_sqr(a5, a4);
	for (i = 1; i < 8; i++)
		sm2_fp_sqr(a5, a5);
	sm2_fp_mul(a5, a5, a4);
	for (i = 0; i < 8; i++)
		sm2_fp_sqr(a5, a5);
	sm2_fp_mul(a5, a5, a4);
	for (i = 0; i < 4; i++)
		sm2_fp_sqr(a5, a5);
	sm2_fp_mul(a5, a5, a3);
	sm2_fp_sqr(a5, a5);
	sm2_fp_sqr(a5, a5);
	sm2_fp_mul(a5, a5, a2);
	sm2_fp_sqr(a5, a5);
	sm2_fp_mul(a5, a5, a);
	sm2_fp_sqr(a4, a5);
	sm2_fp_mul(a3, a4, a1);
	sm2_fp_sqr(a5, a4);
	for (i = 1; i< 31; i++)
		sm2_fp_sqr(a5, a5);
	sm2_fp_mul(a4, a5, a4);
	sm2_fp_sqr(a4, a4);
	sm2_fp_mul(a4, a4, a);
	sm2_fp_mul(a3, a4, a2);
	for (i = 0; i < 33; i++)
		sm2_fp_sqr(a5, a5);
	sm2_fp_mul(a2, a5, a3);
	sm2_fp_mul(a3, a2, a3);
	for (i = 0; i < 32; i++)
		sm2_fp_sqr(a5, a5);
	sm2_fp_mul(a2, a5, a3);
	sm2_fp_mul(a3, a2, a3);
	sm2_fp_mul(a4, a2, a4);
	for (i = 0; i < 32; i++)
		sm2_fp_sqr(a5, a5);
	sm2_fp_mul(a2, a5, a3);
	sm2_fp_mul(a3, a2, a3);
	sm2_fp_mul(a4, a2, a4);
	for (i = 0; i < 32; i++)
		sm2_fp_sqr(a5, a5);
	sm2_fp_mul(a2, a5, a3);
	sm2_fp_mul(a3, a2, a3);
	sm2_fp_mul(a4, a2, a4);
	for (i = 0; i < 32; i++)
		sm2_fp_sqr(a5, a5);
	sm2_fp_mul(a2, a5, a3);
	sm2_fp_mul(a3, a2, a3);
	sm2_fp_mul(a4, a2, a4);
	for (i = 0; i < 32; i++)
		sm2_fp_sqr(a5, a5);
	sm2_fp_mul(r, a4, a5);

	sm2_bn_clean(a1);
	sm2_bn_clean(a2);
	sm2_bn_clean(a3);
	sm2_bn_clean(a4);
	sm2_bn_clean(a5);
}

int sm2_fp_sqrt(SM2_Fp r, const SM2_Fp a)
{
	SM2_BN u;
	SM2_BN y; // temp result, prevent call sm2_fp_sqrt(a, a)

	// r = a^((p + 1)/4) when p = 3 (mod 4)
	sm2_bn_add(u, SM2_P, SM2_ONE);
	sm2_bn_rshift(u, u, 2);
	sm2_fp_exp(y, a, u);

	// check r^2 == a
	sm2_fp_sqr(u, y);
	if (sm2_bn_cmp(u, a) != 0) {
		error_print();
		return -1;
	}

	sm2_bn_copy(r, y);
	return 1;
}

void sm2_fn_add(SM2_Fn r, const SM2_Fn a, const SM2_Fn b)
{
	sm2_bn_add(r, a, b);
	if (sm2_bn_cmp(r, SM2_N) >= 0) {
		sm2_bn_sub(r, r, SM2_N);
	}
}

void sm2_fn_sub(SM2_Fn r, const SM2_Fn a, const SM2_Fn b)
{
	if (sm2_bn_cmp(a, b) >= 0) {
		sm2_bn_sub(r, a, b);
	} else {
		SM2_BN t;
		sm2_bn_add(t, a, SM2_N);
		sm2_bn_sub(r, t, b);
	}
}

void sm2_fn_neg(SM2_Fn r, const SM2_Fn a)
{
	if (sm2_bn_is_zero(a)) {
		sm2_bn_copy(r, a);
	} else {
		sm2_bn_sub(r, SM2_N, a);
	}
}

/* bn288 only used in barrett reduction */
static int sm2_bn288_cmp(const uint64_t a[9], const uint64_t b[9])
{
	int i;
	for (i = 8; i >= 0; i--) {
		if (a[i] > b[i])
			return 1;
		if (a[i] < b[i])
			return -1;
	}
	return 0;
}

static void sm2_bn288_add(uint64_t r[9], const uint64_t a[9], const uint64_t b[9])
{
	int i;
	r[0] = a[0] + b[0];
	for (i = 1; i < 9; i++) {
		r[i] = a[i] + b[i] + (r[i-1] >> 32);
	}
	for (i = 0; i < 8; i++) {
		r[i] &= 0xffffffff;
	}
}

static void sm2_bn288_sub(uint64_t ret[9], const uint64_t a[9], const uint64_t b[9])
{
	int i;
	uint64_t r[9];

	r[0] = ((uint64_t)1 << 32) + a[0] - b[0];
	for (i = 1; i < 8; i++) {
		r[i] = 0xffffffff + a[i] - b[i] + (r[i - 1] >> 32);
		r[i - 1] &= 0xffffffff;
	}
	r[i] = a[i] - b[i] + (r[i - 1] >> 32) - 1;
	r[i - 1] &= 0xffffffff;

	for (i = 0; i < 9; i++) {
		ret[i] = r[i];
	}
}

void sm2_fn_mul(SM2_BN ret, const SM2_BN a, const SM2_BN b)
{
	SM2_BN r;
	static const uint64_t mu[9] = {
		0xf15149a0, 0x12ac6361, 0xfa323c01, 0x8dfc2096, 1, 1, 1, 1, 1,
	};

	uint64_t s[18];
	uint64_t zh[9];
	uint64_t zl[9];
	uint64_t q[9];
	uint64_t w;
	int i, j;

	/* z = a * b */
	for (i = 0; i < 8; i++) {
		s[i] = 0;
	}
	for (i = 0; i < 8; i++) {
		w = 0;
		for (j = 0; j < 8; j++) {
			w += s[i + j] + a[i] * b[j];
			s[i + j] = w & 0xffffffff;
			w >>= 32;
		}
		s[i + 8] = w;
	}

	/* zl = z mod (2^32)^9 = z[0..8]
	 * zh = z // (2^32)^7 = z[7..15] */
	for (i = 0; i < 9; i++) {
		zl[i] = s[i];
		zh[i] = s[7 + i];
	}
	//printf("zl = "); for (i = 8; i >= 0; i--) printf("%08x", (uint32_t)zl[i]); printf("\n");
	//printf("zh = "); for (i = 8; i >= 0; i--) printf("%08x", (uint32_t)zh[i]); printf("\n");

	/* q = zh * mu // (2^32)^9 */
	for (i = 0; i < 9; i++) {
		s[i] = 0;
	}
	for (i = 0; i < 9; i++) {
		w = 0;
		for (j = 0; j < 9; j++) {
			w += s[i + j] + zh[i] * mu[j];
			s[i + j] = w & 0xffffffff;
			w >>= 32;
		}
		s[i + 9] = w;
	}
	for (i = 0; i < 8; i++) {
		q[i] = s[9 + i];
	}
	//printf("q  = "); for (i = 7; i >= 0; i--) printf("%08x", (uint32_t)q[i]); printf("\n");

	/* q = q * n mod (2^32)^9 */
	for (i = 0; i < 17; i++) {
		s[i] = 0;
	}
	for (i = 0; i < 8; i++) {
		w = 0;
		for (j = 0; j < 8; j++) {
			w += s[i + j] + q[i] * SM2_N[j];
			s[i + j] = w & 0xffffffff;
			w >>= 32;
		}
		s[i + 8] = w;
	}
	for (i = 0; i < 9; i++) {
		q[i] = s[i];
	}
	//printf("qn = "); for (i = 8; i >= 0; i--) printf("%08x ", (uint32_t)q[i]); printf("\n");

	/* r = zl - q (mod (2^32)^9) */

	if (sm2_bn288_cmp(zl, q)) {
		sm2_bn288_sub(zl, zl, q);
	} else {
		uint64_t c[9] = {0,0,0,0,0,0,0,0,0x100000000};
		sm2_bn288_sub(q, c, q);
		sm2_bn288_add(zl, q, zl);
	}
	//printf("zl  = "); for (i = 8; i >= 0; i--) printf("%08x ", (uint32_t)zl[i]); printf("\n");
	for (i = 0; i < 8; i++) {
		r[i] = zl[i];
	}
	r[7] += zl[8] << 32;

	/* while r >= p do: r = r - n */
	while (sm2_bn_cmp(r, SM2_N) >= 0) {
		sm2_bn_sub(r, r, SM2_N);
		//printf("r-n = "); for (i = 7; i >= 0; i--) printf("%16llx ", r[i]); printf("\n");
	}
	sm2_bn_copy(ret, r);
}

void sm2_fn_mul_word(SM2_Fn r, const SM2_Fn a, uint32_t b)
{
	SM2_Fn t;
	sm2_bn_set_word(t, b);
	sm2_fn_mul(r, a, t);
}

void sm2_fn_sqr(SM2_BN r, const SM2_BN a)
{
	sm2_fn_mul(r, a, a);
}

void sm2_fn_exp(SM2_BN r, const SM2_BN a, const SM2_BN e)
{
	SM2_BN t;
	uint32_t w;
	int i, j;

	sm2_bn_set_one(t);
	for (i = 7; i >= 0; i--) {
		w = (uint32_t)e[i];
		for (j = 0; j < 32; j++) {
			sm2_fn_sqr(t, t);
			if (w & 0x80000000) {
				sm2_fn_mul(t, t, a);
			}
			w <<= 1;
		}
	}
	sm2_bn_copy(r, t);
}

void sm2_fn_inv(SM2_BN r, const SM2_BN a)
{
	SM2_BN e;
	sm2_bn_sub(e, SM2_N, SM2_TWO);
	sm2_fn_exp(r, a, e);
}

int sm2_fn_rand(SM2_BN r)
{
	if (sm2_bn_rand_range(r, SM2_N) != 1) {
		error_print();
		return -1;
	}
	return 1;
}



void sm2_jacobian_point_init(SM2_JACOBIAN_POINT *R)
{
	memset(R, 0, sizeof(SM2_JACOBIAN_POINT));
	R->X[0] = 1;
	R->Y[0] = 1;
}

int sm2_jacobian_point_is_at_infinity(const SM2_JACOBIAN_POINT *P)
{
	return sm2_bn_is_zero(P->Z);
}

void sm2_jacobian_point_set_xy(SM2_JACOBIAN_POINT *R, const SM2_BN x, const SM2_BN y)
{
	sm2_bn_copy(R->X, x);
	sm2_bn_copy(R->Y, y);
	sm2_bn_set_one(R->Z);
}

void sm2_jacobian_point_get_xy(const SM2_JACOBIAN_POINT *P, SM2_BN x, SM2_BN y)
{
	if (sm2_bn_is_one(P->Z)) {
		sm2_bn_copy(x, P->X);
		if (y) {
			sm2_bn_copy(y, P->Y);
		}
	} else {
		SM2_BN z_inv;
		sm2_fp_inv(z_inv, P->Z);
		if (y) {
			sm2_fp_mul(y, P->Y, z_inv);
		}
		sm2_fp_sqr(z_inv, z_inv);
		sm2_fp_mul(x, P->X, z_inv);
		if (y) {
			sm2_fp_mul(y, y, z_inv);
		}
	}
}

int sm2_jacobian_pointpoint_print(FILE *fp, int fmt, int ind, const char *label, const SM2_JACOBIAN_POINT *P)
{
	int len = 0;
	SM2_BN x;
	SM2_BN y;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	sm2_jacobian_point_get_xy(P, x, y);

	sm2_bn_print(fp, fmt, ind, "x", x);
	sm2_bn_print(fp, fmt, ind, "y", y);

	return 1;
}

int sm2_jacobian_point_is_on_curve(const SM2_JACOBIAN_POINT *P)
{
	SM2_BN t0;
	SM2_BN t1;
	SM2_BN t2;

	if (sm2_bn_is_one(P->Z)) {
		sm2_fp_sqr(t0, P->Y);
		sm2_fp_add(t0, t0, P->X);
		sm2_fp_add(t0, t0, P->X);
		sm2_fp_add(t0, t0, P->X);
		sm2_fp_sqr(t1, P->X);
		sm2_fp_mul(t1, t1, P->X);
		sm2_fp_add(t1, t1, SM2_B);
	} else {
		sm2_fp_sqr(t0, P->Y);
		sm2_fp_sqr(t1, P->Z);
		sm2_fp_sqr(t2, t1);
		sm2_fp_mul(t1, t1, t2);
		sm2_fp_mul(t1, t1, SM2_B);
		sm2_fp_mul(t2, t2, P->X);
		sm2_fp_add(t0, t0, t2);
		sm2_fp_add(t0, t0, t2);
		sm2_fp_add(t0, t0, t2);
		sm2_fp_sqr(t2, P->X);
		sm2_fp_mul(t2, t2, P->X);
		sm2_fp_add(t1, t1, t2);
	}

	if (sm2_bn_cmp(t0, t1) != 0) {
		error_print();
		return -1;
	}
	return 1;
}

void sm2_jacobian_point_neg(SM2_JACOBIAN_POINT *R, const SM2_JACOBIAN_POINT *P)
{
	sm2_bn_copy(R->X, P->X);
	sm2_fp_neg(R->Y, P->Y);
	sm2_bn_copy(R->Z, P->Z);
}

void sm2_jacobian_point_dbl(SM2_JACOBIAN_POINT *R, const SM2_JACOBIAN_POINT *P)
{
	const uint64_t *X1 = P->X;
	const uint64_t *Y1 = P->Y;
	const uint64_t *Z1 = P->Z;
	SM2_BN T1;
	SM2_BN T2;
	SM2_BN T3;
	SM2_BN X3;
	SM2_BN Y3;
	SM2_BN Z3;
				//printf("X1 = "); print_bn(X1);
				//printf("Y1 = "); print_bn(Y1);
				//printf("Z1 = "); print_bn(Z1);

	if (sm2_jacobian_point_is_at_infinity(P)) {
		sm2_jacobian_point_copy(R, P);
		return;
	}

	sm2_fp_sqr(T1, Z1);		//printf("T1 = Z1^2    = "); print_bn(T1);
	sm2_fp_sub(T2, X1, T1);	//printf("T2 = X1 - T1 = "); print_bn(T2);
	sm2_fp_add(T1, X1, T1);	//printf("T1 = X1 + T1 = "); print_bn(T1);
	sm2_fp_mul(T2, T2, T1);	//printf("T2 = T2 * T1 = "); print_bn(T2);
	sm2_fp_tri(T2, T2);		//printf("T2 =  3 * T2 = "); print_bn(T2);
	sm2_fp_dbl(Y3, Y1);		//printf("Y3 =  2 * Y1 = "); print_bn(Y3);
	sm2_fp_mul(Z3, Y3, Z1);	//printf("Z3 = Y3 * Z1 = "); print_bn(Z3);
	sm2_fp_sqr(Y3, Y3);		//printf("Y3 = Y3^2    = "); print_bn(Y3);
	sm2_fp_mul(T3, Y3, X1);	//printf("T3 = Y3 * X1 = "); print_bn(T3);
	sm2_fp_sqr(Y3, Y3);		//printf("Y3 = Y3^2    = "); print_bn(Y3);
	sm2_fp_div2(Y3, Y3);	//printf("Y3 = Y3/2    = "); print_bn(Y3);
	sm2_fp_sqr(X3, T2);		//printf("X3 = T2^2    = "); print_bn(X3);
	sm2_fp_dbl(T1, T3);		//printf("T1 =  2 * T1 = "); print_bn(T1);
	sm2_fp_sub(X3, X3, T1);	//printf("X3 = X3 - T1 = "); print_bn(X3);
	sm2_fp_sub(T1, T3, X3);	//printf("T1 = T3 - X3 = "); print_bn(T1);
	sm2_fp_mul(T1, T1, T2);	//printf("T1 = T1 * T2 = "); print_bn(T1);
	sm2_fp_sub(Y3, T1, Y3);	//printf("Y3 = T1 - Y3 = "); print_bn(Y3);

	sm2_bn_copy(R->X, X3);
	sm2_bn_copy(R->Y, Y3);
	sm2_bn_copy(R->Z, Z3);

				//printf("X3 = "); print_bn(R->X);
				//printf("Y3 = "); print_bn(R->Y);
				//printf("Z3 = "); print_bn(R->Z);

}

void sm2_jacobian_point_add(SM2_JACOBIAN_POINT *R, const SM2_JACOBIAN_POINT *P, const SM2_JACOBIAN_POINT *Q)
{
	const uint64_t *X1 = P->X;
	const uint64_t *Y1 = P->Y;
	const uint64_t *Z1 = P->Z;
	const uint64_t *x2 = Q->X;
	const uint64_t *y2 = Q->Y;
	SM2_BN T1;
	SM2_BN T2;
	SM2_BN T3;
	SM2_BN T4;
	SM2_BN X3;
	SM2_BN Y3;
	SM2_BN Z3;

	if (sm2_jacobian_point_is_at_infinity(Q)) {
		sm2_jacobian_point_copy(R, P);
		return;
	}

	if (sm2_jacobian_point_is_at_infinity(P)) {
		sm2_jacobian_point_copy(R, Q);
		return;
	}

	assert(sm2_bn_is_one(Q->Z));

	sm2_fp_sqr(T1, Z1);
	sm2_fp_mul(T2, T1, Z1);
	sm2_fp_mul(T1, T1, x2);
	sm2_fp_mul(T2, T2, y2);
	sm2_fp_sub(T1, T1, X1);
	sm2_fp_sub(T2, T2, Y1);
	if (sm2_bn_is_zero(T1)) {
		if (sm2_bn_is_zero(T2)) {
			SM2_JACOBIAN_POINT _Q, *Q = &_Q;
			sm2_jacobian_point_set_xy(Q, x2, y2);

			sm2_jacobian_point_dbl(R, Q);
			return;
		} else {
			sm2_jacobian_point_set_infinity(R);
			return;
		}
	}
	sm2_fp_mul(Z3, Z1, T1);
	sm2_fp_sqr(T3, T1);
	sm2_fp_mul(T4, T3, T1);
	sm2_fp_mul(T3, T3, X1);
	sm2_fp_dbl(T1, T3);
	sm2_fp_sqr(X3, T2);
	sm2_fp_sub(X3, X3, T1);
	sm2_fp_sub(X3, X3, T4);
	sm2_fp_sub(T3, T3, X3);
	sm2_fp_mul(T3, T3, T2);
	sm2_fp_mul(T4, T4, Y1);
	sm2_fp_sub(Y3, T3, T4);

	sm2_bn_copy(R->X, X3);
	sm2_bn_copy(R->Y, Y3);
	sm2_bn_copy(R->Z, Z3);
}

void sm2_jacobian_point_sub(SM2_JACOBIAN_POINT *R, const SM2_JACOBIAN_POINT *P, const SM2_JACOBIAN_POINT *Q)
{
	SM2_JACOBIAN_POINT _T, *T = &_T;
	sm2_jacobian_point_neg(T, Q);
	sm2_jacobian_point_add(R, P, T);
}

void sm2_jacobian_point_mul(SM2_JACOBIAN_POINT *R, const SM2_BN k, const SM2_JACOBIAN_POINT *P)
{
	char bits[257] = {0};
	SM2_JACOBIAN_POINT _Q, *Q = &_Q;
	SM2_JACOBIAN_POINT _T, *T = &_T;
	int i;

	// FIXME: point_add need affine, so we can not use point_add
	if (!sm2_bn_is_one(P->Z)) {
		SM2_BN x;
		SM2_BN y;
		sm2_jacobian_point_get_xy(P, x, y);
		sm2_jacobian_point_set_xy(T, x, y);
		P = T;
	}

	sm2_jacobian_point_set_infinity(Q);
	sm2_bn_to_bits(k, bits);
	for (i = 0; i < 256; i++) {
		sm2_jacobian_point_dbl(Q, Q);
		if (bits[i] == '1') {
			sm2_jacobian_point_add(Q, Q, P);
		}
	}
	sm2_jacobian_point_copy(R, Q);
}

void sm2_jacobian_point_to_bytes(const SM2_JACOBIAN_POINT *P, uint8_t out[64])
{
	SM2_BN x;
	SM2_BN y;
	sm2_jacobian_point_get_xy(P, x, y);
	sm2_bn_to_bytes(x, out);
	sm2_bn_to_bytes(y, out + 32);
}

void sm2_jacobian_point_from_bytes(SM2_JACOBIAN_POINT *P, const uint8_t in[64])
{
	sm2_bn_from_bytes(P->X, in);
	sm2_bn_from_bytes(P->Y, in + 32);
	sm2_bn_set_word(P->Z, 1);
	/* should we check if sm2_jacobian_point_is_on_curve */
}

#ifdef USE_SM2_GCACHE
void sm2_init_cache(SM2_JACOBIAN_POINT cache[][256], const SM2_JACOBIAN_POINT *G)
{
	int i, j, k, m;
	SM2_JACOBIAN_POINT cache2[8], *P;
	SM2_JACOBIAN_POINT _Q, *Q = &_Q;
	SM2_JACOBIAN_POINT _T, *T = &_T;
	sm2_jacobian_point_copy(T, G);

	for (i = 0; i < 32; i++) {
		for (k = 0; k < 8; k++) {
			sm2_jacobian_point_copy(cache2 + k, T);
			sm2_jacobian_point_dbl(T, T);
			if (!sm2_bn_is_one(T->Z)) {
				SM2_BN x, y;
				sm2_jacobian_point_get_xy(T, x, y);
				sm2_jacobian_point_set_xy(T, x, y);
			}
		}
		for (j = 0; j < 256; j++) {
			sm2_jacobian_point_set_infinity(Q);
			for (m = j, k = 0; m && k < 8; k++) {
				if (m & 0x1) {
					P = cache2 + k;
					sm2_jacobian_point_add(Q, Q, P);
				}
				m >>= 1;
			}
			if (!sm2_jacobian_point_is_at_infinity(Q) && !sm2_bn_is_one(Q->Z)) {
				SM2_BN x, y;
				sm2_jacobian_point_get_xy(Q, x, y);
				sm2_jacobian_point_set_xy(Q, x, y);
			}
			sm2_jacobian_point_copy(&cache[i][j], Q);
		}
	}
}

void sm2_jacobian_point_fastmul_generator(SM2_JACOBIAN_POINT *R, const uint8_t k[32])
{
	static SM2_JACOBIAN_POINT SM2_JPOINT_GCACHE[32][256];
	static int SM2_GCACHE_INITED = 0;
	int i;
	SM2_JACOBIAN_POINT *P;
	SM2_JACOBIAN_POINT _Q, *Q = &_Q;

	// Init the cache, size: 32 * 256
	if (SM2_GCACHE_INITED == 0) {
		sm2_init_cache(SM2_JPOINT_GCACHE, SM2_G);
		SM2_GCACHE_INITED = 1;
	}

	sm2_jacobian_point_set_infinity(Q);
	for (i = 31; i >= 0; i--) {
		P = SM2_JPOINT_GCACHE[31 - i] + k[i];
		sm2_jacobian_point_add(Q, Q, P);
	}

	sm2_jacobian_point_copy(R, Q);
}
#endif

void sm2_jacobian_point_mul_generator(SM2_JACOBIAN_POINT *R, const SM2_BN k)
{
#ifdef USE_SM2_GCACHE
	uint8_t _k[32];
	sm2_bn_to_bytes(k, _k);
	sm2_jacobian_point_fastmul_generator(R, _k);
#else
	sm2_jacobian_point_mul(R, k, SM2_G);
#endif
}

/* R = t * P + s * G */
void sm2_jacobian_point_mul_sum(SM2_JACOBIAN_POINT *R, const SM2_BN t, const SM2_JACOBIAN_POINT *P, const SM2_BN s)
{
	SM2_JACOBIAN_POINT _sG, *sG = &_sG;
	SM2_BN x;
	SM2_BN y;

	/* T = s * G */
	sm2_jacobian_point_mul_generator(sG, s);

	// R = t * P
	sm2_jacobian_point_mul(R, t, P);
	sm2_jacobian_point_get_xy(R, x, y);
	sm2_jacobian_point_set_xy(R, x, y);

	// R = R + T
	sm2_jacobian_point_add(R, sG, R);
}

void sm2_jacobian_point_from_hex(SM2_JACOBIAN_POINT *P, const char hex[64 * 2])
{
	sm2_bn_from_hex(P->X, hex);
	sm2_bn_from_hex(P->Y, hex + 64);
	sm2_bn_set_one(P->Z);
}

int sm2_jacobian_point_equ_hex(const SM2_JACOBIAN_POINT *P, const char hex[128])
{
	SM2_BN x;
	SM2_BN y;
	SM2_JACOBIAN_POINT _T, *T = &_T;

	sm2_jacobian_point_get_xy(P, x, y);
	sm2_jacobian_point_from_hex(T, hex);

	return (sm2_bn_cmp(x, T->X) == 0) && (sm2_bn_cmp(y, T->Y) == 0);
}

int sm2_point_is_on_curve(const SM2_POINT *P)
{
	SM2_JACOBIAN_POINT T;
	sm2_jacobian_point_from_bytes(&T, (const uint8_t *)P);
	return sm2_jacobian_point_is_on_curve(&T);
}

int sm2_point_is_at_infinity(const SM2_POINT *P)
{
	return mem_is_zero((uint8_t *)P, sizeof(SM2_POINT));
}

int sm2_point_from_x(SM2_POINT *P, const uint8_t x[32], int y)
{
	SM2_BN _x, _y, _g, _z;
	sm2_bn_from_bytes(_x, x);

	// g = x^3 - 3x + b = (x^2 - 3)*x + b
	sm2_fp_sqr(_g, _x);
	sm2_fp_sub(_g, _g, SM2_THREE);
	sm2_fp_mul(_g, _g, _x);
	sm2_fp_add(_g, _g, SM2_B);

	// y = g^(u + 1) mod p, u = (p - 3)/4
	sm2_fp_exp(_y, _g, SM2_U_PLUS_ONE);

	// z = y^2 mod p
	sm2_fp_sqr(_z, _y);
	if (sm2_bn_cmp(_z, _g)) {
		error_print();
		return -1;
	}

	if ((y == 0x02 && sm2_bn_is_odd(_y)) || ((y == 0x03) && !sm2_bn_is_odd(_y))) {
		sm2_fp_neg(_y, _y);
	}

	sm2_bn_to_bytes(_x, P->x);
	sm2_bn_to_bytes(_y, P->y);

	sm2_bn_clean(_x);
	sm2_bn_clean(_y);
	sm2_bn_clean(_g);
	sm2_bn_clean(_z);

	if (sm2_point_is_on_curve(P) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_point_from_xy(SM2_POINT *P, const uint8_t x[32], const uint8_t y[32])
{
	memcpy(P->x, x, 32);
	memcpy(P->y, y, 32);
	return sm2_point_is_on_curve(P);
}

int sm2_point_add(SM2_POINT *R, const SM2_POINT *P, const SM2_POINT *Q)
{
	SM2_JACOBIAN_POINT P_;
	SM2_JACOBIAN_POINT Q_;

	sm2_jacobian_point_from_bytes(&P_, (uint8_t *)P);
	sm2_jacobian_point_from_bytes(&Q_, (uint8_t *)Q);
	sm2_jacobian_point_add(&P_, &P_, &Q_);
	sm2_jacobian_point_to_bytes(&P_, (uint8_t *)R);

	return 1;
}

int sm2_point_sub(SM2_POINT *R, const SM2_POINT *P, const SM2_POINT *Q)
{
	SM2_JACOBIAN_POINT P_;
	SM2_JACOBIAN_POINT Q_;

	sm2_jacobian_point_from_bytes(&P_, (uint8_t *)P);
	sm2_jacobian_point_from_bytes(&Q_, (uint8_t *)Q);
	sm2_jacobian_point_sub(&P_, &P_, &Q_);
	sm2_jacobian_point_to_bytes(&P_, (uint8_t *)R);

	return 1;
}

int sm2_point_neg(SM2_POINT *R, const SM2_POINT *P)
{
	SM2_JACOBIAN_POINT P_;

	sm2_jacobian_point_from_bytes(&P_, (uint8_t *)P);
	sm2_jacobian_point_neg(&P_, &P_);
	sm2_jacobian_point_to_bytes(&P_, (uint8_t *)R);

	return 1;
}

int sm2_point_dbl(SM2_POINT *R, const SM2_POINT *P)
{
	SM2_JACOBIAN_POINT P_;

	sm2_jacobian_point_from_bytes(&P_, (uint8_t *)P);
	sm2_jacobian_point_dbl(&P_, &P_);
	sm2_jacobian_point_to_bytes(&P_, (uint8_t *)R);

	return 1;
}

int sm2_point_mul(SM2_POINT *R, const uint8_t k[32], const SM2_POINT *P)
{
	SM2_BN _k;
	SM2_JACOBIAN_POINT _P;

	sm2_bn_from_bytes(_k, k);
	sm2_jacobian_point_from_bytes(&_P, (uint8_t *)P);
	sm2_jacobian_point_mul(&_P, _k, &_P);
	sm2_jacobian_point_to_bytes(&_P, (uint8_t *)R);

	sm2_bn_clean(_k);
	return 1;
}

int sm2_point_mul_generator(SM2_POINT *R, const uint8_t k[32])
{
	SM2_BN _k;
	SM2_JACOBIAN_POINT _R;

#ifdef USE_SM2_GCACHE
	sm2_jacobian_point_fastmul_generator(&_R, k);
#else
	sm2_bn_from_bytes(_k, k);
	sm2_jacobian_point_mul_generator(&_R, _k);
	sm2_bn_clean(_k);
#endif
	sm2_jacobian_point_to_bytes(&_R, (uint8_t *)R);

	return 1;
}

int sm2_point_mul_sum(SM2_POINT *R, const uint8_t k[32], const SM2_POINT *P, const uint8_t s[32])
{
	SM2_BN _k;
	SM2_JACOBIAN_POINT _P;
	SM2_BN _s;

	sm2_bn_from_bytes(_k, k);
	sm2_jacobian_point_from_bytes(&_P, (uint8_t *)P);
	sm2_bn_from_bytes(_s, s);
	sm2_jacobian_point_mul_sum(&_P, _k, &_P, _s);
	sm2_jacobian_point_to_bytes(&_P, (uint8_t *)R);

	sm2_bn_clean(_k);
	sm2_bn_clean(_s);
	return 1;
}

int sm2_point_print(FILE *fp, int fmt, int ind, const char *label, const SM2_POINT *P)
{
	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	format_bytes(fp, fmt, ind, "x", P->x, 32);
	format_bytes(fp, fmt, ind, "y", P->y, 32);
	return 1;
}

void sm2_point_to_compressed_octets(const SM2_POINT *P, uint8_t out[33])
{
	*out++ = (P->y[31] & 0x01) ? 0x03 : 0x02;
	memcpy(out, P->x, 32);
}

void sm2_point_to_uncompressed_octets(const SM2_POINT *P, uint8_t out[65])
{
	*out++ = 0x04;
	memcpy(out, P, 64);
}

int sm2_point_from_octets(SM2_POINT *P, const uint8_t *in, size_t inlen)
{
	if ((*in == 0x02 || *in == 0x03) && inlen == 33) {
		if (sm2_point_from_x(P, in + 1, *in) != 1) {
			error_print();
			return -1;
		}
	} else if (*in == 0x04 && inlen == 65) {
		if (sm2_point_from_xy(P, in + 1, in + 33) != 1) {
			error_print();
			return -1;
		}
	} else {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_point_to_der(const SM2_POINT *P, uint8_t **out, size_t *outlen)
{
	uint8_t octets[65];
	if (!P) {
		return 0;
	}
	sm2_point_to_uncompressed_octets(P, octets);
	if (asn1_octet_string_to_der(octets, sizeof(octets), out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_point_from_der(SM2_POINT *P, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_octet_string_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (dlen != 65) {
		error_print();
		return -1;
	}
	if (sm2_point_from_octets(P, d, dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_point_from_hash(SM2_POINT *R, const uint8_t *data, size_t datalen)
{
	SM2_BN u;
	SM2_Fp x;
	SM2_Fp y;
	SM2_Fp s;
	SM2_Fp s_;
	uint8_t dgst[32];

	// u = (p + 1)/4
	sm2_bn_add(u, SM2_P, SM2_ONE);
	sm2_bn_rshift(u, u, 2);

	do {
		sm3_digest(data, datalen, dgst);

		sm2_bn_from_bytes(x, dgst);
		if (sm2_bn_cmp(x, SM2_P) >= 0) {
			sm2_bn_sub(x, x, SM2_P);
		}

		// s = y^2 = x^3 + a*x + b
		sm2_fp_sqr(s, x);
		sm2_fp_sub(s, s, SM2_THREE);
		sm2_fp_mul(s, s, x);
		sm2_fp_add(s, s, SM2_B);

		// y = s^((p+1)/4) = (sqrt(s) (mod p))
		sm2_fp_exp(y, s, u);
		sm2_fp_sqr(s_, y);

		data = dgst;
		datalen = sizeof(dgst);

	} while (sm2_bn_cmp(s, s_) != 0);

	sm2_bn_to_bytes(x, R->x);
	sm2_bn_to_bytes(y, R->y);
	return 1;
}

