/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <gmssl/hex.h>
#include <gmssl/asn1.h>
#include <gmssl/error.h>


static void print_buf(const uint8_t *a, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++) {
		printf("%02x ", a[i]);
	}
	printf("\n");
}

static void print_integer(const uint8_t *a, size_t alen)
{
	size_t i;
	printf("integer = ");
	for (i = 0; i < alen; i++) {
		printf("%02x", a[i]);
	}
	printf("\n");
}

static void print_bits(const uint8_t *bits, size_t nbits)
{
	size_t i;
	printf("bits (%zu) = ", nbits);
	for (i = 0; i < (nbits + 7)/8; i++) {
		printf("%02x", bits[i]);
	}
	printf("\n");
}

static void print_octets(const uint8_t *o, size_t olen)
{
	size_t i;
	printf("octets (%zu) = ", olen);
	for (i = 0; i < olen; i++) {
		printf("%02x", o[i]);
	}
	printf("\n");
}

static int test_asn1_tag(void)
{
    int tag;
    format_print(stderr, 0, 0, "Testing all tag values from 0 to 255:\n");
    for (tag = 0; tag <= 255; tag++) {
        const char *name = asn1_tag_name(tag);
        if (name) {
            format_print(stderr, 0, 4, "%s (0x%02x)\n", name, tag);
        } else {
            format_print(stderr, 0, 4, "Unknown Tag (0x%02x)\n", tag);
        }
    }
    printf("%s() ok\n", __FUNCTION__);
    return 1;
}

static int test_asn1_length(void)
{
	size_t tests[] = {
		0,
		5,
		127,
		128,
		256,
		344,
		65537,
		1<<23,
		INT_MAX, // INT_MAX = 2^31 - 1
		//(size_t)1<<31, // default int value of (1<<31) is -2^31, 2^31 is larger than the INT_MAX limit
	};
	size_t length;
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	size_t i;

	format_print(stderr, 0, 0, "Length:\n");
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (asn1_length_to_der(tests[i], &p, &len) != 1) {
			error_print();
			return -1;
		}
		format_bytes(stderr, 0, 4, "", buf, len);
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		int ret;
		ret = asn1_length_from_der(&length, &cp, &len);
		if (ret != 1 && ret != -2) {
			error_print();
			return -1;
		}
		if (length != tests[i]) {
			error_print();
			return -1;
		}
		format_print(stderr, 0, 4, "%zd\n", length);
	}
	if (len != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_asn1_length_from_ber(void)
{
	char *tests[] = {
		"80",
		"8100",
		"8101",
		"820000",
		"820001",
		"8200ff",
		"83001122",
		"8400ffffff",
		"850100000000",
	};
	uint8_t buf[16];
	const uint8_t *p;
	size_t a, len, i;

	for (i = 0; i < sizeof(tests)/sizeof(tests[i]); i++) {
		hex_to_bytes(tests[i], strlen(tests[i]), buf, &len);
		p = buf;
		len = (size_t)((uint64_t)1 << 33);
		if (asn1_length_from_der(&a, &p, &len) != -1) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_asn1_boolean(void)
{
	int tests[] = {0, 1};
	int val;
	uint8_t buf[128] = {0};
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	size_t i;

	format_print(stderr, 0, 0, "%s\n", asn1_tag_name(ASN1_TAG_BOOLEAN));
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (asn1_boolean_to_der(tests[i], &p, &len) != 1) {
			error_print();
			return -1;
		}
		format_bytes(stderr, 0, 4, "", buf, len);
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (asn1_boolean_from_der(&val, &cp, &len) != 1
			|| asn1_check(val == tests[i]) != 1) {
			error_print();
			return -1;
		}
		format_print(stderr, 0, 4, "%s\n", val ? "true" : "false");
	}
	if (len != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_asn1_int(void)
{
	int tests[] = {
		0,
		1,
		127,
		128,
		65535,
		65537,
		1<<23,
		1<<30,
	};
	int val;
	uint8_t buf[256] = {0};
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	size_t i;

	format_print(stderr, 0, 0, "%s\n", asn1_tag_name(ASN1_TAG_INTEGER));
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (asn1_int_to_der(tests[i], &p, &len) != 1) {
			error_print();
			return -1;
		}
		format_bytes(stderr, 0, 4, "", buf, len);
	}
	// integer == -1 (similar as NULL for other types) means do not encode
	if (asn1_int_to_der(-1, &p, &len) != 0) {
		error_print();
		return -1;
	}

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (asn1_int_from_der(&val, &cp, &len) != 1
			|| asn1_check(val == tests[i]) != 1) {
			error_print();
			return -1;
		}
		format_print(stderr, 0, 4, "%d\n", val);
	}
	if (len != 0) {
		error_print();
		return -1;
	}

	// test if val has been inited when return 0
	if (asn1_int_from_der(&val, &cp, &len) != 0) {
		error_print();
		return -1;
	}
	if (val != -1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_asn1_bits(void)
{
	int tests[] = {
		0x01,
		0x02,
		0x03,
		0x7f,
		0xfe,
		0xff,
		0xffff,
		0xfffff,
	};
	uint8_t der[] = {
		0x03,0x02,0x07,0x80,
		0x03,0x02,0x06,0x40,
		0x03,0x02,0x06,0xC0,
		0x03,0x02,0x01,0xFE,
		0x03,0x02,0x00,0x7F,
		0x03,0x02,0x00,0xFF,
		0x03,0x03,0x00,0xFF,0xFF,
		0x03,0x04,0x04,0xFF,0xFF,0xF0,
	};
	int bits;
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	size_t i;

	format_print(stderr, 0, 0, "%s\n", asn1_tag_name(ASN1_TAG_BIT_STRING));
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (asn1_bits_to_der(tests[i], &p, &len) != 1) {
			error_print();
			return -1;
		}
		format_bytes(stderr, 0, 4, "", buf, len);
	}
	if (sizeof(der) != len
		|| memcmp(der, buf, len) != 0) {
		error_print();
		return -1;
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (asn1_bits_from_der(&bits, &cp, &len) != 1
			|| asn1_check(bits == tests[i]) != 1) {
			error_print();
			return -1;
		}
		format_print(stderr, 0, 4, "%x\n", bits);
	}
	if (len != 0) {
		error_print();
		return -1;
	}
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_asn1_null(void)
{
	uint8_t buf[256] = {0};
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	size_t i;

	format_print(stderr, 0, 0, "NULL\n");
	for (i = 0; i < 3; i++) {
		if (asn1_null_to_der(&p, &len) != 1) {
			error_print();
			return -1;
		}
		format_bytes(stderr, 0, 4, "", buf, len);
	}
	for (i = 0; i < 3; i++) {
		if (asn1_null_from_der(&cp, &len) != 1) {
			error_print();
			return -1;
		}
		format_print(stderr, 0, 4, "%s\n", asn1_tag_name(ASN1_TAG_NULL));
	}
	if (asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_asn1_object_identifier(void)
{
	format_print(stderr, 0, 0, "%s\n", asn1_tag_name(ASN1_TAG_OBJECT_IDENTIFIER));

	// test 1
	{
		char *name = "sm2";
		uint32_t oid[] = { 1,2,156,10197,1,301 };
		uint8_t der[] = { 0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D };
		uint32_t nodes[32];
		size_t nodes_cnt;
		uint8_t buf[128];
		uint8_t *p = buf;
		const uint8_t *cp = buf;
		size_t len = 0;

		format_print(stderr, 0 ,4, "%s ", name);
		if (asn1_object_identifier_to_der(oid, sizeof(oid)/sizeof(int), &p, &len) != 1
			|| asn1_check(len == sizeof(der)) != 1
			|| asn1_check(memcmp(buf, der, sizeof(der)) == 0) != 1
			|| asn1_object_identifier_from_der(nodes, &nodes_cnt, &cp, &len) != 1
			|| asn1_length_is_zero(len) != 1
			|| asn1_object_identifier_equ(nodes, nodes_cnt, oid, sizeof(oid)/sizeof(int)) != 1) {
			fprintf(stderr, "failed\n");
			error_print();
			return -1;
		} else {
			printf("ok\n");
		}
	}

	// test 2
	{
		char *name = "x9.62-ecPublicKey";
		uint32_t oid[] = { 1,2,840,10045,2,1 };
		uint8_t der[] = { 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
		uint8_t buf[128];
		uint32_t nodes[32];
		size_t nodes_cnt;
		uint8_t *p = buf;
		const uint8_t *cp = buf;
		size_t len = 0;

		format_print(stderr, 0 ,4, "%s ", name);
		if (asn1_object_identifier_to_der(oid, sizeof(oid)/sizeof(int), &p, &len) != 1
			|| asn1_check(len == sizeof(der)) != 1
			|| asn1_check(memcmp(buf, der, sizeof(der)) == 0) != 1
			|| asn1_object_identifier_from_der(nodes, &nodes_cnt, &cp, &len) != 1
			|| asn1_length_is_zero(len) != 1
			|| asn1_object_identifier_equ(nodes, nodes_cnt, oid, sizeof(oid)/sizeof(int)) != 1) {
			fprintf(stderr, "failed\n");
			error_print();
			return -1;
		} else {
			printf("ok\n");
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_asn1_printable_string(void)
{
	char *tests[] = {
		"hello",
		"world",
		"Just do it", // string "Just do it!" include invalid '!'
	};
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	size_t i;

	format_print(stderr, 0, 0, "%s\n", asn1_tag_name(ASN1_TAG_PrintableString));
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (asn1_printable_string_to_der(tests[i], strlen(tests[i]), &p, &len) != 1) {
			error_print();
			return -1;
		}
		format_bytes(stderr, 0, 4, "", buf, len);
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		const char *d;
		size_t dlen;
		if (asn1_printable_string_from_der(&d, &dlen, &cp, &len) != 1
			|| strlen(tests[i]) != dlen
			|| memcmp(tests[i], d, dlen) != 0) {
			error_print();
			return -1;
		}
		format_string(stderr, 0, 4, "", (uint8_t *)d, dlen);
	}
	if (len != 0) {
		error_print();
		return -1;
	}
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_asn1_printable_string_check(void)
{
	char *printable_str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?";
	if (asn1_string_is_printable_string(printable_str, strlen(printable_str)) != 1) {
		error_print();
		return -1;
	}

	if (asn1_string_is_printable_string("a*b", 3) == 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_asn1_printable_string_case_ignore_match(void)
{
	if (asn1_printable_string_case_ignore_match("HELLO", 5, "WORLD", 5) == 1) {
		error_print();
		return -1;
	}

	if (asn1_printable_string_case_ignore_match("HELLO", 5, "HELLO", 5) != 1) {
		error_print();
		return -1;
	}
	if (asn1_printable_string_case_ignore_match("HELLO", 5, "hello", 5) != 1) {
		error_print();
		return -1;
	}
	if (asn1_printable_string_case_ignore_match("  HELLO", 7, "hello", 5) != 1) {
		error_print();
		return -1;
	}
	if (asn1_printable_string_case_ignore_match("  HELLO", 7, "hello   ", 8) != 1) {
		error_print();
		return -1;
	}
	if (asn1_printable_string_case_ignore_match(" A2b ", 5, "  a2B  ", 7) != 1) {
		error_print();
		return -1;
	}
	if (asn1_printable_string_case_ignore_match("     ", 5, "       ", 7) != 1) {
		error_print();
		return -1;
	}
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_asn1_utf8_string(void)
{
	char *tests[] = {
		"hello",
		"world",
		"Just do it!",
	};
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	size_t i;

	format_print(stderr, 0, 0, "%s\n", asn1_tag_name(ASN1_TAG_UTF8String));
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (asn1_utf8_string_to_der(tests[i], strlen(tests[i]), &p, &len) != 1) {
			error_print();
			return -1;
		}
		format_bytes(stderr, 0, 4, "", buf, len);
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		const char *d;
		size_t dlen;
		if (asn1_utf8_string_from_der(&d, &dlen, &cp, &len) != 1
			|| strlen(tests[i]) != dlen
			|| memcmp(tests[i], d, dlen) != 0) {
			error_print();
			return -1;
		}
		format_string(stderr, 0, 4, "", (uint8_t *)d, dlen);
	}
	if (len != 0) {
		error_print();
		return -1;
	}
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_asn1_ia5_string(void)
{
	char *tests[] = {
		"hello",
		"world",
		"Just do it!",
	};
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	size_t i;

	format_print(stderr, 0, 0, "%s\n", asn1_tag_name(ASN1_TAG_IA5String));
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (asn1_ia5_string_to_der(tests[i], strlen(tests[i]), &p, &len) != 1) {
			error_print();
			return -1;
		}
		format_bytes(stderr, 0, 4, "", buf, len);
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		const char *d;
		size_t dlen;
		if (asn1_ia5_string_from_der(&d, &dlen, &cp, &len) != 1
			|| strlen(tests[i]) != dlen
			|| memcmp(tests[i], d, dlen) != 0) {
			error_print();
			return -1;
		}
		format_string(stderr, 0, 4, "", (uint8_t *)d, dlen);
	}
	if (len != 0) {
		error_print();
		return -1;
	}
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_time(void)
{
	time_t tval = 0;
	printf("%s", ctime(&tval));
	time(&tval);
	printf("%s", ctime(&tval));

	printf("%08x%08x\n", (uint32_t)(tval >> 32), (uint32_t)tval);

	return 1;
}

static int test_asn1_time(void)
{
	time_t tests[] = {
		0,
		31*86400,
		(31+28)*86400,
	 };
	char *utc_time[] = {
		"700101000000Z",
		"700201000000Z",
		"700301000000Z",
	};
	char *gen_time[] = {
		"19700101000000Z",
		"19700201000000Z",
		"19700301000000Z",
	};
	time_t cur = time(NULL);
	time_t ts;
	char str[16] = {0};
	int i;

	if (asn1_time_to_str(0, cur, str) != 1
		|| asn1_time_from_str(0, &ts, str) != 1
		|| ts != cur) {
		error_print();
		return -1;
	}

	if (asn1_time_to_str(1, cur, str) != 1
		|| asn1_time_from_str(1, &ts, str) != 1
		|| ts != cur) {
		error_print();
		return -1;
	}

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		memset(str, 0, sizeof(str));
		if (asn1_time_to_str(1, tests[i], str) != 1
			|| strcmp(str, utc_time[i]) != 0) {
			error_print();
			return -1;
		}

		memset(str, 0, sizeof(str));
		if (asn1_time_to_str(0, tests[i], str) != 1
			|| strcmp(str, gen_time[i]) != 0) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_asn1_time_limits(void)
{
	char *tests[] = {
		"20491231235959Z",
		"20500101000000Z",
		"99991231235959Z",
	};
	size_t i;

	time_t tv[sizeof(tests)/sizeof(tests[0])];
	char str[16] = {0};

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (asn1_time_from_str(0, &tv[i], tests[i]) != 1) {
			error_print();
			return -1;
		}
		fprintf(stderr, "    %s: %lld\n", tests[i], (long long)tv[i]);
	}
	if (tv[0] + 1 != tv[1]) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_asn1_utc_time(void)
{
	time_t tests[] = {
		0,
		0,
		1<<30,
	};
	time_t tv;
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	size_t i;

	time(&tests[1]);

	format_print(stderr, 0, 0, "%s\n", asn1_tag_name(ASN1_TAG_UTCTime));
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (asn1_utc_time_to_der(tests[i], &p, &len) != 1) {
			error_print();
			return -1;
		}
		format_bytes(stderr, 0, 4, "", buf, len);
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (asn1_utc_time_from_der(&tv, &cp, &len) != 1
			|| asn1_check(tv == tests[i]) != 1) {
			error_print();
			return -1;
		}
		format_print(stderr, 0, 4, "%s", ctime(&tv));
	}
	if (len != 0) {
		error_print();
		return -1;
	}
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_asn1_generalized_time(void)
{
	time_t tests[] = {
		0,
		1<<30,
	};
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	size_t i;

	time(&tests[0]);

	format_print(stderr, 0, 0, "%s\n", asn1_tag_name(ASN1_TAG_GeneralizedTime));
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (asn1_generalized_time_to_der(tests[i], &p, &len) != 1) {
			error_print();
			return -1;
		}
		format_bytes(stderr, 0, 4, "", buf, len);
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		time_t tv;
		if (asn1_generalized_time_from_der(&tv, &cp, &len) != 1
			|| asn1_check(tv == tests[i]) != 1) {
			error_print();
			return -1;
		}
		format_print(stderr, 0, 4, "%s", ctime(&tv));
	}
	if (len != 0) {
		error_print();
		return -1;
	}
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_asn1_from_der_null_args(void)
{
	uint8_t buf[100];
	const uint8_t *cp = NULL;
	size_t len = 100;

	int val;
	const char *str;
	size_t dlen;
	time_t t;
	uint32_t nodes[32];
	size_t nodes_cnt;

	fprintf(stderr, "%s: *inlen = 0\n", __FUNCTION__);
	cp = buf;
	len = 0;
	if (asn1_boolean_from_der(&val, &cp, &len) != 0) { error_print(); return -1; }
	if (asn1_int_from_der(&val, &cp, &len)  != 0) { error_print(); return -1; }
	if (asn1_bits_from_der(&val, &cp, &len) != 0) { error_print(); return -1; }
	if (asn1_null_from_der(&cp, &len) != 0) { error_print(); return -1; }
	if (asn1_object_identifier_from_der(nodes, &nodes_cnt, &cp, &len) != 0) { error_print(); return -1; }
	if (asn1_utf8_string_from_der(&str, &dlen, &cp, &len) != 0) { error_print(); return -1; }
	if (asn1_printable_string_from_der(&str, &dlen, &cp, &len) != 0) { error_print(); return -1; }
	if (asn1_ia5_string_from_der(&str, &dlen, &cp, &len) != 0) { error_print(); return -1; }
	if (asn1_utc_time_from_der(&t, &cp, &len) != 0) { error_print(); return -1; }
	if (asn1_generalized_time_from_der(&t, &cp, &len) != 0) { error_print(); return -1; }
	fprintf(stderr, "%s: result = NULL\n", __FUNCTION__);

	cp = NULL;
	len = 100;
	if (asn1_boolean_from_der(NULL, &cp, &len) != -1) { error_print(); return -1; }
	if (asn1_int_from_der(NULL, &cp, &len)  != -1) { error_print(); return -1; }
	if (asn1_bits_from_der(NULL, &cp, &len) != -1) { error_print(); return -1; }
	//if (asn1_null_from_der(&cp, &len) != -1) { error_print(); return -1; }
	if (asn1_object_identifier_from_der(NULL, &nodes_cnt, &cp, &len) != -1) { error_print(); return -1; }
	if (asn1_utf8_string_from_der(NULL, &dlen, &cp, &len) != -1) { error_print(); return -1; }
	if (asn1_printable_string_from_der(NULL, &dlen, &cp, &len) != -1) { error_print(); return -1; }
	if (asn1_ia5_string_from_der(NULL, &dlen, &cp, &len) != -1) { error_print(); return -1; }
	if (asn1_utc_time_from_der(NULL, &cp, &len) != -1) { error_print(); return -1; }
	if (asn1_generalized_time_from_der(NULL, &cp, &len) != -1) { error_print(); return -1; }

	fprintf(stderr, "%s: *inlen = 0\n", __FUNCTION__);
	cp = buf;
	len = 0;
	if (asn1_boolean_from_der(&val, &cp, &len) != 0) { error_print(); return -1; }
	fprintf(stderr, "%s: in = NULL\n", __FUNCTION__);
	len = 100;
	if (asn1_boolean_from_der(&val, NULL, &len) != -1) { error_print(); return -1; }
	if (asn1_int_from_der(&val, NULL, &len)  != -1) { error_print(); return -1; }
	if (asn1_bits_from_der(&val, NULL, &len) != -1) { error_print(); return -1; }
	if (asn1_null_from_der(NULL, &len) != -1) { error_print(); return -1; }
	if (asn1_object_identifier_from_der(nodes, &nodes_cnt, NULL, &len) != -1) { error_print(); return -1; }
	if (asn1_utf8_string_from_der(&str, &dlen, NULL, &len) != -1) { error_print(); return -1; }
	if (asn1_printable_string_from_der(&str, &dlen, NULL, &len) != -1) { error_print(); return -1; }
	if (asn1_ia5_string_from_der(&str, &dlen, NULL, &len) != -1) { error_print(); return -1; }
	if (asn1_utc_time_from_der(&t, NULL, &len) != -1) { error_print(); return -1; }
	if (asn1_generalized_time_from_der(&t, NULL, &len) != -1) { error_print(); return -1; }

	fprintf(stderr, "%s: inlen = NULL\n", __FUNCTION__);
	cp = buf;
	if (asn1_boolean_from_der(&val, &cp, NULL) != -1) { error_print(); return -1; }
	if (asn1_int_from_der(&val, &cp, NULL)  != -1) { error_print(); return -1; }
	if (asn1_bits_from_der(&val, &cp, NULL) != -1) { error_print(); return -1; }
	if (asn1_null_from_der(&cp, NULL) != -1) { error_print(); return -1; }
	if (asn1_object_identifier_from_der(nodes, &nodes_cnt, &cp, NULL) != -1) { error_print(); return -1; }
	if (asn1_utf8_string_from_der(&str, &dlen, &cp, NULL) != -1) { error_print(); return -1; }
	if (asn1_printable_string_from_der(&str, &dlen, &cp, NULL) != -1) { error_print(); return -1; }
	if (asn1_ia5_string_from_der(&str, &dlen, &cp, NULL) != -1) { error_print(); return -1; }
	if (asn1_utc_time_from_der(&t, &cp, NULL) != -1) { error_print(); return -1; }
	if (asn1_generalized_time_from_der(&t, &cp, NULL) != -1) { error_print(); return -1; }

	fprintf(stderr, "%s: *in = NULL\n", __FUNCTION__);
	cp = NULL;
	len = 100;
	if (asn1_boolean_from_der(&val, &cp, &len) != -1) { error_print(); return -1; }
	if (asn1_int_from_der(&val, &cp, &len)  != -1) { error_print(); return -1; }
	if (asn1_bits_from_der(&val, &cp, &len) != -1) { error_print(); return -1; }
	if (asn1_null_from_der(&cp, &len) != -1) { error_print(); return -1; }
	if (asn1_object_identifier_from_der(nodes, &nodes_cnt, &cp, &len) != -1) { error_print(); return -1; }
	if (asn1_utf8_string_from_der(&str, &dlen, &cp, &len) != -1) { error_print(); return -1; }
	if (asn1_printable_string_from_der(&str, &dlen, &cp, &len) != -1) { error_print(); return -1; }
	if (asn1_ia5_string_from_der(&str, &dlen, &cp, &len) != -1) { error_print(); return -1; }
	if (asn1_utc_time_from_der(&t, &cp, &len) != -1) { error_print(); return -1; }
	if (asn1_generalized_time_from_der(&t, &cp, &len) != -1) { error_print(); return -1; }

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_asn1_tag() != 1) goto err;
	if (test_asn1_length() != 1) goto err;
	if (test_asn1_length_from_ber() != 1) goto err;
	if (test_asn1_boolean() != 1) goto err;
	if (test_asn1_int() != 1) goto err;
	if (test_asn1_bits() != 1) goto err;
	if (test_asn1_null() != 1) goto err;
	if (test_asn1_object_identifier() != 1) goto err;
	if (test_asn1_printable_string() != 1) goto err;
	if (test_asn1_printable_string_case_ignore_match() != 1) goto err;
	if (test_asn1_utf8_string() != 1) goto err;
	if (test_asn1_ia5_string() != 1) goto err;
	if (test_asn1_time() != 1) goto err;
	if (test_asn1_time_limits() != 1) goto err;
	if (test_asn1_utc_time() != 1) goto err;
	if (test_asn1_generalized_time() != 1) goto err;
	if (test_asn1_from_der_null_args() != 1) goto err;
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return -1;
}
