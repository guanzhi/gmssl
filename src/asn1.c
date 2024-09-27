/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


// https://www.obj-sys.com/asn1tutorial/node128.html

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <limits.h>
#include <time.h>
#include <ctype.h>
#include <gmssl/oid.h>
#include <gmssl/asn1.h>
#include <gmssl/error.h>
#include <gmssl/endian.h>


static const char *asn1_tag_index[] = {
	"[0]",  "[1]",  "[2]",  "[3]",  "[4]",  "[5]",  "[6]",  "[7]",  "[8]",  "[9]",
	"[10]", "[11]", "[12]", "[13]", "[14]", "[15]", "[16]", "[17]", "[18]", "[19]",
	"[20]", "[21]", "[22]", "[23]", "[24]", "[25]", "[26]", "[27]", "[28]", "[29]",
	"[30]", "[31]",
};

const char *asn1_tag_name(int tag)
{
	if (tag < 0 || tag > 0xff) {
		error_print();
		return NULL;
	}

	switch (tag & 0xc0) {
	case ASN1_TAG_CONTENT_SPECIFIC: return asn1_tag_index[tag & 0x1f];
	case ASN1_TAG_APPLICATION: return "Application";
	case ASN1_TAG_PRIVATE: return "Private";
	}

	switch (tag) {
	case ASN1_TAG_BOOLEAN: return "BOOLEAN";
	case ASN1_TAG_INTEGER: return "INTEGER";
	case ASN1_TAG_BIT_STRING: return "BIT STRING";
	case ASN1_TAG_OCTET_STRING: return "OCTET STRING";
	case ASN1_TAG_NULL: return "NULL";
	case ASN1_TAG_OBJECT_IDENTIFIER: return "OBJECT IDENTIFIER";
	case ASN1_TAG_ObjectDescriptor: return "ObjectDescriptor";
	case ASN1_TAG_EXTERNAL: return "EXTERNAL";
	case ASN1_TAG_REAL: return "REAL";
	case ASN1_TAG_ENUMERATED: return "ENUMERATED";
	case ASN1_TAG_EMBEDDED: return "EMBEDDED";
	case ASN1_TAG_UTF8String: return "UTF8String";
	case ASN1_TAG_RELATIVE_OID: return "RELATIVE_OID";
	case ASN1_TAG_NumericString: return "NumericString";
	case ASN1_TAG_PrintableString: return "PrintableString";
	case ASN1_TAG_TeletexString: return "TeletexString";
	case ASN1_TAG_VideotexString: return "VideotexString";
	case ASN1_TAG_IA5String: return "IA5String";
	case ASN1_TAG_UTCTime: return "UTCTime";
	case ASN1_TAG_GeneralizedTime: return "GeneralizedTime";
	case ASN1_TAG_GraphicString: return "GraphicString";
	case ASN1_TAG_VisibleString: return "VisibleString";
	case ASN1_TAG_GeneralString: return "GeneralString";
	case ASN1_TAG_UniversalString: return "UniversalString";
	case ASN1_TAG_CHARACTER_STRING: return "CHARACTER STRING";
	case ASN1_TAG_BMPString: return "BMPString";
	case ASN1_TAG_SEQUENCE: return "SEQUENCE";
	case ASN1_TAG_SET: return "SET";
	case ASN1_TAG_EXPLICIT: return "EXPLICIT";
	}

	error_print();
	return NULL;
}

// not in-use
int asn1_tag_is_cstring(int tag)
{
	switch (tag) {
	case ASN1_TAG_UTF8String:
	case ASN1_TAG_NumericString:
	case ASN1_TAG_PrintableString:
	case ASN1_TAG_TeletexString:
	case ASN1_TAG_IA5String:
	case ASN1_TAG_GeneralString:
		return 1;
	}
	return 0;
}

// not in-use
int asn1_tag_to_der(int tag, uint8_t **out, size_t *outlen)
{
	if (!outlen) {
		error_print();
		return -1;
	}
	if (out && *out) {
		*(*out)++ = (uint8_t)tag;
	}
	(*outlen)++;
	return 1;
}

// not in-use
int asn1_tag_from_der(int *tag, const uint8_t **in, size_t *inlen)
{
	if (!tag || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if (*inlen == 0) {
		return 0;
	}
	*tag = *(*in)++;
	(*inlen)--;
	return 1;
}

int asn1_tag_from_der_readonly(int *tag, const uint8_t **in, size_t *inlen)
{
	if (!tag || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if (*inlen == 0) {
		return 0;
	}
	*tag = **in;
	return 1;
}

int asn1_length_to_der(size_t len, uint8_t **out, size_t *outlen)
{
	if (len > INT_MAX) {
		error_print();
		return -1;
	}
	if (!outlen) {
		error_print();
		return -1;
	}

	if (len < 128) {
		if (out && *out) {
			*(*out)++ = (uint8_t)len;
		}
		(*outlen)++;

	} else {
		uint8_t buf[4];
		int nbytes;

		if (len < 256) nbytes = 1;
		else if (len < 65536) nbytes = 2;
		else if (len < (1 << 24)) nbytes = 3;
		else nbytes = 4;
		PUTU32(buf, (uint32_t)len);

		if (out && *out) {
			*(*out)++ = 0x80 + nbytes;
			memcpy(*out, buf + 4 - nbytes, nbytes);
			(*out) += nbytes;
		}
		(*outlen) += 1 + nbytes;
	}
	return 1;
}

int asn1_length_from_der(size_t *len, const uint8_t **in, size_t *inlen)
{
	if (!len || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}

	if (*inlen == 0) {
		error_print();
		return -1;
	}

	if (**in < 128) {
		*len = *(*in)++;
		(*inlen)--;

	} else {
		uint8_t buf[4] = {0};
		size_t nbytes  = *(*in)++ & 0x7f;
		(*inlen)--;

		if (nbytes < 1 || nbytes > 4) {
			error_print();
			return -1;
		}
		if (*inlen < nbytes) {
			error_print();
			return -1;
		}
		// make sure length is not in BER long presentation
		if (nbytes == 1 && **in < 0x80) {
			error_print();
			return -1;
		}
		if (nbytes > 1 && **in == 0) {
			error_print();
			return -1;
		}

		memcpy(buf + 4 - nbytes, *in, nbytes);
		*len = (size_t)GETU32(buf);
		*in += nbytes;
		*inlen -= nbytes;
	}

	// check if the left input is enough for reading (d,dlen)
	if (*inlen < *len) {
		error_print();
		return -2; // Special error for test_asn1_length() // TODO: fix asn1test.c test vector 			
	}
	return 1;
}

// asn1_data_to_der do not check the validity of data
int asn1_data_to_der(const uint8_t *data, size_t datalen, uint8_t **out, size_t *outlen)
{
	if (!outlen) {
		error_print();
		return -1;
	}
	if (datalen == 0) {
		return 0;
	}
	if (out && *out) {
		if (!data) {
			error_print();
			return -1;
		}
		memcpy(*out, data, datalen);
		*out += datalen;
	}
	*outlen += datalen;
	return 1;
}

// not in-use
int asn1_data_from_der(const uint8_t **data, size_t datalen, const uint8_t **in, size_t *inlen)
{
	if (!data || !datalen || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if (*inlen < datalen) {
		error_print();
		return -1;
	}
	*data = *in;
	*in += datalen;
	*inlen -= datalen;
	return 1;
}

int asn1_header_to_der(int tag, size_t dlen, uint8_t **out, size_t *outlen)
{
	if (!outlen) {
		error_print();
		return -1;
	}

	if (out && *out) {
		*(*out)++ = (uint8_t)tag;
	}
	(*outlen)++;

	(void)asn1_length_to_der(dlen, out, outlen);
	return 1;
}

int asn1_type_to_der(int tag, const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen)
{
	if (!outlen) {
		error_print();
		return -1;
	}

	if (!d) {
		if (dlen) {
			error_print();
			return -1;
		}
		return 0;
	}

	// tag
	if (out && *out) {
		*(*out)++ = (uint8_t)tag;
	}
	(*outlen)++;

	// length
	(void)asn1_length_to_der(dlen, out, outlen);

	// data
	if (out && *out) {
		memcpy(*out, d, dlen);
		*out += dlen;
	}
	*outlen += dlen;

	return 1;
}

int asn1_type_from_der(int tag, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen)
{
	if (!d || !dlen || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}

	// tag
	if (*inlen == 0 || **in != tag) {
		*d = NULL;
		*dlen = 0;
		return 0;
	}
	(*in)++;
	(*inlen)--;

	// length
	if (asn1_length_from_der(dlen, in, inlen) != 1) {
		error_print();
		return -1;
	}

	// data
	*d = *in;
	*in += *dlen;
	*inlen -= *dlen;
	return 1;
}

int asn1_nonempty_type_to_der(int tag, const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen)
{
	int ret;

	if (d && dlen == 0) {
		error_print();
		return -1;
	}
	if ((ret = asn1_type_to_der(tag, d, dlen, out, outlen)) != 1) {
		if (ret) error_print();
		return ret;
	}
	return 1;
}

int asn1_nonempty_type_from_der(int tag, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen)
{
	int ret;

	if ((ret = asn1_type_from_der(tag, d, dlen, in, inlen)) != 1) {
		if (ret) error_print();
		return ret;
	}
	if (*dlen == 0) {
		error_print();
		return -1;
	}
	return 1;
}

int asn1_any_type_from_der(int *tag, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen)
{
	if (!tag || !d || !dlen || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}

	if (*inlen == 0) {
		*tag = - 1;
		*d = NULL;
		*dlen = 0;
		return 0;
	}

	*tag = *(*in)++;
	(*inlen)--;

	if (asn1_length_from_der(dlen, in, inlen) != 1) {
		error_print();
		return -1;
	}

	*d = *in;
	*in += *dlen;
	*inlen -= *dlen;
	return 1;
}

// we need to check this is an asn.1 type
int asn1_any_to_der(const uint8_t *a, size_t alen, uint8_t **out, size_t *outlen)
{
	if (!outlen) {
		error_print();
		return -1;
	}

	if (!a) {
		if (a) {
			error_print();
			return -1;
		}
		return 0;
	}

	if (out && *out) {
		memcpy(*out, a, alen);
		*out += alen;
	}
	*outlen += alen;

	return 1;
}

int asn1_any_from_der(const uint8_t **a, size_t *alen, const uint8_t **in, size_t *inlen)
{
	int ret;
	int tag;
	const uint8_t *d;
	size_t dlen;

	if (!a || !alen || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	*a = *in;
	*alen = *inlen;

	if ((ret = asn1_any_type_from_der(&tag, &d, &dlen, in, inlen)) != 1) {
		if (ret) error_print();
		return ret;
	}
	*alen -= *inlen;

	return 1;
}

const char *asn1_boolean_name(int val)
{
	switch (val) {
	case 1: return "true";
	case 0: return "false";
	}
	return NULL;
}

int asn1_boolean_from_name(int *val, const char *name)
{
	if (strcmp(name, "true") == 0) {
		*val = 1;
		return 1;
	} else if (strcmp(name, "false") == 0) {
		*val = 0;
		return 1;
	}
	*val = -1;
	return -1;
}

int asn1_boolean_to_der_ex(int tag, int val, uint8_t **out, size_t *outlen)
{
	if (!outlen) {
		error_print();
		return -1;
	}

	if (val < 0) {
		return 0;
	}

	if (out && *out) {
		*(*out)++ = tag;
		*(*out)++ = 0x01;
		*(*out)++ = val ? 0xff : 0x00;
	}
	(*outlen) += 3;
	return 1;
}

int asn1_boolean_from_der_ex(int tag, int *val, const uint8_t **in, size_t *inlen)
{
	if (!val || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if (*inlen == 0 || (*in)[0] != tag) {
		*val = -1;
		return 0;
	}

	if (*inlen < 3) {
		error_print();
		return -1;
	}
	if ((*in)[1] != 0x01) {
		error_print();
		return -1;
	}

	if ((*in)[2] != ASN1_TRUE && (*in)[2] != ASN1_FALSE) {
		error_print();
		return -1;
	}
	*val = ((*in)[2] == ASN1_TRUE) ? 1 : 0;
	*in += 3;
	*inlen -= 3;
	return 1;
}

int asn1_integer_to_der_ex(int tag, const uint8_t *a, size_t alen, uint8_t **out, size_t *outlen)
{
	if (!outlen) {
		error_print();
		return -1;
	}

	if (!a) {
		return 0;
	}
	if (alen <= 0 || alen > INT_MAX) {
		error_print();
		return -1;
	}

	if (out && *out)
		*(*out)++ = tag;
	(*outlen)++;

	while (*a == 0 && alen > 1) {
		a++;
		alen--;
	}

	if (a[0] & 0x80) {
		asn1_length_to_der(alen + 1, out, outlen);
		if (out && *out) {
			*(*out)++ = 0x00;
			memcpy(*out, a, alen);
			(*out) += alen;
		}
		(*outlen) += 1 + alen;
	} else {
		asn1_length_to_der(alen, out ,outlen);
		if (out && *out) {
			memcpy(*out, a, alen);
			(*out) += alen;
		}
		(*outlen) += alen;
	}

	return 1;
}

int asn1_integer_from_der_ex(int tag, const uint8_t **a, size_t *alen, const uint8_t **in, size_t *inlen)
{
	size_t len;

	if (!a || !alen || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}

	// tag
	if (*inlen == 0 || **in != tag) {
		*a = NULL;
		*alen = 0;
		return 0;
	}
	(*in)++;
	(*inlen)--;

	// length (not zero)
	if (asn1_length_from_der(&len, in, inlen) != 1) {
		error_print();
		return -1;
	}
	if (len == 0) {
		error_print();
		return -1;
	}

	// check if ASN1_INTEGER is negative
	if (**in & 0x80) {
		error_print();
		return -1;
	}

	// remove leading zero
	if (**in == 0 && len > 1) {
		(*in)++;
		(*inlen)--;
		len--;

		// the following bit should be one
		if (((**in) & 0x80) == 0) {
			error_print();
			return -1;
		}
	}

	// no leading zeros
	if (**in == 0 && len > 1) {
		error_print();
		return -1;
	}

	// return integer bytes
	*a = *in;
	*alen = len;
	*in += len;
	*inlen -= len;

	return 1;
}

int asn1_int_to_der_ex(int tag, int a, uint8_t **out, size_t *outlen)
{
	uint8_t buf[4] = {0};
	size_t len = 0;

	if (a == -1) {
		return 0;
	}

	while (a > 0) {
		buf[3 - len] = a & 0xff;
		a >>= 8;
		len++;
	}
	if (!len) {
		len = 1;
	}

	if (asn1_integer_to_der_ex(tag, buf + 4 - len, len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int asn1_int_from_der_ex(int tag, int *a, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *p;
	size_t len;
	size_t i;

	if (!a || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}

	if ((ret = asn1_integer_from_der_ex(tag, &p, &len, in, inlen)) != 1) {
		if (ret < 0) error_print();
		else *a = -1;
		return ret;
	}
	if (len > sizeof(*a)) {
		error_print();
		return -1;
	}

	*a = 0;
	for (i = 0; i < len; i++) {
		*a = ((*a) << 8) | p[i];
	}
	if (*a < 0) {
		error_print();
		return -1;
	}
	return 1;
}

int asn1_bit_string_to_der_ex(int tag, const uint8_t *bits, size_t nbits, uint8_t **out, size_t *outlen)
{
	size_t nbytes = (nbits + 7) / 8;
	size_t unused_nbits = nbytes * 8 - nbits;

	if (!outlen) {
		error_print();
		return -1;
	}

	if (!bits) {
		if (nbits) {
			error_print();
			return -1;
		}
		return 0;
	}

	// tag
	if (out && *out) {
		*(*out)++ = tag;
	}
	(*outlen)++;

	// length
	(void)asn1_length_to_der(nbytes + 1, out, outlen);

	// unused num of bits
	if (out && *out) {
		*(*out)++ = (uint8_t)unused_nbits;
	}
	(*outlen)++;

	// bits
	if (out && *out) {
		memcpy(*out, bits, nbytes);
		*out += nbytes;
	}
	*outlen += nbytes;

	return 1;
}

int asn1_bit_string_from_der_ex(int tag, const uint8_t **bits, size_t *nbits, const uint8_t **in, size_t *inlen)
{
	size_t len;
	int unused_bits;

	if (!bits || !nbits || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}

	// tag
	if (*inlen == 0 || **in != tag) {
		*bits = NULL;
		*nbits = 0;
		return 0;
	}
	(*in)++;
	(*inlen)--;

	// length (min == 2)
	if (asn1_length_from_der(&len, in, inlen) != 1) {
		error_print();
		return -1;
	}
	if (len < 2) {
		error_print();
		return -1;
	}

	// unused_bits counter
	unused_bits = **in;
	if (unused_bits > 7) {
		error_print();
		return -1;
	}
	(*in)++;
	(*inlen)--;
	len--;

	// return bits
	*bits = *in;
	*nbits = (len << 3) - unused_bits;
	*in += len;
	*inlen -= len;

	return 1;
}

int asn1_bit_octets_to_der_ex(int tag, const uint8_t *octs, size_t nocts, uint8_t **out, size_t *outlen)
{
	int ret;
	if ((ret = asn1_bit_string_to_der_ex(tag, octs, nocts << 3, out, outlen)) != 1) {
		if (ret) error_print();
		return ret;
	}
	return 1;
}

int asn1_bit_octets_from_der_ex(int tag, const uint8_t **octs, size_t *nocts, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *bits;
	size_t nbits;

	if (!octs || !nocts) {
		error_print();
		return -1;
	}

	if ((ret = asn1_bit_string_from_der_ex(tag, &bits, &nbits, in, inlen)) != 1) {
		if (ret < 0) error_print();
		else {
			*octs = NULL;
			*nocts = 0;
		}
		return ret;
	}

	if (nbits % 8) {
		error_print();
		return -1;
	}
	*octs = bits;
	*nocts = nbits >> 3;
	return 1;
}

int asn1_bits_to_der_ex(int tag, int bits, uint8_t **out, size_t *outlen)
{
	size_t nbits = 0;
	uint8_t mask = 0x80;
	uint8_t buf[4] = {0};
	int i = 0;

	if (bits < 0) {
		return 0;
	}
	while (bits > 0) {
		if (bits & 1)
			buf[i] |= mask;
		mask >>= 1;
		bits >>= 1;
		nbits++;
		if (nbits % 8 == 0) {
			i++;
			mask = 0x80;
		}
	}
	if (!nbits) {
		nbits = 1;
	}

	if (asn1_bit_string_to_der_ex(tag, buf, nbits, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int asn1_bits_from_der_ex(int tag, int *bits, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *p;
	uint8_t c;
	size_t nbits;
	size_t i;

	if (!bits) {
		error_print();
		return -1;
	}

	if ((ret = asn1_bit_string_from_der_ex(tag, &p, &nbits, in, inlen)) != 1) {
		if (ret < 0) error_print();
		else *bits = -1;
		return ret;
	}

	if (nbits > 31) {
		error_print();
		return -1;
	}

	*bits = 0;
	for (i = 0; i < nbits; i++) {
		if (i % 8 == 0) {
			c = *p++;
		}
		*bits |= ((c & 0x80) >> 7) << i;
		c <<= 1;
	}
	return 1;
}

int asn1_bits_print(FILE *fp, int fmt, int ind, const char *label, const char **names, size_t names_cnt, int bits)
{
	size_t i;
	format_print(fp, fmt, ind, "%s: ", label);

	for (i = 0; i < names_cnt; i++) {
		if (bits & 0x01)
			fprintf(fp, "%s%s", names[i], bits >> 1 ? "," : "");
		bits >>= 1;
	}
	fprintf(fp, "\n");
	if (bits) {
		error_print();
		return -1;
	}
	return 1;
}

const char *asn1_null_name(void)
{
	return "null";
}

int asn1_null_to_der(uint8_t **out, size_t *outlen)
{
	if (!outlen) {
		error_print();
		return -1;
	}
	if (out && *out) {
		*(*out)++ = ASN1_TAG_NULL;
		*(*out)++ = 0x00;
	}
	*outlen += 2;
	return 1;
}

int asn1_null_from_der(const uint8_t **in, size_t *inlen)
{
	if (!in || !(*in) || !inlen) {
		error_print();
		return -1;
	}

	// tag
	if (*inlen == 0 || **in != ASN1_TAG_NULL) {
		return 0;
	}
	(*in)++;
	(*inlen)--;

	// value
	if (*inlen < 1) {
		error_print();
		return -1;
	}
	if (**in != 0x00) {
		error_print();
		return -1;
	}
	(*in)++;
	(*inlen)--;
	return 1;
}

static void asn1_oid_node_to_base128(uint32_t a, uint8_t **out, size_t *outlen)
{
	uint8_t buf[5];
	int n = 0;

	buf[n++] = a & 0x7f;
	a >>= 7;

	while (a) {
		buf[n++] = 0x80 | (a & 0x7f);
		a >>= 7;
	}

	while (n--) {
		if (out && *out) {
			*(*out)++ = buf[n];
		}
		(*outlen)++;
	}
}

static int asn1_oid_node_from_base128(uint32_t *a, const uint8_t **in, size_t *inlen)
{
	uint8_t buf[5];
	int n = 0;
	int i;

	for (;;) {
		if ((*inlen)-- < 1 || n >= 5) {
			error_print();
			return -1;
		}
		buf[n] = *(*in)++;
		if ((buf[n++] & 0x80) == 0) {
			break;
		}
	}

	// 32 - 7*4 = 4, so the first byte should be like 1000bbbb
	if (n == 5 && (buf[0] & 0x70)) {
		error_print();
		return -1;
	}

	*a = 0;
	for (i = 0; i < n; i++) {
		*a = ((*a) << 7) | (buf[i] & 0x7f);
	}

	return 1;
}

int asn1_object_identifier_to_octets(const uint32_t *nodes, size_t nodes_cnt, uint8_t *out, size_t *outlen)
{
	if (!nodes || !outlen) {
		error_print();
		return -1;
	}
	if (nodes_cnt < ASN1_OID_MIN_NODES || nodes_cnt > ASN1_OID_MAX_NODES) {
		error_print();
		return -1;
	}
	if (out) {
		*out++ = (uint8_t)(nodes[0] * 40 + nodes[1]);
	}
	(*outlen) = 1;
	nodes += 2;
	nodes_cnt -= 2;

	while (nodes_cnt--) {
		asn1_oid_node_to_base128(*nodes++, &out, outlen);
	}
	return 1;
}

int asn1_object_identifier_from_octets(uint32_t *nodes, size_t *nodes_cnt, const uint8_t *in, size_t inlen)
{
	if (!nodes_cnt || !in || !inlen) {
		error_print();
		return -1;
	}

	if (nodes) {
		*nodes++ = (*in) / 40;
		*nodes++ = (*in) % 40;
	}
	in++;
	inlen--;
	*nodes_cnt = 2;

	while (inlen) {
		uint32_t val;
		if (*nodes_cnt > ASN1_OID_MAX_NODES) {
			error_print();
			return -1;
		}
		if (asn1_oid_node_from_base128(&val, &in, &inlen) < 0) {
			error_print();
			return -1;
		}
		if (nodes) {
			*nodes++ = val;
		}
		(*nodes_cnt)++;
	}

	return 1;
}

int asn1_object_identifier_to_der_ex(int tag, const uint32_t *nodes, size_t nodes_cnt, uint8_t **out, size_t *outlen)
{
	uint8_t octets[ASN1_OID_MAX_OCTETS];
	size_t octetslen = 0;

	if (!outlen) {
		error_print();
		return -1;
	}
	if (!nodes) {
		if (nodes_cnt) {
			error_print();
			return -1;
		}
		return 0;
	}

	if (asn1_object_identifier_to_octets(nodes, nodes_cnt, octets, &octetslen) != 1) {
		error_print();
		return -1;
	}

	if (out && *out) {
		*(*out)++ = tag;
	}
	(*outlen)++;

	(void)asn1_length_to_der(octetslen, out, outlen);

	if (out && *out) {
		memcpy(*out, octets, octetslen);
		*out += octetslen;
	}
	*outlen += octetslen;
	return 1;
}

int asn1_object_identifier_from_der_ex(int tag, uint32_t *nodes, size_t *nodes_cnt,
	const uint8_t **in, size_t *inlen)
{
	size_t len;

	// unlike _from_octets(), _from_der() require output buffer
	if (!nodes || !nodes_cnt || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}

	// tag
	if (*inlen == 0 || **in != tag) {
		*nodes_cnt = 0;
		return 0;
	}
	(*in)++;
	(*inlen)--;

	// length (not zero)
	if (asn1_length_from_der(&len, in, inlen) != 1) {
		error_print();
		return -1;
	}
	if (len < ASN1_OID_MIN_OCTETS) {
		error_print();
		return -1;
	}

	// parse OID
	if (asn1_object_identifier_from_octets(nodes, nodes_cnt, *in, len) != 1) {
		error_print();
		return -1;
	}
	*in += len;
	*inlen -= len;

	return 1;
}

int asn1_object_identifier_equ(const uint32_t *a, size_t a_cnt, const uint32_t *b, size_t b_cnt)
{
	if (!a || a_cnt < ASN1_OID_MIN_NODES || a_cnt > ASN1_OID_MAX_NODES
		|| !b || b_cnt < ASN1_OID_MIN_NODES || b_cnt > ASN1_OID_MAX_NODES) {
		error_print();
		return 0; // _equ() should return 1 or 0
	}
	if (a_cnt != b_cnt || memcmp(a, b, b_cnt * sizeof(uint32_t))) {
		return 0;
	}
	return 1;
}

int asn1_object_identifier_print(FILE *fp, int format, int indent, const char *label, const char *name,
	const uint32_t *nodes, size_t nodes_cnt)
{
	size_t i;
	format_print(fp, format, indent, "%s: %s", label, name ? name : "(unknown)");
	if (nodes) {
		fprintf(fp, " (");
		for (i = 0; i < nodes_cnt - 1; i++) {
			fprintf(fp, "%d.", (int)nodes[i]);
		}
		fprintf(fp, "%d)", nodes[i]);
	}
	fprintf(fp, "\n");
	return 1;
}

const ASN1_OID_INFO *asn1_oid_info_from_name(const ASN1_OID_INFO *infos, size_t infos_cnt, const char *name)
{
	size_t i;

	if (!infos || !infos_cnt || !name) {
		error_print();
		return NULL;
	}
	for (i = 0; i < infos_cnt; i++) {
		if (strcmp(infos[i].name, name) == 0) {
			return &infos[i];
		}
	}
	return NULL;
}

const ASN1_OID_INFO *asn1_oid_info_from_oid(const ASN1_OID_INFO *infos, size_t infos_cnt, int oid)
{
	size_t i;

	if (!infos || !infos_cnt || oid < 0) {
		error_print();
		return NULL;
	}
	for (i = 0; i < infos_cnt; i++) {
		if (infos[i].oid == oid) {
			return &infos[i];
		}
	}
	return NULL;
}

int asn1_oid_info_from_der_ex(const ASN1_OID_INFO **info, uint32_t *nodes, size_t *nodes_cnt,
	const ASN1_OID_INFO *infos, size_t infos_cnt, const uint8_t **in, size_t *inlen)
{
	int ret;
	size_t i;

	if (!info) {
		error_print();
		return -1;
	}
	if ((ret = asn1_object_identifier_from_der(nodes, nodes_cnt, in, inlen)) != 1) {
		if (ret < 0) error_print();
		else *info = NULL;
		return ret;
	}

	for (i = 0; i < infos_cnt; i++) {
		if (*nodes_cnt == infos[i].nodes_cnt
			&& memcmp(nodes, infos[i].nodes, (*nodes_cnt) * sizeof(int)) == 0) {
			*info = &infos[i];
			return 1;
		}
	}

	// OID with correct encoding but in the (infos, infos_cnt) list
	*info = NULL;
	return 1;
}

int asn1_oid_info_from_der(const ASN1_OID_INFO **info, const ASN1_OID_INFO *infos, size_t count, const uint8_t **in, size_t *inlen)
{
	int ret;
	uint32_t nodes[ASN1_OID_MAX_NODES];
	size_t nodes_cnt;

	if ((ret = asn1_oid_info_from_der_ex(info, nodes, &nodes_cnt, infos, count, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (*info == NULL) {
		asn1_object_identifier_print(stderr, 0, 0, "Unknown OID", NULL, nodes, nodes_cnt);
		error_print();
		return -1;
	}
	return 1;
}

/*
utf-8 character encoding
 	1-byte: 0xxxxxxx
	2-byte: 110xxxxx 10xxxxxx
	3-byte: 1110xxxx 10xxxxxx 10xxxxxx
	4-byte: 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
*/
static int asn1_utf8char_from_bytes(uint32_t *c, const uint8_t **pin, size_t *pinlen)
{
	uint32_t utf8char;
	const uint8_t *in = *pin;
	size_t inlen = *pinlen;
	uint32_t utf8char_len, i;

	if (!inlen) {
		return 0;
	}

	if ((in[0] & 0x80) == 0x00) {
		utf8char_len = 1;
	} else if ((in[0] & 0xe0) == 0xc0) {
		utf8char_len = 2;
	} else if ((in[0] & 0xf0) == 0xe0) {
		utf8char_len = 3;
	} else if ((in[0] & 0xf8) == 0xf0) {
		utf8char_len = 4;
	} else {
		//error_print(); // disable error_print for _is_ compare
		return -1;
	}

	if (inlen < utf8char_len) {
		//error_print(); // disable error_print for _is_ compare
		return -1;
	}

	utf8char = in[0];
	for (i = 1; i < utf8char_len; i++) {
		if ((in[i] & 0x60) != 0x80) {
			//error_print(); // disable error_print for _is_ compare
			return -1;
		}
		utf8char = (utf8char << 8) | in[i];
	}

	*c = utf8char;
	(*pin) += utf8char_len;
	(*pinlen) -= utf8char_len;
	return 1;
}


int asn1_string_is_utf8_string(const char *a, size_t alen)
{
	uint32_t utf8char;

	if (!a || !alen) {
		return 0;
	}
	while (alen) {
		if (asn1_utf8char_from_bytes(&utf8char, (const uint8_t **)&a, &alen) != 1) {
			return 0;
		}
	}
	return 1;
}

int asn1_utf8_string_to_der_ex(int tag, const char *d, size_t dlen, uint8_t **out, size_t *outlen)
{
	int ret;
	if (asn1_string_is_utf8_string(d, dlen) != 1) {
		error_print();
		return -1;
	}
	if ((ret = asn1_type_to_der(tag, (const uint8_t *)d, dlen, out, outlen)) != 1) {
		if (ret) error_print();
		return ret;
	}
	return 1;
}

int asn1_utf8_string_from_der_ex(int tag, const char **a, size_t *alen, const uint8_t **in, size_t *inlen)
{
	int ret;
	if ((ret = asn1_type_from_der(tag, (const uint8_t **)a, alen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (*a == NULL || *alen == 0) {
		error_print();
		return -1;
	}
	if (asn1_string_is_utf8_string(*a, *alen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

static int asn1_char_is_printable(int a)
{
	if (('0' <= a && a <= '9')
		|| ('a' <= a && a <= 'z')
		|| ('A' <= a && a <= 'Z')) {
		return 1;
	}

	switch (a) {
	case ' ': case '\'': case '(': case ')':
	case '+': case ',': case '-': case '.':
	case '/': case ':': case '=': case '?':
		return 1;
	}
	return 0;
}

int asn1_string_is_printable_string(const char *a, size_t alen)
{
	size_t i;
	for (i = 0; i < alen; i++) {
		if (asn1_char_is_printable(a[i]) != 1) {
			return 0;
		}
	}
	return 1;
}

int asn1_printable_string_case_ignore_match(const char *a, size_t alen,
	const char *b, size_t blen)
{
	// remove leading and suffix space chars
	while (alen && *a == ' ') {
		a++;
		alen--;
	}
	while (alen && a[alen - 1] == ' ') {
		alen--;
	}

	// remove leading and suffix space chars
	while (blen && *b == ' ') {
		b++;
		blen--;
	}
	while (blen && b[blen - 1] == ' ') {
		blen--;
	}

	if (alen != blen) {
		return 0;
	}
	// case insensitive compare
	while (alen--) {
		if (toupper(*a) != toupper(*b)) {
			return 0;
		}
	}
	return 1;
}

int asn1_printable_string_to_der_ex(int tag, const char *d, size_t dlen, uint8_t **out, size_t *outlen)
{
	int ret;
	if (asn1_string_is_printable_string(d, dlen) != 1) {
		error_print();
		return -1;
	}
	if ((ret = asn1_type_to_der(tag, (const uint8_t *)d, dlen, out, outlen)) != 1) {
		if (ret) error_print();
		return ret;
	}
	return 1;
}

int asn1_printable_string_from_der_ex(int tag, const char **a, size_t *alen, const uint8_t **in, size_t *inlen)
{
	int ret;

	if ((ret = asn1_type_from_der(tag, (const uint8_t **)a, alen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (*a == NULL || *alen == 0) {
		error_print();
		return -1;
	}
	if (asn1_string_is_printable_string(*a, *alen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int asn1_string_is_ia5_string(const char *a, size_t alen)
{
	size_t i;
	for (i = 0; i < alen; i++) {
		if (!isascii(a[i])) {
			return 0;
		}
	}
	return 1;
}

int asn1_ia5_string_to_der_ex(int tag, const char *d, size_t dlen, uint8_t **out, size_t *outlen)
{
	int ret;
	if (asn1_string_is_ia5_string(d, dlen) != 1) {
		error_print();
		return -1;
	}
	if ((ret = asn1_type_to_der(tag, (const uint8_t *)d, dlen, out, outlen)) != 1) {
		if (ret) error_print();
		return ret;
	}
	return 1;
}

int asn1_ia5_string_from_der_ex(int tag, const char **a, size_t *alen, const uint8_t **in, size_t *inlen)
{
	int ret;

	if ((ret = asn1_type_from_der(tag, (const uint8_t **)a, alen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (*a == NULL || *alen == 0) {
		error_print();
		return -1;
	}
	if (asn1_string_is_ia5_string(*a, *alen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int asn1_string_print(FILE *fp, int fmt, int ind, const char *label, int tag, const uint8_t *d, size_t dlen)
{
	format_print(fp, fmt, ind, "%s: ", label);
	while (dlen--) {
		fprintf(fp, "%c", *d++);
	}
	fprintf(fp, "\n");
	return 1;
}

static int is_leap_year(int year) {
	return ((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)) ? 1 : 0;
}

#define val(c)	((c)-'0')

int asn1_time_from_str(int utc_time, time_t *timestamp, const char *str)
{
	int time_str_len[2] = { 15, 13 };
	int days_per_year[2] = { 365, 366 };
	int days_per_month[] = { 0,31,28,31,30,31,30,31,31,30,31,30,31 };
	int year, month, day, hour, minute, second;
	const char *p = str;
	int i;

	utc_time &= 1;
	for (i = 0; i < time_str_len[utc_time] - 1; i++) {
		if (!('0' <= str[i] && str[i] <= '9')) {
			error_print();
			return -1;
		}
	}
	if (str[i] != 'Z') {
		error_print();
		return -1;
	}

	if (utc_time) {
		year = val(p[0]) * 10 + val(p[1]);
		if (year <= 50) {
			year += 2000;
		} else {
			year += 1900;
		}
		p += 2;
	} else {
		year = val(p[0]) * 1000 + val(str[1]) * 100 + val(str[2]) * 10 + val(str[3]);
		p += 4;
	}
	if (is_leap_year(year)) {
		days_per_month[2] = 29;
	}
	month	= val(p[0]) * 10 + val(p[1]); p += 2;
	day	= val(p[0]) * 10 + val(p[1]); p += 2;
	hour	= val(p[0]) * 10 + val(p[1]); p += 2;
	minute	= val(p[0]) * 10 + val(p[1]); p += 2;
	second	= val(p[0]) * 10 + val(p[1]);

	if (year < 1970
		|| month < 1 || month > 12
		|| day < 1 || day > days_per_month[month]
		|| hour < 0 || hour > 23
		|| minute < 0 || minute > 59
		|| second < 0 || second > 59) {
		error_print();
		return -1;
	}

	day--;

	while (year-- > 1970) {
		day += days_per_year[is_leap_year(year)];
	}
	while (month-- > 1) {
		day += days_per_month[month];
	}
	*timestamp = (time_t)day * 86400 + hour * 3600 + minute * 60 + second;

	return 1;
}

int asn1_time_to_str(int utc_time, time_t timestamp, char *str)
{
	int days_per_month[] = { 0,31,28,31,30,31,30,31,31,30,31,30,31 };
	int days_per_year[2] = { 365, 366 };
	int max_year[2] = { 9999, 2050 };
	int year, month, second, hour, minute;
	time_t day;
	char *p = str;

	utc_time &= 1;
	day = timestamp / 86400;
	second = timestamp % 86400;

	// In UTCTime, year in [1951, 2050], YY <= 50, year = 20YY; YY > 50, year = 19YY
	// For Validity, year SHOULD <= 2049 (NOT 2050)
	for (year = 1970; year <= max_year[utc_time]; year++) {
		if (day < days_per_year[is_leap_year(year)]) {
			break;
		}
		day -= days_per_year[is_leap_year(year)];
	}
	if (year > max_year[utc_time]) {
		error_print();
		return -1;
	}

	day++;

	if (is_leap_year(year)) {
		days_per_month[2] = 29;
	}
	for (month = 1; month <= 12; month++) {
		if (day <= days_per_month[month]) {
			break;
		}
		day -= days_per_month[month];
	}

	hour = second / 3600;
	second %= 3600;
	minute = second / 60;
	second %= 60;

	if (utc_time) {
		memset(p, '0', 12);
	} else {
		memset(p, '0', 14);
		p[0] += (year / 100) / 10;
		p[1] += (year / 100) % 10;
		p += 2;
	}

	year %= 100;
	p[0] += year / 10;
	p[1] += year % 10;
	p[2] += month / 10;
	p[3] += month % 10;
	p[4] += (int)day / 10;
	p[5] += day % 10;
	p[6] += hour / 10;
	p[7] += hour % 10;
	p[8] += minute / 10;
	p[9] += minute % 10;
	p[10] += second / 10;
	p[11] += second % 10;
	p[12] = 'Z';

	return 1;
}

int asn1_utc_time_to_der_ex(int tag, time_t a, uint8_t **out, size_t *outlen)
{
	char buf[ASN1_UTC_TIME_STRLEN + 1] = {0};
	int utc_time = 1;

	if (!outlen) {
		error_print();
		return -1;
	}
	if (a == -1) {
		return 0;
	}

	if (asn1_time_to_str(utc_time, a, buf) != 1) {
		error_print();
		return -1;
	}

	if (out && *out) {
		*(*out)++ = tag;
	}
	(*outlen)++;
	asn1_length_to_der(ASN1_UTC_TIME_STRLEN, out, outlen);
	if (out && *out) {
		memcpy(*out, buf, ASN1_UTC_TIME_STRLEN);
		(*out) += ASN1_UTC_TIME_STRLEN;
	}
	*outlen += ASN1_UTC_TIME_STRLEN;

	return 1;
}

int asn1_utc_time_from_der_ex(int tag, time_t *t, const uint8_t **in, size_t *inlen)
{
	size_t len;

	if (!t || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}

	// tag
	if (*inlen == 0 || **in != tag) {
		*t = -1;
		return 0;
	}
	(*in)++;
	(*inlen)--;

	// length
	if (asn1_length_from_der(&len, in, inlen) != 1) {
		error_print();
		return -1;
	}

	if (len == sizeof("YYMMDDHHMMSSZ")-1) {
		char buf[sizeof("YYMMDDHHMMSSZ")-1];
		memcpy(buf, *in, len);
		if (asn1_time_from_str(1, t, buf) != 1) {
			error_print();
			return -1;
		}
	} else if (len == sizeof("YYMMDDHHMMSS+HHMM")-1) {
		char buf[sizeof("YYMMDDHHMMSS+HHMM")-1];
		memcpy(buf, *in, len);
		// this format is not supported yet
		error_print();
		return -1;
	} else {
		error_print();
		return -1;
	}

	*in += len;
	*inlen -= len;
	return 1;
}

int asn1_generalized_time_to_der_ex(int tag, time_t a, uint8_t **out, size_t *outlen)
{
	char buf[ASN1_GENERALIZED_TIME_STRLEN + 1] = {0};
	int utc_time = 0;

	if (!outlen) {
		error_print();
		return -1;
	}
	if (a == -1) {
		return 0;
	}

	if (asn1_time_to_str(utc_time, a, buf) != 1) {
		error_print();
		return -1;
	}

	if (out && *out)
		*(*out)++ = tag;
	(*outlen)++;
	asn1_length_to_der(ASN1_GENERALIZED_TIME_STRLEN, out, outlen);
	if (out && *out) {
		memcpy(*out, buf, ASN1_GENERALIZED_TIME_STRLEN);
		(*out) += ASN1_GENERALIZED_TIME_STRLEN;
	}
	*outlen += ASN1_GENERALIZED_TIME_STRLEN;

	return 1;
}

int asn1_generalized_time_from_der_ex(int tag, time_t *t, const uint8_t **in, size_t *inlen)
{
	size_t len;

	if (!t || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}

	// tag
	if (*inlen == 0 || **in != tag) {
		*t = -1;
		return 0;
	}
	(*in)++;
	(*inlen)--;

	// length
	if (asn1_length_from_der(&len, in, inlen) != 1) {
		error_print();
		return -1;
	}

	if (len == sizeof("YYYYMMDDHHMMSSZ")-1) {
		char buf[sizeof("YYYYMMDDHHMMSSZ")-1];
		memcpy(buf, *in, len);
		if (asn1_time_from_str(0, t, buf) != 1) {
			error_print();
			return -1;
		}
	} else if (len == sizeof("YYYYMMDDHHMMSS+HHMM")-1) {
		char buf[sizeof("YYYYMMDDHHMMSS+HHMM")-1];
		memcpy(buf, *in, len);
		error_print();
		return -1;
	} else {
		error_print();
		return -1;
	}

	*in += len;
	*inlen -= len;
	return 1;
}

int asn1_sequence_of_int_to_der(const int *nums, size_t nums_cnt, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	size_t i;

	if (!nums || !nums_cnt || !outlen) {
		error_print();
		return -1;
	}

	for (i = 0; i < nums_cnt; i++) {
		if (asn1_int_to_der(nums[i], NULL, &len) != 1) {
			error_print();
			return -1;
		}
	}
	if (asn1_sequence_header_to_der(len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	for (i = 0; i < nums_cnt; i++) {
		if (asn1_int_to_der(nums[i], out, outlen) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}

int asn1_sequence_of_int_from_der(int *nums, size_t *nums_cnt, size_t max_nums, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if (!nums || !nums_cnt || !max_nums) {
		error_print();
		return -1;
	}

	*nums_cnt = 0;
	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	while (dlen) {
		int num;
		if (*nums_cnt > max_nums) {
			error_print();
			return -1;
		}
		if (asn1_int_from_der(&num, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		*nums++ = num;
		(*nums_cnt)++;
	}
	return 1;
}

int asn1_sequence_of_int_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int val;
	format_print(fp, fmt, ind, "%s: ", label);
	while (dlen) {
		if (asn1_int_from_der(&val, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		fprintf(fp, "%d%s", val, dlen ? "," : "");
	}
	fprintf(fp, "\n");
	return 1;
}

int asn1_types_get_count(const uint8_t *d, size_t dlen, int tag, size_t *cnt)
{
	int item_tag;
	const uint8_t *item_d;
	size_t item_dlen;

	if (!d || !cnt) {
		error_print();
		return -1;
	}
	*cnt = 0;
	while (dlen) {
		if (asn1_any_type_from_der(&item_tag, &item_d, &item_dlen, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		if (item_tag != tag) {
			error_print();
			return -1;
		}
		(*cnt)++;
	}
	return 1;
}

int asn1_types_get_item_by_index(const uint8_t *d, size_t dlen, int tag,
	int index, const uint8_t **item_d, size_t *item_dlen)
{
	int a_tag;
	const uint8_t *a_d;
	size_t a_dlen;
	int i = 0;

	if (!d || !item_d || !item_dlen) {
		error_print();
		return -1;
	}

	while (dlen) {
		if (asn1_any_type_from_der(&a_tag, &a_d, &a_dlen, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		if (a_tag != tag) {
			error_print();
			return -1;
		}
		if (i++ == index) {
			*item_d = d;
			*item_dlen = dlen;
			return 1; // do not check the following
		}
	}

	error_print();
	return -1;
}

int asn1_check(int expr)
{
	if (expr)
		return 1;
	error_print();
	return -1;
}

int asn1_length_is_zero(size_t len)
{
	if (len) {
		error_print();
		return -1;
	}
	return 1;
}

int asn1_length_le(size_t len1, size_t len2)
{
	if (len1 > len2) {
		error_print();
		format_print(stderr, 0, 0, "%s: %zu <= %zu failed\n", __FUNCTION__, len1, len2);
		return -1;
	}
	return 1;
}
