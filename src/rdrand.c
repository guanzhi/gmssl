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
#include <stdlib.h>
#include <gmssl/error.h>
#include <immintrin.h>
#if defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))
#include <x86intrin.h>
#endif

int rdrand_bytes(uint8_t *buf, size_t buflen)
{
	unsigned long long val;
	uint8_t *p = (uint8_t *)&val;

	while (buflen) {
		size_t len = buflen >= sizeof(val) ? sizeof(val) : buflen;
		if (_rdrand64_step(&val) != 1) {
			error_print();
			return -1;
		}
		memcpy(buf, p, len);
		buf += len;
		buflen -= len;
	}
	return 1;
}

#ifdef INTEL_RDSEED
int rdseed_bytes(uint8_t *buf, size_t buflen)
{
	unsigned long long val;
	uint8_t *p = (uint8_t *)&val;

	while (buflen) {
		size_t len = buflen >= sizeof(val) ? sizeof(val) : buflen;
		if (_rdseed64_step(&val) != 1) {
			error_print();
			return -1;
		}
		memcpy(buf, p, len);
		buf += len;
		buflen -= len;
	}
	return 1;
}
#endif
