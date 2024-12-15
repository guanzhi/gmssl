/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <gmssl/error.h>


int file_size(FILE *fp, size_t *size)
{
	int fd;
	struct stat st;

#ifdef _WIN32
	fd = _fileno(fp);
#else
	fd = fileno(fp);
#endif
	if (fstat(fd, &st) < 0) {
		error_print();
		return -1;
	}
	*size = st.st_size;
	return 1;
}

int file_read_all(const char *file, uint8_t **out, size_t *outlen)
{
	int ret = -1;
	FILE *fp = NULL;
	size_t fsize;
	uint8_t *buf = NULL;

	if (!(fp = fopen(file, "rb"))
		|| file_size(fp, &fsize) != 1
		|| (buf = malloc(fsize)) == NULL) {
		error_print();
		goto end;
	}
	if (fread(buf, 1, fsize, fp) != fsize) {
		error_print();
		goto end;
	}
	*out = buf;
	*outlen = fsize;
	buf = NULL;
	ret = 1;
end:
	if (fp) fclose(fp);
	if (buf) free(buf);
	return ret;
}

