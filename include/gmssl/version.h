/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#ifndef GMSSL_VERSION_H
#define GMSSL_VERSION_H

#ifdef __cplusplus
extern "C" {
#endif

#define GMSSL_VERSION_NUM 30102
#define GMSSL_VERSION_STR "GmSSL 3.1.2 Dev"

int gmssl_version_num(void);
const char *gmssl_version_str(void);

#ifdef __cplusplus
}
#endif
#endif
