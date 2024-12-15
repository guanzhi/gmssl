/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#ifndef GMSSL_DYLIB_H
#define GMSSL_DYLIB_H

#include <string.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


#ifdef _WIN32

#include <windows.h>

typedef HMODULE dylib_handle_t;

#define dylib_load_library(so_path)	LoadLibraryA(so_path)
#define dylib_get_function(handle,name)	GetProcAddress(handle,name)
#define dylib_close_library(handle)
#define dylib_error_str()		""


#else

#include <dlfcn.h>

typedef void *dylib_handle_t;

#define dylib_load_library(so_path)	dlopen(so_path,RTLD_LAZY)
#define dylib_get_function(handle,name)	dlsym(handle,name)
#define dylib_close_library(handle)	dlclose(handle)
#define dylib_error_str()		dlerror()


#endif




#ifdef __cplusplus
}
#endif
#endif
