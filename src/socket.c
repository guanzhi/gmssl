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
#include <gmssl/socket.h>
#include <gmssl/error.h>


#ifdef _WIN32
int tls_socket_lib_init(void)
{
	WORD wVersion = MAKEWORD(2, 2);
	WSADATA wsaData;
	int err;

	if ((err = WSAStartup(wVersion, &wsaData)) != 0) {
		fprintf(stderr, "WSAStartup() return error %d\n", err);
		error_print();
		return -1;
	}
	return 1;
}

int tls_socket_lib_cleanup(void)
{
	if (WSACleanup() != 0) {
		fprintf(stderr, "WSACleanup() return error %d\n", WSAGetLastError());
		error_print();
		return -1;
	}
	return 1;
}

int tls_socket_create(tls_socket_t *sock, int af, int type, int protocol)
{
	if (!sock) {
		error_print();
		return -1;
	}
	// INVALID_SOCKET == -1
	if ((*sock = socket(af, type, protocol)) == INVALID_SOCKET) {
		fprintf(stderr, "%s %d: socket error: %d\n", __FILE__, __LINE__, WSAGetLastError());
		error_print();
		return -1;
	}
	return 1;
}

int tls_socket_connect(tls_socket_t sock, const struct sockaddr_in *addr)
{
	int addr_len = (int)sizeof(struct sockaddr_in);
	if (connect(sock, (const struct sockaddr *)addr, addr_len) == SOCKET_ERROR) {
		fprintf(stderr, "%s %d: socket error: %d\n", __FILE__, __LINE__, WSAGetLastError());
		error_print();
		return -1;
	}
	return 1;
}

int tls_socket_bind(tls_socket_t sock, const struct sockaddr_in *addr)
{
	int addr_len = (int)sizeof(struct sockaddr_in);
	if (bind(sock, (const struct sockaddr *)addr, addr_len) == SOCKET_ERROR) {
		fprintf(stderr, "%s %d: socket bind error: %u\n", __FILE__, __LINE__, WSAGetLastError());
		error_print();
		return -1;
	}
	return 1;
}

int tls_socket_listen(tls_socket_t sock, int backlog)
{
	if (listen(sock, backlog) == SOCKET_ERROR) {
		fprintf(stderr, "%s %d: socket listen error: %u\n", __FILE__, __LINE__, WSAGetLastError());
		error_print();
		return -1;
	}
	return 1;
}

int tls_socket_accept(tls_socket_t sock, struct sockaddr_in *addr, tls_socket_t *conn_sock)
{
	int addr_len = (int)sizeof(struct sockaddr_in);
	if ((*conn_sock = accept(sock, (struct sockaddr *)addr, &addr_len)) == INVALID_SOCKET) {
		fprintf(stderr, "%s %d: accept error: %u\n", __FILE__, __LINE__, WSAGetLastError());
		error_print();
		return -1;
	}
	return 1;
}

#else

int tls_socket_lib_init(void)
{
	return 1;
}

int tls_socket_lib_cleanup(void)
{
	return 1;
}

int tls_socket_create(tls_socket_t *sock, int af, int type, int protocol)
{
	if (!sock) {
		error_print();
		return -1;
	}
	if ((*sock = socket(af, type, protocol)) == -1) {
		fprintf(stderr, "%s %d: socket error: %s\n", __FILE__, __LINE__, strerror(errno));
		error_print();
		return -1;
	}
	return 1;
}

int tls_socket_connect(tls_socket_t sock, const struct sockaddr_in *addr)
{
	socklen_t addr_len = sizeof(struct sockaddr_in);
	if (connect(sock, (const struct sockaddr *)addr, addr_len) == -1) {
		fprintf(stderr, "%s %d: socket error: %s\n", __FILE__, __LINE__, strerror(errno));
		error_print();
		return -1;
	}
	return 1;
}

int tls_socket_bind(tls_socket_t sock, const struct sockaddr_in *addr)
{
	socklen_t addr_len = (socklen_t)sizeof(struct sockaddr_in);
	if (bind(sock, (const struct sockaddr *)addr, addr_len) == -1) {
		fprintf(stderr, "%s %d: socket bind error: %s\n", __FILE__, __LINE__, strerror(errno));
		error_print();
		return -1;
	}
	return 1;
}

int tls_socket_listen(tls_socket_t sock, int backlog)
{
	if (listen(sock, backlog) == -1) {
		fprintf(stderr, "%s %d: socket listen error: %s\n", __FILE__, __LINE__, strerror(errno));
		error_print();
		return -1;
	}
	return 1;
}

int tls_socket_accept(tls_socket_t sock, struct sockaddr_in *addr, tls_socket_t *conn_sock)
{
	socklen_t addr_len = (socklen_t)sizeof(struct sockaddr_in);
	if ((*conn_sock = accept(sock, (struct sockaddr *)addr, &addr_len)) == -1) {
		fprintf(stderr, "%s %d: accept: %s\n", __FILE__, __LINE__, strerror(errno));
		error_print();
		return -1;
	}
	return 1;
}
#endif
