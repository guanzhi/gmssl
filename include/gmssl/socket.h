/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#ifndef GMSSL_SOCKET_H
#define GMSSL_SOCKET_H

#include <string.h>
#include <stdint.h>
#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif



#ifdef WIN32
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

#include <winsock2.h>

typedef SOCKET tls_socket_t;
typedef int tls_ret_t;
typedef int tls_socklen_t;


#define tls_socket_send(sock,buf,len,flags)	send(sock,buf,(int)(len),flags)
#define tls_socket_recv(sock,buf,len,flags)	recv(sock,buf,(int)(len),flags)
#define tls_socket_close(sock)			closesocket(sock)

#else

#include <fcntl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <unistd.h>

typedef int tls_socket_t;
typedef ssize_t tls_ret_t;
typedef socklen_t tls_socklen_t;


#define tls_socket_send(sock,buf,len,flags)	send(sock,buf,len,flags)
#define tls_socket_recv(sock,buf,len,flags)	recv(sock,buf,len,flags)
#define tls_socket_close(sock)			close(sock)

#endif

int tls_socket_lib_init(void);
int tls_socket_lib_cleanup(void);
int tls_socket_create(tls_socket_t *sock, int af, int type, int protocl);
int tls_socket_connect(tls_socket_t sock, const struct sockaddr_in *addr);
int tls_socket_bind(tls_socket_t sock, const struct sockaddr_in *addr);
int tls_socket_listen(tls_socket_t sock, int backlog);
int tls_socket_accept(tls_socket_t sock, struct sockaddr_in *addr, tls_socket_t *conn_sock);
int tls_socket_wait_recv(tls_socket_t sock);
int tls_socket_wait_send(tls_socket_t sock);

#ifdef __cplusplus
}
#endif
#endif
