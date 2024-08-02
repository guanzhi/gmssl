/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/tls.h>
#include <gmssl/x509.h>
#include <gmssl/error.h>
#ifndef WIN32
	#include <sys/select.h>
#endif


#define TIMEOUT_SECONDS 1

static int client_ciphers[] = { TLS_cipher_ecc_sm4_cbc_sm3, };

static const char *usage =
	"-host str [-port num] [-cacert file]"
	" [-cert file -key file -pass str]"
	" [-outcerts file]"
	" [-get path]"
	" [-quiet]";

static const char *help =
"Options\n"
"\n"
"    -host str              Domain name or IP address of remote host\n"
"    -port num              Port number of remote host, default 443\n"
"    -cacert file           Trusted CA certificate(s) in PEM format\n"
"    -cert file             Client certificate(s) in PEM format\n"
"    -key file              Private key of client certificate\n"
"    -pass password         Password of encrypted private key\n"
"    -get path              Send a GET request with given path of URI\n"
"    -outcerts file         Save server certificates to a PEM file\n"
"    -quiet                 Without printing any status message\n"
"\n"
"Examples\n"
"\n"
"  gmssl tlcp_client -host www.pbc.gov.cn -get / -outcerts certs.pem\n"
"\n"
"  gmssl tlcp_client -host www.pbc.gov.cn -port 443\n"
"\n";

int tlcp_client_main(int argc, char *argv[])
{
	int ret = -1;
	char *prog = argv[0];
	char *host = NULL;
	int port = 443;
	char *cacertfile = NULL;
	char *certfile = NULL;
	char *keyfile = NULL;
	char *pass = NULL;
	char *get = NULL;
	char *outcertsfile = NULL;
	int quiet = 0;
	struct hostent *hp;
	struct sockaddr_in server;
	tls_socket_t sock = -1;
	TLS_CTX ctx;
	TLS_CONNECT conn;
	char buf[1024] = {0};
	size_t len = sizeof(buf);
	char send_buf[1024] = {0};
	int read_stdin = 1;

	argc--;
	argv++;
	if (argc < 1) {
		fprintf(stderr, "usage: gmssl %s %s\n", prog, usage);
		return 1;
	}
	while (argc >= 1) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: gmssl %s %s\n\n", prog, usage);
			printf("%s\n", help);
			ret = 0;
			goto end;
		} else if (!strcmp(*argv, "-host")) {
			if (--argc < 1) goto bad;
			host = *(++argv);
		} else if (!strcmp(*argv, "-port")) {
			if (--argc < 1) goto bad;
			port = atoi(*(++argv));
		} else if (!strcmp(*argv, "-cacert")) {
			if (--argc < 1) goto bad;
			cacertfile = *(++argv);
		} else if (!strcmp(*argv, "-cert")) {
			if (--argc < 1) goto bad;
			certfile = *(++argv);
		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			keyfile = *(++argv);
		} else if (!strcmp(*argv, "-pass")) {
			if (--argc < 1) goto bad;
			pass = *(++argv);
		} else if (!strcmp(*argv, "-get")) {
			if (--argc < 1) goto bad;
			get = *(++argv);
		} else if (!strcmp(*argv, "-outcerts")) {
			if (--argc < 1) goto bad;
			outcertsfile = *(++argv);
		} else if (!strcmp(*argv, "-quiet")) {
			quiet = 1;
		} else {
			fprintf(stderr, "%s: invalid option '%s'\n", prog, *argv);
			return 1;
bad:
			fprintf(stderr, "%s: option '%s' argument required\n", prog, *argv);
			return 0;
		}
		argc--;
		argv++;
	}

	if (!host) {
		fprintf(stderr, "%s: '-in' option required\n", prog);
		return -1;
	}

	if (tls_socket_lib_init() != 1) {
		error_print();
		return -1;
	}

	if (tls_socket_create(&sock, AF_INET, SOCK_STREAM, 0) != 1) {
		fprintf(stderr, "%s: open socket error\n", prog);
		goto end;
	}

	if (!(hp = gethostbyname(host))) {
		fprintf(stderr, "%s: invalid hostname '%s'\n", prog, host);
		goto end;
	}
	server.sin_addr = *((struct in_addr *)hp->h_addr_list[0]);
	server.sin_family = AF_INET;
	server.sin_port = htons(port);

	if (tls_socket_connect(sock, &server) != 1) {
		fprintf(stderr, "%s: socket connect error\n", prog);
		goto end;
	}

	if (tls_ctx_init(&ctx, TLS_protocol_tlcp, TLS_client_mode) != 1
		|| tls_ctx_set_cipher_suites(&ctx, client_ciphers, sizeof(client_ciphers)/sizeof(client_ciphers[0])) != 1) {
		fprintf(stderr, "%s: context init error\n", prog);
		goto end;
	}

	if (cacertfile) {
		if (tls_ctx_set_ca_certificates(&ctx, cacertfile, TLS_DEFAULT_VERIFY_DEPTH) != 1) {
			fprintf(stderr, "%s: context init error\n", prog);
			goto end;
		}
	}

	if (certfile) {
		if (!keyfile) {
			fprintf(stderr, "%s: option '-key' should be assigned with '-cert'\n", prog);
			goto end;
		}
		if (!pass) {
			fprintf(stderr, "%s: option '-pass' should be assigned with '-pass'\n", prog);
			goto end;
		}
		if (tls_ctx_set_certificate_and_key(&ctx, certfile, keyfile, pass) != 1) {
			fprintf(stderr, "%s: context init error\n", prog);
			goto end;
		}
	}

	if (quiet) {
		ctx.quiet = 1;
	}

	if (tls_init(&conn, &ctx) != 1
		|| tls_set_socket(&conn, sock) != 1
		|| tls_do_handshake(&conn) != 1) {
		fprintf(stderr, "%s: error\n", prog);
		goto end;
	}

	if (outcertsfile) {
		FILE *outcertsfp;
		if (!(outcertsfp = fopen(outcertsfile, "wb"))) {
			fprintf(stderr, "%s: open '%s' failure\n", prog, outcertsfile);
			perror("fopen");
			goto end;
		}
		if (x509_certs_to_pem(conn.server_certs, conn.server_certs_len, outcertsfp) != 1) {
			fprintf(stderr, "%s: x509_certs_to_pem error\n", prog);
			fclose(outcertsfp);
			goto end;
		}
		fclose(outcertsfp);
	}

//	tls_shutdown(&conn);
//	return 0;

	if (get) {
		struct timeval timeout;
		timeout.tv_sec = TIMEOUT_SECONDS;
		timeout.tv_usec = 0;

		snprintf(buf, sizeof(buf), "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", get, host);

		if (tls_send(&conn, (uint8_t *)buf, strlen(buf), &len) != 1) {
			fprintf(stderr, "%s: send error\n", prog);
			goto end;
		}

		// use timeout to close the HTTP connection
		if (setsockopt(conn.sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) != 0) {
			perror("setsockopt");
			fprintf(stderr, "%s: set socket timeout error\n", prog);
			goto end;
		}

		for (;;) {
			int rv;

			rv = tls_recv(&conn, (uint8_t *)buf, sizeof(buf), &len);

			if (rv == 1) {
				fwrite(buf, 1, len, stdout);
				fflush(stdout);
			} else if (rv == 0) {
				fprintf(stderr, "%s: TLCP connection is closed by remote host\n", prog);
				goto end;
			} else if (rv == -EAGAIN) {
				// when timeout, tls_recv return -EAGAIN (-11)
				tls_shutdown(&conn);
				ret = 0;
				goto end;
			} else {
				fprintf(stderr, "%s: tls_recv error\n", prog);
				goto end;
			}
		}

		read_stdin = 0;
	}

	for (;;) {
		fd_set fds;

		FD_ZERO(&fds);
		FD_SET(conn.sock, &fds);

		if (read_stdin) {
#ifdef WIN32
			if (fgets(buf, sizeof(buf), stdin)) {
				if (tls_send(&conn, (uint8_t *)buf, strlen(buf), &len) != 1) {
					fprintf(stderr, "%s: send error\n", prog);
					goto end;
				}
			} else {
				if (!feof(stdin)) {
					fprintf(stderr, "%s: length of input line exceeds buffer size\n", prog);
					goto end;
				}	
				read_stdin = 0;
			}	
#else
			FD_SET(STDIN_FILENO, &fds); // in POSIX, first arg type is int
#endif
		}
		if (select(conn.sock + 1, &fds, NULL, NULL, NULL) < 0) {
			fprintf(stderr, "%s: select error\n", prog);
			goto end;
		}

#ifdef WIN32
#else
		if (read_stdin && FD_ISSET(STDIN_FILENO, &fds)) {

			if (fgets(buf, sizeof(buf), stdin)) {
				if (tls_send(&conn, (uint8_t *)buf, strlen(buf), &len) != 1) {
					fprintf(stderr, "%s: send error\n", prog);
					goto end;
				}
			} else {
				if (!feof(stdin)) {
					fprintf(stderr, "%s: length of input line exceeds buffer size\n", prog);
					goto end;
				}
				read_stdin = 0;
			}
		}
#endif

		if (FD_ISSET(conn.sock, &fds)) {
			int rv;

			rv = tls_recv(&conn, (uint8_t *)buf, sizeof(buf), &len);

			if (rv == 1) {
				fwrite(buf, 1, len, stdout);
				fflush(stdout);
			} else if (rv == 0) {
				fprintf(stderr, "Connection closed by remote host\n");
				goto end;
			} else if (rv == -EAGAIN) {
				// should not happen
				error_print();
				goto end;
			} else {
				error_print();
				fprintf(stderr, "%s: tls_recv error\n", prog);
				goto end;
			}
		}
	}

end:
	// FIXME: clean ctx and connection ASAP, as Ctrl-C is not handled
	if (sock != -1) tls_socket_close(sock);
	tls_ctx_cleanup(&ctx);
	tls_cleanup(&conn);
	return ret;
}
