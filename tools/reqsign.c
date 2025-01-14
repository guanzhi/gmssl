/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
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
#include <gmssl/hex.h>
#include <gmssl/mem.h>
#include <gmssl/rand.h>
#include <gmssl/x509.h>
#include <gmssl/x509_ext.h>
#include <gmssl/x509_req.h>


static const char *options =
	" [-in pem]"
	" [-req_sm2_id str | -req_sm2_id_hex hex]"
	" [-serial_len num]"
	" -days num"
	" -cacert pem -key file -pass pass"
	" [-sm2_id str | -sm2_id_hex hex]"
	" [-gen_authority_key_id]"
	" [-gen_subject_key_id]"
	" [-key_usage str]*"
	" [-subject_dns_name str]*"
	" [-issuer_dns_name str]*"
	" [-ca -path_len_constraint num]"
	" [-ext_key_usage str]*"
	" [-crl_http_uri uri] [-crl_ldap_uri uri]"
	" [-inhibit_any_policy num]"
	" [-ca_issuers_uri uri] [-ocsp_uri uri uri]"
	" [-out pem]";

static char *usage =
"Options\n"
"\n"
"    -in pem | stdin              Input CSR file in PEM format\n"
"    -req_sm2_id str              CSR Owner's ID in SM2 signature algorithm\n"
"    -req_sm2_id_hex hex          CSR Owner's ID in hex format\n"
"                                 When `-req_sm2_id` or `-req_sm2_id_hex` is specified,\n"
"                                   must use the same ID in other commands explicitly.\n"
"                                 If neither `-req_sm2_id` nor `-req_sm2_id_hex` is specified,\n"
"                                   the default string '1234567812345678' is used\n"
"    -serial_len num              Serial number length in bytes\n"
"    -days num                    Validity peroid in days\n"
"    -cacert pem                  Issuer CA certificate\n"
"    -key pem                     Issuer private key file in PEM format\n"
"    -sm2_id str                  Authority's ID in SM2 signature algorithm\n"
"    -sm2_id_hex hex              Authority's ID in hex format\n"
"                                 When `-sm2_id` or `-sm2_id_hex` is specified,\n"
"                                   must use the same ID in other commands explicitly.\n"
"                                 If neither `-sm2_id` nor `-sm2_id_hex` is specified,\n"
"                                   the default string '1234567812345678' is used\n"
"    -pass pass                   Password for decrypting private key file\n"
"    -out pem                     Output certificate file in PEM format\n"
"\n"
"  Extension options\n"
"\n"
"    -gen_authority_key_id        Generate AuthorityKeyIdentifier extension use SM3\n"
"    -gen_subject_key_id          Generate SubjectKeyIdentifier extension use SM3\n"
"    -key_usage str               Add KeyUsage extension\n"
"                                 this option can be called multi-times\n"
"                                 avaiable values:\n"
"                                     digitalSignature\n"
"                                     nonRepudiation\n"
"                                     keyEncipherment\n"
"                                     dataEncipherment\n"
"                                     keyAgreement\n"
"                                     keyCertSign\n"
"                                     cRLSign\n"
"                                     encipherOnly\n"
"                                     decipherOnly\n"
"    -subject_dns_name str        Add DNS name to SubjectAltName extension\n"
"                                 this option can be called multi-times\n"
"    -issuer_dns_name str         Add DNS name to IssuerAltName extension\n"
"                                 this option can be called multi-times\n"
"    -ca                          Set cA of BasicConstaints extension\n"
"    -path_len_constraint num    Set pathLenConstaint of BasicConstaints extension\n"
"    -ext_key_usage str           Set ExtKeyUsage extension\n"
"                                 this option can be called multi-times\n"
"                                 avaiable values:\n"
"                                     anyExtendedKeyUsage\n"
"                                     serverAuth\n"
"                                     clientAuth\n"
"                                     codeSigning\n"
"                                     emailProtection\n"
"                                     timeStamping\n"
"                                     OCSPSigning\n"
"    -crl_http_uri uri            Set HTTP URI of CRL of CRLDistributionPoints extension\n"
"    -crl_ldap_uri uri            Set LDAP URI of CRL of CRLDistributionPoints extension\n"
"    -inhibit_any_policy num      Set skipCerts number of InhibitAnyPolicy extension\n"
"    -ca_issuers_uri uri          Set URI of the CA certificate in DER-encoding o FreshestCRL extension\n"
"    -ocsp_uri uri                Set OCSP URI of FreshestCRL extension\n"
"\n"
"Examples\n"
"\n"
"    # Generate self-signed root CA certificate\n"
"\n"
"    gmssl sm2keygen -pass P@ssw0rd -out rootcakey.pem\n"
"    gmssl certgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN ROOTCA -days 3650 \\\n"
"          -key rootcakey.pem -pass P@ssw0rd \\\n"
"          -ca -path_len_constraint 6 \\\n"
"          -key_usage keyCertSign -key_usage cRLSign \\\n"
"          -crl_http_uri http://pku.edu.cn/ca.crl \\\n"
"          -ca_issuers_uri http://pku.edu.cn/ca.crt -ocsp_uri http://ocsp.pku.edu.cn \\\n"
"          -out rootcacert.pem\n"
"\n"
"    # Generate sub-CA certificate request\n"
"\n"
"    gmssl sm2keygen -pass P@ssw0rd -out cakey.pem\n"
"    gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN CA -key cakey.pem -pass P@ssw0rd -out careq.pem\n"
"\n"
"    # Sign certificate request to generate sub-CA certificate\n"
"\n"
"    gmssl reqsign -in careq.pem -serial_len 12 -days 365 \\\n"
"          -cacert rootcacert.pem -key rootcakey.pem -pass P@ssw0rd \\\n"
"          -ca -path_len_constraint 0 \\\n"
"          -key_usage keyCertSign -key_usage cRLSign \\\n"
"          -crl_http_uri http://pku.edu.cn/ca.crl \\\n"
"          -ca_issuers_uri http://pku.edu.cn/ca.crt -ocsp_uri http://ocsp.pku.edu.cn \\\n"
"          -out cacert.pem\n"
"\n";

static int ext_key_usage_set(int *usages, const char *usage_name)
{
	int flag = 0;
	if (x509_key_usage_from_name(&flag, usage_name) != 1) {
		return -1;
	}
	*usages |= flag;
	return 1;
}

int reqsign_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *str;

	// Input Req/CSR
	char *infile = NULL;
	FILE *infp = stdin;
	uint8_t req[512];
	size_t reqlen;
	char req_id[SM2_MAX_ID_LENGTH + 1] = {0};
	size_t req_id_len = 0;

	// SerialNumber
	uint8_t serial[20];
	int serial_len = 12;

	// Validity
	int days = 0;
	time_t not_before;
	time_t not_after;

	// Subject from Req
	const uint8_t *subject;
	size_t subject_len;
	SM2_KEY subject_public_key;

	// CA certficate and Private Key
	uint8_t *cacert = NULL;
	size_t cacertlen;
	FILE *keyfp = NULL;
	char *pass = NULL;
	SM2_KEY sm2_key;
	char signer_id[SM2_MAX_ID_LENGTH + 1] = {0};
	size_t signer_id_len = 0;

	// Issuer from CA certificate
	const uint8_t *issuer;
	size_t issuer_len;
	SM2_KEY issuer_public_key;

	// Output
	char *outfile = NULL;
	FILE *outfp = stdout;
	uint8_t *cert = NULL;
	size_t certlen = 0;
	uint8_t *p;

	// Extensions
	uint8_t exts[4096];
	size_t extslen = 0;

	// AuthorityKeyIdentifier
	int gen_authority_key_id = 0;

	// SubjectKeyIdentifier
	int gen_subject_key_id = 0;

	// KeyUsage
	int key_usage = 0;

	// SubjectAltName
	uint8_t subject_alt_name[2048];
	size_t subject_alt_name_len = 0;

	// IssuerAltName
	uint8_t issuer_alt_name[512];
	size_t issuer_alt_name_len = 0;

	// BasicConstraints
	int ca = -1;
	int path_len_constraint = -1;

	// ExtKeyUsageSyntax
	int ext_key_usages[12];
	size_t ext_key_usages_cnt = 0;

	// CRLDistributionPoints
	char *crl_http_uri = NULL;
	char *crl_ldap_uri = NULL;

	// InhibitAnyPolicy
	int inhibit_any_policy = -1;

	// FreshestCRL
	char *ca_issuers_uri = NULL;
	char *ocsp_uri = NULL;

	argc--;
	argv++;

	if (argc < 1) {
		fprintf(stderr, "usage: %s %s\n", prog, options);
		return 1;
	}

	while (argc >= 1) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: gmssl %s %s\n\n", prog, options);
			printf("%s\n", usage);
			ret = 0;
			goto end;
		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);
			if (!(infp = fopen(infile, "rb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, infile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-req_sm2_id")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if (strlen(str) > sizeof(req_id) - 1) {
				fprintf(stderr, "%s: invalid `-req_sm2_id` length\n", prog);
				goto end;
			}
			strncpy(req_id, str, sizeof(req_id));
			req_id_len = strlen(str);
		} else if (!strcmp(*argv, "-req_sm2_id_hex")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if (strlen(str) > (sizeof(req_id) - 1) * 2) {
				fprintf(stderr, "%s: invalid `-req_sm2_id_hex` length\n", prog);
				goto end;
			}
			if (hex_to_bytes(str, strlen(str), (uint8_t *)req_id, &req_id_len) != 1) {
				fprintf(stderr, "%s: invalid `-req_sm2_id_hex` value\n", prog);
				goto end;
			}

		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			outfile = *(++argv);
			if (!(outfp = fopen(outfile, "wb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, outfile, strerror(errno));
				goto end;
			}

		} else if (!strcmp(*argv, "-serial_len")) {
			if (--argc < 1) goto bad;
			serial_len = atoi(*(++argv));
			if (serial_len <= 0 || serial_len > sizeof(serial)) {
				fprintf(stderr, "%s: invalid `-serial_len` value, need a number less than %zu\n", prog, sizeof(serial));
				goto end;
			}
		} else if (!strcmp(*argv, "-days")) {
			if (--argc < 1) goto bad;
			days = atoi(*(++argv));
			if (days <= 0) {
				fprintf(stderr, "%s: invalid `-days` value, need a positive number\n", prog);
				goto end;
			}

		} else if (!strcmp(*argv, "-cacert")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if (x509_cert_new_from_file(&cacert, &cacertlen, str) != 1) {
				fprintf(stderr, "%s: load ca certificate '%s' failure\n", prog, str);
				goto end;
			}
		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if (!(keyfp = fopen(str, "rb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, str, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-pass")) {
			if (--argc < 1) goto bad;
			pass = *(++argv);
		} else if (!strcmp(*argv, "-sm2_id")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if (strlen(str) > sizeof(signer_id) - 1) {
				fprintf(stderr, "%s: invalid `-sm2_id` length\n", prog);
				goto end;
			}
			strncpy(signer_id, str, sizeof(signer_id));
			signer_id_len = strlen(str);
		} else if (!strcmp(*argv, "-sm2_id_hex")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if (strlen(str) > (sizeof(signer_id) - 1) * 2) {
				fprintf(stderr, "%s: invalid `-sm2_id_hex` length\n", prog);
				goto end;
			}
			if (hex_to_bytes(str, strlen(str), (uint8_t *)signer_id, &signer_id_len) != 1) {
				fprintf(stderr, "%s: invalid `-sm2_id_hex` value\n", prog);
				goto end;
			}

		// following copy from certgen.c
		} else if (!strcmp(*argv, "-gen_authority_key_id")) {
			gen_authority_key_id = 1;
		} else if (!strcmp(*argv, "-gen_subject_key_id")) {
			gen_subject_key_id = 1;
		} else if (!strcmp(*argv, "-key_usage")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if (ext_key_usage_set(&key_usage, str) != 1) {
				fprintf(stderr, "%s: invalid `-key_usage` value '%s'\n", prog, str);
				goto end;
			}
		} else if (!strcmp(*argv, "-subject_dns_name")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if (x509_general_names_add_dns_name(
				subject_alt_name, &subject_alt_name_len, sizeof(subject_alt_name), str) != 1) {
				fprintf(stderr, "%s: inner error on processing `-subject_dns_name`\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-issuer_dns_name")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if (x509_general_names_add_dns_name(
				issuer_alt_name, &issuer_alt_name_len, sizeof(issuer_alt_name), str) != 1) {
				fprintf(stderr, "%s: inner error on processing `-issuer_dns_name`\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-ca")) {
			ca = 1;
		} else if (!strcmp(*argv, "-path_len_constraint")) {
			if (--argc < 1) goto bad;
			path_len_constraint = atoi(*(++argv));
			if (path_len_constraint < 0) {
				fprintf(stderr, "%s: invalid `-path_len_constraint` value\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-ext_key_usage")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if (x509_key_purpose_from_name(str) <= 0) {
				fprintf(stderr, "%s: invalid `-ext_key_usage` value '%s'\n", prog, str);
				goto end;
			}
			if (ext_key_usages_cnt >= sizeof(ext_key_usages)/sizeof(ext_key_usages[0])) {
				fprintf(stderr, "%s: too much `-ext_key_usage` options\n", prog);
				goto end;
			}
			ext_key_usages[ext_key_usages_cnt++] = x509_key_purpose_from_name(str);
		} else if (!strcmp(*argv, "-crl_http_uri")) {
			if (--argc < 1) goto bad;
			crl_http_uri = *(++argv);
		} else if (!strcmp(*argv, "-crl_ldap_uri")) {
			if (--argc < 1) goto bad;
			crl_ldap_uri = *(++argv);
		} else if (!strcmp(*argv, "-inhibit_any_policy")) {
			if (--argc < 1) goto bad;
			inhibit_any_policy = atoi(*(++argv));
			if (inhibit_any_policy < 0) {
				fprintf(stderr, "%s: invalid `-inhibit_any_policy` value\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-ca_issuers_uri")) {
			if (--argc < 1) goto bad;
			ca_issuers_uri = *(++argv);
		} else if (!strcmp(*argv, "-ocsp_uri")) {
			if (--argc < 1) goto bad;
			ocsp_uri = *(++argv);

		} else {
			fprintf(stderr, "%s: illegal option '%s'\n", prog, *argv);
			goto end;
bad:
			fprintf(stderr, "%s: '%s' option value missing\n", prog, *argv);
			goto end;
		}

		argc--;
		argv++;
	}

	if (!days) {
		fprintf(stderr, "%s: '-days' option required\n", prog);
		printf("usage: gmssl %s %s\n\n", prog, options);
		goto end;
	}
	if (!cacert) {
		fprintf(stderr, "%s: '-cacert' option required\n", prog);
		printf("usage: gmssl %s %s\n\n", prog, options);
		goto end;
	}
	if (!keyfp) {
		fprintf(stderr, "%s: '-key' option required\n", prog);
		printf("usage: gmssl %s %s\n\n", prog, options);
		goto end;
	}
	if (!pass) {
		fprintf(stderr, "%s: '-pass' option required\n", prog);
		printf("usage: gmssl %s %s\n\n", prog, options);
		goto end;
	}

	if (x509_req_from_pem(req, &reqlen, sizeof(req), infp) != 1) {
		fprintf(stderr, "%s: parse CSR failure\n", prog);
		goto end;
	}
	if (!req_id_len) {
		strcpy(req_id, SM2_DEFAULT_ID);
		req_id_len = strlen(SM2_DEFAULT_ID);
	}
	if (x509_req_verify(req, reqlen, req_id, req_id_len) != 1) {
		fprintf(stderr, "%s: signature verification failure\n", prog);
		goto end;
	}
	if (x509_req_get_details(req, reqlen,
		NULL, &subject, &subject_len, &subject_public_key,
		NULL, NULL, NULL, NULL, NULL) != 1) {
		fprintf(stderr, "%s: parse CSR failure\n", prog);
		goto end;
	}

	if (x509_cert_get_subject(cacert, cacertlen, &issuer, &issuer_len) != 1
		|| x509_cert_get_subject_public_key(cacert, cacertlen, &issuer_public_key) != 1) {
		fprintf(stderr, "%s: parse CA certificate failure\n", prog);
		goto end;
	}
	if (sm2_private_key_info_decrypt_from_pem(&sm2_key, pass, keyfp) != 1) {
		fprintf(stderr, "%s: load private key failure\n", prog);
		goto end;
	}
	if (sm2_public_key_equ(&sm2_key, &issuer_public_key) != 1) {
		fprintf(stderr, "%s: private key and CA certificate not match\n", prog);
		goto end;
	}
	if (!signer_id_len) {
		strcpy(signer_id, SM2_DEFAULT_ID);
		signer_id_len = strlen(SM2_DEFAULT_ID);
	}

	if (rand_bytes(serial, serial_len) != 1) {
		fprintf(stderr, "%s: random number generator error\n", prog);
		goto end;
	}

	time(&not_before);
	if (x509_validity_add_days(&not_after, not_before, days) != 1) {
		fprintf(stderr, "%s: set Validity failure\n", prog);
		goto end;
	}

	// following code copy from certgen.c
	// Extensions
	if (gen_authority_key_id) {
		if (x509_exts_add_default_authority_key_identifier(exts, &extslen, sizeof(exts), &sm2_key) != 1) {
			fprintf(stderr, "%s: set AuthorityKeyIdentifier extension failure\n", prog);
			goto end;
		}
	}
	if (gen_subject_key_id) {
		if (x509_exts_add_subject_key_identifier_ex(exts, &extslen, sizeof(exts), -1, &subject_public_key) != 1) {
			fprintf(stderr, "%s: set SubjectKeyIdentifier extension failure\n", prog);
			goto end;
		}
	}
	if (key_usage) {
		if (x509_exts_add_key_usage(exts, &extslen, sizeof(exts), X509_critical, key_usage) != 1) {
			fprintf(stderr, "%s: set KeyUsage extension failure\n", prog);
			goto end;
		}
	}
	// no CertificatePolicies
	// no PolicyMappings
	if (subject_alt_name_len) {
		if (x509_exts_add_subject_alt_name(exts, &extslen, sizeof(exts),
			-1, subject_alt_name, subject_alt_name_len) != 1) {
			fprintf(stderr, "%s: set SubjectAltName extension failure\n", prog);
			goto end;
		}
	}
	if (issuer_alt_name_len) {
		if (x509_exts_add_issuer_alt_name(exts, &extslen, sizeof(exts),
			-1, issuer_alt_name, issuer_alt_name_len) != 1) {
			fprintf(stderr, "%s: set IssuerAltName extension failure\n", prog);
			goto end;
		}
	}
	// no SubjectDirectoryAttributes
	if (ca >= 0 || path_len_constraint >= 0) {
		if (x509_exts_add_basic_constraints(exts, &extslen, sizeof(exts),
			X509_critical, ca, path_len_constraint) != 1) {
			fprintf(stderr, "%s: set BasicConstraints extension failure\n", prog);
			goto end;
		}
	}
	// no NameConstraints
	// no PolicyConstraints
	if (ext_key_usages_cnt) {
		if (x509_exts_add_ext_key_usage(exts, &extslen, sizeof(exts),
			-1, ext_key_usages, ext_key_usages_cnt) != 1) {
			fprintf(stderr, "%s: set ExtKeyUsage extension failure\n", prog);
			goto end;
		}
	}
	if (crl_http_uri || crl_ldap_uri) {
		if (x509_exts_add_crl_distribution_points(exts, &extslen, sizeof(exts),
			-1,
			crl_http_uri, crl_http_uri ? strlen(crl_http_uri) : 0,
			crl_ldap_uri, crl_ldap_uri ? strlen(crl_ldap_uri) : 0) != 1) {
			fprintf(stderr, "%s: set CRLDistributionPoints extension failure\n", prog);
			return -1;
		}
	}
	if (inhibit_any_policy >= 0) {
		if (x509_exts_add_inhibit_any_policy(exts, &extslen, sizeof(exts),
			X509_critical, inhibit_any_policy) != 1) {
			fprintf(stderr, "%s: set InhibitAnyPolicy extension failure\n", prog);
			goto end;
		}
	}
	if (ca_issuers_uri || ocsp_uri) {
		if (x509_exts_add_authority_info_access(exts, &extslen, sizeof(exts), 0,
			ca_issuers_uri, ca_issuers_uri ? strlen(ca_issuers_uri) : 0,
			ocsp_uri, ocsp_uri ? strlen(ocsp_uri) : 0) != 1) {
			fprintf(stderr, "%s: set AuthorityInfoAccess extension failure\n",  prog);
			goto end;
		}
	}

	if (x509_cert_sign_to_der(
		X509_version_v3,
		serial, serial_len,
		OID_sm2sign_with_sm3,
		issuer, issuer_len,
		not_before, not_after,
		subject, subject_len,
		&subject_public_key,
		NULL, 0,
		NULL, 0,
		exts, extslen,
		&sm2_key, signer_id, signer_id_len,
		NULL, &certlen) != 1) {
		fprintf(stderr, "%s: certificate generation failure\n", prog);
		goto end;
	}
	if (!(cert = malloc(certlen))) {
		fprintf(stderr, "%s: malloc failure\n", prog);
		goto end;
	}
	p = cert;
	certlen = 0;
	if (x509_cert_sign_to_der(
		X509_version_v3,
		serial, serial_len,
		OID_sm2sign_with_sm3,
		issuer, issuer_len,
		not_before, not_after,
		subject, subject_len,
		&subject_public_key,
		NULL, 0,
		NULL, 0,
		exts, extslen,
		&sm2_key, signer_id, signer_id_len,
		&p, &certlen) != 1) {
		fprintf(stderr, "%s: certificate generation failure\n", prog);
		goto end;
	}

	if (x509_cert_to_pem(cert, certlen, outfp) != 1) {
		fprintf(stderr, "%s: output certificate failed\n", prog);
		goto end;
	}
	ret = 0;
end:
	gmssl_secure_clear(&sm2_key, sizeof(SM2_KEY));
	if (cert) free(cert);
	if (keyfp) fclose(keyfp);
	if (infile && infp) fclose(infp);
	if (outfile && outfp) fclose(outfp);
	return ret;
}
