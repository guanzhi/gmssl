/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#ifndef GMSSL_TLS_H
#define GMSSL_TLS_H


#include <stdint.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/digest.h>
#include <gmssl/block_cipher.h>
#include <gmssl/socket.h>


#ifdef __cplusplus
extern "C" {
#endif


typedef uint32_t uint24_t;

#define tls_uint8_size()	1
#define tls_uint16_size()	2
#define tls_uint24_size()	3

void tls_uint8_to_bytes(uint8_t a, uint8_t **out, size_t *outlen);
void tls_uint16_to_bytes(uint16_t a, uint8_t **out, size_t *outlen);
void tls_uint24_to_bytes(uint24_t a, uint8_t **out, size_t *outlen);
void tls_uint32_to_bytes(uint32_t a, uint8_t **out, size_t *outlen);
void tls_array_to_bytes(const uint8_t *data, size_t len, uint8_t **out, size_t *outlen);
void tls_uint8array_to_bytes(const uint8_t *data, size_t datalen, uint8_t **out, size_t *outlen);
void tls_uint16array_to_bytes(const uint8_t *data, size_t datalen, uint8_t **out, size_t *outlen);
void tls_uint24array_to_bytes(const uint8_t *data, size_t datalen, uint8_t **out, size_t *outlen);
int tls_uint8_from_bytes(uint8_t *a, const uint8_t **in, size_t *inlen);
int tls_uint16_from_bytes(uint16_t *a, const uint8_t **in, size_t *inlen);
int tls_uint24_from_bytes(uint24_t *a, const uint8_t **in, size_t *inlen);
int tls_uint32_from_bytes(uint32_t *a, const uint8_t **in, size_t *inlen);
int tls_array_from_bytes(const uint8_t **data, size_t datalen, const uint8_t **in, size_t *inlen);
int tls_uint8array_from_bytes(const uint8_t **data, size_t *datalen, const uint8_t **in, size_t *inlen);
int tls_uint16array_from_bytes(const uint8_t **data, size_t *datalen, const uint8_t **in, size_t *inlen);
int tls_uint24array_from_bytes(const uint8_t **data, size_t *datalen, const uint8_t **in, size_t *inlen);
int tls_length_is_zero(size_t len);


typedef enum {
	TLS_protocol_tlcp			= 0x0101,
	TLS_protocol_ssl2			= 0x0002,
	TLS_protocol_ssl3			= 0x0300,
	TLS_protocol_tls1			= 0x0301,
	TLS_protocol_tls11			= 0x0302,
	TLS_protocol_tls12			= 0x0303,
	TLS_protocol_tls13			= 0x0304,
	TLS_protocol_dtls1			= 0xfeff, // {254, 255}
	TLS_protocol_dtls12			= 0xfefd, // {254, 253}
} TLS_PROTOCOL;

const char *tls_protocol_name(int proto);


typedef enum {
	TLS_cipher_null_with_null_null		= 0x0000,

	// TLS 1.3, RFC 8998
	TLS_cipher_sm4_gcm_sm3			= 0x00c6,
	TLS_cipher_sm4_ccm_sm3			= 0x00c7,

	// TLCP, GB/T 38636-2020, GM/T 0024-2012
	TLS_cipher_ecdhe_sm4_cbc_sm3		= 0xe011, // TODO: let TLSv1.2 use this as default cipher suite
	TLS_cipher_ecdhe_sm4_gcm_sm3		= 0xe051,
	TLS_cipher_ecc_sm4_cbc_sm3		= 0xe013,
	TLS_cipher_ecc_sm4_gcm_sm3		= 0xe053,
	TLS_cipher_ibsdh_sm4_cbc_sm3		= 0xe015,
	TLS_cipher_ibsdh_sm4_gcm_sm3		= 0xe055,
	TLS_cipher_ibc_sm4_cbc_sm3		= 0xe017,
	TLS_cipher_ibc_sm4_gcm_sm3		= 0xe057,
	TLS_cipher_rsa_sm4_cbc_sm3		= 0xe019,
	TLS_cipher_rsa_sm4_gcm_sm3		= 0xe059,
	TLS_cipher_rsa_sm4_cbc_sha256		= 0xe01c,
	TLS_cipher_rsa_sm4_gcm_sha256		= 0xe05a,

	// TLS 1.3 RFC 8446
	TLS_cipher_aes_128_gcm_sha256		= 0x1301, // Mandatory-to-implement
	TLS_cipher_aes_256_gcm_sha384		= 0x1302, // SHOULD implement
	TLS_cipher_chacha20_poly1305_sha256	= 0x1303, // SHOULD implement
	TLS_cipher_aes_128_ccm_sha256		= 0x1304,
	TLS_cipher_aes_128_ccm_8_sha256		= 0x1305,

	TLS_cipher_empty_renegotiation_info_scsv = 0x00ff,
} TLS_CIPHER_SUITE;

const char *tls_cipher_suite_name(int cipher);
int tls_cipher_suites_select(const uint8_t *client_ciphers, size_t client_ciphers_len,
	const int *server_ciphers, size_t server_ciphers_cnt, int *selected_cipher);
int tls_cipher_suite_in_list(int cipher, const int *list, size_t list_count);


typedef enum {
	TLS_compression_null	= 0,
	TLS_compression_default	= 1,
} TLS_COMPRESSION_METHOD;

const char *tls_compression_method_name(int meth);


typedef enum {
	TLS_record_invalid			= 0,  // TLS 1.3
	TLS_record_change_cipher_spec		= 20, // 0x14
	TLS_record_alert			= 21, // 0x15
	TLS_record_handshake			= 22, // 0x16
	TLS_record_application_data		= 23, // 0x17
	TLS_record_heartbeat			= 24, // 0x18
	TLS_record_tls12_cid			= 25, // 0x19
} TLS_RECORD_TYPE;

const char *tls_record_type_name(int type);


typedef enum  {
	TLS_handshake_hello_request		= 0,
	TLS_handshake_client_hello		= 1,
	TLS_handshake_server_hello		= 2,
	TLS_handshake_hello_verify_request	= 3,
	TLS_handshake_new_session_ticket	= 4,
	TLS_handshake_end_of_early_data		= 5,
	TLS_handshake_hello_retry_request	= 6,
	TLS_handshake_encrypted_extensions	= 8,
	TLS_handshake_certificate		= 11,
	TLS_handshake_server_key_exchange	= 12,
	TLS_handshake_certificate_request	= 13,
	TLS_handshake_server_hello_done		= 14,
	TLS_handshake_certificate_verify	= 15,
	TLS_handshake_client_key_exchange	= 16,
	TLS_handshake_finished			= 20,
	TLS_handshake_certificate_url		= 21,
	TLS_handshake_certificate_status	= 22,
	TLS_handshake_supplemental_data		= 23,
	TLS_handshake_key_update		= 24,
	TLS_handshake_compressed_certificate	= 25,
	TLS_handshake_ekt_key			= 26,
	TLS_handshake_message_hash		= 254,
} TLS_HANDSHAKE_TYPE;

const char *tls_handshake_type_name(int type);


typedef enum {
	TLS_cert_type_rsa_sign			= 1,
	TLS_cert_type_dss_sign			= 2,
	TLS_cert_type_rsa_fixed_dh		= 3,
	TLS_cert_type_dss_fixed_dh		= 4,
	TLS_cert_type_rsa_ephemeral_dh_RESERVED = 5,
	TLS_cert_type_dss_ephemeral_dh_RESERVED = 6,
	TLS_cert_type_fortezza_dms_RESERVED	= 20,
	TLS_cert_type_ecdsa_sign		= 64, // also for sm2
	TLS_cert_type_rsa_fixed_ecdh		= 65,
	TLS_cert_type_ecdsa_fixed_ecdh		= 66,
	TLS_cert_type_gost_sign256		= 67,
	TLS_cert_type_gost_sign512		= 68,
	TLS_cert_type_ibc_params		= 80,
} TLS_CERTIFICATE_TYPE;

const char *tls_cert_type_name(int type);
int tls_cert_type_from_oid(int oid);

typedef enum {
	TLS_extension_server_name		= 0,
	TLS_extension_max_fragment_length	= 1,
	TLS_extension_client_certificate_url	= 2,
	TLS_extension_trusted_ca_keys		= 3,
	TLS_extension_truncated_hmac		= 4,
	TLS_extension_status_request		= 5,
	TLS_extension_user_mapping		= 6,
	TLS_extension_client_authz		= 7,
	TLS_extension_server_authz		= 8,
	TLS_extension_cert_type			= 9,
	TLS_extension_supported_groups		= 10,
	TLS_extension_ec_point_formats		= 11,
	TLS_extension_srp			= 12,
	TLS_extension_signature_algorithms	= 13,
	TLS_extension_use_srtp			= 14,
	TLS_extension_heartbeat			= 15,
	TLS_extension_application_layer_protocol_negotiation= 16,
	TLS_extension_status_request_v2		= 17,
	TLS_extension_signed_certificate_timestamp = 18,
	TLS_extension_client_certificate_type	= 19,
	TLS_extension_server_certificate_type	= 20,
	TLS_extension_padding			= 21,
	TLS_extension_encrypt_then_mac		= 22,
	TLS_extension_extended_master_secret	= 23,
	TLS_extension_token_binding		= 24,
	TLS_extension_cached_info		= 25,
	TLS_extension_tls_lts			= 26,
	TLS_extension_compress_certificate	= 27,
	TLS_extension_record_size_limit		= 28,
	TLS_extension_pwd_protect		= 29,
	TLS_extension_pwd_clear			= 30,
	TLS_extension_password_salt		= 31,
	TLS_extension_ticket_pinning		= 32,
	TLS_extension_tls_cert_with_extern_psk	= 33,
	TLS_extension_delegated_credentials	= 34,
	TLS_extension_session_ticket		= 35,
	TLS_extension_TLMSP			= 36,
	TLS_extension_TLMSP_proxying		= 37,
	TLS_extension_TLMSP_delegate		= 38,
	TLS_extension_supported_ekt_ciphers	= 39,
	TLS_extension_pre_shared_key		= 41,
	TLS_extension_early_data		= 42,
	TLS_extension_supported_versions	= 43,
	TLS_extension_cookie			= 44,
	TLS_extension_psk_key_exchange_modes	= 46,
	TLS_extension_certificate_authorities	= 47,
	TLS_extension_oid_filters		= 48,
	TLS_extension_post_handshake_auth	= 49,
	TLS_extension_signature_algorithms_cert	= 50,
	TLS_extension_key_share			= 51,
	TLS_extension_transparency_info		= 52,
	TLS_extension_connection_id		= 53,
	TLS_extension_external_id_hash		= 55,
	TLS_extension_external_session_id	= 56,
	TLS_extension_quic_transport_parameters	= 57,
	TLS_extension_ticket_request		= 58,
	TLS_extension_renegotiation_info	= 65281,
} TLS_EXTENSION_TYPE;

const char *tls_extension_name(int ext);


typedef enum {
	TLS_point_uncompressed			= 0,
	TLS_point_ansix962_compressed_prime	= 1,
	TLS_point_ansix962_compressed_char2	= 2,
} TLS_EC_POINT_FORMAT;

const char *tls_ec_point_format_name(int format);


typedef enum {
	TLS_curve_type_explicit_prime		= 1,
	TLS_curve_type_explicit_char2		= 2,
	TLS_curve_type_named_curve		= 3,
} TLS_CURVE_TYPE;

const char *tls_curve_type_name(int type);


typedef enum {
	TLS_curve_secp256k1			= 22,
	TLS_curve_secp256r1			= 23,
	TLS_curve_secp384r1			= 24,
	TLS_curve_secp521r1			= 25,
	TLS_curve_brainpoolp256r1		= 26,
	TLS_curve_brainpoolp384r1		= 27,
	TLS_curve_brainpoolp512r1		= 28,
	TLS_curve_x25519			= 29,
	TLS_curve_x448				= 30,
	TLS_curve_brainpoolp256r1tls13		= 31,
	TLS_curve_brainpoolp384r1tls13		= 32,
	TLS_curve_brainpoolp512r1tls13		= 33,
	TLS_curve_sm2p256v1			= 41, // GmSSLv2: 30
} TLS_NAMED_CURVE;

const char *tls_curve_name(int curve);


typedef enum {
	TLS_sig_rsa_pkcs1_sha1			= 0x0201,
	TLS_sig_ecdsa_sha1			= 0x0203,
	TLS_sig_rsa_pkcs1_sha256		= 0x0401,
	TLS_sig_ecdsa_secp256r1_sha256		= 0x0403,
	TLS_sig_rsa_pkcs1_sha256_legacy		= 0x0420,
	TLS_sig_rsa_pkcs1_sha384		= 0x0501,
	TLS_sig_ecdsa_secp384r1_sha384		= 0x0503,
	TLS_sig_rsa_pkcs1_sha384_legacy		= 0x0520,
	TLS_sig_rsa_pkcs1_sha512		= 0x0601,
	TLS_sig_ecdsa_secp521r1_sha512		= 0x0603,
	TLS_sig_rsa_pkcs1_sha512_legacy		= 0x0620,
	TLS_sig_sm2sig_sm3			= 0x0708, // GmSSLv2: 0x0707
	TLS_sig_rsa_pss_rsae_sha256		= 0x0804,
	TLS_sig_rsa_pss_rsae_sha384		= 0x0805,
	TLS_sig_rsa_pss_rsae_sha512		= 0x0806,
	TLS_sig_ed25519				= 0x0807,
	TLS_sig_ed448				= 0x0808,
	TLS_sig_rsa_pss_pss_sha256		= 0x0809,
	TLS_sig_rsa_pss_pss_sha384		= 0x080A,
	TLS_sig_rsa_pss_pss_sha512		= 0x080B,
	TLS_sig_ecdsa_brainpoolP256r1tls13_sha256 = 0x081A,
	TLS_sig_ecdsa_brainpoolP384r1tls13_sha384 = 0x081B,
	TLS_sig_ecdsa_brainpoolP512r1tls13_sha512 = 0x081C,
} TLS_SIGNATURE_SCHEME;

const char *tls_signature_scheme_name(int scheme);


typedef enum {
	TLS_change_cipher_spec = 1,
} TLS_CHANGE_CIPHER_SPEC_TYPE;


typedef enum {
	TLS_alert_level_undefined = 0,
	TLS_alert_level_warning = 1,
	TLS_alert_level_fatal = 2,
} TLS_ALERT_LEVEL;

const char *tls_alert_level_name(int level);


typedef enum {
	TLS_alert_close_notify			= 0,
	TLS_alert_unexpected_message		= 10,
	TLS_alert_bad_record_mac		= 20,
	TLS_alert_decryption_failed		= 21,
	TLS_alert_record_overflow		= 22,
	TLS_alert_decompression_failure		= 30,
	TLS_alert_handshake_failure		= 40,
	TLS_alert_no_certificate		= 41,
	TLS_alert_bad_certificate		= 42,
	TLS_alert_unsupported_certificate	= 43,
	TLS_alert_certificate_revoked		= 44,
	TLS_alert_certificate_expired		= 45,
	TLS_alert_certificate_unknown		= 46,
	TLS_alert_illegal_parameter		= 47,
	TLS_alert_unknown_ca			= 48,
	TLS_alert_access_denied			= 49,
	TLS_alert_decode_error			= 50,
	TLS_alert_decrypt_error			= 51,
	TLS_alert_export_restriction		= 60,
	TLS_alert_protocol_version		= 70,
	TLS_alert_insufficient_security		= 71,
	TLS_alert_internal_error		= 80,
	TLS_alert_user_canceled			= 90,
	TLS_alert_no_renegotiation		= 100,
	TLS_alert_unsupported_extension		= 110,
	TLS_alert_unsupported_site2site		= 200,
	TLS_alert_no_area			= 201,
	TLS_alert_unsupported_areatype		= 202,
	TLS_alert_bad_ibcparam			= 203,
	TLS_alert_unsupported_ibcparam		= 204,
	TLS_alert_identity_need			= 205,
} TLS_ALERT_DESCRIPTION;

const char *tls_alert_description_text(int description);


int tls_prf(const uint8_t *secret, size_t secretlen, const char *label,
	const uint8_t *seed, size_t seedlen,
	const uint8_t *more, size_t morelen,
	size_t outlen, uint8_t *out);
int tls13_hkdf_extract(const DIGEST *digest, const uint8_t salt[32], const uint8_t in[32], uint8_t out[32]);
int tls13_hkdf_expand_label(const DIGEST *digest, const uint8_t secret[32],
	const char *label, const uint8_t *context, size_t context_len,
	size_t outlen, uint8_t *out);
int tls13_derive_secret(const uint8_t secret[32], const char *label, const DIGEST_CTX *dgst_ctx, uint8_t out[32]);

int tls_cbc_encrypt(const SM3_HMAC_CTX *hmac_ctx, const SM4_KEY *enc_key,
	const uint8_t seq_num[8], const uint8_t header[5],
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int tls_cbc_decrypt(const SM3_HMAC_CTX *hmac_ctx, const SM4_KEY *dec_key,
	const uint8_t seq_num[8], const uint8_t header[5],
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int tls_record_encrypt(const SM3_HMAC_CTX *hmac_ctx, const SM4_KEY *cbc_key,
	const uint8_t seq_num[8], const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen);
int tls_record_decrypt(const SM3_HMAC_CTX *hmac_ctx, const SM4_KEY *cbc_key,
	const uint8_t seq_num[8], const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen);

int tls_seq_num_incr(uint8_t seq_num[8]);
int tls_random_generate(uint8_t random[32]);
int tls_random_print(FILE *fp, const uint8_t random[32], int format, int indent);
int tls_pre_master_secret_generate(uint8_t pre_master_secret[48], int protocol);
int tls_pre_master_secret_print(FILE *fp, const uint8_t pre_master_secret[48], int format, int indent);

int tls_secrets_print(FILE *fp,
	const uint8_t *pre_master_secret, size_t pre_master_secret_len,
	const uint8_t client_random[32], const uint8_t server_random[32],
	const uint8_t master_secret[48],
	const uint8_t *key_block, size_t key_block_len,
	int format, int indent);


typedef struct {
	uint8_t type;
	uint8_t protocol[2];
	uint8_t data_length[2];
} TLS_RECORD_HEADER;

#define TLS_RECORD_HEADER_SIZE		(1 + tls_uint16_size() + tls_uint16_size())		// 5
#define TLS_MAX_PLAINTEXT_SIZE		(1 << 14)						// 16384
#define TLS_MAX_COMPRESSED_SIZE		((1 << 14) + 1024)					// 17408
#define TLS_MAX_CIPHERTEXT_SIZE		((1 << 14) + 2048)					// 18432
#define TLS_MAX_RECORD_SIZE		(TLS_RECORD_HEADER_SIZE + TLS_MAX_CIPHERTEXT_SIZE)	// 18437

#define tls_record_type(record)		((record)[0])
#define tls_record_header(record)	((record)+0)
#define tls_record_protocol(record)	(((uint16_t)((record)[1]) << 8) | (record)[2])
#define tls_record_data(record)		((record)+TLS_RECORD_HEADER_SIZE)
#define tls_record_data_length(record)	(((uint16_t)((record)[3]) << 8) | (record)[4])
#define tls_record_length(record)	((size_t)(TLS_RECORD_HEADER_SIZE + tls_record_data_length(record)))

int tls_record_set_type(uint8_t *record, int type);
int tls_record_set_protocol(uint8_t *record, int protocol);
int tls_record_set_data_length(uint8_t *record, size_t length);
int tls_record_set_data(uint8_t *record, const uint8_t *data, size_t datalen);


// parse ServerKeyExchange, ClientKeyExchange depends on current cipher_suite		
#define tls_format_set_cipher_suite(fmt,cipher)	do {(fmt)|=((cipher)<<8);} while (0)
int tls_record_print(FILE *fp, const uint8_t *record,  size_t recordlen, int format, int indent);
int tlcp_record_print(FILE *fp, const uint8_t *record,  size_t recordlen, int format, int indent);

int tls_record_send(const uint8_t *record, size_t recordlen, tls_socket_t sock);
int tls_record_recv(uint8_t *record, size_t *recordlen, tls_socket_t sock);
int tls12_record_recv(uint8_t *record, size_t *recordlen, tls_socket_t sock);


// Handshake
typedef struct {
	uint8_t type;
	uint8_t length[3];
} TLS_HANDSHAKE_HEADER;

#define TLS_HANDSHAKE_HEADER_SIZE	4
#define TLS_MAX_HANDSHAKE_DATA_SIZE 	(TLS_MAX_PLAINTEXT_SIZE - TLS_HANDSHAKE_HEADER_SIZE)

#define tls_handshake_data(p)		((p) + TLS_HANDSHAKE_HEADER_SIZE)
//#define tls_handshake_data_length(p)


int tls_record_set_handshake(uint8_t *record, size_t *recordlen,
	int type, const uint8_t *data, size_t datalen);
int tls_record_get_handshake(const uint8_t *record,
	int *type, const uint8_t **data, size_t *datalen);
int tls_handshake_print(FILE *fp, const uint8_t *handshake, size_t handshakelen, int format, int indent);

// HelloRequest
int tls_hello_request_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent);

// ClientHello, ServerHello
#define TLS_MIN_SESSION_ID_SIZE		0
#define TLS_MAX_SESSION_ID_SIZE		32

int tls_record_set_handshake_client_hello(uint8_t *record, size_t *recordlen,
	int client_protocol, const uint8_t random[32],
	const uint8_t *session_id, size_t session_id_len,
	const int *cipher_suites, size_t cipher_suites_count,
	const uint8_t *exts, size_t exts_len);
int tls_record_get_handshake_client_hello(const uint8_t *record,
	int *client_protocol, const uint8_t **random,
	const uint8_t **session_id, size_t *session_id_len,
	const uint8_t **cipher_suites, size_t *cipher_suites_len,
	const uint8_t **exts, size_t *exts_len);
int tls_client_hello_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent);

int tls_record_set_handshake_server_hello(uint8_t *record, size_t *recordlen,
	int server_protocol, const uint8_t random[32],
	const uint8_t *session_id, size_t session_id_len,
	int cipher_suite, const uint8_t *exts, size_t exts_len);
int tls_record_get_handshake_server_hello(const uint8_t *record,
	int *protocol, const uint8_t **random, const uint8_t **session_id, size_t *session_id_len,
	int *cipher_suite, const uint8_t **exts, size_t *exts_len);
int tls_server_hello_print(FILE *fp, const uint8_t *server_hello, size_t len, int format, int indent);

// Extensions
int tls_ec_point_formats_ext_to_bytes(const int *formats, size_t formats_cnt,
	uint8_t **out, size_t *outlen);
int tls_process_client_ec_point_formats(const uint8_t *ext_data, size_t ext_datalen,
	uint8_t **out, size_t *outlen);
int tls_process_server_ec_point_formats(const uint8_t *ext_data, size_t ext_datalen);

int tls_supported_groups_ext_to_bytes(const int *groups, size_t groups_cnt,
	uint8_t **out, size_t *outlen);
int tls_process_client_supported_groups(const uint8_t *ext_data, size_t ext_datalen,
	uint8_t **out, size_t *outlen);
int tls_process_server_supported_groups(const uint8_t *ext_data, size_t ext_datalen);

int tls_signature_algorithms_ext_to_bytes_ex(int ext_type, const int *algs, size_t algs_cnt,
	uint8_t **out, size_t *outlen);
int tls_signature_algorithms_ext_to_bytes(const int *algs, size_t algs_cnt,
	uint8_t **out, size_t *outlen);
int tls13_signature_algorithms_cert_ext_to_bytes(const int *algs, size_t algs_cnt,
	uint8_t **out, size_t *outlen);
int tls_process_client_signature_algorithms(const uint8_t *ext_data, size_t ext_datalen,
	uint8_t **out, size_t *outlen);
int tls_process_server_signature_algors(const uint8_t *ext_data, size_t ext_datalen);

int tls13_supported_versions_ext_to_bytes(int handshake_type, const int *protos, size_t protos_cnt,
	uint8_t **out, size_t *outlen);
int tls13_process_client_supported_versions(const uint8_t *ext_data, size_t ext_datalen,
	uint8_t **out, size_t *outlen);

int tls13_process_server_supported_versions(const uint8_t *ext_data, size_t ext_datalen);

int tls13_key_share_entry_to_bytes(const SM2_Z256_POINT *point, uint8_t **out, size_t *outlen);
int tls13_client_key_share_ext_to_bytes(const SM2_Z256_POINT *point, uint8_t **out, size_t *outlen);
int tls13_server_key_share_ext_to_bytes(const SM2_Z256_POINT *point, uint8_t **out, size_t *outlen);
int tls13_process_client_key_share(const uint8_t *ext_data, size_t ext_datalen,
	const SM2_KEY *server_ecdhe_key, SM2_Z256_POINT *client_ecdhe_public,
	uint8_t **out, size_t *outlen);
int tls13_process_server_key_share(const uint8_t *ext_data, size_t ext_datalen, SM2_Z256_POINT *point);


int tls13_certificate_authorities_ext_to_bytes(const uint8_t *ca_names, size_t ca_names_len,
	uint8_t **out, size_t *outlen);

int tls_ext_from_bytes(int *type, const uint8_t **data, size_t *datalen, const uint8_t **in, size_t *inlen);
int tls_process_client_exts(const uint8_t *exts, size_t extslen, uint8_t *out, size_t *outlen, size_t maxlen);
int tls_process_server_exts(const uint8_t *exts, size_t extslen,
	int *ec_point_format, int *supported_group, int *signature_algor);


// Certificate
int tls_record_set_handshake_certificate(uint8_t *record, size_t *recordlen,
	const uint8_t *certs, size_t certslen);
// see the impl of tls_record_get_handshake_certificate			
// a standalone cert-chain parsing function should be given			
int tls_record_get_handshake_certificate(const uint8_t *record, uint8_t *certs, size_t *certslen);

// ServerKeyExchange
int tls_server_key_exchange_print(FILE *fp, const uint8_t *ske, size_t skelen, int format, int indent);

#define TLS_MAX_SIGNATURE_SIZE	SM2_MAX_SIGNATURE_SIZE
int tls_sign_server_ecdh_params(const SM2_KEY *server_sign_key,
	const uint8_t client_random[32], const uint8_t server_random[32],
	int curve, const SM2_Z256_POINT *point, uint8_t *sig, size_t *siglen);
int tls_verify_server_ecdh_params(const SM2_KEY *server_sign_key,
	const uint8_t client_random[32], const uint8_t server_random[32],
	int curve, const SM2_Z256_POINT *point, const uint8_t *sig, size_t siglen);
int tls_record_set_handshake_server_key_exchange_ecdhe(uint8_t *record, size_t *recordlen,
	int curve, const SM2_Z256_POINT *point, const uint8_t *sig, size_t siglen);
int tls_record_get_handshake_server_key_exchange_ecdhe(const uint8_t *record,
	int *curve, SM2_Z256_POINT *point, const uint8_t **sig, size_t *siglen);
int tls_server_key_exchange_ecdhe_print(FILE *fp, const uint8_t *data, size_t datalen,
	int format, int indent);

int tlcp_record_set_handshake_server_key_exchange_pke(uint8_t *record, size_t *recordlen,
	const uint8_t *sig, size_t siglen);
int tlcp_record_get_handshake_server_key_exchange_pke(const uint8_t *record,
	const uint8_t **sig, size_t *siglen);
int tlcp_server_key_exchange_pke_print(FILE *fp, const uint8_t *sig, size_t siglen, int format, int indent);



// CertificateRequest
#define TLS_MAX_CERTIFICATE_TYPES	256
#define TLS_MAX_CA_NAMES_SIZE		(TLS_MAX_HANDSHAKE_DATA_SIZE - tls_uint8_size() - tls_uint16_size())

int tls_authorities_from_certs(uint8_t *ca_names, size_t *ca_names_len, size_t maxlen, const uint8_t *certs, size_t certslen);
int tls_authorities_issued_certificate(const uint8_t *ca_names, size_t ca_namelen, const uint8_t *certs, size_t certslen);
int tls_cert_types_accepted(const uint8_t *types, size_t types_len, const uint8_t *client_certs, size_t client_certs_len);

int tls_record_set_handshake_certificate_request(uint8_t *record, size_t *recordlen,
	const uint8_t *cert_types, size_t cert_types_len,
	const uint8_t *ca_names, size_t ca_names_len);
int tls_record_get_handshake_certificate_request(const uint8_t *record,
	const uint8_t **cert_types, size_t *cert_types_len,
	const uint8_t **ca_names, size_t *ca_names_len);
int tls_certificate_request_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent);


// ServerHelloDone
int tls_record_set_handshake_server_hello_done(uint8_t *record, size_t *recordlen);
int tls_record_get_handshake_server_hello_done(const uint8_t *record);
int tls_server_hello_done_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent);

// ClientKeyExchange
int tls_record_set_handshake_client_key_exchange_pke(uint8_t *record, size_t *recordlen,
	const uint8_t *enced_pms, size_t enced_pms_len);
int tls_record_get_handshake_client_key_exchange_pke(const uint8_t *record,
	const uint8_t **enced_pms, size_t *enced_pms_len);
int tls_client_key_exchange_pke_print(FILE *fp, const uint8_t *cke, size_t ckelen, int format, int indent);
int tls_client_key_exchange_print(FILE *fp, const uint8_t *cke, size_t ckelen, int format, int indent);

int tls_record_set_handshake_client_key_exchange_ecdhe(uint8_t *record, size_t *recordlen,
	const SM2_Z256_POINT *point); // shoulde we use SM2_Z256_POITN?						
int tls_record_get_handshake_client_key_exchange_ecdhe(const uint8_t *record, SM2_Z256_POINT *point);			
int tls_client_key_exchange_ecdhe_print(FILE *fp, const uint8_t *data, size_t datalen,
	int format, int indent);

// CertificateVerify
int tls_record_set_handshake_certificate_verify(uint8_t *record, size_t *recordlen,
	const uint8_t *sig, size_t siglen);
int tls_record_get_handshake_certificate_verify(const uint8_t *record,
	const uint8_t **sig, size_t *siglen);
int tls_certificate_verify_print(FILE *fp, const uint8_t *p, size_t len, int format, int indent);

typedef enum {
	TLS_client_verify_client_hello		= 0,
	TLS_client_verify_server_hello		= 1,
	TLS_client_verify_server_certificate	= 2,
	TLS_client_verify_server_key_exchange	= 3,
	TLS_client_verify_cert_request		= 4,
	TLS_client_verify_server_hello_done	= 5,
	TLS_client_verify_client_certificate	= 6,
	TLS_client_verify_client_key_exchange	= 7,
} TLS_CLIENT_VERIFY_INDEX;

typedef struct {
	TLS_CLIENT_VERIFY_INDEX index;
	uint8_t *handshake[8]; // Record data only, no record header
	size_t handshake_len[8];
} TLS_CLIENT_VERIFY_CTX;

int tls_client_verify_init(TLS_CLIENT_VERIFY_CTX *ctx);
int tls_client_verify_update(TLS_CLIENT_VERIFY_CTX *ctx, const uint8_t *handshake, size_t handshake_len);
int tls_client_verify_finish(TLS_CLIENT_VERIFY_CTX *ctx, const uint8_t *sig, size_t siglen, const SM2_KEY *public_key);
void tls_client_verify_cleanup(TLS_CLIENT_VERIFY_CTX *ctx);

// Finished
// FIXME: to support TLS 1.3  need MIN, MAX or TLS12, TLS13, TLCP...			
#define TLS_VERIFY_DATA_SIZE 12 // TLS 1.3 use longer verify_data (>= 12 bytes)		
#define TLS_FINISHED_RECORD_SIZE	(TLS_RECORD_HEADER_SIZE + TLS_HANDSHAKE_HEADER_SIZE + TLS_VERIFY_DATA_SIZE) // 21
#define TLS_MAX_PADDING_SIZE		(1 + 255)
#define TLS_MAC_SIZE			SM3_HMAC_SIZE
#define TLS_FINISHED_RECORD_BUF_SIZE	(TLS_FINISHED_RECORD_SIZE + TLS_MAC_SIZE + TLS_MAX_PADDING_SIZE) // 309


int tls_record_set_handshake_finished(uint8_t *record, size_t *recordlen,
	const uint8_t *verify_data, size_t verify_data_len);
int tls_record_get_handshake_finished(const uint8_t *record,
	const uint8_t **verify_data, size_t *verify_data_len);
int tls_finished_print(FILE *fp, const uint8_t *a, size_t len, int format, int indent);


// Alert
typedef struct {
	uint8_t level;
	uint8_t description;
} TLS_ALERT;

#define TLS_ALERT_RECORD_SIZE (TLS_RECORD_HEADER_SIZE + 2)

int tls_record_set_alert(uint8_t *record, size_t *recordlen, int alert_level, int alert_description);
int tls_record_get_alert(const uint8_t *record, int *alert_level, int *alert_description);
int tls_alert_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent);


// ChangeCipherSpec
typedef struct {
	uint8_t type;
} TLS_CHANGE_CIPHER_SPEC;

const char *tls_change_cipher_spec_text(int change_cipher_spec);
int tls_change_cipher_spec_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent);
int tls_record_set_change_cipher_spec(uint8_t *record, size_t *recordlen);
int tls_record_get_change_cipher_spec(const uint8_t *record);

// ApplicationData
int tls_record_set_application_data(uint8_t *record, size_t *recordlen,
	const uint8_t *data, size_t datalen);
int tls_record_get_application_data(uint8_t *record,
	const uint8_t **data, size_t *datalen);
int tls_application_data_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent);



enum {
	TLS_server_mode = 0,
	TLS_client_mode = 1,
};

#define TLS_MAX_CIPHER_SUITES_COUNT	64

typedef struct {
	int protocol;
	int is_client;
	int cipher_suites[TLS_MAX_CIPHER_SUITES_COUNT];
	size_t cipher_suites_cnt;
	uint8_t *cacerts;
	size_t cacertslen;
	uint8_t *certs;
	size_t certslen;
	SM2_KEY signkey;
	SM2_KEY kenckey;
	int verify_depth;

	int quiet;
} TLS_CTX;

int tls_ctx_init(TLS_CTX *ctx, int protocol, int is_client);
int tls_ctx_set_cipher_suites(TLS_CTX *ctx, const int *cipher_suites, size_t cipher_suites_cnt);
int tls_ctx_set_ca_certificates(TLS_CTX *ctx, const char *cacertsfile, int depth);
int tls_ctx_set_certificate_and_key(TLS_CTX *ctx, const char *chainfile,
	const char *keyfile, const char *keypass);
int tls_ctx_set_tlcp_server_certificate_and_keys(TLS_CTX *ctx, const char *chainfile,
	const char *signkeyfile, const char *signkeypass,
	const char *kenckeyfile, const char *kenckeypass);
void tls_ctx_cleanup(TLS_CTX *ctx);



#define TLS_MAX_CERTIFICATES_SIZE	2048
#define TLS_DEFAULT_VERIFY_DEPTH	4
#define TLS_MAX_VERIFY_DEPTH		5


typedef struct {
	int protocol;
	int is_client;
	int cipher_suites[TLS_MAX_CIPHER_SUITES_COUNT];
	size_t cipher_suites_cnt;
	tls_socket_t sock;

	uint8_t enced_record[TLS_MAX_RECORD_SIZE];
	size_t enced_record_len;


	uint8_t record[TLS_MAX_RECORD_SIZE];

	uint8_t databuf[TLS_MAX_RECORD_SIZE];
	uint8_t *data;
	size_t datalen;

	int cipher_suite;
	uint8_t session_id[32];
	size_t session_id_len;
	uint8_t server_certs[TLS_MAX_CERTIFICATES_SIZE]; // TODO: use ptr and malloc			
	size_t server_certs_len;
	uint8_t client_certs[TLS_MAX_CERTIFICATES_SIZE];
	size_t client_certs_len;
	uint8_t ca_certs[2048];
	size_t ca_certs_len;

	SM2_KEY sign_key;
	SM2_KEY kenc_key;

	int verify_result;

	uint8_t master_secret[48];
	uint8_t key_block[96];

	SM3_HMAC_CTX client_write_mac_ctx;
	SM3_HMAC_CTX server_write_mac_ctx;
	SM4_KEY client_write_enc_key;
	SM4_KEY server_write_enc_key;
	uint8_t client_seq_num[8];
	uint8_t server_seq_num[8];

	uint8_t client_write_iv[12]; // tls13
	uint8_t server_write_iv[12]; // tls13
	BLOCK_CIPHER_KEY client_write_key;
	BLOCK_CIPHER_KEY server_write_key;

	int quiet;
} TLS_CONNECT;


#define TLS_MAX_EXTENSIONS_SIZE 512 // FIXME: no reason to give fixed max length			


int tls_init(TLS_CONNECT *conn, const TLS_CTX *ctx);
int tls_set_socket(TLS_CONNECT *conn, tls_socket_t sock);
int tls_do_handshake(TLS_CONNECT *conn);
int tls_send(TLS_CONNECT *conn, const uint8_t *in, size_t inlen, size_t *sentlen);
int tls_recv(TLS_CONNECT *conn, uint8_t *out, size_t outlen, size_t *recvlen);
int tls_shutdown(TLS_CONNECT *conn);
void tls_cleanup(TLS_CONNECT *conn);

int tlcp_do_connect(TLS_CONNECT *conn);
int tlcp_do_accept(TLS_CONNECT *conn);
int tls12_do_connect(TLS_CONNECT *conn);
int tls12_do_accept(TLS_CONNECT *conn);


#define TLS13_SM2_ID		"TLSv1.3+GM+Cipher+Suite"
#define TLS13_SM2_ID_LENGTH	(sizeof(TLS13_SM2_ID)-1)

int tls13_do_connect(TLS_CONNECT *conn);
int tls13_do_accept(TLS_CONNECT *conn);

int tls_send_alert(TLS_CONNECT *conn, int alert);
int tls_send_warning(TLS_CONNECT *conn, int alert);

int tls13_send(TLS_CONNECT *conn, const uint8_t *data, size_t datalen, size_t *sentlen);
int tls13_recv(TLS_CONNECT *conn, uint8_t *out, size_t outlen, size_t *recvlen);


int tls13_connect(TLS_CONNECT *conn, const char *hostname, int port, FILE *server_cacerts_fp,
	FILE *client_certs_fp, const SM2_KEY *client_sign_key);
int tls13_accept(TLS_CONNECT *conn, int port,
	FILE *server_certs_fp, const SM2_KEY *server_sign_key,
	FILE *client_cacerts_fp);


int tls13_supported_versions_ext_print(FILE *fp, int fmt, int ind, int handshake_type, const uint8_t *data, size_t datalen);
int tls13_key_share_ext_print(FILE *fp, int fmt, int ind, int handshake_type, const uint8_t *data, size_t datalen);


int tls_process_client_hello_exts(const uint8_t *exts, size_t extslen, uint8_t *out, size_t *outlen, size_t maxlen);
int tls_process_server_hello_exts(const uint8_t *exts, size_t extslen,
	int *ec_point_format, int *supported_group, int *signature_algor);


int tls13_encrypted_extensions_print(FILE *fp, int fmt, int ind, const uint8_t *data, size_t datalen);

int tls13_extension_print(FILE *fp, int fmt, int ind,
	int handshake_type, int ext_type, const uint8_t *ext_data, size_t ext_datalen);
int tls13_extensions_print(FILE *fp, int fmt, int ind,
	int handshake_type, const uint8_t *exts, size_t extslen);

int tls13_certificate_print(FILE *fp, int fmt, int ind, const uint8_t *cert, size_t certlen);
int tls13_certificate_request_print(FILE *fp, int fmt, int ind, const uint8_t *cert, size_t certlen);
int tls13_certificate_verify_print(FILE *fp, int fmt, int ind, const uint8_t *d, size_t dlen);
int tls13_record_print(FILE *fp, int format, int indent, const uint8_t *record, size_t recordlen);


int tls13_gcm_encrypt(const BLOCK_CIPHER_KEY *key, const uint8_t iv[12],
	const uint8_t seq_num[8], int record_type,
	const uint8_t *in, size_t inlen, size_t padding_len, // TLSInnerPlaintext.content
	uint8_t *out, size_t *outlen); // TLSCiphertext.encrypted_record
int tls13_gcm_decrypt(const BLOCK_CIPHER_KEY *key, const uint8_t iv[12],
	const uint8_t seq_num[8], const uint8_t *in, size_t inlen,
	int *record_type, uint8_t *out, size_t *outlen);


#ifdef ENABLE_TLS_DEBUG
#	define tls_trace(s) fprintf(stderr,(s))
#	define tls_record_trace(fp,rec,reclen,fmt,ind)  tls_record_print(fp,rec,reclen,fmt,ind)
#	define tls_encrypted_record_trace(fp,rec,reclen,fmt,ind)  tls_encrypted_record_print(fp,rec,reclen,fmt,ind)
#	define tlcp_record_trace(fp,rec,reclen,fmt,ind)  tlcp_record_print(fp,rec,reclen,fmt,ind)
#	define tls12_record_trace(fp,rec,reclen,fmt,ind)  tls12_record_print(fp,rec,reclen,fmt,ind)
#	define tls13_record_trace(fp,rec,reclen,fmt,ind)  tls13_record_print(fp,fmt,ind,rec,reclen)
#else
#	define tls_trace(s)
#	define tls_record_trace(fp,rec,reclen,fmt,ind)
#	define tls_encrypted_record_trace(fp,rec,reclen,fmt,ind)
#	define tlcp_record_trace(fp,rec,reclen,fmt,ind)
#	define tls12_record_trace(fp,rec,reclen,fmt,ind)
#	define tls13_record_trace(fp,rec,reclen,fmt,ind)
#endif

int tls_encrypted_record_print(FILE *fp, const uint8_t *record,  size_t recordlen, int format, int indent);

#ifdef  __cplusplus
}
#endif
#endif
