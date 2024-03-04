cmake_minimum_required(VERSION 3.6)
project(GmSSL C)

SET(CMAKE_PROJECT_HOMEPAGE_URL "http://gmssl.org")

set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
SET(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH};${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include_directories(include)

set(src
	src/version.c
	src/debug.c
	src/sm4_tbox.c
	src/sm4_modes.c
	src/sm3.c
	src/sm3_hmac.c
	src/sm3_kdf.c
	src/sm3_digest.c
	src/sm2_alg.c
	src/sm2_key.c
	src/sm2_lib.c
	src/sm2_ctx.c
	src/sm9_alg.c
	src/sm9_key.c
	src/sm9_lib.c
	src/zuc.c
	src/zuc_modes.c
	src/hash_drbg.c
	src/block_cipher.c
	src/digest.c
	src/hmac.c
	src/hkdf.c
	src/pbkdf2.c
	src/gf128.c
	src/gcm.c
	src/aead.c
	src/pkcs8.c
	src/ec.c
	src/rsa.c
	src/asn1.c
	src/hex.c
	src/base64.c
	src/pem.c
	src/x509_alg.c
	src/x509_cer.c
	src/x509_ext.c
	src/x509_req.c
	src/x509_crl.c
	src/x509_new.c
	src/cms.c
	src/sdf/sdf.c
	src/sdf/sdf_lib.c
	src/sdf/sdf_meth.c
	src/sdf/sdf_ext.c
	src/sdf/sdf_sansec.c
	src/skf/skf.c
	src/skf/skf_lib.c
	src/skf/skf_meth.c
	src/skf/skf_ext.c
	src/skf/skf_prn.c
	src/skf/skf_wisec.c
	src/socket.c
	src/tls.c
	src/tls_ext.c
	src/tls_trace.c
	src/tlcp.c
	src/tls12.c
	src/tls13.c
	src/file.c
)

set(tools
	tools/gmssl.c
	tools/version.c
	tools/sm4.c
	tools/sm3.c
	tools/sm3hmac.c
	tools/sm3xmss_keygen.c
	tools/sm2keygen.c
	tools/sm2sign.c
	tools/sm2verify.c
	tools/sm2encrypt.c
	tools/sm2decrypt.c
	tools/sm9setup.c
	tools/sm9keygen.c
	tools/sm9sign.c
	tools/sm9verify.c
	tools/sm9encrypt.c
	tools/sm9decrypt.c
	tools/zuc.c
	tools/rand.c
	tools/pbkdf2.c
	tools/certgen.c
	tools/certparse.c
	tools/certverify.c
	tools/certrevoke.c
	tools/reqgen.c
	tools/reqparse.c
	tools/reqsign.c
	tools/crlgen.c
	tools/crlget.c
	tools/crlparse.c
	tools/crlverify.c
	tools/cmssign.c
	tools/cmsverify.c
	tools/cmsencrypt.c
	tools/cmsdecrypt.c
	tools/cmsparse.c
	tools/sdfutil.c
	tools/skfutil.c
	tools/tlcp_client.c
	tools/tlcp_server.c
	tools/tls12_client.c
	tools/tls12_server.c
	tools/tls13_client.c
	tools/tls13_server.c
)

set(tests
	sm4
	sm3
	sm2
	sm2_enc
	sm9
	zuc
	hash_drbg
	block_cipher
	digest
	hmac
	hkdf
	pbkdf2
	gf128
	gcm
	aead
	pkcs8
	ec
	asn1
	hex
	base64
	pem
	x509
	x509_oid
	x509_alg
	x509_str
	x509_ext
	x509_req
	x509_crl
	cms
	tls
	tls13
)

set(demos
	asn1_oid_from_der_demo
	asn1_oid_to_der_demo
	base64_demo
	http_get_demo
	password_to_key_demo
	pem_from_der_demo
	pem_to_der_demo
	rand_demo
	sdf_info_demo
	sdf_rand_demo
	sdf_sign_demo
	#sm2_ciphertext_to_der_demo
	sm2_ecdh_demo
	sm2_encrypt_demo
	sm2_encrypt_fixlen_demo
	sm2_id_demo
	sm2_keygen_demo
	sm2_keyparse_demo
	sm2_point_demo
	sm2_point_from_bin_demo
	sm2_point_from_hash_demo
	sm2_point_from_octets_demo
	sm2_point_to_bin_demo
	sm2_point_to_octets_demo
	sm2_private_key_demo
	sm2_private_key_parse_demo
	sm2_public_key_demo
	sm2_sig_from_bin_demo
	#sm2_sig_from_der_demo
	sm2_sig_to_der_demo
	sm2_sign_ctx_demo
	sm2_sign_ctx_fixlen_demo
	sm2_sign_demo
	#sm2_sign_digest_demo
	sm3_ctx_demo
	sm3_ctx_stdin_demo
	sm3_demo
	sm3_hmac_ctx_demo
	sm3_hmac_demo
	sm4_cbc_ctx_decrypt_stdin_demo
	sm4_cbc_ctx_encrypt_stdin_demo
	sm4_cbc_demo
	sm4_cbc_padding_demo
	sm4_cbc_sm3_hmac_demo
	sm4_consts_demo
	sm4_ctr_demo
	sm4_ctr_encrypt_update_demo
	sm4_ctr_sm3_hmac_demo
	sm4_demo
	sm4_ecb_demo
	sm4_gcm_ctx_demo
	sm4_gcm_demo
	sm4_key_demo
	sm9_encrypt_demo
	sm9_keygen_demo
	sm9_sign_demo
	#tlcp_get_demo
	#tlcp_post_demo
	version_demo
	x509_cert_check_demo
	x509_cert_parse_demo
	x509_cert_print_demo
	x509_cert_verify_demo
	x509_crl_download_demo
	#x509_crl_find_revoked_cert_demo
	x509_crl_print_demo
	#x509_crl_verify_demo
	zuc_demo
	zuc_encrypt_stdin_demo
)

include(CheckSymbolExists)

# when an option has been enabled, `cmake ..` will not refresh the value
# use `cmake .. -DENABLE_XXX=OFF` to disable the option

option(ENABLE_SM2_ALGOR_ID_ENCODE_NULL "Enable AlgorithmIdenifier with algorithm sm2sign_with_sm3 encode a NULL object as parameters" OFF)
if (ENABLE_SM2_ALGOR_ID_ENCODE_NULL)
	message(STATUS "ENABLE_SM2_ALGOR_ID_ENCODE_NULL is ON")
	add_definitions(-DENABLE_SM2_ALGOR_ID_ENCODE_NULL)
endif()


option(ENABLE_SM2_PRIVATE_KEY_EXPORT "Enable export un-encrypted SM2 private key" OFF)
if (ENABLE_SM2_PRIVATE_KEY_EXPORT)
	message(STATUS "ENABLE_SM2_PRIVATE_KEY_EXPORT is ON")
	add_definitions(-DENABLE_SM2_PRIVATE_KEY_EXPORT)
	list(APPEND demos sm2_key_export_demo)
endif()


option(ENABLE_TLS_DEBUG "Enable TLS and TLCP print debug message" OFF)
if (ENABLE_TLS_DEBUG)
	message(STATUS "ENABLE_TLS_DEBUG is ON")
	add_definitions(-DENABLE_TLS_DEBUG)
endif()


#option(ENABLE_SM3_AVX_BMI2 "Enable SM3 AVX+BMI2 assembly implementation" OFF)
#if (ENABLE_SM3_AVX_BMI2)
#	message(STATUS "ENABLE_SM3_AVX_BMI2 is ON")
#	add_definitions(-DENABLE_SM3_AVX_BMI2)
#	enable_language(ASM)
#	list(APPEND src src/sm3_avx_bmi2.s)
#endif()


option(ENABLE_SM4_AESNI_AVX "Enable SM4 AESNI+AVX assembly implementation" OFF)
if (ENABLE_SM4_AESNI_AVX)
	message(STATUS "ENABLE_SM4_AESNI_AVX is ON")
	add_definitions(-DENABLE_SM4_AESNI_AVX)
	list(APPEND src src/sm4_aesni_avx.c)
	list(APPEND tests sm4_aesni_avx)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=native")
endif()


option(ENABLE_SM4_ECB "Enable SM4 ECB mode" OFF)
if (ENABLE_SM4_ECB)
	message(STATUS "ENABLE_SM4_ECB is ON")
	add_definitions(-DENABLE_SM4_ECB)
	list(APPEND src src/sm4_ecb.c)
	list(APPEND tests sm4_ecb)
endif()

option(ENABLE_SM4_OFB "Enable SM4 OFB mode" OFF)
if (ENABLE_SM4_OFB)
	message(STATUS "ENABLE_SM4_OFB is ON")
	add_definitions(-DENABLE_SM4_OFB)
	list(APPEND src src/sm4_ofb.c)
	list(APPEND tests sm4_ofb)
endif()

option(ENABLE_SM4_CFB "Enable SM4 CFB mode" OFF)
if (ENABLE_SM4_CFB)
	message(STATUS "ENABLE_SM4_CFB is ON")
	add_definitions(-DENABLE_SM4_CFB)
	list(APPEND src src/sm4_cfb.c)
	list(APPEND tests sm4_cfb)
endif()

option(ENABLE_SM4_CBC_MAC "Enable SM4-CBC-MAC" OFF)

option(ENABLE_SM4_CCM "Enable SM4 CCM mode" OFF)
if (ENABLE_SM4_CCM)
	message(STATUS "ENABLE_SM4_CCM is ON")
	set(ENABLE_SM4_CBC_MAC ON)
	add_definitions(-DENABLE_SM4_CCM)
	list(APPEND src src/sm4_ccm.c)
	list(APPEND tests sm4_ccm)
endif()

option(ENABLE_SM4_XTS "Enable SM4 XTS mode" OFF)
if (ENABLE_SM4_XTS)
	message(STATUS "ENABLE_SM4_XTS is ON")
	add_definitions(-DENABLE_SM4_XTS)
	list(APPEND src src/sm4_xts.c)
	list(APPEND tests sm4_xts)
endif()


option(ENABLE_SM2_Z256 "Enable SM2 z256 implementation" OFF)
if (ENABLE_SM2_Z256)
	message(STATUS "ENABLE_SM2_Z256 is ON")
	add_definitions(-DENABLE_SM2_Z256)
	list(APPEND src src/sm2_z256.c src/sm2_z256_table.c src/sm2_z256_sign.c)
	list(APPEND tests sm2_z256 sm2_sign)
else ()
	list(APPEND src src/sm2_sign.c)
endif()


option(ENABLE_SM2_EXTS "Enable SM2 Extensions" OFF)
if (ENABLE_SM2_EXTS)
	message(STATUS "ENABLE_SM4_AESNI_AVX")
	list(APPEND src
		src/sm2_key_share.c
		src/sm2_recover.c
		src/sm2_blind.c
		src/sm2_ring.c
		src/sm2_elgamal.c
		src/sm2_commit.c)
	list(APPEND tests sm2_key_share sm2_blind sm2_ring sm2_elgamal sm2_commit)
endif()


option(ENABLE_SM3_XMSS "Enable SM3-XMSS signature" ON)
if (ENABLE_SM3_XMSS)
	message(STATUS "ENABLE_SM3_XMSS is ON")
	list(APPEND src src/sm3_xmss.c)

	option(ENABLE_SM3_XMSS_CROSSCHECK "Enable XMSS SHA-256 cross-check" OFF)
	if (ENABLE_SM3_XMSS_CROSSCHECK)
		message(STATUS "ENABLE_SM3_XMSS_CROSSCHECK is ON")
		add_definitions(-DENABLE_SM3_XMSS_CROSSCHECK)
		list(APPEND tests sm3_xmss)
	endif()
endif()


option(ENABLE_SHA1 "Enable SHA1" OFF)
if (ENABLE_SHA1)
	message(STATUS "ENABLE_SHA1 is ON")
	add_definitions(-DENABLE_SHA1)
	list(APPEND src src/sha1.c)
	list(APPEND tests sha1)
	list(APPEND demos sha1_digest_demo)
endif()


# TODO: pbkdf, hkdf and tls13 rely on sha2
option(ENABLE_SHA2 "Enable SHA2" ON)
if (ENABLE_SHA2)
	message(STATUS "ENABLE_SHA2 is ON")
	add_definitions(-DENABLE_SHA2)
	list(APPEND src src/sha256.c src/sha512.c)
	list(APPEND tests sha224 sha256 sha384 sha512)
	list(APPEND demos sha256_digest_demo sha512_digest_demo sha512_256_digest_demo)
endif()


option(ENABLE_AES "Enable AES" ON)
if (ENABLE_AES)
	message(STATUS "ENABLE_AES is ON")
	list(APPEND src src/aes.c src/aes_modes.c)
	list(APPEND tests aes)
endif()


option(ENABLE_CHACHA20 "Enable Chacha20" OFF)
if (ENABLE_CHACHA20)
	message(STATUS "ENABLE_CHACHA20 is ON")
	list(APPEND src src/chacha20.c)
	list(APPEND tests chacha20)
endif()



option(ENABLE_INTEL_RDRAND "Enable Intel RDRAND instructions" OFF)
option(ENABLE_INTEL_RDSEED "Enable Intel RDSEED instructions" OFF)

if (ENABLE_INTEL_RDRAND)
	include(CheckSourceCompiles)
	set(CMAKE_REQUIRED_FLAGS "-rdrand")
	check_source_compiles(C
		"#include <immintrin.h> int main(void) { unsigned long long val; _rdrand64_step(&val); return 0; }"
		HAVE_INTEL_RDRAND)
	if (HAVE_INTEL_RDRAND)
		message(STATUS "ENABLE_INTEL_RDRAND")
		add_definitions(-DENABLE_INTEL_RDRAND)
		list(APPEND src src/rdrand.c)
		list(APPEND demos rdrand_demo)
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mrdrnd")
	endif()
	if (ENABLE_INTEL_RDSEED)
		set(CMAKE_REQUIRED_FLAGS "-rdseed")
		check_source_compiles(C
			"#include <immintrin.h> int main(void) { unsigned long long val; _rdseed64_step(&val); return 0; }"
			HAVE_INTEL_RDSEED)
		if (HAVE_INTEL_RDSEED)
			message(STATUS "ENABLE_INTEL_RDSEED")
			add_definitions(-DENABLE_INTEL_RDSEED)
			set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mrdseed")
		endif()
	endif()
endif()


if (ENABLE_SM4_CBC_MAC)
	message(STATUS "ENABLE_SM4_CBC_MAC is ON")
	list(APPEND src src/sm4_cbc_mac.c)
	list(APPEND tests sm4_cbc_mac)
	list(APPEND demos sm4_cbc_mac_demo)
endif()


option(ENABLE_GMT_0105_RNG "Enable GM/T 0105 Software RNG" OFF)
if (ENABLE_GMT_0105_RNG)
	message(STATUS "ENABLE_GMT_0105_RNG is ON")
	list(APPEND src src/sm3_rng.c src/sm4_rng.c)
	list(APPEND tests sm3_rng sm4_rng)
endif()


check_symbol_exists(getentropy "unistd.h" HAVE_GETENTROPY)
if (WIN32)
	list(APPEND src src/rand_win.c src/http_win.c)
elseif (APPLE)
	list(APPEND src src/rand_apple.c src/http.c)
elseif (HAVE_GETENTROPY)
	list(APPEND src src/rand_unix.c src/http.c)
	message(STATUS "have getentropy")
else()
	list(APPEND src src/rand.c src/http.c)
endif()


option(ENABLE_HTTP_TESTS "Enable HTTP GET/POST related tests" OFF)
if (ENABLE_HTTP_TESTS)
	message(STATUS "ENABLE_HTTP_TESTS")
	list(APPEND tests http http_crl)
endif()


option(BUILD_SHARED_LIBS "Build using shared libraries" ON)

if (CMAKE_C_COMPILER_ID MATCHES "MSVC")
	message(STATUS "CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS")
	set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON) # set before add_library
endif()

add_library(gmssl ${src})





if (WIN32)
	target_link_libraries(gmssl -lws2_32)
elseif (APPLE)
	target_link_libraries(gmssl dl)
	target_link_libraries(gmssl "-framework Security")
	#target_link_libraries(gmssl "-framework CoreFoundation") # rand_apple.c CFRelease()
elseif (MINGW)
	target_link_libraries(gmssl PRIVATE wsock32)
else()
	target_link_libraries(gmssl dl)
endif()


set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")

SET_TARGET_PROPERTIES(gmssl PROPERTIES VERSION 3.1 SOVERSION 3)


install(TARGETS gmssl ARCHIVE DESTINATION lib LIBRARY DESTINATION lib RUNTIME DESTINATION bin)
install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/gmssl DESTINATION include)


option(ENABLE_SOFT_SDF "Enable Software SDF Implementation" OFF)
if (ENABLE_SOFT_SDF)
	message(STATUS "ENABLE_SOFT_SDF is ON")
	list(APPEND tests soft_sdf)
	add_library(soft_sdf SHARED src/sdf/soft_sdf.c)
	target_link_libraries(soft_sdf PRIVATE gmssl)
	set_target_properties(soft_sdf PROPERTIES VERSION 3.1 SOVERSION 3)
endif()


if (NOT ${CMAKE_SYSTEM_NAME} STREQUAL "iOS")

	add_library(sdf_dummy SHARED src/sdf/sdf_dummy.c)
	set_target_properties(sdf_dummy PROPERTIES VERSION 3.1 SOVERSION 3)

	add_library(skf_dummy SHARED src/skf/skf_dummy.c)
	set_target_properties(skf_dummy PROPERTIES VERSION 3.1 SOVERSION 3)

	add_executable(gmssl-bin ${tools})
	target_link_libraries(gmssl-bin LINK_PUBLIC gmssl)
	set_target_properties(gmssl-bin PROPERTIES RUNTIME_OUTPUT_NAME gmssl)
	if (MINGW)
		target_link_libraries(gmssl-bin PRIVATE Ws2_32)
	endif()

	enable_testing()
	foreach(name ${tests})
		add_test(NAME ${name} COMMAND ${name}test)
		add_executable(${name}test tests/${name}test.c)
		target_link_libraries (${name}test LINK_PUBLIC gmssl)
	endforeach()

	install(TARGETS gmssl-bin RUNTIME DESTINATION bin)
endif()

if (CMAKE_C_COMPILER_ID MATCHES "MSVC")
	set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT gmssl-bin)
	set(CMAKE_INSTALL_PREFIX "C:/Program Files/GmSSL") # change by `cmake -DCMAKE_INSTALL_PREFIX=C:\path\to\install`
	# run `set path=%path%;C:\Program Files\GmSSL\bin`
	add_compile_definitions(_CRT_SECURE_NO_WARNINGS)

	target_compile_options(gmssl PRIVATE /utf-8)
	target_compile_options(gmssl-bin PRIVATE /utf-8)

#	target_compile_options(gmssl PRIVATE /wd4996)
#	target_compile_options(gmssl-bin PRIVATE /wd4996)
endif()

# cmake .. -DENABLE_DEMOS=ON
option(ENABLE_DEMOS "Build demos" OFF)
if (ENABLE_DEMOS)
	message(STATUS "ENABLE_DEMOS is ON")
	foreach(name ${demos})
		add_executable(${name} demos/src/${name}.c)
		target_link_libraries(${name} gmssl)
	endforeach()
endif()

# Generate install package with cpack
#	cpack -G TGZ
#	cpack -G STGZ
#	cpack -G NSIS64 # Windows only
#
# Install the STGZ package
#	./GmSSL-<version>-Linux.sh --prefix=/usr/local
#
set(CPACK_PACKAGE_NAME "GmSSL")
set(CPACK_PACKAGE_VENDOR "GmSSL develop team")
set(CPACK_PACKAGE_VERSION "3.1.2-Dev")
set(CPACK_PACKAGE_DESCRIPTION_FILE ${PROJECT_SOURCE_DIR}/README.md)
string(CONCAT CPACK_PACKAGE_DESCRIPTION_SUMMARY
    "GmSSL is an open source cryptographic toolbox that supports SM2 / SM3 / SM4 / SM9 "
    "and other national secret (national commercial password) algorithm. ")
set(CPACK_RESOURCE_FILE_LICENSE "${PROJECT_SOURCE_DIR}/LICENSE")
set(CPACK_NSIS_MODIFY_PATH ON)
include(CPack)

