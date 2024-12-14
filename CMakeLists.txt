if (CMAKE_VERSION VERSION_LESS "3.0")
	cmake_minimum_required(VERSION 2.8)
else()
	cmake_minimum_required(VERSION 3.6)
endif()

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/include/gmssl/version.h" _gmssl_version_h_contents REGEX "#define GMSSL_VERSION_STR")
string(REGEX MATCH "\"GmSSL [^\"]*" _gmssl_version ${_gmssl_version_h_contents})
string(REGEX REPLACE ".* ([0-9]+\\.[0-9]+\\.[0-9]+) (.*)" "\\1-\\2" _gmssl_version ${_gmssl_version})
unset(_gmssl_version_h_contents)

string(REGEX REPLACE "([0-9]+\.[0-9]+\.[0-9]+).+" "\\1" _gmssl_version_sem "${_gmssl_version}")
project(GmSSL
	VERSION ${_gmssl_version_sem}
	HOMEPAGE_URL "http://gmssl.org"
	LANGUAGES C)

set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
SET(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH};${CMAKE_CURRENT_SOURCE_DIR}/cmake")

option(ENABLE_TEST_SPEED "Enable test speed" OFF)



option(ENABLE_SM2_ARM64 "Enable SM2_Z256 ARMv8 assembly" OFF)
option(ENABLE_SM3_ARM64 "Enable SM3 Arm Neon implementation (10% faster on Apple M2)" OFF)
option(ENABLE_SM4_ARM64 "Enable SM4 AARCH64 assembly implementation" OFF)
option(ENABLE_SM4_CE "Enable SM4 ARM CE assembly implementation" OFF)
option(ENABLE_SM9_ARM64 "Enable SM9_Z256 ARMv8 assembly" OFF)
option(ENABLE_GMUL_ARM64 "Enable GF(2^128) Multiplication AArch64 assembly" OFF)


option(ENABLE_SM4_AVX2 "Enable SM4 AVX2 8x implementation" OFF)
option(ENABLE_SM4_AESNI "Enable SM4 AES-NI (4x) implementation" OFF)
option(ENABLE_SM2_AMD64 "Enable SM2_Z256 X86_64 assembly" OFF)


option(ENABLE_SM3_SSE "Enable SM3 SSE assembly implementation" OFF)

option(ENABLE_SM4_CTR_AESNI_AVX "Enable SM4 CTR AESNI+AVX assembly implementation" OFF)
option(ENABLE_SM4_CL "Enable SM4 OpenCL" OFF)


option(ENABLE_INTEL_RDRAND "Enable Intel RDRAND instructions" OFF)
option(ENABLE_INTEL_RDSEED "Enable Intel RDSEED instructions" OFF)

option(ENABLE_SM4_ECB "Enable SM4 ECB mode" ON)
option(ENABLE_SM4_OFB "Enable SM4 OFB mode" ON)
option(ENABLE_SM4_CFB "Enable SM4 CFB mode" ON)
option(ENABLE_SM4_CCM "Enable SM4 CCM mode" ON)
option(ENABLE_SM4_XTS "Enable SM4 XTS mode" ON)
option(ENABLE_SM4_CBC_MAC "Enable SM4-CBC-MAC" ON)

option(ENABLE_SM2_EXTS "Enable SM2 Extensions" OFF)
option(ENABLE_SM3_XMSS "Enable SM3-XMSS signature" ON)


option(ENABLE_SHA1 "Enable SHA1" ON)
option(ENABLE_SHA2 "Enable SHA2" ON)
option(ENABLE_AES "Enable AES" ON)
option(ENABLE_CHACHA20 "Enable Chacha20" ON)

option(ENABLE_SKF "Enable SKF module" OFF)
option(ENABLE_SDF "Enable SDF module" ON)

option(ENABLE_ASM_UNDERSCORE_PREFIX "Add prefix `_` to assembly symbols" ON)

option(ENABLE_TLS_DEBUG "Enable TLS and TLCP print debug message" OFF)

option (ENABLE_SM2_ENC_PRE_COMPUTE "Enable SM2 encryption precomputing" ON)

set(src
	src/version.c
	src/debug.c
	src/sm4.c
	src/sm4_cbc.c
	src/sm4_ctr.c
	src/sm4_gcm.c
	src/sm3.c
	src/sm3_hmac.c
	src/sm3_kdf.c
	src/sm3_pbkdf2.c
	src/sm3_digest.c
	src/sm2_z256.c
	src/sm2_z256_table.c
	src/sm2_key.c
	src/sm2_sign.c
	src/sm2_enc.c
	src/sm2_exch.c
	src/sm9_z256.c
	src/sm9_z256_table.c
	src/sm9_key.c
	src/sm9_sign.c
	src/sm9_enc.c
	src/sm9_exch.c
	src/zuc.c
	src/zuc_modes.c
	src/block_cipher.c
	src/digest.c
	src/hmac.c
	src/hkdf.c
	src/gf128.c
	src/ghash.c
	src/sm4_cbc_sm3_hmac.c
	src/sm4_ctr_sm3_hmac.c
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
	src/socket.c
	src/tls.c
	src/tls_ext.c
	src/tls_trace.c
	src/tlcp.c
	src/tls12.c
	src/tls13.c
	src/file.c
	src/file.c
)

set(tools
	tools/gmssl.c
	tools/version.c
	tools/sm4.c
	tools/sm4_cbc.c
	tools/sm4_ctr.c
	tools/sm4_gcm.c
	tools/sm4_cbc_sm3_hmac.c
	tools/sm4_ctr_sm3_hmac.c
	tools/sm3.c
	tools/sm3hmac.c
	tools/sm3_pbkdf2.c
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
	tools/ghash.c
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
	tools/tlcp_client.c
	tools/tlcp_server.c
	tools/tls12_client.c
	tools/tls12_server.c
	tools/tls13_client.c
	tools/tls13_server.c
)

set(tests
	sm4
	sm4_cbc
	sm4_ctr
	sm4_gcm
	sm3
	sm4_sm3_hmac
	sm2_z256
	sm2_key
	sm2_sign
	sm2_enc
	sm9
	zuc
	block_cipher
	digest
	hmac
	hkdf
	gf128
	ghash
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




include(CheckSymbolExists)


option(ENABLE_SMALL_FOOTPRINT "Enable small code size" OFF)
if (ENABLE_SMALL_FOOTPRINT)
	message(STATUS "ENABLE_SMALL_FOOTPRINT is ON")
	add_definitions(-DENABLE_SMALL_FOOTPRINT)
endif()



if (ENABLE_TEST_SPEED)
	message(STATUS "ENABLE_TEST_SPEED is ON")
	add_definitions(-DENABLE_TEST_SPEED)
endif()


option(ENABLE_SM2_ALGOR_ID_ENCODE_NULL "Enable AlgorithmIdenifier with algorithm sm2sign_with_sm3 encode a NULL object as parameters" OFF)
if (ENABLE_SM2_ALGOR_ID_ENCODE_NULL)
	message(STATUS "ENABLE_SM2_ALGOR_ID_ENCODE_NULL is ON")
	add_definitions(-DENABLE_SM2_ALGOR_ID_ENCODE_NULL)
endif()

if (ENABLE_ASM_UNDERSCORE_PREFIX)
	message(STATUS "ENABLE_ASM_UNDERSCORE_PREFIX is ON")
	add_definitions(-DENABLE_ASM_UNDERSCORE_PREFIX)
endif()

if (ENABLE_GMUL_ARM64)
	message(STATUS "ENABLE_GMUL_ARM64 is ON")
	add_definitions(-DENABLE_GMUL_ARM64)
	enable_language(ASM)
	#list(APPEND src src/gf128_arm64.S)
	list(APPEND src src/gf128_arm64.c)
endif()



if (ENABLE_SM2_ARM64)
	message(STATUS "ENABLE_SM2_ARM64 is ON")
	add_definitions(-DENABLE_SM2_ARM64)
	enable_language(ASM)
	list(APPEND src src/sm2_z256_arm64.S)
endif()

if (ENABLE_SM2_AMD64)
	message(STATUS "ENABLE_SM2_AMD64 is ON")
	add_definitions(-DENABLE_SM2_AMD64)
	enable_language(ASM)
	list(APPEND src src/sm2_z256_amd64.S)
endif()

if (ENABLE_SM2_NEON)
	message(STATUS "ENABLE_SM2_NEON is ON")
	add_definitions(-DENABLE_SM2_NEON)
endif()

if (ENABLE_SM9_ARM64)
	message(STATUS "ENABLE_SM9_ARM64 is ON")
	add_definitions(-DENABLE_SM9_ARM64)
	enable_language(ASM)
	list(APPEND src src/sm9_z256_arm64.S)
endif()


if (ENABLE_TLS_DEBUG)
	message(STATUS "ENABLE_TLS_DEBUG is ON")
	add_definitions(-DENABLE_TLS_DEBUG)
endif()


if (ENABLE_SM3_SSE)
	message(STATUS "ENABLE_SM3_SSE is ON")
	list(FIND src src/sm3.c sm3_index)
	list(REMOVE_AT src ${sm3_index})
	list(INSERT src ${sm3_index} src/sm3_sse.c)
endif()

if (ENABLE_SM3_ARM64)
	message(STATUS "ENABLE_SM3_ARM64 is ON")
	list(FIND src src/sm3.c index)
	list(REMOVE_AT src ${index})
	list(INSERT src ${index} src/sm3_arm64.c)
endif()

if (ENABLE_SM4_ARM64)
	message(STATUS "ENABLE_SM4_ARM64 is ON")
	list(FIND src src/sm4.c sm4_index)
	list(REMOVE_AT src ${sm4_index})
	list(INSERT src ${sm4_index} src/sm4_arm64.c)
	enable_language(ASM)
endif()

if (ENABLE_SM4_AVX2)
	message(STATUS "ENABLE_SM4_AVX2 is ON")
	list(FIND src src/sm4.c sm4_index)
	list(REMOVE_AT src ${sm4_index})
	list(INSERT src ${sm4_index} src/sm4_avx2.c)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=native")
endif()

if (ENABLE_SM4_AESNI)
	message(STATUS "ENABLE_SM4_AESNI is ON")
	list(FIND src src/sm4.c sm4_index)
	list(REMOVE_AT src ${sm4_index})
	list(INSERT src ${sm4_index} src/sm4_aesni.c)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=native")
endif()




if (ENABLE_SM4_CE)
	message(STATUS "ENABLE_SM4_CE is ON")
	list(FIND src src/sm4.c sm4_index)
	list(REMOVE_AT src ${sm4_index})
	list(INSERT src ${sm4_index} src/sm4_ce.c)
	set_source_files_properties(src/sm4_ce.c PROPERTIES COMPILE_OPTIONS "-march=armv8.2-a+sm4")
endif()


if (ENABLE_SM4_CTR_AESNI_AVX)
	message(STATUS "ENABLE_SM4_CTR_AESNI_AVX is ON")
	list(FIND src src/sm4_ctr.c sm4_ctr_index)
	list(REMOVE_AT src ${sm4_ctr_index})
	list(INSERT src ${sm4_ctr_index} src/sm4_ctr_aesni_avx.c)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=native")
endif()



if (ENABLE_SM4_CL)
	message(STATUS "ENABLE_SM4_CL is ON")
	add_definitions(-DENABLE_SM4_CL)
	if (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
		add_definitions(-DMACOS) # to include <OpenCL/OpenCL.h>
	endif()
	list(APPEND src src/sm4_cl.c)
	list(APPEND tests sm4_cl)
endif()

if (ENABLE_SM4_ECB)
	message(STATUS "ENABLE_SM4_ECB is ON")
	add_definitions(-DENABLE_SM4_ECB)
	list(APPEND src src/sm4_ecb.c)
	list(APPEND tools tools/sm4_ecb.c)
	list(APPEND tests sm4_ecb)
endif()

if (ENABLE_SM4_OFB)
	message(STATUS "ENABLE_SM4_OFB is ON")
	add_definitions(-DENABLE_SM4_OFB)
	list(APPEND src src/sm4_ofb.c)
	list(APPEND tools tools/sm4_ofb.c)
	list(APPEND tests sm4_ofb)
endif()

if (ENABLE_SM4_CFB)
	message(STATUS "ENABLE_SM4_CFB is ON")
	add_definitions(-DENABLE_SM4_CFB)
	list(APPEND src src/sm4_cfb.c)
	list(APPEND tools tools/sm4_cfb.c)
	list(APPEND tests sm4_cfb)
endif()

if (ENABLE_SM4_CCM)
	message(STATUS "ENABLE_SM4_CCM is ON")
	set(ENABLE_SM4_CBC_MAC ON)
	add_definitions(-DENABLE_SM4_CCM)
	list(APPEND src src/sm4_ccm.c)
	list(APPEND tools tools/sm4_ccm.c)
	list(APPEND tests sm4_ccm)
endif()

if (ENABLE_SM4_XTS)
	message(STATUS "ENABLE_SM4_XTS is ON")
	add_definitions(-DENABLE_SM4_XTS)
	list(APPEND src src/sm4_xts.c)
	list(APPEND tools tools/sm4_xts.c)
	list(APPEND tests sm4_xts)
endif()


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


if (ENABLE_SHA1)
	message(STATUS "ENABLE_SHA1 is ON")
	add_definitions(-DENABLE_SHA1)
	list(APPEND src src/sha1.c)
	list(APPEND tests sha1)
endif()


if (ENABLE_SHA2)
	message(STATUS "ENABLE_SHA2 is ON")
	add_definitions(-DENABLE_SHA2)
	list(APPEND src src/sha256.c src/sha512.c)
	list(APPEND tests sha224 sha256 sha384 sha512)
endif()


if (ENABLE_AES)
	message(STATUS "ENABLE_AES is ON")
	list(APPEND src src/aes.c src/aes_modes.c)
	list(APPEND tests aes)
endif()


if (ENABLE_CHACHA20)
	message(STATUS "ENABLE_CHACHA20 is ON")
	list(APPEND src src/chacha20.c)
	list(APPEND tests chacha20)
endif()


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
	list(APPEND tools tools/sm4_cbc_mac.c)
	list(APPEND tests sm4_cbc_mac)
endif()


check_symbol_exists(getentropy "unistd.h" HAVE_GETENTROPY)
if (WIN32)
	add_definitions(-D_WINSOCK_DEPRECATED_NO_WARNINGS)
	list(APPEND src src/rand_win.c src/http_win.c)
elseif (APPLE)
	list(APPEND src src/rand_apple.c src/http.c)
elseif (HAVE_GETENTROPY)
	list(APPEND src src/rand_unix.c src/http.c)
	message(STATUS "have getentropy")
else()
	list(APPEND src src/rand.c src/http.c)
endif()


if (ENABLE_SKF)
	message(STATUS "ENABLE_SKF is ON")
	list(APPEND src
		src/skf/skf.c
		src/skf/skf_lib.c
		src/skf/skf_meth.c
		src/skf/skf_ext.c
		src/skf/skf_prn.c
		src/skf/skf_wisec.c)
	list(APPEND tools tools/skfutil.c)
	add_library(skf_dummy SHARED src/skf/skf_dummy.c)
	set_target_properties(skf_dummy PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION ${PROJECT_VERSION_MAJOR})
endif()

if (ENABLE_SDF)
	message(STATUS "ENABLE_SDF is ON")
	add_definitions(-DENABLE_SDF)
	list(APPEND src
		src/sdf/sdf.c
		src/sdf/sdf_lib.c
		src/sdf/sdf_meth.c
		src/sdf/sdf_ext.c
		src/sdf/sdf_sansec.c)
	list(APPEND tools tools/sdfinfo.c tools/sdfdigest.c tools/sdfexport.c tools/sdfsign.c tools/sdfencrypt.c tools/sdfdecrypt.c tools/sdftest.c)
endif()


option(ENABLE_HTTP_TESTS "Enable HTTP GET/POST related tests" OFF)
if (ENABLE_HTTP_TESTS)
	message(STATUS "ENABLE_HTTP_TESTS")
	list(APPEND tests http http_crl)
endif()


option(BUILD_SHARED_LIBS "Build using shared libraries" ON)

if (MSVC)
	message(STATUS "CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS")
	set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON) # set before add_library
endif()

add_library(gmssl ${src})
add_library(GmSSL::${PROJECT_NAME} ALIAS gmssl)

target_include_directories(gmssl PUBLIC
	$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
	$<INSTALL_INTERFACE:include>
)



if (WIN32)
	target_link_libraries(gmssl -lws2_32)
elseif (APPLE)
	if (ENABLE_SDF)
		target_link_libraries(gmssl dl)
	endif()
	target_link_libraries(gmssl "-framework Security")
	if (ENABLE_SM4_CL)
		# FIXME: different rules for cl and OpenCL framework
		target_link_libraries(gmssl "-framework OpenCL")
	endif()
	#target_link_libraries(gmssl "-framework CoreFoundation") # rand_apple.c CFRelease()
elseif (MINGW)
	target_link_libraries(gmssl PRIVATE wsock32)
else()
	if (ENABLE_SDF)
		target_link_libraries(gmssl dl)
	endif()
endif()


set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")

include(GNUInstallDirs)
set(GmSSL_CMAKE_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME})

set(_targets_export_name ${PROJECT_NAME}Targets)
include(CMakePackageConfigHelpers)
configure_package_config_file(
	${PROJECT_SOURCE_DIR}/cmake/${PROJECT_NAME}Config.cmake.in
	${PROJECT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
	INSTALL_DESTINATION ${GmSSL_CMAKE_DIR})
write_basic_package_version_file(
	${PROJECT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
	VERSION ${PROJECT_VERSION}
	COMPATIBILITY SameMajorVersion)
install(
	FILES
		${PROJECT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
		${PROJECT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
	DESTINATION ${GmSSL_CMAKE_DIR})

install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/gmssl DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(TARGETS gmssl
	EXPORT ${_targets_export_name}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
set_target_properties(gmssl PROPERTIES
	VERSION ${PROJECT_VERSION} SOVERSION ${PROJECT_VERSION_MAJOR}
	EXPORT_NAME ${PROJECT_NAME})
export(EXPORT ${_targets_export_name}
	NAMESPACE GmSSL::
	FILE "${CMAKE_CURRENT_BINARY_DIR}/cmake/${_targets_export_name}.cmake")

install(EXPORT ${_targets_export_name}
	NAMESPACE GmSSL::
	DESTINATION ${GmSSL_CMAKE_DIR})

if(UNIX AND NOT APPLE)
	message(STATUS "Detected Linux, configuring /etc/ld.so.conf.d/gmssl.conf")
	install(CODE "
		execute_process(COMMAND mkdir -p /etc/ld.so.conf.d)
		execute_process(COMMAND bash -c \"echo /usr/local/lib > /etc/ld.so.conf.d/gmssl.conf\")
		execute_process(COMMAND ldconfig)
	")
endif()


if (NOT ${CMAKE_SYSTEM_NAME} STREQUAL "iOS")
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

if (MSVC)
	set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT gmssl-bin)

	add_compile_definitions(_CRT_SECURE_NO_WARNINGS)

	target_compile_options(gmssl PRIVATE /utf-8)
	target_compile_options(gmssl-bin PRIVATE /utf-8)

#	target_compile_options(gmssl PRIVATE /wd4996)
#	target_compile_options(gmssl-bin PRIVATE /wd4996)
endif()


add_test(NAME sm3_commands COMMAND ${CMAKE_COMMAND} -P "${CMAKE_SOURCE_DIR}/cmake/sm3_commands.cmake")
add_test(NAME sm2_commands COMMAND ${CMAKE_COMMAND} -P "${CMAKE_SOURCE_DIR}/cmake/sm2_commands.cmake")
add_test(NAME cert_commands COMMAND ${CMAKE_COMMAND} -P "${CMAKE_SOURCE_DIR}/cmake/cert_commands.cmake")
if(NOT WIN32)
	add_test(NAME tlcp_commands COMMAND ${CMAKE_COMMAND} -P "${CMAKE_SOURCE_DIR}/cmake/tlcp_commands.cmake")
	add_test(NAME tls12_commands COMMAND ${CMAKE_COMMAND} -P "${CMAKE_SOURCE_DIR}/cmake/tls12_commands.cmake")
	add_test(NAME tls13_commands COMMAND ${CMAKE_COMMAND} -P "${CMAKE_SOURCE_DIR}/cmake/tls13_commands.cmake")
endif()

# Generate install package with cpack
#	cpack -G TGZ
#	cpack -G STGZ
#	cpack -G NSIS64 # Windows only
#
# Install the STGZ package
#	./GmSSL-<version>-Linux.sh --prefix=/usr/local
#
# The `-DEV` part is important
string(REGEX REPLACE "([0-9]+\.[0-9]+)\.([0-9]+.*)" "\\2" CPACK_PACKAGE_VERSION_PATCH "${_gmssl_version}")
set(CPACK_PACKAGE_VENDOR "GmSSL develop team")
set(CPACK_RESOURCE_FILE_LICENSE ${PROJECT_SOURCE_DIR}/LICENSE)
set(CPACK_RESOURCE_FILE_README ${PROJECT_SOURCE_DIR}/README.md)
set(CPACK_GENERATOR TGZ) # default generator, can be overwritten by `cpack -G`
set(CPACK_NSIS_MODIFY_PATH ON)
include(CPack)
