# GmSSL

[![CMake-Ubuntu/macOS](https://github.com/guanzhi/GmSSL/workflows/CMake/badge.svg)](https://github.com/guanzhi/GmSSL/actions/workflows/cmake.yml)
[![CMake-Windows](https://github.com/guanzhi/GmSSL/workflows/CMake-windows/badge.svg)](https://github.com/guanzhi/GmSSL/actions/workflows/cmake-windows.yml)
[![CMake-Android](https://github.com/guanzhi/GmSSL/actions/workflows/android-ci.yml/badge.svg)](https://github.com/guanzhi/GmSSL/actions/workflows/android-ci.yml)
[![CMake-iOS](https://github.com/guanzhi/GmSSL/actions/workflows/ios.yml/badge.svg)](https://github.com/guanzhi/GmSSL/actions/workflows/ios.yml)

GmSSL是由北京大学自主开发的国产商用密码开源库，实现了对国密算法、标准和安全通信协议的全面功能覆盖，支持包括移动端在内的主流操作系统和处理器，支持密码钥匙、密码卡等典型国产密码硬件，提供功能丰富的命令行工具及多种编译语言编程接口。


## 主要特性

* 超轻量：GmSSL 3 大幅度降低了内存需求和二进制代码体积，不依赖动态内存，可以用于无操作系统的低功耗嵌入式环境(MCU、SOC等)，开发者也可以更容易地将国密算法和SSL协议嵌入到现有的项目中。
* 更合规：GmSSL 3 可以配置为仅包含国密算法和国密协议(TLCP协议)，依赖GmSSL 的密码应用更容易满足密码产品型号检测的要求，避免由于混杂非国密算法、不安全算法等导致的安全问题和合规问题。
* 更安全：TLS 1.3在安全性和通信延迟上相对之前的TLS协议有巨大的提升，GmSSL 3 支持TLS 1.3协议和RFC 8998的国密套件。GmSSL 3 默认支持密钥的加密保护，提升了密码算法的抗侧信道攻击能力。
* 跨平台：GmSSL 3 更容易跨平台，构建系统不再依赖Perl，默认的CMake构建系统可以容易地和Visual Studio、Android NDK等默认编译工具配合使用，开发者也可以手工编写Makefile在特殊环境中编译、剪裁。

## 下载

* GmSSL的主分支版本为 [GmSSL-3.1.1](https://github.com/guanzhi/GmSSL/releases/tag/v3.1.1)，主要增加跨平台特性，特别是对Windows/Visual Studio的支持，Windows、Android、iOS平台的开发者需要使用该版本。

## 编译与安装

GmSSL 3 采用了cmake构建系统。下载源代码后将其解压缩，进入源码目录，执行：

```shell
cmake -B build # -G "Ninja Multi-Config"
cmake --build build
ctest --test-dir build
sudo cmake --install build # --prefix /path
```

可以手动指定generator，比如`cmake -B build -G Ninja`以指定Ninja作为generator。

在`cmake --install`完成后，GmSSL会在默认安装目录中安装`gmssl`命令行工具，在头文件目录中创建`gmssl`目录，并且在库目录中安装`libgmssl.a`、`libgmssl.so`等库文件。

## 主要功能

### 密码算法

* 分组密码：SM4 (CBC/CTR/GCM/ECB/CFB/OFB/CCM/XTS), AES (CBC/CTR/GCM)
* 序列密码：ZUC/ZUC-256, ChaCha20
* 哈希函数: SM3, SHA-1, SHA-224/256/384/512
* 公钥密码：SM2加密/签名, SM9加密/签名
* MAC算法：HMAC, GHASH, CBC-MAC
* 密钥导出函数：PBKDF2、HKDF
* 随机数生成器：Intel RDRAND, HASH_DRBG (NIST.SP.800-90A)

### 证书和数字信封

* 数字证书：X.509证书, CRL证书注销列表, CSR (PKCS #10) 证书签名请求
* 私钥加密：基于SM4/SM3口令加密的PEM格式私钥 (PKCS #8)
* 数字信封：SM2密码消息 (GM/T 0010-2012)

### SSL协议

* TLCP 1.1，支持密码套`TLS_ECC_SM4_CBC_SM3 {0xE0,0x13}` (GB/T 38636-2020、GM/T 0024-2014)
* TLS 1.2，支持密码套件`TLS_ECDHE_SM4_CBC_SM3 {0xE0,0x11}` (GB/T 38636-2020、GM/T 0024-2014)
* TLS 1.3，支持密码套件`TLS_SM4_GCM_SM3 {0x00,0xC6}`  (RFC 8998)

### 多语言接口

GmSSL通过子项目提供多种多种编程语言绑定

 * [GmSSL-Java](https://github.com/GmSSL/GmSSL-Java) 以JNI方式实现的Java语言绑定
 * [GmSSL-PHP](https://github.com/GmSSL/GmSSL-PHP) 以PHP扩展方式实现的PHP语言绑定
 * [GmSSL-Go](https://github.com/GmSSL/GmSSL-Go) 以CGO方式实现的Go语言绑定
 * [GmSSL-Python](https://github.com/GmSSL/GmSSL-Python) 以ctypes方式实现的Python语言绑定
 * [GmSSL-JS](https://github.com/guanzhi/GmSSL-JS) 纯JavaScript实现的国密算法库

### 支持国密硬件

GmSSL内置支持国密SDF密码硬件（通常为PCI-E接口的密码卡或者服务器密码机）和SKF密码硬件（通常为小型USB密码钥匙）。经过测试的密码产品型号包括：

* to be added.

开发者也可以用GmSSL的子项目SoftSDF(https://github.com/GmSSL/SoftSDF) ，用功能等效（但是不具备密码硬件密钥保护等价的安全性）的软件SDF模块来进行开发和测试，正式部署的时候再替换为硬件SDF。

### OpenSSL兼容性

GmSSL 3.0版本重写了所有的代码并改变了原有API，因此当前GmSSL版本和OpenSSL不兼容，无法直接用GmSSL替换OpenSSL进行编译。GmSSL提供了子项目 OpenSSL-Compatibility-Layer (https://github.com/GmSSL/OpenSSL-Compatibility-Layer) 提供了OpenSSL的兼容层，Nginx等应用可以通过OpenSSL-Compatibility-Layer调用GmSSL功能。经过测试目前兼容层可以兼容Nginx 1.16 ~ 1.25 之间的版本。

## Benchmark

性能测试结果是在单核单线程且未修改处理器默认配置下5次测试中取最好效果。由于未关闭睿频或进行大小核设置，这个成绩通常会略高于多核多线程中每核心的平均成绩。

```
cmake .. -DENABLE_TEST_SPEED=ON
cmake --build .
./bin/sm4test; ./bin/sm3test; ./bin/sm2_signtest; ./bin/sm2_enctest; ./bin/sm9test; ./bin/zuctest
```

MacBook Pro 13-inch 2018: 2.7 GHz Quad-Core Intel Core i7, Intel  Iris Plus Graphics 655. 8 GB 2133 HMz LPDDR3. macOS Sonoma 14.3.

```
speed_sm4_encrypt: 164.826108 MiB per second
speed_sm4_encrypt_blocks: 163.120495 MiB per second
speed_sm4_cbc_encrypt_blocks: 156.870435 MiB per second
speed_sm4_cbc_decrypt_blocks: 174.701097 MiB per second
speed_sm4_ctr_encrypt_blocks: 178.457901 MiB per second
speed_sm4_ctr32_encrypt_blocks: 185.007458 MiB per second
speed_zuc_generate_keystream: 337.403260-MiB per second
speed_zuc_encrypt: 356.315696-MiB per second
test_sm3_speed: 273.551034 MiB per second
sm2_sign_ctx speed (ENABLE_SM2_AMD64): 4096 signs time 0.036916 seconds, 110954.599632 signs per second
sm2_sign_ctx speed : 4096 signs time 0.236611 seconds, 17311.114023 signs per second
test_sm2_encrypt_ctx_speed (ENABLE_SM2_AMD64): 17879.592122 encryptions per second
test_sm2_encrypt_ctx_speed: 1869.314131 encryptions per second
test_sm9_z256_pairing_speed: 173 pairings per second
```

MacBook Air M2 2022. Apple M2. 16 GB. Sonoma 14.5.

```
speed_sm4_encrypt: 143.180578 MiB per second
speed_sm4_encrypt_blocks: 190.928509 MiB per second
speed_sm4_cbc_encrypt_blocks: 148.519447 MiB per second
speed_sm4_cbc_decrypt_blocks: 187.305378 MiB per second
speed_sm4_ctr_encrypt_blocks: 191.195450 MiB per second
speed_sm4_ctr32_encrypt_blocks: 191.522725 MiB per second
speed_zuc_generate_keystream: 344.604781-MiB per second
speed_zuc_encrypt: 344.723575-MiB per second
test_sm3_speed: 327.298762 MiB per second
sm2_sign_ctx speed : 4096 signs time 0.290709 seconds, 14089.691066 signs per second
test_sm2_encrypt_ctx_speed: 1518.575861 encryptions per second
test_sm9_z256_pairing_speed: 141 pairings per seconds
```

## ChangeLog

自从3.1.1版本以来

* 提升了全部国密算法的性能，并在`tests`测试程序中增加了国密算法的性能测试
* 增加了SM4 ECB/CFB/OFB/CCM/XTS加密模式，带SM3-HMAC的SM4 CBC/CTR模式，并且在`gmssl`命令行工具中增加了所有SM4加密模式的选项
* 在`gmssl`命令行中增加了GHASH计算的选项
* 增加了`sdftest`正确性和兼容性测试命令，以独立子项目的形式提供了SDF的软件实现SoftSDF
* 移除了RC4, MD5等已被攻破的密码算法

## 开发者们
<a href="https://github.com/guanzhi/GmSSL/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=guanzhi/GmSSL" />
</a>

## Stargazers over time

[![Stargazers over time](https://starchart.cc/guanzhi/GmSSL.svg)](https://starchart.cc/guanzhi/GmSSL)

