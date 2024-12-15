# 编译与安装

[TOC]

## 概述

GmSSL当前版本采用CMake构建系统。由于CMake是一个跨平台的编译、安装工具，因此GmSSL可以在大多数主流操作系统上编译、安装和运行。GmSSL项目官方测试了Windows (包括Visual Stduio和Cygwin)、Linux、Mac、Android和iOS这几个主流操作系统上的编译，并通过GitHub的CI工作流对提交的最新代码进行自动化的编译测试。

和其他基于CMake的开源项目类似，GmSSL的构建过程主要包含配置、编译、测试、安装这几个步骤。在下载并解压GmSSL源代码后，进入源代码目录，执行如下命令：

```bash
cmake -B build # -G "Ninja Multi-Config"
cmake --build build
ctest --test-dir build
sudo cmake --install build # --prefix /path
```

就可以完成配置、编译、测试和安装。

在执行`cmake --build`编译成功后，在`build/bin`目录下会生成项目的可执行文件和库文件。对于密码工具来说，在安装使用之前通过`ctest`进行测试是重要的一步，如果测试失败，那么不应该使用这个软件。在发生某个测试错误后，可以执行`build/bin`下的具体某个测试命令行，如`sm4test`，这样可以看到具体的错误打印信息。

执行`sudo cmake --install`，安装完成后，可以命令行中调用`gmssl`命令行工具。在Linux和Mac环境下，头文件通常被安装在`/usr/local/include/gmssl`目录下，库文件被安装在`/usr/local/lib`目录下。

## 项目源代码

GmSSL项目的源代码在GitHub中发布和维护。

项目在GitHub的主页为：https://github.com/guanzhi/GmSSL

源代码包含主分支的最新代码和定期发布的Release版本，建议优先采用主分支最新版。

### 通过CI判断当前代码状态

有时候最新提交的代码可能存在编译错误，通常这些错误会在1-2天内被新的提交修复。如果当前最新代码还没有修复，那么可以通过GitHub的CI状态来选择没有错误的代码。

通过GitHub的CI工作流状态可以判断某次提交是否存在编译错误，目前GmSSL项目中配置了如下编译环境：

* CMake ubuntu-latest
* CMake windows-latest
* CMake macos-latest
* CMake-Android
* CMake-iOS

通过查看这些CI的状态，可以判断当前代码是否可以在对应操作系统上成功编译。如果当前最新代码无法在某个平台上编译，那么可以选择之前某个通过测试的Commit版本。

##配置编译选项

在执行`cmake`阶段可以对项目的默认编译配置进行修改，修改是通过设置CMake变量来完成的，可以查看项目源代码中的`CMakeLists.txt`中所有的`option`指令来查看可选的配置。例如：

```cmake
option(BUILD_SHARED_LIBS "Build using shared libraries" OFF)
```

表明项目默认生成静态库，不生成动态库。

###设置生成动态库或静态库

GmSSL的CMake默认生成动态库，可以通过设定CMake变量`BUILD_SHARED_LIBS`为`ON`或者`OFF`来指定生成动态库或静态库。

```
cmake .. -DBUILD_SHARED_LIBS=ON
```

 ### 设置优化的密码算法实现

GmSSL包含了针对特定硬件和处理指令集的密码算法优化实现，如针对Intel AVX2等指令集的优化，针对GPU的优化等，这些优化实现在匹配的处理器上的实现速度或安全性会大大超过默认的C语言实现。

在配置阶段可以显式地指定采用优化实现，可选的CMake配置变量包括：

* `ENABLE_SM3_AVX_BMI2`  SM3算法的AVX + BMI2指令集实现。
* `ENABLE_SM3_X8_AVX2` SM3算法的AVX2指令集并行实现。
* `ENABLE_SM3_X16_AVX512` SM3算法的AVX512指令集并行实现。
* `ENABLE_SM4_AESNI_AVX` SM4算法的AESNI +AVX指令集实现。
* `ENABLE_RDRND` 基于Intel RDRND指令的硬件随机数生成器。
* `ENABLE_GF128_PCLMULQDQ` 基于Intel PCLMULQDQ指令的GCM模式实现。

### 编译不安全的密码算法

处于教学目的，GmSSL源代码中包含了一组不安全的密码算法，这些算法默认情况下不被编译到二进制文件中，可以通过设置`ENABLE_BROKEN_CRYPTO`，在配置阶段启用这些算法，在当前`build`目录中执行：

```bash
cmake .. -DENABLE_BROKEN_CRYPTO=ON
cmake --build .
```

重新编译后，加入GmSSL库文件的算法包括：

* DES分组密码
* SHA1哈希函数
* MD5哈希函数
* RC4序列密码

## 在Visual Studio环境中编译

CMake支持通过指定不同的构建系统生成器（Generator），生成不同类型的Makefile。在Windows和Visual Studio环境下，CMake即可以生成常规的Visual Studio解决方案(.sln)文件，在Visual Studio图形界面中完成编译，也可以生成类似于Linux环境下的Makefile文件，在命令行环境下完成编译和测试。

### 生成Makefile/Ninja编译

在安装完Visual Studio之后，在启动菜单栏中会出现Visual Studio菜单目录，其中包含x64 Native Tools Command Prompt for VS 2022等多个终端命令行环境菜单项。

```pwsh
C:\Program Files\Microsoft Visual Studio\2022\Community>cd /path/to/gmssl
cmake -B build -G "NMake Makefiles"
# cmake -B build -G "Ninja"
ctest --test-dir build
```

在编译完成后直接执行安装会报权限错误，这是因为安装过程需要向系统目录中写入文件，而当前打开命令行环境的用户不具备该权限。可以通过右键选择“更多-以管理员身份运行”打开x64 Native Tools Command Prompt for VS 2022终端，执行

```pwsh
cmake --install build
```

那么`gmssl`命令行程序、头文件和库文件分别被写入`C:/Program Files/GmSSL/bin`、`C:/Program Files/GmSSL/include`、`C:/Program Files/GmSSL/lib`这几个系统目录中。为了能够直接在命令行环境任意目录下执行`gmssl`命令行程序，需要将其安装目录加入到系统路径中，可以执行：

```batch
set path=%path%;C:\Program Files\GmSSL\bin
```

设置完毕后可以在命令行中执行`path`，查看新的路径是否已经成功加入。

### 在Visual Studio图形界面中编译

在安装完Visual Studio之后，在启动菜单栏中会出现Visual Studio菜单目录，其中包含x64 Native Tools Command Prompt for VS 2022等多个终端命令行环境菜单项。

```pwsh
C:\Program Files\Microsoft Visual Studio\2022\Community>cd /path/to/gmssl
# 此处`-G`可以不显式指定, 因为cmake在windows上使用MSBuild作为默认generator
cmake -B build # -G "Visual Studio 17 2022"
```

完成后可以看到CMake在`build`目录下生成了一个`GmSSL.sln`文件和大量的`.vcxproj`文件。

点击`GmSSL.sln`就打开Visual Studio，点击Visual Studio工具栏上的"本地Windows调试器"按钮，可以启动编译。

在Visual Studio界面中可以选择Debug、Release、MinSizeRel等不同配置。

### 在Visual Studio中运行测试

在解决方案资源管理器中找到`RUN_TESTS`项目，右键菜单选择"调试-启动新实例"，即可运行测试，并且在”输出“窗口中看到测试结果。测试完成后会出现RUN_TESTS拒绝访问的对话框。

### 选择生成32位或64位程序

通过在Visual Studio不同的命令行环境中编译GmSSL，可以生成32位的X86或者64位的X86_64程序，在x64 Native Tools Command Prompt for VS 2022命令行环境下，生成的是64位的程序，在x86 Native Tools Command Prompt for VS 2022命令行环境下，生成的是32位的程序。

可以通过Windows操作系统内置的资源管理器来检查编译生成的可执行程序是32位还是64位，在资源管理器的CPU页面中，通过“选择列”增加“平台”列，这样就可以显示每个进程的是32位或64位。可以运行`gmssl tlcp_client`或者在某个测试文件中增加循环时间来保持命令行运行一段时间。

## 在Cygwin环境中编译

Cygwin是Windows上的Linux模拟运行环境。Cygwin提供了Linux Shell和大量Linux命令行工具，也提供了应用程序开发必须的编译工具、头文件和库文件。面向Linux开发的应用通常依赖`unistd.h`、`sys/socket.h`等头文件及函数，但是Visual Studio的C库并没有提供这些POSIX函数实现，因此这些Linux应用没有办法直接在Windows环境下编译。Cygwin通过封装Windows操作系统原生功能，提供了一个POSIX接口层，以及封装这些功能的动态库(`cygwin1.dll`)，并且提供了GCC、CMake等完整的Linux编译工具链，这意味着标准所有Linux环境下的标准头文件都存在，并且代码中依赖GCC编译器的特殊语法都可以被编译器识别（Visual Studio的`cl`编译器不能完整支持C99语法），因此标准的Linux应用都可以通过Cygwin移植到Windows环境，编译为Windows本地应用。Cygwin提供的Linux Shell环境意味Shell脚本也是可以使用的。

在Cygwin环境下编译生成的可执行程序是原生的Windows程序，和Visual Studio编译的程序的主要区别在于，Cygwin下编译的程序都必须依赖`cygwin1.dll`这个动态库，因为应用所有的POSIX函数调用都需要通过这个动态库翻译为Windows本地的系统调用（如WinSock2），因此发布Cygwin的程序不太方便，必须要包含一个较大的`cygwin1.dll`库文件。另外如果应用涉及大量的系统调用，那么通过Cygwin中间层会引入一定的开销，理论上会比Visual Studio编译的应用效率略低。

总的来说，如果你想在Windows环境下快速尝试一下GmSSL的命令行功能，并且可能需要利用Linux Shell环境下的一些常用工具做实验和测试，或者不太熟悉Visual Studio开发环境，那么采用Cygwin环境是一个非常方便的选择。

### 准备Cygwin环境

Cygwin的安装、配置都是通过一个单一的`setup-x86_64.exe`应用程序完成的。在Cygwin的官网 https://www.cygwin.com/ 可以下载这个应用程序。

注意，在首次安装的时候可能没有选择所有需要的程序，再次运行`setup-x86_64.exe`程序可以对环境进行配置和更新。有些工具，例如CMake，官方提供了独立的Windows安装包，在Cygwin环境下没有必要独立安装这些工具，也不建议安装，所有依赖的Linux工具都应该通过Cygwin环境来配置管理。

在安装、配置完成之后，可以通过运行`Cygwin64 Terminal`应用，打开一个命令行环境。

### 在Cygwin环境中编译GmSSL

Cygwin环境相对标准的Linux环境有一些细微的差别。首先，在Cygwin命令行环境中，文件系统是一个类似Linux文件系统结构的独立目录，如果源代码已经下载到Windows操作系统中（比如，下载到用户的Download目录），那么需要首先将源代码拷贝到Cygwin文件系统的用户目录中（例如当前用户默认目录`~`）。在Cygwin文件系统中，Windows文件系统被映射到`/cygdrive`目录中，Windows当前用户Guan Zhi的下载目录中的`GmSSL-master.zip`文件就被映射到`/cygdrive/c/Users/Guan Zhi/Downloads/GmSSL-master.zip`中。

```bash
cp "/cygdrive/c/Users/Guan Zhi/Downloads/GmSSL-master.zip" ~/
```

然后可以按照Linux环境下相似的过程编译、安装

```bash
unzip GmSSL-master.zip
cd GmSSL-master
cmake -B build
cmake --build build
ctest --test-dir build
cmake --install build # --prefix /path
```

注意，由于在Cygwin环境中用户本身具有系统权限，因此在执行`cmake --install`时不需要`sudo`。

在安装完成之后，可以在Cygwin的命令行环境下执行`gmssl`命令行，或者运行源代码`demo`目录下的演示脚本。

注意，将`gmssl`等可执行程序直接从Cygwin目录拷贝到Windows文件系统下，在执行时会提示找不到`cygwin1.dll`的错误，运行或者发布可执行程序时，应处理好对这个动态库的依赖问题。

### 存在的问题

似乎CMake选项`BUILD_SHARED_LIBS` 不起作用，总会同时生成静态库和动态库。

Cygwin的动态库名称比较特殊，是以`cyg`开头的。

## 面向iOS/iPhoneOS的交叉编译

下载 https://github.com/leetal/ios-cmake ，将`ios.toolchain.cmake`文件复制到`build`目录。

```bash
mkdir build; cd build
cmake .. -G Xcode -DCMAKE_TOOLCHAIN_FILE=../ios.toolchain.cmake -DPLATFORM=OS64
cmake --build . --config Release
```

如果出现“error: Signing for "gmssl" requires a development team.”错误，可以用Xcode打开工程文件，在Signing配置中设置Development Team。

## 面向Android的交叉编译

下载Android NDK，执行

```bash
mkdir build; cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake  -DANDROID_ABI=arm64-v8a  -DANDROID_PLATFORM=android-23
cmake --build .
```

## 安装包构建

依赖cmake工具包中的cpack工具，生成可发布的安装包。

生成的安装包在`build`目录下。

### 构建DEB安装包

```
mkdir build; cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cpack -G DEB
```

### 构建RPM安装包

```
mkdir build; cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cpack -G RPM
```

### 构建`.sh`安装脚本

```
mkdir build; cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cpack -G DEB
make package
```

## 生成二进制包

为了保证兼容性，发布的二进制包不包含针对特定指令集的优化代码，并且不启用编译器的`-O3`优化。

在正式发布之前，需要在测试平台上编译、测试、安装。验证`gmssl`命令行可以正确使用，验证`sm3_demo.c`可以正确和`-lgmssl`编译，并且可以正确输出哈希值。

完成编译和测试后，进行编译打包操作。

### 生成开发压缩包

对于需要打包多模式 (`Debug`, `Release`, `RelWithDebInfo`) 的 (主要为Windows平台，因为`MSVC`的`Debug`/`Release`标准库运行时独立)，可以根据以下示例进行操作。示例中脚本需要环境中存在ninja。

```shell
cmake -B build -G "Ninja Multi-Config" -DCMAKE_CONFIGURATION_TYPES="Debug;Release" -DBUILD_SHARED_LIBS=OFF -DCMAKE_DEBUG_POSTFIX="d"
cd build
cmake --build . --config Debug
cmake --build . --config Release
cpack -C "Debug;Release" # -G TGZ
```

其中指定`BUILD_SHARED_LIBS=OFF`重新生成了静态库，以及和静态库连接的`gmssl`二进制程序，因此最终打包的`gmssl`命令行不依赖系统库之外的动态库。

### 在CMake中进行依赖

GmSSL库较为简单，只需将对应头文件路径与所需链接库配置进target即可。但目前也已支持了Modern CMake的依赖方式。

假设我们将以上打包内容解压至`/path/GmSSL-3.1.2-win64`

```cmake
set(GmSSL_ROOT "/path/GmSSL-3.1.2-win64")
find_package(GmSSL REQUIRED) # required表示必须找到，否则报错

# `MyTarget` is created by `add_library` or `add_executable`
target_link_libraries(MyTarget GmSSL::GmSSL)
```
通过以上配置，即可正常使用GmSSL。
