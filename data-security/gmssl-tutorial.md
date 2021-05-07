# 国密证书测试手记


## 前言

有个项目需要过密评，需要将应用系统改造为使用国密证书。经过调研OpenSSL 1.1.1+版本已经支持了SMX系列的算法，可以生成SM2的公私钥对，但是只支持SHA算法签名的证书，不支持使用SM3算法签名的证书。故这里调研大名鼎鼎的GmSSL，看看对国密证书的支持情况。

## 环境准备

**0. 环境**
```
采用一台云主机： 
CentOS Linux release 7.6.1810 (Core) 
```

**1. 安装GmSSL**

```bash
# 从官网下载GmSSL
wget 'https://github.com/guanzhi/GmSSL/archive/refs/heads/master.zip' -O GmSSL-master.zip

# 解压
unzip GmSSL-master.zip

# Config配置
cd GmSSL-master
./config
make # 漫长的编译过程
make install
```

**2. 排查**
直接执行`gmssl`命令会直接报错：
```bash 
$ gmssl 
gmssl: error while loading shared libraries: libssl.so.1.1: cannot open shared object file: No such file or directory

$ whereis gmssl
gmssl: /usr/local/bin/gmssl

$ ldd /usr/local/bin/gmssl 
	linux-vdso.so.1 =>  (0x00007ffcba7a1000)
	libssl.so.1.1 => not found
	libcrypto.so.1.1 => not found
	libdl.so.2 => /lib64/libdl.so.2 (0x00007fec70aba000)
	libpthread.so.0 => /lib64/libpthread.so.0 (0x00007fec7089e000)
	libc.so.6 => /lib64/libc.so.6 (0x00007fec704d0000)
	/lib64/ld-linux-x86-64.so.2 (0x00007fec70cbe000)

# 经检查，在/usr/local/lib64/目录下能够找到 notfound 的两个so库，并与编译出来的库做对比，MD5是一致的。
$ md5sum  /usr/local/lib64/libcrypto.so libcrypto.so
38bc417f9cdb50b26714781890350d8e  /usr/local/lib64/libcrypto.so
38bc417f9cdb50b26714781890350d8e  libcrypto.so

# 打开Makefile，将 LDFLAG= 修改为 "LDFLAGS= -Wl,-rpath=$(LIBRPATH)"
$ vim Makefile

# 删除编译好的gmssl可执行程序，重新执行Makefile，并拷贝到目标路径
$ rm -fr ./apps/gmssl && make && cp -af ./app/gmssl /usr/local/bin/gmssl

# 再次执行gmssl命令，正常
$ gmssl
GmSSL>

```