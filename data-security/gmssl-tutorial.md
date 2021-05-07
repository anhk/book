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