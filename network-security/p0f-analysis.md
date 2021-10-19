# P0F分析

p0f是一款被动式指纹识别工具，通过捕获并分析主机收发的数据包，对目标主机进行基于指纹的鉴别。

<font color="red">注： p0f最近一次更新为2016年，故指纹库已经无法满足当前最新的主机及网络现状。</font>
经过测试，Win10 + Chrome-86.0.4240.111 无法正常识别。

源代码下载：[传送门](https://github.com/p0f/p0f)

## 使用方式

```
用法: p0f [ ...选项... ] [ '过滤规则' ]

网络接口选项:

  -i iface  - 指定网络监听的接口
  -r file   - 读取指定的pcap文件
  -p        - 将侦听网卡设置为混杂模式，需要与-i选项配合
  -L        - 列出所有可用接口

操作模式和输出配置:

  -f file   - 指定指纹数据库路径 (p0f.fp)
  -o file   - 将信息写入日志文件
  -s name   - 使用Unix域套接字响应查询API
  -u user   - 以指定用户身份运行程序，工作目录会切换到该用户根目录下
  -d        - 以后台方式运营程序 (requires -o or -s)

性能相关选项:

  -S limit  - 限制并发API连接数量 (20)
  -t c,h    - 设置连接/主机名超时时间 (30s,120m)
  -m c,h    - 设置缓存连接/主机名最大数量 (1000,10000)

过滤规则使用BPF规则，可通过man tcpdump了解
```

**使用样例：**
```bash
./p0f -i eth0 -p 'port (80 or 443)' # 监听网卡eth0的80和443端口，并设置为混杂模式
```

## 技术分析

### MTU 识别

P0F支持使用MTU来识别链路类型，经过抓包验证，SYN包 及 SYN-ACK包 均含有MSS选项。

P0F字典文件如下：

```
[mtu]
label = Ethernet or modem
sig   = 576
sig   = 1500

label = DSL
sig   = 1452
sig   = 1454
sig   = 1492

......省略号......

label = loopback
sig   = 3924
sig   = 16384
sig   = 16436
```

代码中计算MTU方式，使用TCP头中的MSS选项，加上IP头和TCP头长度得出。
```cpp
if (!pk->mss || f->sendsyn) return; // 无mss选项或本机外发连接，则直接退出

if (pk->ip_ver == IP_VER4) mtu = pk->mss + MIN_TCP4; // IPv4 计算MSS 
else mtu = pk->mss + MIN_TCP6;                       // IPv6 计算MSS

// 其中MIN_TCP4和MIN_TCP6 定义如下:
#define MIN_TCP4 (sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr))
#define MIN_TCP6 (sizeof(struct ipv6_hdr) + sizeof(struct tcp_hdr))
```

### TCP 指纹

#### 字典文件分析

TCP指纹分为请求(SYN)和响应(SYN+ACK)，不同的客户端软件通过不同操作系统，其指纹是不同的。

P0F字典文件如下：
```
[tcp:request]  ==> Syn
label = s:unix:Linux:3.11 and newer
sig   = *:64:0:*:mss*20,10:mss,sok,ts,nop,ws:df,id+:0
sig   = *:64:0:*:mss*20,7:mss,sok,ts,nop,ws:df,id+:0
......省略号......

label = s:win:Windows:XP
sig   = *:128:0:*:16384,0:mss,nop,nop,sok:df,id+:0
sig   = *:128:0:*:65535,0:mss,nop,nop,sok:df,id+:0
......省略号......

[tcp:response] ==> SynAck
label = s:unix:Linux:3.x
sig   = *:64:0:*:mss*10,0:mss:df:0
sig   = *:64:0:*:mss*10,0:mss,sok,ts:df:0
......省略号......

label = s:win:Windows:XP
sig   = *:128:0:*:65535,0:mss:df,id+:0
sig   = *:128:0:*:65535,0:mss,nop,ws:df,id+:0
sig   = *:128:0:*:65535,0:mss,nop,nop,sok:df,id+:0
......省略号......
```

label字段解释：
```
label = s/g : classes : signame : sig_flavor
    s/g：         g代表generic
    classes:      类别
                    win、unix、other 三种
                    !: userland, 如nmap等
    signame:      类别名称
    sig_flavor：  类别（版本）
```

sig字段解释：
```
sig = 4/6/* : ttl/+dist/- : lenOp ：mss : win,scale : option : quirks : payload-class
    4/6/*:            代表IPv4、IPv6还是 不区分IP版本
    ttl/+dist/-:      Initial TTL, 带减号为Random TTL; 如64-代表小于64的任意数
                        ttl+dist: 兼容直接从p0f输出的raw_sig拷贝的指纹
    lenOp:            Length of IP option, 指纹库中均为0
    mss:              0<mss<65535 或 *
    win:              Window size
                        *: ANY
                        %: MOD，指纹库未用到
                        mss*num: Window size是mss的num倍数
                        mtu*num:  Window size是mtu的num倍数
                        num: Window size
    scale:            Window size scaling factor, 支持*或数字
    option:           Option Layout，最大可配24个
                        eol+num: EOL及Padding长度
                        nop,mss,ws,sok,sack,ts: tcp options
                        ?optno: Option数量， 指纹库未用到
    quirks:           Quirks
                        ---- ip ----
                        df: Don't fragment，不分片本及，IPv4适用
                        id+: Non-zero IDs when DF set，IPv4适用
                        id-: Zero IDs when DF not set，IPv4适用
                        ecn: IP头部TOS中的ECN选项，值为0x01或0x02
                        0+: IP "must be zero" field，IPv4 flag, IPv4适用
                        flow: IPv6 flows used，IPv6适用，ver_tos&0xFFFFF != 0
                        ---- tcp core ----
                        seq-: SEQ is zero 
                        ack+: ACK non-zero when ACK flag not set
                        ack-: ACK is zero when ACK flag set 
                        uptr+: URG non-zero when URG flag not set
                        urgf+: URG flag set  
                        pushf+: PUSH flag on a control packet
                        ---- tcp option ----
                        ts1-: Own timestamp set to zero 
                        ts2+: Peer timestamp non-zero on SYN 
                        opt+: Non-zero padding past EOL 
                        exws: Excessive window scaling 
                        bad: Problem parsing TCP options
    payload-class：   Payload class (Length of Payload)
                        *: ANY
                        0: Zero
                        +: Non-Zero
```

#### TCP指纹匹配方法分析

**数据包处理**
```cpp
void parse_packet(void* junk, const struct pcap_pkthdr* hdr, const u8* data) {

    // 数据包长度校验，IPv6与IPv4类似
    u32 hdr_len = (ip4->ver_hlen & 0x0F) * 4;
    u16 flags_off = ntohs(RD16(ip4->flags_off));
    u16 tot_len = ntohs(RD16(ip4->tot_len));

    if (packet_len < MIN_TCP4) {}
    if (hdr_len < sizeof(struct ipv4_hdr)) {}
    if (tot_len > packet_len) {}
    if (hdr_len + sizeof(struct tcp_hdr) > packet_len) {}

    // 协议检查
    if (ip4->proto != PROTO_TCP) { return ; } // 非TCP包，不处理
    if (flags_off & ~(IP4_DF | IP4_MBZ)) { return ; } // 如果分片数据包的offset不为0，不处理

    // 根据抓取的数据包，初始化数据包信息packet_data
    // ...... 省略号 ......

    // 处理TCP流信息
    flow_dispatch(&pk);
}
```

**TCP流表处理**
```cpp
static void flow_dispatch(struct packet_data* pk) {
    f = lookup_flow(pk, &to_srv);  // 查找流表

    switch (pk->tcp_type) {
    case TCP_SYN:
        if (f) { } // 现有流记录收到Syn包，检查是否是重传，如不是重传则重建流信息
        f = create_flow_from_syn(pk); // 创建流信息
        tsig = fingerprint_tcp(1, pk, f); // 根据TCP信息计算指纹
        if (!tsig && !f->sendsyn) { destroy_flow(f); return; } // 无指纹，销毁流
        fingerprint_mtu(1, pk, f); // 计算mtu指纹
        check_ts_tcp(1, pk, f); // 检查TCP uptime

        if (tsig) { f->client->last_syn = tsig; } // 记录last syn
        break;
    case TCP_SYN | TCP_ACK:
    case TCP_RST | TCP_ACK:
    case TCP_RST:
    case TCP_FIN | TCP_ACK:
    case TCP_FIN:
    case TCP_ACK:
        // 忽略分析
    }
}

```

**TCP指纹处理**
```cpp
struct tcp_sig* fingerprint_tcp(u8 to_srv, struct packet_data* pk,
                                struct packet_flow* f) {
    sig = ck_alloc(sizeof(struct tcp_sig));
    packet_to_sig(pk, sig); // 根据packet信息计算指纹信息

    tcp_find_match(to_srv, sig, 0, f->syn_mss); // 指纹库对比
    if ((m = sig->matched)) { } // 打印日志
    score_nat(to_srv, sig, f); // 当前指纹与历史指纹数据进行对比，检查NAT
}
```

**TCP指纹对比**
```cpp
static void tcp_find_match(u8 to_srv, struct tcp_sig* ts, u8 dupe_det,
                           u16 syn_mss) {
    for (i = 0; i < sig_cnt[to_srv][bucket]; i++) {
        // 循环扫描指纹库中每一条，直到命中
        // ...... 省略号 ......

        if (!fuzzy) { // 如果完全匹配，直接返回
            if (!ref->generic) { 
                ts->matched = ref;
                ts->dist    = refs->ttl - ts->ttl;
                return; 
            } else if (!gmatch) gmatch = ref; // 记录 gmatch
        } else if (!fmatch) fmatch = ref; // 记录fmatch
    }

    if (gmatch) { // 优先使用gmatch
        ts->matched = gmatch;
        ts->dist    = gmatch->sig->ttl - ts->ttl;
        return;
    }

    /* No fuzzy matching for userland tools. */
    if (fmatch && fmatch->class_id == -1) return; // 用户态工具不做模糊匹配

    /* Let's try to guess distance if no match; or if match TTL out of
       range. */
    if (!fmatch || fmatch->sig->ttl < ts->ttl || // 根据ttl计算distance
        (!fmatch->bad_ttl && fmatch->sig->ttl - ts->ttl > MAX_DIST))
        // static u8 guess_dist(u8 ttl) { // TTL向上对齐
        //     if (ttl <= 32) return 32 - ttl;
        //     if (ttl <= 64) return 64 - ttl;
        //     if (ttl <= 128) return 128 - ttl;
        //     return 255 - ttl;
        // }
        ts->dist = guess_dist(ts->ttl);
    else
        ts->dist = fmatch->sig->ttl - ts->ttl;

    /* Record the outcome. */
    ts->matched = fmatch;
    if (fmatch) ts->fuzzy = 1;
}
```
### UPtime 检测

```cpp
void check_ts_tcp(u8 to_srv, struct packet_data* pk, struct packet_flow* f) {
}
```

### HTTP 指纹

主要为HTTP协议头，包括客户端请求以及服务器响应的指纹； 这里暂时忽略


### NAT 指纹

忽略

## 后续

- 补全字典文件（2016~今）