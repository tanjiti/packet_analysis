# 功能

* 读取pcap包，打印详细的icmp/tcp/udp协议

* 读取pcap包或网络接口

    1. 打印详细的tcp会话／udp报文数据，目前支持mysql/pgsql/smtp/ftp/redis/mongodb认证协议解析，http/dns完整协议解析

    2. IP数据包统计信息，用于监控网络异常流量





# 安装

 `pip install -r requirements.txt`


* [pynids](https://github.com/MITRECND/pynids.git)

   * mac

   `brew install libnids`

   * linux

   `sudo apt-get install libnet1-dev libpcap-dev`

   `git clone https://github.com/MITRECND/pynids.git`

   `cd pynids`

   `sudo python setup.py build`

   `sudo python setup.py install`

* [dpkt](http://dpkt.readthedocs.io/en/latest/index.html)

   `pip install dpkt`

   或者

   `git clone https://github.com/kbandla/dpkt.git`


# 使用
* 读取pcap包，打印详细的icmp/tcp/udp协议

    `python print_pcap.py --help`

    `python print_pcap.py --pcapfile=data/pcap_pub/http_gzip.pcap  --assetport=80`

    <b>详细使用可以参看Documents [二](http://tanjiti.lofter.com/post/1cc6c85b_10c4e0e2)</b>


* 读取pcap包或网络接口，打印详细的tcp会话数据

   第一步:指定配置
   [server.yaml](etc/server.yaml)


   第二步:
   `python print_tcp_session.py`

   <b>详细使用可以参看Documents [十一](http://tanjiti.lofter.com/post/1cc6c85b_10c4e0ce) 、[十二](http://tanjiti.lofter.com/post/1cc6c85b_10c6c87f)</b>



# Bugs
## libnids
1. 不支持ipv6格式的数据包

2. 当server.yaml中配置为重组双向流量时

    `data_stream_direct: 2`

    只在tcp flag为RST或FIN时才会打印数据

3. 不支持多进程


# Documents

[一、TCP/IP数据包基础知识](http://tanjiti.lofter.com/post/1cc6c85b_10c4e0e4)

[二、TCP/IP数据包分析应用-端口扫描](http://tanjiti.lofter.com/post/1cc6c85b_10c4e0e2)

[三、TCP/IP协议分析-MySQL认证协议](http://tanjiti.lofter.com/post/1cc6c85b_10c4e0e1)

[四、TCP/IP协议分析-PostgreSQL认证协议](http://tanjiti.lofter.com/post/1cc6c85b_10c4e0dd)

   
[五、TCP/IP协议分析-MongoDB认证协议](http://tanjiti.lofter.com/post/1cc6c85b_10c4e0dc)

[六、TCP/IP协议分析-Redis认证协议](http://tanjiti.lofter.com/post/1cc6c85b_10c4e0d7)

[七、TCP/IP协议分析-FTP认证协议](http://tanjiti.lofter.com/post/1cc6c85b_10c4e0d5)

[八、TCP/IP协议分析-SMTP认证协议](http://tanjiti.lofter.com/post/1cc6c85b_10c4e0d2)

[九、TCP/IP协议分析-SSH协议](http://tanjiti.lofter.com/post/1cc6c85b_10c4e0d0)

[十、TCP/IP协议分析-RDP协议](http://tanjiti.lofter.com/post/1cc6c85b_10c4e0cf)

[十一、TCP/IP数据包分析应用-TCP会话重组](http://tanjiti.lofter.com/post/1cc6c85b_10c4e0ce)

[十二、TCP/IP协议分析-DNS协议-UDP](http://tanjiti.lofter.com/post/1cc6c85b_10c6c87f)





# 示例

<code>python print_tcp_session.py</code>
=====================

<b> 1. UDP-DNS协议详解 </b>

    pcap_file: data/pcap_pub/dns/netforensics_evidence05.pcap

    UDP-DNS 协议解析

        {
      "ts": 1268758265.098157,
      "src_ip": "192.168.23.2",
      "src_port": 53,
      "dst_ip": "192.168.23.129",
      "dst_port": 52499,
      "header": {
        "aa": 0,
        "qr": 1,
        "num_of_answers": 1,
        "tc": 0,
        "num_of_additional": 4,
        "rd": 1,
        "opcode": "QUERY",
        "ra": 1,
        "num_of_authority": 4,
        "rcode": "NOERROR",
        "id": 48291,
        "num_of_questions": 1
      },
      "questions": [
        {
          "qclass": "IN",
          "qtype": "A",
          "qname": "freeways.in."
        }
      ],
      "answers": [
        {
          "ttl": 5,
          "rname": "freeways.in.",
          "rtype": "A",
          "rclass": 1,
          "rdata": "212.252.32.20"
        }
      ],
      "authority": [
        {
          "ttl": 5,
          "rname": "freeways.in.",
          "rtype": "NS",
          "rclass": 2,
          "rdata": "ns4.everydns.net."
        }
      ],
      "additional": [
        {
          "ttl": 5,
          "rname": "ns4.everydns.net.",
          "rtype": "A",
          "rclass": 1,
          "rdata": "208.76.60.100"
        }
      ]
    }


<b> 2. TCP-HTTP 协议详解 </b>

    pcap_file: data/pcap_pub/cve/cve-2016-4971.pcap

    {
      "ts_start": 1467904494.307728,
      "ts_end": 1467904494.392242,
      "src_ip": "192.168.186.128",
      "src_port": 41352,
      "dst_ip": "192.168.186.128",
      "dst_port": 80,
      "req_method": "GET",
      "req_uri": "/file",
      "req_version": "1.1",
      "req_headers": {
        "user-agent": "Wget/1.17 (linux-gnu)",
        "accept": "*/*",
        "accept-encoding": "identity",
        "host": "192.168.186.128",
        "connection": "Keep-Alive"
      },
      "req_body": "",
      "resp_version": "1.0",
      "resp_status": "301",
      "resp_reason": "Moved Permanently",
      "resp_headers": {
        "server": "SimpleHTTP/0.6 Python/2.7.12",
        "date": "Thu, 07 Jul 2016 15:14:54 GMT",
        "location": "ftp://anonymous@192.168.186.128:21/.wgetrc"
      },
      "resp_body": ""
    }

<b> 3. IP 数据包元信息</b>

    数据包方向 时间戳 协议类型 源IP:源端口(IP归属地)(服务类型）目的IP:目的端口(IP归属地)(服务类型) 数据包大小

    IN	2017-08-18 13:23:41	TCP	58.217.200.117:14000(江苏省南京市-None-None-NONE)(scotty-ft)	10.0.0.2:58747(局域网-None-None-NONE)(NONE)	240

    OUT	2017-08-18 13:23:41	TCP	10.0.0.2:58747(局域网-None-None-NONE)(NONE)	58.217.200.117:14000(江苏省南京市-None-None-NONE)(scotty-ft)	40


   备注: 14000(scotty-ft) 为微信、QQ发送语音文件的协议


<code>python print_pcap.py</code>
===================

1. UDP报文

   <code>python print_pcap.py --pcapfile=data/pcap_pub/dns/dns.pcap</code>

        [UDP]	[1112201545.38	2005-03-30 16:52:25]	217.13.4.24:53(00:12:a9:00:32:23) ----->192.168.170.56:1711(00:60:08:45:e4:55)	ttl=58	DATA_BINARY=76 63 85 83 00 01 00 00 00 00 00 00 05 47 52 49 4d 4d 0b 75 74 65 6c 73 79 73 74 65 6d 73 05 6c 6f 63 61 6c 00 00 01 00 01	LEN=41

2. TCP报文

    <code>python print_pcap.py --pcapfile=data/pcap_pub/cve/httpoxy.pcap</code>

        [TCP]   [1469135972.46  2016-07-21 21:19:32]    192.168.235.135:55034(00:0c:29:92:67:d7) ----->192.168.235.136:8080(00:0c:29:79:fd:94)  SEQ=618963631   ACK=2424513936  FLAGS=['ACK', 'PSH']    WIN=229 DATA=GET /index.py HTTP/1.1
        Host: 192.168.235.136:8080
        User-Agent: curl/7.43.0
        Accept: */*
        Proxy: 192.168.235.135:11000

3. ICMP报文

        [ICMP_Unreach]	[1500285748.08	2017-07-17 10:02:28]	10.0.0.5:500(98:01:a7:9e:dd:c1) ----->10.0.0.2:63816(58:f3:9c:51:90:c7)	3:3[host:port unreachable]	ttl=43	DATA_BINARY=	LEN=0



联系
===
[原博客](http://danqingdani.blog.163.com/) 被封号了

[欢迎订阅lofter上的备份](http://tanjiti.lofter.com/rss)

[新浪微博weibo](http://weibo.com/tanjiti)

[豆瓣读书](https://book.douban.com/people/tanjiti/) 分享最近看的书籍

[baidu网盘](https://pan.baidu.com/share/home?uk=1377047511#category/type=0) 分享的内容很快就会被删掉



