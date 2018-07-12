
.. role:: example-rule-emphasis

IP关键字
-----------

ttl
^^^

ttl关键字用于检查IP数据包标头中time-to-live值， 其格式是::

  ttl:<number>

例如::

  ttl:10;

在ttl关键字的末尾，您可以输入要匹配的值。Time-to-live值决定定数据包在网络中传输的最长时间，如果此字段设置为0，则必须销毁数据包，time-to-live基于跳数，数据包每经过一跳，TTL值就减一。这个机制的目的是限制数据包无限循环路由。

规则中ttl关键字例子:

.. container:: example-rule

    alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL MISC 0 ttl"; :example-rule-emphasis:`ttl:0;` reference:url,support.microsoft.com/default.aspx?scid=kb#-#-EN-US#-#-q138268; reference:url,www.isi.edu/in-notes/rfc1122.txt; classtype:misc-activity; sid:2101321; rev:9;)

ipopts
^^^^^^
ipopts关键字用来检查特定的IP选项是否设定。Ipopts必须在规则的开头使用，每条规则只能匹配一个选项。 这些选项包括:

=========  =============================
IP选项      描述
=========  =============================
rr         记录路由
eol        列表结束
nop        无操作
ts         时间戳
sec        IP安全
esec       IP安全扩展
lsrr       宽松源路由选项
ssrr       严格源路由选项
satid      流标识符
any        任意IP选项
=========  =============================

ipopts关键字格式::

  ipopts: <name>

例如::

  ipopts: lsrr;

规则中使用ipopts的例子:

.. container:: example-rule

    alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL MISC source route ssrr"; :example-rule-emphasis:`ipopts:ssrr;` reference:arachnids,422; classtype:bad-unknown; sid:2100502; rev:3;)

sameip
^^^^^^

每个数据包都有一个源IP地址和一个目的IP地址。 可以是源IP与目的IP相同。 使用sameip关键字，您可以检查源IP地址是否与目的IP地址相同。 sameip
关键字的格式是::

  sameip;

规则中使用sameip的例子:

.. container:: example-rule

    alert ip any any -> any any (msg:"GPL SCAN same SRC/DST"; :example-rule-emphasis:`sameip;` reference:bugtraq,2666; reference:cve,1999-0016; reference:url,www.cert.org/advisories/CA-1997-28.html; classtype:bad-unknown; sid:2100527; rev:9;)

ip_proto
^^^^^^^^
使用ip_proto关键字，您可以匹配数据包头中的IP协议。您可以使用协议的名称或编号来匹配下面的协议::

   1     ICMP        因特网控制消息协议
   6     TCP         传输控制协议
  17     UDP         用户数据报协议
  47     GRE         通用路由封装协议
  50     ESP         IPv6 Encap安全有效负载
  51     AH          Ipv6身份验证标头
  58     IPv6-ICMP   ICMP for Ipv6

完整的协议和协议号列表请参考
http://en.wikipedia.org/wiki/List_of_IP_protocol_numbers

规则中使用ip_proto的例子:

.. container:: example-rule

    alert ip any any -> any any (msg:"GPL MISC IP Proto 103 PIM"; :example-rule-emphasis:`ip_proto:103;` reference:bugtraq,8211; reference:cve,2003-0567; classtype:non-standard-protocol; sid:2102189; rev:4;)

例子中的命名变量为::

    ip_proto:PIM

id
^^

使用id关键字，您可以匹配指定的IP ID值。 ID标识主机发送的每个数据包，并且通常每发送一个数据包就递增一个数值。 IP ID用作片段标识号。 每个数据包都有一个IP ID，当数据包被分段时，该数据包的所有分段都具有相同的ID。 以这种方式，分组的接收器知道哪些分段属于同一数据包。 （IP ID不关心ID号顺序，分段重组时使用偏移来完成，它阐明了分段的顺序。）

id关键字格式为::

  id:<number>;

规则中使用id的例子:

.. container:: example-rule

    alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET DELETED F5 BIG-IP 3DNS TCP Probe 1"; :example-rule-emphasis:`id: 1;` dsize: 24; flags: S,12; content:"\|00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\|"; window: 2048; reference:url,www.f5.com/f5products/v9intro/index.html; reference:url,doc.emergingthreats.net/2001609; classtype:misc-activity; sid:2001609; rev:13;)

geoip
^^^^^
geoip关键字使您能够匹配源和目标IP地址来自哪个网络以及它所属的国家/地区。Suricata使用Maxmind的GeoIP API来实现这个功能。

geoip的语法格式为::

  geoip: src, RU;
  geoip: both, CN, RU;
  geoip: dst, CN, RU, IR;
  geoip: both, US, CA, UK;
  geoip: any, CN, IR;

因此，您可以使用以下标识符来明确匹配的方向::

  both: 使用指定geoip (geopip’s)来匹配双向
  any: 使用指定geoip (’s)来匹配任意一个方向.
  dest: 使用指定geoip来匹配目的.
  src: 使用指定geoip来匹配源.

这个关键字仅支持IPv4. 由于他使用了Maxmind的GeoIP API, 必须将libgeoip编译入suricata.

fragbits (IP分段)
^^^^^^^^^^^^^^^^^^^^^^^^^^^

使用fragbits关键字，可以检查IP头中是否设置了分段和保留位。fragbits关键字应放在规则的开头。Fragbits用于IP分段机制。 在将数据包从一个Internet网络路由到另一个Internet网络期间，可能发生数据包大于网络可以处理的最大数据包长度的情况。 在这种情况下，可以分段发送数据包。网络中数据包长度的最大值称为最大传输单位（MTU）.

您可以匹配以下比特位::

  M - 更多分段
  D - 不要分段
  R - 保留位

可以使用以下修饰符更多地指定对此位的匹配::

  +         匹配指定的位，以及任何其他位
  *         如果设置了任何指定位，则匹配
  !         如果未设置指定的位，则匹配

格式::

  fragbits:[*+!]<[MDR]>;

规则中使用fragbits的例子:

.. container:: example-rule

   alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET EXPLOIT Invalid non-fragmented packet with fragment offset>0"; :example-rule-emphasis:`fragbits: M;` fragoffset: >0; reference:url,doc.emergingthreats.net/bin/view/Main/2001022; classtype:bad-unknown; sid:2001022; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

fragoffset
^^^^^^^^^^

使用fragoffset关键字，您可以匹配IP分段偏移字段的指定十进制值。 如果要检查会话的第一个分段，则必须将fragoffset 0与More Fragment选项组合在一起来使用。分段的偏移字段便于重组。 id用于确定哪些分段属于哪个数据包，而分段的偏移字段用于说明分段的顺序.

您可以使用以下修饰符::

  <       如果小于指定值，则匹配
  >       如果大于指定值，则匹配
  !       如果指定的值不存在则匹配

fragoffset格式::

  fragoffset:[!|<|>]<number>;

规则中使用fragoffset的例子:

.. container:: example-rule

   alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET EXPLOIT Invalid non-fragmented packet with fragment offset>0"; fragbits: M; :example-rule-emphasis:`fragoffset: >0;` reference:url,doc.emergingthreats.net/bin/view/Main/2001022; classtype:bad-unknown; sid:2001022; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

TCP关键字
------------

seq
^^^
可以在规则中使用seq关键字来检查指定的TCP序列号。序列号是TCP连接两端随机生成的数字。客户端和服务器都创建一个序列号，随着各方发送字节的增加而增加，所以双方这个序列号是不同的。该序列号必须由连接的双方确认。TCP通过序列号处理数据包的确认、顺序和重传。它的数字着发送方发送的每个数据字节而增加。seq有助于跟踪字节在所属的数据流中处于哪个位置。如果SYN标志设置为1，则数据的第一个字节的序列号是此数字加1（以此类推，2）

例子::

  seq:0;

规则中使用seq的例子:

.. container:: example-rule

    alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL SCAN NULL"; flow:stateless; ack:0; flags:0; :example-rule-emphasis:`seq:0;` reference:arachnids,4; classtype:attempted-recon; sid:2100623; rev:7;)

数据包中seq的例子 (Wireshark):

.. image:: header-keywords/Wireshark_seq.png


ack
^^^

ack是对TCP连接另一端发送的所有先前（数据）字节的接收的确认。 在大多数情况下，TCP连接的每个数据包在第一个SYN之后都有一个ACK标志，而ack-number随着每个新数据字节的接收而增加。 可以在规则中使用ack关键字来检查指定的TCP确认号.

ack的格式::

  ack:1;

规则中使用ack的例子:

.. container:: example-rule

    alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL SCAN NULL"; flow:stateless; :example-rule-emphasis:`ack:0;` flags:0; seq:0; reference:arachnids,4; classtype:attempted-recon; sid:2100623; rev:7;)

数据包中ack的例子(Wireshark):

.. image:: header-keywords/Wireshark_ack.png

window
^^^^^^

window关键字用于检查指定的TCP窗口大小。TCP窗口大小是一种控制数据流的机制。窗口由接收端设置（接收端通告的窗口大小），并指示可以接收的字节数。在发送方可以发送相同数量的新数据之前，接收端必须先确认此数据量。该机制用于防止接收端数据溢出。窗口大小的值是有限的，可以是2到65535字节。为了更多地利用带宽，您可以使用更大的TCP窗口。

window关键字格式::

  window:[!]<number>;

规则中使用window的例子:

.. container:: example-rule

    alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL DELETED typot trojan traffic"; flow:stateless; flags:S,12; :example-rule-emphasis:`window:55808;` reference:mcafee,100406; classtype:trojan-activity; sid:2182; rev:8;)

ICMP关键字
-------------

ICMP（Internet控制消息协议）是IP协议栈的一部分。 在传输数据（数据报）方面，IP协议本身并不可靠。ICMP协议可以在出现问题时提供反馈。它不会阻止问题的发生，但有助于理解出错的原因和地点。如果需要可靠性，使用IP的协议必须自己处理可靠性。很多情况下会发送ICMP消息。 例如，当目的地不可达时，如果没有足够的缓冲容量来转发数据，或者当数据报发送时不能进行分段，则等等。 更多信息可参考ICMP消息类型列表。

ICMP消息有四个重要内容，可以与相应的ICMP关键字匹配。 它们是：消息的类型，代码，id和序列号。

itype
^^^^^

itype关键字用于匹配指定的ICMP类型（数字）。ICMP有几种消息，并使用代码来表示这些消息。不同的消息由不同的名称区分，但更重要的是类型代码。 有关更多信息，请参阅包含消息类型和代码列表。

itype关键字格式::

  itype:min<>max;
  itype:[<|>]<number>;

例如
这个例子匹配类型代码大于10的ICMP数据包::

  itype:>10;

规则中使用itype关键字的例子:

.. container:: example-rule

    alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL SCAN Broadscan Smurf Scanner"; dsize:4; icmp_id:0; icmp_seq:0; :example-rule-emphasis:`itype:8;` classtype:attempted-recon; sid:2100478; rev:4;)

下面列出了撰写本文时所有的已知ICMP类型。可以在 `IANA的网站 <https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml>`_ 找到最新的列表

==========  ==========================================================
ICMP类型     Name
==========  ==========================================================
0           回显应答
3           目标不可达
4           源端被关闭（基本流控制）
5           重定向
6           Alternate Host Address
8           回显请求
9           路由器通告
10          路由器请求
11          TTL为0
12          参数错误
13          时间戳请求
14          时间戳请求应答
15          信息请求
16          信息请求应答
17          地址掩码请求
18          地址掩码应答
30          Traceroute
31          数据报转换错误
32          Mobile Host Redirect
33          IPv6 Where-Are-You
34          IPv6 I-Am-Here
35          Mobile Registration Request
36          Mobile Registration Reply
37          Domain Name Request
38          Domain Name Reply
39          SKIP
40          Photuris
41          Experimental mobility protocols such as Seamoby
==========  ==========================================================

icode
^^^^^

使用icode关键字，您可以匹配指定的ICMP代码。 ICMP消息的代码阐明了该消息。与ICMP类型一起，它表明您正在处理什么样的问题。每个ICMP类型的代码都有不同的用途。

icode关键字格式::

  icode:min<>max;
  icode:[<|>]<number>;

例如:
这个例子匹配ICMP代码大于5的数据包::

  icode:>5;

规则中使用icode关键字的例子:

.. container:: example-rule

    alert icmp $HOME_NET any -> $EXTERNAL_NET any (msg:"GPL MISC Time-To-Live Exceeded in Transit"; :example-rule-emphasis:`icode:0;` itype:11; classtype:misc-activity; sid:2100449; rev:7;)

下面列出了所有ICMP类型的含义。如果未列出类型，则仅定义代码0，并且具有上表中ICMP类型的含义。
最新的列表可以在 `IANA的网站 <https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml>`_ 上找到。

==========  ==========  =========================================================================
ICMP类型     ICMP代码    描述
==========  ==========  =========================================================================
3           - 0         - 网络不可达
            - 1         - 主机不可达
            - 2         - 协议不可达
            - 3         - 端口不可达
            - 4         - 需要进行分片但设置了不分片
            - 5         - 源站选路失败
            - 6         - 目的网络未知
            - 7         - 目的主机未知
            - 8         - 源主机被隔离
            - 9         - 目的网络通信被强制禁止
            - 10        - 目的主机通信被强制禁止
            - 11        - 由于服务类型TOS，网络不可达
            - 12        - 由于服务类型TOS，主机不可达
            - 13        - 由于过滤，通信被强制禁止
            - 14        - 主机越权
            - 15        - 优先中止生效
5           - 0         - 对网络重定向
            - 1         - 对主机重定向
            - 2         - 对服务类型和网络重定向
            - 3         - 对服务类型和主机重定向
9           - 0         - 常规路由器通告
            - 16        - 不路由常规流量
11          - 0         - 传输期间TTL为0
            - 1         - 数据报组装期间TTL为0
12          - 0         - 坏的IP首部（包括各种差错）
            - 1         - 缺少必需的选项
            - 2         - 错误的长度
40          - 0         - Bad SPI
            - 1         - Authentication Failed
            - 2         - Decompression Failed
            - 3         - Decryption Failed
            - 4         - Need Authentication
            - 5         - Need Authorization
==========  ==========  =========================================================================


icmp_id
^^^^^^^

使用icmp_id关键字，您可以匹配指定的ICMP id值。每个ICMP数据包在发送时都会获得一个id。在接收方收到数据包时，它将使用相同的ID发送回复，以便发送方识别它并将其与正确的ICMP请求关联。

icmp_id关键字格式::

  icmp_id:<number>;

例如:
这个例子匹配ICMP ID为0的数据包::

  icmp_id:0;

规则中使用icmp_id关键字的例子:

.. container:: example-rule

    alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL SCAN Broadscan Smurf Scanner"; dsize:4; :example-rule-emphasis:`icmp_id:0;` icmp_seq:0; itype:8; classtype:attempted-recon; sid:2100478; rev:4;)

icmp_seq
^^^^^^^^

您可以使用icmp_seq关键字检查ICMP序列号。 ICMP消息都有序列号。 这可以用于（与id一起）用于检查哪个回复消息属于哪个请求消息。

icmp_seq关键字格式::

  icmp_seq:<number>;

例如:
这个例子匹配ICMP序列号为0的数据包::

  icmp_seq:0;

规则中使用icmp_seq关键字的例子:

.. container:: example-rule

    alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL SCAN Broadscan Smurf Scanner"; dsize:4; icmp_id:0; :example-rule-emphasis:`icmp_seq:0;` itype:8; classtype:attempted-recon; sid:2100478; rev:4;)
