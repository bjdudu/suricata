
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

使用id关键字，您可以匹配特定的IP ID值。 ID标识主机发送的每个数据包，并且通常每发送一个数据包就递增一个数值。 IP ID用作片段标识号。 每个数据包都有一个IP ID，当数据包被分段时，该数据包的所有分段都具有相同的ID。 以这种方式，分组的接收器知道哪些分段属于同一数据包。 （IP ID不关心ID号顺序，分段重组时使用偏移来完成，它阐明了分段的顺序。）

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

fragbits (IP fragmentation)
^^^^^^^^^^^^^^^^^^^^^^^^^^^

With the fragbits keyword, you can check if the fragmentation and
reserved bits are set in the IP header. The fragbits keyword should be
placed at the beginning of a rule. Fragbits is used to modify the
fragmentation mechanism. During routing of messages from one Internet
module to the other, it can occur that a packet is bigger than the
maximal packet size a network can process. In that case, a packet can
be send in fragments. This maximum of the packet size is called
Maximal Transmit Unit (MTU)使用fragbits关键字，可以检查IP头中是否设置了分段和保留位。 fragbits关键字应放在规则的开头。 Fragbits用于修改碎片机制。 在将消息从一个Internet模块路由到另一个Internet模块期间，可能发生数据包大于网络可以处理的最大数据包大小。 在这种情况下，可以分段发送数据包。 数据包大小的最大值称为最大传输单位（MTU）.

You can match on the following bits::

  M - More Fragments
  D - Do not Fragment
  R - Reserved Bit

Matching on this bits can be more specified with the following
modifiers::

  +         match on the specified bits, plus any others
  *         match if any of the specified bits are set
  !         match if the specified bits are not set

Format::

  fragbits:[*+!]<[MDR]>;

Example of fragbits in a rule:

.. container:: example-rule

   alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET EXPLOIT Invalid non-fragmented packet with fragment offset>0"; :example-rule-emphasis:`fragbits: M;` fragoffset: >0; reference:url,doc.emergingthreats.net/bin/view/Main/2001022; classtype:bad-unknown; sid:2001022; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

fragoffset
^^^^^^^^^^

With the fragoffset keyword you can match on specific decimal values
of the IP fragment offset field. If you would like to check the first
fragments of a session, you have to combine fragoffset 0 with the More
Fragment option. The fragmentation offset field is convenient for
reassembly. The id is used to determine which fragments belong to
which packet and the fragmentation offset field clarifies the order of
the fragments.

You can use the following modifiers::

  <       match if the value is smaller than the specified value
  >       match if the value is greater than the specified value
  !       match if the specified value is not present

Format of fragoffset::

  fragoffset:[!|<|>]<number>;

Example of fragoffset in a rule:

.. container:: example-rule

   alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET EXPLOIT Invalid non-fragmented packet with fragment offset>0"; fragbits: M; :example-rule-emphasis:`fragoffset: >0;` reference:url,doc.emergingthreats.net/bin/view/Main/2001022; classtype:bad-unknown; sid:2001022; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

TCP keywords
------------

seq
^^^
The seq keyword can be used in a signature to check for a specific TCP
sequence number. A sequence number is a number that is generated
practically at random by both endpoints of a TCP-connection. The
client and the server both create a sequence number, which increases
with one with every byte that they send. So this sequence number is
different for both sides. This sequence number has to be acknowledged
by both sides of the connection. Through sequence numbers, TCP
handles acknowledgement, order and retransmission. Its number
increases with every data-byte the sender has send. The seq helps
keeping track of to what place in a data-stream a byte belongs. If the
SYN flag is set at 1, than the sequence number of the first byte of
the data is this number plus 1 (so, 2).

Example::

  seq:0;

Example of seq in a signature:

.. container:: example-rule

    alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL SCAN NULL"; flow:stateless; ack:0; flags:0; :example-rule-emphasis:`seq:0;` reference:arachnids,4; classtype:attempted-recon; sid:2100623; rev:7;)

Example of seq in a packet (Wireshark):

.. image:: header-keywords/Wireshark_seq.png


ack
^^^

The ack is the acknowledgement of the receipt of all previous
(data)-bytes send by the other side of the TCP-connection. In most
occasions every packet of a TCP connection has an ACK flag after the
first SYN and a ack-number which increases with the receipt of every
new data-byte. The ack keyword can be used in a signature to check
for a specific TCP acknowledgement number.

Format of ack::

  ack:1;

Example of ack in a signature:

.. container:: example-rule

    alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL SCAN NULL"; flow:stateless; :example-rule-emphasis:`ack:0;` flags:0; seq:0; reference:arachnids,4; classtype:attempted-recon; sid:2100623; rev:7;)

Example of ack in a packet (Wireshark):

.. image:: header-keywords/Wireshark_ack.png

window
^^^^^^

The window keyword is used to check for a specific TCP window size.
The TCP window size is a mechanism that has control of the
data-flow. The window is set by the receiver (receiver advertised
window size) and indicates the amount of bytes that can be
received. This amount of data has to be acknowledged by the receiver
first, before the sender can send the same amount of new data. This
mechanism is used to prevent the receiver from being overflowed by
data. The value of the window size is limited and can be 2 to 65.535
bytes. To make more use of your bandwidth you can use a bigger
TCP-window.

The format of the window keyword::

  window:[!]<number>;

Example of window in a rule:

.. container:: example-rule

    alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL DELETED typot trojan traffic"; flow:stateless; flags:S,12; :example-rule-emphasis:`window:55808;` reference:mcafee,100406; classtype:trojan-activity; sid:2182; rev:8;)

ICMP keywords
-------------

ICMP (Internet Control Message Protocol) is a part of IP. IP at itself
is not reliable when it comes to delivering data (datagram). ICMP
gives feedback in case problems occur. It does not prevent problems
from happening, but helps in understanding what went wrong and
where. If reliability is necessary, protocols that use IP have to take
care of reliability themselves. In different situations ICMP messages
will be send. For instance when the destination is unreachable, if
there is not enough buffer-capacity to forward the data, or when a
datagram is send fragmented when it should not be, etcetera. More can
be found in the list with message-types.

There are four important contents of a ICMP message on which can be
matched with corresponding ICMP-keywords. These are: the type, the
code, the id and the sequence of a message.

itype
^^^^^

The itype keyword is for matching on a specific ICMP type (number).
ICMP has several kinds of messages and uses codes to clarify those
messages. The different messages are distinct by different names, but
more important by numeric values. For more information see the table
with message-types and codes.

The format of the itype keyword::

  itype:min<>max;
  itype:[<|>]<number>;

Example
This example looks for an ICMP type greater than 10::

  itype:>10;

Example of the itype keyword in a signature:

.. container:: example-rule

    alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL SCAN Broadscan Smurf Scanner"; dsize:4; icmp_id:0; icmp_seq:0; :example-rule-emphasis:`itype:8;` classtype:attempted-recon; sid:2100478; rev:4;)

The following lists all ICMP types known at the time of writing. A recent table can be found `at the website of IANA <https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml>`_

==========  ==========================================================
ICMP Type   Name
==========  ==========================================================
0           Echo Reply
3           Destination Unreachable
4           Source Quench
5           Redirect
6           Alternate Host Address
8           Echo
9           Router Advertisement
10          Router Solicitation
11          Time Exceeded
12          Parameter Problem
13          Timestamp
14          Timestamp Reply
15          Information Request
16          Information Reply
17          Address Mask Request
18          Address Mask Reply
30          Traceroute
31          Datagram Conversion Error
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

With the icode keyword you can match on a specific ICMP code.  The
code of a ICMP message clarifies the message. Together with the
ICMP-type it indicates with what kind of problem you are dealing with.
A code has a different purpose with every ICMP-type.

The format of the icode keyword::

  icode:min<>max;
  icode:[<|>]<number>;

Example:
This example looks for an ICMP code greater than 5::

  icode:>5;

Example of the icode keyword in a rule:

.. container:: example-rule

    alert icmp $HOME_NET any -> $EXTERNAL_NET any (msg:"GPL MISC Time-To-Live Exceeded in Transit"; :example-rule-emphasis:`icode:0;` itype:11; classtype:misc-activity; sid:2100449; rev:7;)

The following lists the meaning of all ICMP types. When a code is not listed,
only type 0 is defined and has the meaning of the ICMP code, in the table above.
A recent table can be found `at the website of IANA <https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml>`_

==========  ==========  =========================================================================
ICMP Code   ICMP Type   Description
==========  ==========  =========================================================================
3           - 0         - Net Unreachable
            - 1         - Host Unreachable
            - 2         - Protocol Unreachable
            - 3         - Port Unreachable
            - 4         - Fragmentation Needed and Don't Fragment was Set
            - 5         - Source Route Failed
            - 6         - Destination Network Unknown
            - 7         - Destination Host Unknown
            - 8         - Source Host Isolated
            - 9         - Communication with Destination Network is Administratively Prohibited
            - 10        - Communication with Destination Host is Administratively Prohibited
            - 11        - Destination Network Unreachable for Type of Service
            - 12        - Destination Host Unreachable for Type of Service
            - 13        - Communication Administratively Prohibited
            - 14        - Host Precedence Violation
            - 15        - Precedence cutoff in effect
5           - 0         - Redirect Datagram for the Network (or subnet)
            - 1         - Redirect Datagram for the Host
            - 2         - Redirect Datagram for the Type of Service and Network
            - 3         - Redirect Datagram for the Type of Service and Host
9           - 0         - Normal router advertisement
            - 16        - Doest not route common traffic
11          - 0         - Time to Live exceeded in Transit
            - 1         - Fragment Reassembly Time Exceeded
12          - 0         - Pointer indicates the error
            - 1         - Missing a Required Option
            - 2         - Bad Length
40          - 0         - Bad SPI
            - 1         - Authentication Failed
            - 2         - Decompression Failed
            - 3         - Decryption Failed
            - 4         - Need Authentication
            - 5         - Need Authorization
==========  ==========  =========================================================================


icmp_id
^^^^^^^

With the icmp_id keyword you can match on specific ICMP id-values.
Every ICMP-packet gets an id when it is being send. At the moment the
receiver has received the packet, it will send a reply using the same
id so the sender will recognize it and connects it with the correct
ICMP-request.

Format of the icmp_id keyword::

  icmp_id:<number>;

Example:
This example looks for an ICMP ID of 0::

  icmp_id:0;

Example of the icmp_id keyword in a rule:

.. container:: example-rule

    alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL SCAN Broadscan Smurf Scanner"; dsize:4; :example-rule-emphasis:`icmp_id:0;` icmp_seq:0; itype:8; classtype:attempted-recon; sid:2100478; rev:4;)

icmp_seq
^^^^^^^^

You can use the icmp_seq keyword to check for a ICMP sequence number.
ICMP messages all have sequence numbers. This can be useful (together
with the id) for checking which reply message belongs to which request
message.

Format of the icmp_seq keyword::

  icmp_seq:<number>;

Example:
This example looks for an ICMP Sequence of 0::

  icmp_seq:0;

Example of icmp_seq in a rule:

.. container:: example-rule

    alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL SCAN Broadscan Smurf Scanner"; dsize:4; icmp_id:0; :example-rule-emphasis:`icmp_seq:0;` itype:8; classtype:attempted-recon; sid:2100478; rev:4;)
