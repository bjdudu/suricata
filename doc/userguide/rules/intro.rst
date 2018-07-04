规则格式
============

规则在Suricata中起着非常重要的作用，大多数情况下人们使用现有的规则集.

官方途径来安装规则集请参考 :doc:`../rule-management/suricata-update`.

本Suricata规则文件解释了所有关于规则的内容; 如何阅读，调整和创建它们。

规则/签名包括以下内容：

* **action**, 确定规则匹配时执行的动作
* **header**, 定义协议，IP地址，端口和方向.
* **rule options**, 定义规则细节.


.. role:: example-rule-action
.. role:: example-rule-header
.. role:: example-rule-options
.. role:: example-rule-emphasis

下面是一个规则的例子:

.. container:: example-rule

    :example-rule-action:`drop` :example-rule-header:`tcp $HOME_NET any -> $EXTERNAL_NET any` :example-rule-options:`(msg:"ET TROJAN Likely Bot Nick in IRC (USA +..)"; flow:established,to_server; flowbits:isset,is_proto_irc; content:"NICK "; pcre:"/NICK .*USA.*[0-9]{3,}/i"; reference:url,doc.emergingthreats.net/2008124; classtype:trojan-activity; sid:2008124; rev:2;)`

在这个例子里, :example-rule-action:`红色` 是动作,
:example-rule-header:`绿色` 规则头部， :example-rule-options:`蓝色`
是规则选项。

我们将在本节中使用上述规则作为示例，高亮显示规则的不同部分。它是来自Emerging Threats数据库的签名，这是一个开放式数据库，其中包含许多规则，您可以在Suricata实例中免费下载和使用这些规则。

动作
------
.. container:: example-rule

    :example-rule-emphasis:`drop` tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Likely Bot Nick in IRC (USA +..)"; flow:established,to_server; flowbits:isset,is_proto_irc; content:"NICK "; pcre:"/NICK .*USA.*[0-9]{3,}/i"; reference:url,doc.emergingthreats.net/2008124; classtype:trojan-activity; sid:2008124; rev:2;)

更多信息请参见 :ref:`suricata-yaml-action-order`.


协议
--------
.. container:: example-rule

    drop :example-rule-emphasis:`tcp` $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Likely Bot Nick in IRC (USA +..)"; flow:established,to_server; flowbits:isset,is_proto_irc; content:"NICK "; pcre:"/NICK .*USA.*[0-9]{3,}/i"; reference:url,doc.emergingthreats.net/2008124; classtype:trojan-activity; sid:2008124; rev:2;)

这个规则关键字告诉Suricata什么协议是它关注的，你可以选择以下四种基础协议:

* tcp (for tcp-traffic)
* udp
* icmp
* ip (ip 意味着 'all' or 'any')

还有一些所谓的应用层协议或者第七层协议可以选择，它们包括:

* http
* ftp
* tls (this includes ssl)
* smb
* dns
* dcerpc
* ssh
* smtp
* imap
* msn
* modbus (默认禁用)
* dnp3 (默认禁用)
* enip (默认禁用)
* nfs (取决于rust是否可用)
* ikev2 (取决于rust是否可用)
* krb5 (取决于rust是否可用)
* ntp (取决于rust是否可用)
* dhcp (取决于rust是否可用)

这些协议是否可用取决于协议是否在suricata.yaml配置文件中启用。

如果你有一个HTTP协议的规则，Suricata确认这条规则只会匹配HTTP相关的流量

源和目的
----------------------
.. container:: example-rule

    drop tcp :example-rule-emphasis:`$HOME_NET` any -> :example-rule-emphasis:`$EXTERNAL_NET` any (msg:"ET TROJAN Likely Bot Nick in IRC (USA +..)"; flow:established,to_server; flowbits:isset,is_proto_irc; content:"NICK "; pcre:"/NICK .*USA.*[0-9]{3,}/i"; reference:url,doc.emergingthreats.net/2008124; classtype:trojan-activity; sid:2008124; rev:2;)

*第一个高亮部分就是源,第二个是目的(注意箭头的方向).*

源和目的分别表示流量的来源和流量的目的，可以使用IP地址（支持IPv4和IPv6）和IP范围来定义源和目的，并且可以用以下操作符来进行组合使用:

==============  =========================
操作符           描述
==============  =========================
../..           IP范围 (CIDR表示法)
!               排除/取反
[.., ..]        组合
==============  =========================

通常，我们可以使用变量, 如 ``$HOME_NET`` 和
``$EXTERNAL_NET``. 配置文件中指定了这些变量的IP地址，用于代替规则中的变量。
更多信息请参考 :ref:`suricata-yaml-rule-vars`  

例如:

==================================  ==========================================
例子                                含义
==================================  ==========================================
! 1.1.1.1                           除了1.1.1.1的任意IP
![1.1.1.1, 1.1.1.2]                 除了1.1.1.1 和 1.1.1.2 的任意IP
$HOME_NET                           配置文件中设置的HOME_NET变量
[$EXTERNAL_NET, !$HOME_NET]         包含EXTERNAL_NET但不包含HOME_NET的地址
[10.0.0.0/24, !10.0.0.5]            10.0.0.0/24但不包括10.0.0.5
[..., [....]]
[..., ![.....]]
==================================  ==========================================

.. warning::

   如果你在配置文件中做了如下设置::

       HOME_NET: any
       EXTERNAL_NET: ! $HOME_NET

   那么你不能在规则中使用 ``$EXTERNAL_NET`` ，这是因为它代表
   'not any'. 这是一个无效设置。

端口 (源和目的)
------------------------------
.. container:: example-rule

    drop tcp $HOME_NET :example-rule-emphasis:`any` -> $EXTERNAL_NET :example-rule-emphasis:`any` (msg:"ET TROJAN Likely Bot Nick in IRC (USA +..)"; flow:established,to_server; flowbits:isset,is_proto_irc; content:"NICK "; pcre:"/NICK .*USA.*[0-9]{3,}/i"; reference:url,doc.emergingthreats.net/2008124; classtype:trojan-activity; sid:2008124; rev:2;)

*第一个高亮部分是源端口，第二是是目的端口 (注意箭头方向).*

流量通过端口进入和流出，不同的端口具有不同的端口号。例如，HTTP的默认端口是80，而443通常是HTTPS的端口。但请注意，端口不代表通信中使用的协议。相反，它确定哪个应用程序正在接收数据。

上面提到的端口通常是目标端口。 源端口，即发送数据包的应用程序使用的端口，通常由操作系统随机分配。 在为自己的HTTP服务编写规则时，通常会编写``any - > 80``，因为这意味着从任何源端口到HTTP应用程序（在端口80上运行）的任何数据包都是匹配的。

在端口设置中你也可以像上面描述的那样使用特定操作符, 例如:

==============  ==================
操作符           描述
==============  ==================
:               商品范围
!               排除/取反
[.., ..]        组合
==============  ==================

例如:

==============  ==========================================
例子                             含义
==============  ==========================================
[80, 81, 82]    端口 80, 81 and 82
[80: 82]        从80到82端口
[1024: ]        从1024到最高端口号
!80             除了80的任意端口
[80:100,!99]    从80到100，99除外
[1:80,![2,4]]   从1到80, 除开2和4
[.., [..,..]]
==============  ==========================================


方向
---------
.. container:: example-rule

    drop tcp $HOME_NET any :example-rule-emphasis:`->` $EXTERNAL_NET any (msg:"ET TROJAN Likely Bot Nick in IRC (USA +..)"; flow:established,to_server; flowbits:isset,is_proto_irc; content:"NICK "; pcre:"/NICK .*USA.*[0-9]{3,}/i"; reference:url,doc.emergingthreats.net/2008124; classtype:trojan-activity; sid:2008124; rev:2;)

方向告诉规则匹配哪个方向的流量，几乎所有的规则都有一个右箭头(``->``)来指示方向，这意味着只有相同方向的流量才会被匹配。但是，匹配双向流量的规则也是存在的 (``<>``)::

  source -> destination
  source <> destination  (both directions)

.. warning::

   没有相反方向, 即没有 ``<-`` 符号。

下图中的例子说明了这个问题， 比如，有一个IP地址为1.2.3.4和端口1024的客户端，以及一个IP地址为5.6.7.8的服务器，监听端口80（通常是HTTP）。客户端向服务器发送消息，服务器回复应答。

.. image:: intro/TCP-session.png

现在，我们有一条规则包含如下头部::

    alert tcp 1.2.3.4 1024 -> 5.6.7.8 80

只有第一个数据包才会被这条规则匹配，因为方向确定了我们无法匹配应答数据包。

规则选项
------------
规则剩下的部分由规则选项组成。 这些选项用括号括起来并用分号分隔。有些选项有设置内容(如 ``msg``),
它由选项关键字指定, 后面跟上冒号,再后面就是设置值。其它的没有设置内容,仅仅只有选项关键字(如 ``nocase``)::

  <keyword>: <settings>;
  <keyword>;

规则选项具有特定的顺序，更改其顺序将改变规则的含义。

.. note::

    字符 ``;`` 和 ``"`` 在Suricata规则语言中具有特殊的含义，如果要在规则选项设置值中使用它们，必须要进行转义。例如::

	    msg:"Message with semicolon\;";

    因此，您还必须转义反斜杠，因为它充当转义字符。 

本章的剩下部分记录各种关键字的使用.

关键字的一些通用细节如下.

.. _rules-modifiers:

修饰符关键字
~~~~~~~~~~~~~~~~~

一些关键字会当作修饰符来工作。有两种类型的修饰符：

* 老一点的 **'content修饰符'** 可以回顾一下规则, 如::

      alert http any any -> any any (content:"index.php"; http_uri; sid:1;)

  在上面的例子中，模式 'index.php' 被强行用来检查HTTP uri缓冲区，而不是整个数据包内容.

* 比较新的类型被称作 **'sticky buffer'**. 它将缓冲区名称放在第一位，其后面的所有关键字都作用于该缓冲区, 例如::

      alert http any any -> any any (http_response_line; content:"403 Forbidden"; sid:1;)

  在上面的例子中，模式 '403 Forbidden' 被用来检查HTTP响应头，这是因为他跟在 ``http_response_line`` 关键字后面.

.. _rules-normalized-buffers:

标准化缓冲区
~~~~~~~~~~~~~~~~~~
数据包由原始数据组成,HTTP和重组会复制这些类型的数据包数据。它们清除异常内容，组合数据包等。 余下部分叫做“标准化缓冲区”:

.. image:: normalized-buffers/normalization1.png

因为数据正在规范化，所以它的内容发生了变化，这种规范化也是一种解析。 规范化缓冲区包括：所有HTTP关键字，重组流，TLS-，SSL-，SSH-，FTP-和dcerpc-缓冲区。

请注意有一些例外情况，例如 ``http_raw_uri``关键字，
更多信息参见 :ref:`rules-http-uri-normalization` 
