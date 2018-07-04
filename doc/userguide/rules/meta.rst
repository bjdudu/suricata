元关键字
=============

.. role:: example-rule-emphasis

元关键字设置对Suricata的检测没有影响; 但是它却对Suricata的事件输出有影响。

msg (消息)
-------------
msg关键字指定规则产生的告警文本信息。

msg格式::

  msg: "一些描述信息";

例如::

  msg:"ATTACK-RESPONSES 403 Forbidden";
  msg:"ET EXPLOIT SMB-DS DCERPC PnP bind attempt";

继续上一章的例子, 这是实际规则中的关键字:

.. container:: example-rule

    drop tcp $HOME_NET any -> $EXTERNAL_NET any (:example-rule-emphasis:`msg:"ET TROJAN Likely Bot Nick in IRC (USA +..)";` flow:established,to_server; flowbits:isset,is_proto_irc; content:"NICK "; pcre:"/NICK .*USA.*[0-9]{3,}/i"; reference:url,doc.emergingthreats.net/2008124; classtype:trojan-activity; sid:2008124; rev:2;)

.. tip::

   一般习惯于将规则选项的第一部分大写，并且用来表示规则类型。

   同样习惯于将 ``msg`` 作为第一个规则选项关键字。

.. note:: 在msg中下列字符必须转义:
	      ``;`` ``\`` ``"``

sid (规则ID)
------------------

sid关键字指定每条规则的id号，这个id用一个数字来表示，其格式是::

  sid:123;

规则中sid的例子:

.. container:: example-rule

    drop tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Likely Bot Nick in IRC (USA +..)"; flow:established,to_server; flowbits:isset,is_proto_irc; content:"NICK "; pcre:"/NICK .*USA.*[0-9]{3,}/i"; reference:url,doc.emergingthreats.net/2008124; classtype:trojan-activity; :example-rule-emphasis:`sid:2008124;` rev:2;)

.. tip::

   一般习惯于将规则 ``sid`` 放到最后一个规则选项关键字 (或者如果有 ``rev``的话，就放到倒数第二个)。

rev (revision)
--------------
sid关键字几乎每次都伴随着rev，Rev代表规则的版本。如果修改了规则，则规则编写者应当增加rev的数值。rev规则选项关键字的格式是::

  rev:123;


规则中rev的例子:

.. container:: example-rule

    drop tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Likely Bot Nick in IRC (USA +..)"; flow:established,to_server; flowbits:isset,is_proto_irc; content:"NICK "; pcre:"/NICK .*USA.*[0-9]{3,}/i"; reference:url,doc.emergingthreats.net/2008124; classtype:trojan-activity; sid:2008124; :example-rule-emphasis:`rev:2;`)

.. tip::

    一般习惯于将sid放在rev的前面, 并且它们一起放在所有关键字的最后。

gid (组ID)
--------------
gid关键字可用于为不同的签名组提供另一个id值（像sid一样）。 Suricata默认使用gid 1，我们可以修改这个gid。它通常不会被改变，改变它没有技术含义。你只能在告警中看到它。

fast.log告警中的gid示例。 在[1:2008124:2]中，1是gid（2008124是sid，2是rev）。

.. container:: example-rule

    10/15/09-03:30:10.219671  [**] [:example-rule-emphasis:`1`:2008124:2] ET TROJAN Likely Bot Nick in IRC (USA +..) [**] [Classification: A Network Trojan was Detected]
    [Priority: 3] {TCP} 192.168.1.42:1028 -> 72.184.196.31:6667


classtype
---------
classtype关键字提供有关规则和警报分类的信息，它由短名称，长名称和优先级组成，它用来标识规则是仅仅是信息性的还是关于黑客的，classification.config指定了规则中使用的每个classtype的优先级。

classtype定义举例::

  config classification: web-application-attack,Web Application Attack,1
  config classification: not-suspicious,Not Suspicious Traffic,3

现在我们在配置中定义了这两个classtypes，就可以在规则中使用它们了。一条classtype为web-application-attack的规则，它的优先级被设置为1，并且产生的告警内容中会包含 'Web Application Attack':

=======================  ======================  ===========
classtype                告警                     优先级
=======================  ======================  ===========
web-application-attack   Web Application Attack  1
not-suspicious           Not Suspicious Traffic  3
=======================  ======================  ===========

接下来的例子也包含classtype, 它是 trojan-activity:

.. container:: example-rule

    drop tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Likely Bot Nick in IRC (USA +..)"; flow:established,to_server; flowbits:isset,is_proto_irc; content:"NICK "; pcre:"/NICK .*USA.*[0-9]{3,}/i"; reference:url,doc.emergingthreats.net/2008124; :example-rule-emphasis:`classtype:trojan-activity;` sid:2008124; rev:2;)


.. tip::

    通常习惯于将classtype放在sid and rev前面，其它的关键字后面.

参考
---------

参考关键字表示指向规则有关的信息以及试图解决规则相关问题的位置。参考关键字可以在规则中多次出现，此关键字适用于规则编写者和分析师，他们会研究规则匹配的原因。 它的格式如下::

  reference: type, reference

一个典型的指向www.info.com的参考是这样的::

  reference: url, www.info.com

但是，参考类型有很多种，一个众所周知的例子是CVE数据库，它为漏洞分配编号。为了避免你多次输入相同URL的麻烦，你可以这样来定义参考::

  reference: cve, CVE-2014-1234

这会定义一个指向http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-1234 的参考。
所有参考类型都在reference.config配置文件中定义。

下面的例子也定义了一个参考:

.. container:: example-rule

    drop tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Likely Bot Nick in IRC (USA +..)"; flow:established,to_server; flowbits:isset,is_proto_irc; content:"NICK "; pcre:"/NICK .*USA.*[0-9]{3,}/i"; :example-rule-emphasis:`reference:url,doc.emergingthreats.net/2008124;` classtype:trojan-activity; sid:2008124; rev:2;)


优先级
--------
优先级关键字用一个从1到255数字表示，但是通常只使用从1到4，高优先级的规则将会优先检查，最高优先级是1。classtype中指定的优先级会被priority关键字优先级覆盖，priority关键字格式如下:

  priority:1;

metadata
--------

meatadata关键字允许将其他非功能性信息添加到规则中，虽然它的格式很自由，但建议使用key, value键值对，这是因为Suricata可以在eve告警中包含这些值。其格式是::

  metadata: key value;
  metadata: key value, key value;

target
------
target关键字允许规则编写者指定告警的哪一侧是攻击的目标，如果指定了，告警事件中会包含有关源和目标的信息。

其格式是::

   target:[src_ip|dest_ip]

如果设置成src_ip，那么生成的事件(JSON中的src_ip字段) 中源IP就是攻击目标，如果设置成dest_ip，生成事件中目的IP就是攻击目标。
