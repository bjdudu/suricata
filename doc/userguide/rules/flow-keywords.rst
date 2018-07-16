流关键字
=============

flowbits
--------

Flowbits由两部分组成。 第一部分描述了它将要执行的操作，第二部分是flowbit的名称。

一个流有多个数据包，Suricata将这些流保存在内存中。更多信息请参阅 :ref:`suricata-yaml-flow-settings`. Flowbits可以确保在多数据包匹配时生成告警。例如一条规则决定只有两个数据包都匹配时才会生成告警，因此，当第二个数据包匹配时，Suricata必须知道第一个数据包是否也匹配。如果第一个数据包匹配，Flowbits标记流，那么Suricata'知道'它应该在第二个数据包也匹配时生成告警。

Flowbits有不同的动作。包括:

::

  flowbits: set, name                可能的话，在流中设置条件/'name'
  flowbits: isset, name              在规则匹配并且设置条件的时候产生一条告警
  flowbits: toggle, name             反转当前设置。所以如果设置了某个条件，那么将取消设置，反之亦然。
  flowbits: unset, name              用来取消流中的条件设置.
  flowbits: isnotset, name           在规则匹配并且未设置条件的时候产生一条告警
  flowbits: noalert                  禁止规则产生告警.

如:

.. image:: flow-keywords/Flowbit_3.png

当你查看第一条规则时，你会发现如果不是规则末尾的'flowbits: noalert'，那么这条规则在匹配时会产生一条告警。这条规则的目的是匹配'userlogin'并在流中标记，因此没有必要生成告警。 如果没有第一条规则，第二条规则则无效。如果第一条规则匹配，flowbits在流中设置一个特定的条件成立，现在使用第二条规则可以检查先前的数据包是否满足该特定条件。 如果满足并且第二条规则匹配，则会产生一条告警。

可以在规则中多次使用flowbits并组合不同的功能。

flow
----

flow关键字可用于匹配流的方向，客户端<=>服务器，还可以匹配流是否established。flow关键字也可用于表示规则必须仅在流上(only_stream) 或仅在数据包上匹配(no_stream)。

所以，你可以用flow关键来匹配:

to_client
  匹配从服务器到客户端的数据包.
to_server
  匹配从客户端到服务器的数据包.
from_client
  匹配从客户端到服务器的数据包（与to_server相同）.
from_server
  匹配从服务器到客户端的数据包（与to_client相同）.
established
  匹配established连接.
not_established
  匹配不属于established连接的数据包.
stateless
  匹配无论是否属于established连接的数据包.
only_stream
  匹配已由流引擎重新组装的数据包.
no_stream
  匹配尚未由流引擎重组的数据包。 将不匹配已重新组装的数据包.
only_frag
  匹配已从分段重组的数据包.
no_frag
  匹配尚未进行分段重组的数据包.

多个flow选项可以组合使用,如 ::

  flow:to_client, established
  flow:to_server, established, only_stream
  flow:to_server, not_established, no_frag

 *established* 的确认依赖于协议:

* TCP连接在三次握手后变成established.

  .. image:: flow-keywords/Flow1.png

* 其它协议(如UDP), 只要看见通信双方的流量就可以认为连接建立(established)了.

  .. image:: flow-keywords/Flow2.png


flowint
-------

我们将很快在引擎中添加全局变量任务，flowint是这个任务的前身，这将允许在变量中捕获，存储和比较数据。顾名思义他是全局的，因此，您可以比较来自不相关流中的数据包的数据。

Flowint允许使用变量进行存储和数学运算。它的运行方式与flowbits非常相似，但增加了数学功能，并且可以存储和操作整数，而不仅仅是标志的集合。我们可以将它用于许多非常有用的事情，例如统计次数，添加或减去次数，或者在流中对多个因子进行阈值处理。 这将很快扩展到全局上下文，因此用户可以在流之间执行这些操作。

它的语法如下:

flowint: , ;

定义一个变量(非必须), 或检查变量是否设置.

flowint: , , ;

flowint: , < +,-,=,>,<,>=,<=,==, != >, ;

比较或改变变量。 加，减，大于或小于，大于等于，小于等于都可以使用。比较项可以是整数或其他变量。

________________________________________

例如，如果您想要统计在特定流中某用户名出现的次数，次数超过5时告警.

::

  alert tcp any any -> any any (msg:"Counting Usernames"; content:"jonkman"; \
        flowint: usernamecount, +, 1; noalert;)

这条规则规定用户名每出现一次，变量usernamecount就加1，不会每次出现产生告警。

现在我们想让它在流中出现超过5次时告警.

::

  alert tcp any any -> any any (msg:"More than Five Usernames!"; content:"jonkman"; \
        flowint: usernamecount, +, 1; flowint:usernamecount, >, 5;)

因此，仅当usernamecount大于5时，我们会得到一条告警.

So now let’s say we want to get an alert as above but NOT if there
have been more occurrences of that username logging out. 现在我们可以说在没有用户注销的情况下，可以以上面的规则得到一条告警。假设此特定协议使用"jonkman logout"表示注销，尝试:

::

  alert tcp any any -> any any (msg:"Username Logged out"; content:"logout jonkman"; \
        flowint: usernamecount, -, 1; flowint:usernamecount, >, 5;)

所以现在只有当这个特定用户名有超过五个活动登录时，才会产生告警。

这是一个相当简单的例子，但我相信它显示了这样一个简单的函数可以为规则编写做些什么。在登录跟踪，IRC状态机，恶意软件跟踪和暴力破解检测等方面都可以应用。

假设我们正在跟踪一个通常允许每个连接有五次登录失败的协议，但是我们有一个漏洞，攻击者可以在五次尝试之后继续登录，我们需要了解它之后的登录。

::

  alert tcp any any -> any any (msg:"Start a login count"; content:"login failed"; \
        flowint:loginfail, notset; flowint:loginfail, =, 1; noalert;)

第一击，如果尚未设置变量，我们会检测到第一次登陆失败，定义变量将并其设置为1。

::

  alert tcp any any -> any any (msg:"Counting Logins"; content:"login failed"; \
        flowint:loginfail, isset; flowint:loginfail, +, 1; noalert;)

如果设置变量，我们就将其加1.

::

  alert tcp any any -> any any (msg:"More than Five login fails in a Stream"; \
        content:"login failed"; flowint:loginfail, isset; flowint:loginfail, >, 5;)


如果在同一个流中超过5次登陆失败就产生一条告警.

但是，我们想在两次成功登录并且之后登录失败的情况下，也产生告警.

::

  alert tcp any any -> any any (msg:"Counting Good Logins"; content:"login successful"; \
        flowint:loginsuccess, +, 1; noalert;)

这里我们统计成功登陆，现在我们统计成功登陆相关的失败登陆:

::

  alert tcp any any -> any any (msg:"Login fail after two successes"; \
        content:"login failed"; flowint:loginsuccess, isset; flowint:loginsuccess, =, 2;)

下面是一些其它的例子:

::

  alert tcp any any -> any any (msg:"Setting a flowint counter"; content:"GET"; \
        flowint:myvar, notset; flowint:maxvar,notset;                           \
        flowint:myvar,=,1; flowint: maxvar,=,6;)

::

  alert tcp any any -> any any (msg:"Adding to flowint counter";                \
        content:"Unauthorized"; flowint:myvar,isset; flowint: myvar,+,2;)

::

  alert tcp any any -> any any (msg:"if the flowint counter is 3 create a new counter"; \
        content:"Unauthorized"; flowint:myvar, isset; flowint:myvar,==,3; \
        flowint:cntpackets,notset; flowint:cntpackets, =, 0;)

::

  alert tcp any any -> any any (msg:"count the rest without generating alerts"; \
        flowint:cntpackets,isset; flowint:cntpackets, +, 1; noalert;)

::

  alert tcp any any -> any any (msg:"fire this when it reach 6";                \
        flowint: cntpackets, isset;                                             \
        flowint: maxvar,isset; flowint: cntpackets, ==, maxvar;)


stream_size
-----------

流大小选项根据序列号注册的字节数匹配流量。这个关键字有多个修饰符:

::

  >      大于
  <      小于
  =      等于
  !=     不等于
  >=    大于等于
  <=    小于等于

格式

::

  stream_size:<server|client|both|either>, <modifier>, <number>;

规则中使用stream-size关键字的例子:
