.. Start with the most common basic options.

.. option:: -h

   显示使用概要

.. option:: -V

   显示Suricata版本

.. option:: -c <path>

   指定配置文件路径

.. option:: -T

   测试配置

.. option:: -v

   -v 选项让Suricata输出详细信息。 多次使用这个选项可以得到更多详细信息。

.. Basic input options.

.. option:: -r <path>

   以pcap离线模式运行从pcap文件中读取数据。 如果<path>指定一个目录，则将按照修改时间的顺序处理该目录中的所有文件，以保持流状态。

.. option:: --pcap-file-continuous

   与-r 选项一起使用以指示运行模式应该保持活动直到被中断。 在以目录方式添加处理文件时，加上这个选项不会重置流状态。

.. option::  -i <interface>

   -i 选项指定用于嗅探数据包的网卡，此选项将尝试可用的最佳数据包捕获方法。

.. option:: --pcap[=<device>]

   以PCAP模式运行。 如果未指定设备，则将使用配置文件中*pcap*部分提供的接口。
   
.. option:: --af-packet[=<device>]

   指定Linux上使用AF_PACKET进行数据包捕获。 如果没有指定设备，则使用yaml配置文件中af-packet部分的设备列表。

.. option:: -q <queue id>

   根据NFQUEUE队列ID运行在inline nfqueue模式，这个ID可能会多次提供

.. Back to other basic options.

.. option:: -s <filename.rules>

   -s 选项指定一个规则文件，这个文件可以与yaml配置文件中指定的规则文件一起加载使用。

.. option:: -S <filename.rules>

   -S 选项指定一个规则文件，这个文件会单独加载使用，而不加载yaml配置文件中指定的规则文件。

.. option:: -l <directory>

   -l 选项指定默认日志目录。 即使您已经在yaml配置文件中设置了default-log-dir，Suricata也会忽略这个设置。如果您没有使用-l选项，Suricata将使用yaml中设置的目录。

.. option:: -D

   通常当你使用console运行suricata时，这个console会被suricata占用而不能用来处理其他工作，console关闭时suricata也会被关闭。使用-D选项，suricata会在后台运行，这时你可以使用console干处理其他工作而不会影响到suricata运行。

.. option:: --runmode <runmode>

   *--runmode* 选项指定你想要使用的运行模式，此命令行选项可以覆盖yaml中的运行模式设置。

   运行模式包括: *workers*, *autofp* and *single*.

   更多关于运行模式的资料请参考手册中的  :doc:`Runmodes
   </performance/runmodes>`  .

.. option:: -F <bpf filter file>

   指定BPF过滤器文件.

.. option:: -k [all|none]

   强制（all）或禁用（none）校验和检查。

.. option:: --user=<user>

   初始化后设置进程用户，这个选项会覆盖配置文件中* run-as *部分指定的用户。

.. option:: --group=<group>

   指定进程运行的用户组，这个选项会覆盖配置文件中* run-as *部分设定的用户组。

.. option:: --pidfile <file>

   将进程ID写到指定文件，这个选项会覆盖配置文件中*pid-file*部分的设定值，并且当进程不是以后台进程运行时，强制写文件。

.. option:: --init-errors-fatal

   设置若加载规则文件时出错，就失败退出。

.. option:: --disable-detection

   禁用检测引擎

.. Information options.
   
.. option:: --dump-config

   将配置文件中加载的配置转储到终端并退出。

.. option:: --build-info

   显示Suricata编译时的编译选项信息。

.. option:: --list-app-layer-protos

   列出支持的所有应用层协议。

.. option:: --list-keywords=[all|csv|<kword>]

   列出支持的所有规则关键字。

.. option:: --list-runmodes

   列出支持的所有运行模式。

.. Advanced options.

.. option:: --set <key>=<value>

   设置一个配置值来覆盖基本配置参数。例如，更改默认日志目录::

     --set default-log-dir=/var/tmp

.. option:: --engine-analysis

   打印关于引擎中不同部分的分析报告，要知道可以打印什么报告请参考配置文件engine-analysis部分。

.. option:: --unix-socket=<file>

   指定Suricata的unix控制套接字，这个选项会覆盖配置文件中* unix-command * 部分指定的 * filename *。

.. Advanced input options.

.. option:: --pcap-buffer-size=<size>

   指定PCAP包捕获缓冲区大小 (0 - 2147483647).

.. option:: --netmap[=<device>]

   在FreeBSD或Linux上启用NETMAP数据包捕获，如果未指定设备，则使用yaml配置文件中netmap部分设置的设备列表。

.. option:: --pfring[=<device>]

   启用PF_RING数据包捕获，如果未指定设备，将使用Suricata配置文件中指定的设备。
  
.. option:: --pfring-cluster-id <id>

   设置PF_RING集群ID.
   
.. option:: --pfring-cluster-type <type>

   设置PF_RING集群类型 (cluster_round_robin, cluster_flow).

.. option:: -d <divert-port>

   使用IPFW转发模式运行

.. option:: --dag <device>

   Enable packet capture off a DAG card. If capturing off a specific
   stream the stream can be select using a device name like
   "dag0:4". This option may be provided multiple times read off
   multiple devices and/or streams.启用DAG卡数据包捕获。可使用诸如“dag0：4”之类的设备名称来选择捕获特定流，这个选项可以多次使用以指定多个设备和/或流。
	    
.. option:: --napatech

   使用Napatech Streams API进行数据包捕获。

.. option:: --mpipe

   使用TileGX mpipe接口进行数据包捕获.

.. option:: --erf-in=<file>

   从指定的ERF(Endace可扩展记录格式)文件中读取数据以离线模式运行

.. option:: --simulate-ips

   以非IPS模式运行时伪装成IPS模式
