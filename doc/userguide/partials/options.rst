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

   通常当你使用console运行suricata时，这个console会被suricata占用而不能用来处理其他工作，console关闭时suricata也wf 被关闭。使用-D选项，suricata会在后台运行，这时你可以使用console干处理其他工作而不会影响到suricata运行。

.. option:: --runmode <runmode>

   With the *--runmode* option you can set the runmode that you would
   like to use. This command line option can override the yaml runmode
   option.

   Runmodes are: *workers*, *autofp* and *single*.

   For more information about runmodes see :doc:`Runmodes
   </performance/runmodes>` in the user guide.

.. option:: -F <bpf filter file>

   Use BPF filter from file.

.. option:: -k [all|none]

   Force (all) the checksum check or disable (none) all checksum
   checks.

.. option:: --user=<user>

   Set the process user after initialization. Overrides the user
   provided in the *run-as* section of the configuration file.

.. option:: --group=<group>

   Set the process group to group after initialization. Overrides the
   group provided in the *run-as* section of the configuration file.

.. option:: --pidfile <file>

   Write the process ID to file. Overrides the *pid-file* option in
   the configuration file and forces the file to be written when not
   running as a daemon.

.. option:: --init-errors-fatal

   Exit with a failure when errors are encountered loading signatures.

.. option:: --disable-detection

   Disable the detection engine.

.. Information options.
   
.. option:: --dump-config

   Dump the configuration loaded from the configuration file to the
   terminal and exit.

.. option:: --build-info

   Display the build information the Suricata was built with.

.. option:: --list-app-layer-protos

   List all supported application layer protocols.

.. option:: --list-keywords=[all|csv|<kword>]

   List all supported rule keywords.

.. option:: --list-runmodes

   List all supported run modes.

.. Advanced options.

.. option:: --set <key>=<value>

   Set a configuration value. Useful for overriding basic
   configuration parameters in the configuration. For example, to
   change the default log directory::

     --set default-log-dir=/var/tmp

.. option:: --engine-analysis

   Print reports on analysis of different sections in the engine and
   exit. Please have a look at the conf parameter engine-analysis on
   what reports can be printed

.. option:: --unix-socket=<file>

   Use file as the Suricata unix control socket. Overrides the
   *filename* provided in the *unix-command* section of the
   configuration file.

.. Advanced input options.

.. option:: --pcap-buffer-size=<size>

   Set the size of the PCAP buffer (0 - 2147483647).

.. option:: --netmap[=<device>]

   Enable capture of packet using NETMAP on FreeBSD or Linux. If no
   device is supplied, the list of devices from the netmap section
   in the yaml is used.

.. option:: --pfring[=<device>]

   Enable PF_RING packet capture. If no device provided, the devices in
   the Suricata configuration will be used.
  
.. option:: --pfring-cluster-id <id>

   Set the PF_RING cluster ID.
   
.. option:: --pfring-cluster-type <type>

   Set the PF_RING cluster type (cluster_round_robin, cluster_flow).

.. option:: -d <divert-port>

   Run inline using IPFW divert mode.

.. option:: --dag <device>

   Enable packet capture off a DAG card. If capturing off a specific
   stream the stream can be select using a device name like
   "dag0:4". This option may be provided multiple times read off
   multiple devices and/or streams.
	    
.. option:: --napatech

   Enable packet capture using the Napatech Streams API.

.. option:: --mpipe

   Enable packet capture using the TileGX mpipe interface.

.. option:: --erf-in=<file>

   Run in offline mode reading the specific ERF file (Endace
   extensible record format).

.. option:: --simulate-ips

   Simulate IPS mode when running in a non-IPS mode.
