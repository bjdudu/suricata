安装
============

在使用Suricata之前，我们必须安装它。. Suricata可以通过二进制包: :ref:`install-binary-packages` 在各种不同的发行版上安装。

对于熟悉自己编译软件的人来说，推荐使用自己编译源代码方式安装的。

高级用户可以查看高级指南, 参见 :ref:`install-advanced`.

源码方式
------

通过源码方式安装可以最大程序地控制Suricata安装过程.

基本步骤 ::

    tar xzvf suricata-4.0.0.tar.gz
    cd suricata-4.0.0
    ./configure
    make
    make install

这将Suricata安装到 ``/usr/local/bin/`` 目录, 默认配置文件位于 ``/usr/local/etc/suricata/`` 目录，日志输出到
``/usr/local/var/log/suricata`` 目录


常规configure选项
^^^^^^^^^^^^^^^^^^^^^^^^

.. option:: --disable-gccmarch-native

    不根据硬件来优化生成的二进制代码，加上这个选项意味着生成的Suricata程序是可移植的或者在VM中使用.

.. option:: --prefix=/usr/

    Suricata二进制文件将安装到/usr/bin/目录. 默认是安装到  ``/usr/local/`` 目录

.. option:: --sysconfdir=/etc

    Suricata配置文件目录将设定为 /etc/suricata/ ，默认是  ``/usr/local/etc/`` 目录

.. option:: --localstatedir=/var

    Suricata日志输出目录将设定为 /var/log/suricata/. 默认是 ``/usr/local/var/log/suricata`` 目录

.. option:: --enable-lua

    为检测和输出模块启用Lua支持.

.. option:: --enable-geopip

    为检测模块启用GeoIP支持.

.. option:: --enable-rust

    启用试验性Rust支持

依赖
^^^^^^^^^^^^

编译Suricata你需要安装以下开发库和头文件:

  libpcap, libpcre, libmagic, zlib, libyaml

下面这几个工具也是必须的:

  make gcc (or clang) pkg-config

若要编译的程序具有所有功能特性, 需要添加这些:

  libjansson, libnss, libgeoip, liblua5.1, libhiredis, libevent

Rust支持 (试验性):

  rustc, cargo

Ubuntu/Debian
"""""""""""""

最小依赖::

    apt-get install libpcre3 libpcre3-dbg libpcre3-dev build-essential libpcap-dev   \
                    libyaml-0-2 libyaml-dev pkg-config zlib1g zlib1g-dev \
                    make libmagic-dev

建议::

    apt-get install libpcre3 libpcre3-dbg libpcre3-dev build-essential libpcap-dev   \
                    libnet1-dev libyaml-0-2 libyaml-dev pkg-config zlib1g zlib1g-dev \
                    libcap-ng-dev libcap-ng0 make libmagic-dev libjansson-dev        \
                    libnss3-dev libgeoip-dev liblua5.1-dev libhiredis-dev libevent-dev

对于iptables/nftables IPS集成，额外添加::

    apt-get install libnetfilter-queue-dev libnetfilter-queue1  \
                    libnetfilter-log-dev libnetfilter-log1      \
                    libnfnetlink-dev libnfnetlink0

Rust支持 (仅Ubuntu)::

    apt-get install rustc cargo

.. _install-binary-packages:

二进制包
---------------

Ubuntu
^^^^^^

针对Ubuntu, OISF维护了一个问题包含最新的稳定发行版本源，地址是 ``suricata-stable`` .

使用这个源::

    sudo add-apt-repository ppa:oisf/suricata-stable
    sudo apt-get update
    sudo apt-get install suricata

Debian
^^^^^^

在Debian 9 (Stretch)下，运行::

    apt-get install suricata

在Debian Jessie中，Suricata已经过期, 但在Debian Backports中，有一个更新的版本.

以root身份运行::

    echo "deb http://http.debian.net/debian jessie-backports main" > \
        /etc/apt/sources.list.d/backports.list
    apt-get update
    apt-get install suricata -t jessie-backports

Fedora
^^^^^^

::

    dnf install suricata

RHEL/CentOS
^^^^^^^^^^^

对于RedHat Enterprise Linux 7 和 CentOS 7 ，可以使用 EPEL 源.

::

    yum install epel-release
    yum install suricata


.. _install-advanced:

高级安装
---------------------

从GIT和其他操作系统安装的各种安装指南都保存在:
https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Suricata_Installation

