.. _eve-json-output:

Eve JSON输出
===============

Suricata能够使用JSON输出告警，HTTP事件，DNS事件,TLS事件和文件信息。

The most common way to use this is through 'EVE', which is a firehose approach where all these logs go into a single file.
最常用的方法是通过'EVE'把所有这些日志都放在一个文件中。

.. literalinclude:: ../../partials/eve-log.yaml

任意一条告警，HTTP日志等将会输出到 'eve.json' 这一个文件中，这个文件能够被第三方工具进行处理，如Logstash或者jq. 

输出类型
~~~~~~~~~~~~

EVE可以通过多种方式输出. ``regular`` 表示输出到文件. 其它选项有 ``syslog``, ``unix_dgram``, ``unix_stream`` 和 ``redis``.

输出类型 ::

      filetype: regular #regular|syslog|unix_dgram|unix_stream|redis
      filename: eve.json
      #prefix: "@cee: " # prefix to prepend to each log entry
      # the following are valid when type: syslog above
      #identity: "suricata"
      #facility: local5
      #level: Info ## possible levels: Emergency, Alert, Critical,
                   ## Error, Warning, Notice, Info, Debug
      #redis:
      #  server: 127.0.0.1
      #  port: 6379
      #  async: true ## if redis replies are read asynchronously
      #  mode: list ## possible values: list|lpush (default), rpush, channel|publish
      #             ## lpush and rpush are using a Redis list. "list" is an alias for lpush
      #             ## publish is using a Redis channel. "channel" is an alias for publish
      #  key: suricata ## key or channel to use (default to suricata)
      # Redis pipelining set up. This will enable to only do a query every
      # 'batch-size' events. This should lower the latency induced by network
      # connection at the cost of some memory. There is no flushing implemented
      # so this setting as to be reserved to high traffic suricata.
      #  pipelining:
      #    enabled: yes ## set enable to yes to enable query pipelining
      #    batch-size: 10 ## number of entry to keep in buffer

告警
~~~~~~

告警是记录规则匹配的事件，它可以被元数据修改，例如应用层（HTTP，DNS等）根据规则及其元素生成一条告警。

Metadata::

        - alert:
            #payload: yes             # 使payload以base64编码输出
            #payload-buffer-size: 4kb # 向eve-log输出payload缓冲区的最大size
            #payload-printable: yes   # 使payload以可打印(lossy)格式输出
            #packet: yes              # enable dumping of packet (without stream segments)
            #http-body: yes           # enable dumping of http body in Base64
            #http-body-printable: yes # enable dumping of http body in printable format

            # metadata:

              # Include the decoded application layer (ie. http, dns)
              #app-layer: true

              # Log the the current state of the flow record.
              #flow: true

              #rule:
                # Log the metadata field from the rule in a structured
                # format.
                #metadata: true

                # Log the raw rule text.
                #raw: false

DNS
~~~

DNS records are logged one log record per query/answer record.

YAML::

        - dns:
            # control logging of queries and answers
            # default yes, no to disable
            query: yes     # enable logging of DNS queries
            answer: yes    # enable logging of DNS answers
            # control which RR types are logged
            # all enabled if custom not specified
            #custom: [a, aaaa, cname, mx, ns, ptr, txt]

To reduce verbosity the output can be filtered by supplying the record types
to be logged under ``custom``.

TLS
~~~

TLS records are logged one record per session.

YAML::

        - tls:
            extended: yes     # enable this for extended logging information
            # custom allows to control which tls fields that are included
            # in eve-log
            #custom: [subject, issuer, serial, fingerprint, sni, version, not_before, not_after, certificate, chain, ja3]

The default is to log certificate subject and issuer. If ``extended`` is
enabled, then the log gets more verbose.

By using ``custom`` it is possible to select which TLS fields to log.

Date modifiers in filename
~~~~~~~~~~~~~~~~~~~~~~~~~~

It is possible to use date modifiers in the eve-log filename.

::

   outputs:
     - eve-log:
         filename: eve-%s.json

The example above adds epoch time to the filename. All the date modifiers from the
C library should be supported. See the man page for ``strftime`` for all supported
modifiers.

.. _output_eve_rotate:

Rotate log file
~~~~~~~~~~~~~~~

Eve-log can be configured to rotate based on time.

::

  outputs:
    - eve-log:
        filename: eve-%Y-%m-%d-%H:%M.json
        rotate-interval: minute

The example above creates a new log file each minute, where the filename contains
a timestamp. Other supported ``rotate-interval`` values are ``hour`` and ``day``.

In addition to this, it is also possible to specify the ``rotate-interval`` as a
relative value. One example is to rotate the log file each X seconds.

::

  outputs:
    - eve-log:
        filename: eve-%Y-%m-%d-%H:%M:%S.json
        rotate-interval: 30s

The example above rotates eve-log each 30 seconds. This could be replaced with
``30m`` to rotate every 30 minutes, ``30h`` to rotate every 30 hours, ``30d``
to rotate every 30 days, or ``30w`` to rotate every 30 weeks.

Multiple Logger Instances
~~~~~~~~~~~~~~~~~~~~~~~~~

It is possible to have multiple 'EVE' instances, for example the following is valid:

::

  outputs:
    - eve-log:
        enabled: yes
        type: file
        filename: eve-ips.json
        types:
          - alert
          - drop

    - eve-log:
        enabled: yes
        type: file
        filename: eve-nsm.json
        types:
          - http
          - dns
          - tls

So here the alerts and drops go into 'eve-ips.json', while http, dns and tls go into 'eve-nsm.json'.

In addition to this, each log can be handled completely separately:

::

  outputs:
    - alert-json-log:
        enabled: yes
        filename: alert-json.log
    - dns-json-log:
        enabled: yes
        filename: dns-json.log
    - drop-json-log:
        enabled: yes
        filename: drop-json.log
    - http-json-log:
        enabled: yes
        filename: http-json.log
    - ssh-json-log:
        enabled: yes
        filename: ssh-json.log
    - tls-json-log:
        enabled: yes
        filename: tls-json.log

For most output types, you can add multiple:

::

  outputs:
    - alert-json-log:
        enabled: yes
        filename: alert-json1.log
    - alert-json-log:
        enabled: yes
        filename: alert-json2.log

Except for ``drop`` for which only a single logger instance is supported.

File permissions
~~~~~~~~~~~~~~~~

Log file permissions can be set individually for each logger. ``filemode`` can be used to
control the permissions of a log file, e.g.:

::

  outputs:
    - eve-log:
        enabled: yes
        filename: eve.json
        filemode: 600

The example above sets the file permissions on ``eve.json`` to 600, which means that it is
only readable and writable by the owner of the file.

JSON flags
~~~~~~~~~~

Several flags can be specified to control the JSON output in EVE:

::

  outputs:
    - eve-log:
        json:
          # Sort object keys in the same order as they were inserted
          preserve-order: yes

          # Make the output more compact
          compact: yes

          # Escape all unicode characters outside the ASCII range
          ensure-ascii: yes

          # Escape the '/' characters in string with '\/'
          escape-slash: yes

All these flags are enabled by default, and can be modified per EVE instance.
