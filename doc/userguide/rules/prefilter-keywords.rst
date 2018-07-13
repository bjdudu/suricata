=====================
预过滤关键字
=====================

.. _rules-keyword-fast_pattern:

fast_pattern
============
.. toctree::

   fast-pattern-explained

在多模式匹配器（MPM）中仅使用规则中的一个content，如果有多个content，那么Suricata会使用'strongest' content，strong由长度、content的变化程度以及正在检查什么样的缓冲区这样一个组合来决定。通常情况下，长度越长和变化程度越高越好。有关Suricata如何确定快速模式匹配的完整详细信息参见 :doc:`fast-pattern-explained`.

有时规则的作者会得出这样的结论：他宁愿让Suricata选择另外一个content，而不是按它默认的选择去做。

例如::

  User-agent: Mozilla/5.0 Badness;

  content:”User-Agent|3A|”;
  content:”Badness”; distance:0;

在这个例子中，您看到第一个content比第二个content更长且更具多变性，因此您知道Suricata将使MPM使用此content进行匹配。但是由于“User-Agent：”会经常被匹配到，并且“Badness”在网络流量中出现得较少，因此您可以使Suricata使“fast_pattern”使用第二个content进行匹配。

::

  content:”User-Agent|3A|”;
  content:”Badness”; distance:0; fast_pattern;

fast_pattern关键字对他前面的content起作用。

.. image:: fast-pattern/fast_pattern.png

Fast-pattern也可以和前面提到的所有关键字以及所有提到的HTTP修饰符组合在一起使用。

fast_pattern:only
~~~~~~~~~~~~~~~~~

有时候一条规则只有一个content,在这种情况下，使用MPM找到匹配后，Suricata将不再进行检查。如果只有一个content,那么整条规则匹配了，Suricata会自动注意到这一点。在某些规则中，仍然用 'fast_pattern:only;'表示。尽管Suricata没有必要使用fast_pattern:only,但是仍然支持这种写法.

fast_pattern:'chop'
~~~~~~~~~~~~~~~~~~~~

如果您不希望MPM使用整个content，可以使用fast_pattern 'chop'。

如::

  content: “aaaaaaaaabc”; fast_pattern:8,4;

这样的话， MPM只使用从第8字节开始的4个字节（也就是最后4个字节）进行匹配.


预过滤
=========
可以使用'prefilter'关键字在特定规则中启用其他非MPM关键字的预过滤引擎。

在下面的规则中，TTL检测将用于预过滤而不是那个单字节的模式匹配:

::

  alert ip any any -> any any (ttl:123; prefilter; content:"a"; sid:1;)

有关如何配置预过滤引擎的更多信息请参见  :ref:`suricata-yaml-prefilter`
