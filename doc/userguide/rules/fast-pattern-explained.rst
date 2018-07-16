Suricata快速匹配模式选择详解
=============================================

如果在规则中明确设置了'fast_pattern'关键字，Suricata将采用快速模式匹配。'fast_pattern'关键字在一条规则中只能设置一次。如果规则中没有设置'fast_pattern'，Suricata将自动选择一个content来使用快速模式匹配。

以下说明Suricata快速模式匹配自动选择的逻辑。

请注意，如果存在正（即非否定）content匹配，则忽略否定content匹配以进行快速模式选择。 如果不存在，才考虑否定的content匹配。

fast_pattern选择标准如下:

#. Suricata首先匹配规则中具有最高“优先级”的所有content，优先级基于匹配的缓冲区，通常'http_*' 缓冲区具有更高的优先级 (更小的数字代表更高的优先级)。关于什么样的缓冲区拥有什么样的优先级请参阅   :ref:`附录 B <fast-pattern-explained-appendix-b>` .
#. 在步骤1中进行的content匹配（最高优先级content匹配）中，最长（就字符/字节长度而言）content匹配使用快速模式匹配。
#. 如果多个content匹配具有相同的最高优先级并且都是最长长度，则具有最高字符/字节多样性评分（“模式强度”）的那个匹配用作快速模式匹配。关于确定模式强度的算法详情请参见  :ref:`附录 C <fast-pattern-explained-appendix-c>` .
#. 如果多个content匹配具有相同的最高优先级，都是最长长度，且具有相同的最高模式强度，则*最后注册*的缓冲区("list_id") 使用快速模式匹配。 不同的缓冲区/列表注册顺序详情请参阅 :ref:`附录 B
   <fast-pattern-explained-appendix-b>` .
#. 如果多个content匹配具有相同的最高优先级，都是最长长度，具有相同的最高模式强度，并且具有相同的list_id(即在同一个缓冲区内匹配)，那么content按照在规则中从左到右的顺序，第一个content使用快速匹配。

值得注意的是，对于具有相同优先级，长度和模式强度的content匹配，'http_stat_msg'，'http_stat_code'和'http_method'优先于常规'content'匹配。

附录
----------

.. _fast-pattern-explained-appendix-a:

附录 A - 缓冲区, list_id值, Suricata 1.3.4中它们的注册顺序
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

在Suricata 1.1.x - 1.4.x中，这些应该都是一样的.

======= ============================== ======================== ==================
list_id 内容修饰符关键字                 缓冲区名                  注册顺序
======= ============================== ======================== ==================
1       <none> (regular content match) DETECT_SM_LIST_PMATCH    1 (first)
2       http_uri                       DETECT_SM_LIST_UMATCH    2
6       http_client_body               DETECT_SM_LIST_HCBDMATCH 3
7       http_server_body               DETECT_SM_LIST_HSBDMATCH 4
8       http_header                    DETECT_SM_LIST_HHDMATCH  5
9       http_raw_header                DETECT_SM_LIST_HRHDMATCH 6
10      http_method                    DETECT_SM_LIST_HMDMATCH  7
11      http_cookie                    DETECT_SM_LIST_HCDMATCH  8
12      http_raw_uri                   DETECT_SM_LIST_HRUDMATCH 9
13      http_stat_msg                  DETECT_SM_LIST_HSMDMATCH 10
14      http_stat_code                 DETECT_SM_LIST_HSCDMATCH 11
15      http_user_agent                DETECT_SM_LIST_HUADMATCH 12 (last)
======= ============================== ======================== ==================

注意: 在决定Suricata 1.3.4的快速模式匹配时，注册顺序无关紧要，但list_id值起作用。

.. _fast-pattern-explained-appendix-b:

附录 B - 缓冲区, list_id值, 优先级，Suricata 2.0.7中它们的注册顺序
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

在Suricata 2.0.x 中，这些应该都是一样的.

========================================== ================== ============================== ============================= =======
优先级 (数字小代表高优先级)                   注册顺序           内容修饰符关键字                缓冲区名字                     list_id
========================================== ================== ============================== ============================= =======
3                                          11                 <none> (regular content match) DETECT_SM_LIST_PMATCH         1
3                                          12                 http_method                    DETECT_SM_LIST_HMDMATCH       12
3                                          13                 http_stat_code                 DETECT_SM_LIST_HSCDMATCH      9
3                                          14                 http_stat_msg                  DETECT_SM_LIST_HSMDMATCH      8
2                                          1 (first)          http_client_body               DETECT_SM_LIST_HCBDMATCH      4
2                                          2                  http_server_body               DETECT_SM_LIST_HSBDMATCH      5
2                                          3                  http_header                    DETECT_SM_LIST_HHDMATCH       6
2                                          4                  http_raw_header                DETECT_SM_LIST_HRHDMATCH      7
2                                          5                  http_uri                       DETECT_SM_LIST_UMATCH         2
2                                          6                  http_raw_uri                   DETECT_SM_LIST_HRUDMATCH      3
2                                          7                  http_host                      DETECT_SM_LIST_HHHDMATCH      10
2                                          8                  http_raw_host                  DETECT_SM_LIST_HRHHDMATCH     11
2                                          9                  http_cookie                    DETECT_SM_LIST_HCDMATCH       13
2                                          10                 http_user_agent                DETECT_SM_LIST_HUADMATCH      14
2                                          15 (last)          dns_query                      DETECT_SM_LIST_DNSQUERY_MATCH 20
========================================== ================== ============================== ============================= =======

注意: 在决定Suricata 2.0.7的快速模式匹配时，list_id无关紧要，但注册顺序值起作用.

.. _fast-pattern-explained-appendix-c:

附录 C - 模式强度算法
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

来自detect-engine-mpm.c. 基本上，模式强度“评分”从零开始，从左到右检查传入的字节数组中的每个字符/字节。如果当前字符/字节是第一次出现，接下来根据当前字符/字节类型来加分，如果当前字符是字母，则分数加3，如果不是字母字符，但是可打印字符或者是0x00, 0x01, 0xFF，则分数加4，如果不是这些字符，那么分数加6。如果不是第一次出现的话，分数加1。最终得到模式强度评分。

.. code-block:: c

   /** \brief Predict a strength value for patterns
    *
    *  Patterns with high character diversity score higher.
    *  Alpha chars score not so high
    *  Other printable + a few common codes a little higher
    *  Everything else highest.
    *  Longer patterns score better than short patters.
    *
    *  \param pat pattern
    *  \param patlen length of the pattern
    *
    *  \retval s pattern score
    */
    uint32_t PatternStrength(uint8_t *pat, uint16_t patlen) {
	uint8_t a[256];
	memset(&a, 0 ,sizeof(a));
	uint32_t s = 0;
	uint16_t u = 0;
	for (u = 0; u < patlen; u++) {
	    if (a[pat[u]] == 0) {
		if (isalpha(pat[u]))
		    s += 3;
		else if (isprint(pat[u]) || pat[u] == 0x00 || pat[u] == 0x01 || pat[u] == 0xFF)
		    s += 4;
		else
		    s += 6;
		a[pat[u]] = 1;
	    } else {
		s++;
	    }
	}
	return s;
    }
