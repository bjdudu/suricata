.. Options for developers - unittests.

.. option:: -u

   运行单元测试并退出，要求Suricata编译时添加 *--enable-unittests* 选项.

.. option:: -U, --unittest-filter=REGEX

   -U 选项指定将要运行的单元测试，这个选项可以使用正则表达式，例如: suricata -u -U
   http

.. option:: --list-unittests

   列出所有单元测试

.. option:: --fatal-unittests

   单元测试出错时启动致命失败，Suricata将会退出而不是继续进行测试。

.. option:: --unittests-coverage

   显示单元测试覆盖报告。
