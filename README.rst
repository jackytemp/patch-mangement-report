============ 
补丁管理报告
============

补丁管理摘要
------------ 
+------------+------------+-----------+------------+------------+-----------+------------+ 
| 网络范围 192.168.1.1-192.168.1.255                                                     | 
+============+============+===========+============+============+===========+============+ 
|补丁安装状态| 数量       | 高危      | 重要       | 中等       | 一般      | 低         | 
+------------+------------+-----------+------------+------------+-----------+------------+ 
| 已安装补丁 | 0          | 0         | 0          | 0          | 0         | 0          | 
+------------+------------+-----------+------------+------------+-----------+------------+ 
| 未安装补丁 | 140        | 32        | 47         | 14         | 3         |  44        | 
+------------+------------+-----------+------------+------------+-----------+------------+ 
| 小计       | 140        | 32        | 47         | 15         | 3         | 44         | 
+------------+------------+-----------+------------+------------+-----------+------------+ 

高危等级补丁
   - CESA-2011:0436_
   - CESA-2011:0844_
   - CESA-2011:0999_
 
重要等级补丁
   - CESA-2011:0436_
   - CESA-2011:0844_
   - CESA-2011:0999_
 
中等等级补丁
  - CESA-2013:0522_
  - CESA-2013:0528_
  - CESA-2013:0568_

一般等级补丁
  - CESA-2013:1803_
  - CESA-2013:1804_
  - CESA-2013:1850_
  - CESA-2013:1866_
 
低等级补丁
  - CESA-2014:1307_
  - CESA-2014:1388_
  - CESA-2014:1389_
 
192.168.1.33
   - CESA-2009:1452_
   - CESA-2009:1427_
   - CESA-2009:1452_
   - CESA-2009:1463_

192.168.1.141
   - CESA-2009:1452_
   - CESA-2009:1427_
   - CESA-2009:1452_
   - CESA-2009:1463_
192.168.1.235
   - CESA-2009:1452_
   - CESA-2009:1427_
   - CESA-2009:1452_
   - CESA-2009:1463_


补丁详情
---------
.. _CESA-2009:1427:

CESA-2009:1427
^^^^^^^^^^^^^^
发布日期
  2009-09-08

严重级别
  中等

补丁描述
  An updated fetchmail package that fixes multiple security issues is now
  available for Red Hat Enterprise Linux 3, 4, and 5.
  
  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.
  
  Fetchmail is a remote mail retrieval and forwarding utility intended for
  use over on-demand TCP/IP links, such as SLIP and PPP connections.
  
  It was discovered that fetchmail is affected by the previously published
  "null prefix attack", caused by incorrect handling of NULL characters in
  X.509 certificates. If an attacker is able to get a carefully-crafted
  certificate signed by a trusted Certificate Authority, the attacker could
  use the certificate during a man-in-the-middle attack and potentially
  confuse fetchmail into accepting it by mistake. (CVE-2009-2666)
  
  A flaw was found in the way fetchmail handles rejections from a remote SMTP
  server when sending warning mail to the postmaster. If fetchmail sent a
  warning mail to the postmaster of an SMTP server and that SMTP server
  rejected it, fetchmail could crash. (CVE-2007-4565)
  
  A flaw was found in fetchmail. When fetchmail is run in double verbose
  mode ("-v -v"), it could crash upon receiving certain, malformed mail
  messages with long headers. A remote attacker could use this flaw to cause
  a denial of service if fetchmail was also running in daemon mode ("-d").
  (CVE-2008-2711)
  
  Note: when using SSL-enabled services, it is recommended that the fetchmail
  "--sslcertck" option be used to enforce strict SSL certificate checking.
  
  All fetchmail users should upgrade to this updated package, which contains
  backported patches to correct these issues. If fetchmail is running in
  daemon mode, it must be restarted for this update to take effect (use the
  "fetchmail --quit" command to stop the fetchmail process).

CVE(s)
  `CVE-2007-4565 <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4565/>`_

  `CVE-2008-2711 <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2711/>`_

  `CVE-2009-2666 <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2666/>`_

其他参考
  `RHSA-2009-1427 <https://rhn.redhat.com/errata/RHSA-2009-1427.html>`_

修复平台
  RHEL Desktop Workstation (v. 5 client)

  Red Hat Desktop (v. 3)

  Red Hat Desktop (v. 4)

  Red Hat Enterprise Linux (v. 5 server)

  Red Hat Enterprise Linux AS (v. 3)

  Red Hat Enterprise Linux AS (v. 4)

  Red Hat Enterprise Linux AS (v. 4.8.z)

  Red Hat Enterprise Linux ES (v. 3)

  Red Hat Enterprise Linux ES (v. 4)

  Red Hat Enterprise Linux ES (v. 4.8.z)

  Red Hat Enterprise Linux EUS (v. 5.4.z server)

  Red Hat Enterprise Linux WS (v. 3)

  Red Hat Enterprise Linux WS (v. 4)

已经部署的主机
  192.168.1.33_  部署于 Mon 02 Feb 2015 01:38:00 AM EST
  
  192.168.1.141_ 部署于 Mon 02 Feb 2015 01:38:00 AM EST

  192.168.1.235_ 部署于 Mon 02 Feb 2015 01:38:00 AM EST

需要但未部署的主机
  192.168.1.134_

  192.168.1.132_

  192.168.1.6_


.. _CESA-2009:1452:

CESA-2009:1452
^^^^^^^^^^^^^^

.. _CESA-2009:1463:

CESA-2009:1463
^^^^^^^^^^^^^^

.. _CESA-2009:1470:

CESA-2009:1470
^^^^^^^^^^^^^^

.. _CESA-2009:1549:

CESA-2009:1549
^^^^^^^^^^^^^^

.. _CESA-2009:1642:

CESA-2009:1642
^^^^^^^^^^^^^^


服务器详情
-----------
.. _192.168.1.33:

192.168.1.33
^^^^^^^^^^^^^^
主IP
  192.168.1.33

其他IP
  10.7.7.102

  172.16.8.1

主机名
  fetchmail.aaa.com

操作系统(OS)
  CentOS 6.6 x86

已经部署的补丁
  - 高危等级补丁
      - CESA-2009:1427_   部署于 Mon 02 Feb 2015 01:38:00 AM EST
      - CESA-2009:1452_   部署于 Mon 02 Feb 2015 01:38:00 AM EST
  - 重要等级补丁
      - CESA-2009:1427_   部署于 Mon 02 Feb 2015 01:38:00 AM EST
      - CESA-2009:1452_   部署于 Mon 02 Feb 2015 01:38:00 AM EST
  - 中等等级补丁
      - 暂无
  - 一般等级补丁
      - 暂无
  - 低等级补丁
 

需要但未部署的补丁
  - 高危等级补丁
      - CESA-2009:1452_   最后检查于 Mon 02 Feb 2015 01:38:00 AM EST
  - 重要等级补丁
      - 暂无
  - 中等等级补丁
      - 暂无
  - 一般等级补丁
      - 暂无
  - 低等级补丁
      - 暂无

.. _192.168.1.141:

192.168.1.141
^^^^^^^^^^^^^^

.. _192.168.1.235:

192.168.1.235
^^^^^^^^^^^^^^

.. _192.168.1.134:

192.168.1.134
^^^^^^^^^^^^^^

.. _192.168.1.132:

192.168.1.132
^^^^^^^^^^^^^^

.. _192.168.1.6:

192.168.1.6
^^^^^^^^^^^^^^
