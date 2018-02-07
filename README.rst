Subverting your server through its BMC: the HPE iLO4 case
=========================================================


Introduction
------------

iLO is the server management solution embedded in almost every HP servers for
more than 10 years. It provides every feature required by a system
administrator to remotely manage a server without having to reach it
physically. Such features include power management, remote system console,
remote CD/DVD image mounting, as well as many monitoring indicators.

We've performed a deep dive security study of HP ``iLO4`` (known to be used on
the family of servers ``HP ProLiant Gen8`` and ``ProLiant Gen9`` servers) and
the results of this study were presented at the **REcon** conference held in
Brussels (February 2 - 4, 2018, see [1]_).

``iLO4`` runs on a dedicated ``ARM`` processor embedded in the server,
and is totally independent from the main processor. It has a dedicated flash
chip to hold its firmware, a dedicated RAM chip and a dedicated network
interface. On the software side, the operating system is the proprietary RTOS
GreenHills Integrity [2]_.


Results
-------

One critical vulnerability was identified and reported to the ``HP PSIRT`` in
February 2017, known as ``CVE-2017-12542`` (``CVSSv3`` 9.8 [3]_) :

* Authentication bypass and remote code execution
* Fixed in ``iLO4`` versions ``2.53`` (released in May 2017, buggy) and ``2.54`` [4]_


Slides and demos
----------------

The slides from our **REcon** talk are available here_ . They cover the
following points:

* Firmware unpacking and memory space understanding
* GreenHills OS Integrity internals:

    * kernel object model
    * virtual memory
    * process isolation

* Review of exposed attack surface: ``www``, ``ssh``, *etc.*
* Vulnerability discovery and exploitation
* Demonstration of a new exploitation technique that allows to
  compromise the host server operating system through DMA.


To illustrate them, we also release the three demos as videos. The first one
demonstrates the use of the vulnerability we discovered to bypass the
authentication from the RedFish API:


.. image:: https://github.com/airbus-seclab/ilo4_toolbox/blob/master/demos/demo1_connection_bypass.gif
    :width: 100%
    :align: center

In the second one we show how the vulnerability can also be turned into an
arbitrary remote code execution (``RCE``) in the process of the web server;
allowing read access to the ``iLO`` file-system for example.


.. image:: https://github.com/airbus-seclab/ilo4_toolbox/blob/master/demos/demo2_dump_users.gif
    :width: 100%
    :align: center

Finally, in  the third videos, we leverage this ``RCE`` to exploit an ``iLO4``
feature which allows us to access (``RW``) to the host memory and inject a
payload in the host Linux kernel.


.. image:: https://github.com/airbus-seclab/ilo4_toolbox/blob/master/demos/demo3_host_pwn.gif
    :width: 100%
    :align: center




Tooling
-------

To support our research we've developed scripts and tools to help us
automatize some tasks, especially firmware unpacking and mapping.


Firmware
********

``ilo4_extract.py`` script takes an ``HP Signed file`` as input (obtained from
the update package). It is invoked with:

::

    >python ilo4_extract.py ilo4_244.bin extract


Extract from the output log:

::

    [+] iLO Header 0: iLO4 v 2.44.7 19-Jul-2016
      > magic              : iLO4
      > build_version      :  v 2.44.7 19-Jul-2016
      > type               : 0x08
      > compression_type   : 0x1000
      > field_24           : 0xaf8
      > field_28           : 0x105f57
      > decompressed_size  : 0x16802e0
      > raw_size           : 0xd0ead3
      > load_address       : 0xffffffff
      > field_38           : 0x0
      > field_3C           : 0xffffffff
      > signature


From the extracted file, ``ilo0.bin`` is the ``Integrity`` applicative image
(userland). It contains all the tasks that will run on the ``iLO`` system. To
parse each of these tasks and generate the ``IDA Pro`` loading script, one can
use the script ``dissection.rb``.

It relies upon the ``Metasm `` framework[5]_ and also requires the ``Bindata``
library [6]_.

::

    >ruby dissection.rb ilo0.bin


Back to the kernel image, ``ilo4_extract.py`` told us that:

::

    [+] iLO Header 1: iLO4 v 0.8.36 16-Nov-2015
      > magic              : iLO4
      > build_version      :  v 0.8.36 16-Nov-2015
      > type               : 0x02
      > compression_type   : 0x1000
      > field_24           : 0x9fd
      > field_28           : 0x100344
      > decompressed_size  : 0xc0438
      > raw_size           : 0x75dad
      > load_address       : 0x20001000
      > field_38           : 0x0
      > field_3C           : 0xffffffff

Using ``IDA Pro`` to load the extracted file ``ilo1.bin`` at ``0x20001000`` as
``ARM`` code, one can also study the ``Integrity`` kernel.


* ``secinfo4.py`` parses the section information embedded into the kernel image
  and creates the appropriate memory segment in the disassembler
* ``parse_mr.py`` dumps the registered ``Memory Region`` objects


``iLO5`` format differs slightly, however the same ``dissection.rb`` script
can be used to extract the ``Integrity`` applicative image.



Network
*******

Finally, to help people scan for existing vulnerable iLO systems exposed in
their own infrastructures, we release a simple ``Go`` scanner. It attempts to
fetch a special ``iLO`` page:  "``/xmldata?item=ALL``"; if it exists, then it
extracts the firmware version and HP server type.


First edit the "``targets``" variable in the code and specify the internal
``IP`` ranges you want to scan.

::

   var (
        targets = []string{
                "10.0.0.0/8",
                "192.168.66.0/23",
                "172.16.133.0/24"}
   )


Then compile the code for your OS/architecture.

::

    > env GOOS=target-OS GOARCH=target-architecture go build iloscan.go


For example:

::

    > env GOOS=openbsd GOARCH=amd64 go build iloscan.go
    > ./iloscan

Then look the result in ``/tmp/iloscan.log`` (can be changed in the source):

::

    > less /tmp/iloscan.log
    192.168.66.69{{ RIMP} [{{ HSI} ProLiant DL380 G7}] [{{ MP} 1.80 ILOCZ2069K2S4       ILO583970CZ2069K2S4}]}


Authors
-------

* Fabien PERIGAUD - ``fabien [dot] perigaud [at] synacktiv [dot] com`` - ``@0xf4b``
* Alexandre GAZET - ``alexandre [dot] gazet [at] airbus [dot] com``
* Joffrey CZARNY  - ``snorky [at] insomnihack [dot] net`` - ``@\_Sn0rkY``



License
-------

The scripts and scanner are released under the [GPLv2].



References
----------

.. [1] https://recon.cx/2018/brussels/talks/subvert_server_bmc.html
.. [2] https://www.ghs.com/products/rtos/integrity.html
.. [3] http://h20565.www2.hpe.com/hpsc/doc/public/display?docId=hpesbhf03769en_us
.. [4] https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12542
.. [5] https://github.com/jjyg/metasm
.. [6] https://github.com/dmendel/bindata
.. [GPLv2] https://github.com/airbus-seclab/ilo4_toolbox/blob/master/COPYING
.. _here: https://github.com/airbus-seclab/airbus-seclab.github.io/blob/master/ilo/RECONBRX2018-Slides-Subverting_your_server_through_its_BMC_the_HPE_iLO4_case-perigaud-gazet-czarny.pdf
