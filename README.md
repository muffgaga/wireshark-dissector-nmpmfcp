Wireshark Dissector for NMPM FCP Communication
==============================================

A Wireshark Plugin for Dissection of HBP/NMPM Communication.

Tested on Debian wheezy's wireshark 1.8.2.


Building
--------
    $ apt-get source wireshark/wheezy
    $ cd wireshark-1.8.2/plugins
    $ git clone https://github.com/muffgaga/wireshark-dissector-nmpmfcp.git hostarq
    # add "hostarq" to @SUBDIRS@ variable in plugins/Makefile.am
    $ ./autogen.sh
    $ ./configure
    $ make


Edit-Test Cycle
---------------
    $ make -C plugins
    $ WIRESHARK_RUN_FROM_BUILD_DIRECTORY=1 ./wireshark
