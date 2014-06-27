Wireshark Dissector for NMPM FCP Communication
==============================================

A Wireshark Plugin for Dissection of HBP/NMPM Communication.

Tested on Debian wheezy's wireshark 1.8.2.

Building
--------
    $ apt-get source wireshark/wheezy
    # put this directory into plugins and rename it to "hostarq"
    # add hostarq to SUBDIRS variable in plugins/Makefile.am
    $ ./autogen.sh
    $ ./configure
    $ make

Edit-Test Cycle
---------------
    $ make -C plugins
    $ WIRESHARK_RUN_FROM_BUILD_DIRECTORY=1 ./wireshark
