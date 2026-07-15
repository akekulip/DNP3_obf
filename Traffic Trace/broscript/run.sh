#!/bin/bash

#cmd="/usr/local/bin/bro"
cmd="/usr/local/zeek/bin/zeek"

#sudo $cmd -C -r ../SEL751.pcap ./latency.bro
#sudo $cmd -C -r ../SEL751L.pcap ./testtcp.bro
sudo $cmd -C -r ../ION7550.pcap ./testtcp.bro
#sudo $cmd -C -r ../AB1400.pcap ./testtcp.bro
