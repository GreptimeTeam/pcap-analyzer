#!/bin/sh

./target/release/assemble-pcap \
  --sql "select ts, link_type, length, packet_data from tcpdumps order by pcap_index limit 99" \
  --out "/tmp/test.pcap"
