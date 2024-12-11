#!/bin/sh

# cat ./assets/sample-tcpdump.pcap | PCAP_ANALYZER_LOG=trace,h2=info,tower=info,hyper=info,tonic=info ./target/debug/pcap-analyzer -j 1 -

tcpdump -i en0 -w - -U -c 99 | tee ./assets/sample-tcpdump.pcap | \
  PCAP_ANALYZER_LOG=info,h2=info,tower=info,hyper=info,tonic=info ./target/release/pcap-analyzer -j 1 -
