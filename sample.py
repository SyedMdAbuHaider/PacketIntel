from scapy.all import *
wrpcap("test.pcap", [IP()/TCP(), IP()/UDP()])