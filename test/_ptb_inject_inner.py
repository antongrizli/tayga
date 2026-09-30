import sys
sys.path.insert(0, '/usr/lib/python3/dist-packages')
import logging; logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import *
emb = IPv6(src='fd9b:64:1:ff::10', dst='64:ff9b::b00:2', nh=6, hlim=63)/TCP(sport=12345,dport=80,flags='S',seq=1000)
ptb = Ether(src='ff:ff:ff:ff:ff:ff',dst='ff:ff:ff:ff:ff:ff')/IPv6(src='64:ff9b::c000:201',dst='fd9b:64:1:fe::2',nh=58)/ICMPv6PacketTooBig(mtu=1280)/emb
sendp(ptb, iface='server0', verbose=0)
print('PTB_SENT')
