
import sys; sys.path.insert(0,'/usr/lib/python3/dist-packages')
import logging; logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import sendp, Ether
with open('/Users/antongrizli/Documents/MikroTik/tayga-clat-perf/test/_ptb_e2e.bin','rb') as f: raw=f.read()
sendp(Ether(raw), iface='server0', verbose=0)
print('PTB_INJECTED_E2E')
