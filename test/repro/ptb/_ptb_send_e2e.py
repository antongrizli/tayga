from pathlib import Path

import sys; sys.path.insert(0,'/usr/lib/python3/dist-packages')
import logging; logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import sendp, Ether
with open(str(Path(__file__).with_name('_ptb_e2e.bin')),'rb') as f: raw=f.read()
sendp(Ether(raw), iface='server0', verbose=0)
print('PTB_INJECTED_E2E')
