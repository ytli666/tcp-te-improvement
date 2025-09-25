#!/usr/bin/env python3
import sys
import struct
from scapy.all import sniff, TCP, get_if_list

def get_if():
    for iface in get_if_list():
        if "eth0" in iface:
            return iface
    print("Cannot find eth0 interface")
    sys.exit(1)

def handle_pkt(pkt):
    if TCP in pkt and pkt[TCP].options:
        for opt in pkt[TCP].options:
            if isinstance(opt, tuple) and opt[0] == 253:
                data = opt[1]
                if len(data) == 20:
                    regs = struct.unpack('!5I', data)
                    print(f"total_time             = {regs[0]}")
                    print(f"elapsed_time           = {regs[1]}")
                    print(f"total_size             = {regs[2]}")
                    print(f"sent_size              = {regs[3]}")
                    print(f"estimated_remaining_time = {regs[4]}")
                    print('-' * 40)
                else:
                    print(f"Unexpected payload length: {len(data)}")

def main():
    iface = get_if()
    print(f"Sniffing on {iface}, waiting for custom-TCP-option packets...")
    sniff(iface=iface,
          filter="tcp and src host 10.0.0.1 and dst host 10.0.1.1",
          prn=handle_pkt,
          store=False)

if __name__ == '__main__':
    main()
