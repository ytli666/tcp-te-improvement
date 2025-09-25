#!/usr/bin/env python3
import sys
import struct
import time
from scapy.all import Ether, IP, TCP, sendp, get_if_list, get_if_hwaddr

TOTAL_SIZE = 1000000 

def get_if():
    for iface in get_if_list():
        if "eth0" in iface:
            return iface
    print("Cannot find eth0 interface")
    sys.exit(1)

def main():
    iface = get_if()

    curr = {
        'total_time':               -1,
        'elapsed_time':             0,
        'total_size':               TOTAL_SIZE,
        'sent_size':                0,
        'estimated_remaining_time': -1
    }

    start_ms = int(time.time() * 1000)
    CHUNK_SIZE = 100

    ROUND = TOTAL_SIZE // CHUNK_SIZE
    for i in range(ROUND):
        payload = struct.pack(
            '!5I',
            curr['total_time'],
            curr['elapsed_time'],
            curr['total_size'],
            curr['sent_size'],
            curr['estimated_remaining_time']
        )

        opts = [
            ('NOP', None),
            ('MSS', 1460),
            (253, payload)
        ]
        pkt = (
            Ether(src=get_if_hwaddr(iface), dst="08:00:00:00:00:FE") /
            IP(src="10.0.0.1", dst="10.0.1.1") /
            TCP(sport=1234, dport=80, flags="S", options=opts)
        )
        sendp(pkt, iface=iface, verbose=False)

        curr['sent_size'] += CHUNK_SIZE
        now_ms = int(time.time() * 1000)
        curr['elapsed_time'] = now_ms - start_ms

        if curr['sent_size'] > 0 and curr['sent_size'] <= curr['total_size']:
            ratio = curr['sent_size'] / curr['total_size']
            curr['estimated_remaining_time'] = int(curr['elapsed_time'] / ratio) - curr['elapsed_time']



    print(f"Sent {TOTAL_SIZE} packets.")

if __name__ == '__main__':
    main()
