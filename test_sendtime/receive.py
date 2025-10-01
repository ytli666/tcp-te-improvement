#!/usr/bin/env python3
import argparse, time, sys, signal
from collections import defaultdict, deque
from scapy.all import sniff, TCP, IP, get_if_list

def pick_iface():
    for i in get_if_list():
        if "eth0" in i: return i
    print("Cannot find eth0-like interface"); sys.exit(1)

class Flow:
    def __init__(self):
        self.first=None; self.last=None
        self.win_t=deque(maxlen=16); self.win_b=deque(maxlen=16)
        self.sum_bytes=0; self.inst_bps=0.0; self.avg_bps=0.0
        self.last_fields=None  # (total_time, elapsed_ms, total_size, sent_size, remain_ms)
    def update(self, now, pktlen, fields):
        if self.first is None: self.first = now
        self.last = now
        self.sum_bytes += pktlen
        self.win_t.append(now); self.win_b.append(pktlen)
        if len(self.win_t)>=2:
            dt = max(1e-6, self.win_t[-1]-self.win_t[0])
            self.inst_bps = (sum(self.win_b)*8.0)/dt
        life = max(1e-6, self.last-self.first)
        self.avg_bps = (self.sum_bytes*8.0)/life
        if fields: self.last_fields = fields

def unpack_opt253(tcp):
    if not tcp.options: return None
    for o in tcp.options:
        if isinstance(o, tuple) and o[0]==253 and o[1] and len(o[1])>=20:
            b = o[1]
            import struct
            try: return struct.unpack("!5i", b[:20])  # 5 * int32
            except: return None
    return None

def main():
    ap = argparse.ArgumentParser(description="Receiver with wire-rate, kind=253 parsing, elapsed & total bits")
    ap.add_argument("--dport", type=int, default=9090)
    ap.add_argument("--interval", type=float, default=1.0)
    args = ap.parse_args()

    iface = pick_iface()
    bpf = f"tcp dst port {args.dport}"
    flows = defaultdict(Flow)

    # 新增：全域統計（從第一個封包開始計時；累積所有收到的 bytes）
    first_ts = None
    total_bytes = 0

    running = True
    def stop(_s,_f):
        nonlocal running; running=False
    signal.signal(signal.SIGINT, stop); signal.signal(signal.SIGTERM, stop)

    def handle(pkt):
        nonlocal first_ts, total_bytes
        if IP not in pkt or TCP not in pkt: return
        if pkt[TCP].dport != args.dport: return
        now = time.time()
        if first_ts is None:
            first_ts = now
        total_bytes += len(bytes(pkt))  # 線上實收的位元組（含 L3/L4 header）
        key = pkt[IP].src
        fields = unpack_opt253(pkt[TCP])
        flows[key].update(now, len(bytes(pkt)), fields)

    print(f"[recv] iface={iface}, filter='{bpf}', interval={args.interval}s (Ctrl+C to stop)")
    nxt=time.time()+args.interval
    while running:
        sniff(iface=iface, filter=bpf, store=False, prn=handle, timeout=args.interval)
        now=time.time()
        if now>=nxt:
            tot_inst = sum(f.inst_bps for f in flows.values())/1e6   # Mb/s
            tot_avg  = sum(f.avg_bps  for f in flows.values())/1e6   # Mb/s
            elapsed  = 0.0 if first_ts is None else max(0.0, now - first_ts)
            total_mb = (total_bytes * 8.0) / 1e6                      # 轉成 Mb

            print(f"wire inst: {tot_inst:8.2f} Mb/s | wire avg: {tot_avg:8.2f} Mb/s "
                  f"| flows={len(flows)} | elapsed: {elapsed:6.2f} s | total: {total_mb:8.2f} Mb")

            # 仍保留每流最後一次攜帶的 253 欄位
            for ip, f in flows.items():
                if f.last_fields:
                    t_total, t_elapsed, sz_total, sz_sent, t_remain = f.last_fields
                    print(f"  {ip}  sz={sz_sent}/{sz_total}  t_elapsed={t_elapsed}ms  t_remain={t_remain}ms")
            nxt=now+args.interval

if __name__ == "__main__":
    main()
