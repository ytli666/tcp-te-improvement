#!/usr/bin/env python3
import argparse, json, math, struct, sys, time, gc
from scapy.all import Ether, IP, TCP, Raw, sendp, get_if_list, get_if_hwaddr, get_if_addr

TOPO_FILE = "topology.json"
ETH_MTU   = 1500
IP_HDR    = 20
TCP_BASE  = 20

# 固定設定
TOTAL_BYTES = 10 * 1024 * 1024        # 100 MB（Bytes）
RATE_MBPS   = 5.0                      # 5 Mb/s（megabits per second）

def load_topo():
    try:
        with open(TOPO_FILE) as f:
            return json.load(f)
    except Exception:
        return {"hosts": {}, "default_dmac": "08:00:00:00:00:FE"}

def pick_iface():
    for i in get_if_list():
        if "eth0" in i:   # mininet host 常見 hX-eth0
            return i
    print("Cannot find eth0-like interface"); sys.exit(1)

def opt_len_bytes(opts):
    """估算 TCP options 實際長度並補齊 4-byte 對齊"""
    total = 0
    for o in opts:
        if isinstance(o, tuple):
            k = o[0]
            if k == "NOP":
                total += 1
            elif k == "MSS":
                total += 4
            elif isinstance(k, int):          # 自訂 kind
                total += 2 + (len(o[1]) if o[1] else 0)
    pad = (-total) % 4
    return total + pad

def clamp_i32(x):
    x = int(x)
    return max(-(2**31), min(2**31-1, x))

def build_opt(t_total, t_elapsed, sz_total, sz_sent, t_remain):
    payload = struct.pack("!5i", *(clamp_i32(v) for v in
        (t_total, t_elapsed, sz_total, sz_sent, t_remain)))
    # 與你原本格式一致：NOP、MSS 之後放 kind=253
    return [("NOP", None), ("MSS", 1460), (253, payload)]

def main():
    ap = argparse.ArgumentParser(description="TCP sender (fixed 100MB @ 5 Mb/s) with kind=253 progress")
    ap.add_argument("dst", help="destination host name or IP（例如 h9 或 10.0.0.9）")
    ap.add_argument("--dport", type=int, default=9090)
    args = ap.parse_args()

    topo  = load_topo()
    iface = pick_iface()
    src_ip = get_if_addr(iface)

    # 解析目的 IP / DMAC
    if args.dst in topo.get("hosts", {}):
        dst_ip = topo["hosts"][args.dst]["ip"].split("/")[0]
    else:
        dst_ip = args.dst
    dmac = topo.get("default_dmac", "08:00:00:00:00:FE")

    # 固定總量與速率（Bytes/s；Mb/s → /8）
    total_bytes = int(TOTAL_BYTES)
    rate_Bps    = RATE_MBPS * 1_000_000.0 / 8.0

    # 預先估 options 長度、計算 payload 上限
    trial_opts  = build_opt(-1, -1, total_bytes, 0, -1)
    opt_len     = opt_len_bytes(trial_opts)
    max_payload = max(1, ETH_MTU - IP_HDR - (TCP_BASE + opt_len))
    payload_bytes = max_payload                # 每包盡量貼近 MTU
    per_inc       = payload_bytes              # 每包邏輯進度

    rounds = int(math.ceil(total_bytes / float(per_inc)))
    base = Ether(src=get_if_hwaddr(iface), dst=dmac) / IP(src=src_ip, dst=dst_ip, ttl=64)

    print(f"[send] {src_ip} -> {dst_ip}:{args.dport}  total={total_bytes}B  payload={payload_bytes}B  "
          f"opts={opt_len}B  rounds≈{rounds}  FIXED-RATE≈{RATE_MBPS:.2f} Mb/s")

    # 關 GC 降抖動
    was_gc = gc.isenabled()
    if was_gc: gc.disable()

    # —— 閉迴路節流 ——：以「理想已送位元組 = rate * elapsed」做回授，任何落後都會在下輪補上
    SLICE_MIN_SLEEP = 0.003  # 無需補送時的小睡，避免忙等

    start = time.perf_counter()
    sent_size = 0
    idx = 0

    try:
        while sent_size < total_bytes:
            now = time.perf_counter()
            target_bytes = min(total_bytes, int(rate_Bps * (now - start)))
            need = target_bytes - sent_size

            batch = []
            batch_bytes = 0

            # 把「落後的 bytes」補上；限制單批大小避免尖峰
            while need > 0 and sent_size < total_bytes and len(batch) < 4096 and batch_bytes < 64*1024:
                elapsed_ms = int((time.perf_counter() - start) * 1000)
                ratio      = (sent_size / float(total_bytes)) if total_bytes > 0 else 0.0
                est_total  = int(elapsed_ms / ratio) if ratio > 0 else -1
                remain_ms  = max(0, est_total - elapsed_ms) if est_total > 0 else -1

                opts = build_opt(-1, elapsed_ms, total_bytes, sent_size, remain_ms)
                tcp  = TCP(sport=1234, dport=args.dport, flags="PA", window=65535, options=opts)
                chunk = min(payload_bytes, total_bytes - sent_size)
                pkt  = base / tcp / Raw(b"X" * chunk)   # 真的帶資料
                batch.append(pkt)

                inc = min(per_inc, total_bytes - sent_size)
                sent_size  += inc
                batch_bytes += inc
                need       -= inc
                idx        += 1

            if batch:
                sendp(batch, iface=iface, verbose=False)

            if need <= 0:
                time.sleep(SLICE_MIN_SLEEP)

        # 補 FIN（讓收端知道已完成）
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        opts = build_opt(-1, elapsed_ms, total_bytes, total_bytes, 0)
        fin1 = base / TCP(sport=1234, dport=args.dport, flags="FA", window=65535, options=opts)
        fin2 = base / TCP(sport=1234, dport=args.dport, flags="FA", window=65535, options=opts)
        sendp([fin1, fin2], iface=iface, verbose=False)

    finally:
        if was_gc: gc.enable()

    dur  = max(1e-9, time.perf_counter() - start)
    mbps = (sent_size * 8.0) / 1e6 / dur
    print(f"[send] sent={sent_size}B in {dur:.3f}s  ≈ {mbps:.2f} Mb/s  (target≈{RATE_MBPS:.2f} Mb/s)")

if __name__ == "__main__":
    main()
