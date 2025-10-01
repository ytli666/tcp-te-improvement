#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import argparse, json, os, re, sys, grpc, ast
from collections import deque

# Import P4Runtime lib from parent utils dir
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '../../utils/'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.switch import ShutdownAllSwitchConnections

# ---------- Topology & graph helpers ----------

def load_topo(path):
    with open(path) as f:
        return json.load(f)

def parse_endpoint(ep: str):
    """
    "s1-p2" -> ("s1", 2)
    "h1" / "s1" -> ("h1", None) / ("s1", None)
    """
    if '-p' in ep:
        n, p = ep.split('-p', 1)
        return n, int(p)
    return ep, None

def build_port_map(topo):
    """
    Build neighbor->port map:
      port_map[node][neighbor] = port_no
    Priority:
      1) topo["ports"]
      2) topo["links"]
         - "hX" <-> "sY-pZ"    => port_map["sY"]["hX"] = Z
         - "sA-pU" <-> "sB-pV" => both directions
         - old format w/o "-p" => assign ports by appearance
    """
    port_map = {}
    if "ports" in topo:
        for node, nbrs in topo["ports"].items():
            port_map.setdefault(node, {})
            for nb, p in nbrs.items():
                port_map[node][nb] = int(p)

    for a, b in topo["links"]:
        na, pa = parse_endpoint(a)
        nb, pb = parse_endpoint(b)
        if pa is None and pb is not None:
            port_map.setdefault(nb, {})
            port_map[nb].setdefault(na, pb)
        elif pb is None and pa is not None:
            port_map.setdefault(na, {})
            port_map[na].setdefault(nb, pa)
        elif pa is not None and pb is not None:
            port_map.setdefault(na, {})
            port_map.setdefault(nb, {})
            port_map[na].setdefault(nb, pa)
            port_map[nb].setdefault(na, pb)
        else:
            for x, y in ((na, nb), (nb, na)):
                port_map.setdefault(x, {})
                if y not in port_map[x]:
                    port_map[x][y] = len(port_map[x]) + 1
    return port_map

def infer_all_switches(topo):
    """
    Infer switches from:
      - topo["switches"] keys/list
      - topo["device_ids"] keys
      - endpoints in topo["links"]
    """
    sws = set()
    sws.update(list(topo.get("switches", {}).keys()) if isinstance(topo.get("switches"), dict)
               else topo.get("switches", []))
    if "device_ids" in topo:
        for k in topo["device_ids"].keys():
            if k.startswith("s"):
                sws.add(k)
    for a, b in topo["links"]:
        na, _ = parse_endpoint(a); nb, _ = parse_endpoint(b)
        for n in (na, nb):
            if n.startswith("s"):
                sws.add(n)
    return sorted(sws)

def bfs_path(start, goal, links):
    """
    BFS over links graph (strip "-pX" to get node names).
    """
    G = {}
    for a, b in links:
        na, _ = parse_endpoint(a)
        nb, _ = parse_endpoint(b)
        G.setdefault(na, []).append(nb)
        G.setdefault(nb, []).append(na)
    q = deque([(start, [start])]); seen = set()
    while q:
        x, p = q.popleft()
        if x == goal: return p
        if x in seen: continue
        seen.add(x)
        for y in G.get(x, []):
            if y not in seen:
                q.append((y, p + [y]))
    return None

def dijkstra_path(start, goal, links, used_edges=None):

    used_edges = used_edges or set()
    G = {}
    for a, b in links:
        na, _ = parse_endpoint(a)
        nb, _ = parse_endpoint(b)
        G.setdefault(na, set()).add(nb)
        G.setdefault(nb, set()).add(na)

    dist = {n: float("inf") for n in G}
    dist[start] = 0
    prev = {}

    unvisited = set(G.keys())

    while unvisited:
        u = min(unvisited, key=lambda n: dist[n])
        unvisited.remove(u)
        if dist[u] == float("inf"):
            break
        if u == goal:
            break
        for v in G.get(u, []):
            edge = tuple(sorted((u, v)))
            # 如果這條邊已經被用過，給它一個很大的成本
            penalty = 1000 if edge in used_edges else 0
            alt = dist[u] + 1 + penalty
            if alt < dist[v]:
                dist[v] = alt
                prev[v] = u

    if goal not in prev and start != goal:
        return None
    path = [goal]
    while path[-1] != start:
        path.append(prev[path[-1]])
    return list(reversed(path))

def bfs_path_prefer_existing(start, goal, links, used_edges):
    """
    BFS，但每個節點展開鄰居時，會先放入「已存在的邊」(in used_edges)，
    盡量走既有路徑，再考慮新邊。
    """
    # 建圖
    G = {}
    for a, b in links:
        na, _ = parse_endpoint(a)
        nb, _ = parse_endpoint(b)
        G.setdefault(na, set()).add(nb)
        G.setdefault(nb, set()).add(na)

    def ordered_neighbors(u):
        nbrs = list(G.get(u, []))
        # 把已存在的邊（無向，以排序 tuple 表示）放前面
        pref, rest = [], []
        for v in nbrs:
            e = tuple(sorted((u, v)))
            (pref if e in used_edges else rest).append(v)
        return pref + rest

    from collections import deque
    q = deque([(start, [start])]); seen = set()
    while q:
        x, path = q.popleft()
        if x == goal:
            return path
        if x in seen:
            continue
        seen.add(x)
        for y in ordered_neighbors(x):
            if y not in seen:
                q.append((y, path + [y]))
    return None

def switches_on_path(path_nodes, topo):
    host_set = set(topo.get("hosts", {}).keys())
    return [n for n in path_nodes if n not in host_set]

def get_device_id(sw_name, topo):
    if "device_ids" in topo and sw_name in topo["device_ids"]:
        return int(topo["device_ids"][sw_name])
    m = re.search(r"(\d+)$", sw_name)
    if m:
        return max(0, int(m.group(1)) - 1)
    return 0

def get_grpc_addr(sw_name, topo):
    if "grpc_addrs" in topo and sw_name in topo["grpc_addrs"]:
        return topo["grpc_addrs"][sw_name]
    m = re.search(r"(\d+)$", sw_name)
    if m:
        return f"127.0.0.1:{50050 + int(m.group(1))}"
    return "127.0.0.1:50051"

def get_host_ip_mac(host, topo):
    ip = topo["hosts"][host]["ip"].split("/")[0]
    mac = topo["hosts"][host].get("mac")
    return ip, mac

# ---------- P4Runtime helpers ----------

def install_pipeline_on(switch_conn, p4info_helper, bmv2_file_path):
    switch_conn.SetForwardingPipelineConfig(
        p4info=p4info_helper.p4info,
        bmv2_json_file_path=bmv2_file_path
    )

def build_ipv4_forward_entry(p4info_helper, dst_ip, dst_mac, egress_port, prefix_len=32):
    return p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={"hdr.ipv4.dstAddr": (dst_ip, prefix_len)},
        action_name="MyIngress.ipv4_forward",
        action_params={"dstAddr": dst_mac, "port": int(egress_port)}
    )

def build_ipv4_match_entry(p4info_helper, dst_ip, prefix_len=32):
    return p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={"hdr.ipv4.dstAddr": (dst_ip, prefix_len)},
        default_action=False
    )

# ---------- Core programming ----------

def write_or_exists(conn, entry):
    """
    Try to INSERT; if the key already exists on this switch,
    treat it as success and keep going (we don't require MODIFY/DELETE).
    """
    try:
        conn.WriteTableEntry(entry)
        return "insert"
    except grpc.RpcError as e:
        msg = (e.details() or "").lower()
        code = getattr(e.code(), "name", "")
        if "exist" in msg or code in ("ALREADY_EXISTS", "UNKNOWN"):
            return "exists"
        raise

def program_one_direction(conns, p4info_helper, path_nodes, port_map, dst_ip, dst_mac, prefix_len=32):
    """
    Program a unidirectional path hop by hop.
    Compatible with minimal p4runtime_lib (no Modify/Delete helpers).
    """
    for i in range(1, len(path_nodes) - 1):
        sw = path_nodes[i]
        if sw not in conns:  # skip host nodes
            continue

        next_hop = path_nodes[i + 1]
        try:
            out_port = port_map[sw][next_hop]
        except KeyError:
            raise RuntimeError(f"[{sw}] missing port to neighbor {next_hop}; check topology links/ports")

        entry = build_ipv4_forward_entry(p4info_helper, dst_ip, dst_mac, out_port, prefix_len)
        try:
            mode = write_or_exists(conns[sw], entry)
            if mode == "insert":
                print(f"[{sw}] Insert: {dst_ip}/{prefix_len} -> port {int(out_port)}, dmac {dst_mac}")
            else:
                print(f"[{sw}] Exists:  {dst_ip}/{prefix_len} (keep current entry)")
        except grpc.RpcError as e:
            print(f"[{sw}] Write failed: {e.details() or e.code().name} (continue)")
            continue

def program_bidirectional(conns, p4info_helper, port_map, topo, path_nodes):
    if len(path_nodes) < 3:
        raise RuntimeError("Path too short; need at least h_src -> sX -> h_dst")

    src = path_nodes[0]
    dst = path_nodes[-1]
    src_ip, src_mac = get_host_ip_mac(src, topo)
    dst_ip, dst_mac_opt = get_host_ip_mac(dst, topo)
    DEFAULT_DMAC = topo.get("default_dmac", "08:00:00:00:00:FE")
    dst_mac = dst_mac_opt or DEFAULT_DMAC

    # Forward direction: src -> dst
    program_one_direction(conns, p4info_helper, path_nodes, port_map, dst_ip, dst_mac)
    # Reverse direction: dst -> src (needed for ICMP replies)
    rev_path = list(reversed(path_nodes))
    program_one_direction(conns, p4info_helper, rev_path, port_map, src_ip, src_mac)

def program_unidirectional(conns, p4info_helper, port_map, topo, path_nodes):
    """
    單向：只下 src -> dst 的 rule；不寫回頭路。
    """
    if len(path_nodes) < 3:
        raise RuntimeError("Path too short; need at least h_src -> sX -> h_dst")

    src = path_nodes[0]
    dst = path_nodes[-1]
    # 目的端 host 的 IP/MAC（作為 LPM 與 DMAC）
    dst_ip, dst_mac_opt = get_host_ip_mac(dst, topo)
    DEFAULT_DMAC = topo.get("default_dmac", "08:00:00:00:00:FE")
    dst_mac = dst_mac_opt or DEFAULT_DMAC

    # 只安裝「往 dst」的 hop-by-hop
    program_one_direction(conns, p4info_helper, path_nodes, port_map, dst_ip, dst_mac)

# ---------- Controller shell (interactive loop) ----------

class Controller:
    def __init__(self, topo_path, p4info_path, bmv2_json_path):
        self.topo_path = topo_path
        self.topo = load_topo(topo_path)
        self.p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_path)
        self.bmv2_json_path = bmv2_json_path
        self.port_map = build_port_map(self.topo)
        self.conns = {}
        self.used_edges = set()
        self._connect_and_install()

    def _connect_and_install(self):
        sws = infer_all_switches(self.topo)
        if not sws:
            raise RuntimeError("No switches inferred from topology.json (check switches/links/device_ids).")
        print(f"Connecting and installing pipeline on: {', '.join(sws)}")
        for sw in sws:
            addr = get_grpc_addr(sw, self.topo)
            devid = get_device_id(sw, self.topo)
            conn = p4runtime_lib.bmv2.Bmv2SwitchConnection(name=sw, address=addr, device_id=devid)
            conn.MasterArbitrationUpdate()
            install_pipeline_on(conn, self.p4info_helper, self.bmv2_json_path)
            self.conns[sw] = conn
            print(f"[{sw}] pipeline installed @ {addr} (device_id={devid})")

    def reload_topo(self):
        self.topo = load_topo(self.topo_path)
        self.port_map = build_port_map(self.topo)
        print("Topology reloaded and port_map rebuilt.")

    def add_path_src_dst(self, src_host, dst_host, use_dijkstra=False):
        if use_dijkstra:
            path_nodes = dijkstra_path(src_host, dst_host, self.topo["links"], self.used_edges)
        else:
            path_nodes = bfs_path_prefer_existing(src_host, dst_host, self.topo["links"], self.used_edges)
        if not path_nodes:
            print(f"No path from {src_host} to {dst_host}.")
            return
        print(f"Programming ONE-WAY path: {' -> '.join(path_nodes)}")
        # 記錄這些邊為「已使用」，供下次 BFS 優先走
        for i in range(len(path_nodes)-1):
            e = tuple(sorted((path_nodes[i], path_nodes[i+1])))
            self.used_edges.add(e)
        # 單向安裝（只安裝 src->dst）
        program_unidirectional(self.conns, self.p4info_helper, self.port_map, self.topo, path_nodes)

    def add_path_json(self, path_json_str):
        try:
            nodes = json.loads(path_json_str)
        except json.JSONDecodeError:
            nodes = ast.literal_eval(path_json_str)
        if not isinstance(nodes, list) or len(nodes) < 3:
            print("Bad path_json: need a node list of length >= 3.")
            return
        print(f"Programming ONE-WAY path: {' -> '.join(nodes)}")
        # 記錄 used_edges
        for i in range(len(nodes)-1):
            e = tuple(sorted((nodes[i], nodes[i+1])))
            self.used_edges.add(e)
        program_unidirectional(self.conns, self.p4info_helper, self.port_map, self.topo, nodes)

    def show_tables(self, target_sw=None):
        targets = [target_sw] if target_sw else list(self.conns.keys())
        for sw in targets:
            conn = self.conns.get(sw)
            if not conn:
                print(f"[{sw}] not connected"); continue
            print(f"\n----- Table entries on {sw} -----")
            for response in conn.ReadTableEntries():
                for entity in response.entities:
                    entry = entity.table_entry
                    tname = self.p4info_helper.get_tables_name(entry.table_id)
                    print(tname, end=": ")
                    for m in entry.match:
                        fname = self.p4info_helper.get_match_field_name(tname, m.field_id)
                        val = self.p4info_helper.get_match_field_value(m)
                        print(f"{fname} {val}", end=" ")
                    try:
                        action = entry.action.action
                        aname = self.p4info_helper.get_actions_name(action.action_id)
                        print(f"-> {aname}", end=" ")
                        for p in action.params:
                            pname = self.p4info_helper.get_action_param_name(aname, p.param_id)
                            print(f"{pname} {p.value}", end=" ")
                    except Exception:
                        pass
                    print()

    def delete_dst(self, dst_ip, target_sw=None, prefix_len=32):
        """
        Best-effort delete: only works if your p4runtime_lib exposes DeleteTableEntry().
        Otherwise we just warn and skip.
        """
        targets = [target_sw] if target_sw else list(self.conns.keys())
        for sw in targets:
            conn = self.conns[sw]
            if not hasattr(conn, "DeleteTableEntry"):
                print(f"[{sw}] Delete not supported by this p4runtime_lib (skipped).")
                continue
            entry = build_ipv4_match_entry(self.p4info_helper, dst_ip, prefix_len)
            try:
                conn.DeleteTableEntry(entry)
                print(f"[{sw}] deleted {dst_ip}/{prefix_len}")
            except Exception as e:
                print(f"[{sw}] delete {dst_ip}/{prefix_len} failed: {e}")

    def clear_all(self, target_sw=None):
        """
        Best-effort clear: only works if DeleteTableEntry() exists.
        """
        targets = [target_sw] if target_sw else list(self.conns.keys())
        for sw in targets:
            conn = self.conns[sw]
            print(f"[{sw}] clearing MyIngress.ipv4_lpm ...")
            if not hasattr(conn, "DeleteTableEntry"):
                print(f"[{sw}] Delete not supported by this p4runtime_lib (skipped).")
                continue
            to_delete = []
            for response in conn.ReadTableEntries():
                for entity in response.entities:
                    entry = entity.table_entry
                    tname = self.p4info_helper.get_tables_name(entry.table_id)
                    if tname != "MyIngress.ipv4_lpm":
                        continue
                    dst_val = None; plen = None
                    for m in entry.match:
                        fname = self.p4info_helper.get_match_field_name(tname, m.field_id)
                        if fname == "hdr.ipv4.dstAddr":
                            dst_val, plen = self.p4info_helper.get_match_field_value(m)
                    if dst_val is not None:
                        to_delete.append((dst_val, plen))
            for dst, plen in to_delete:
                ent = build_ipv4_match_entry(self.p4info_helper, dst, plen)
                try:
                    conn.DeleteTableEntry(ent)
                except Exception as e:
                    print(f"[{sw}] delete {dst}/{plen} failed: {e}")
            print(f"[{sw}] clear done (best-effort).")

    def loop(self):
        banner = (
            "\n=== P4 Path Controller ===\n"
            "Commands:\n"
            "  h1 h9                      # ONE-WAY BFS path (src dst), prefers existing edges\n"
            "  dij h1 h9                  # ONE-WAY Dijkstra (penalizes used edges)\n"
            "  path [\"h1\",\"s3\",\"s5\",\"h9\"]   # Program given node list (JSON or Python list), ONE-WAY\n"
            "  show [s1]                  # Show all tables or a single switch\n"
            "  del 10.0.0.9 [/32] [s1]    # Delete prefix (best-effort; may be unsupported)\n"
            "  clear [s1]                 # Clear ipv4_lpm (best-effort)\n"
            "  reload topo                # Reload topology.json\n"
            "  help                       # Show this help\n"
            "  exit/quit                  # Close and exit\n"
        )
        print(banner)
        while True:
            try:
                raw = input(">> ").strip()
                if not raw:
                    continue
                if raw in ("exit", "quit"):
                    break
                if raw == "help":
                    print(banner); continue
                if raw.startswith("show"):
                    parts = raw.split()
                    self.show_tables(parts[1] if len(parts) > 1 else None)
                    continue
                if raw.startswith("reload topo"):
                    self.reload_topo(); continue
                if raw.startswith("clear"):
                    parts = raw.split()
                    self.clear_all(parts[1] if len(parts) > 1 else None)
                    continue
                if raw.startswith("del"):
                    parts = raw.split()
                    if len(parts) < 2:
                        print("Usage: del <dst_ip> [/plen] [switch]"); continue
                    dst_ip = parts[1]
                    plen = 32
                    target = None
                    if len(parts) >= 3:
                        if parts[2].startswith("/"):
                            plen = int(parts[2][1:])
                            if len(parts) >= 4:
                                target = parts[3]
                        else:
                            target = parts[2]
                    self.delete_dst(dst_ip, target, plen); continue
                if raw.startswith("path "):
                    arg = raw[len("path "):].strip()
                    self.add_path_json(arg); continue
                sp = raw.split()
                if len(sp) == 2:
                    self.add_path_src_dst(sp[0], sp[1]); continue
                if raw.startswith("dij "):
                    parts = raw.split()
                    if len(parts) == 3:
                        self.add_path_src_dst(parts[1], parts[2], use_dijkstra=True)
                        continue
                print("Unrecognized command. Type 'help' for usage.")
            except KeyboardInterrupt:
                break
            except grpc.RpcError as e:
                print("gRPC Error:", e.details()); print(f"({e.code().name})")
            except Exception as e:
                print("Error:", e)

    def close(self):
        ShutdownAllSwitchConnections()

# ---------- main ----------

def main():
    ap = argparse.ArgumentParser(description='(Loop) Path-aware P4Runtime Controller (supports "sX-pY" links)')
    ap.add_argument('--topo', type=str, default='topology.json', help='Path to topology.json')
    ap.add_argument('--p4info', type=str, default='./build/flow.p4.p4info.txt', help='Path to p4info text')
    ap.add_argument('--bmv2-json', type=str, default='./build/flow.json', help='Path to BMv2 JSON')
    args = ap.parse_args()

    for f, msg in [(args.p4info, "p4info"), (args.bmv2_json, "BMv2 JSON"), (args.topo, "topology")]:
        if not os.path.exists(f):
            ap.print_help(); print(f"\n{msg} file not found: {f}"); ap.exit(1)

    ctl = Controller(args.topo, args.p4info, args.bmv2_json)
    try:
        ctl.loop()
    finally:
        ctl.close()

if __name__ == '__main__':
    main()
