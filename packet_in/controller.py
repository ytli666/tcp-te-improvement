#!/usr/bin/env python3
import argparse
import os
import sys
import asyncio
import functools
import traceback
import time
import json
from scapy.all import Ether, IP
import networkx as nx
import grpc

# Import P4Runtime lib from parent utils dir
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))

import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.switch import ShutdownAllSwitchConnections

# Global structures
link_ports = {}       # (sw, neighbor) -> port (int)
graph = nx.Graph()
host_to_switch = {}   # "h1" -> "s13"
ip_to_host = {} # "10.0.0.1" -> "h1"
ip_to_mac = {} # "10.0.0.1" -> "08:00:00:00:00:01"
p4info_helper = None

# dictionary of connected switch objects
SWITCHES = {}

# define to_thread if missing (py3.8 fallback)
if not hasattr(asyncio, "to_thread"):
    async def to_thread(func, /, *args, **kwargs):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, functools.partial(func, *args, **kwargs))
    asyncio.to_thread = to_thread


def load_topology(topo_file):
    """
    Parse topology.json (dict-style hosts/switches).
    Build graph, link_ports, and host_to_switch.
    """
    global graph, link_ports, host_to_switch, ip_to_host, ip_to_mac
    graph = nx.Graph()
    link_ports = {}
    host_to_switch = {}
    ip_to_host = {}
    ip_to_mac = {}

    with open(topo_file, 'r') as f:
        topo = json.load(f)

    # hosts
    hosts = topo.get("hosts", {})
    for hname, hdata in hosts.items():
        graph.add_node(hname, type="host", ip=hdata.get("ip"), mac=hdata.get("mac"))
        temp = hdata.get("ip")
        ip_to_host[temp[0:temp.index("/")]] = hname
        ip_to_mac[temp[0:temp.index("/")]] = hdata.get("mac")

    # switches
    switches = topo.get("switches", {})
    for sname, sdata in switches.items():
        graph.add_node(sname, type="switch", cpu_port=int(sdata.get("cpu_port", 510)))

    def parse_switchport(label):
        if "-p" in label:
            s, p = label.split("-p")
            return s, int(p)
        return label, None

    for raw in topo.get("links", []):
        n1, n2 = raw[0], raw[1]
        n1_name, n1_port = parse_switchport(n1)
        n2_name, n2_port = parse_switchport(n2)

        graph.add_edge(n1_name, n2_name, weight=1)

        if n1_port is not None:
            link_ports[(n1_name, n2_name)] = n1_port
        if n2_port is not None:
            link_ports[(n2_name, n1_name)] = n2_port

        if n1_name.startswith("h") and n2_name.startswith("s"):
            host_to_switch[n1_name] = n2_name
        if n2_name.startswith("h") and n1_name.startswith("s"):
            host_to_switch[n2_name] = n1_name

    print("[Topo] loaded:")
    print("  hosts:", list(hosts.keys()))
    print("  switches:", list(switches.keys()))
    print("  host->switch:", host_to_switch)
    print("  sample link_ports:", list(link_ports.items())[:10])
    print("  ip -> host: ", ip_to_host)


def install_arp_rules():
    """
    Install ARP rules
    """
    for host, sw in host_to_switch.items():
        sw_conn = SWITCHES.get(sw)
        if sw_conn is None:
            print(f"[WARN] No switch connection for {sw}")
            continue

        ip = graph.nodes[host]["ip"].split("/")[0]
        mac = graph.nodes[host]["mac"]

        try:
            table_entry = p4info_helper.buildTableEntry(
                table_name="MyIngress.arp_exact",
                match_fields={"hdr.arp.tpa": ip},
                action_name="MyIngress.arp_forward",
                action_params={"addr": mac}
            )
            sw_conn.WriteTableEntry(table_entry)
            print(f"[BOOTSTRAP] {sw}: dst={ip} ({host}) -> mac={mac}")
        except Exception as e:
            print(f"[ERROR] Failed to install direct host rule on {sw} for {host}: {e}")
            traceback.print_exc()


def install_direct_host_rules():
    """
    For each host directly connected to a switch,
    pre-install rule on that switch so packets destined
    to that host's IP are sent directly to the correct port + MAC.
    """
    for host, sw in host_to_switch.items():
        sw_conn = SWITCHES.get(sw)
        if sw_conn is None:
            print(f"[WARN] No switch connection for {sw}")
            continue

        ip = graph.nodes[host]["ip"].split("/")[0]
        mac = graph.nodes[host]["mac"]

        out_port = link_ports.get((sw, host))
        if out_port is None:
            print(f"[WARN] No port mapping for ({sw}, {host})")
            continue

        try:
            table_entry = p4info_helper.buildTableEntry(
                table_name="MyIngress.ipv4_direct",
                match_fields={"hdr.ipv4.dstAddr": (ip, 32)},
                action_name="MyIngress.ipv4_forward",
                action_params={"dstAddr": mac, "port": int(out_port)}
            )
            sw_conn.WriteTableEntry(table_entry)
            print(f"[BOOTSTRAP] {sw}: dst={ip} ({host}) -> port {out_port}, mac={mac}")
        except Exception as e:
            print(f"[ERROR] Failed to install direct host rule on {sw} for {host}: {e}")
            traceback.print_exc()


def install_path_on_switches(path, src_ip, dst_ip):
    """
    Install forwarding rules along `path` (a list of node names), using link_ports.
    Match on hdr.ipv4.dstAddr /32.
    """
    global p4info_helper
    if not p4info_helper:
        print("[ERROR] p4info_helper not initialized")
        return

    for i in range(len(path) - 1):
        node = path[i]
        next_node = path[i + 1]
        if not node.startswith("s"):
            continue
        sw_conn = SWITCHES.get(node)
        if sw_conn is None:
            print(f"[WARN] No switch connection for {node}")
            continue
        out_port = link_ports.get((node, next_node))
        if out_port is None:
            print(f"[WARN] No port mapping for {(node, next_node)}")
            continue

        try:
            table_entry = p4info_helper.buildTableEntry(
                table_name="MyIngress.ipv4_lpm",
                match_fields={
                    "hdr.ipv4.srcAddr": src_ip,
                    "hdr.ipv4.dstAddr": (dst_ip, 32)
                },
                action_name="MyIngress.ipv4_forward",
                action_params={"dstAddr": ip_to_mac[dst_ip], "port": int(out_port)}
            )
            sw_conn.WriteTableEntry(table_entry)
            print(f"[INFO] Installed rule on {node}: dst={dst_ip} -> port {out_port}")
        except Exception as e:
            print(f"[ERROR] Failed to install rule on {node}: {e}")
            traceback.print_exc()


def send_packet_out(sw, payload, out_port):
    md_info = None
    for c in p4info_helper.p4info.controller_packet_metadata:
        if c.preamble.name.endswith("packet_out"):
            for m in c.metadata:
                if m.name == "egress_port":
                    md_info = m
                    break
    if md_info is None:
        print("[ERROR] egress_port metadata not found in p4info")
        return False

    metadata = [
        {"metadata_id": md_info.id, "value": out_port, "bitwidth": md_info.bitwidth}
    ]
    try:
        sw.PacketOut(payload, metadata)
        print(f"[INFO] PacketOut sent to {sw.name} out_port={out_port}")
        return True
    except Exception as e:
        print(f"[ERROR] PacketOut failed: {e}")
        return False


async def packetInHandler(notif_queue, sw):
    """
    Poll sw.PacketIn() in a thread and push to asyncio queue.
    """
    while True:
        try:
            packet_in = await asyncio.to_thread(sw.PacketIn)
            if packet_in is None:
                await asyncio.sleep(0.05)
                continue
            message = {"type": "packet-in", "sw": sw, "packet-in": packet_in}
            await notif_queue.put(message)
        except grpc.RpcError as e:
            print(f"[gRPC Error in packetInHandler for {sw.name}]: {e}")
            await asyncio.sleep(1)
        except Exception as e:
            print(f"[Unexpected Error in packetInHandler for {sw.name}]: {e}")
            traceback.print_exc()
            await asyncio.sleep(1)


async def processNotif(notif_queue):
    """
    Consume notifications and handle PacketIn messages by
    parsing payload, computing shortest path, installing rules,
    and sending a PacketOut for the original packet (best-effort).
    """
    while True:
        notif = await notif_queue.get()
        try:
            if notif["type"] == "packet-in":
                pktin = notif["packet-in"]
                payload = pktin.payload
                if payload is None:
                    notif_queue.task_done()
                    continue
                ether = Ether(payload)
                if IP not in ether:
                    notif_queue.task_done()
                    continue
                src_ip = ether[IP].src
                dst_ip = ether[IP].dst

                src_host = ip_to_host[src_ip]
                dst_host = ip_to_host[dst_ip]

                print(f"[PacketIn] from switch={notif['sw'].name} src={src_ip} dst={dst_ip} -> src_host={src_host} dst_host={dst_host}")

                if src_host is None or dst_host is None:
                    print("[WARN] cannot infer host names from IPs")
                    notif_queue.task_done()
                    continue
                if src_host not in host_to_switch or dst_host not in host_to_switch:
                    print(f"[WARN] host_to_switch missing mapping for {src_host} or {dst_host}")
                    notif_queue.task_done()
                    continue

                src_sw = host_to_switch[src_host]
                dst_sw = host_to_switch[dst_host]
                print(f"src: {src_host}; dst: {dst_host}")

                # compute path between switches
                try:
                    path = nx.shortest_path(graph, src_sw, dst_sw, weight="weight")
                    print(f"[INFO] Computed path: {path}")
                    # install rules
                    install_path_on_switches(path, src_ip, dst_ip)

                    rev_path = list(reversed(path))
                    print(f"[INFO] Computed reverse path: {rev_path}")
                    install_path_on_switches(rev_path, dst_ip, src_ip)

                    
                except nx.NetworkXNoPath:
                    print(f"[WARN] No path between {src_sw} and {dst_sw}")

        except Exception as e:
            print(f"[Error processing notification]: {e}")
            traceback.print_exc()
        finally:
            notif_queue.task_done()


async def main_async(p4info_file_path, bmv2_file_path):
    global p4info_helper, SWITCHES

    # init p4info helper
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    from google.protobuf.text_format import MessageToString

    print("\n=== Controller Packet Metadata ===")
    for c in p4info_helper.p4info.controller_packet_metadata:
        print(f"[Metadata Block] {c.preamble.name}")
        for md in c.metadata:
            print(f"  - field: {md.name}, id={md.id}, bitwidth={md.bitwidth}")
    print("==================================\n")


    # load topology
    load_topology("topology.json")

    # Create connections for every switch node in the topology graph that begins with 's'
    switch_nodes = sorted([n for n in graph.nodes() if n.startswith("s")])

    # build switch connections
    for sw_name in switch_nodes:
        device_id = int(sw_name[1:]) - 1
        grpc_port = 50051 + device_id
        addr = f"127.0.0.1:{grpc_port}"
        sw = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name=sw_name,
            address=addr,
            device_id=device_id,
            proto_dump_file=f"logs/{sw_name}-p4runtime-requests.txt"
        )
        print(f"sw name: {sw_name}; address: {addr}; device id: {device_id}; grpc port: {grpc_port}")
        print(f"[INFO] Connected to {sw_name} @ {addr}")
        SWITCHES[sw_name] = sw

    # master arbitration + install pipeline
    for sw in SWITCHES.values():
        sw.MasterArbitrationUpdate()

    for sw in SWITCHES.values():
        sw.SetForwardingPipelineConfig(
            p4info=p4info_helper.p4info,
            bmv2_json_file_path=bmv2_file_path
        )
        print(f"[INFO] Installed pipeline on {sw.name}")
    
    install_arp_rules()
    install_direct_host_rules()

    # create notification queue and spawn packetInHandler tasks
    notif_queue = asyncio.Queue()

    tasks = []
    for sw in SWITCHES.values():
        tasks.append(asyncio.create_task(packetInHandler(notif_queue, sw)))

    tasks.append(asyncio.create_task(processNotif(notif_queue)))

    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        pass
    except KeyboardInterrupt:
        print("Interrupted, shutting down...")
    finally:
        ShutdownAllSwitchConnections()


def main(p4info, bmv2_json):
    try:
        asyncio.run(main_async(p4info, bmv2_json))
    except KeyboardInterrupt:
        print("Stopping controller.")
        ShutdownAllSwitchConnections()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/flow.p4.p4info.txtpb')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/flow.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)
    main(args.p4info, args.bmv2_json)
