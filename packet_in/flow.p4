// SPDX-License-Identifier: Apache-2.0
/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/* CONSTANTS */
const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_ARP = 0x0806;
const bit<8>  TYPE_TCP  = 6;

const bit<16> ARP_OPER_REPLY     = 2;

#define CPU_PORT 510

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header arp_t {
    bit<16> hrd; // Hardware Type
    bit<16> pro; // Protocol Type
    bit<8> hln; // Hardware Address Length
    bit<8> pln; // Protocol Address Length
    bit<16> op;  // Opcode
    macAddr_t sha; // Sender Hardware Address
    ip4Addr_t spa; // Sender Protocol Address
    macAddr_t tha; // Target Hardware Address
    ip4Addr_t tpa; // Target Protocol Address
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header tcp_option_flow_info_t {
    bit<8>  kind;
    bit<8>  length;
    bit<32> total_time;
    bit<32> elapsed_time;
    bit<32> total_size;
    bit<32> sent_size;
    bit<32> estimated_remaining_time;
}


@controller_header("packet_out")
header packet_out_t {
    bit<16> egress_port;
}

struct metadata {
    /* empty */
}

struct headers {
    packet_out_t packet_out;
    ethernet_t   ethernet;
    arp_t        arp;
    ipv4_t       ipv4;
    tcp_t        tcp;
    tcp_option_flow_info_t  flow_info;
}

/* ===== Registers ===== */
register<bit<32>>(1024) reg_total_time;
register<bit<32>>(1024) reg_elapsed_time;
register<bit<32>>(1024) reg_total_size;
register<bit<32>>(1024) reg_sent_size;
register<bit<32>>(1024) reg_estimated_remaining_time;
register<bit<32>>(1) reg_ptr;

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        transition select(standard_metadata.ingress_port) {
            CPU_PORT: parse_packet_out;
            default:  parse_ethernet;
        }
    }

    state parse_packet_out {
        packet.extract(hdr.packet_out);
        transition parse_ethernet;
    }

    state parse_ethernet { 
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_ARP:  parse_arp;
            TYPE_IPV4: parse_ipv4;
            default:   accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP: parse_tcp;
            default:  accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        bit<4> tcp_header_length = hdr.tcp.dataOffset;
        transition select(tcp_header_length) {
            5:       accept;
            default: parse_tcp_options;
        }
    }

    state parse_tcp_options {
        bit<8> kind = packet.lookahead<bit<8>>();
        transition select(kind) {
            0:    accept;
            1:    parse_nop;
            0xfd: parse_flow_info;
            default: parse_other_option;
        }
    }

    state parse_nop {
        packet.advance(8);
        transition parse_tcp_options;
    }

    state parse_other_option {
        packet.advance(8);
        transition select(packet.lookahead<bit<8>>()) {
            2:  parse_skip_1;  3:  parse_skip_2;  4:  parse_skip_3;
            5:  parse_skip_4;  6:  parse_skip_5;  7:  parse_skip_6;
            8:  parse_skip_7;  9:  parse_skip_8; 10: parse_skip_9;
            11: parse_skip_10;12: parse_skip_11;13: parse_skip_12;
            14: parse_skip_13;15: parse_skip_14;16: parse_skip_15;
            17: parse_skip_16;18: parse_skip_17;19: parse_skip_18;
            20: parse_skip_19;21: parse_skip_20;22: parse_skip_21;
            23: parse_skip_22;24: parse_skip_23;25: parse_skip_24;
            26: parse_skip_25;27: parse_skip_26;28: parse_skip_27;
            29: parse_skip_28;30: parse_skip_29;31: parse_skip_30;
            32: parse_skip_31;33: parse_skip_32;34: parse_skip_33;
            35: parse_skip_34;36: parse_skip_35;37: parse_skip_36;
            38: parse_skip_37;39: parse_skip_38;40: parse_skip_39;
            default: accept;
        }
    }

    // Skip states
    state parse_skip_1  { packet.advance(1*8);  transition parse_tcp_options; }
    state parse_skip_2  { packet.advance(2*8);  transition parse_tcp_options; }
    state parse_skip_3  { packet.advance(3*8);  transition parse_tcp_options; }
    state parse_skip_4  { packet.advance(4*8);  transition parse_tcp_options; }
    state parse_skip_5  { packet.advance(5*8);  transition parse_tcp_options; }
    state parse_skip_6  { packet.advance(6*8);  transition parse_tcp_options; }
    state parse_skip_7  { packet.advance(7*8);  transition parse_tcp_options; }
    state parse_skip_8  { packet.advance(8*8);  transition parse_tcp_options; }
    state parse_skip_9  { packet.advance(9*8);  transition parse_tcp_options; }
    state parse_skip_10 { packet.advance(10*8); transition parse_tcp_options; }
    state parse_skip_11 { packet.advance(11*8); transition parse_tcp_options; }
    state parse_skip_12 { packet.advance(12*8); transition parse_tcp_options; }
    state parse_skip_13 { packet.advance(13*8); transition parse_tcp_options; }
    state parse_skip_14 { packet.advance(14*8); transition parse_tcp_options; }
    state parse_skip_15 { packet.advance(15*8); transition parse_tcp_options; }
    state parse_skip_16 { packet.advance(16*8); transition parse_tcp_options; }
    state parse_skip_17 { packet.advance(17*8); transition parse_tcp_options; }
    state parse_skip_18 { packet.advance(18*8); transition parse_tcp_options; }
    state parse_skip_19 { packet.advance(19*8); transition parse_tcp_options; }
    state parse_skip_20 { packet.advance(20*8); transition parse_tcp_options; }
    state parse_skip_21 { packet.advance(21*8); transition parse_tcp_options; }
    state parse_skip_22 { packet.advance(22*8); transition parse_tcp_options; }
    state parse_skip_23 { packet.advance(23*8); transition parse_tcp_options; }
    state parse_skip_24 { packet.advance(24*8); transition parse_tcp_options; }
    state parse_skip_25 { packet.advance(25*8); transition parse_tcp_options; }
    state parse_skip_26 { packet.advance(26*8); transition parse_tcp_options; }
    state parse_skip_27 { packet.advance(27*8); transition parse_tcp_options; }
    state parse_skip_28 { packet.advance(28*8); transition parse_tcp_options; }
    state parse_skip_29 { packet.advance(29*8); transition parse_tcp_options; }
    state parse_skip_30 { packet.advance(30*8); transition parse_tcp_options; }
    state parse_skip_31 { packet.advance(31*8); transition parse_tcp_options; }
    state parse_skip_32 { packet.advance(32*8); transition parse_tcp_options; }
    state parse_skip_33 { packet.advance(33*8); transition parse_tcp_options; }
    state parse_skip_34 { packet.advance(34*8); transition parse_tcp_options; }
    state parse_skip_35 { packet.advance(35*8); transition parse_tcp_options; }
    state parse_skip_36 { packet.advance(36*8); transition parse_tcp_options; }
    state parse_skip_37 { packet.advance(37*8); transition parse_tcp_options; }
    state parse_skip_38 { packet.advance(38*8); transition parse_tcp_options; }
    state parse_skip_39 { packet.advance(39*8); transition parse_tcp_options; }

    state parse_flow_info {
        packet.extract(hdr.flow_info);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   ************
*************************************************************************/
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    
    
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action send_to_cpu() {
        // Clone to CPU port (Port 510 is BMv2 CPU port)
        standard_metadata.egress_spec =  CPU_PORT; // usually 510
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            send_to_cpu;
        }
        size = 1024;
        default_action = send_to_cpu();
    }

    action arp_forward(macAddr_t addr) {
        standard_metadata.egress_spec = standard_metadata.ingress_port;

        //Ethernet
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = addr;

        // ARP
        hdr.arp.op = ARP_OPER_REPLY;
        ip4Addr_t tmp_spa = hdr.arp.spa;
        hdr.arp.spa = hdr.arp.tpa;
        hdr.arp.tpa = tmp_spa;
        hdr.arp.tha = hdr.arp.sha;
        hdr.arp.sha = addr;
    }

    table arp_exact {
        key = {
            hdr.arp.tpa : exact;
        }
        actions = {
            arp_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        if (hdr.packet_out.isValid()) {
            // Process PacketOut from controller
            standard_metadata.egress_spec = (bit<9>) hdr.packet_out.egress_port;
            hdr.packet_out.setInvalid();
        }
        else if (hdr.arp.isValid()) {
            arp_exact.apply();
        }
        else if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
            if (hdr.flow_info.isValid()) {
                bit<32> ptr;
                reg_ptr.read(ptr,0);
                bit<32> index = ptr % 1024;
                reg_total_time.write(index, hdr.flow_info.total_time);
                reg_elapsed_time.write(index, hdr.flow_info.elapsed_time);
                reg_total_size.write(index, hdr.flow_info.total_size);
                reg_sent_size.write(index, hdr.flow_info.sent_size);
                reg_estimated_remaining_time.write(index, hdr.flow_info.estimated_remaining_time);
                ptr = (ptr + 1) % 1024;
                reg_ptr.write(0,ptr); 
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/
control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.flow_info);
    }
}

/*************************************************************************
***********************  S W I T C H  **********************************
*************************************************************************/
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
