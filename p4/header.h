#pragma once

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<128> ipv6_addr_t;
typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_IPV6 = 16w0x86dd;
const ether_type_t ETHERTYPE_VLAN = 16w0x0810;

const bit<4> VERSION_IPV4 = 0x4;
const bit<4> VERSION_IPV6 = 0x6;

const bit<4> PAD_RANDOM = 0x0;
const bit<4> PAD_CONST = 0x1;
const bit<4> PAD_QUICID = 0x2;


typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_ICMP = 1;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;
//const bit<64> NET_PREFIX = 64w0xf;
//const bit<32> SUB_NET = 32w0x1111fff0;
//const bit<64> NET_PREFIX = 64w0x262000c400000ff1;
//const bit<64> NET_PREFIX = 64w0x262000c4000000fe;
const bit<64> PUB_NET_PREFIX = 64w0x262000c4000000fc;

const bit<64> NET_PREFIX = 64w0x262000c4000000fe;
// const bit<32> SUB_NET = 32w0xbe97e1ff;
const bit<32> SUB_NET = 32w0x0e42a1ff;

header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<16> flags_frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header ipv6_h {
    bit<4> version;
    bit<8> traffic_class;
    bit<20> flow_label;
    bit<16> payload_length;
    bit<8> next_hdr;
    bit<8> hop_limit;
    bit<64> src_prex;
    bit<32> src_sub; // for random padding
    bit<32> src_addr; 
    bit<64> dst_prex;
    bit<32> dst_sub;
    bit<32> dst_addr;
    
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> udp_total_len;
    bit<16> checksum;
}

header quic_form_h {
    bit<1> header_form; // 0 is short, 1 is long 
    bit<7> reserved_bits; // ignore
}   

header quic_long_t {
    bit<32> version;
    bit<8>  id_len;
    bit<32> conn_id; // only needs the first N bits 
}

header quic_short_t {
    bit<32> conn_id; // only needs the first N bits 
}

@pa_no_overlay("ingress", "ipv6.src_addr")
@pa_no_overlay("ingress", "ipv6.src_sub")
@pa_no_overlay("ingress", "ipv6.dst_addr")
@pa_no_overlay("ingress", "ipv6.dst_sub")
@pa_no_overlay("ingress", "udp.src_port")
@pa_no_overlay("ingress", "udp.dst_port")
@pa_no_overlay("ingress", "tcp.src_port")
@pa_no_overlay("ingress", "tcp.dst_port")
@pa_no_overlay("ingress", "udp.checksum")

struct header_t {
    ethernet_h ethernet;
    ipv6_h ipv6;
    ipv4_h ipv4;
    tcp_h tcp;
    udp_h udp;
    quic_form_h quic_form;
    quic_long_t quic_long;
    quic_short_t quic_short;
}



@pa_container_size("ingress", "ig_md.new_ip", 32)
@pa_no_overlay("ingress", "ig_md.chksum_udp")
// @pa_container_size("ingress", "ig_md.conn_id", 32)
@pa_no_overlay("ingress", "ig_md.c1")
@pa_no_overlay("ingress", "ig_md.c2")
@pa_no_overlay("ingress", "ig_md.c3")
@pa_no_overlay("ingress", "ig_md.c4")
@pa_no_overlay("ingress", "ig_md.r1")
@pa_no_overlay("ingress", "ig_md.r2")
@pa_no_overlay("ingress", "ig_md.r3")
@pa_no_overlay("ingress", "ig_md.r4")
struct ig_metadata_t {
    bit<64> otp1;
    bit<64> otp2;
    bit<2> cur_ver; 

    bit<8> c1; 
    bit<8> c2;
    bit<8> c3;
    bit<8> c4;

    bit<8> r1;
    bit<8> r2;
    bit<8> r3;
    bit<8> r4;

    bit<32> new_ip;
    bit<32> new_ip1;

    bit<32> new_rnd;
    bit<32> new_rnd1;

    bit<4> slice1;
    bit<4> slice2;
    
    bit<16> chksum_udp;
    bit<16> chksum_udp_dec;
    bit<16> chksum_tcp;
    // bit<32> chksum_udp1;

    bit<32> conn_id;
    bool is_enc;
    bool is_set_sub;
    bool is_dec;
    bit<1> direction;
    bit<4> mask;
}

struct eg_metadata_t {
    bit<32> addr;
    bit<16> chksum_udp;
    bit<16> chksum_tcp;
    bit<32> tag;
    bool is_enc;
    bool is_set_sub;
    bool is_dec;
    bit<4> mask;
    bit<16> tag_hi;
    
}
