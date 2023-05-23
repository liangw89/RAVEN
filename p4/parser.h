#pragma once


parser TofinoIngressParser(
        packet_in pkt,
        inout ig_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }

    state parse_resubmit {
        // Parse resubmitted packet here.
        pkt.advance(64); 
        transition accept;
    }

    state parse_port_metadata {
        pkt.advance(64);  // tofino 1 port metadata size
        transition accept;
    }

}

parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out ig_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;

#if __p4c_major__ < 9
    Checksum<bit<16>> (HashAlgorithm_t.CSUM16) chksum;
    // Checksum<bit<32>> (HashAlgorithm_t.CSUM32) tag;
#else
    Checksum() chksum;
    Checksum() chksum_dec;
    // Checksum<bit<32>> (HashAlgorithm_t.CSUM32) tag;
#endif

    state start {
        tofino_parser.apply(pkt, ig_md, ig_intr_md);
        transition parse_ethernet;
    }


    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV6 : parse_ipv6;
            ETHERTYPE_IPV4 : parse_ipv4;
            default : accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }
    
    state parse_ipv6 {
        pkt.extract(hdr.ipv6);
        chksum.subtract({hdr.ipv6.src_prex, hdr.ipv6.src_sub, hdr.ipv6.src_addr, 
           hdr.ipv6.dst_prex, hdr.ipv6.dst_sub, hdr.ipv6.dst_addr});
        chksum_dec.subtract({hdr.ipv6.src_prex, hdr.ipv6.src_sub, hdr.ipv6.src_addr, 
           hdr.ipv6.dst_prex, hdr.ipv6.dst_sub, hdr.ipv6.dst_addr});
       
        transition select(hdr.ipv6.next_hdr) {
            IP_PROTOCOLS_UDP: parse_udp;
            IP_PROTOCOLS_TCP: parse_tcp;
            default: accept;
        }

    }
    
    state parse_udp {

        pkt.extract(hdr.udp);
        chksum.subtract({hdr.udp.checksum, hdr.udp.src_port, hdr.udp.dst_port});
        chksum_dec.subtract({hdr.udp.checksum, hdr.udp.src_port, hdr.udp.dst_port});

        ig_md.chksum_udp_dec = chksum_dec.get();
        
        transition select(hdr.udp.src_port, hdr.udp.dst_port) {
            (_, 0x1151): parse_quic_form; //4433, QUIC
            (_, 0x35): set_enc; //53, dns
            (_, 0xe608): set_enc; //58888, WireGuard
            (0x35, _): set_dec;
            (0xe608, _): set_dec;
            (0x1151, _): set_dec;
            default: accept;
        }

    }

    state parse_tcp {

        pkt.extract(hdr.tcp);
        chksum.subtract({hdr.tcp.checksum, hdr.tcp.src_port, hdr.tcp.dst_port});
        ig_md.chksum_tcp = chksum.get();

        transition select(hdr.tcp.src_port, hdr.tcp.dst_port) {
            (_, 0x1bb): set_enc;
            (0x1bb, _): set_dec;
            default: accept;
        }

    }
    
    state parse_quic_form {
        pkt.extract(hdr.quic_form);
        transition select(hdr.quic_form.header_form) {
            1: parse_quic_long;
            0: parse_quic_short;
            default: accept;
        }
    }


    state parse_quic_short {
        pkt.extract(hdr.quic_short);
        ig_md.conn_id = hdr.quic_short.conn_id;
        chksum.subtract({ig_md.conn_id});
        ig_md.chksum_udp = chksum.get();
        transition set_enc;
    }

    state parse_quic_long {

        pkt.extract(hdr.quic_long);
        ig_md.conn_id = hdr.quic_long.conn_id;
        chksum.subtract({ig_md.conn_id});
        ig_md.chksum_udp = chksum.get();
        transition set_enc;

    }

    state set_enc {
        ig_md.is_enc = true;
        ig_md.is_dec = false;
        ig_md.mask = 0b0111;
        transition accept;
    }

    state set_dec {
        ig_md.is_enc = false;
        ig_md.is_dec = true;
        ig_md.mask = 0b0111;
        transition accept;
    }



}



// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {
    
#if __p4c_major__ < 9    
    Checksum<bit<16>> (HashAlgorithm_t.CSUM16) chksum_udp;
    Checksum<bit<16>> (HashAlgorithm_t.CSUM16) chksum_udp_dec;
    Checksum<bit<16>> (HashAlgorithm_t.CSUM16) chksum_tcp;
#else
    Checksum() chksum_udp;
    Checksum() chksum_udp_dec;
    Checksum() chksum_tcp;
#endif

    apply {

        if (hdr.udp.isValid()) {
            if (ig_md.is_enc) {
                hdr.udp.checksum = chksum_udp.update({
                    hdr.ipv6.src_prex,
                    hdr.ipv6.src_sub,
                    hdr.ipv6.src_addr,
                    hdr.udp.src_port,
                    hdr.ipv6.dst_prex,
                    hdr.ipv6.dst_sub,
                    hdr.ipv6.dst_addr,
                    hdr.udp.dst_port,
                    ig_md.chksum_udp,
                    ig_md.conn_id
                });
            }

            if (ig_md.is_dec) {
                hdr.udp.checksum = chksum_udp_dec.update({
                    hdr.ipv6.src_prex,
                    hdr.ipv6.src_sub,
                    hdr.ipv6.src_addr,
                    hdr.udp.src_port,
                    hdr.ipv6.dst_prex,
                    hdr.ipv6.dst_sub,
                    hdr.ipv6.dst_addr,
                    hdr.udp.dst_port,
                    ig_md.chksum_udp_dec
                });
            }
        }

        if (hdr.tcp.isValid()) {
            hdr.tcp.checksum = chksum_tcp.update({
                hdr.ipv6.src_prex,
                hdr.ipv6.src_sub,
                hdr.ipv6.src_addr,
                hdr.tcp.src_port,
                hdr.ipv6.dst_prex,
                hdr.ipv6.dst_sub,
                hdr.ipv6.dst_addr,
                hdr.tcp.dst_port,
                ig_md.chksum_tcp
            });
        }


        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.ipv6);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.tcp);

        pkt.emit(hdr.quic_form);
        pkt.emit(hdr.quic_long);
        pkt.emit(hdr.quic_short);
    }

}

// ---------------------------------------------------------------------------
// Egress parser
// ---------------------------------------------------------------------------

parser TofinoEgressParser(
        packet_in pkt,
        inout eg_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}


parser SwitchEgressParser(
        packet_in pkt,
        out header_t hdr,
        out eg_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {
        
    TofinoEgressParser() tofino_parser;

#if __p4c_major__ < 9
    Checksum<bit<16>> (HashAlgorithm_t.CSUM16) chksum;
    // Checksum<bit<32>> (HashAlgorithm_t.CSUM32) tag;
#else
    Checksum() chksum;
    // Checksum<bit<32>> (HashAlgorithm_t.CSUM32) tag;
#endif

    state start {
        tofino_parser.apply(pkt, eg_md, eg_intr_md);
        transition parse_ethernet;
    }


    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV6 : parse_ipv6;
            ETHERTYPE_IPV4 : parse_ipv4;
            default : accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }
    
    state parse_ipv6 {
        pkt.extract(hdr.ipv6);
        chksum.subtract({hdr.ipv6.src_prex, hdr.ipv6.src_sub, hdr.ipv6.src_addr, 
            hdr.ipv6.dst_prex, hdr.ipv6.dst_sub, hdr.ipv6.dst_addr});

        transition select(hdr.ipv6.next_hdr) {
            IP_PROTOCOLS_UDP: parse_udp;
            IP_PROTOCOLS_TCP: parse_tcp;
            default: accept;
        }

        
    }
    
    state parse_udp {

        pkt.extract(hdr.udp);
        chksum.subtract({hdr.udp.checksum, hdr.udp.src_port, hdr.udp.dst_port});
        eg_md.chksum_udp = chksum.get();

        transition select(hdr.udp.src_port, hdr.udp.dst_port) {
            (_, 0x35): set_enc; //53, dns
            (_, 0xe608): set_enc; //58888, WireGuard
            (_, 0x1151): set_enc; //4433, QUIC
            (0x35, _): set_dec;
            (0xe608, _): set_dec;
            (0x1151, _): set_dec;
            default: accept;
        }

    }

    state parse_tcp {

        pkt.extract(hdr.tcp);
        chksum.subtract({hdr.tcp.checksum, hdr.tcp.src_port, hdr.tcp.dst_port});
        eg_md.chksum_tcp = chksum.get();

        transition select(hdr.tcp.src_port, hdr.tcp.dst_port) {
            (_, 0x1bb): set_enc;
            (0x1bb, _): set_dec;
            default: accept;
        }

    }
   
    state set_enc {
        eg_md.is_enc = true;
        eg_md.is_dec = false;
        eg_md.mask = 0b0111;
        transition accept;
    }

    state set_dec {
        eg_md.is_enc = false;
        eg_md.is_dec = true;
        eg_md.mask = 0b0111;
        transition accept;
    }
}

// ---------------------------------------------------------------------------
// Egress Deparser
// ---------------------------------------------------------------------------
control SwitchEgressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in eg_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {

#if __p4c_major__ < 9    
    Checksum<bit<16>> (HashAlgorithm_t.CSUM16) chksum_udp;
    Checksum<bit<16>> (HashAlgorithm_t.CSUM16) chksum_tcp;
#else
    Checksum() chksum_udp;
    Checksum() chksum_tcp;
#endif

    apply {

        if (hdr.udp.isValid()) {
            hdr.udp.checksum = chksum_udp.update({
                hdr.ipv6.src_prex,
                hdr.ipv6.src_sub,
                hdr.ipv6.src_addr,
                hdr.udp.src_port,
                hdr.ipv6.dst_prex,
                hdr.ipv6.dst_sub,
                hdr.ipv6.dst_addr,
                hdr.udp.dst_port,
                eg_md.chksum_udp
            });
        }

        if (hdr.tcp.isValid()) {
            hdr.tcp.checksum = chksum_tcp.update({
                hdr.ipv6.src_prex,
                hdr.ipv6.src_sub,
                hdr.ipv6.src_addr,
                hdr.tcp.src_port,
                hdr.ipv6.dst_prex,
                hdr.ipv6.dst_sub,
                hdr.ipv6.dst_addr,
                hdr.tcp.dst_port,
                eg_md.chksum_tcp
            });
        }


        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.ipv6);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.tcp);

    }
}
