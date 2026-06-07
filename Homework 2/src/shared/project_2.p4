/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_MPLS = 0x8847;
const bit<16> TYPE_NSH  = 0x894F;

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
    bit<3>  res;
    bit<9>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header mpls_t {
    bit<20> label;
    bit<3>  tc;
    bit<1>  bos;
    bit<8>  ttl;
}

header nsh_t {
    bit<2>  ver;
    bit<1>  oam;
    bit<1>  u1;
    bit<4>  ttl;
    bit<8>  length;
    bit<4>  u2;
    bit<4>  md_type;
    bit<8>  next_proto;
    bit<24> spi;
    bit<8>  si;
}

struct metadata_t {
    
}

struct headers {
    ethernet_t outer_ethernet;
    mpls_t     mpls;
    nsh_t      nsh;
    ethernet_t inner_ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser( packet_in packet, out headers hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata ) {
    state start {
        transition parse_outer_ethernet;
    }

    state parse_outer_ethernet {
        packet.extract( hdr.outer_ethernet );
        transition select( hdr.outer_ethernet.etherType ) {
            TYPE_MPLS: parse_mpls;
            TYPE_NSH:  parse_nsh;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_mpls {
        packet.extract( hdr.mpls );
        transition parse_nsh;
    }

    state parse_nsh {
        packet.extract( hdr.nsh );
        transition parse_inner_ethernet;
    }

    state parse_inner_ethernet {
        packet.extract( hdr.inner_ethernet );
        transition select( hdr.inner_ethernet.etherType ) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract( hdr.ipv4 );
        transition select( hdr.ipv4.protocol ) {
            6: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract( hdr.tcp );
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum( inout headers hdr, inout metadata_t meta ) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress( inout headers hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata ) {
    action drop() {
        mark_to_drop( standard_metadata );
    }

    // Carrying return traffic via IPv4 
    action ipv4_forward( macAddr_t dstAddr, egressSpec_t port ) {
        standard_metadata.egress_spec = port;
        hdr.outer_ethernet.srcAddr = hdr.outer_ethernet.dstAddr;
        hdr.outer_ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = { 
            hdr.ipv4.dstAddr: lpm; 
            }
        actions = { 
            ipv4_forward; 
            drop; 
            NoAction; 
        }
        size = 1024;
        default_action = NoAction();
    }

    // Managing SFC classification inside edge nodes ( e.g., A )
    action classify_sfc( bit<24> spi, bit<8> si, bit<20> mpls_label, macAddr_t next_hop_mac, egressSpec_t port ) {
        hdr.inner_ethernet.setValid();
        hdr.nsh.setValid();
        hdr.mpls.setValid();

        // Preserving original ethernet frame as "inner_ethernet"
        hdr.inner_ethernet.dstAddr = hdr.outer_ethernet.dstAddr;
        hdr.inner_ethernet.srcAddr = hdr.outer_ethernet.srcAddr;
        hdr.inner_ethernet.etherType = 0x0800;

        hdr.outer_ethernet.srcAddr = hdr.outer_ethernet.dstAddr;
        hdr.outer_ethernet.dstAddr = next_hop_mac;
        hdr.outer_ethernet.etherType = TYPE_MPLS;

        // Configuring NSH Context ( SPI, SI )
        hdr.nsh.ver = 0;
        hdr.nsh.oam = 0;
        hdr.nsh.u1 = 0;
        hdr.nsh.ttl = 15;
        hdr.nsh.length = 6;
        hdr.nsh.u2 = 0;
        hdr.nsh.md_type = 1;     // MD-Type 1
        hdr.nsh.next_proto = 3;  // Note: "3" denotes Ethernet payload
        hdr.nsh.spi = spi;
        hdr.nsh.si = si;
        
        // Setting MPLS label
        hdr.mpls.label = mpls_label;
        hdr.mpls.tc = 0;
        hdr.mpls.bos = 1;
        hdr.mpls.ttl = 64;

        standard_metadata.egress_spec = port;
    }

    table classifier_exact {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
        }
        actions = { 
            classify_sfc; 
            NoAction; 
        }
        size = 1024;
        default_action = NoAction();
    }

    // Forwarding underlay traffic through MPLS using transit nodes ( e.g., B, C )
    action mpls_forward( macAddr_t next_hop_mac, egressSpec_t port ) {
        hdr.outer_ethernet.srcAddr = hdr.outer_ethernet.dstAddr;
        hdr.outer_ethernet.dstAddr = next_hop_mac;
        standard_metadata.egress_spec = port;
        hdr.mpls.ttl = hdr.mpls.ttl - 1;
    }

    table mpls_exact {
        key = { 
            hdr.mpls.label: exact; 
        }
        actions = { 
            mpls_forward; 
            drop; 
            NoAction; 
        }
        size = 1024;
        default_action = NoAction();
    }

    // Delivering packets to SFs exploiting SFFs ( e.g., D, E )
    action forward_to_sf( egressSpec_t sf_port ) {
        // Remove SFC Encapsulation before sending to an NSH-unaware SF
        hdr.mpls.setInvalid();
        hdr.nsh.setInvalid();
        
        // Restore original "inner_ethernet" frame
        hdr.outer_ethernet = hdr.inner_ethernet;
        hdr.inner_ethernet.setInvalid();
        
        standard_metadata.egress_spec = sf_port;
    }

    action forward_to_next_sff( bit<20> mpls_label, macAddr_t next_hop_mac, egressSpec_t port ) {
        hdr.outer_ethernet.srcAddr = hdr.outer_ethernet.dstAddr;

        // Swap or push new MPLS label to reach the next SFF
        hdr.mpls.label = mpls_label;
        hdr.mpls.tc = 0;   
        hdr.mpls.bos = 1;
        hdr.outer_ethernet.dstAddr = next_hop_mac;
        standard_metadata.egress_spec = port;
    }

    action end_of_chain( macAddr_t next_hop_mac, egressSpec_t port ) {
        // Complete the steering removing all SFC headers and forward standard IPv4/Eth
        hdr.mpls.setInvalid();
        hdr.nsh.setInvalid();

        hdr.outer_ethernet.srcAddr = hdr.outer_ethernet.dstAddr;
        hdr.outer_ethernet.dstAddr = next_hop_mac;
        hdr.outer_ethernet.etherType = 0x0800;

        hdr.inner_ethernet.setInvalid();
        
        standard_metadata.egress_spec = port;
    }

    table sff_exact {
        key = {
            hdr.nsh.spi: exact;
            hdr.nsh.si: exact;
        }
        actions = { 
            forward_to_sf; 
            forward_to_next_sff;
            drop; 
            NoAction; 
        }
        size = 1024;
        default_action = NoAction();
    }

    // Enabling SFF proxy by simply restoring context from SF return 
    action restore_nsh( bit<24> spi, bit<8> si, bit<20> mpls_label, macAddr_t next_hop_mac, egressSpec_t port ) {
        hdr.inner_ethernet.setValid();
        hdr.nsh.setValid();

        hdr.inner_ethernet.dstAddr = hdr.outer_ethernet.dstAddr;
        hdr.inner_ethernet.srcAddr = hdr.outer_ethernet.srcAddr;
        hdr.inner_ethernet.etherType = 0x0800;

        hdr.outer_ethernet.srcAddr = hdr.outer_ethernet.dstAddr;
        hdr.outer_ethernet.dstAddr = next_hop_mac;

        hdr.nsh.ver = 0;
        hdr.nsh.oam = 0;
        hdr.nsh.u1 = 0;
        hdr.nsh.ttl = 15;
        hdr.nsh.length = 6;
        hdr.nsh.u2 = 0;
        hdr.nsh.md_type = 1;
        hdr.nsh.next_proto = 3;
        hdr.nsh.spi = spi;
        hdr.nsh.si = si;
        
        // If next hop is remote, push MPLS. Otherwise, just NSH.
        if( mpls_label != 0 ) {
            hdr.mpls.setValid();
            hdr.mpls.label = mpls_label;
            hdr.mpls.tc = 0; 
            hdr.mpls.bos = 1;
            hdr.mpls.ttl = 64;
            hdr.outer_ethernet.etherType = TYPE_MPLS;
        } 
        else {
            hdr.mpls.setInvalid();
            hdr.outer_ethernet.etherType = TYPE_NSH; 
        }

        standard_metadata.egress_spec = port;
    }

    table proxy_exact {
        key = {
            standard_metadata.ingress_port: exact; // Note: The port physically connected to the SF
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
        }
        actions = { 
            restore_nsh; 
            end_of_chain;
            NoAction; 
        }
        size = 1024;
        default_action = NoAction();
    }

    // Defining SFs as pure reflectors
    action reflect_and_mark( bit<8> watermark_value ) {
        // Send packet back to the same port it arrived from ( to the SFF )
        standard_metadata.egress_spec = standard_metadata.ingress_port;
        
        // Add a watermark to the "diffserv" field to trace SFC traversal
        hdr.ipv4.diffserv = hdr.ipv4.diffserv + watermark_value;
    }

    table sf_exact {
        key = { 
            standard_metadata.ingress_port: exact; 
        }
        actions = { 
            reflect_and_mark; 
            NoAction; 
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        if ( hdr.ipv4.isValid() && !hdr.nsh.isValid() ) {
            // Traffic is being decapsulated to determine scenario
            if ( proxy_exact.apply().hit ) {
                // Packet returned from SF, NSH context successfully restored
            } 
            else if ( sf_exact.apply().hit ) {
                // Packet is inside an SF node and was reflected
            } 
            else if ( classifier_exact.apply().hit ) {
                // Packet matched a chain policy and entered the SFC domain
            } 
            else {
                // Ordinary routing ( e.g., backward traffic bypassing chains )
                ipv4_lpm.apply();
            }
        } 
        else if ( hdr.nsh.isValid() ) {
            // Packet is in the SFC domain
            if ( !sff_exact.apply().hit ) {
                // If the SFF table doesn't process it, allow MPLS underlay to forward it
                if ( hdr.mpls.isValid() ) {
                    mpls_exact.apply();
                }
            }
        }
        else if ( hdr.mpls.isValid() && !hdr.nsh.isValid() ) {
            // Pure MPLS forwarding fallback
            mpls_exact.apply(); 
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress( inout headers hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata ) { 
    apply {  } 
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum( inout headers hdr, inout metadata_t meta ) {
    apply {
        // Recompute IPv4 checksum because SF reflectors modify the "diffserv" component
        update_checksum( hdr.ipv4.isValid(), { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16 );
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser( packet_out packet, in headers hdr ) {
    apply {
        packet.emit( hdr.outer_ethernet );
        packet.emit( hdr.mpls );
        packet.emit( hdr.nsh );
        packet.emit( hdr.inner_ethernet );
        packet.emit( hdr.ipv4 );
        packet.emit( hdr.tcp );
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
