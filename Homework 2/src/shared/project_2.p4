/*
 * P4 program for basic IPv4 forwarding
 * Phase 1: Underlay routing for shortest path
 */
#include <core.p4>
#include <v1model.p4>

// ----------------------------------------------------------------------
// Headers Definition
// ----------------------------------------------------------------------
// [Comment] Type definitions for 48-bit MAC addresses and 32-bit IPv4 addresses.
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

// [Comment] Structure definition for the standard Ethernet header.
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

// [Comment] Structure definition for the standard IPv4 header including all standard fields.
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

struct metadata {
    // Empty metadata for Phase 1
    // [Comment] Placeholder for custom metadata fields, currently unused in Phase 1.
}

struct headers {
    // [Comment] Grouping defined headers into a single struct for parsing and deparsing.
    ethernet_t ethernet;
    ipv4_t     ipv4;
}

// ----------------------------------------------------------------------
// Parser
// ----------------------------------------------------------------------
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    // [Comment] The parser starts here and immediately transitions to Ethernet parsing.
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        // [Comment] Extract the Ethernet header from the incoming packet.
        packet.extract(hdr.ethernet);
        // Branch based on EtherType
        // [Comment] Check the EtherType to determine if the payload is an IPv4 packet (0x0800).
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        // [Comment] Extract the IPv4 header and finish parsing.
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

// ----------------------------------------------------------------------
// Checksum
// ----------------------------------------------------------------------
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        // Verification logic not strictly required for Phase 1 simulation
        // [Comment] No inbound checksum verification is performed in this phase.
    }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        // Recompute IPv4 checksum since TTL will change
        // [Comment] The checksum must be updated before egress because the TTL field is modified during routing.
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

// ----------------------------------------------------------------------
// Ingress Processing
// ----------------------------------------------------------------------
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        // [Comment] Action to mark the packet to be dropped by the switch engine.
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, bit<9> port) {
        // Set the egress port
        // [Comment] Assign the destination output port for the packet.
        standard_metadata.egress_spec = port;

        // Update MAC addresses for the next hop
        // [Comment] Rewrite the source MAC to the current destination MAC, and set the new destination MAC.
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;

        // Decrement Time To Live
        // [Comment] Decrease the IP TTL to prevent infinite routing loops.
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    // Match-Action table for IPv4 routing
    table ipv4_lpm {
        key = {
            // [Comment] Longest Prefix Match (LPM) on the IPv4 destination address.
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            // [Comment] Possible actions that this table can apply.
            ipv4_forward;
            drop;
            NoAction;
        }
        // [Comment] Define the maximum number of entries this table can hold.
        size = 1024;
        default_action = drop();
    }

    apply {
        // Apply routing only if IPv4 header is present and TTL is valid
        // [Comment] Execute the routing table only if the packet is actually IPv4.
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}

// ----------------------------------------------------------------------
// Egress Processing
// ----------------------------------------------------------------------
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
        // Empty for Phase 1
        // [Comment] No egress pipeline operations are defined yet.
    }
}

// ----------------------------------------------------------------------
// Deparser
// ----------------------------------------------------------------------
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        // Re-assemble the packet
        // [Comment] Serialize the modified headers back into the outgoing byte stream.
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

// ----------------------------------------------------------------------
// Switch Instantiation
// ----------------------------------------------------------------------
// [Comment] Compile all control blocks into the main V1Switch architecture model.
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;