/* Copyright (c) 2017 Northbound Networks
 *
 * Written By Paul Zanna (paul@northboundnetworks.com)
 *
 */

// Field match definitions
#define PREREQ_INVALID 1<<0
#define PREREQ_VLAN 1<<1
#define PREREQ_IPV4 1<<2
#define PREREQ_IPV6 1<<3
#define PREREQ_ARP 1<<4
#define PREREQ_TCP 1<<5
#define PREREQ_UDP 1<<6
#define PREREQ_SCTP 1<<7
#define PREREQ_ICMPV4 1<<8
#define PREREQ_ICMPV6 1<<9
#define PREREQ_ND_SLL 1<<10
#define PREREQ_ND_TLL 1<<11
#define PREREQ_MPLS 1<<12
#define PREREQ_PBB 1<<13
#define PREREQ_ETH_TYPE_MASK (PREREQ_IPV4 | PREREQ_IPV6 | PREREQ_ARP | PREREQ_MPLS | PREREQ_PBB)
#define PREREQ_IP_PROTO_MASK (PREREQ_TCP | PREREQ_UDP | PREREQ_SCTP | PREREQ_ICMPV4 | PREREQ_ICMPV6)
#define PREREQ_IP_MASK (PREREQ_IPV4 | PREREQ_IPV6)
#define PREREQ_ND_MASK (PREREQ_ND_SLL | PREREQ_ND_TLL)

void of13_message(struct ofp_header *ofph, int size, int count);
void packet_in13(uint8_t buffer_no, uint8_t *buffer, uint16_t ul_size, uint8_t port, uint8_t reason, int flow);
void packet_out13(struct ofp_header *msg);
void remove_flow13(int flow_id);
void flowrem_notif13(int flowid, uint8_t reason);
void of_error13(struct ofp_header *msg, uint16_t type, uint16_t code);
void port_status_message13(uint8_t port);
uint32_t get_bound_flows(uint32_t id);

